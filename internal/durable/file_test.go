// ABOUTME: Tests for the durable-publication helper: barriers taken, barriers reported when they fail.
// ABOUTME: Permission tests induce a real directory-sync failure; they are meaningless as root and skip.
package durable_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2389-research/observatory/internal/durable"
)

// What these tests prove, and what they do not.
//
// Six of the seven barriers here are mutation-proven: removing the post-rename
// directory sync, the sync inside Remove, the syncs inside MkdirAll, the
// temporary-file cleanup, the requested mode, or the sync/close ordering each
// makes a named test below fail.
//
// The seventh — WriteFile's tmp.Sync() — has no failing test, and no test here
// pretends otherwise. Inducing an fsync failure on a regular file needs a full
// device or a fault-injecting block layer, neither of which a unit suite has.
// What is proven is that the sync precedes the close, because os.File.Sync on a
// closed descriptor answers ErrClosed and every success below would turn red.
//
// Nothing here proves durability itself. fsync is a promise the kernel makes to
// the disk, and only power loss collects on it. A process crash never tests it:
// the page cache outlives the process. See TestLedgerSurvivesAProcessCrash for
// what a crash does prove.

// A 0300 directory permits create and rename (write+execute) and denies open
// for read, which is what SyncDir needs. Root bypasses the check entirely, so
// every test built on that trick has to skip rather than assert a false pass.
func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("permission barriers do not apply to root; run this suite unprivileged")
	}
}

// denyDirectoryRead drops the directory to write+execute and restores it at
// cleanup, because t.TempDir's own removal needs read back.
func denyDirectoryRead(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatalf("chmod %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
}

func TestWriteFilePublishesPrivateContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "record.json")

	if err := durable.WriteFile(path, 0o600, []byte(`{"vm":"a"}`)); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != `{"vm":"a"}` {
		t.Errorf("content = %q; want %q", got, `{"vm":"a"}`)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %v; want 0600", perm)
	}
	// A success here is also the proof that the file sync precedes the close:
	// os.File.Sync on a closed descriptor answers ErrClosed, so the reversed
	// order would surface as a failure rather than as silent non-durability.
}

func TestWriteFilePublishesTheRequestedMode(t *testing.T) {
	// os.CreateTemp already answers 0600, so a 0600-only suite would pass with
	// the mode ignored entirely. A second mode makes the request load-bearing.
	dir := t.TempDir()
	path := filepath.Join(dir, "readable.json")

	if err := durable.WriteFile(path, 0o644, []byte(`{"vm":"a"}`)); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("mode = %v; want 0644", perm)
	}
}

func TestWriteFileReplacesOneCompleteRecordWithAnother(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "record.json")

	if err := durable.WriteFile(path, 0o600, []byte(`{"vm":"a","uid":10000}`)); err != nil {
		t.Fatalf("first WriteFile: %v", err)
	}
	if err := durable.WriteFile(path, 0o600, []byte(`{"vm":"a","uid":10001}`)); err != nil {
		t.Fatalf("second WriteFile: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != `{"vm":"a","uid":10001}` {
		t.Errorf("content = %q; want the second record complete", got)
	}
	if names := siblingNames(t, dir); len(names) != 1 {
		t.Errorf("directory holds %v; want only the published record", names)
	}
}

func TestWriteFileLeavesTheOldRecordIntactWhenItCannotStart(t *testing.T) {
	skipIfRoot(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "record.json")
	if err := durable.WriteFile(path, 0o600, []byte(`{"vm":"a","uid":10000}`)); err != nil {
		t.Fatalf("seed WriteFile: %v", err)
	}

	// Read and execute only: the temporary file cannot be created, so nothing
	// the publication does can reach the old record.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := durable.WriteFile(path, 0o600, []byte(`{"vm":"a","uid":10001}`))
	if err == nil {
		t.Fatal("WriteFile succeeded into a directory it cannot write")
	}

	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read back: %v", readErr)
	}
	if string(got) != `{"vm":"a","uid":10000}` {
		t.Errorf("content = %q; want the old record byte-identical", got)
	}
}

func TestWriteFileRemovesItsTemporaryFileWhenPublicationFails(t *testing.T) {
	dir := t.TempDir()
	// A directory cannot be replaced by a rename, so publication fails after
	// the temporary file exists — the one window that can litter.
	path := filepath.Join(dir, "record.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}

	if err := durable.WriteFile(path, 0o600, []byte(`{"vm":"a"}`)); err == nil {
		t.Fatal("WriteFile succeeded onto a directory")
	}

	for _, name := range siblingNames(t, dir) {
		if name != "record.json" {
			t.Errorf("failed publication left %q behind", name)
		}
	}
}

func TestWriteFileReportsAFailedDirectorySync(t *testing.T) {
	skipIfRoot(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "record.json")
	denyDirectoryRead(t, dir)

	err := durable.WriteFile(path, 0o600, []byte(`{"vm":"a"}`))
	if err == nil {
		t.Fatal("WriteFile reported success without the directory barrier")
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("err = %v; want the directory-sync permission failure", err)
	}
	if !strings.Contains(err.Error(), "sync") {
		t.Errorf("err = %v; want it to name the barrier that failed", err)
	}
}

func TestSyncDirRejectsAPathItCannotOpen(t *testing.T) {
	dir := t.TempDir()
	if err := durable.SyncDir(filepath.Join(dir, "absent")); err == nil {
		t.Fatal("SyncDir reported success for a directory that does not exist")
	}
}

func TestRemoveIsQuietWhenTheRecordIsAlreadyGone(t *testing.T) {
	dir := t.TempDir()
	if err := durable.Remove(filepath.Join(dir, "absent.json")); err != nil {
		t.Fatalf("Remove of an absent record: %v", err)
	}
}

func TestRemoveUnlinksTheRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "record.json")
	if err := durable.WriteFile(path, 0o600, []byte(`{"vm":"a"}`)); err != nil {
		t.Fatalf("seed WriteFile: %v", err)
	}

	if err := durable.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("stat after Remove = %v; want the record gone", err)
	}
}

func TestRemoveReportsAFailedDirectorySync(t *testing.T) {
	skipIfRoot(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "record.json")
	if err := durable.WriteFile(path, 0o600, []byte(`{"vm":"a"}`)); err != nil {
		t.Fatalf("seed WriteFile: %v", err)
	}
	denyDirectoryRead(t, dir)

	err := durable.Remove(path)
	if err == nil {
		t.Fatal("Remove reported a durable removal without the directory barrier")
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("err = %v; want the directory-sync permission failure", err)
	}
}

func TestMkdirAllCreatesTheWholeTree(t *testing.T) {
	dir := t.TempDir()
	leaf := filepath.Join(dir, "vms", "vm-1")

	if err := durable.MkdirAll(leaf, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	info, err := os.Stat(leaf)
	if err != nil {
		t.Fatalf("stat leaf: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("leaf is not a directory")
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("mode = %v; want 0700", perm)
	}
	// Idempotent: a second call repeats barriers without changing the tree.
	if err := durable.MkdirAll(leaf, 0o700); err != nil {
		t.Fatalf("second MkdirAll: %v", err)
	}
}

func TestMkdirAllReportsAFailedDirectorySync(t *testing.T) {
	skipIfRoot(t)
	dir := t.TempDir()
	parent := filepath.Join(dir, "vms")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}
	denyDirectoryRead(t, parent)

	err := durable.MkdirAll(filepath.Join(parent, "vm-1"), 0o700)
	if err == nil {
		t.Fatal("MkdirAll reported success without the directory barrier")
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("err = %v; want the directory-sync permission failure", err)
	}
	if err := durable.MkdirAll(filepath.Join(parent, "vm-1"), 0o700); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("visible directory retry lost its failed barrier: %v", err)
	}
}

func siblingNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestRemoveAllRetryRepeatsDirectoryBarrier(t *testing.T) {
	skipIfRoot(t)
	parent := t.TempDir()
	path := filepath.Join(parent, "vm")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	denyDirectoryRead(t, parent)
	if err := durable.RemoveAll(path); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("first removal must fail barrier: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("tree not removed: %v", err)
	}
	if err := durable.RemoveAll(path); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("retry skipped unsettled barrier: %v", err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := durable.RemoveAll(path); err != nil {
		t.Fatalf("recovered barrier: %v", err)
	}
}

func TestRemoveAllAbsentAncestorsStillSyncsSurvivor(t *testing.T) {
	skipIfRoot(t)
	parent := t.TempDir()
	denyDirectoryRead(t, parent)
	if err := durable.RemoveAll(filepath.Join(parent, "gone", "vm")); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("absent parents skipped barrier: %v", err)
	}
}
