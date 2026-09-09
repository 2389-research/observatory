// ABOUTME: The jail root is chowned to the guest, so its entries are the guest's to
// ABOUTME: replace: these plant symlinks in it and prove root never follows one.

//go:build linux

package privd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// stageOne writes body into stageDir under name and returns the StagedFile that
// names it, digest and all, so StartVM's verify step passes and the test reaches
// the copy it is actually about.
func stageOne(t *testing.T, stageDir, name string, body []byte) StagedFile {
	t.Helper()
	if err := os.MkdirAll(stageDir, 0o750); err != nil {
		t.Fatalf("mkdir stage dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stageDir, name), body, 0o600); err != nil {
		t.Fatalf("write staged file: %v", err)
	}
	sum := sha256.Sum256(body)
	return StagedFile{Name: name, SHA256: hex.EncodeToString(sum[:])}
}

// mkJailRoot builds <jailBase>/firecracker/<vmID>/root the way a previous start
// left it, and returns both paths.
func mkJailRoot(t *testing.T, jailBase, vmID string) (jailDir, root string) {
	t.Helper()
	jailDir = filepath.Join(jailBase, "firecracker", vmID)
	root = filepath.Join(jailDir, "root")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatalf("mkdir jail root: %v", err)
	}
	return jailDir, root
}

// wantInvalidState fails unless err is privd's typed refusal.
func wantInvalidState(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("want a refusal, got nil")
	}
	var be *BackendError
	if !errors.As(err, &be) || be.Cause != "invalid_state" {
		t.Fatalf("want a BackendError with cause invalid_state, got %#v (%v)", err, err)
	}
}

// TestStagedVMWillNotWriteThroughASymlinkInTheJailRoot is the escalation in its
// plainest form. StartVM chowns the jail tree to the guest's uid in step 2, so
// after one start the guest owns <jail>/root and can replace any name in it with
// a symlink. privd then copies the next start's boot artifacts in as root. A
// symlink named vmlinux pointing at a file the guest cannot write is a file
// privd writes for it.
func TestStagedVMWillNotWriteThroughASymlinkInTheJailRoot(t *testing.T) {
	ops, jailBase, _ := guardOps(t)
	const vmID = "vm-jailfd-file"
	_, root := mkJailRoot(t, jailBase, vmID)

	outside := filepath.Join(t.TempDir(), "a-file-the-guest-cannot-write")
	if err := os.WriteFile(outside, []byte("untouched"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "vmlinux")); err != nil {
		t.Fatalf("plant symlink: %v", err)
	}

	// Stand in for the jailer with a hook that writes this process's own pid,
	// so a start that is not refused succeeds outright and the only thing left
	// to look at is what landed outside the jail.
	ops.hooks.RunCmd = func([]string) error {
		return os.WriteFile(filepath.Join(root, "firecracker.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)
	}

	stageDir := filepath.Join(ops.cfg.StageRoot, vmID)
	file := stageOne(t, stageDir, "vmlinux", []byte("a kernel image"))

	entry := VMEntry{VMID: vmID, UID: os.Getuid(), GID: os.Getgid()}
	_, err := startStagedForTest(t, ops, &entry, StartVMReq{
		VMID:     vmID,
		UID:      os.Getuid(),
		GID:      os.Getgid(),
		StageDir: stageDir,
		Files:    []StagedFile{file},
	})
	got, readErr := os.ReadFile(outside)
	if readErr != nil {
		t.Fatalf("read outside file: %v", readErr)
	}
	if string(got) != "untouched" {
		t.Errorf("privd wrote through the symlink: the file outside the jail now holds %q", got)
	}
	wantInvalidState(t, err)
}

// TestStagedVMWillNotFollowASymlinkedJailRoot moves the symlink one level up.
// chownTree chowns <jail> itself, not just <jail>/root, so the guest can also
// replace the root directory wholesale and redirect every copy at once.
func TestStagedVMWillNotFollowASymlinkedJailRoot(t *testing.T) {
	ops, jailBase, _ := guardOps(t)
	const vmID = "vm-jailfd-dir"

	jailDir := filepath.Join(jailBase, "firecracker", vmID)
	if err := os.MkdirAll(jailDir, 0o750); err != nil {
		t.Fatalf("mkdir jail dir: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "somewhere-else")
	if err := os.MkdirAll(outside, 0o750); err != nil {
		t.Fatalf("mkdir outside dir: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(jailDir, "root")); err != nil {
		t.Fatalf("plant symlink: %v", err)
	}

	stageDir := filepath.Join(ops.cfg.StageRoot, vmID)
	file := stageOne(t, stageDir, "vmlinux", []byte("a kernel image"))

	ops.hooks.RunCmd = func([]string) error {
		return os.WriteFile(filepath.Join(outside, "firecracker.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)
	}

	entry := VMEntry{VMID: vmID, UID: os.Getuid(), GID: os.Getgid()}
	_, err := startStagedForTest(t, ops, &entry, StartVMReq{
		VMID:     vmID,
		UID:      os.Getuid(),
		GID:      os.Getgid(),
		StageDir: stageDir,
		Files:    []StagedFile{file},
	})
	entries, readErr := os.ReadDir(outside)
	if readErr != nil {
		t.Fatalf("read outside dir: %v", readErr)
	}
	for _, e := range entries {
		if e.Name() != "firecracker.pid" { // the stand-in jailer's own file
			t.Errorf("privd copied %q into the symlinked root", e.Name())
		}
	}
	wantInvalidState(t, err)
}

// TestStagedVMWillNotReadAPidFileThroughASymlink is the worst of the three,
// because it needs no write at all. The pid privd reads out of the jail goes
// straight into the ledger, and the only thing standing between that number and
// a later SIGKILL is a starttime compare against the same /proc entry. A symlink
// pointing at a file that holds "1" hands privd init's pid and init's starttime,
// which agree with each other, and the next stop of this VM signals pid 1.
func TestStagedVMWillNotReadAPidFileThroughASymlink(t *testing.T) {
	ops, jailBase, _ := guardOps(t)
	const vmID = "vm-jailfd-pid"
	_, root := mkJailRoot(t, jailBase, vmID)

	outside := filepath.Join(t.TempDir(), "a-pid-privd-was-not-given")
	if err := os.WriteFile(outside, []byte("1\n"), 0o600); err != nil {
		t.Fatalf("write outside pid file: %v", err)
	}
	ops.hooks.RunCmd = func([]string) error {
		return os.Symlink(outside, filepath.Join(root, "firecracker.pid"))
	}

	entry := VMEntry{VMID: vmID, UID: os.Getuid(), GID: os.Getgid()}
	resp, err := startStagedForTest(t, ops, &entry, StartVMReq{VMID: vmID, UID: os.Getuid(), GID: os.Getgid()})
	if err == nil {
		t.Fatalf("StartVM read a pid through a symlink and returned pid %d", resp.PID)
	}
	if resp.PID != 0 {
		t.Errorf("StartVM returned pid %d alongside its error", resp.PID)
	}
}

// TestCopyFromPinnedFdRefusesANameTheJailerWouldNotStage covers what the
// descriptor does not. openat resolves ".." against a dirfd exactly as it does
// against a path, so anchoring the copy bounds symlinks and leaves traversal to
// the name whitelist. VerifyStagedFile asks it first; this asks whether the copy
// would still hold on its own.
func TestCopyFromPinnedFdRefusesANameTheJailerWouldNotStage(t *testing.T) {
	tmp := t.TempDir()
	stageDir := filepath.Join(tmp, "stage")
	jail := filepath.Join(tmp, "jail", "root")
	for _, d := range []string{stageDir, jail} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	src := stageOne(t, stageDir, "vmlinux", []byte("a kernel image"))
	stageFd, err := openDirNoFollow(stageDir)
	if err != nil {
		t.Fatalf("open stage dir: %v", err)
	}
	defer stageFd.Close()
	pinned, err := VerifyStagedFileAt(stageFd, src)
	if err != nil {
		t.Fatalf("VerifyStagedFileAt: %v", err)
	}
	defer pinned.Close()

	jailDir, err := openDirNoFollow(jail)
	if err != nil {
		t.Fatalf("open jail root: %v", err)
	}
	defer jailDir.Close()

	escape := StagedFile{Name: "../escaped", SHA256: src.SHA256}
	if err := CopyFromPinnedFd(pinned, jailDir, escape, -1, -1); err == nil {
		t.Fatal("CopyFromPinnedFd accepted a traversing name")
	}
	if _, err := os.Stat(filepath.Join(tmp, "jail", "escaped")); err == nil {
		t.Error("CopyFromPinnedFd wrote outside the jail root")
	}
}

// TestStagedVMRefusesAJailRootThatAlreadyHoldsAStagedFile is the debris policy.
// ReleaseVM removes the tree on a clean stop and AbortStartVM removes it on
// every StartVM that returns an error, so the only way a boot artifact is
// already sitting in the root is that one of those did not finish -- privd
// killed mid-start, or a RemoveAll that errored (server.go logs that one).
// Overwriting it starts a VM into a chroot privd did not build and cannot
// describe.
//
// The refusal also stops privd depending on fs.protected_hardlinks, a sysctl it
// does not own, to keep the copy off an inode it was not given. O_NOFOLLOW says
// nothing about a hardlink; O_EXCL refuses every name that is already there,
// whatever kind of thing it is.
func TestStagedVMRefusesAJailRootThatAlreadyHoldsAStagedFile(t *testing.T) {
	ops, jailBase, _ := guardOps(t)
	const vmID = "vm-jailfd-debris"
	_, root := mkJailRoot(t, jailBase, vmID)

	leftover := []byte("a kernel from a start that never finished")
	if err := os.WriteFile(filepath.Join(root, "vmlinux"), leftover, 0o600); err != nil {
		t.Fatalf("plant leftover: %v", err)
	}

	stageDir := filepath.Join(ops.cfg.StageRoot, vmID)
	file := stageOne(t, stageDir, "vmlinux", []byte("the kernel this start staged"))
	ops.hooks.RunCmd = func([]string) error {
		return os.WriteFile(filepath.Join(root, "firecracker.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)
	}

	entry := VMEntry{VMID: vmID, UID: os.Getuid(), GID: os.Getgid()}
	_, err := startStagedForTest(t, ops, &entry, StartVMReq{
		VMID:     vmID,
		UID:      os.Getuid(),
		GID:      os.Getgid(),
		StageDir: stageDir,
		Files:    []StagedFile{file},
	})

	got, readErr := os.ReadFile(filepath.Join(root, "vmlinux"))
	if readErr != nil {
		t.Fatalf("read leftover: %v", readErr)
	}
	if string(got) != string(leftover) {
		t.Errorf("privd overwrote the leftover: the jail root now holds %q", got)
	}
	wantInvalidState(t, err)
}

// TestStagedVMStillCopiesIntoAJailRootItJustMade keeps the refusal from being
// bought by refusing every start. The ordinary case -- an empty root privd
// created a moment ago -- still takes all five artifacts.
func TestStagedVMStillCopiesIntoAJailRootItJustMade(t *testing.T) {
	ops, jailBase, _ := guardOps(t)
	const vmID = "vm-jailfd-clean"

	entry := VMEntry{VMID: vmID, UID: os.Getuid(), GID: os.Getgid(), NetCIDR: "10.99.0.0/30"}
	stageDir := filepath.Join(ops.cfg.StageRoot, vmID)
	var files []StagedFile
	for _, name := range StagedFileNames {
		body := "bytes of " + name
		if name == "fc-config.json" {
			body = bindingConfig(t, entry)
		}
		files = append(files, stageOne(t, stageDir, name, []byte(body)))
	}
	root := filepath.Join(jailBase, "firecracker", vmID, "root")
	ops.hooks.RunCmd = func([]string) error {
		return os.WriteFile(filepath.Join(root, "firecracker.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)
	}

	resp, err := startStagedForTest(t, ops, &entry, StartVMReq{
		VMID:     vmID,
		CID:      3,
		UID:      os.Getuid(),
		GID:      os.Getgid(),
		StageDir: stageDir,
		Files:    files,
	})
	if err != nil {
		t.Fatalf("StartVM on a fresh jail root: %v", err)
	}
	if resp.PID != os.Getpid() {
		t.Errorf("StartVM returned pid %d, want the stand-in's %d", resp.PID, os.Getpid())
	}
	for _, name := range StagedFileNames {
		got, readErr := os.ReadFile(filepath.Join(root, name))
		if readErr != nil {
			t.Errorf("read %s from the jail root: %v", name, readErr)
			continue
		}
		want := "bytes of " + name
		if name == "fc-config.json" {
			want = bindingConfig(t, entry)
		}
		if string(got) != want {
			t.Errorf("jail root holds %q for %s", got, name)
		}
	}
}
