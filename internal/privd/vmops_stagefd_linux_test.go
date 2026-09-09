// ABOUTME: Tests that privd reads staged files from a directory it derives and holds open,
// ABOUTME: not from the path its caller named. Non-root: RunCmd stands in for the jailer.

//go:build linux

package privd

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// stageOps builds a RealOps over a real jail base and a real stage root, the
// two directories privd's config names and the caller does not.
func stageOps(t *testing.T, stageRoot string) (*RealOps, string) {
	t.Helper()
	dir := t.TempDir()
	jailBase := filepath.Join(dir, "jail")
	if err := os.MkdirAll(jailBase, 0o750); err != nil {
		t.Fatalf("mkdir jail base: %v", err)
	}
	ops := NewRealOps(RealOpsCfg{JailBase: jailBase, StageRoot: stageRoot})
	ops.log = log.New(&bytes.Buffer{}, "", 0)
	return ops, jailBase
}

// startFrom runs StartVM for vmID with a stand-in jailer that writes the pid
// file, and returns the jail root alongside the result.
func startFrom(t *testing.T, ops *RealOps, jailBase, vmID, sendStageDir string, files []StagedFile) (string, error) {
	t.Helper()
	root := filepath.Join(jailBase, "firecracker", vmID, "root")
	ops.hooks.RunCmd = func([]string) error {
		return os.WriteFile(filepath.Join(root, "firecracker.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)
	}
	entry := VMEntry{VMID: vmID, UID: os.Getuid(), GID: os.Getgid()}
	_, err := startStagedForTest(t, ops, &entry, StartVMReq{
		VMID:     vmID,
		UID:      os.Getuid(),
		GID:      os.Getgid(),
		StageDir: sendStageDir,
		Files:    files,
	})
	return root, err
}

// TestStagedVMReadsTheStageDirItDerives is the finding. stage_dir arrived in the
// request, so the caller chose which directory root read gigabytes out of. It
// is derivable -- vm_id is one validated path component and the adapter joins
// it onto the same stage root -- so privd derives it and the field stops being
// load-bearing.
//
// The decoy holds the same five names with different bytes. Reading the field
// gets the decoy and a digest mismatch; deriving gets the real directory.
func TestStagedVMReadsTheStageDirItDerives(t *testing.T) {
	stageRoot := t.TempDir()
	ops, jailBase := stageOps(t, stageRoot)
	const vmID = "vm-stage-derive"

	real := stageOne(t, filepath.Join(stageRoot, vmID), "vmlinux", []byte("the kernel privd should read"))
	decoy := filepath.Join(stageRoot, "vm-decoy")
	stageOne(t, decoy, "vmlinux", []byte("a kernel the caller pointed at"))

	root, err := startFrom(t, ops, jailBase, vmID, decoy, []StagedFile{real})
	if err != nil {
		t.Fatalf("StartVM: %v", err)
	}
	got, readErr := os.ReadFile(filepath.Join(root, "vmlinux"))
	if readErr != nil {
		t.Fatalf("read copied kernel: %v", readErr)
	}
	if string(got) != "the kernel privd should read" {
		t.Errorf("jail root holds %q -- privd read the directory the caller named", got)
	}
}

// TestStagedVMWillNotFollowASymlinkedStageDir: deriving the path is not enough on
// its own, because the caller owns the stage root and can leave a symlink at the
// name privd derives. The open of that one component is O_NOFOLLOW, so the
// symlink is refused rather than resolved.
func TestStagedVMWillNotFollowASymlinkedStageDir(t *testing.T) {
	stageRoot := t.TempDir()
	ops, jailBase := stageOps(t, stageRoot)
	const vmID = "vm-stage-symdir"

	elsewhere := filepath.Join(stageRoot, "elsewhere")
	file := stageOne(t, elsewhere, "vmlinux", []byte("a kernel behind a symlinked stage dir"))
	if err := os.Symlink(elsewhere, filepath.Join(stageRoot, vmID)); err != nil {
		t.Fatalf("symlink stage dir: %v", err)
	}

	root, err := startFrom(t, ops, jailBase, vmID, filepath.Join(stageRoot, vmID), []StagedFile{file})
	if _, statErr := os.Stat(filepath.Join(root, "vmlinux")); statErr == nil {
		t.Error("privd copied a kernel it reached through a symlinked stage dir")
	}
	if err == nil {
		t.Fatal("want a refusal, got nil")
	}
}

// TestStagedVMWillNotFollowASymlinkedStagedFile is the trap. os.Root resolves a
// symlink that stays inside the root and ignores a caller's O_NOFOLLOW while
// doing it, so porting this read to Root.OpenFile would quietly turn today's
// refusal into a copy. The file open stays a bare openat against the stage
// dir's descriptor, where O_NOFOLLOW means what it says.
func TestStagedVMWillNotFollowASymlinkedStagedFile(t *testing.T) {
	stageRoot := t.TempDir()
	ops, jailBase := stageOps(t, stageRoot)
	const vmID = "vm-stage-symfile"

	// The target is inside the stage root: an escaping symlink is the easy case,
	// and it is not the one os.Root would let through.
	inside := stageOne(t, filepath.Join(stageRoot, "inside"), "vmlinux", []byte("a kernel one directory over"))
	stageDir := filepath.Join(stageRoot, vmID)
	if err := os.MkdirAll(stageDir, 0o750); err != nil {
		t.Fatalf("mkdir stage dir: %v", err)
	}
	if err := os.Symlink(filepath.Join(stageRoot, "inside", "vmlinux"), filepath.Join(stageDir, "vmlinux")); err != nil {
		t.Fatalf("symlink staged file: %v", err)
	}

	root, err := startFrom(t, ops, jailBase, vmID, stageDir, []StagedFile{inside})
	if _, statErr := os.Stat(filepath.Join(root, "vmlinux")); statErr == nil {
		t.Error("privd copied a kernel it reached through a symlinked staged file")
	}
	if err == nil {
		t.Fatal("want a refusal, got nil")
	}
}

// TestStagedVMReadsThroughASymlinkedStageRoot keeps the refusals above from
// costing a supported install. StageRoot is privd's own config and is allowed
// to be a symlink -- /var/vmobs/stage pointing at another filesystem is the
// reason the containment check used to call EvalSymlinks at all. Only the
// components below it are the caller's, and only those are O_NOFOLLOW.
func TestStagedVMReadsThroughASymlinkedStageRoot(t *testing.T) {
	dir := t.TempDir()
	realRoot := filepath.Join(dir, "real-stage")
	if err := os.MkdirAll(realRoot, 0o750); err != nil {
		t.Fatalf("mkdir real stage root: %v", err)
	}
	linkedRoot := filepath.Join(dir, "stage-link")
	if err := os.Symlink(realRoot, linkedRoot); err != nil {
		t.Fatalf("symlink stage root: %v", err)
	}
	ops, jailBase := stageOps(t, linkedRoot)
	const vmID = "vm-stage-symroot"

	file := stageOne(t, filepath.Join(realRoot, vmID), "vmlinux", []byte("a kernel under a symlinked root"))
	root, err := startFrom(t, ops, jailBase, vmID, filepath.Join(linkedRoot, vmID), []StagedFile{file})
	if err != nil {
		t.Fatalf("StartVM with a symlinked stage root: %v", err)
	}
	got, readErr := os.ReadFile(filepath.Join(root, "vmlinux"))
	if readErr != nil {
		t.Fatalf("read copied kernel: %v", readErr)
	}
	if string(got) != "a kernel under a symlinked root" {
		t.Errorf("jail root holds %q", got)
	}
}
