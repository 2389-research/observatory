// ABOUTME: Proof that StagedFile.Name is trusted as a basename and is not one.
// ABOUTME: Verify+copy resolve the same name from two different bases; one escapes.

//go:build linux

package privd

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestStagedFileNameEscapesTheJailRoot demonstrates the check/use gap zd43 names:
// StartVM treats StagedFile.Name as a basename because its doc comment says so,
// and nothing enforces it. The name is joined onto two different bases -- the
// client's stage dir when the file is opened and digest-verified, and the jail
// root when it is copied -- so a name with enough ".." resolves inside the stage
// root on the read and outside the jail on the write. privd runs as root; the
// controller uid that sends this request does not, and that difference is the
// only thing privd exists to hold.
//
// The digest gate does not close it: the caller supplies both the bytes and the
// digest it claims for them.
//
// Contained by construction -- every path here is under t.TempDir(), and the
// "escape" lands in a sibling of the fake jail, not on the host.
func TestStagedFileNameEscapesTheJailRoot(t *testing.T) {
	tmp := t.TempDir()

	// The client's stage dir, deliberately deep. handleStartVM constrains
	// stage_dir to resolve under the stage root; it does not constrain its depth,
	// and the depth is what lets one name reach different places from the two
	// bases.
	stageDir := filepath.Join(tmp, "stage", "d1", "d2", "d3")
	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The jail root StartVM copies into.
	jailRoot := filepath.Join(tmp, "jail", "root")
	if err := os.MkdirAll(jailRoot, 0o750); err != nil {
		t.Fatal(err)
	}

	// One name, two resolutions:
	//   from stageDir -> <tmp>/stage/d1/victim/owned.txt   (inside the stage root)
	//   from jailRoot -> <tmp>/victim/owned.txt            (outside the jail)
	const name = "../../victim/owned.txt"
	srcPath := filepath.Join(stageDir, name)
	dstPath := filepath.Join(jailRoot, name)
	if filepath.Dir(dstPath) == filepath.Clean(jailRoot) {
		t.Fatalf("test is not exercising an escape: dst %q is inside the jail root", dstPath)
	}

	// The destination directory has to exist -- os.OpenFile with O_CREATE does not
	// build parents -- which is why the escape targets an existing directory. On a
	// real host that is no obstacle: /etc/cron.d, /etc/systemd/system and /root/.ssh
	// are all there already.
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		t.Fatal(err)
	}

	payload := []byte("content the caller chose, written by root, outside the jail\n")
	if err := os.MkdirAll(filepath.Dir(srcPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcPath, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	f := StagedFile{Name: name, SHA256: hex.EncodeToString(sum[:])}

	pinned, err := VerifyStagedFile(stageDir, f)
	if err != nil {
		t.Fatalf("VerifyStagedFile refused the traversing name: %v", err)
	}
	defer pinned.Close()

	// uid/gid -1 leaves ownership alone, so the copy's chown does not need root.
	// The write is what matters; a root privd would also chown the escaped path.
	if err := CopyFromPinnedFd(pinned, jailRoot, f, -1, -1); err != nil {
		t.Fatalf("CopyFromPinnedFd refused the traversing name: %v", err)
	}

	got, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatalf("no file at the escaped path %q: %v", dstPath, err)
	}
	t.Errorf("privd wrote %d bytes to %q, which is outside the jail root %q: %q",
		len(got), dstPath, jailRoot, string(got))
}
