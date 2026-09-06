// ABOUTME: StagedFile.Name is joined onto two bases; these prove it cannot leave either.
// ABOUTME: The escape case measures what a traversing name would have written.

//go:build linux

package privd

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestStagedFileNameCannotEscapeTheJailRoot: StartVM joins StagedFile.Name onto
// two different bases -- the caller's stage dir when the file is opened and
// digest-verified, and the jail root when it is copied. A name with enough ".."
// resolves inside the stage root on the read and outside the jail on the write,
// because the two bases sit at different depths and stage_dir's depth is the
// caller's to choose: handleStartVM constrains where it resolves, not how deep.
//
// Neither existing gate closes this. O_NOFOLLOW refuses a symlink at the final
// component and says nothing about "..". The digest gate checks that the bytes
// match what the caller claimed for them, not that the caller may write them.
// The uid gate serves exactly one uid -- and privd runs as root while that uid
// does not, which is the whole of what SPEC 3.3 puts privd here to hold.
//
// Every path below is under t.TempDir(); the "escape" lands in a sibling of a
// fake jail. On the failure path the test reads the escaped file back, so the
// message says what a real host would have taken.
func TestStagedFileNameCannotEscapeTheJailRoot(t *testing.T) {
	tmp := t.TempDir()

	// Deliberately deep, so one name can reach different places from the two bases.
	stageDir := filepath.Join(tmp, "stage", "d1", "d2", "d3")
	jailRoot := filepath.Join(tmp, "jail", "root")
	for _, d := range []string{stageDir, jailRoot} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
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
	// build parents -- which is why the escape targets an existing one. On a real
	// host that is no obstacle: /etc/cron.d, /etc/systemd/system and /root/.ssh are
	// all there already.
	for _, d := range []string{filepath.Dir(srcPath), filepath.Dir(dstPath)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	payload := []byte("content the caller chose, written by root, outside the jail\n")
	if err := os.WriteFile(srcPath, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	f := StagedFile{Name: name, SHA256: hex.EncodeToString(sum[:])}

	stageFd, err := openDirNoFollow(stageDir)
	if err != nil {
		t.Fatalf("open stage dir: %v", err)
	}
	defer stageFd.Close()

	pinned, err := VerifyStagedFileAt(stageFd, f)
	if err == nil {
		// Not refused. Finish the copy the way StartVM would and report what it took:
		// a refusal that only happens later is not a refusal, and the bytes on disk
		// are the difference between a hardening opinion and a hole.
		defer pinned.Close()
		// uid/gid -1 leaves ownership alone, so the copy needs no root here. A root
		// privd would also chown the escaped path to the VM's uid.
		jailRootDir, openErr := openDirNoFollow(jailRoot)
		if openErr != nil {
			t.Fatalf("open jail root: %v", openErr)
		}
		defer jailRootDir.Close()
		copyErr := CopyFromPinnedFd(pinned, jailRootDir, f, -1, -1)
		got, readErr := os.ReadFile(dstPath)
		if copyErr == nil && readErr == nil {
			t.Fatalf("VerifyStagedFile accepted %q and the copy wrote %d bytes to %q, outside the jail root %q: %q",
				name, len(got), dstPath, jailRoot, string(got))
		}
		t.Fatalf("VerifyStagedFile accepted %q; the copy then failed (%v) and the escaped path read back %v",
			name, copyErr, readErr)
	}
	if _, statErr := os.Stat(dstPath); statErr == nil {
		t.Errorf("VerifyStagedFile refused %q but something still wrote %q", name, dstPath)
	}
}

// TestVerifyStagedFileTakesTheNamesALaunchStages: the refusal above must not be
// bought by refusing everything. Each name the jailer really sends still opens
// and verifies.
func TestVerifyStagedFileTakesTheNamesALaunchStages(t *testing.T) {
	stageDir := t.TempDir()
	stageFd, err := openDirNoFollow(stageDir)
	if err != nil {
		t.Fatalf("open stage dir: %v", err)
	}
	defer stageFd.Close()
	for _, name := range StagedFileNames {
		payload := []byte("bytes of " + name)
		if err := os.WriteFile(filepath.Join(stageDir, name), payload, 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(payload)
		f := StagedFile{Name: name, SHA256: hex.EncodeToString(sum[:])}
		pinned, err := VerifyStagedFileAt(stageFd, f)
		if err != nil {
			t.Errorf("VerifyStagedFileAt refused %q, which every launch stages: %v", name, err)
			continue
		}
		pinned.Close()
	}
}
