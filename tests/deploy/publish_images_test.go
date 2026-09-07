// ABOUTME: Checks scripts/publish-guest-images refuses clearly when it cannot
// ABOUTME: publish, so an operator learns what is missing instead of a gh error.
package deploy_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const publishScriptPath = "../../scripts/publish-guest-images"

// publishFixture lays out a dist directory and a lock that agree, and returns
// both paths. Individual tests then break exactly one thing.
func publishFixture(t *testing.T) (lock, dist string) {
	t.Helper()
	dir := t.TempDir()
	dist = filepath.Join(dir, "dist")
	if err := os.MkdirAll(dist, 0o755); err != nil {
		t.Fatalf("mkdir dist: %v", err)
	}
	for name, body := range fetchBodies {
		if err := os.WriteFile(filepath.Join(dist, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	lock = writeLock(t, dir,
		"", sha256Hex(fetchBodies["vmlinux"]),
		"", sha256Hex(fetchBodies["rootfs.ext4"]))
	return lock, dist
}

func runPublish(t *testing.T, lock, dist string, extraPath string, args ...string) (string, error) {
	t.Helper()
	argv := append([]string{publishScriptPath, "--lock", lock, "--dist", dist}, args...)
	cmd := exec.Command("sh", argv...)
	cmd.Env = append(os.Environ(), "PATH="+extraPath)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// pathWithoutGh builds a PATH holding every tool the script needs before it
// reaches the upload, and nothing else -- so the run gets as far as gh and no
// further. Removing one entry from the real PATH is not possible; naming the
// dependencies is, and it keeps this test honest about what they are.
func pathWithoutGh(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	found := 0
	for _, tool := range []string{"dirname", "jq", "cut", "sha256sum", "shasum"} {
		real, err := exec.LookPath(tool)
		if err != nil {
			continue // sha256sum and shasum are the macOS/Linux pair; one is enough
		}
		if err := os.Symlink(real, filepath.Join(bin, tool)); err != nil {
			t.Fatalf("link %s: %v", tool, err)
		}
		found++
	}
	if found < 4 {
		t.Fatalf("only %d of the script's tools are on PATH; cannot build the fixture", found)
	}
	return bin
}

// TestPublishRefusesWithoutGh: gh is how this talks to GitHub at all. Its own
// "command not found" says nothing about what the operator is trying to do.
//
// The fixture's artifacts match the lock, so the run reaches the gh check
// rather than stopping earlier -- which is the order that matters. gh was
// checked first once, and on a host without gh installed every other refusal
// in this file reported the missing tool instead of the thing it was testing.
func TestPublishRefusesWithoutGh(t *testing.T) {
	lock, dist := publishFixture(t)
	out, err := runPublish(t, lock, dist, pathWithoutGh(t), "--tag", "guest-images-1")
	if err == nil {
		t.Fatalf("publish ran with no gh on PATH:\n%s", out)
	}
	if !strings.Contains(out, "gh") {
		t.Errorf("refusal does not name gh:\n%s", out)
	}
	// It got past the local checks to get there.
	if !strings.Contains(out, "vmlinux matches its pin") {
		t.Errorf("the artifact checks did not run before the gh check:\n%s", out)
	}
}

// TestPublishRefusesAMissingArtifact: there is nothing to upload, and gh's error
// for a missing file names the path without saying how to produce it.
func TestPublishRefusesAMissingArtifact(t *testing.T) {
	lock, dist := publishFixture(t)
	if err := os.Remove(filepath.Join(dist, "vmlinux")); err != nil {
		t.Fatalf("remove vmlinux: %v", err)
	}

	out, err := runPublish(t, lock, dist, os.Getenv("PATH"), "--tag", "guest-images-1")
	if err == nil {
		t.Fatalf("publish ran with vmlinux missing:\n%s", out)
	}
	if !strings.Contains(out, "vmlinux") {
		t.Errorf("refusal does not name the missing artifact:\n%s", out)
	}
}

// TestPublishRefusesArtifactsTheLockDoesNotName: the load-bearing one. The lock
// is what every install verifies its download against, so publishing bytes whose
// digest is not the pinned one would hand every future installer a file that
// fails verification -- with the failure landing on them, not here.
func TestPublishRefusesArtifactsTheLockDoesNotName(t *testing.T) {
	lock, dist := publishFixture(t)
	if err := os.WriteFile(filepath.Join(dist, "vmlinux"), []byte("different bytes\n"), 0o644); err != nil {
		t.Fatalf("rewrite vmlinux: %v", err)
	}

	out, err := runPublish(t, lock, dist, os.Getenv("PATH"), "--tag", "guest-images-1")
	if err == nil {
		t.Fatalf("publish uploaded bytes the lock does not name:\n%s", out)
	}
	for _, want := range []string{"vmlinux", sha256Hex(fetchBodies["vmlinux"])} {
		if !strings.Contains(out, want) {
			t.Errorf("refusal does not name %q:\n%s", want, out)
		}
	}
	// The remedy is a repin, and it has to say so: an operator who believes the
	// new bytes are correct needs images/build-all.sh --repin, not a retry.
	if !strings.Contains(out, "--repin") {
		t.Errorf("refusal does not name the repin path:\n%s", out)
	}
}

// TestPublishRefusesWithoutATag: a release needs a name, and defaulting to one
// would publish under a tag nobody chose.
func TestPublishRefusesWithoutATag(t *testing.T) {
	lock, dist := publishFixture(t)
	out, err := runPublish(t, lock, dist, os.Getenv("PATH"))
	if err == nil {
		t.Fatalf("publish ran with no tag:\n%s", out)
	}
	if !strings.Contains(out, "--tag") {
		t.Errorf("refusal does not name --tag:\n%s", out)
	}
}
