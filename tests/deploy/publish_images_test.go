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

// TestPublishRefusesWithoutGh: gh is how this talks to GitHub at all. Its own
// "command not found" says nothing about what the operator is trying to do.
func TestPublishRefusesWithoutGh(t *testing.T) {
	lock, dist := publishFixture(t)
	// An empty PATH still finds sh's builtins; gh and jq are both gone.
	out, err := runPublish(t, lock, dist, filepath.Join(t.TempDir(), "empty"), "--tag", "guest-images-1")
	if err == nil {
		t.Fatalf("publish ran with no gh on PATH:\n%s", out)
	}
	if !strings.Contains(out, "gh") {
		t.Errorf("refusal does not name gh:\n%s", out)
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
