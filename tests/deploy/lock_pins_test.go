// ABOUTME: Runs images/lock-pins.sh over fixture pins files, so a source build
// ABOUTME: checks its artifacts against runtime.lock.json instead of rewriting it.
package deploy_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const lockPinsPath = "../../images/lock-pins.sh"

// The digests a matching build produces. Real sha256 values are 64 hex chars;
// these are the right shape so a mismatch message is legible.
const (
	pinnedVmlinux = "1111111111111111111111111111111111111111111111111111111111111111"
	pinnedRootfs  = "2222222222222222222222222222222222222222222222222222222222222222"
	builtVmlinux  = "3333333333333333333333333333333333333333333333333333333333333333"
)

// writePins lays out the images/dist directory the two build scripts leave behind.
func writePins(t *testing.T, dir, vmlinuxSHA, rootfsSHA string) string {
	t.Helper()
	dist := filepath.Join(dir, "dist")
	if err := os.MkdirAll(dist, 0o755); err != nil {
		t.Fatalf("mkdir dist: %v", err)
	}
	kernel := "KERNEL_VERSION=6.1.186\n" +
		"KERNEL_URL=https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.1.186.tar.xz\n" +
		"KERNEL_SHA256=aaaa\nCONFIG_SHA256=bbbb\n" +
		"VMLINUX_SHA256=" + vmlinuxSHA + "\n"
	rootfs := "ROOTFS_SHA256=" + rootfsSHA + "\n" +
		"BASE_IMAGE_REF=ubuntu@sha256:cccc\nAPT_SNAPSHOT=20260820T000000Z\n"
	for name, body := range map[string]string{"kernel.pins": kernel, "rootfs.pins": rootfs} {
		if err := os.WriteFile(filepath.Join(dist, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	// The artifacts themselves; the script refuses when they are missing.
	for _, name := range []string{"vmlinux", "rootfs.ext4"} {
		if err := os.WriteFile(filepath.Join(dist, name), []byte("artifact"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dist
}

// writePinnedLock writes a lock naming pinnedVmlinux and pinnedRootfs, plus a
// published URL that a --repin must carry through untouched.
func writePinnedLock(t *testing.T, dir string) string {
	t.Helper()
	lock := `{
  "schema": "vmobs.runtime_lock.v1",
  "guest_kernel": {
    "version": "6.1.186",
    "source_url": "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.1.186.tar.xz",
    "source_sha256": "aaaa",
    "config_sha256": "bbbb",
    "vmlinux_sha256": "` + pinnedVmlinux + `",
    "vmlinux_path": "images/dist/vmlinux",
    "vmlinux_url": "https://example.invalid/vmlinux"
  },
  "root_image": {
    "sha256": "` + pinnedRootfs + `",
    "path": "images/dist/rootfs.ext4",
    "base_image_ref": "ubuntu@sha256:cccc",
    "apt_snapshot": "20260820T000000Z",
    "inventory": "images/dist/rootfs.inventory.json",
    "url": "https://example.invalid/rootfs.ext4"
  }
}
`
	path := filepath.Join(dir, "runtime.lock.json")
	if err := os.WriteFile(path, []byte(lock), 0o644); err != nil {
		t.Fatalf("write lock: %v", err)
	}
	return path
}

func runLockPins(t *testing.T, lock, dist string, args ...string) (string, error) {
	t.Helper()
	argv := append([]string{lockPinsPath, "--lock", lock, "--dist", dist}, args...)
	out, err := exec.Command("bash", argv...).CombinedOutput()
	return string(out), err
}

// TestLockPinsVerifyPassesWhenTheBuildMatches: the ordinary case. A build that
// reproduces the pinned artifacts is silent about the lock and exits clean.
func TestLockPinsVerifyPassesWhenTheBuildMatches(t *testing.T) {
	dir := t.TempDir()
	dist := writePins(t, dir, pinnedVmlinux, pinnedRootfs)
	lock := writePinnedLock(t, dir)

	out, err := runLockPins(t, lock, dist)
	if err != nil {
		t.Fatalf("verify of a matching build failed: %v\n%s", err, out)
	}
}

// TestLockPinsVerifyFailsAndNamesRepin: the lock is an input, so a build that
// disagrees with it is a finding, not a silent edit. The message has to carry
// both digests and the flag that accepts the new one -- an operator who sees
// only "mismatch" has to go read the script to learn what to do.
func TestLockPinsVerifyFailsAndNamesRepin(t *testing.T) {
	dir := t.TempDir()
	dist := writePins(t, dir, builtVmlinux, pinnedRootfs)
	lock := writePinnedLock(t, dir)

	out, err := runLockPins(t, lock, dist)
	if err == nil {
		t.Fatalf("verify of a mismatched build passed:\n%s", out)
	}
	for _, want := range []string{"vmlinux_sha256", pinnedVmlinux, builtVmlinux, "--repin"} {
		if !strings.Contains(out, want) {
			t.Errorf("mismatch message does not name %q:\n%s", want, out)
		}
	}
}

// TestLockPinsVerifyLeavesTheLockAlone: the defect this whole script exists to
// fix. build-all.sh used to rewrite runtime.lock.json in place, so a stranger's
// first build dirtied the checkout and every image built from it was tagged
// -dirty. Verifying must not write.
func TestLockPinsVerifyLeavesTheLockAlone(t *testing.T) {
	dir := t.TempDir()
	dist := writePins(t, dir, builtVmlinux, pinnedRootfs)
	lock := writePinnedLock(t, dir)

	before, err := os.ReadFile(lock)
	if err != nil {
		t.Fatalf("read lock: %v", err)
	}
	if _, err := runLockPins(t, lock, dist); err == nil {
		t.Fatal("expected the mismatch to fail")
	}
	after, err := os.ReadFile(lock)
	if err != nil {
		t.Fatalf("read lock: %v", err)
	}
	if string(before) != string(after) {
		t.Error("verify rewrote runtime.lock.json; the lock is an input, not an output")
	}
}

// TestRepinWritesTheBuiltDigests: the deliberate kernel bump. --repin takes the
// build's word for the digests and leaves every field it does not own alone --
// notably the published URLs, which a repin has no way to recompute.
func TestRepinWritesTheBuiltDigests(t *testing.T) {
	dir := t.TempDir()
	dist := writePins(t, dir, builtVmlinux, pinnedRootfs)
	lock := writePinnedLock(t, dir)

	out, err := runLockPins(t, lock, dist, "--repin")
	if err != nil {
		t.Fatalf("--repin failed: %v\n%s", err, out)
	}

	raw, err := os.ReadFile(lock)
	if err != nil {
		t.Fatalf("read lock: %v", err)
	}
	got := string(raw)
	if !strings.Contains(got, builtVmlinux) {
		t.Errorf("lock does not carry the built vmlinux digest after --repin:\n%s", got)
	}
	if strings.Contains(got, pinnedVmlinux) {
		t.Errorf("lock still carries the old vmlinux digest after --repin:\n%s", got)
	}
	if !strings.Contains(got, "https://example.invalid/vmlinux") {
		t.Errorf("--repin dropped guest_kernel.vmlinux_url:\n%s", got)
	}
	if !strings.Contains(got, "https://example.invalid/rootfs.ext4") {
		t.Errorf("--repin dropped root_image.url:\n%s", got)
	}
}

// TestLockPinsRefusesAMissingArtifact: pins without the file they describe mean
// a build that half-finished. Verifying those digests would pass and hand the
// installer a lock pointing at nothing.
func TestLockPinsRefusesAMissingArtifact(t *testing.T) {
	dir := t.TempDir()
	dist := writePins(t, dir, pinnedVmlinux, pinnedRootfs)
	lock := writePinnedLock(t, dir)
	if err := os.Remove(filepath.Join(dist, "vmlinux")); err != nil {
		t.Fatalf("remove vmlinux: %v", err)
	}

	out, err := runLockPins(t, lock, dist)
	if err == nil {
		t.Fatalf("verify passed with vmlinux missing:\n%s", out)
	}
	if !strings.Contains(out, "vmlinux") {
		t.Errorf("message does not name the missing artifact:\n%s", out)
	}
}
