// ABOUTME: Tests for LoadBootConfig's mount path: the mountpoint must be created if absent.
// ABOUTME: Linux-only, non-root — the mount itself fails EPERM, which is the point.
//go:build linux

package guest_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/2389-research/observatory/internal/guest"
)

// Under systemd, /run is a fresh tmpfs: nothing pre-creates guestd's config
// mountpoint, so LoadBootConfig must create it before mounting. Non-root, the
// mount then fails EPERM. A NOT-ENOENT assertion plus a stat of the directory
// prove MkdirAll ran before mount — ENOENT here was the pre-fix failure mode,
// where mount was attempted against a missing mountpoint.
func TestLoadBootConfigCreatesMountpoint(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the mount could succeed and change the failure mode")
	}
	mountpoint := filepath.Join(t.TempDir(), "vmobs", "config")

	_, err := guest.LoadBootConfig("/dev/null", mountpoint)
	if err == nil {
		t.Fatal("LoadBootConfig succeeded as non-root; expected a mount failure")
	}
	if errors.Is(err, unix.ENOENT) {
		t.Fatalf("mountpoint was not created before mounting: %v", err)
	}
	if st, statErr := os.Stat(mountpoint); statErr != nil || !st.IsDir() {
		t.Fatalf("mountpoint %s missing after LoadBootConfig (stat: %v)", mountpoint, statErr)
	}
}
