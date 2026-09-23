// ABOUTME: Builds a fresh, real 8 MiB HFS+ filesystem for the full-disk recovery test.
// ABOUTME: hdiutil creates and mounts a disk image; detach always runs before its temp dir goes.
//go:build darwin

package api_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// smallFilesystem creates a fresh 8 MiB HFS+ volume and returns its mount
// point. hdiutil missing from PATH skips the test; any other failure fails it
// with the command's output. These commands were checked by hand on this Mac
// as a regular user. HFS+ does not copy on write, so an in-place overwrite
// (the writer's status file) still works once the volume is full.
func smallFilesystem(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("hdiutil"); err != nil {
		t.Skip("hdiutil not on PATH")
	}

	dir := t.TempDir()
	img := filepath.Join(dir, "img.dmg")
	mnt := filepath.Join(dir, "mnt")

	if out, err := exec.Command("hdiutil", "create", "-size", "8m", "-fs", "HFS+", "-volname", "vmobs-enospc", img).CombinedOutput(); err != nil {
		t.Fatalf("hdiutil create: %v\n%s", err, out)
	}
	if err := os.Mkdir(mnt, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", mnt, err)
	}
	if out, err := exec.Command("hdiutil", "attach", "-nobrowse", "-noverify", "-noautoopen", "-mountpoint", mnt, img).CombinedOutput(); err != nil {
		t.Fatalf("hdiutil attach: %v\n%s", err, out)
	}
	// Registered after TempDir's own cleanup, so it runs first (t.Cleanup is
	// LIFO): the volume is detached before its temp dir is removed.
	t.Cleanup(func() {
		if out, err := exec.Command("hdiutil", "detach", "-force", mnt).CombinedOutput(); err != nil {
			t.Errorf("hdiutil detach %s: %v\n%s", mnt, err, out)
		}
	})

	return mnt
}
