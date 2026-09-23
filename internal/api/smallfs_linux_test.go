// ABOUTME: Builds a fresh, real 8 MiB tmpfs filesystem for the full-disk recovery test.
// ABOUTME: Mounting needs CAP_SYS_ADMIN; non-root and EPERM both skip rather than fail.
//go:build linux

package api_test

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

// smallFilesystem mounts a fresh 8 MiB tmpfs and returns its mount point. A
// size-bounded tmpfs still returns ENOSPC once full, the same as a
// disk-backed filesystem. Mounting needs CAP_SYS_ADMIN: not running as root
// skips, EPERM skips naming the missing capability, and any other error
// fails the test.
func smallFilesystem(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("mounting tmpfs needs root")
	}

	mnt := t.TempDir()
	err := syscall.Mount("tmpfs", mnt, "tmpfs", 0, "size=8m")
	if errors.Is(err, syscall.EPERM) {
		t.Skip("mounting tmpfs needs CAP_SYS_ADMIN")
	}
	if err != nil {
		t.Fatalf("mount tmpfs on %s: %v", mnt, err)
	}
	t.Cleanup(func() {
		if err := syscall.Unmount(mnt, 0); err != nil {
			t.Errorf("unmount %s: %v", mnt, err)
		}
	})

	return mnt
}
