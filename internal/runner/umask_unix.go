// ABOUTME: Unix umask helper for creating the control socket with mode 0600.
// ABOUTME: Needed on darwin and linux; not available on Windows.

//go:build darwin || linux

package runner

import "syscall"

// applyUmask sets the process umask to mask and returns the old value.
func applyUmask(mask int) int {
	return syscall.Umask(mask)
}
