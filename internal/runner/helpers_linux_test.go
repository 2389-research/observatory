// ABOUTME: Linux-only test helpers for the runner package.
// ABOUTME: umask is a syscall not available on non-linux platforms.

//go:build linux

package runner_test

import "syscall"

// umask sets the process umask and returns the previous value.
func umask(mask int) int {
	return syscall.Umask(mask)
}
