// ABOUTME: Unix test helpers for the runner package.
// ABOUTME: umask is a syscall the unix platforms share and Windows does not have.

//go:build unix

package runner_test

import "syscall"

// umask sets the process umask and returns the previous value.
func umask(mask int) int {
	return syscall.Umask(mask)
}
