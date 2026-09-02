// ABOUTME: Linux-only test for applyProcessUmask, which sets vmobs-privd's process
// ABOUTME: umask so the jailer's v.sock inherits group-write permission for the daemon.
//go:build linux

package main

import (
	"syscall"
	"testing"
)

func TestApplyProcessUmask(t *testing.T) {
	// Capture the test process's real original umask via the set-then-restore dance
	// (Umask has no read-only mode: setting is the only way to learn what was there),
	// then restore it immediately so we don't disturb other tests in this binary.
	original := syscall.Umask(0)
	syscall.Umask(original)
	defer syscall.Umask(original)

	// Seed a known, distinguishable umask so applyProcessUmask's return value
	// (the previous umask) can be asserted unambiguously.
	syscall.Umask(0o022)

	prev := applyProcessUmask()
	if prev != 0o022 {
		t.Errorf("applyProcessUmask() returned previous umask %o; want %o", prev, 0o022)
	}

	// Peek the umask now in effect without leaving it disturbed: Umask(0) sets it
	// to 0 and returns what was there, so we restore that value right away.
	got := syscall.Umask(0)
	syscall.Umask(got)
	if got != 0o002 {
		t.Errorf("umask after applyProcessUmask() = %o; want %o", got, 0o002)
	}
}
