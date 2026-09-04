// ABOUTME: Non-Linux stub so the broker compiles and vets on a development Mac.
// ABOUTME: There is no served mode off Linux; a PTY here is a refusal, not a fake.
//go:build !linux

package pty

import (
	"fmt"
	"os"
	"runtime"
)

// Open reports that this platform allocates no PTY. Guest sessions exist only
// inside a Firecracker microVM, which is Linux.
func Open(_, _ uint16) (*os.File, string, error) {
	return nil, "", fmt.Errorf("pty: no pseudo-terminal support on %s", runtime.GOOS)
}

func setWinsize(_ *os.File, _, _ uint16) error {
	return fmt.Errorf("pty: no pseudo-terminal support on %s", runtime.GOOS)
}
