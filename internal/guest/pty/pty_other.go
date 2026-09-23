// ABOUTME: Non-Linux stub so the broker compiles and vets on a development Mac.
// ABOUTME: There is no served mode off Linux; a PTY here is a refusal, not a fake.
//go:build !linux

package pty

import (
	"fmt"
	"os"
	"runtime"
)

// errNoPTY is a package variable, not an error built per call: staticcheck
// would otherwise prove both stubs always fail and report the broker's shared
// err checks as always true (SA4023), which holds only off Linux.
var errNoPTY = fmt.Errorf("pty: no pseudo-terminal support on %s", runtime.GOOS)

// Open reports that this platform allocates no PTY. Guest sessions exist only
// inside a Firecracker microVM, which is Linux.
func Open(_, _ uint16) (*os.File, string, error) {
	return nil, "", errNoPTY
}

func setWinsize(_ *os.File, _, _ uint16) error {
	return errNoPTY
}
