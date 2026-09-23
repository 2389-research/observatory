// ABOUTME: Non-linux stub for peerUID (SO_PEERCRED is linux-specific).
// ABOUTME: Always returns -1 so the server rejects all connections on non-linux platforms.

//go:build !linux

package privd

import (
	"errors"
	"net"
)

// errNoPeerCred is a package variable, not an error built per call:
// staticcheck would otherwise prove the stub always fails and report the
// server's shared err check as always true (SA4023), which holds only off Linux.
var errNoPeerCred = errors.New("peerUID not supported on this platform")

// peerUID is not supported on non-linux platforms.
func peerUID(conn *net.UnixConn) (int, error) {
	return -1, errNoPeerCred
}

// Ensure the net import is used.
var _ *net.UnixConn
