// ABOUTME: Non-linux stub for peerUID (SO_PEERCRED is linux-specific).
// ABOUTME: Always returns -1 so the server rejects all connections on non-linux platforms.

//go:build !linux

package privd

import (
	"fmt"
	"net"
)

// peerUID is not supported on non-linux platforms.
func peerUID(conn *net.UnixConn) (int, error) {
	return -1, fmt.Errorf("peerUID not supported on this platform")
}

// Ensure the net import is used.
var _ *net.UnixConn
