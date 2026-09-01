// ABOUTME: Linux peer-credential extraction for unix domain sockets via SO_PEERCRED.
// ABOUTME: Used by the server to authenticate connecting processes by UID.

//go:build linux

package privd

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the effective UID of the peer on a unix domain connection.
func peerUID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return -1, err
	}
	if credErr != nil {
		return -1, credErr
	}
	return int(cred.Uid), nil
}
