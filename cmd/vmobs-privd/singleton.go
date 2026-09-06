// ABOUTME: The exclusive hold vmobs-privd takes on its socket path and ledger directory before it binds.
// ABOUTME: main_linux.go is the only caller; main_other.go is a stub that never starts a daemon.

// flock is a unix call; linux is where privd runs and darwin is where its gate is developed.
//go:build linux || darwin

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/2389-research/observatory-v2/internal/privd"
)

// singleton is privd's proof that it alone owns this socket and this ledger.
type singleton struct {
	socketLock *privd.InstanceLock
	ledgerLock *privd.InstanceLock
}

// acquireSingleton claims the two things a privd must own alone, then clears the
// socket its predecessor left behind.
//
// The order is the fix. The startup path used to remove the socket path
// unconditionally, and a unix socket's name is not held by the process bound to
// it: a second privd unlinked the first one's socket and bound its own, leaving
// the first running on a name nothing could reach while every client silently
// moved to the second. Taking the lock first means the removal happens only once
// nothing else can be listening -- the stale socket is now provably stale.
//
// Two locks because there are two invariants, and one of them is not about the
// socket at all. Since kata `4fap` privd refuses a jail uid, a guest CID or a
// subnet another VM in its ledger already holds, and that refusal assumes every
// claim on the host passes through one process: two privds sharing one ledger
// directory serialize their claims behind separate mutexes, so both can read an
// identity as free and both take it. Neither lock catches two complete installs
// that share nothing, and nothing here claims to -- a vmobsd pointed at one of
// those never reaches the other.
func acquireSingleton(flags privdFlags) (*singleton, error) {
	// The paths are used exactly as given. Cleaning them first would be worse
	// than useless: filepath.Abs resolves ".." lexically while the kernel
	// resolves it after following symlinks, so a cleaned path can name a
	// different file than the one net.Listen binds -- privd would hold a lock in
	// one directory and serve a socket in another. Left alone, the lock, the
	// removal and the bind are all the same string and the kernel resolves all
	// three the same way.
	socketPath, ledgerDir := flags.socket, flags.ledgerDir

	socketLock, err := privd.AcquireInstanceLock(socketPath + ".lock")
	if err != nil {
		return nil, fmt.Errorf("another vmobs-privd owns the socket %s: %w", socketPath, err)
	}

	// privd owns the directory its ledger lives in; on the deployed host
	// systemd's RuntimeDirectory has already made it.
	if err := os.MkdirAll(ledgerDir, 0o700); err != nil {
		_ = socketLock.Release()
		return nil, fmt.Errorf("create ledger directory %s: %w", ledgerDir, err)
	}

	// Inside the directory, not beside it: two names for one directory then take
	// one lock, because the kernel resolves both to a single inode. A sibling
	// <dir>.privd.lock would be two separate files whenever the directory is
	// reached through a symlink.
	ledgerLock, err := privd.AcquireInstanceLock(filepath.Join(ledgerDir, privd.LedgerLockName))
	if err != nil {
		_ = socketLock.Release()
		return nil, fmt.Errorf("another vmobs-privd owns the ledger directory %s: %w", ledgerDir, err)
	}

	// Safe at last: we hold the name, so anything at it belongs to a privd that
	// is gone.
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		_ = ledgerLock.Release()
		_ = socketLock.Release()
		return nil, fmt.Errorf("remove stale socket %s: %w", socketPath, err)
	}

	return &singleton{socketLock: socketLock, ledgerLock: ledgerLock}, nil
}

// release drops both holds. The process exiting would do the same; this is for
// the tests and for the orderly shutdown path.
func (s *singleton) release() {
	if s == nil {
		return
	}
	_ = s.ledgerLock.Release()
	_ = s.socketLock.Release()
}
