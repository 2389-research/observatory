// ABOUTME: InstanceLock: privd's exclusive, non-blocking hold on a path it must own alone.
// ABOUTME: flock-based, so the kernel drops it however the process dies — no stale-pidfile class.
package privd

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// InstanceLock is an exclusive hold on one path, released when the process ends
// however it ends.
//
// It exists because privd's guarantees are per-host, not per-process. Since kata
// `4fap` the ledger refuses a jail uid, a guest CID or a subnet another VM
// already holds, and that refusal is only as good as there being one privd: two
// of them with separate ledgers cannot see each other at all, and two sharing
// one ledger directory still serialize their claims behind separate mutexes, so
// both can read an identity as free and both take it.
//
// flock is the right primitive and a pidfile is not. The hold belongs to the
// open file description, so the kernel releases it when the process exits, is
// killed, or panics -- there is no path where a dead privd keeps the next one
// out. The file itself only records who holds it, for the refusal message.
//
// The descriptor is a bare int rather than an *os.File on purpose. os.File
// carries a cleanup that closes the fd once nothing refers to the file, and
// closing it releases the flock: an *os.File the caller stopped mentioning can
// have privd's hold collected out from under a running daemon, which is the one
// failure this type exists to prevent. Measured on go1.26.6, not assumed. A bare
// fd has no such cleanup, so the hold lasts until Release or process exit and
// the caller has nothing to keep alive.
type InstanceLock struct {
	fd   int
	path string
}

// AcquireInstanceLock takes an exclusive, non-blocking hold on lockPath and
// records the calling pid in it. It fails, naming the holder, when another
// process already holds it.
//
// The directory must exist: a lock helper that created path components would be
// choosing a mode for a directory that is not its own.
func AcquireInstanceLock(lockPath string) (*InstanceLock, error) {
	// O_CLOEXEC is load-bearing, not hygiene. privd execs the jailer, and
	// firecracker execs beneath that; an inherited lock fd would leave a guest
	// holding privd's hold, so a restarted privd would be refused by a VM its
	// predecessor launched.
	fd, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock %s: %w", lockPath, err)
	}

	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		holder := recordedHolder(fd)
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("lock %s is already held by %s: %w", lockPath, holder, err)
	}

	// Replace whatever a previous holder recorded. A pid left by a process that
	// died would name the wrong one in the next refusal.
	if err := syscall.Ftruncate(fd, 0); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("truncate lock %s: %w", lockPath, err)
	}
	if _, err := syscall.Pwrite(fd, []byte(strconv.Itoa(os.Getpid())+"\n"), 0); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("record pid in lock %s: %w", lockPath, err)
	}

	return &InstanceLock{fd: fd, path: lockPath}, nil
}

// Release drops the hold. Releasing twice is not an error; releasing a second
// time must not close an fd number the runtime has since handed to something
// else.
func (l *InstanceLock) Release() error {
	if l == nil || l.fd < 0 {
		return nil
	}
	fd := l.fd
	l.fd = -1
	// Closing the descriptor releases the flock; an explicit LOCK_UN first would
	// only widen the window in which the fd is open and unlocked.
	if err := syscall.Close(fd); err != nil {
		return fmt.Errorf("release lock %s: %w", l.path, err)
	}
	return nil
}

// recordedHolder describes whoever holds the lock, from the pid they wrote into
// it. A refusal that says only "already in use" leaves the operator exactly
// where the silent collision did, so this reports a pid whenever there is one
// and admits it does not know when there is not.
func recordedHolder(fd int) string {
	b := make([]byte, 32)
	n, err := syscall.Pread(fd, b, 0)
	if err != nil || n <= 0 {
		return "another process"
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b[:n])))
	if err != nil || pid <= 0 {
		return "another process"
	}
	return fmt.Sprintf("pid %d", pid)
}
