// ABOUTME: Tests the exclusive hold privd takes on its socket path and its ledger directory.
// ABOUTME: Portable — flock conflicts between two open file descriptions, so one process is enough.
package privd

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestInstanceLockRefusesASecondHolder is the whole point: a second privd asks
// for the same hold and is told no, by pid. flock is held by the open file
// description rather than by the process, so opening the same path twice in one
// process is the same conflict two processes see -- which is why this test needs
// neither a second process nor root.
func TestInstanceLockRefusesASecondHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "privd.lock")

	first, err := AcquireInstanceLock(path)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer func() { _ = first.Release() }()

	second, err := AcquireInstanceLock(path)
	if err == nil {
		_ = second.Release()
		t.Fatal("second acquire succeeded; two privds would both believe they own the host")
	}
	if !strings.Contains(err.Error(), strconv.Itoa(os.Getpid())) {
		t.Errorf("error %q does not name the holder's pid %d", err, os.Getpid())
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q does not name the lock %s", err, path)
	}
}

// TestInstanceLockReleaseFreesIt: privd removes its socket and exits on SIGTERM,
// and systemd restarts it. A hold that outlived the process would turn every
// restart into a failure.
func TestInstanceLockReleaseFreesIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "privd.lock")

	first, err := AcquireInstanceLock(path)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}

	second, err := AcquireInstanceLock(path)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	if err := second.Release(); err != nil {
		t.Fatalf("second release: %v", err)
	}
}

// TestInstanceLockIgnoresAStaleLockFile: the file is a place to record the
// holder, not the hold itself. The kernel drops the flock when the process dies
// however it dies, so a lock file left by a killed privd must not keep the next
// one out -- the failure mode of every pidfile ever written.
func TestInstanceLockIgnoresAStaleLockFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "privd.lock")
	if err := os.WriteFile(path, []byte("999999\n"), 0o600); err != nil {
		t.Fatalf("plant stale lock file: %v", err)
	}

	lock, err := AcquireInstanceLock(path)
	if err != nil {
		t.Fatalf("acquire over a stale lock file: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
}

// TestInstanceLockRecordsItsOwnPID: the pid in the file is what the next privd
// reports to the operator. It has to be written, and it has to replace whatever
// a previous holder left, or the refusal names a process that died long ago.
func TestInstanceLockRecordsItsOwnPID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "privd.lock")
	if err := os.WriteFile(path, []byte("999999999\n"), 0o600); err != nil {
		t.Fatalf("plant stale pid: %v", err)
	}

	lock, err := AcquireInstanceLock(path)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer func() { _ = lock.Release() }()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read lock file: %v", err)
	}
	if got, want := strings.TrimSpace(string(b)), strconv.Itoa(os.Getpid()); got != want {
		t.Errorf("lock file holds %q, want the running pid %q", got, want)
	}
}

// TestInstanceLockFailsWhenTheDirectoryIsMissing: acquiring does not create the
// directory it locks in. privd's caller makes its ledger directory deliberately,
// with the mode it wants; a lock helper that quietly created a path component
// would decide that for it.
func TestInstanceLockFailsWhenTheDirectoryIsMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent", "privd.lock")

	lock, err := AcquireInstanceLock(path)
	if err == nil {
		_ = lock.Release()
		t.Fatal("acquire succeeded in a directory that does not exist")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q does not name the lock it could not open", err)
	}
}

// TestInstanceLockSurvivesCollection: the hold must last until Release or until
// the process ends, and must not depend on the caller still mentioning the
// value. An *os.File would fail this -- its cleanup closes the descriptor once
// nothing refers to the file, and closing it releases the flock, so a daemon
// that acquired a lock and moved on could have its hold collected while it ran.
// The descriptor is a bare int for this reason and this test is why.
func TestInstanceLockSurvivesCollection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "privd.lock")

	// Acquire and drop every reference to the lock.
	func() {
		if _, err := AcquireInstanceLock(path); err != nil {
			t.Fatalf("acquire: %v", err)
		}
	}()
	for i := 0; i < 3; i++ {
		runtime.GC()
	}

	second, err := AcquireInstanceLock(path)
	if err == nil {
		_ = second.Release()
		t.Fatal("the hold was released by garbage collection; a running privd could lose it mid-serve")
	}
}

// TestInstanceLockReleaseIsIdempotent: main releases on its way out and the
// process exit would do the same. A second Release that closed the descriptor
// again would close whatever fd number the runtime had since handed out.
func TestInstanceLockReleaseIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "privd.lock")

	lock, err := AcquireInstanceLock(path)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("first release: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("second release: %v", err)
	}
}

// TestInstanceLockDoesNotSurviveIntoAChild: privd execs the jailer, and
// firecracker execs beneath that. An inherited lock descriptor would leave a
// guest holding privd's hold for as long as the guest lived, so a restarted
// privd would be refused by a VM its own predecessor launched -- and the
// refusal would name a dead pid.
//
// os/exec does not sweep descriptors; it passes stdio plus ExtraFiles and
// relies on everything else carrying O_CLOEXEC. That makes the flag the thing
// preventing this, which is why it is set explicitly and tested here.
func TestInstanceLockDoesNotSurviveIntoAChild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "privd.lock")

	lock, err := AcquireInstanceLock(path)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	// A child started the way privd starts the jailer, outliving the release.
	child := exec.Command("/bin/sh", "-c", "sleep 30")
	if err := child.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
	})

	if err := lock.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}

	second, err := AcquireInstanceLock(path)
	if err != nil {
		t.Fatalf("the hold survived into an exec'd child, so a restart is refused by its own descendant: %v", err)
	}
	if err := second.Release(); err != nil {
		t.Fatalf("release second: %v", err)
	}
}
