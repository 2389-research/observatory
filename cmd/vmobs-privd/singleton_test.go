// ABOUTME: Tests that a second vmobs-privd refuses to start rather than taking a live one's socket or ledger.
// ABOUTME: Real unix sockets, real flocks, no root — the locks are taken before anything is removed or bound.

// flock is a unix call; linux is where privd runs and darwin is where its gate is developed.
//go:build linux || darwin

package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sunPathMax is the size of sockaddr_un.sun_path, including its terminator. A
// socket path that does not fit is refused by bind(2) as EINVAL, which reads as
// "invalid argument" and says nothing about length.
const sunPathMax = 108

// shortTempDir returns a scratch directory whose name is short enough to hold a
// unix socket. shortTempDir(t) embeds the test's own name, and on darwin its
// /var/folders prefix is already 48 characters, so the two together overflow
// sun_path and every bind in this file fails for a reason no message names.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "vmobs-privd")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// flagsFor builds the two paths acquireSingleton cares about, under one root.
func flagsFor(t *testing.T, root string) privdFlags {
	t.Helper()
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", root, err)
	}
	flags := privdFlags{
		socket:    filepath.Join(root, "privd.sock"),
		ledgerDir: filepath.Join(root, "ledger"),
	}
	if len(flags.socket) >= sunPathMax {
		t.Fatalf("socket path is %d bytes, over the %d-byte sun_path limit: %s",
			len(flags.socket), sunPathMax, flags.socket)
	}
	return flags
}

// TestSecondPrivdCannotStealTheSocket is the kata in one test. A unix socket's
// name is not held by the process bound to it, so the old startup path removed
// whatever was there and bound its own: the first privd kept running on a name
// nothing could reach, and every client silently moved to the second.
//
// The assertion that matters is the last one -- not that the second start
// failed, but that the first privd is still reachable after it did.
func TestSecondPrivdCannotStealTheSocket(t *testing.T) {
	flags := flagsFor(t, shortTempDir(t))

	first, err := acquireSingleton(flags)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer first.release()

	ln, err := net.Listen("unix", flags.socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	second, err := acquireSingleton(flags)
	if err == nil {
		second.release()
		t.Fatal("a second privd started against a live one's socket")
	}
	if !strings.Contains(err.Error(), flags.socket) {
		t.Errorf("error %q does not name the socket it refused", err)
	}

	conn, err := net.Dial("unix", flags.socket)
	if err != nil {
		t.Fatalf("the first privd is no longer reachable at %s: %v", flags.socket, err)
	}
	_ = conn.Close()
}

// TestSecondPrivdCannotShareTheLedger: separate socket paths, one ledger
// directory. This is the kata `4fap` hole reopened one layer down -- both
// processes read and write the same entries, but each serializes its claims
// behind its own mutex, so both can see an identity as free and both take it.
// A socket-only guard would let this through.
func TestSecondPrivdCannotShareTheLedger(t *testing.T) {
	root := shortTempDir(t)
	first := flagsFor(t, root)
	second := first
	second.socket = filepath.Join(root, "other.sock")

	held, err := acquireSingleton(first)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer held.release()

	got, err := acquireSingleton(second)
	if err == nil {
		got.release()
		t.Fatal("a second privd started against a live one's ledger directory")
	}
	if !strings.Contains(err.Error(), first.ledgerDir) {
		t.Errorf("error %q does not name the ledger directory it refused", err)
	}
}

// TestTheLockAndTheSocketResolveTogether: privd locks the socket path exactly as
// given, so the lock file and the socket net.Listen binds are always in one
// directory.
//
// The shape below is where lexical cleaning and the kernel disagree. "link" points
// into b/, so the kernel reads link/../sock as b/sock, while filepath.Clean reads
// it as a/sock -- and a privd that cleaned first would take its lock in a/ and then
// bind the socket in b/, on top of a live privd it never noticed. Exotic as a
// command line, ordinary as a deployment: a symlinked run directory plus a
// relative path in a unit file gets there.
func TestTheLockAndTheSocketResolveTogether(t *testing.T) {
	root := shortTempDir(t)
	inner := filepath.Join(root, "b", "inner")
	if err := os.MkdirAll(inner, 0o700); err != nil {
		t.Fatalf("mkdir inner: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "a"), 0o700); err != nil {
		t.Fatalf("mkdir a: %v", err)
	}
	if err := os.Symlink(inner, filepath.Join(root, "a", "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	first := flagsFor(t, root)
	first.socket = filepath.Join(root, "b", "sock")
	second := first
	second.socket = filepath.Join(root, "a", "link") + "/../sock"
	second.ledgerDir = filepath.Join(root, "other-ledger")

	held, err := acquireSingleton(first)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer held.release()

	// Prove the premise before asserting on it: the two spellings really are one
	// socket. Without this the test could pass on a path that never collided.
	if _, err := os.Stat(second.socket + ".lock"); err != nil {
		t.Fatalf("the two spellings do not name one file: %v", err)
	}

	got, err := acquireSingleton(second)
	if err == nil {
		got.release()
		t.Fatal("a second privd took the lock in one directory and would bind the socket in another")
	}
}

// TestTwoIndependentPrivdsAreAllowed: nothing here claims a host may run only
// one privd process. It claims one privd per socket and one per ledger, which is
// what the guarantees rest on. Two complete installs that share neither are two
// separate universes, and a vmobsd pointed at one never reaches the other.
func TestTwoIndependentPrivdsAreAllowed(t *testing.T) {
	root := shortTempDir(t)
	first := flagsFor(t, filepath.Join(root, "a"))
	second := flagsFor(t, filepath.Join(root, "b"))

	held, err := acquireSingleton(first)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer held.release()

	got, err := acquireSingleton(second)
	if err != nil {
		t.Fatalf("second, independent acquire: %v", err)
	}
	got.release()
}

// TestPrivdRestartsAfterRelease: systemd restarts privd on failure and setup.sh
// stops and starts it as routine maintenance. A hold that outlived the process
// would turn the next start into a failure that looks exactly like this guard
// working correctly.
func TestPrivdRestartsAfterRelease(t *testing.T) {
	flags := flagsFor(t, shortTempDir(t))

	first, err := acquireSingleton(flags)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	first.release()

	second, err := acquireSingleton(flags)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	second.release()
}

// TestAcquireSingletonRemovesAStaleSocket: privd removes the socket its
// predecessor left, and it may do so only once it holds the lock -- by then
// nothing else can be listening on the name. This is the same removal the
// startup path always did, moved behind the proof it was always missing.
func TestAcquireSingletonRemovesAStaleSocket(t *testing.T) {
	flags := flagsFor(t, shortTempDir(t))

	stale, err := net.Listen("unix", flags.socket)
	if err != nil {
		t.Fatalf("create stale socket: %v", err)
	}
	// Close without unlinking, the way a killed privd leaves it behind.
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = stale.Close()
	if _, err := os.Stat(flags.socket); err != nil {
		t.Fatalf("stale socket did not survive close: %v", err)
	}

	held, err := acquireSingleton(flags)
	if err != nil {
		t.Fatalf("acquire over a stale socket: %v", err)
	}
	defer held.release()

	if _, err := os.Stat(flags.socket); !os.IsNotExist(err) {
		t.Errorf("stale socket still present after acquire (stat err = %v); listen would fail with EADDRINUSE", err)
	}
}

// TestAcquireSingletonMakesItsLedgerDirectory: systemd's RuntimeDirectory
// creates it on the deployed host, but privd is also started by hand and by the
// gate. It owns the directory its ledger lives in.
func TestAcquireSingletonMakesItsLedgerDirectory(t *testing.T) {
	flags := flagsFor(t, shortTempDir(t))

	held, err := acquireSingleton(flags)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer held.release()

	info, err := os.Stat(flags.ledgerDir)
	if err != nil {
		t.Fatalf("ledger directory absent after acquire: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("%s is not a directory", flags.ledgerDir)
	}
}

// TestSecondPrivdCannotTakeTheSocketWithItsOwnLedger is what the socket lock is
// for. An operator separating the two daemons gives the second its own
// --ledger-dir, which frees the ledger lock; the socket is still one address and
// the first privd is still listening on it.
func TestSecondPrivdCannotTakeTheSocketWithItsOwnLedger(t *testing.T) {
	root := shortTempDir(t)
	first := flagsFor(t, root)
	second := first
	second.ledgerDir = filepath.Join(root, "other-ledger")

	held, err := acquireSingleton(first)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer held.release()

	ln, err := net.Listen("unix", first.socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	got, err := acquireSingleton(second)
	if err == nil {
		got.release()
		t.Fatal("a second privd with its own ledger took a live one's socket")
	}

	conn, err := net.Dial("unix", first.socket)
	if err != nil {
		t.Fatalf("the first privd is no longer reachable at %s: %v", first.socket, err)
	}
	_ = conn.Close()
}

// TestFailedAcquireLetsGoOfTheSocketLock: acquiring takes the socket lock first
// and the ledger lock second, so a failure at the ledger has to give the socket
// back. Keeping it would make one bad --ledger-dir on a hand-started privd wedge
// the address until that process was found and killed -- and the wedge would
// look exactly like this guard doing its job.
func TestFailedAcquireLetsGoOfTheSocketLock(t *testing.T) {
	root := shortTempDir(t)
	good := flagsFor(t, root)

	// A regular file where the ledger directory should be: MkdirAll fails with
	// ENOTDIR, after the socket lock is already held.
	broken := good
	broken.ledgerDir = filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(broken.ledgerDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("plant a file where the ledger directory goes: %v", err)
	}

	if held, err := acquireSingleton(broken); err == nil {
		held.release()
		t.Fatal("acquire succeeded with a regular file as its ledger directory")
	}

	held, err := acquireSingleton(good)
	if err != nil {
		t.Fatalf("acquire after a failed one: %v", err)
	}
	held.release()
}

// TestSecondPrivdIsRefusedThroughASymlinkedLedger: the lock file lives inside
// the ledger directory so that two names for that directory take one lock.
// filepath.Abs cleans a path but does not resolve symlinks, so this is the case
// the placement buys -- a sibling lock file would be two different files and
// both privds would proceed onto one ledger.
func TestSecondPrivdIsRefusedThroughASymlinkedLedger(t *testing.T) {
	root := shortTempDir(t)
	first := flagsFor(t, root)
	if err := os.MkdirAll(first.ledgerDir, 0o700); err != nil {
		t.Fatalf("mkdir ledger: %v", err)
	}

	alias := filepath.Join(root, "ledger-alias")
	if err := os.Symlink(first.ledgerDir, alias); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	second := first
	second.socket = filepath.Join(root, "other.sock")
	second.ledgerDir = alias

	held, err := acquireSingleton(first)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer held.release()

	got, err := acquireSingleton(second)
	if err == nil {
		got.release()
		t.Fatal("a symlink to the ledger directory started a second privd on it")
	}
}

func TestPrivdRefusesWritableLedgerDirectory(t *testing.T) {
	flags := flagsFor(t, shortTempDir(t))
	if err := os.Mkdir(flags.ledgerDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(flags.ledgerDir, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(flags.socket, []byte("predecessor"), 0600); err != nil {
		t.Fatal(err)
	}
	held, err := acquireSingleton(flags)
	if err == nil {
		held.release()
		t.Fatal("privd accepted an untrusted ledger directory")
	}
	if _, err := os.Stat(flags.socket); err != nil {
		t.Fatalf("refusal touched socket: %v", err)
	}
}
