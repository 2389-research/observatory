// ABOUTME: The jail's firecracker.pid is a file the guest's uid owns, and privd
// ABOUTME: echoes it: these prove the echo is bounded and cannot carry the file out.

//go:build linux

package privd

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// pidFileMarker sits far enough into the junk that only an unbounded read
// reaches it. A test that finds this string in a message has found privd
// handing out the contents of a file it was told to read a number from.
const pidFileMarker = "MARKER-THAT-MUST-NOT-LEAVE-THE-PID-FILE"

// junkPidFile is what a guest writes into firecracker.pid when it wants privd
// to read something else out loud. The jail root is chowned to the guest's uid
// in step 2 of StartVM, so this file is the guest's to write.
func junkPidFile() []byte {
	junk := bytes.Repeat([]byte("A"), 64)
	junk = append(junk, pidFileMarker...)
	junk = append(junk, bytes.Repeat([]byte("B"), 4096)...)
	return junk
}

// assertBoundedAndSilent fails when a message carries the marker, or when it is
// anywhere near the size of the file it was reporting on. The size check is the
// one that survives a change of marker: an error the length of the pid file is
// an error that read the whole pid file.
func assertBoundedAndSilent(t *testing.T, what, msg string) {
	t.Helper()
	if strings.Contains(msg, pidFileMarker) {
		t.Errorf("%s carries the contents of the pid file:\n%s", what, msg)
	}
	if len(msg) > 512 {
		t.Errorf("%s is %d bytes; privd read past the end of a pid and put it in a message", what, len(msg))
	}
}

// TestStartVMDoesNotEchoAPidFileItCannotParse covers the return path. The error
// travels back over the privd socket to a caller that is not root, so whatever
// it carries has crossed the privilege boundary.
func TestStartVMDoesNotEchoAPidFileItCannotParse(t *testing.T) {
	ops, jailBase, _ := guardOps(t)
	const vmID = "vm-pidfile-start"

	// The jailer is the thing that writes firecracker.pid. Standing in for it
	// with the hook is what lets this test run without root or a real jailer.
	ops.hooks.RunCmd = func([]string) error {
		root := filepath.Join(jailBase, "firecracker", vmID, "root")
		return os.WriteFile(filepath.Join(root, "firecracker.pid"), junkPidFile(), 0o600)
	}

	entry := VMEntry{VMID: vmID, UID: os.Getuid(), GID: os.Getgid()}
	_, err := ops.StartVM(&entry, StartVMReq{VMID: vmID, UID: os.Getuid(), GID: os.Getgid()})
	if err == nil {
		t.Fatal("StartVM accepted a firecracker.pid holding no pid")
	}
	assertBoundedAndSilent(t, "the StartVM error", err.Error())
}

// TestAbortStartDoesNotEchoAPidFileItCannotParse covers the log path. This one
// stays on the host, but privd's log is read by operators and shipped by
// whatever collects the journal, so an unbounded read here spills just as far.
func TestAbortStartDoesNotEchoAPidFileItCannotParse(t *testing.T) {
	ops, jailBase, logBuf := guardOps(t)
	const vmID = "vm-pidfile-abort"

	jailDir := filepath.Join(jailBase, "firecracker", vmID)
	if err := os.MkdirAll(filepath.Join(jailDir, "root"), 0o750); err != nil {
		t.Fatalf("mkdir jail root: %v", err)
	}
	pidFile := filepath.Join(jailDir, "root", "firecracker.pid")
	if err := os.WriteFile(pidFile, junkPidFile(), 0o600); err != nil {
		t.Fatalf("write pid file: %v", err)
	}

	ops.killJailedVMM(jailDir, vmID)
	assertBoundedAndSilent(t, "the abort-start log line", logBuf.String())
}

// TestReadPidFileStopsAtTheBound is the bound itself, tested where it lives.
func TestReadPidFileStopsAtTheBound(t *testing.T) {
	name := filepath.Join(t.TempDir(), "firecracker.pid")
	junk := junkPidFile()
	if err := os.WriteFile(name, junk, 0o600); err != nil {
		t.Fatalf("write pid file: %v", err)
	}

	raw, err := readPidFile(name)
	if err != nil {
		t.Fatalf("readPidFile: %v", err)
	}
	if len(raw) > maxPidFileBytes {
		t.Errorf("readPidFile returned %d bytes of a %d-byte file; the bound is %d", len(raw), len(junk), maxPidFileBytes)
	}
	if strings.Contains(raw, pidFileMarker) {
		t.Errorf("readPidFile reached %d bytes in, past the bound", bytes.Index(junk, []byte(pidFileMarker)))
	}
}

// TestReadPidFileReadsWhatFirecrackerWrites keeps the bound from being a way to
// break the thing it protects: the pid file firecracker actually writes still
// parses.
func TestReadPidFileReadsWhatFirecrackerWrites(t *testing.T) {
	name := filepath.Join(t.TempDir(), "firecracker.pid")
	if err := os.WriteFile(name, []byte("4194303\n"), 0o600); err != nil {
		t.Fatalf("write pid file: %v", err)
	}

	raw, err := readPidFile(name)
	if err != nil {
		t.Fatalf("readPidFile: %v", err)
	}
	if raw != "4194303" {
		t.Errorf("readPidFile = %q, want %q", raw, "4194303")
	}
}

// TestReadPidFileKeepsTrailingBytes pins the half of the contract that decides
// whether the bound can be turned into a weapon. A guest that writes a
// neighbour's pid followed by padding must not have privd read the pid and
// discard the rest: the padding stays, the parse fails, and nothing is signalled.
func TestReadPidFileKeepsTrailingBytes(t *testing.T) {
	name := filepath.Join(t.TempDir(), "firecracker.pid")
	body := append([]byte("4242\n"), bytes.Repeat([]byte("A"), 4096)...)
	if err := os.WriteFile(name, body, 0o600); err != nil {
		t.Fatalf("write pid file: %v", err)
	}

	raw, err := readPidFile(name)
	if err != nil {
		t.Fatalf("readPidFile: %v", err)
	}
	if raw == "4242" {
		t.Fatal("readPidFile stopped at the newline; a pid with padding after it must not parse as that pid")
	}
	if _, err := strconv.Atoi(raw); err == nil {
		t.Errorf("readPidFile returned %q, which parses as a pid", raw)
	}
}
