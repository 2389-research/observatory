// ABOUTME: Portable /proc scan for the gate's firecracker-process leak observable,
// ABOUTME: kept build-tag-free so its parsing is testable off Linux.

package integration_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// countFirecrackerProcs counts processes under procRoot whose argv[0] names the
// firecracker binary, and reports how many pids it could not read.
//
// It reads <pid>/cmdline, not <pid>/exe. Reading the exe symlink of a process
// owned by another uid returns EACCES, and every jailed Firecracker runs as
// uid 20000+slot while the gate runs as an ordinary user — so the exe-based
// count this replaces was structurally incapable of returning anything but 0,
// and did: run 4's evidence recorded "jail=2 fc_procs=0" beside two VMs that
// had just been asserted running. cmdline is world-readable; this is what ps
// reads to show you other users' command lines.
//
// The match is on argv[0]'s base name, not a substring of the whole command
// line. The runner is started with --uds <JailBase>/firecracker/<id>/root/v.sock,
// so "pgrep -f firecracker" would count every runner as a Firecracker.
//
// A pid that vanishes between the directory listing and the read is not an
// error — processes exit. Anything else is counted as unreadable and returned,
// because a count that silently skips what it cannot see is the defect this
// function exists to remove.
func countFirecrackerProcs(procRoot string) (count, unreadable int, err error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return 0, 0, fmt.Errorf("read %s: %w", procRoot, err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, atoiErr := strconv.Atoi(e.Name()); atoiErr != nil {
			continue // not a pid directory
		}
		raw, readErr := os.ReadFile(filepath.Join(procRoot, e.Name(), "cmdline"))
		if readErr != nil {
			if errors.Is(readErr, os.ErrNotExist) || errors.Is(readErr, syscall.ESRCH) {
				continue // the process exited while we were looking at it
			}
			unreadable++
			continue
		}
		argv0, _, _ := bytes.Cut(raw, []byte{0})
		if len(argv0) == 0 {
			continue // kernel thread or zombie: no argv to read
		}
		if filepath.Base(string(argv0)) == "firecracker" {
			count++
		}
	}
	return count, unreadable, nil
}

// writeProc lays down one synthetic /proc/<pid> directory. cmdline nil means the
// file is absent (a process that exited); mode 0 means present but unreadable.
func writeProc(t *testing.T, procRoot, pid string, cmdline []byte, mode os.FileMode) {
	t.Helper()
	dir := filepath.Join(procRoot, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if cmdline == nil {
		return
	}
	f := filepath.Join(dir, "cmdline")
	if err := os.WriteFile(f, cmdline, 0o644); err != nil {
		t.Fatalf("write %s: %v", f, err)
	}
	if mode != 0o644 {
		if err := os.Chmod(f, mode); err != nil {
			t.Fatalf("chmod %s: %v", f, err)
		}
		t.Cleanup(func() { _ = os.Chmod(f, 0o644) })
	}
}

func argv(parts ...string) []byte {
	var b bytes.Buffer
	for _, p := range parts {
		b.WriteString(p)
		b.WriteByte(0)
	}
	return b.Bytes()
}

// TestCountFirecrackerProcs pins the two ways this observable has been wrong:
// it must not need /proc/<pid>/exe (unreadable for another uid, which made the
// old count structurally zero), and it must not match a runner just because
// "firecracker" appears somewhere in its arguments.
func TestCountFirecrackerProcs(t *testing.T) {
	procRoot := t.TempDir()

	// A jailed Firecracker: argv[0] is the binary inside the chroot, and there is
	// no exe symlink to read.
	writeProc(t, procRoot, "101", argv("/srv/vmobs/jail/firecracker/vm-a/root/firecracker",
		"--id", "vm-a", "--config-file", "fc-config.json"), 0o644)
	writeProc(t, procRoot, "102", argv("/firecracker", "--id", "vm-b"), 0o644)

	// The runner carries the jail path in --uds. "pgrep -f firecracker" counts it;
	// an argv[0] match must not.
	writeProc(t, procRoot, "201", argv("/usr/local/bin/vmobs-runner",
		"--vm-id", "vm-a", "--uds", "/srv/vmobs/jail/firecracker/vm-a/root/v.sock"), 0o644)

	// Noise: a kernel thread (empty cmdline), a process that exited between the
	// listing and the read (no cmdline file), and a non-pid directory.
	writeProc(t, procRoot, "301", []byte{}, 0o644)
	writeProc(t, procRoot, "302", nil, 0o644)
	if err := os.MkdirAll(filepath.Join(procRoot, "self"), 0o755); err != nil {
		t.Fatalf("mkdir self: %v", err)
	}

	count, unreadable, err := countFirecrackerProcs(procRoot)
	if err != nil {
		t.Fatalf("countFirecrackerProcs: %v", err)
	}
	if count != 2 {
		t.Errorf("count = %d, want 2 (two firecracker processes, no exe symlink anywhere)", count)
	}
	if unreadable != 0 {
		t.Errorf("unreadable = %d, want 0", unreadable)
	}
}

// TestCountFirecrackerProcsReportsUnreadable: a pid whose cmdline exists but
// cannot be read is reported, not silently skipped. A count that hides what it
// could not see is the defect this observable had.
func TestCountFirecrackerProcsReportsUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read a 0000-mode file, so this case cannot be staged as root")
	}
	procRoot := t.TempDir()
	writeProc(t, procRoot, "101", argv("/firecracker", "--id", "vm-a"), 0o644)
	writeProc(t, procRoot, "102", argv("/firecracker", "--id", "vm-b"), 0o000)

	count, unreadable, err := countFirecrackerProcs(procRoot)
	if err != nil {
		t.Fatalf("countFirecrackerProcs: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
	if unreadable != 1 {
		t.Errorf("unreadable = %d, want 1 — an unreadable pid must be reported", unreadable)
	}
}

// TestCountFirecrackerProcsMissingRoot: an unreadable proc root is an error, not
// a zero. Zero would read as "no firecracker processes leaked".
func TestCountFirecrackerProcsMissingRoot(t *testing.T) {
	if _, _, err := countFirecrackerProcs(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("countFirecrackerProcs on a missing proc root returned no error")
	}
}
