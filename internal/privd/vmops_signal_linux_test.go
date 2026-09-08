// ABOUTME: The signal paths aim a descriptor, not a pid: these prove one is taken,
// ABOUTME: given back, and that a failed identity check leaves the process running.

//go:build linux

package privd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pidfdCount reports how many of this process's open descriptors are pidfds.
// The link target the kernel gives them is the only thing that names them; there
// is no fcntl that says "this is a pidfd".
//
// It is never zero in this package's tests: every exec.Cmd holds one for its
// child, so assertions here are on the delta and never on the absolute count.
func pidfdCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	n := 0
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err != nil {
			continue // the fd from ReadDir itself, already closed
		}
		if strings.Contains(target, "pidfd") {
			n++
		}
	}
	return n
}

// TestOpenProcessTakesAPidfd is a canary on the mechanism every signal in this
// package rests on. os.FindProcess calls pidfd_open on Linux 5.3 and later, and
// os.Process.Signal then routes through pidfd_send_signal instead of kill(2) --
// which is what makes a signal aimed at a descriptor rather than at a number
// another process could inherit.
//
// None of that is in privd's source, so nothing else here would notice it going
// away: a kernel too old for pidfd_open, or a future standard library that stops
// asking for one, silently returns the signal paths to naming processes by pid.
// This test fails when that happens.
func TestOpenProcessTakesAPidfd(t *testing.T) {
	f := spawnFakeFirecracker(t, "--id", "vm-pidfd-001")

	before := pidfdCount(t)
	p, err := openProcess(f.pid)
	if err != nil {
		t.Fatalf("openProcess(%d): %v", f.pid, err)
	}
	after := pidfdCount(t)
	if after != before+1 {
		t.Errorf("openProcess took %d pidfds (%d -> %d), want exactly 1: the signal paths "+
			"are naming this process by its pid, not by a descriptor", after-before, before, after)
	}

	if err := p.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if got := pidfdCount(t); got != before {
		t.Errorf("after Release the pidfd count is %d, want %d back at the starting count", got, before)
	}
}

// TestOpenProcessRefusesAPidThatIsGone proves the descriptor fails closed. A
// reaped process has no struct pid left to open, so there is nothing to signal
// and nothing to mistake for the process that inherits its number next.
func TestOpenProcessRefusesAPidThatIsGone(t *testing.T) {
	f := spawnFakeFirecracker(t, "--id", "vm-pidfd-002")
	pid := f.pid
	if err := f.cmd.Process.Kill(); err != nil {
		t.Fatalf("kill the stand-in: %v", err)
	}
	<-f.exited // reaped by spawnFakeFirecracker's goroutine

	p, err := openProcess(pid)
	if err == nil {
		_ = p.Release()
		t.Fatalf("openProcess(%d) succeeded for a reaped process; a signal through it would land "+
			"on whatever inherits that pid", pid)
	}
}

// TestSignalVMKillsTheProcessTheLedgerNames is the delivery half: the whole
// point of the identity gate is that it lets the real signal through.
func TestSignalVMKillsTheProcessTheLedgerNames(t *testing.T) {
	ops, _, _ := guardOps(t)
	f := spawnFakeFirecracker(t, "--id", "vm-signal-001")

	statData, err := os.ReadFile(ProcStatPath(f.pid))
	if err != nil {
		t.Fatalf("read %s: %v", ProcStatPath(f.pid), err)
	}
	boot, ns := recoveryHost(t)
	entry := VMEntry{BootID: boot, PIDNamespace: ns, VMID: "vm-signal-001", PID: f.pid, StartTime: ParseStartTime(string(statData))}

	if err := ops.SignalVM(entry, "kill"); err != nil {
		t.Fatalf("SignalVM: %v", err)
	}
	if f.alive(t) {
		t.Errorf("pid %d survived a SignalVM(kill) whose ledger entry names it", f.pid)
	}
}

// TestSignalVMSignalsNothingWhenTheIdentityIsWrong pins the order the fix is
// about. Taking a descriptor first is only safe because the checks still run
// before the signal does: a version that opened the process and signalled it,
// leaving the starttime compare for afterwards, would kill a healthy VMM on
// every stale ledger entry. The refusal alone does not say that -- the process
// has to still be running when it returns.
func TestSignalVMSignalsNothingWhenTheIdentityIsWrong(t *testing.T) {
	ops, _, _ := guardOps(t)
	f := spawnFakeFirecracker(t, "--id", "vm-signal-002")

	boot, ns := recoveryHost(t)
	entry := VMEntry{BootID: boot, PIDNamespace: ns, VMID: "vm-signal-002", PID: f.pid, StartTime: "99999999"}

	err := ops.SignalVM(entry, "kill")
	if err == nil {
		t.Fatal("SignalVM with a mismatched starttime returned nil")
	}
	var be *BackendError
	if !AsBackendError(err, &be) {
		t.Fatalf("expected BackendError, got %T: %v", err, err)
	}
	if be.Cause != "invalid_state" {
		t.Errorf("cause = %q, want invalid_state", be.Cause)
	}
	if !f.alive(t) {
		t.Errorf("SignalVM refused the mismatched entry but pid %d died anyway: the signal is "+
			"reaching the process before the identity check does", f.pid)
	}
}

// TestSignalPathsGiveBackTheirDescriptors. privd is a long-lived root daemon;
// a descriptor leaked once per signal is a descriptor leaked once per stop, and
// the file it eventually cannot open is the next VM's kernel image.
//
// Both routes are driven down their refusing branch on purpose: a descriptor is
// taken before either one knows whether it will signal, so the leak they are
// capable of is the leak this measures, and the stand-in stays alive to be
// signalled again.
func TestSignalPathsGiveBackTheirDescriptors(t *testing.T) {
	ops, jailBase, _ := guardOps(t)
	f := spawnFakeFirecracker(t, "--id", "vm-signal-003")

	boot, ns := recoveryHost(t)
	stale := VMEntry{BootID: boot, PIDNamespace: ns, VMID: "vm-signal-003", PID: f.pid, StartTime: "99999999"}
	// The pid file names our stand-in, but the jail dir belongs to another VM,
	// so the argv check withholds the kill.
	writeJailedPID(t, jailBase, "vm-signal-neighbour", f.pid)

	before := pidfdCount(t)
	for i := 0; i < 50; i++ {
		if err := ops.SignalVM(stale, "term"); err == nil {
			t.Fatalf("SignalVM with a stale entry returned nil on iteration %d", i)
		}
		ops.killJailedVMM("vm-signal-neighbour")
	}
	if !f.alive(t) {
		t.Fatal("the stand-in died during the leak loop; both routes were supposed to refuse")
	}
	if got := pidfdCount(t); got != before {
		t.Errorf("pidfd count %d -> %d over 100 signal attempts; the signal paths are leaking "+
			"descriptors", before, got)
	}
}

// TestNoSignalIsSentByPid is the only thing that can state the property the
// other tests here rest on. Whether a signal went through a descriptor or
// through a pid number is invisible from outside unless the pid is recycled
// mid-call, and forcing that needs privileges privd's tests do not have -- so
// every behavioural test in this file passes just as well against a version
// that opens a descriptor, checks it, and then signals the bare pid anyway.
//
// This one reads the source instead. kill(2) by pid has no legitimate caller
// left in this package; a new one is the mutation the rest of the file cannot
// see.
func TestNoSignalIsSentByPid(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, banned := range []string{"unix.Kill(", "syscall.Kill("} {
			if strings.Contains(string(src), banned) {
				t.Errorf("%s calls %s: signal a process through the descriptor openProcess "+
					"returns, so the process signalled is the process that was checked", name, banned)
			}
		}
	}
}
