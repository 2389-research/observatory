// ABOUTME: Tests the jail-identity guard on AbortStartVM's kill: a stale pid file can name
// ABOUTME: another VM's firecracker, and SIGKILLing a healthy neighbour is worse than a leak.

//go:build linux

package privd

import (
	"bytes"
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeFirecracker is a live process the kernel records as "firecracker".
// exited is closed once the process has been reaped, so every reader sees it.
type fakeFirecracker struct {
	pid    int
	exited chan struct{}
}

// spawnFakeFirecracker starts a long-lived process whose comm reads
// "firecracker". comm comes from the basename of the path handed to execve, so a
// symlink of that name over any harmless binary is enough — and it has to be a
// real running process, because the guard reads /proc to identify it.
func spawnFakeFirecracker(t *testing.T) *fakeFirecracker {
	t.Helper()
	sleepBin, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatalf("no sleep binary to stand in for firecracker: %v", err)
	}
	link := filepath.Join(t.TempDir(), "firecracker")
	if err := os.Symlink(sleepBin, link); err != nil {
		t.Fatalf("symlink %s -> %s: %v", link, sleepBin, err)
	}
	/* #nosec G204 — link is a temp-dir symlink this test just created. */
	cmd := exec.Command(link, "120") //nolint:gosec
	if err := cmd.Start(); err != nil {
		t.Fatalf("start fake firecracker: %v", err)
	}
	f := &fakeFirecracker{pid: cmd.Process.Pid, exited: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(f.exited)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-f.exited:
		case <-time.After(5 * time.Second):
			t.Errorf("fake firecracker pid %d did not exit after the cleanup kill", f.pid)
		}
	})

	// The premise. Without comm reading "firecracker" the guard short-circuits
	// before the check under test and every assertion below proves nothing.
	statData, err := os.ReadFile(ProcStatPath(f.pid))
	if err != nil {
		t.Fatalf("read %s: %v", ProcStatPath(f.pid), err)
	}
	if comm := ParseComm(string(statData)); comm != "firecracker" {
		t.Fatalf("comm of the stand-in process = %q, want \"firecracker\": the kernel takes comm from "+
			"the basename of the execve path, and without it this test never reaches the jail check", comm)
	}
	return f
}

// alive reports whether the process is still running. Presence in /proc is not
// enough: a SIGKILLed child stays there as a zombie until it is reaped, with its
// start time unchanged, so PIDAlive would call it alive.
func (f *fakeFirecracker) alive(t *testing.T) bool {
	t.Helper()
	select {
	case <-f.exited:
		return false
	case <-time.After(500 * time.Millisecond):
		return true
	}
}

// guardOps builds a RealOps over a temp jail base with its log captured.
func guardOps(t *testing.T) (*RealOps, string, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	jailBase := filepath.Join(dir, "jail")
	if err := os.MkdirAll(jailBase, 0o750); err != nil {
		t.Fatalf("mkdir jail base: %v", err)
	}
	ops := NewRealOps(RealOpsCfg{JailBase: jailBase, StageRoot: filepath.Join(dir, "stage")})
	var buf bytes.Buffer
	ops.log = log.New(&buf, "", 0)
	return ops, jailBase, &buf
}

// writeJailedPID builds the jail tree a failed start leaves behind and writes pid
// into its firecracker.pid — the only thing in that tree that names a process.
func writeJailedPID(t *testing.T, jailBase, vmID string, pid int) string {
	t.Helper()
	jailDir := filepath.Join(jailBase, "firecracker", vmID)
	root := filepath.Join(jailDir, "root")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatalf("mkdir jail root: %v", err)
	}
	pidFile := filepath.Join(root, "firecracker.pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		t.Fatalf("write pid file: %v", err)
	}
	return jailDir
}

// stubProcRootLink replaces the /proc/<pid>/root resolver for one test. The
// matching case needs a chrooted process, which an unprivileged test cannot
// create, so the resolver stands in for the kernel there.
func stubProcRootLink(t *testing.T, fn func(pid int) (string, error)) {
	t.Helper()
	prev := procRootLink
	procRootLink = fn
	t.Cleanup(func() { procRootLink = prev })
}

// TestAbortStartVMSparesAnotherVMsFirecracker is the finding. StartVM's MkdirAll
// does not clear the tree, so a failed start's firecracker.pid survives into the
// next attempt; pids recycle; and on a host whose whole job is running
// firecrackers, the process that inherits the pid is often another VM's VMM. comm
// cannot tell them apart. Nothing here is chrooted into this VM's jail, so
// nothing here may be killed.
func TestAbortStartVMSparesAnotherVMsFirecracker(t *testing.T) {
	ops, jailBase, logBuf := guardOps(t)
	fc := spawnFakeFirecracker(t)
	writeJailedPID(t, jailBase, "vm-recycled", fc.pid)

	if err := ops.AbortStartVM(VMEntry{VMID: "vm-recycled"}); err != nil {
		t.Fatalf("AbortStartVM: %v", err)
	}
	if !fc.alive(t) {
		t.Fatalf("the rollback SIGKILLed pid %d, a live firecracker running outside this VM's jail; "+
			"killing a healthy neighbour is worse than the leak this rollback exists to prevent (log: %q)",
			fc.pid, logBuf.String())
	}
}

// TestAbortStartVMKillsTheFirecrackerInItsOwnJail: the guard must still let the
// kill through for the process it exists to reap. A firecracker started by a
// start_vm that then failed is recorded nowhere — the ledger keeps PID 0 and the
// manifest is written only after start_vm returns — so if this rollback does not
// kill it, nothing ever will.
func TestAbortStartVMKillsTheFirecrackerInItsOwnJail(t *testing.T) {
	ops, jailBase, logBuf := guardOps(t)
	fc := spawnFakeFirecracker(t)
	jailDir := writeJailedPID(t, jailBase, "vm-own", fc.pid)

	stubProcRootLink(t, func(pid int) (string, error) {
		if pid != fc.pid {
			t.Errorf("guard resolved /proc/%d/root; want the pid the jail's pid file names (%d)", pid, fc.pid)
		}
		return filepath.Join(jailDir, "root"), nil
	})

	if err := ops.AbortStartVM(VMEntry{VMID: "vm-own"}); err != nil {
		t.Fatalf("AbortStartVM: %v", err)
	}
	if fc.alive(t) {
		t.Errorf("pid %d is chrooted into this VM's own jail and survived the rollback (log: %q)",
			fc.pid, logBuf.String())
	}
}

// TestAbortStartVMWithholdsTheKillWhenTheJailCannotBeRead: a resolver that fails
// — the process exited between the two reads, or /proc refused — proves nothing
// about identity, so it withholds the kill like every other failure here, and
// says so.
func TestAbortStartVMWithholdsTheKillWhenTheJailCannotBeRead(t *testing.T) {
	ops, jailBase, logBuf := guardOps(t)
	fc := spawnFakeFirecracker(t)
	writeJailedPID(t, jailBase, "vm-unreadable", fc.pid)

	stubProcRootLink(t, func(int) (string, error) {
		return "", errors.New("injected: permission denied")
	})

	if err := ops.AbortStartVM(VMEntry{VMID: "vm-unreadable"}); err != nil {
		t.Fatalf("AbortStartVM: %v", err)
	}
	if !fc.alive(t) {
		t.Error("an unresolvable /proc/<pid>/root let the kill through; unproven identity must withhold it")
	}
	if !strings.Contains(logBuf.String(), strconv.Itoa(fc.pid)) {
		t.Errorf("log = %q; a withheld kill has to name the pid it left running", logBuf.String())
	}
}
