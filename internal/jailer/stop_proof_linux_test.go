// ABOUTME: doStop must observe the VMM die before anything downstream reads "stopped".
// ABOUTME: A signal sent, and a runner phase claiming terminal, are both claims, not proof.

//go:build linux

package jailer

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/privd"
	"github.com/2389-research/observatory-v2/internal/runner"
	"github.com/2389-research/observatory-v2/internal/runtime"
)

// scriptedPrivd is a privdClient whose signal and release answers the test
// chooses. It embeds unreachablePrivd so the verbs doStop never calls keep
// failing loudly rather than quietly succeeding.
//
// killOnSignal is what separates a signal that worked from one that did not: a
// real privd hands the signal to the kernel, and the whole point of the proof
// gate is that doStop must not take "the call returned" for "the process died".
type scriptedPrivd struct {
	unreachablePrivd

	mu           sync.Mutex
	signals      []string
	signalErr    error
	killOnSignal *os.Process
	releaseErr   error
	releaseCalls int
}

func (p *scriptedPrivd) SignalVM(_ context.Context, req privd.SignalVMReq) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.signals = append(p.signals, req.VMID+"/"+req.Kind)
	if p.signalErr != nil {
		return p.signalErr
	}
	if p.killOnSignal != nil && req.Kind == "kill" {
		_ = p.killOnSignal.Kill()
	}
	return nil
}

func (p *scriptedPrivd) ReleaseVM(_ context.Context, _ privd.ReleaseVMReq) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.releaseCalls++
	return p.releaseErr
}

func (p *scriptedPrivd) snapshot() ([]string, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.signals...), p.releaseCalls
}

// standInVMM spawns a process that stays alive until the test kills it, and
// returns the identity a manifest records for a VMM: pid plus /proc start time.
// A sleep would do, except that a stand-in whose death the test has to observe
// is easier to hold open on a pipe than to race against a timeout.
func standInVMM(t *testing.T) (pid int, starttime string, proc *os.Process) {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", "read line")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start stand-in vmm: %v", err)
	}
	// The stand-in has to leave /proc when it dies, and a child only does that
	// once its parent reaps it. The real VMM is started by privd, daemonized and
	// reparented to init, which reaps it; this goroutine is standing in for init.
	// Without it a killed stand-in lingers as a zombie with its start time
	// intact, the proof gate correctly reports it still alive, and the test reads
	// exactly like the bug it exists to catch.
	reaped := make(chan struct{})
	go func() {
		defer close(reaped)
		_ = cmd.Wait()
	}()
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		<-reaped
	})
	pid = cmd.Process.Pid
	data, err := os.ReadFile(privd.ProcStatPath(pid))
	if err != nil {
		t.Fatalf("read /proc/%d/stat: %v", pid, err)
	}
	starttime = privd.ParseStartTime(string(data))
	if starttime == "" {
		t.Fatalf("stand-in vmm %d has no parseable start time", pid)
	}
	return pid, starttime, cmd.Process
}

// stopProofAdapter is stopOnlyAdapter with a privd whose answers the test picks.
func stopProofAdapter(t *testing.T, pc *scriptedPrivd) *Adapter {
	t.Helper()
	dir := t.TempDir()
	return &Adapter{
		cfg: Config{StateDir: filepath.Join(dir, "state")},
		pc:  pc,
	}
}

// writeLiveVMMManifest writes a manifest naming a live runner and a live VMM,
// which is the only shape where "did the VMM die?" has a real answer.
func writeLiveVMMManifest(t *testing.T, stateDir, vmID string, vmmPID int, vmmStart string) {
	t.Helper()
	m := Manifest{
		VMID:      vmID,
		RunnerPID: spawnRunnerLookalike(t, "--vm-id", vmID),
		VMMPID:    vmmPID,
		VMMStart:  vmmStart,
	}
	if err := writeManifest(stateDir, m); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

// okCtl answers every ctl command OK, so the graceful branch is reached and the
// runner-state file alone decides what the poll observes.
func okCtl(t *testing.T) {
	t.Helper()
	restore := dialCtlFn
	dialCtlFn = func(string, runner.CtlRequest, time.Duration) (runner.CtlReply, error) {
		return runner.CtlReply{OK: true}, nil
	}
	t.Cleanup(func() { dialCtlFn = restore })
}

// TestDoStopRefusesToReportAStopItCouldNotProve: privd accepts both signals and
// the VMM survives them — SIGKILL cannot reap a task in uninterruptible sleep,
// and a privd whose ledger entry is stale signals nothing at all. doStop used to
// discard both SignalVM results and set forced=true regardless, so the manager
// wrote "stopped" and handed the VM's memory back to admission while it ran.
func TestDoStopRefusesToReportAStopItCouldNotProve(t *testing.T) {
	okCtl(t)
	pc := &scriptedPrivd{} // signals answer OK and kill nothing
	a := stopProofAdapter(t, pc)
	pid, start, _ := standInVMM(t)
	writeLiveVMMManifest(t, a.cfg.StateDir, "vm-survives", pid, start)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	_, err := captureStderrErr(t, func() error {
		_, e := a.doStop(ctx, "vm-survives", time.Second, true)
		return e
	})

	var notProven *runtime.ErrStopNotProven
	if !errors.As(err, &notProven) {
		t.Fatalf("doStop err = %v (%T), want *runtime.ErrStopNotProven: a stop nobody observed must not read as one that happened", err, err)
	}
	if notProven.VMID != "vm-survives" {
		t.Errorf("ErrStopNotProven.VMID = %q, want vm-survives", notProven.VMID)
	}
	if !strings.Contains(notProven.Reason, "alive") {
		t.Errorf("reason %q does not say the VMM was still alive", notProven.Reason)
	}

	if !privd.PIDAlive(pid, start) {
		t.Fatal("the stand-in VMM died on its own; this test proved nothing")
	}
	_, releases := pc.snapshot()
	if releases != 0 {
		t.Errorf("release_vm attempts = %d, want 0: the jail chroot of a live VM must not be reclaimed", releases)
	}
}

// TestDoStopCarriesTheSignalFailureIntoTheReason: when privd refuses the signal
// the refusal is the whole explanation of why nothing died, and it was dropped
// into a discarded return value.
func TestDoStopCarriesTheSignalFailureIntoTheReason(t *testing.T) {
	okCtl(t)
	pc := &scriptedPrivd{signalErr: errors.New("privd: no ledger entry for this vm")}
	a := stopProofAdapter(t, pc)
	pid, start, _ := standInVMM(t)
	writeLiveVMMManifest(t, a.cfg.StateDir, "vm-unsignalled", pid, start)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	_, err := captureStderrErr(t, func() error {
		_, e := a.doStop(ctx, "vm-unsignalled", time.Second, true)
		return e
	})

	var notProven *runtime.ErrStopNotProven
	if !errors.As(err, &notProven) {
		t.Fatalf("doStop err = %v (%T), want *runtime.ErrStopNotProven", err, err)
	}
	if !strings.Contains(notProven.Reason, "no ledger entry") {
		t.Errorf("reason %q does not carry privd's refusal, which is the only account of why nothing died", notProven.Reason)
	}
}

// TestDoStopEscalatesWhenThePhaseClaimsTerminalButTheVMMLives: the runner writes
// "finalized" from three places and only one of them looked at the VMM —
// onFinalize answers the ctl command blind, and cleanExit writes it on any
// runner error exit (internal/runner/runner.go). A guest that breaks the channel
// after acking the shutdown reaches "finalized" with its VMM untouched, and the
// graceful poll used to accept that as a completed stop and send no signal at all.
func TestDoStopEscalatesWhenThePhaseClaimsTerminalButTheVMMLives(t *testing.T) {
	okCtl(t)
	pid, start, proc := standInVMM(t)
	pc := &scriptedPrivd{killOnSignal: proc}
	a := stopProofAdapter(t, pc)
	writeLiveVMMManifest(t, a.cfg.StateDir, "vm-phantom", pid, start)

	stateFile := filepath.Join(a.cfg.StateDir, "vms", "vm-phantom", "runner-state.json")
	if err := runner.WriteState(stateFile, runner.State{VMID: "vm-phantom", Phase: runner.PhaseFinalized}); err != nil {
		t.Fatalf("seed runner state: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	var forced bool
	_, err := captureStderrErr(t, func() error {
		var e error
		forced, e = a.doStop(ctx, "vm-phantom", time.Second, false)
		return e
	})
	if err != nil {
		t.Fatalf("doStop: %v", err)
	}
	if !forced {
		t.Error("forced = false: a phase that claims terminal over a live VMM is not a graceful stop")
	}

	signals, _ := pc.snapshot()
	if len(signals) == 0 {
		t.Fatal("no signal was sent: doStop took the runner's word for a death it never observed")
	}
	if privd.PIDAlive(pid, start) {
		t.Error("the VMM is still alive after a stop that returned success")
	}
}

// TestDoStopReportsPendingCleanupWhenTheChrootSurvivesAProvenDeath: the VMM is
// gone, so the compute is genuinely free and the row belongs at "stopped" — but
// the jail chroot and privd's ledger entry are still there. That debt used to go
// to stderr and nowhere else.
func TestDoStopReportsPendingCleanupWhenTheChrootSurvivesAProvenDeath(t *testing.T) {
	okCtl(t)
	pid, start, proc := standInVMM(t)
	pc := &scriptedPrivd{
		killOnSignal: proc,
		releaseErr:   &privd.RemoteError{Cause: "exec_failed", Message: "rm -rf jail dir: permission denied"},
	}
	a := stopProofAdapter(t, pc)
	writeLiveVMMManifest(t, a.cfg.StateDir, "vm-debt", pid, start)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	var forced bool
	_, err := captureStderrErr(t, func() error {
		var e error
		forced, e = a.doStop(ctx, "vm-debt", 0, true)
		return e
	})

	var pending *runtime.ErrCleanupPending
	if !errors.As(err, &pending) {
		t.Fatalf("doStop err = %v (%T), want *runtime.ErrCleanupPending", err, err)
	}
	if !forced {
		t.Error("forced = false after a ForceStop")
	}
	if pending.VMID != "vm-debt" {
		t.Errorf("ErrCleanupPending.VMID = %q, want vm-debt", pending.VMID)
	}
	if pending.Resource == "" {
		t.Error("ErrCleanupPending names no resource, so nothing says what was left behind")
	}
	if !strings.Contains(pending.Reason, "permission denied") {
		t.Errorf("reason %q does not carry privd's error", pending.Reason)
	}
	if privd.PIDAlive(pid, start) {
		t.Error("the VMM is alive: this is the unproven case, not the pending-cleanup one")
	}
}

// TestDoStopOnAProvenDeadVMMSucceeds: the ordinary forced stop. Without it the
// three tests above are satisfied by a doStop that always refuses.
func TestDoStopOnAProvenDeadVMMSucceeds(t *testing.T) {
	okCtl(t)
	pid, start, proc := standInVMM(t)
	pc := &scriptedPrivd{killOnSignal: proc}
	a := stopProofAdapter(t, pc)
	writeLiveVMMManifest(t, a.cfg.StateDir, "vm-clean-kill", pid, start)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	var forced bool
	_, err := captureStderrErr(t, func() error {
		var e error
		forced, e = a.doStop(ctx, "vm-clean-kill", 0, true)
		return e
	})
	if err != nil {
		t.Fatalf("doStop: %v", err)
	}
	if !forced {
		t.Error("forced = false after a ForceStop")
	}
	_, releases := pc.snapshot()
	if releases == 0 {
		t.Error("release_vm was never attempted on a proven-dead VM: the chroot leaks")
	}
}

// TestVMMProvenGoneNeedsAnIdentityOrAnEmptyPid: privd.PIDAlive(pid, "") returns
// false, so a manifest carrying a pid and no start time would read as proof of
// death from a check that never looked at anything. The pid's own absence from
// /proc is proof; its presence with no identity to check against is not.
func TestVMMProvenGoneNeedsAnIdentityOrAnEmptyPid(t *testing.T) {
	pid, start, proc := standInVMM(t)

	if gone, detail := vmmProvenGone(Manifest{VMMPID: pid, VMMStart: start}); gone {
		t.Errorf("a live VMM read as proven gone: %s", detail)
	}
	if gone, detail := vmmProvenGone(Manifest{VMMPID: pid}); gone {
		t.Errorf("a live pid with no recorded start time read as proven gone: %s", detail)
	}
	if gone, _ := vmmProvenGone(Manifest{}); !gone {
		t.Error("a manifest naming no VMM has nothing alive to prove dead, but read as unproven")
	}

	_ = proc.Kill()
	deadline := time.Now().Add(5 * time.Second)
	for privd.PIDAlive(pid, start) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if gone, detail := vmmProvenGone(Manifest{VMMPID: pid, VMMStart: start}); !gone {
		t.Errorf("a dead VMM did not read as proven gone: %s", detail)
	}
}

// captureStderrErr is captureStderr for a body that returns an error.
func captureStderrErr(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	var err error
	out := captureStderr(t, func() { err = fn() })
	return out, err
}
