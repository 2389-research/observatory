// ABOUTME: Reconcile's adoption verdict, staged from manifests and live processes.
// ABOUTME: A runner is this VM's only when its own argv says so.

//go:build linux

package jailer_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/jailer"
	"github.com/2389-research/observatory/internal/network"
	"github.com/2389-research/observatory/internal/preflight"
	"github.com/2389-research/observatory/internal/privd"
	"github.com/2389-research/observatory/internal/runner"
)

// startBlocker starts a process that holds the given trailing argv for as long as
// the test needs it, and returns it unstarted-for-cleanup by the caller.
//
// The argv has to survive: Reconcile reads it after the fixture has written files
// and built an adapter, not microseconds after the spawn. `sleep 300 --vm-id x`
// does not survive — sleep rejects the flag and exits immediately, and the zombie
// it leaves has a live /proc/<pid>/stat with an empty cmdline, which is precisely
// the shape that reads as "alive, identity unknown" and gets adopted. A shell
// passes the words after its script through as positional parameters instead, and
// blocks in the `read` builtin on a pipe nobody writes to.
func startBlocker(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("/bin/sh", append([]string{"-c", "read line", "vmobs-runner"}, args...)...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn: %v", err)
	}
	t.Cleanup(func() { _ = stdin.Close() })
	return cmd
}

// spawnWithArgv starts a long-lived process with the given trailing argv and
// returns its pid and start time, read while it is alive.
func spawnWithArgv(t *testing.T, args ...string) (int, string) {
	t.Helper()
	cmd := startBlocker(t, args...)
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	pid := cmd.Process.Pid
	waitForArgv(t, pid)
	data, err := os.ReadFile(privd.ProcStatPath(pid))
	if err != nil {
		t.Fatalf("read /proc/%d/stat: %v", pid, err)
	}
	return pid, privd.ParseStartTime(string(data))
}

// reapedWithStart spawns, records identity, kills and reaps: a pid that is gone.
func reapedWithStart(t *testing.T, args ...string) (int, string) {
	t.Helper()
	cmd := startBlocker(t, args...)
	pid := cmd.Process.Pid
	waitForArgv(t, pid)
	data, err := os.ReadFile(privd.ProcStatPath(pid))
	if err != nil {
		t.Fatalf("read /proc/%d/stat: %v", pid, err)
	}
	start := privd.ParseStartTime(string(data))
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	return pid, start
}

// waitForArgv fails the test unless the pid is a live process with a readable
// argv. A fixture that dies early does not fail an adoption assertion — it moves
// the assertion onto a different branch, where a zombie reads alive and unnamed —
// so the fixture is checked here rather than trusted.
func waitForArgv(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil && len(data) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pid %d has no readable cmdline 5s after starting; the fixture is not a live process", pid)
}

// adoptionFixture writes one VM's manifest and runner state into a fresh state
// dir and returns an adapter over it. RunnerBin points at nothing: a VM whose
// runner is not adoptable falls through to a respawn, and this suite is about the
// verdict, not the repair.
func adoptionFixture(t *testing.T, vmID string, m jailer.Manifest, s runner.State) *jailer.Adapter {
	t.Helper()
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	vmStateDir := filepath.Join(stateDir, "vms", vmID)
	if err := os.MkdirAll(vmStateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := jailer.WriteManifestExported(stateDir, m); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vmStateDir, "runner-state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	pool, err := network.NewAllocator(nil, []netip.Prefix{netip.MustParsePrefix("10.93.0.0/24")})
	if err != nil {
		t.Fatal(err)
	}
	cfg := jailer.Config{
		StateDir:    stateDir,
		StageRoot:   filepath.Join(dir, "stage"),
		JailBase:    filepath.Join(dir, "jail"),
		SpoolRoot:   filepath.Join(dir, "spool"),
		RunnerBin:   filepath.Join(dir, "no-such-runner"),
		RepoRoot:    filepath.Join(dir, "images"),
		LockPath:    filepath.Join(dir, "lock.json"),
		PrivdSocket: filepath.Join(dir, "privd.sock"),
		JailUIDBase: os.Getuid(),
		JailGID:     os.Getgid(),
		MaxSlots:    8,
		CIDBase:     5,
		Allocator:   pool,
		Preflight: func(context.Context, bool) preflight.Report {
			return preflight.Report{Overall: preflight.StatusPass}
		},
	}
	a, err := jailer.New(cfg, &privd.Client{SocketPath: cfg.PrivdSocket})
	if err != nil {
		t.Fatalf("jailer.New: %v", err)
	}
	return a
}

func outcomeFor(t *testing.T, a *jailer.Adapter, vmID string) jailer.Finding {
	t.Helper()
	findings, err := a.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	for _, f := range findings {
		if f.VMID == vmID {
			return f
		}
	}
	t.Fatalf("no Finding for %s (findings: %v)", vmID, findings)
	return jailer.Finding{}
}

// stagedManifest describes a VM whose launch completed: VMM up, runner spawned.
func stagedManifest(vmID string, vmmPID int, vmmStart string, runnerPID int, runnerStart string) jailer.Manifest {
	return jailer.Manifest{
		VMID:        vmID,
		BootID:      "boot-1",
		Slot:        0,
		UID:         os.Getuid(),
		GID:         os.Getgid(),
		CID:         5,
		CIDR:        "10.93.0.0/30",
		VMMPID:      vmmPID,
		VMMStart:    vmmStart,
		RunnerPID:   runnerPID,
		RunnerStart: runnerStart,
		Stages:      []string{"reserved", "staged", "network", "vmm_started", "runner_spawned", "attached"},
	}
}

func attachedState(vmID string, runnerPID, vmmPID int, vmmStart string) runner.State {
	return runner.State{
		VMID:         vmID,
		BootID:       "boot-1",
		InstanceID:   "inst-1",
		RunnerPID:    runnerPID,
		VMMPID:       vmmPID,
		VMMStartTime: vmmStart,
		Phase:        runner.PhaseAttached,
	}
}

// TestReconcileAdoptsARunnerThatNamesThisVM: the daemon restarted, the VMM and its
// runner did not. This is the case a controller restart must not turn into a
// failed row.
func TestReconcileAdoptsARunnerThatNamesThisVM(t *testing.T) {
	const vmID = "vm-ours"
	vmmPID, vmmStart := spawnWithArgv(t, "firecracker-stand-in")
	runnerPID, runnerStart := spawnWithArgv(t, "--vm-id", vmID, "--ping-interval", "5s")

	a := adoptionFixture(t, vmID,
		stagedManifest(vmID, vmmPID, vmmStart, runnerPID, runnerStart),
		attachedState(vmID, runnerPID, vmmPID, vmmStart))

	if f := outcomeFor(t, a, vmID); f.Outcome != "adopted" {
		t.Errorf("outcome = %q, want adopted (detail: %s)", f.Outcome, f.Detail)
	}
}

// TestReconcileDoesNotAdoptAnotherVMsRunner is the recycled-pid case with teeth: the
// pid in the manifest is alive, its start time matches, and its runner state file
// says attached — every check but the argv agrees. Adopting it leaves this VM's row
// reading running with no runner behind it and no one watching the microVM.
func TestReconcileDoesNotAdoptAnotherVMsRunner(t *testing.T) {
	const vmID = "vm-ours"
	vmmPID, vmmStart := spawnWithArgv(t, "firecracker-stand-in")
	runnerPID, runnerStart := spawnWithArgv(t, "--vm-id", "vm-theirs")

	a := adoptionFixture(t, vmID,
		stagedManifest(vmID, vmmPID, vmmStart, runnerPID, runnerStart),
		attachedState(vmID, runnerPID, vmmPID, vmmStart))

	if f := outcomeFor(t, a, vmID); f.Outcome == "adopted" {
		t.Errorf("outcome = adopted for a pid running vm-theirs (detail: %s)", f.Detail)
	}
}

// TestReconcileDoesNotAdoptADeadRunner: the VMM outlived the controller but its
// runner did not, so nothing is draining the guest's telemetry. That VM needs a
// fresh runner, which is a repair — never an adoption of what is already there.
func TestReconcileDoesNotAdoptADeadRunner(t *testing.T) {
	const vmID = "vm-ours"
	vmmPID, vmmStart := spawnWithArgv(t, "firecracker-stand-in")
	runnerPID, runnerStart := reapedWithStart(t, "--vm-id", vmID)

	a := adoptionFixture(t, vmID,
		stagedManifest(vmID, vmmPID, vmmStart, runnerPID, runnerStart),
		attachedState(vmID, runnerPID, vmmPID, vmmStart))

	f := outcomeFor(t, a, vmID)
	if f.Outcome == "adopted" {
		t.Errorf("outcome = adopted for a reaped runner pid (detail: %s)", f.Detail)
	}
	// The respawn is what should have been attempted, and it cannot succeed with
	// no runner binary — so the detail has to name that, not something else.
	if f.Outcome != "ambiguous" {
		t.Errorf("outcome = %q, want ambiguous once the respawn fails (detail: %s)", f.Outcome, f.Detail)
	}
}

// TestReconcileDoesNotAdoptWhenTheRunnerIsNotAttached: a runner still starting has
// not reached the VMM yet, and one that saw the VMM exit is reporting the opposite
// of health. Neither is a runner to adopt.
func TestReconcileDoesNotAdoptWhenTheRunnerIsNotAttached(t *testing.T) {
	for _, phase := range []string{runner.PhaseStarting, runner.PhaseDegraded, runner.PhaseVMMExited, runner.PhaseFinalized} {
		t.Run(phase, func(t *testing.T) {
			const vmID = "vm-ours"
			vmmPID, vmmStart := spawnWithArgv(t, "firecracker-stand-in")
			runnerPID, runnerStart := spawnWithArgv(t, "--vm-id", vmID)

			s := attachedState(vmID, runnerPID, vmmPID, vmmStart)
			s.Phase = phase
			a := adoptionFixture(t, vmID,
				stagedManifest(vmID, vmmPID, vmmStart, runnerPID, runnerStart), s)

			if f := outcomeFor(t, a, vmID); f.Outcome == "adopted" {
				t.Errorf("outcome = adopted for a runner in phase %q (detail: %s)", phase, f.Detail)
			}
		})
	}
}

// TestReconcileDoesNotAdoptWhenTheVMMIsGone: no argv check rescues a VM whose
// microVM has exited. The runner is alive and naming this VM, and the answer is
// still that the VM is gone.
func TestReconcileDoesNotAdoptWhenTheVMMIsGone(t *testing.T) {
	const vmID = "vm-ours"
	vmmPID, vmmStart := reapedWithStart(t, "firecracker-stand-in")
	runnerPID, runnerStart := spawnWithArgv(t, "--vm-id", vmID)

	a := adoptionFixture(t, vmID,
		stagedManifest(vmID, vmmPID, vmmStart, runnerPID, runnerStart),
		attachedState(vmID, runnerPID, vmmPID, vmmStart))

	if f := outcomeFor(t, a, vmID); f.Outcome != "vmm_gone" {
		t.Errorf("outcome = %q, want vmm_gone (detail: %s)", f.Outcome, f.Detail)
	}
}
