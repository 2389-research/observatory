// ABOUTME: Tests that the runner liveness check is an identity check, not a pid lookup.
// ABOUTME: A recycled pid must read dead; a manifest with no recorded start time must not.

//go:build linux

package jailer

import (
	"os"
	"os/exec"
	"strconv"
	"testing"

	"github.com/2389-research/observatory-v2/internal/privd"
)

// TestReadRunnerStartMatchesProc: the value the spawn sites record must be the same
// field privd.PIDAlive later compares against, or every liveness check answers no.
func TestReadRunnerStartMatchesProc(t *testing.T) {
	pid := os.Getpid()

	got := readRunnerStart(pid)
	if got == "" {
		t.Fatalf("readRunnerStart(%d) = %q; the test process is running, so its start time is readable", pid, got)
	}
	if _, err := strconv.ParseUint(got, 10, 64); err != nil {
		t.Errorf("readRunnerStart(%d) = %q, not a clock-ticks count: %v", pid, got, err)
	}

	data, err := os.ReadFile(privd.ProcStatPath(pid))
	if err != nil {
		t.Fatalf("read %s: %v", privd.ProcStatPath(pid), err)
	}
	if want := privd.ParseStartTime(string(data)); got != want {
		t.Errorf("readRunnerStart(%d) = %q, want %q (the field privd.PIDAlive compares)", pid, got, want)
	}
}

// TestReadRunnerStartOnADeadPID: the spawn sites assign this unconditionally, so an
// unreadable /proc entry has to come back empty rather than as some previous value.
func TestReadRunnerStartOnADeadPID(t *testing.T) {
	if got := readRunnerStart(reapedPID(t)); got != "" {
		t.Errorf("readRunnerStart on a reaped pid = %q, want \"\"", got)
	}
}

// TestRunnerAliveRejectsARecycledPID is the point of the whole field. A pid the
// kernel has handed to another process is exactly a live /proc/<pid> whose start
// time does not match the manifest, and the old check — a bare stat of /proc/<pid> —
// called that the runner. doStop would then try a graceful shutdown through a ctl
// socket nobody is serving, and Reconcile would adopt a VM whose runner is gone.
func TestRunnerAliveRejectsARecycledPID(t *testing.T) {
	// A process whose argv names the VM, so the argv check has nothing to veto and
	// the start-time comparison is what decides.
	pid := spawnRunnerLookalike(t, "--vm-id", "vm-ours")
	real := readRunnerStart(pid)
	if real == "" {
		t.Fatalf("cannot read pid %d's start time; the case under test needs it", pid)
	}

	// A start time this process cannot have: its own, plus one tick.
	ticks, err := strconv.ParseUint(real, 10, 64)
	if err != nil {
		t.Fatalf("parse start time %q: %v", real, err)
	}
	stale := strconv.FormatUint(ticks+1, 10)

	if runnerAlive(pid, stale, "vm-ours") {
		t.Errorf("runnerAlive(%d, %q) = true; pid %d is alive but started at %q, so the "+
			"manifest's runner is gone and its pid was reused", pid, stale, pid, real)
	}
	if !runnerAlive(pid, real, "vm-ours") {
		t.Errorf("runnerAlive(%d, %q) = false; that is that process's own start time", pid, real)
	}
}

// TestRunnerAliveFallsBackWithoutAStartTime: manifests written before the field
// existed, and spawns whose start-time read lost the race, carry an empty value.
// Reading those runners dead would push doStop past the graceful path and let
// Reconcile spawn a second runner onto a live VM, so the empty case must still
// answer from whatever evidence remains — the argv, then a bare /proc entry.
func TestRunnerAliveFallsBackWithoutAStartTime(t *testing.T) {
	live := spawnRunnerLookalike(t, "--vm-id", "vm-ours")
	if !runnerAlive(live, "", "vm-ours") {
		t.Errorf("runnerAlive(%d, \"\") = false; an empty start time must not report a "+
			"live runner dead", live)
	}
	if runnerAlive(reapedPID(t), "", "vm-ours") {
		t.Error("runnerAlive on a reaped pid with no start time = true; /proc has no such entry")
	}
	for _, pid := range []int{0, -1} {
		if runnerAlive(pid, "", "vm-ours") || runnerAlive(pid, "12345", "vm-ours") {
			t.Errorf("runnerAlive(%d, ...) = true; there is no such runner", pid)
		}
	}
}

// TestRunnerAliveOnAReapedPID: a runner that exited and was reaped is dead under
// both forms of the check.
func TestRunnerAliveOnAReapedPID(t *testing.T) {
	pid, start := reapedPIDWithStart(t)
	if start == "" {
		t.Fatal("could not read the child's start time while it was alive")
	}
	if runnerAlive(pid, start, "vm-ours") {
		t.Errorf("runnerAlive(%d, %q) = true for a reaped process", pid, start)
	}
}

// reapedPID spawns a child, kills it, and waits for it, returning its pid. The pid
// is free afterwards; nothing in these tests spawns anything that could claim it in
// between.
func reapedPID(t *testing.T) int {
	t.Helper()
	pid, _ := reapedPIDWithStart(t)
	return pid
}

// reapedPIDWithStart is reapedPID plus the child's start time, read while it was
// still running.
func reapedPIDWithStart(t *testing.T) (int, string) {
	t.Helper()
	cmd := exec.Command("sleep", "300")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn sleep: %v", err)
	}
	pid := cmd.Process.Pid
	start := readRunnerStart(pid)
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill %d: %v", pid, err)
	}
	_ = cmd.Wait()
	return pid, start
}
