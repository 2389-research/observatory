// ABOUTME: Tests that a runner is identified by the VM named in its own argv.
// ABOUTME: A pid running someone else's runner must not be adopted as ours.

//go:build linux

package jailer

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// spawnRunnerLookalike starts a process whose argv has the shape both spawn sites
// build, and returns its pid. What the process does is beside the point; that it
// keeps that argv for the whole test is not.
//
// It is `sh -c`, because a shell hands every word after the command string to the
// script as a positional parameter instead of parsing it as an option. `sleep 300
// --vm-id x` looks right and is not: sleep rejects the flag and exits at once,
// leaving an unreaped zombie whose cmdline reads empty — an identity test that
// silently measures nothing. The script blocks on a pipe nobody writes to, which
// holds the process open without a child of its own, and `read` is a builtin so no
// exec replaces the argv under us.
func spawnRunnerLookalike(t *testing.T, args ...string) int {
	t.Helper()
	cmd := exec.Command("/bin/sh", append([]string{"-c", "read line", "vmobs-runner"}, args...)...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start lookalike: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	waitForReadableCmdline(t, cmd.Process.Pid)
	return cmd.Process.Pid
}

// waitForReadableCmdline fails the test if the lookalike is not a live process with
// a readable argv. A fixture that dies early does not fail an identity assertion —
// it changes which branch the assertion reaches — so the fixture is checked here,
// once, rather than in every test that uses one.
func waitForReadableCmdline(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, known := runnerNamesVM(pid, ""); known {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pid %d has no readable cmdline 5s after starting; the fixture is not a live process", pid)
}

func TestRunnerNamesVMReadsTheVMOutOfArgv(t *testing.T) {
	pid := spawnRunnerLookalike(t, "--vm-id", "vm-ours", "--ping-interval", "5s")

	named, known := runnerNamesVM(pid, "vm-ours")
	if !known {
		t.Fatalf("runnerNamesVM(%d, \"vm-ours\") could not read the argv of a live process", pid)
	}
	if !named {
		t.Errorf("runnerNamesVM(%d, \"vm-ours\") = false; that pid's argv says --vm-id vm-ours", pid)
	}
}

// TestRunnerNamesVMRejectsAnotherVMsRunner is the case the plan names: a pid the
// manifest records is alive and really is a runner, but it is running some other
// VM. Adopting it would leave this VM's row reading running with nothing behind it.
func TestRunnerNamesVMRejectsAnotherVMsRunner(t *testing.T) {
	pid := spawnRunnerLookalike(t, "--vm-id", "vm-theirs")

	named, known := runnerNamesVM(pid, "vm-ours")
	if !known {
		t.Fatalf("runnerNamesVM(%d, \"vm-ours\") could not read the argv of a live process", pid)
	}
	if named {
		t.Errorf("runnerNamesVM(%d, \"vm-ours\") = true; that pid's argv says --vm-id vm-theirs", pid)
	}
}

// TestRunnerNamesVMAcceptsTheJoinedFlagForm: Go's flag package takes --vm-id=x as
// readily as --vm-id x, so a runner started by hand carries the joined form. Reading
// that as "not ours" would let Reconcile spawn a second runner onto a live VM.
func TestRunnerNamesVMAcceptsTheJoinedFlagForm(t *testing.T) {
	pid := spawnRunnerLookalike(t, "--vm-id=vm-ours")

	if named, known := runnerNamesVM(pid, "vm-ours"); !known || !named {
		t.Errorf("runnerNamesVM(%d, \"vm-ours\") = (%v, %v), want (true, true) for --vm-id=vm-ours", pid, named, known)
	}
	if named, _ := runnerNamesVM(pid, "vm-theirs"); named {
		t.Errorf("runnerNamesVM(%d, \"vm-theirs\") = true for --vm-id=vm-ours", pid)
	}
}

// TestRunnerNamesVMRejectsAProcessThatIsNoRunner: every spawn site passes --vm-id,
// so an argv without it belongs to whatever the kernel handed the pid to next.
func TestRunnerNamesVMRejectsAProcessThatIsNoRunner(t *testing.T) {
	pid := spawnRunnerLookalike(t)

	named, known := runnerNamesVM(pid, "vm-ours")
	if !known {
		t.Fatalf("runnerNamesVM(%d, ...) could not read the argv of a live process", pid)
	}
	if named {
		t.Errorf("runnerNamesVM(%d, \"vm-ours\") = true; that argv names no VM at all", pid)
	}
}

// TestRunnerNamesVMKnowsNothingAboutADeadPID: no /proc entry is no evidence, not
// evidence of the negative. runnerAlive decides those on the recorded start time.
func TestRunnerNamesVMKnowsNothingAboutADeadPID(t *testing.T) {
	if named, known := runnerNamesVM(reapedPID(t), "vm-ours"); known || named {
		t.Errorf("runnerNamesVM(<reaped pid>, \"vm-ours\") = (%v, %v), want (false, false)", named, known)
	}
}

// TestRunnerAliveRejectsAPIDRunningAnotherVMsRunner: the argv veto has to reach
// runnerAlive, or the adoption path never sees it. A pid whose start time matches
// the manifest by coincidence is still not this VM's runner.
func TestRunnerAliveRejectsAPIDRunningAnotherVMsRunner(t *testing.T) {
	pid := spawnRunnerLookalike(t, "--vm-id", "vm-theirs")
	start := readRunnerStart(pid)
	if start == "" {
		t.Fatalf("cannot read pid %d's start time; the case under test needs it", pid)
	}

	if runnerAlive(pid, start, "vm-ours") {
		t.Errorf("runnerAlive(%d, %q, \"vm-ours\") = true; pid %d is running vm-theirs", pid, start, pid)
	}
	if !runnerAlive(pid, start, "vm-theirs") {
		t.Errorf("runnerAlive(%d, %q, \"vm-theirs\") = false; that is exactly what pid %d is", pid, start, pid)
	}
}

// TestRunnerAliveUsesArgvWhenTheManifestHasNoStartTime: the empty-start-time
// fallback is a bare /proc/<pid> stat, which reads any recycled pid alive. An argv
// that names a VM answers the question the missing field could not.
func TestRunnerAliveUsesArgvWhenTheManifestHasNoStartTime(t *testing.T) {
	ours := spawnRunnerLookalike(t, "--vm-id", "vm-ours")
	theirs := spawnRunnerLookalike(t, "--vm-id", "vm-theirs")

	if !runnerAlive(ours, "", "vm-ours") {
		t.Errorf("runnerAlive(%d, \"\", \"vm-ours\") = false; that pid's argv names vm-ours", ours)
	}
	if runnerAlive(theirs, "", "vm-ours") {
		t.Errorf("runnerAlive(%d, \"\", \"vm-ours\") = true; that pid's argv names vm-theirs", theirs)
	}
}

// TestRunnerAliveStillFallsBackWhenArgvSaysNothing: a zombie has a /proc entry and
// an empty cmdline, so it is exactly the shape that must not be decided by argv. A
// manifest with no start time keeps its old answer there — reading those runners
// dead would push doStop past the graceful path, which is why the fallback exists.
func TestRunnerAliveStillFallsBackWhenArgvSaysNothing(t *testing.T) {
	pid := zombiePID(t)

	if _, known := runnerNamesVM(pid, "vm-ours"); known {
		t.Fatalf("runnerNamesVM(%d, ...) claims to know something about a zombie's argv", pid)
	}
	if !runnerAlive(pid, "", "vm-ours") {
		t.Errorf("runnerAlive(%d, \"\", \"vm-ours\") = false; with no start time and no argv the "+
			"answer is the bare /proc check, and this pid has an entry", pid)
	}
}

// zombiePID starts a child, kills it, and does not reap it. /proc/<pid> stays, and
// its cmdline reads empty — the one live pid whose argv says nothing.
func zombiePID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("sleep", "300")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn sleep: %v", err)
	}
	pid := cmd.Process.Pid
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill %d: %v", pid, err)
	}
	// Deliberately no Wait: reaping is what removes the /proc entry.
	t.Cleanup(func() { _ = cmd.Wait() })
	waitForZombie(t, pid)
	return pid
}

// waitForZombie waits for the kernel to finish tearing down a killed process, and
// insists the result is a zombie rather than a pid that is simply gone.
//
// The kill returns before the exit completes, so reading cmdline straight after it
// can still see the live argv. An empty cmdline alone is not proof of the state
// this test needs either: a reaped pid reads exactly the same way through that
// keyhole, and it would send runnerAlive down the branch this test exists to keep
// off. /proc/<pid>/stat's state field says which one happened.
func waitForZombie(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		last = procState(t, pid)
		if _, known := runnerNamesVM(pid, "vm-ours"); !known && last == "Z" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pid %d is not an unreaped zombie 5s after being killed (state %q)", pid, last)
}

// procState reads the process state letter out of /proc/<pid>/stat. The comm field
// is parenthesised and may hold anything, so the fields are counted from the last
// ')' rather than from the start of the line.
func procState(t *testing.T, pid int) string {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "gone"
	}
	rest := string(data)
	if i := strings.LastIndex(rest, ")"); i >= 0 {
		rest = rest[i+1:]
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		t.Fatalf("/proc/%d/stat has no state field: %q", pid, string(data))
	}
	return fields[0]
}

// TestRunnerAliveKeepsRejectingARecycledPID guards the check the start time buys,
// now that argv can also answer. A pid running a runner for this very VM but with
// a different start time is a respawn, and the manifest's pid is gone.
func TestRunnerAliveKeepsRejectingARecycledPID(t *testing.T) {
	pid := spawnRunnerLookalike(t, "--vm-id", "vm-ours")
	real := readRunnerStart(pid)
	if real == "" {
		t.Fatalf("cannot read pid %d's start time; the case under test needs it", pid)
	}
	ticks, err := strconv.ParseUint(real, 10, 64)
	if err != nil {
		t.Fatalf("parse start time %q: %v", real, err)
	}
	stale := strconv.FormatUint(ticks+1, 10)

	if runnerAlive(pid, stale, "vm-ours") {
		t.Errorf("runnerAlive(%d, %q, \"vm-ours\") = true; the manifest's runner started at %q", pid, stale, real)
	}
}
