// ABOUTME: Tests for the startup self-check that measures whether this process can
// ABOUTME: perform the jailer's privileged operations before privd agrees to serve.

//go:build linux

package privd

import (
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestJailProbeStepsAreTheMeasuredGates: the step list is the boundary document's
// matrix turned into code, so it must stay in the kernel's own order. A probe that
// tries pivot_root before the mount tree is slave-propagating measures nothing --
// the first failure would be the one that hides the second.
func TestJailProbeStepsAreTheMeasuredGates(t *testing.T) {
	want := []string{"mount_propagation_slave", "netns_create", "tap_create", "pivot_root"}
	steps := jailProbeSteps("/nonexistent")
	if len(steps) != len(want) {
		t.Fatalf("steps = %d, want %d", len(steps), len(want))
	}
	for i, s := range steps {
		if s.name != want[i] {
			t.Errorf("step %d = %q, want %q", i, s.name, want[i])
		}
		if s.needs == "" {
			t.Errorf("step %q names no kernel facility", s.name)
		}
		if s.run == nil {
			t.Errorf("step %q has no operation to run", s.name)
		}
	}
}

// TestJailProbeRemedyReadsTheErrno: EACCES and EPERM on a mount-family call are
// two different misconfigurations and send an operator to two different flags.
// Docker's AppArmor denial is EACCES; a missing capability and a seccomp refusal
// are both EPERM. Collapsing them would tell an operator to edit the wrong thing.
func TestJailProbeRemedyReadsTheErrno(t *testing.T) {
	cases := []struct {
		step    string
		errno   error
		wantSub string
	}{
		{"mount_propagation_slave", unix.EACCES, "apparmor=vmobs-jailer"},
		{"mount_propagation_slave", unix.EPERM, "--cap-add SYS_ADMIN"},
		{"pivot_root", unix.EPERM, "seccomp=deploy/seccomp/vmobs-jailer.json"},
		{"pivot_root", unix.EACCES, "apparmor=vmobs-jailer"},
		{"tap_create", unix.EPERM, "--cap-add NET_ADMIN"},
		{"tap_create", unix.ENOENT, "--device /dev/net/tun"},
		{"netns_create", unix.EPERM, "--cap-add SYS_ADMIN"},
	}
	for _, c := range cases {
		got := jailProbeRemedy(c.step, c.errno)
		if !strings.Contains(got, c.wantSub) {
			t.Errorf("remedy(%s, %v) = %q, want it to name %q", c.step, c.errno, got, c.wantSub)
		}
	}
}

// TestJailProbeRemedyOnEACCESSendsTheOperatorToTheKernel: EACCES means an
// AppArmor profile refused the mount, but the errno cannot say which profile.
// Both live cases arrive identically here, and they need opposite fixes:
// docker-default is in force and ours should replace it, or ours is in force and
// is missing a rule. Measured on aibox03 -- the shipped profile denied privd's
// own probe child, and this remedy told the operator to load the profile that
// had just denied them. Only the kernel's denial line names the profile.
func TestJailProbeRemedyOnEACCESSendsTheOperatorToTheKernel(t *testing.T) {
	got := jailProbeRemedy("mount_propagation_slave", unix.EACCES)
	for _, want := range []string{"journalctl", "DENIED", "docker-default", "vmobs-jailer"} {
		if !strings.Contains(got, want) {
			t.Errorf("EACCES remedy %q does not mention %q", got, want)
		}
	}
}

// TestJailProbeRemedyNeverEmpty: an unclassified failure still has to say
// something an operator can act on. Silence here reads as "no problem".
func TestJailProbeRemedyNeverEmpty(t *testing.T) {
	if got := jailProbeRemedy("mount_propagation_slave", unix.EROFS); got == "" {
		t.Error("an unclassified errno produced an empty remedy")
	}
	if got := jailProbeRemedy("no_such_step", unix.EPERM); got == "" {
		t.Error("an unknown step produced an empty remedy")
	}
}

// TestJailProbeChildDispatch: the child mode is entered only on its exact argv.
// A privd started with an operator's ordinary flags must never fall into it.
func TestJailProbeChildDispatch(t *testing.T) {
	if dir, ok := JailProbeChildArgs([]string{JailProbeChildArg, "/tmp/x"}); !ok || dir != "/tmp/x" {
		t.Errorf("child argv not recognised: dir=%q ok=%v", dir, ok)
	}
	for _, argv := range [][]string{
		{},
		{"--socket", "/run/vmobs/privd.sock"},
		{JailProbeChildArg},
		{"--socket", JailProbeChildArg, "/tmp/x"},
	} {
		if _, ok := JailProbeChildArgs(argv); ok {
			t.Errorf("argv %v entered child mode", argv)
		}
	}
}

// TestJailProbeFailsUnprivileged: run by an ordinary user, the probe must fail and
// the failure must name a step and a remedy. This is the shape an operator meets
// when the container is missing a flag, so the message is the deliverable.
//
// Skipped for root, where the probe is expected to pass on a host that can host VMs.
func TestJailProbeFailsUnprivileged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; this test asserts the unprivileged refusal")
	}
	// A jail base this user owns: the probe now stages under it, so a read-only
	// /srv/vmobs would fail this test for the wrong reason.
	err := ProbeJailSyscalls(t.TempDir())
	if err == nil {
		t.Fatal("probe passed as an unprivileged user, which means it measured nothing")
	}
	msg := err.Error()
	if !strings.Contains(msg, "mount namespace") && !strings.Contains(msg, "mount_propagation_slave") {
		t.Errorf("error %q names neither the namespace nor the first step", msg)
	}
	if !strings.Contains(msg, "SYS_ADMIN") {
		t.Errorf("error %q does not tell the operator what to change", msg)
	}
}

// TestParseJailProbeFailuresReadsEveryLine: a host can be missing several things
// at once, and the probe now reports all of them in one run.
//
// The shape this replaced read the whole output as one flat set of fields, so
// two failure lines collapsed into whichever step came last. Measured cost on
// aibox03: the AppArmor profile was missing two mount rules, and finding the
// second one took a full image rebuild and container restart after fixing the
// first.
func TestParseJailProbeFailuresReadsEveryLine(t *testing.T) {
	got := parseJailProbeFailures("step=mount_propagation_slave errno=13\nstep=netns_create errno=13\n")
	if len(got) != 2 {
		t.Fatalf("parsed %d failures, want 2: %+v", len(got), got)
	}
	if got[0].step != "mount_propagation_slave" || got[1].step != "netns_create" {
		t.Errorf("steps = %q, %q; want mount_propagation_slave, netns_create", got[0].step, got[1].step)
	}
	for i, f := range got {
		if !errors.Is(f.errno, unix.EACCES) {
			t.Errorf("failure %d errno = %v, want EACCES", i, f.errno)
		}
	}
}

// TestParseJailProbeFailuresSkipsLinesNamingNoStep: garbage in the stream must
// not become a failure with an empty name, which would send an operator to the
// fallback remedy for a step that never ran.
func TestParseJailProbeFailuresSkipsLinesNamingNoStep(t *testing.T) {
	if got := parseJailProbeFailures("errno=13\n\nnot a machine line\n"); len(got) != 0 {
		t.Errorf("parsed %+v from lines naming no step, want none", got)
	}
	if got := parseJailProbeFailures(""); len(got) != 0 {
		t.Errorf("parsed %+v from empty output, want none", got)
	}
}
