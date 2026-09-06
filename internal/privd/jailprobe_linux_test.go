// ABOUTME: Tests for the startup self-check that measures whether this process can
// ABOUTME: perform the jailer's privileged operations before privd agrees to serve.

//go:build linux

package privd

import (
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
	err := ProbeJailSyscalls()
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
