// ABOUTME: Tests that doStop says why a graceful stop turned into a forced one.
// ABOUTME: The runner's refusal reason is the only record of what the guest did.

//go:build linux

package jailer

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/runner"
)

// TestDoStopWarnsOnCtlTransportFailure: when the ctl exchange itself fails the
// stop is recorded forced and the transport error is the only thing that says
// why. Dropping it leaves an operator with a forced stop and no reason at all.
func TestDoStopWarnsOnCtlTransportFailure(t *testing.T) {
	restore := dialCtlFn
	dialCtlFn = func(_ string, req runner.CtlRequest, _ time.Duration) (runner.CtlReply, error) {
		if req.Cmd == "shutdown_guest" {
			return runner.CtlReply{}, errors.New("dial runner ctl: connection refused")
		}
		return runner.CtlReply{OK: true}, nil
	}
	t.Cleanup(func() { dialCtlFn = restore })

	a := stopOnlyAdapter(t)
	writeLiveRunnerManifest(t, a.cfg.StateDir, "vm-transport")

	var forced bool
	out := captureStderr(t, func() {
		var err error
		forced, err = a.doStop(t.Context(), "vm-transport", 30*time.Second, false)
		if err != nil {
			t.Errorf("doStop: %v", err)
		}
	})

	if !forced {
		t.Errorf("forced = false; a failed ctl exchange must escalate")
	}
	warn := stopWarnLine(out, "vm-transport")
	if warn == "" {
		t.Fatalf("no jailer stop warning on stderr; captured:\n%s", out)
	}
	if !strings.Contains(warn, "connection refused") {
		t.Errorf("warning does not carry the transport error: %q", warn)
	}
}

// TestDoStopWarnsRunnerRefusalReason: the runner answers shutdown_guest with a
// reason — "shutdown_ack timeout" when the guest never acknowledged, or its own
// write error. doStop read only reply.OK, so the one sentence explaining every
// forced stop on this branch was discarded at the point it arrived.
func TestDoStopWarnsRunnerRefusalReason(t *testing.T) {
	const reason = "shutdown_ack timeout"

	restore := dialCtlFn
	dialCtlFn = func(_ string, req runner.CtlRequest, _ time.Duration) (runner.CtlReply, error) {
		if req.Cmd == "shutdown_guest" {
			return runner.CtlReply{OK: false, Error: reason}, nil
		}
		return runner.CtlReply{OK: true}, nil
	}
	t.Cleanup(func() { dialCtlFn = restore })

	a := stopOnlyAdapter(t)
	writeLiveRunnerManifest(t, a.cfg.StateDir, "vm-refused")

	var forced bool
	out := captureStderr(t, func() {
		var err error
		forced, err = a.doStop(t.Context(), "vm-refused", 30*time.Second, false)
		if err != nil {
			t.Errorf("doStop: %v", err)
		}
	})

	if !forced {
		t.Errorf("forced = false; a refused shutdown must escalate")
	}
	warn := stopWarnLine(out, "vm-refused")
	if warn == "" {
		t.Fatalf("no jailer stop warning on stderr; captured:\n%s", out)
	}
	if !strings.Contains(warn, reason) {
		t.Errorf("warning does not carry the runner's reason %q verbatim: %q", reason, warn)
	}
}

// TestDoStopWarningsDistinguishTransportFromRefusal: the two failures need
// different fixes — a broken socket is a host problem, a refusal is the guest's
// answer — so one shared message would be worth little more than none.
func TestDoStopWarningsDistinguishTransportFromRefusal(t *testing.T) {
	warn := func(vmID string, reply runner.CtlReply, ctlErr error) string {
		restore := dialCtlFn
		dialCtlFn = func(_ string, req runner.CtlRequest, _ time.Duration) (runner.CtlReply, error) {
			if req.Cmd == "shutdown_guest" {
				return reply, ctlErr
			}
			return runner.CtlReply{OK: true}, nil
		}
		defer func() { dialCtlFn = restore }()

		a := stopOnlyAdapter(t)
		writeLiveRunnerManifest(t, a.cfg.StateDir, vmID)
		out := captureStderr(t, func() {
			if _, err := a.doStop(t.Context(), vmID, 30*time.Second, false); err != nil {
				t.Errorf("doStop %s: %v", vmID, err)
			}
		})
		return stopWarnLine(out, vmID)
	}

	transport := warn("vm-a", runner.CtlReply{}, errors.New("boom"))
	refusal := warn("vm-b", runner.CtlReply{OK: false, Error: "boom"}, nil)

	if transport == "" || refusal == "" {
		t.Fatalf("missing warning: transport=%q refusal=%q", transport, refusal)
	}
	// Strip the vmID so only the wording is compared.
	if strings.ReplaceAll(transport, "vm-a", "") == strings.ReplaceAll(refusal, "vm-b", "") {
		t.Errorf("transport failure and runner refusal produced the same wording: %q", transport)
	}
}

// TestDoStopWarnsOnGracefulPollTimeout: the runner accepted shutdown_guest —
// the guest acknowledged it — but the VMM never reached vmm_exited or
// finalized inside the poll window. That is a different fact from a refused
// or unreachable request: it is the only branch that can tell "the guest
// never answered" apart from "the guest answered and then did not go down."
// Losing it collapses both into the same silent forced stop.
func TestDoStopWarnsOnGracefulPollTimeout(t *testing.T) {
	restore := dialCtlFn
	dialCtlFn = func(_ string, _ runner.CtlRequest, _ time.Duration) (runner.CtlReply, error) {
		return runner.CtlReply{OK: true}, nil
	}
	t.Cleanup(func() { dialCtlFn = restore })

	a := stopOnlyAdapter(t)
	writeLiveRunnerManifest(t, a.cfg.StateDir, "vm-hung")
	// No runner-state.json is written for this VM: the poll never observes a
	// terminal phase and must fall through on ctx.Done() with the zero-value
	// state ReadState returns for a missing file — Phase "".

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()

	var forced bool
	out := captureStderr(t, func() {
		var err error
		forced, err = a.doStop(ctx, "vm-hung", 30*time.Second, false)
		if err != nil {
			t.Errorf("doStop: %v", err)
		}
	})

	if !forced {
		t.Errorf("forced = false; a poll that never observes a terminal phase must escalate")
	}
	warn := stopWarnLine(out, "vm-hung")
	if warn == "" {
		t.Fatalf("no jailer stop warning on stderr; captured:\n%s", out)
	}
	if !strings.Contains(warn, `""`) {
		t.Errorf("warning does not report the last observed phase, empty and quoted since no state file was ever written: %q", warn)
	}

	// The window the warning reports must be the one that elapsed. The poll is
	// allotted grace+5s, but it is nested inside the operation context, and here
	// that context ended it after 300ms. An operator told the VMM was given 35s
	// goes looking for a guest that would not die; the truth is a stop that was
	// cut short, which is a different problem with a different fix.
	//
	// Ceiling only. The poll starts after a manifest read and a /proc stat, so how
	// much of the 300ms reaches it is the host's business, and a floor would spend
	// a flake budget on scheduling luck to catch nothing the ceiling misses.
	if elapsed := pollWindowFromWarning(t, warn); elapsed > 5*time.Second {
		t.Errorf("warning reports a %v poll window; the parent context ended the poll after ~300ms: %q", elapsed, warn)
	}
}

// pollWindowRE pulls the duration out of the third-arm warning. It matches both
// the elapsed window and a bare allotted one, so a message that reports the
// wrong quantity is caught by the value rather than by the wording.
var pollWindowRE = regexp.MustCompile(`within (\S+) `)

// pollWindowFromWarning returns the window the third-arm warning reports for its
// poll — the only account an operator gets of how long the VMM was given.
func pollWindowFromWarning(t *testing.T, warn string) time.Duration {
	t.Helper()
	m := pollWindowRE.FindStringSubmatch(warn)
	if m == nil {
		t.Fatalf("the warning reports no poll window at all: %q", warn)
	}
	d, err := time.ParseDuration(m[1])
	if err != nil {
		t.Fatalf("poll window %q in %q is not a duration: %v", m[1], warn, err)
	}
	return d
}

// TestDoStopSilentOnSuccessfulGracefulPoll: a graceful stop that reaches
// vmm_exited inside the grace window is not a warning — a line that fires on
// every healthy stop would bury the one case this branch exists to surface.
func TestDoStopSilentOnSuccessfulGracefulPoll(t *testing.T) {
	restore := dialCtlFn
	dialCtlFn = func(_ string, _ runner.CtlRequest, _ time.Duration) (runner.CtlReply, error) {
		return runner.CtlReply{OK: true}, nil
	}
	t.Cleanup(func() { dialCtlFn = restore })

	a := stopOnlyAdapter(t)
	writeLiveRunnerManifest(t, a.cfg.StateDir, "vm-clean")
	stateFile := filepath.Join(a.cfg.StateDir, "vms", "vm-clean", "runner-state.json")
	if err := runner.WriteState(stateFile, runner.State{VMID: "vm-clean", Phase: runner.PhaseVMMExited}); err != nil {
		t.Fatalf("seed runner state: %v", err)
	}

	var forced bool
	out := captureStderr(t, func() {
		var err error
		forced, err = a.doStop(t.Context(), "vm-clean", 30*time.Second, false)
		if err != nil {
			t.Errorf("doStop: %v", err)
		}
	})

	if forced {
		t.Errorf("forced = true; a poll that observes vmm_exited inside the grace window must not escalate")
	}
	if warn := stopWarnLine(out, "vm-clean"); warn != "" {
		t.Errorf("graceful stop that succeeded within the poll window produced a warning: %q", warn)
	}
}

// stopWarnLine returns the first jailer stop warning mentioning vmID, minus the
// release-chroot warning every one of these tests provokes by design (the
// adapter has no privd behind it).
func stopWarnLine(stderr, vmID string) string {
	for _, line := range strings.Split(stderr, "\n") {
		if !strings.HasPrefix(line, "jailer: stop: warn:") || !strings.Contains(line, vmID) {
			continue
		}
		if strings.Contains(line, "release jail chroot") {
			continue
		}
		return line
	}
	return ""
}

// captureStderr redirects os.Stderr through a pipe for the duration of fn. The
// package writes warnings with fmt.Fprintf(os.Stderr, ...) directly, so this is
// the seam; the pipe buffer holds far more than these warnings, so no reader
// has to run concurrently.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	fn()
	os.Stderr = orig
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stderr: %v", err)
	}
	_ = r.Close()
	return string(out)
}
