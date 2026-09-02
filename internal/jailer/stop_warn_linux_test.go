// ABOUTME: Tests that doStop says why a graceful stop turned into a forced one.
// ABOUTME: The runner's refusal reason is the only record of what the guest did.

//go:build linux

package jailer

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// TestDoStopWarnsOnCtlTransportFailure: when the ctl exchange itself fails the
// stop is recorded forced and the transport error is the only thing that says
// why. Dropping it leaves an operator with a forced stop and no reason at all.
func TestDoStopWarnsOnCtlTransportFailure(t *testing.T) {
	restore := dialCtlFn
	dialCtlFn = func(_ string, req adapterCtlRequest, _ time.Duration) (adapterCtlReply, error) {
		if req.Cmd == "shutdown_guest" {
			return adapterCtlReply{}, errors.New("dial runner ctl: connection refused")
		}
		return adapterCtlReply{OK: true}, nil
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
	dialCtlFn = func(_ string, req adapterCtlRequest, _ time.Duration) (adapterCtlReply, error) {
		if req.Cmd == "shutdown_guest" {
			return adapterCtlReply{OK: false, Error: reason}, nil
		}
		return adapterCtlReply{OK: true}, nil
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
	warn := func(vmID string, reply adapterCtlReply, ctlErr error) string {
		restore := dialCtlFn
		dialCtlFn = func(_ string, req adapterCtlRequest, _ time.Duration) (adapterCtlReply, error) {
			if req.Cmd == "shutdown_guest" {
				return reply, ctlErr
			}
			return adapterCtlReply{OK: true}, nil
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

	transport := warn("vm-a", adapterCtlReply{}, errors.New("boom"))
	refusal := warn("vm-b", adapterCtlReply{OK: false, Error: "boom"}, nil)

	if transport == "" || refusal == "" {
		t.Fatalf("missing warning: transport=%q refusal=%q", transport, refusal)
	}
	// Strip the vmID so only the wording is compared.
	if strings.ReplaceAll(transport, "vm-a", "") == strings.ReplaceAll(refusal, "vm-b", "") {
		t.Errorf("transport failure and runner refusal produced the same wording: %q", transport)
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
