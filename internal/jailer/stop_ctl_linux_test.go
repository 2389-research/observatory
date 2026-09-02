// ABOUTME: Tests for the runner ctl deadlines doStop chooses per command.
// ABOUTME: A constant deadline guarding a configurable wait makes graceful stop unreachable.

//go:build linux

package jailer

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/privd"
	"github.com/2389-research/observatory-v2/internal/runner"
)

// TestCtlDeadlineOutlivesRunnerReplyCeiling: the shutdown_guest socket deadline
// must outlive the longest the runner may legitimately take to answer. The
// runner waits grace + runner.ShutdownReplySlack for the guest's ack and only
// then writes its reply, so a client that gives up sooner never sees a reply at
// all — the graceful path becomes structurally unreachable and every stop is
// recorded forced, whatever the guest did.
func TestCtlDeadlineOutlivesRunnerReplyCeiling(t *testing.T) {
	// 30s is the documented default (docs/examples/host-config.yaml).
	for _, graceS := range []int{1, 5, 10, 30, 60, 300} {
		grace := time.Duration(graceS) * time.Second
		ceiling := grace + runner.ShutdownReplySlack
		got := ctlDeadline(grace)
		if got <= ceiling {
			t.Errorf("ctlDeadline(%s) = %s, want > runner reply ceiling %s", grace, got, ceiling)
		}
	}
}

// TestDialCtlHonoursDeadline: dialCtl must wait exactly as long as its caller
// asked. A fake runner that accepts the connection and never answers is the
// only shape that separates "honours the parameter" from "always waits 30s".
func TestDialCtlHonoursDeadline(t *testing.T) {
	sock := silentCtlServer(t)

	start := time.Now()
	_, err := dialCtl(sock, adapterCtlRequest{Cmd: "shutdown_guest", GraceS: 1}, 200*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("dialCtl returned nil error against a runner that never replies")
	}
	if elapsed > time.Second {
		t.Errorf("dialCtl waited %s for a 200ms deadline; the deadline parameter is ignored", elapsed)
	}
}

// TestDoStopCtlDeadlinePerCommand: shutdown_guest gets the grace-derived
// deadline and finalize keeps its own fixed one. Finalize has no guest round
// trip in it, so tying it to grace would make an unrelated command wait on the
// guest's patience.
func TestDoStopCtlDeadlinePerCommand(t *testing.T) {
	type ctlCall struct {
		cmd      string
		deadline time.Duration
	}
	var calls []ctlCall
	restore := dialCtlFn
	dialCtlFn = func(_ string, req adapterCtlRequest, deadline time.Duration) (adapterCtlReply, error) {
		calls = append(calls, ctlCall{cmd: req.Cmd, deadline: deadline})
		return adapterCtlReply{OK: false, Error: "recorded by test"}, nil
	}
	t.Cleanup(func() { dialCtlFn = restore })

	grace := 30 * time.Second
	a := stopOnlyAdapter(t)
	writeLiveRunnerManifest(t, a.cfg.StateDir, "vm-deadline")

	if _, err := a.doStop(t.Context(), "vm-deadline", grace, false); err != nil {
		t.Fatalf("doStop: %v", err)
	}

	byCmd := map[string]time.Duration{}
	for _, c := range calls {
		byCmd[c.cmd] = c.deadline
	}
	if got, want := byCmd["shutdown_guest"], ctlDeadline(grace); got != want {
		t.Errorf("shutdown_guest deadline = %s, want ctlDeadline(%s) = %s", got, grace, want)
	}
	if got, want := byCmd["finalize"], finalizeCtlDeadline; got != want {
		t.Errorf("finalize deadline = %s, want %s", got, want)
	}
	if byCmd["shutdown_guest"] == byCmd["finalize"] {
		t.Errorf("both ctl commands used the same deadline %s; finalize must not ride on grace",
			byCmd["finalize"])
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// silentCtlServer listens on a unix socket, accepts connections, reads the
// request and never answers — a runner still waiting on its guest.
func silentCtlServer(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "runner.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen %s: %v", sock, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				var req adapterCtlRequest
				_ = json.NewDecoder(conn).Decode(&req)
				<-t.Context().Done()
				_ = conn.Close()
			}()
		}
	}()
	return sock
}

// stopOnlyAdapter builds an Adapter with just the fields doStop reads. It has
// no privd server behind it: releaseVMWhenDead fails and doStop logs and
// carries on, which is the behaviour under test everywhere else too.
func stopOnlyAdapter(t *testing.T) *Adapter {
	t.Helper()
	dir := t.TempDir()
	return &Adapter{
		cfg: Config{StateDir: filepath.Join(dir, "state")},
		pc:  &unreachablePrivd{},
	}
}

// writeLiveRunnerManifest writes a manifest whose runner PID is this test
// process, so runnerAlive says yes and doStop takes the graceful branch. VMMPID
// stays 0 so the forced fallback sends no signals.
func writeLiveRunnerManifest(t *testing.T, stateDir, vmID string) {
	t.Helper()
	if err := writeManifest(stateDir, Manifest{VMID: vmID, RunnerPID: os.Getpid()}); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

// unreachablePrivd is a privdClient with no server behind it. doStop's only
// call into it is ReleaseVM, which it logs and discards by design.
type unreachablePrivd struct{}

func (*unreachablePrivd) AllocateNetwork(context.Context, privd.AllocateNetworkReq) error {
	return errors.New("privd unreachable in test")
}

func (*unreachablePrivd) ReleaseNetwork(context.Context, privd.ReleaseNetworkReq) error {
	return errors.New("privd unreachable in test")
}

func (*unreachablePrivd) StartVM(context.Context, privd.StartVMReq) (privd.StartVMResp, error) {
	return privd.StartVMResp{}, errors.New("privd unreachable in test")
}

func (*unreachablePrivd) SignalVM(context.Context, privd.SignalVMReq) error {
	return errors.New("privd unreachable in test")
}

func (*unreachablePrivd) ReleaseVM(context.Context, privd.ReleaseVMReq) error {
	return errors.New("privd unreachable in test")
}
