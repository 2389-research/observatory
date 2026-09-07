// ABOUTME: Tests for the runner ctl traffic doStop sends: which commands, on what deadlines.
// ABOUTME: A constant deadline guarding a configurable wait makes graceful stop unreachable.

//go:build linux

package jailer

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/guest/proto"
	"github.com/2389-research/observatory/internal/privd"
	"github.com/2389-research/observatory/internal/runner"
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
	_, err := dialCtl(sock, runner.CtlRequest{Cmd: "shutdown_guest", GraceS: 1}, 200*time.Millisecond)
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
	dialCtlFn = func(_ string, req runner.CtlRequest, deadline time.Duration) (runner.CtlReply, error) {
		calls = append(calls, ctlCall{cmd: req.Cmd, deadline: deadline})
		return runner.CtlReply{OK: false, Error: "recorded by test"}, nil
	}
	t.Cleanup(func() { dialCtlFn = restore })

	grace := 30 * time.Second
	a := stopOnlyAdapter(t)
	writeLiveRunnerManifest(t, a.cfg.StateDir, "vm-deadline")

	_, err := a.doStop(t.Context(), "vm-deadline", grace, false)
	requireOnlyCleanupDebt(t, err)

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

// TestDialCtlSpeaksTheRunnersWire: the jailer's ctl client and the runner's ctl
// server are one protocol, and the only way to say so is to run them against
// each other. Every other test here hands dialCtl a socket this file decodes
// itself, which proves the client agrees with the test — the jailer used to
// carry its own copy of the request and reply structs, and a copy tested
// against a copy is how a wire drifts without anyone noticing (issue 0yh5).
// The terminal command is the case that matters: its arguments and its answer
// travel in nested blocks that were added to the runner's shape alone, so a
// second definition could neither send nor read them.
func TestDialCtlSpeaksTheRunnersWire(t *testing.T) {
	var gotGrace int
	var gotCreate runner.TerminalCtlRequest
	sock := filepath.Join(t.TempDir(), "runner.sock")
	srv, err := runner.ListenCtl(t.Context(), sock, runner.CtlHandlers{
		Shutdown: func(graceS int) error { gotGrace = graceS; return nil },
		TerminalCreate: func(_ context.Context, req runner.TerminalCtlRequest) (runner.TerminalCtlReply, error) {
			gotCreate = req
			return runner.TerminalCtlReply{SessionID: "term-1"}, nil
		},
		TerminalList: func(context.Context) (runner.TerminalCtlReply, error) {
			return runner.TerminalCtlReply{Sessions: []proto.TerminalSession{{SessionID: "term-1"}}}, nil
		},
	})
	if err != nil {
		t.Fatalf("ListenCtl: %v", err)
	}
	t.Cleanup(srv.Close)

	reply, err := dialCtl(sock, runner.CtlRequest{Cmd: "shutdown_guest", GraceS: 7}, 5*time.Second)
	if err != nil {
		t.Fatalf("dialCtl shutdown_guest: %v", err)
	}
	if !reply.OK {
		t.Errorf("shutdown_guest reply not OK: %q", reply.Error)
	}
	if gotGrace != 7 {
		t.Errorf("runner saw grace %d, want 7", gotGrace)
	}

	// The request half: a terminal block the server has to receive whole. A
	// narrower request shape reaches the server with no block at all, and it
	// answers "terminal-create needs a terminal block".
	reply, err = dialCtl(sock, runner.CtlRequest{
		Cmd:      "terminal-create",
		Terminal: &runner.TerminalCtlRequest{User: "root", Rows: 40, Cols: 120},
	}, 5*time.Second)
	if err != nil {
		t.Fatalf("dialCtl terminal-create: %v", err)
	}
	if !reply.OK {
		t.Fatalf("terminal-create reply not OK: %q", reply.Error)
	}
	if gotCreate.User != "root" || gotCreate.Rows != 40 || gotCreate.Cols != 120 {
		t.Errorf("runner saw terminal block %+v, want user root at 40x120", gotCreate)
	}

	// The reply half: a block the server sends that has to survive the decode.
	reply, err = dialCtl(sock, runner.CtlRequest{Cmd: "terminal-list"}, 5*time.Second)
	if err != nil {
		t.Fatalf("dialCtl terminal-list: %v", err)
	}
	if !reply.OK {
		t.Fatalf("terminal-list reply not OK: %q", reply.Error)
	}
	if reply.Terminal == nil {
		t.Fatal("terminal-list reply lost its terminal block on the way back")
	}
	if len(reply.Terminal.Sessions) != 1 || reply.Terminal.Sessions[0].SessionID != "term-1" {
		t.Errorf("terminal block = %+v, want one session term-1", reply.Terminal)
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
				var req runner.CtlRequest
				_ = json.NewDecoder(conn).Decode(&req)
				<-t.Context().Done()
				_ = conn.Close()
			}()
		}
	}()
	return sock
}

// TestForceStopSendsNoGuestShutdown: a forced stop must not ask the guest to
// shut down. ForceStop is what a controller restart drives when it finds a stop
// already in flight, and the guest may be acting on the first request right
// then; a second one is a duplicate shutdown aimed at a guest already going
// down.
//
// TestForceStopSendsKill cannot say this. Its harness never powers the guest
// off, so a forced stop that wrongly took the graceful path would wait out the
// poll and fall through to the same SIGKILL: same signals, seconds later, no
// failure. The ctl traffic is the only place the difference shows.
func TestForceStopSendsNoGuestShutdown(t *testing.T) {
	var cmds []string
	restore := dialCtlFn
	dialCtlFn = func(_ string, req runner.CtlRequest, _ time.Duration) (runner.CtlReply, error) {
		cmds = append(cmds, req.Cmd)
		return runner.CtlReply{OK: false, Error: "recorded by test"}, nil
	}
	t.Cleanup(func() { dialCtlFn = restore })

	a := stopOnlyAdapter(t)

	// The control. The graceful branch is reachable only behind a live runner,
	// so prove this manifest reaches it before reading anything into a forced
	// run that stays quiet: a manifest that never got that far would satisfy the
	// assertion below by never trying.
	writeLiveRunnerManifest(t, a.cfg.StateDir, "vm-graceful")
	_, err := a.doStop(t.Context(), "vm-graceful", time.Second, false)
	requireOnlyCleanupDebt(t, err)
	if !slices.Contains(cmds, "shutdown_guest") {
		t.Fatalf("graceful stop sent %v, want a shutdown_guest among them; "+
			"the forced assertion below would pass on a manifest that never reached the ctl path", cmds)
	}

	cmds = nil
	writeLiveRunnerManifest(t, a.cfg.StateDir, "vm-forced")
	_, err = a.doStop(t.Context(), "vm-forced", time.Second, true)
	requireOnlyCleanupDebt(t, err)
	if slices.Contains(cmds, "shutdown_guest") {
		t.Errorf("forced stop sent %v; forceImmediate must skip the guest shutdown entirely", cmds)
	}
}

// stopOnlyAdapter builds an Adapter with just the fields doStop reads. It has
// no privd server behind it, so a stop that gets as far as reclaiming the jail
// chroot ends in ErrCleanupPending -- see requireOnlyCleanupDebt.
func stopOnlyAdapter(t *testing.T) *Adapter {
	t.Helper()
	dir := t.TempDir()
	return &Adapter{
		cfg: Config{StateDir: filepath.Join(dir, "state")},
		pc:  &unreachablePrivd{},
	}
}

// writeLiveRunnerManifest writes a manifest whose runner PID is a live process
// naming this VM in its argv, so runnerAlive says yes and doStop takes the
// graceful branch. VMMPID stays 0 so the forced fallback sends no signals.
//
// The pid has to be runner-shaped, not merely alive: runnerAlive reads the argv
// and refuses a pid running anything else. This test process used to stand in
// here, and it names no VM at all.
func writeLiveRunnerManifest(t *testing.T, stateDir, vmID string) {
	t.Helper()
	m := Manifest{VMID: vmID, RunnerPID: spawnRunnerLookalike(t, "--vm-id", vmID)}
	if err := writeManifest(stateDir, m); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

// unreachablePrivd is a privdClient with no server behind it: every verb fails,
// which is how these tests reach doStop's failure branches.
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
