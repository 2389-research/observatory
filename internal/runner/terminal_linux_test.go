// ABOUTME: End-to-end terminal test: a real guest.Agent and pty.Broker behind a
// ABOUTME: real runner, driven through runner.sock exactly as the host will drive it.

//go:build linux

package runner_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/guest"
	"github.com/2389-research/observatory-v2/internal/guest/proto"
	"github.com/2389-research/observatory-v2/internal/privd"
	"github.com/2389-research/observatory-v2/internal/runner"
)

const testShell = "/bin/bash"

// ctlWireRequest and ctlWireReply are the test's own view of the control
// socket's JSON. Spelling them out here rather than reusing the runner's
// envelope is what makes this a wire test: a renamed field breaks it.
type ctlWireRequest struct {
	Cmd      string                     `json:"cmd"`
	Terminal *runner.TerminalCtlRequest `json:"terminal,omitempty"`
}

type ctlWireReply struct {
	OK       bool                     `json:"ok"`
	Error    string                   `json:"error,omitempty"`
	Terminal *runner.TerminalCtlReply `json:"terminal,omitempty"`
}

// --- vsock stand-in -------------------------------------------------------

// vsockRouter mimics Firecracker's vsock multiplexer: one UDS carrying many
// guest ports, chosen by the CONNECT line. The runner dials 10000 for control
// and 10002 for each attached session, so a single-port stub cannot serve it.
type vsockRouter struct {
	ln    net.Listener
	mu    sync.Mutex
	ports map[uint32]*portListener
}

func newVsockRouter(t *testing.T, path string, ports ...uint32) *vsockRouter {
	t.Helper()
	ln, err := listen0600(path)
	if err != nil {
		t.Fatalf("listen %s: %v", path, err)
	}
	r := &vsockRouter{ln: ln, ports: map[uint32]*portListener{}}
	for _, p := range ports {
		r.ports[p] = newPortListener()
	}
	go r.accept()
	t.Cleanup(func() {
		_ = ln.Close()
		for _, pl := range r.ports {
			_ = pl.Close()
		}
	})
	return r
}

func (r *vsockRouter) listener(port uint32) net.Listener {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ports[port]
}

func (r *vsockRouter) accept() {
	for {
		conn, err := r.ln.Accept()
		if err != nil {
			return
		}
		go r.route(conn)
	}
}

func (r *vsockRouter) route(conn net.Conn) {
	var line []byte
	buf := make([]byte, 1)
	for len(line) < 64 {
		if _, err := conn.Read(buf); err != nil {
			conn.Close()
			return
		}
		if buf[0] == '\n' {
			break
		}
		line = append(line, buf[0])
	}
	var port uint32
	if _, err := fmt.Sscanf(string(line), "CONNECT %d", &port); err != nil {
		conn.Close()
		return
	}
	r.mu.Lock()
	pl := r.ports[port]
	r.mu.Unlock()
	if pl == nil {
		conn.Close()
		return
	}
	if _, err := conn.Write([]byte("OK 12345\n")); err != nil {
		conn.Close()
		return
	}
	pl.deliver(conn)
}

// portListener is a net.Listener fed by the router rather than by the kernel.
type portListener struct {
	ch     chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPortListener() *portListener {
	return &portListener{ch: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *portListener) deliver(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.closed:
		c.Close()
	}
}

func (l *portListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *portListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *portListener) Addr() net.Addr { return dummyAddr{} }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "vsock" }
func (dummyAddr) String() string  { return "guest" }

// --- harness --------------------------------------------------------------

type terminalHarness struct {
	ctlSock string
}

func newTerminalHarness(t *testing.T) *terminalHarness {
	t.Helper()
	if _, err := os.Stat(testShell); err != nil {
		t.Skipf("%s is not installed on this host: %v", testShell, err)
	}

	dir := shortSockDir(t)
	spoolDir := filepath.Join(dir, "spool")
	stateFile := filepath.Join(dir, "runner-state.json")
	ctlSock := filepath.Join(dir, "runner.sock")
	vSock := filepath.Join(dir, "v.sock")

	const token = "terminal-test-capability-token"
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte(token), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatalf("mkdir spool: %v", err)
	}

	router := newVsockRouter(t, vSock, 10000, 10002)

	agent := guest.NewAgent(&guest.BootConfig{
		Schema:          "vmobs.guest_context.v1",
		VMID:            "vm-terminal",
		BootID:          "boot-terminal",
		CapabilityToken: token,
		ProtocolVersion: proto.ProtocolVersion,
	}, proto.CapabilityManifest{
		Schema:        "vmobs.guest_capability.v1",
		KernelRelease: "6.1.0-test",
	})

	agentCtx, agentCancel := context.WithCancel(context.Background())
	t.Cleanup(agentCancel)
	go func() { _ = agent.ServeControl(agentCtx, router.listener(10000)) }()
	go func() { _ = agent.ServeStreams(agentCtx, router.listener(10002)) }()

	vmm := exec.Command("sleep", "300")
	if err := vmm.Start(); err != nil {
		t.Fatalf("start fake vmm: %v", err)
	}
	t.Cleanup(func() {
		_ = vmm.Process.Kill()
		_ = vmm.Wait()
	})
	statData, err := os.ReadFile(privd.ProcStatPath(vmm.Process.Pid))
	if err != nil {
		t.Fatalf("read proc stat: %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	t.Cleanup(runCancel)
	runDone := make(chan error, 1)
	go func() {
		runDone <- runner.Run(runCtx, runner.Config{
			VMID:         "vm-terminal",
			BootID:       "boot-terminal",
			InstanceID:   "inst-terminal-1",
			UDSPath:      vSock,
			TokenFile:    tokenFile,
			SpoolDir:     spoolDir,
			StateFile:    stateFile,
			CtlSock:      ctlSock,
			VMMPID:       vmm.Process.Pid,
			VMMStartTime: privd.ParseStartTime(string(statData)),
			PingInterval: 500 * time.Millisecond,
		})
	}()
	t.Cleanup(func() {
		runCancel()
		select {
		case <-runDone:
		case <-time.After(5 * time.Second):
			t.Error("runner.Run did not return within 5s of cancel")
		}
	})

	if !waitForPhase(t, stateFile, runner.PhaseAttached, 10*time.Second) {
		t.Fatal("runner never attached to the guest")
	}
	return &terminalHarness{ctlSock: ctlSock}
}

// call sends one control-socket command and returns the reply.
func (h *terminalHarness) call(t *testing.T, req ctlWireRequest) ctlWireReply {
	t.Helper()
	conn, err := net.Dial("unix", h.ctlSock)
	if err != nil {
		t.Fatalf("dial ctl: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("encode %s: %v", req.Cmd, err)
	}
	var reply ctlWireReply
	if err := json.NewDecoder(conn).Decode(&reply); err != nil {
		t.Fatalf("decode %s reply: %v", req.Cmd, err)
	}
	return reply
}

// attach opens a session's byte stream. The connection carries one JSON reply
// and then nothing but frames, so the decoder's leftover bytes have to become
// the head of the frame stream — the same splice the host will need. The
// returned reader is that spliced stream; writes go straight to the conn.
func (h *terminalHarness) attach(t *testing.T, sessionID, after string) (ctlWireReply, net.Conn, io.Reader) {
	t.Helper()
	conn, err := net.Dial("unix", h.ctlSock)
	if err != nil {
		t.Fatalf("dial ctl: %v", err)
	}
	// A terminal stream idles between keystrokes; a deadline here would end it
	// mid-test, so only the reply is timed.
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	req := ctlWireRequest{Cmd: "terminal-attach", Terminal: &runner.TerminalCtlRequest{
		SessionID: sessionID, AfterOffset: after,
	}}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		conn.Close()
		t.Fatalf("encode attach: %v", err)
	}
	dec := json.NewDecoder(conn)
	var reply ctlWireReply
	if err := dec.Decode(&reply); err != nil {
		conn.Close()
		t.Fatalf("decode attach reply: %v", err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		t.Fatalf("clear deadline: %v", err)
	}
	return reply, conn, runner.FrameStream(dec, conn)
}

func (h *terminalHarness) create(t *testing.T, id string, ringBytes int) ctlWireReply {
	t.Helper()
	return h.call(t, ctlWireRequest{Cmd: "terminal-create", Terminal: &runner.TerminalCtlRequest{
		SessionID: id,
		Argv:      []string{testShell, "-i"},
		Term:      "xterm-256color",
		Rows:      24,
		Cols:      80,
		RingBytes: ringBytes,
	}})
}

// streamReader collects everything one attachment delivers.
type streamReader struct {
	mu      sync.Mutex
	out     bytes.Buffer
	offsets []uint64
	lens    []int
	drops   []proto.TerminalDropped
	closed  *proto.TerminalClosed
	err     error
}

func readStream(r io.Reader) *streamReader {
	sr := &streamReader{}
	go func() {
		for {
			typ, payload, err := proto.ReadFrame(r)
			if err != nil {
				sr.mu.Lock()
				sr.err = err
				sr.mu.Unlock()
				return
			}
			sr.mu.Lock()
			switch typ {
			case proto.FramePTY:
				if len(payload) >= 8 {
					sr.offsets = append(sr.offsets, binary.BigEndian.Uint64(payload[:8]))
					sr.lens = append(sr.lens, len(payload)-8)
					sr.out.Write(payload[8:])
				}
			case proto.FrameControl:
				var env proto.Envelope
				if json.Unmarshal(payload, &env) == nil {
					switch env.Kind {
					case proto.KindTerminalDropped:
						var d proto.TerminalDropped
						if json.Unmarshal(env.Data, &d) == nil {
							sr.drops = append(sr.drops, d)
						}
					case proto.KindTerminalClosed:
						var c proto.TerminalClosed
						if json.Unmarshal(env.Data, &c) == nil {
							sr.closed = &c
						}
					}
				}
			}
			sr.mu.Unlock()
		}
	}()
	return sr
}

func (s *streamReader) text() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.out.String()
}

func (s *streamReader) dropCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.drops)
}

func (s *streamReader) waitFor(t *testing.T, want string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if bytes.Contains([]byte(s.text()), []byte(want)) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	s.mu.Lock()
	err, frames := s.err, len(s.offsets)
	s.mu.Unlock()
	t.Fatalf("timed out waiting for %q after %d pty frames (reader err: %v); stream so far:\n%s",
		want, frames, err, s.text())
}

// typeLine writes one host->guest input frame: [seq:8 BE][bytes].
func typeLine(t *testing.T, conn net.Conn, seq uint64, line string) {
	t.Helper()
	p := make([]byte, 8+len(line))
	binary.BigEndian.PutUint64(p[:8], seq)
	copy(p[8:], line)
	if err := proto.WriteFrame(conn, proto.FramePTY, p); err != nil {
		t.Fatalf("write input seq %d: %v", seq, err)
	}
}

// --- tests ----------------------------------------------------------------

func TestTerminalCreateRoundTripsToTheGuest(t *testing.T) {
	h := newTerminalHarness(t)

	reply := h.create(t, "sess-create", 0)
	if !reply.OK {
		t.Fatalf("terminal-create failed: %s", reply.Error)
	}
	if reply.Terminal == nil {
		t.Fatal("terminal-create reply carried no terminal block")
	}
	if reply.Terminal.PID <= 0 {
		t.Errorf("pid = %d; terminal.created must carry the guest child's real pid", reply.Terminal.PID)
	}
	if reply.Terminal.StartedAt == "" {
		t.Error("terminal.created carried no started_at")
	}
	if _, err := time.Parse(time.RFC3339Nano, reply.Terminal.StartedAt); err != nil {
		t.Errorf("started_at %q is not RFC3339: %v", reply.Terminal.StartedAt, err)
	}

	closeReply := h.call(t, ctlWireRequest{Cmd: "terminal-close", Terminal: &runner.TerminalCtlRequest{SessionID: "sess-create"}})
	if !closeReply.OK {
		t.Fatalf("terminal-close failed: %s", closeReply.Error)
	}
}

func TestTerminalCreateRefusesAnInterpretedCommand(t *testing.T) {
	h := newTerminalHarness(t)

	reply := h.call(t, ctlWireRequest{Cmd: "terminal-create", Terminal: &runner.TerminalCtlRequest{
		SessionID: "sess-shellout",
		Argv:      []string{"/bin/sh", "-c", "echo pwned"},
		Rows:      24, Cols: 80,
	}})
	if reply.OK {
		_ = h.call(t, ctlWireRequest{Cmd: "terminal-close", Terminal: &runner.TerminalCtlRequest{SessionID: "sess-shellout"}})
		t.Fatal("the guest accepted an argv carrying -c; §8.1 forbids a shell interpreting a string anywhere in this chain")
	}
	if reply.Error == "" {
		t.Error("a refused create returned no reason")
	}
}

func TestTerminalAttachStreamsOutputWithExactOffsets(t *testing.T) {
	h := newTerminalHarness(t)
	if r := h.create(t, "sess-attach", 0); !r.OK {
		t.Fatalf("create: %s", r.Error)
	}
	t.Cleanup(func() {
		h.call(t, ctlWireRequest{Cmd: "terminal-close", Terminal: &runner.TerminalCtlRequest{SessionID: "sess-attach"}})
	})

	reply, conn, frames := h.attach(t, "sess-attach", "0")
	defer conn.Close()
	if !reply.OK {
		t.Fatalf("attach failed: %s", reply.Error)
	}
	if reply.Terminal.ResumeOffset == "" {
		t.Fatal("attach reply carried no resume_offset")
	}
	resume, err := strconv.ParseUint(reply.Terminal.ResumeOffset, 10, 64)
	if err != nil {
		t.Fatalf("resume_offset %q is not a decimal string: %v", reply.Terminal.ResumeOffset, err)
	}
	if reply.Terminal.Gap {
		t.Error("a fresh session reported a replay gap")
	}

	sr := readStream(frames)
	// The marker is built by concatenation so the terminal's echo of the typed
	// line can never contain it: only execution produces MARKER.
	typeLine(t, conn, 1, `printf "MARK""ER-%s\n" one`+"\n")
	sr.waitFor(t, "MARKER-one")

	sr.mu.Lock()
	offsets, lens := append([]uint64(nil), sr.offsets...), append([]int(nil), sr.lens...)
	drops := len(sr.drops)
	sr.mu.Unlock()

	if len(offsets) == 0 {
		t.Fatal("no PTY frames arrived")
	}
	if offsets[0] != resume {
		t.Errorf("first frame offset = %d, want the resume_offset %d", offsets[0], resume)
	}
	if drops == 0 {
		for i := 1; i < len(offsets); i++ {
			if want := offsets[i-1] + uint64(lens[i-1]); offsets[i] != want {
				t.Fatalf("frame %d starts at %d, want %d: offsets must be exact stream positions", i, offsets[i], want)
			}
		}
	}
}

func TestTerminalInputAppliesADuplicateSequenceOnce(t *testing.T) {
	h := newTerminalHarness(t)
	if r := h.create(t, "sess-seq", 0); !r.OK {
		t.Fatalf("create: %s", r.Error)
	}
	t.Cleanup(func() {
		h.call(t, ctlWireRequest{Cmd: "terminal-close", Terminal: &runner.TerminalCtlRequest{SessionID: "sess-seq"}})
	})

	reply, conn, frames := h.attach(t, "sess-seq", "0")
	defer conn.Close()
	if !reply.OK {
		t.Fatalf("attach failed: %s", reply.Error)
	}
	sr := readStream(frames)

	const line = `i=$((i+1)); printf "COUNT""=$i\n"` + "\n"
	typeLine(t, conn, 5, line)
	sr.waitFor(t, "COUNT=1")

	// The same sequence again is a retransmit, not a second keystroke.
	typeLine(t, conn, 5, line)
	typeLine(t, conn, 6, `printf "FENCE""D\n"`+"\n")
	sr.waitFor(t, "FENCED")

	if bytes.Contains([]byte(sr.text()), []byte("COUNT=2")) {
		t.Errorf("a retransmitted seq typed the line twice:\n%s", sr.text())
	}
}

func TestDetachLeavesTheSessionListed(t *testing.T) {
	h := newTerminalHarness(t)
	if r := h.create(t, "sess-detach", 0); !r.OK {
		t.Fatalf("create: %s", r.Error)
	}
	t.Cleanup(func() {
		h.call(t, ctlWireRequest{Cmd: "terminal-close", Terminal: &runner.TerminalCtlRequest{SessionID: "sess-detach"}})
	})

	reply, conn, frames := h.attach(t, "sess-detach", "0")
	if !reply.OK {
		t.Fatalf("attach failed: %s", reply.Error)
	}
	sr := readStream(frames)
	typeLine(t, conn, 1, `printf "ALI""VE\n"`+"\n")
	sr.waitFor(t, "ALIVE")

	// Closing a tab detaches; it does not kill the shell (§8.1).
	conn.Close()

	list := h.call(t, ctlWireRequest{Cmd: "terminal-list"})
	if !list.OK {
		t.Fatalf("terminal-list failed: %s", list.Error)
	}
	var found *proto.TerminalSession
	for i := range list.Terminal.Sessions {
		if list.Terminal.Sessions[i].SessionID == "sess-detach" {
			found = &list.Terminal.Sessions[i]
		}
	}
	if found == nil {
		t.Fatalf("the session vanished when its reader detached: %+v", list.Terminal.Sessions)
	}
	if found.PID <= 0 {
		t.Errorf("listed pid = %d", found.PID)
	}
	if _, err := strconv.ParseUint(found.HeadOffset, 10, 64); err != nil {
		t.Errorf("head_offset %q is not a decimal string", found.HeadOffset)
	}
	if _, err := strconv.ParseUint(found.TailOffset, 10, 64); err != nil {
		t.Errorf("tail_offset %q is not a decimal string", found.TailOffset)
	}

	// Reattaching to the live session gets the ring, not a new shell.
	reply2, conn2, frames2 := h.attach(t, "sess-detach", "0")
	defer conn2.Close()
	if !reply2.OK {
		t.Fatalf("reattach failed: %s", reply2.Error)
	}
	sr2 := readStream(frames2)
	sr2.waitFor(t, "ALIVE")
}

// A ring far smaller than the output guarantees the guest overwrites unread
// bytes. §8.2 says the gap is shown, so terminal.dropped has to reach the
// caller through the relay.
func TestGuestDroppedReachesTheCaller(t *testing.T) {
	h := newTerminalHarness(t)
	if r := h.create(t, "sess-drop", 4096); !r.OK {
		t.Fatalf("create: %s", r.Error)
	}
	t.Cleanup(func() {
		h.call(t, ctlWireRequest{Cmd: "terminal-close", Terminal: &runner.TerminalCtlRequest{SessionID: "sess-drop"}})
	})

	reply, conn, frames := h.attach(t, "sess-drop", "0")
	defer conn.Close()
	if !reply.OK {
		t.Fatalf("attach failed: %s", reply.Error)
	}
	sr := readStream(frames)
	typeLine(t, conn, 1, "seq 1 200000\n")
	typeLine(t, conn, 2, `printf "FLOOD""DONE\n"`+"\n")
	sr.waitFor(t, "FLOODDONE")

	if sr.dropCount() == 0 {
		t.Error("200000 lines through a 4 KiB ring reported no drop; the gap must be shown, never papered over")
	}
	sr.mu.Lock()
	defer sr.mu.Unlock()
	for i, d := range sr.drops {
		from, err1 := strconv.ParseUint(d.FromOffset, 10, 64)
		to, err2 := strconv.ParseUint(d.ToOffset, 10, 64)
		if err1 != nil || err2 != nil {
			t.Fatalf("drop %d has non-decimal offsets %+v", i, d)
		}
		if to <= from {
			t.Errorf("drop %d names an empty range [%d,%d)", i, from, to)
		}
	}
}

func TestAttachToAnUnknownSessionIsRefused(t *testing.T) {
	h := newTerminalHarness(t)

	reply, conn, _ := h.attach(t, "sess-nonexistent", "0")
	defer conn.Close()
	if reply.OK {
		t.Fatal("attach to a session the guest never created was accepted")
	}
	if reply.Error == "" {
		t.Error("a refused attach carried no reason")
	}
}

func TestTerminalCloseReportsTheExitStatus(t *testing.T) {
	h := newTerminalHarness(t)
	if r := h.create(t, "sess-exit", 0); !r.OK {
		t.Fatalf("create: %s", r.Error)
	}

	reply := h.call(t, ctlWireRequest{Cmd: "terminal-close", Terminal: &runner.TerminalCtlRequest{SessionID: "sess-exit"}})
	if !reply.OK {
		t.Fatalf("terminal-close failed: %s", reply.Error)
	}
	if reply.Terminal.Reason == "" {
		t.Error("terminal.closed carried no reason")
	}
	if reply.Terminal.ExitCode == nil && reply.Terminal.Signal == "" {
		t.Error("terminal.closed reported neither an exit code nor a signal")
	}

	list := h.call(t, ctlWireRequest{Cmd: "terminal-list"})
	for _, s := range list.Terminal.Sessions {
		if s.SessionID == "sess-exit" {
			t.Error("a closed session is still listed")
		}
	}
}
