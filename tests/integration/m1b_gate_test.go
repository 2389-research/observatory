// ABOUTME: M1b gate test: real guest terminals over the browser WebSocket relay.
// ABOUTME: Requires VMOBS_FIXTURE=1 and scripts/aibox03/setup.sh (incl. vmobs-privd).

//go:build linux

package integration_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/2389-research/observatory-v2/internal/auth"
)

// The M1b gate runs with authentication required. AT-030's unauthenticated and
// wrong-owner denials have no meaning without it: with authentication off every
// request arrives as local_operator, so there is no second identity to refuse
// and no missing credential to notice.
const (
	m1bOperator = "gate-operator"
	// Length, not secrecy, is what matters here: the daemon runs on loopback for
	// the length of one test and its store is a t.TempDir. auth.InitStore is the
	// only reader.
	m1bPassword = "m1b-gate-operator-password"
	// m1bIntruder owns nothing on this host. AT-030 mints a bearer token for it
	// to prove a valid credential for the wrong owner still cannot reach a PTY.
	m1bIntruder = "intruder"
)

// m1bAttachTimeout bounds one attach: the relay's own path is a runner control
// round trip plus a vsock handshake, and neither has a human in it.
const m1bAttachTimeout = 30 * time.Second

// m1bCommandTimeout bounds one command typed into a guest shell. A `vi` startup
// on a cold page cache is the slowest thing the gate types.
const m1bCommandTimeout = 30 * time.Second

// ---------------------------------------------------------------------------
// The browser end of the relay.
// ---------------------------------------------------------------------------

// wireCtl is one host-to-browser control message, mirrored from
// internal/api/terminal_stream.go's wireStreamMsg. Mirrored rather than
// imported: this is the browser's view of the wire, and a test that shared the
// server's struct could not notice the server changing it.
type wireCtl struct {
	Type             string `json:"type"`
	SessionID        string `json:"session_id"`
	ConnID           string `json:"conn_id"`
	ResumeOffset     string `json:"resume_offset"`
	Gap              bool   `json:"gap"`
	Writer           bool   `json:"writer"`
	Holder           string `json:"holder"`
	MaxInflightBytes string `json:"max_inflight_bytes"`
	Reason           string `json:"reason"`
	FromOffset       string `json:"from_offset"`
	ToOffset         string `json:"to_offset"`
	Cause            string `json:"cause"`
	Message          string `json:"message"`
	ExitCode         *int   `json:"exit_code"`
	Signal           string `json:"signal"`
}

// gateTerm is one browser attached to one terminal session. It speaks the wire
// format in internal/api/terminal_stream.go directly — 8 big-endian bytes of
// offset then PTY bytes outbound, 8 big-endian bytes of sequence then keystrokes
// inbound — so what the gate proves is what a browser would see, not what a
// helper library decided to show it.
type gateTerm struct {
	t         *testing.T
	conn      *websocket.Conn
	sessionID string
	label     string
	ctx       context.Context
	cancel    context.CancelFunc
	// done closes when the reader goroutine has stopped, so close() can wait for
	// it rather than racing the test's own assertions against a live append.
	done chan struct{}

	// seq numbers this connection's input. It starts at 0 and every keystroke
	// message increments it, because the relay drops seq <= lastClientSeq.
	seq atomic.Uint64

	// wmu serializes writes: coder/websocket permits one concurrent writer, and
	// the reader goroutine writes acks while the test goroutine types.
	wmu sync.Mutex

	mu sync.Mutex
	// out is every PTY byte this browser has been handed, in arrival order.
	out []byte
	// ctrl is every control message, in arrival order.
	ctrl []wireCtl
	// consumed is one past the last byte offset received, which is what an ack
	// reports.
	consumed uint64
	// autoAck is the ordinary browser: it acks as fast as it reads. AT-027 turns
	// it off to be the slow one.
	autoAck bool
	// writer is the lease state the host last reported. Every host control
	// message carries it, so it is refreshed from all of them rather than only
	// from the two whose subject it is.
	writer  bool
	readErr error
}

// openTerm attaches a browser to sessionID. The daemon's cookie jar and CSRF
// transport ride along, so the upgrade carries exactly what a logged-in page
// would send.
func (d *m1aDaemon) openTerm(t *testing.T, sessionID, label string) *gateTerm {
	t.Helper()
	dialCtx, dialCancel := context.WithTimeout(context.Background(), m1bAttachTimeout)
	defer dialCancel()

	// A dedicated client: d.httpClient carries a 330s Timeout priced for
	// lifecycle mutations, and a Timeout on a WebSocket client kills the socket
	// mid-session rather than the request.
	wsClient := &http.Client{Jar: d.httpClient.Jar, Transport: d.httpClient.Transport}
	conn, resp, err := websocket.Dial(dialCtx, "ws://"+d.addr+"/api/v1/terminals/"+sessionID+"/stream", &websocket.DialOptions{
		HTTPClient: wsClient,
	})
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			t.Fatalf("openTerm %s: dial %s: %v (status %d, body %s)", label, sessionID, err, resp.StatusCode, body)
		}
		t.Fatalf("openTerm %s: dial %s: %v", label, sessionID, err)
	}
	// A paste and a flood both arrive as whole messages; the guest's own frame
	// cap is the honest ceiling, and the relay never sends more than the window.
	conn.SetReadLimit(4 << 20)

	ctx, cancel := context.WithCancel(context.Background())
	g := &gateTerm{
		t:         t,
		conn:      conn,
		sessionID: sessionID,
		label:     label,
		ctx:       ctx,
		cancel:    cancel,
		done:      make(chan struct{}),
		autoAck:   true,
	}
	go g.read()

	// Every attach begins with one "attached" message. Waiting for it here means
	// no caller has to remember that the resume offset it needs arrives before
	// the first byte does.
	if _, ok := g.waitControl("attached", m1bAttachTimeout); !ok {
		g.close()
		t.Fatalf("openTerm %s: no attached message within %s", label, m1bAttachTimeout)
	}
	t.Cleanup(g.close)
	return g
}

// read is the browser's receive loop: PTY bytes get appended and acked, control
// messages get recorded.
func (g *gateTerm) read() {
	defer close(g.done)
	for {
		typ, data, err := g.conn.Read(g.ctx)
		if err != nil {
			g.mu.Lock()
			g.readErr = err
			g.mu.Unlock()
			return
		}
		switch typ {
		case websocket.MessageBinary:
			if len(data) < 8 {
				continue
			}
			offset := binary.BigEndian.Uint64(data[:8])
			payload := data[8:]
			g.mu.Lock()
			g.out = append(g.out, payload...)
			g.consumed = offset + uint64(len(payload))
			consumed, ack := g.consumed, g.autoAck
			g.mu.Unlock()
			if ack {
				// A failed ack is not worth failing the test from a goroutine: the
				// read that follows will report the same broken socket.
				_ = g.ack(consumed)
			}
		case websocket.MessageText:
			var m wireCtl
			if err := json.Unmarshal(data, &m); err != nil {
				continue
			}
			g.mu.Lock()
			g.ctrl = append(g.ctrl, m)
			g.writer = m.Writer
			g.mu.Unlock()
		}
	}
}

// write sends one frame under the write lock.
func (g *gateTerm) write(typ websocket.MessageType, data []byte) error {
	g.wmu.Lock()
	defer g.wmu.Unlock()
	return g.conn.Write(g.ctx, typ, data)
}

// ack reports the consumed offset, which is what opens the in-flight window.
func (g *gateTerm) ack(offset uint64) error {
	raw, err := json.Marshal(map[string]string{"type": "ack", "offset": strconv.FormatUint(offset, 10)})
	if err != nil {
		return err
	}
	return g.write(websocket.MessageText, raw)
}

// sendInput frames one keystroke message at the given sequence number. Callers
// that want the next sequence use typeKeys; AT-026 calls this directly to
// resend a sequence the host has already accepted.
func (g *gateTerm) sendInput(seq uint64, b []byte) error {
	msg := make([]byte, 8+len(b))
	binary.BigEndian.PutUint64(msg[:8], seq)
	copy(msg[8:], b)
	return g.write(websocket.MessageBinary, msg)
}

// typeKeys sends bytes as the next input message.
// nextSeq takes the next input sequence number without sending anything, for
// the cases that hand the same number to sendInput twice.
func (g *gateTerm) nextSeq() uint64 {
	return g.seq.Add(1)
}

func (g *gateTerm) typeKeys(b []byte) {
	g.t.Helper()
	if err := g.sendInput(g.seq.Add(1), b); err != nil {
		g.t.Fatalf("%s: type %q: %v", g.label, b, err)
	}
}

// typeLine types a command and the Enter key a browser actually sends.
func (g *gateTerm) typeLine(line string) {
	g.t.Helper()
	g.typeKeys([]byte(line + "\r"))
}

// resize asks the guest to change the shell's dimensions.
func (g *gateTerm) resize(rows, cols uint16) {
	g.t.Helper()
	raw, err := json.Marshal(map[string]any{"type": "resize", "rows": rows, "cols": cols})
	if err != nil {
		g.t.Fatalf("%s: marshal resize: %v", g.label, err)
	}
	if err := g.write(websocket.MessageText, raw); err != nil {
		g.t.Fatalf("%s: resize: %v", g.label, err)
	}
}

// lease sends a writer-lease request in the given mode ("acquire" or "steal").
func (g *gateTerm) lease(mode string) {
	g.t.Helper()
	raw, err := json.Marshal(map[string]string{"type": "lease", "mode": mode})
	if err != nil {
		g.t.Fatalf("%s: marshal lease: %v", g.label, err)
	}
	if err := g.write(websocket.MessageText, raw); err != nil {
		g.t.Fatalf("%s: lease %s: %v", g.label, mode, err)
	}
}

// output is everything this browser has been handed so far.
func (g *gateTerm) output() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return string(g.out)
}

// received is how many PTY bytes have arrived. AT-027 compares it against the
// in-flight ceiling.
func (g *gateTerm) received() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.out)
}

// setAutoAck turns the browser's acking on or off and returns how many PTY
// bytes it had received at that moment. Turning it back on acks everything
// received while it was off, which is what resumes the stream.
func (g *gateTerm) setAutoAck(on bool) int {
	g.mu.Lock()
	g.autoAck = on
	consumed := g.consumed
	received := len(g.out)
	g.mu.Unlock()
	if on {
		_ = g.ack(consumed)
	}
	return received
}

// controls is a copy of every control message received so far.
func (g *gateTerm) controls() []wireCtl {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]wireCtl(nil), g.ctrl...)
}

// waitControl waits for a control message of the given type and returns the
// first one. It scans from the start each time, so a message that arrived
// before the call is still found.
func (g *gateTerm) waitControl(typ string, d time.Duration) (wireCtl, bool) {
	deadline := time.Now().Add(d)
	for {
		for _, c := range g.controls() {
			if c.Type == typ {
				return c, true
			}
		}
		if time.Now().After(deadline) {
			return wireCtl{}, false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitControlAfter waits for a control message of the given type that arrives
// at or after index n in the control log, and returns it with its index.
func (g *gateTerm) waitControlAfter(typ string, n int, d time.Duration) (wireCtl, int, bool) {
	deadline := time.Now().Add(d)
	for {
		all := g.controls()
		for i := n; i < len(all); i++ {
			if all[i].Type == typ {
				return all[i], i, true
			}
		}
		if time.Now().After(deadline) {
			return wireCtl{}, 0, false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitFor waits until sub appears in the output stream.
func (g *gateTerm) waitFor(sub string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		if strings.Contains(g.output(), sub) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitForAfter waits until sub appears in the output past byte `from`, so a
// marker the shell printed before this step cannot satisfy it.
func (g *gateTerm) waitForAfter(sub string, from int, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		if out := g.output(); len(out) > from && strings.Contains(out[from:], sub) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// closed reports whether the reader loop has stopped, and why.
func (g *gateTerm) closed() (error, bool) {
	select {
	case <-g.done:
		g.mu.Lock()
		defer g.mu.Unlock()
		return g.readErr, true
	default:
		return nil, false
	}
}

// close ends this browser's connection and waits for its reader to stop.
func (g *gateTerm) close() {
	g.cancel()
	_ = g.conn.CloseNow()
	select {
	case <-g.done:
	case <-time.After(5 * time.Second):
		g.t.Logf("%s: reader did not stop within 5s", g.label)
	}
}

// ---------------------------------------------------------------------------
// Running commands in a guest shell.
// ---------------------------------------------------------------------------

// runGuest types cmd into the shell, waits for it to finish, and returns
// everything the browser received while it ran.
//
// isWriter reports what the host last told this connection about the lease.
func (g *gateTerm) isWriter() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.writer
}

// takeWriter steals the writer lease and waits for the host to confirm it. A
// reconnect inside the lease's grace window lands read-only on purpose (§8.2,
// D6): the departed holder keeps the shell long enough to survive a reload, so
// a new connection has to ask for it the way the browser's button does.
func (g *gateTerm) takeWriter() {
	g.t.Helper()
	if g.isWriter() {
		return
	}
	before := len(g.controls())
	g.lease("steal")
	deadline := time.Now().Add(m1bAttachTimeout)
	for time.Now().Before(deadline) {
		if _, n, ok := g.waitControlAfter("lease", before, 500*time.Millisecond); ok {
			before = n
			if g.isWriter() {
				return
			}
		}
	}
	g.t.Fatalf("%s: never became the writer after a steal; controls: %+v", g.label, g.controls())
}

// gateMarks numbers every sentinel this gate types, across every connection.
// A reattach replays the scrollback of the session it joins, so a per-connection
// counter hands the new connection __M1B_1__ while __M1B_1__ from the old one is
// still arriving in the replay: the wait returns on the replayed text and the
// command it was waiting for is never seen. One counter for the whole gate makes
// every sentinel unique in the transcript.
var gateMarks atomic.Uint64

// The finish signal is a sentinel typed with an empty quote pair inside it, so
// the PTY's echo of the command line and the shell's own output are never the
// same string: the browser sees `echo __M1B""_7__` come back as the echo and
// `__M1B_7__` as the output. Waiting on a mark the echo also matches would
// return before the command had run at all.
func (g *gateTerm) runGuest(cmd string, d time.Duration) string {
	g.t.Helper()
	if !g.isWriter() {
		g.t.Fatalf("%s: cannot run %q from a read-only connection; take the writer lease first", g.label, cmd)
	}
	n := gateMarks.Add(1)
	mark := fmt.Sprintf("__M1B_%d__", n)
	start := g.received()
	g.typeLine(fmt.Sprintf(`%s; echo __M1B""_%d__`, cmd, n))
	if !g.waitFor(mark, d) {
		g.t.Fatalf("%s: %q did not finish within %s\n--- output so far ---\n%s",
			g.label, cmd, d, tailOf(g.output(), 2000))
	}
	full := g.output()
	idx := strings.Index(full[start:], mark)
	if idx < 0 {
		// waitFor found the mark, so it is in the stream; only a start offset past
		// it can get here, and that means the command's own output was consumed
		// before this call. Returning the whole tail is more honest than an empty
		// string that reads like "the command printed nothing".
		return full[start:]
	}
	return full[start : start+idx]
}

// runFullScreen starts a full-screen program, waits for it to paint, sends the
// keys that quit it, and checks the shell came back. wantAny is the set of byte
// sequences any of which proves the program drew something — a CSI introducer,
// which the echoed command line never contains.
func (g *gateTerm) runFullScreen(cmd, quit string, wantAny []string, d time.Duration) bool {
	g.t.Helper()
	start := g.received()
	g.typeLine(cmd)

	painted := false
	deadline := time.Now().Add(d)
	for !painted && time.Now().Before(deadline) {
		for _, w := range wantAny {
			if g.waitForAfter(w, start, 200*time.Millisecond) {
				painted = true
				break
			}
		}
	}
	if !painted {
		g.t.Logf("%s: %q never painted a screen:\n%s", g.label, cmd, tailOf(g.output()[start:], 800))
	}

	g.typeKeys([]byte(quit))
	// The shell answering again is what proves the program exited rather than
	// leaving the terminal wedged in its alternate screen.
	back := g.received()
	g.typeLine("echo BACK\"\"-FROM-FS")
	returned := g.waitForAfter("BACK-FROM-FS", back, d)
	if !returned {
		g.t.Logf("%s: the shell did not answer after quitting %q:\n%s",
			g.label, cmd, tailOf(g.output()[back:], 800))
	}
	return painted && returned
}

// exitCodeOf renders a closed message's exit code, or "none" when the guest
// reported a signal instead. Printing 0 for an absent code would invent one.
func exitCodeOf(m wireCtl) string {
	if m.ExitCode == nil {
		return "none"
	}
	return strconv.Itoa(*m.ExitCode)
}

// tailOf returns the last n bytes of s, for failure messages that must not
// print a megabyte of shell output.
func tailOf(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

// lastLine is the last non-empty line of s, trimmed. Guest answers arrive after
// a prompt and the echo of the command; the answer is the line at the end.
func lastLine(s string) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r", "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			return l
		}
	}
	return ""
}

// afterEquals pulls the value a guest printed as <prefix><value>, taking the
// last occurrence: the command's own echo carries the prefix too.
func afterEquals(s, prefix string) string {
	idx := strings.LastIndex(s, prefix)
	if idx < 0 {
		return ""
	}
	rest := s[idx+len(prefix):]
	end := strings.IndexAny(rest, " \t\r\n")
	if end >= 0 {
		rest = rest[:end]
	}
	return strings.TrimSpace(rest)
}

// hostUname is this host's kernel release, read the way uname -r reads it. The
// guest boots a different kernel, so the two strings must differ.
func hostUname(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		t.Fatalf("read host kernel release: %v", err)
	}
	return strings.TrimSpace(string(b))
}

// ---------------------------------------------------------------------------
// The host side of "no host shell".
// ---------------------------------------------------------------------------

// hostProc is one host process as /proc reports it.
type hostProc struct {
	pid  int
	ppid int
	comm string
}

// readHostProcs reads every process on the host. A pid that disappears between
// the readdir and the read is skipped rather than reported: the snapshot is of
// a moving system, and a vanished process is not evidence of anything.
func readHostProcs(t *testing.T) map[int]hostProc {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatalf("read /proc: %v", err)
	}
	procs := make(map[int]hostProc, len(entries))
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		// "pid (comm) state ppid ...". comm can hold spaces and parentheses, so
		// the fields after it start at the LAST ')' — splitting on whitespace
		// would mis-parse a process named "vmobs (x) y".
		s := string(raw)
		lparen := strings.Index(s, "(")
		rparen := strings.LastIndex(s, ")")
		if lparen < 0 || rparen < lparen {
			continue
		}
		rest := strings.Fields(s[rparen+1:])
		if len(rest) < 2 {
			continue
		}
		ppid, err := strconv.Atoi(rest[1])
		if err != nil {
			continue
		}
		procs[pid] = hostProc{pid: pid, ppid: ppid, comm: s[lparen+1 : rparen]}
	}
	return procs
}

// descendantsOf returns every process under root, transitively. Root itself is
// not included: the question is what the daemon spawned, not whether it exists.
func descendantsOf(procs map[int]hostProc, root int) map[int]hostProc {
	children := make(map[int][]int, len(procs))
	for pid, p := range procs {
		children[p.ppid] = append(children[p.ppid], pid)
	}
	out := make(map[int]hostProc)
	queue := append([]int(nil), children[root]...)
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		if _, seen := out[pid]; seen {
			continue
		}
		out[pid] = procs[pid]
		queue = append(queue, children[pid]...)
	}
	return out
}

// commsOf renders a descendant set as a sorted, countable summary. Comparing
// summaries rather than pid sets is deliberate: a runner that died and was
// respawned has different pids and is still not a shell.
func commsOf(procs map[int]hostProc) string {
	counts := map[string]int{}
	for _, p := range procs {
		counts[p.comm]++
	}
	names := make([]string, 0, len(counts))
	for n := range counts {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s=%d", n, counts[n]))
	}
	return strings.Join(parts, " ")
}

// shellComms are the process names a host-side shell proxy would show up as. A
// terminal that is really a guest PTY puts none of them under vmobsd.
var shellComms = map[string]bool{
	"sh": true, "bash": true, "dash": true, "ash": true, "zsh": true,
	"busybox": true, "script": true, "socat": true,
}

// ---------------------------------------------------------------------------
// Terminal session helpers on the daemon handle.
// ---------------------------------------------------------------------------

// gateSession is one terminal session as the API published it.
type gateSession struct {
	ID    string
	VMID  string
	State string
	PID   int
	Rows  uint16
	Cols  uint16
}

func sessionFrom(body map[string]any) gateSession {
	s := gateSession{}
	s.ID, _ = body["session_id"].(string)
	s.VMID, _ = body["vm_id"].(string)
	s.State, _ = body["state"].(string)
	if v, ok := body["pid"].(float64); ok {
		s.PID = int(v)
	}
	if v, ok := body["rows"].(float64); ok {
		s.Rows = uint16(v)
	}
	if v, ok := body["cols"].(float64); ok {
		s.Cols = uint16(v)
	}
	return s
}

// createTerminal opens a session on vmID and returns what the API said about it.
func (d *m1aDaemon) createTerminal(t *testing.T, vmID string) gateSession {
	t.Helper()
	status, body := d.apiPost(t, "/vms/"+vmID+"/terminals", map[string]any{})
	if status != http.StatusCreated {
		t.Fatalf("create terminal on %s: expected 201, got %d: %v", vmID, status, body)
	}
	sess := sessionFrom(body)
	if sess.ID == "" {
		t.Fatalf("create terminal on %s: no session_id in %v", vmID, body)
	}
	t.Cleanup(func() {
		// Best effort: a session the test already closed answers 204, and a
		// session whose VM is gone is not a leak worth failing teardown over.
		req, err := http.NewRequest(http.MethodDelete, d.baseURL+"/terminals/"+sess.ID, nil)
		if err != nil {
			return
		}
		resp, err := d.httpClient.Do(req)
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	})
	return sess
}

// getTerminal reads one session back, returning the status alongside it so a
// caller can assert a refusal rather than only a shape.
func (d *m1aDaemon) getTerminal(t *testing.T, vmID, sessionID string) (gateSession, bool) {
	t.Helper()
	body := d.apiGet(t, "/vms/"+vmID+"/terminals")
	list, _ := body["terminals"].([]any)
	for _, raw := range list {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		s := sessionFrom(m)
		if s.ID == sessionID {
			return s, true
		}
	}
	return gateSession{}, false
}

// openSessionCount is how many sessions the host holds open on a VM. AT-030
// compares it before and after every denied upgrade.
func (d *m1aDaemon) openSessionCount(t *testing.T, vmID string) int {
	t.Helper()
	body := d.apiGet(t, "/vms/"+vmID+"/terminals")
	list, _ := body["terminals"].([]any)
	n := 0
	for _, raw := range list {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if state, _ := m["state"].(string); state == "open" {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// TestM1bGate — the M1b acceptance gate (AT-019..AT-030).
// ---------------------------------------------------------------------------

// TestM1bGate drives real guest shells the way a browser does: one WebSocket per
// session speaking the §8.2 wire format, against two real Firecracker VMs.
//
// It runs with require_authentication on, because AT-030's denials are empty
// against a daemon that treats every caller as local_operator.
//
// Guard: VMOBS_FIXTURE=1, plus the privd socket and stage dirs m1aSkipChecks
// probes. Evidence lands in tests/integration/evidence/m1b-gate-<hostname>.txt.
func TestM1bGate(t *testing.T) {
	if os.Getenv("VMOBS_FIXTURE") != "1" {
		t.Skip("set VMOBS_FIXTURE=1 to run the M1b terminal gate (requires installed vmobs-privd; must NOT run as root)")
	}
	gateSkipChecks(t)
	m1aSkipChecks(t)

	if os.Getuid() == 0 {
		t.Fatal("M1b gate must not run as root; privileged ops flow through privd socket only")
	}

	repoRoot := findRepoRoot(t)
	daemonBin := buildBinary(t, "github.com/2389-research/observatory-v2/cmd/vmobsd")
	runnerBin := buildBinary(t, "github.com/2389-research/observatory-v2/cmd/vmobs-runner")

	daemon := startDaemon(t, repoRoot, daemonBin, runnerBin, "m1b-primary",
		withRequiredAuth(m1bOperator, m1bPassword))

	hostname, _ := os.Hostname()
	var evidence strings.Builder
	fmt.Fprintf(&evidence, "# M1b gate evidence\n")
	fmt.Fprintf(&evidence, "# hostname: %s\n", hostname)
	fmt.Fprintf(&evidence, "# date: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&evidence, "# pid: %d\n", os.Getpid())
	fmt.Fprintf(&evidence, "# daemon pid: %d\n", daemon.cmd.Process.Pid)
	fmt.Fprintf(&evidence, "# require_authentication: true (operator %q)\n", m1bOperator)

	// The two VMs every terminal subtest runs against. They are created once:
	// a boot is about a minute, and the independence claim needs both alive at
	// the same time anyway.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	vmA := daemon.createVM(t, "m1b-a")
	vmB := daemon.createVM(t, "m1b-b")
	daemon.waitVMState(ctx, t, vmA, "running")
	daemon.waitVMState(ctx, t, vmB, "running")
	fmt.Fprintf(&evidence, "# vm_a: %s\n# vm_b: %s\n", vmA, vmB)

	// The host process tree before any terminal exists. Step 2 compares against
	// this: a guest PTY must add nothing to it.
	baselineProcs := descendantsOf(readHostProcs(t), daemon.cmd.Process.Pid)
	baselineComms := commsOf(baselineProcs)

	// ── AT-025: two VMs, two terminals, no crosstalk ───────────────────────────
	t.Run("at025_session_isolation", func(t *testing.T) {
		sessA := daemon.createTerminal(t, vmA)
		sessB := daemon.createTerminal(t, vmB)
		if sessA.ID == sessB.ID {
			t.Fatalf("two VMs handed out the same session id %q", sessA.ID)
		}
		termA := daemon.openTerm(t, sessA.ID, "vmA")
		termB := daemon.openTerm(t, sessB.ID, "vmB")

		// A marker written into one guest must never surface in the other. The
		// value is the VM id, so a stream carrying the wrong one names its own bug.
		markA := "MARK-" + vmA
		markB := "MARK-" + vmB
		outA := termA.runGuest("echo "+markA+" > /tmp/m1b.mark; cat /tmp/m1b.mark", m1bCommandTimeout)
		outB := termB.runGuest("echo "+markB+" > /tmp/m1b.mark; cat /tmp/m1b.mark", m1bCommandTimeout)

		if !strings.Contains(outA, markA) {
			t.Errorf("vmA stream never carried its own marker %q:\n%s", markA, tailOf(outA, 1000))
		}
		if !strings.Contains(outB, markB) {
			t.Errorf("vmB stream never carried its own marker %q:\n%s", markB, tailOf(outB, 1000))
		}
		if strings.Contains(termA.output(), markB) {
			t.Errorf("vmA's stream carried vmB's marker %q", markB)
		}
		if strings.Contains(termB.output(), markA) {
			t.Errorf("vmB's stream carried vmA's marker %q", markA)
		}

		// Independent shell state on the same host, in two different guests: the
		// file each wrote is the one each reads back.
		backA := termA.runGuest("cat /tmp/m1b.mark", m1bCommandTimeout)
		if !strings.Contains(backA, markA) || strings.Contains(backA, markB) {
			t.Errorf("vmA read back the wrong marker: %s", tailOf(backA, 400))
		}

		// AT-025's own definition is *same-VM* isolation: two sessions on one VM
		// keep separate cwd, shell state and dimensions. Same guest, same kernel,
		// two PTYs.
		sess1 := daemon.createTerminal(t, vmA)
		sess2 := daemon.createTerminal(t, vmA)
		term1 := daemon.openTerm(t, sess1.ID, "vmA-1")
		term2 := daemon.openTerm(t, sess2.ID, "vmA-2")

		term1.runGuest("mkdir -p /tmp/one && cd /tmp/one", m1bCommandTimeout)
		term2.runGuest("mkdir -p /tmp/two && cd /tmp/two", m1bCommandTimeout)
		cwd1 := strings.TrimSpace(term1.runGuest("pwd", m1bCommandTimeout))
		cwd2 := strings.TrimSpace(term2.runGuest("pwd", m1bCommandTimeout))
		if !strings.Contains(cwd1, "/tmp/one") {
			t.Errorf("session 1 cwd should be /tmp/one, got %q", tailOf(cwd1, 200))
		}
		if !strings.Contains(cwd2, "/tmp/two") {
			t.Errorf("session 2 cwd should be /tmp/two, got %q", tailOf(cwd2, 200))
		}

		// Shell variables are per session too.
		term1.runGuest("M1B_WHO=one", m1bCommandTimeout)
		who2 := term2.runGuest("echo who=[$M1B_WHO]", m1bCommandTimeout)
		if strings.Contains(who2, "who=[one]") {
			t.Errorf("session 2 inherited session 1's shell variable: %s", tailOf(who2, 200))
		}

		// Separate dimensions: resizing one leaves the other's stty alone.
		// The relay reads text and binary from one connection in wire order, so
		// the resize is applied before the command that reads the new size.
		term1.resize(40, 120)
		size1 := strings.TrimSpace(term1.runGuest("stty size", m1bCommandTimeout))
		size2 := strings.TrimSpace(term2.runGuest("stty size", m1bCommandTimeout))

		// Two sessions on one VM have different pids.
		if sess1.PID != 0 && sess1.PID == sess2.PID {
			t.Errorf("two sessions on %s report the same guest pid %d", vmA, sess1.PID)
		}

		evidenceSubtest(t, &evidence, "at025_session_isolation", fmt.Sprintf(
			"vm_a=%s session_a=%s vm_b=%s session_b=%s\n"+
				"cross_vm_leak=false marker_a_seen_in_a=%v marker_b_seen_in_b=%v\n"+
				"same_vm sessions=%s,%s pid1=%d pid2=%d cwd1=%q cwd2=%q\n"+
				"resize session1 -> 40x120; stty size: session1=%q session2=%q",
			vmA, sessA.ID, vmB, sessB.ID,
			strings.Contains(outA, markA), strings.Contains(outB, markB),
			sess1.ID, sess2.ID, sess1.PID, sess2.PID,
			lastLine(cwd1), lastLine(cwd2), lastLine(size1), lastLine(size2),
		))

		if !strings.Contains(size1, "40 120") {
			t.Errorf("resize did not reach session 1's guest pty: stty size = %q", tailOf(size1, 200))
		}
		if strings.Contains(size2, "40 120") {
			t.Errorf("session 1's resize changed session 2's pty: stty size = %q", tailOf(size2, 200))
		}
	})

	// ── AT-019: a real guest PTY, not a host shell ─────────────────────────────
	t.Run("at019_real_guest_pty", func(t *testing.T) {
		sess := daemon.createTerminal(t, vmA)
		term := daemon.openTerm(t, sess.ID, "guest-check")

		// Four questions only a guest can answer this way. The host is aibox03
		// with nvme disks and a systemd cgroup tree; the guest is a Firecracker
		// microVM with virtio disks and its own hostname.
		tty := strings.TrimSpace(term.runGuest("tty", m1bCommandTimeout))
		guestHost := strings.TrimSpace(term.runGuest("hostname", m1bCommandTimeout))
		disks := strings.TrimSpace(term.runGuest("ls -d /dev/vd* 2>/dev/null || echo none", m1bCommandTimeout))
		cgroup := strings.TrimSpace(term.runGuest("cat /proc/self/cgroup", m1bCommandTimeout))
		kernel := strings.TrimSpace(term.runGuest("uname -r", m1bCommandTimeout))

		// Job control needs a controlling terminal and a process group. A pipe
		// cannot do this: without a tty the shell has no job table to list.
		jobsOut := term.runGuest("sleep 120 & jobs", m1bCommandTimeout)
		term.runGuest("kill %1 2>/dev/null; true", m1bCommandTimeout)

		// A foreground process reading the terminal: cat with no argument sits on
		// stdin, the PTY echoes the line, and cat writes it back. Two copies of
		// the same text is the echo plus the program's own output — which is what
		// a terminal device does and a pipe does not.
		fgStart := term.received()
		term.typeLine("cat")
		term.typeLine("m1b-foreground")
		if !term.waitFor("m1b-foreground", m1bCommandTimeout) {
			t.Errorf("the foreground process never answered: %s", tailOf(term.output(), 800))
		}
		term.typeKeys([]byte{0x04}) // Ctrl-D ends cat's stdin, not the shell's
		fgOut := term.output()[fgStart:]
		echoes := strings.Count(fgOut, "m1b-foreground")

		hostKernel := hostUname(t)
		hostName, _ := os.Hostname()

		// The host process tree must not have grown a shell. A PTY served from
		// the host would appear here as a descendant of vmobsd; a PTY served from
		// the guest cannot appear at all, because it lives behind the VMM.
		afterProcs := descendantsOf(readHostProcs(t), daemon.cmd.Process.Pid)
		afterComms := commsOf(afterProcs)
		for pid, p := range afterProcs {
			if shellComms[p.comm] {
				t.Errorf("host process tree grew a shell while a terminal was open: pid %d comm %q", pid, p.comm)
			}
		}
		if afterComms != baselineComms {
			t.Errorf("host process tree changed while a terminal was open:\n  before: %s\n  after:  %s",
				baselineComms, afterComms)
		}
		// The pid the API reports for the session is a guest pid. If it named a
		// host process, it would be in the daemon's descendants.
		if sess.PID != 0 {
			if _, onHost := afterProcs[sess.PID]; onHost {
				t.Errorf("session pid %d is a host process under vmobsd, not a guest process", sess.PID)
			}
		}

		if !strings.Contains(tty, "/dev/pts/") {
			t.Errorf("tty did not answer with a pty device: %q", tailOf(tty, 200))
		}
		if strings.Contains(guestHost, hostName) {
			t.Errorf("the shell reports the host's own hostname %q: %q", hostName, tailOf(guestHost, 200))
		}
		if strings.Contains(kernel, hostKernel) {
			t.Errorf("the shell reports the host kernel %q: %q", hostKernel, tailOf(kernel, 200))
		}

		evidenceSubtest(t, &evidence, "at019_real_guest_pty", fmt.Sprintf(
			"session=%s guest_pid=%d\n"+
				"guest tty=%q hostname=%q kernel=%q\n"+
				"host hostname=%q kernel=%q\n"+
				"guest /dev/vd*=%q\n"+
				"guest /proc/self/cgroup=%q\n"+
				"job control: %q\n"+
				"foreground cat: %d occurrences of the typed line (echo + program output)\n"+
				"vmobsd descendants before=%q after=%q (no shell in either)",
			sess.ID, sess.PID,
			lastLine(tty), lastLine(guestHost), lastLine(kernel),
			hostName, hostKernel,
			lastLine(disks), lastLine(cgroup),
			tailOf(strings.TrimSpace(jobsOut), 200),
			echoes,
			baselineComms, afterComms,
		))

		if !strings.Contains(jobsOut, "sleep") {
			t.Errorf("the shell has no job table, so this is not a controlling terminal: %s", tailOf(jobsOut, 500))
		}
		if echoes < 2 {
			t.Errorf("a foreground reader saw the line %d times; a pty echoes it and the program repeats it: %s",
				echoes, tailOf(fgOut, 500))
		}
	})

	// ── AT-022: reconnect resumes the same shell, replaying once ───────────────
	t.Run("at022_reconnect_same_shell", func(t *testing.T) {
		sess := daemon.createTerminal(t, vmA)
		term := daemon.openTerm(t, sess.ID, "reconnect-1")

		// $$ is the shell's own pid inside the guest. Same shell after a
		// reconnect means the same number.
		before := strings.TrimSpace(term.runGuest("echo pid=$$", m1bCommandTimeout))
		beforePID := afterEquals(before, "pid=")
		if beforePID == "" {
			t.Fatalf("could not read the guest shell pid from %q", tailOf(before, 300))
		}
		// A marker in the ring, so a replay that duplicated output would show it
		// twice on the far side of the reconnect. It is typed with an empty quote
		// pair inside it — the same trick runGuest uses — because a pty echoes
		// the command line before the shell prints anything: typed plainly, one
		// clean replay would already read as two.
		unique := "RECONNECT-CANARY-9137"
		term.runGuest(`echo RECONNECT""-CANARY-9137`, m1bCommandTimeout)
		term.close()

		term2 := daemon.openTerm(t, sess.ID, "reconnect-2")
		// The old connection's lease survives its disconnect for the grace
		// window, so the reattached browser starts read-only and asks for the
		// shell — exactly what §8.2 says and what the UI's button does.
		reattachWriter := term2.isWriter()
		term2.takeWriter()
		after := strings.TrimSpace(term2.runGuest("echo pid=$$", m1bCommandTimeout))
		afterPID := afterEquals(after, "pid=")

		// The reattached stream resumes at the ring's tail, so it may replay some
		// of what the first connection already saw. It must never replay it twice
		// inside one connection.
		replay := term2.output()
		dupes := strings.Count(replay, unique)

		evidenceSubtest(t, &evidence, "at022_reconnect_same_shell", fmt.Sprintf(
			"session=%s pid_before=%s pid_after=%s canary_occurrences_after_reattach=%d\n"+
				"writer_on_reattach=%v (lease grace window held by the departed connection), steal succeeded",
			sess.ID, beforePID, afterPID, dupes, reattachWriter,
		))

		if beforePID != afterPID {
			t.Errorf("reconnect landed on a different shell: pid %s before, %s after", beforePID, afterPID)
		}
		if dupes > 1 {
			t.Errorf("reattach replayed the same output %d times; §8.3 replays a ring once", dupes)
		}
	})

	// ── AT-020: full-screen programs, resize, UTF-8, color, paste ──────────────
	t.Run("at020_fullscreen_and_encoding", func(t *testing.T) {
		sess := daemon.createTerminal(t, vmA)
		term := daemon.openTerm(t, sess.ID, "fullscreen")

		// Resize repeatedly; the guest's own stty is the witness, so this is
		// SIGWINCH reaching the guest pty rather than a number the host echoed.
		var sizes []string
		for _, d := range [][2]uint16{{40, 120}, {30, 100}, {50, 132}, {24, 80}} {
			term.resize(d[0], d[1])
			got := lastLine(term.runGuest("stty size", m1bCommandTimeout))
			want := fmt.Sprintf("%d %d", d[0], d[1])
			sizes = append(sizes, fmt.Sprintf("%s->%q", want, got))
			if got != want {
				t.Errorf("resize to %s did not reach the guest: stty size said %q", want, got)
			}
		}

		// UTF-8, color and the alternate screen, emitted by the guest and
		// compared byte for byte. printf's octal escapes keep the test source
		// free of the raw control bytes it is checking for.
		utf8Start := term.received()
		term.runGuest(`printf 'caf\303\251 \346\227\245\346\234\254\n'`, m1bCommandTimeout)
		term.runGuest(`printf '\033[31mRED\033[0m\n'`, m1bCommandTimeout)
		term.runGuest(`printf '\033[?1049hALT\033[?1049l\n'`, m1bCommandTimeout)
		seen := term.output()[utf8Start:]
		for _, want := range []string{"café", "日本", "\x1b[31mRED\x1b[0m", "\x1b[?1049h", "\x1b[?1049l"} {
			if !strings.Contains(seen, want) {
				t.Errorf("the relay did not deliver %q verbatim:\n%s", want, tailOf(seen, 600))
			}
		}

		// Bracketed paste: the browser sends the paste markers as input, and the
		// guest writes what it received to a file. od -c proves the bytes crossed
		// the relay unchanged rather than being interpreted somewhere en route.
		term.typeLine("cat > /tmp/m1b-paste.bin")
		term.typeKeys([]byte("\x1b[200~pasted-text\x1b[201~"))
		// A canonical-mode pty closes stdin on Ctrl-D only at the start of an
		// empty line; sent after the paste it would just flush the partial line
		// and leave cat reading — swallowing the od command that follows. The
		// carriage return ends the pasted line, and the Ctrl-D then ends the file.
		term.typeKeys([]byte{'\r'})
		term.typeKeys([]byte{0x04})
		paste := term.runGuest("od -c /tmp/m1b-paste.bin | head -4", m1bCommandTimeout)
		// od renders ESC as \e or 033 depending on the build; both name the byte.
		pastedOK := strings.Contains(paste, "200") && strings.Contains(paste, "201") &&
			strings.Contains(paste, "p   a   s   t   e   d")
		if !pastedOK {
			t.Errorf("bracketed paste markers did not arrive at the guest verbatim:\n%s", tailOf(paste, 800))
		}

		// The two programs SPEC §8.2 names by name, actually installed in the
		// image and actually started.
		viOK := term.runFullScreen("vi /tmp/m1b-vi.txt", "\x1b:q!\r", []string{"\x1b["}, m1bCommandTimeout)
		topOK := term.runFullScreen("top", "q", []string{"\x1b["}, m1bCommandTimeout)

		evidenceSubtest(t, &evidence, "at020_fullscreen_and_encoding", fmt.Sprintf(
			"session=%s\nresize: %s\n"+
				"utf8 café/日本=%v color CSI=%v alt-screen 1049h/l=%v\n"+
				"bracketed paste reached the guest verbatim=%v\n"+
				"vi drew a screen and exited=%v; top drew a screen and exited=%v\n"+
				"od -c of the pasted file: %s",
			sess.ID, strings.Join(sizes, " "),
			strings.Contains(seen, "café") && strings.Contains(seen, "日本"),
			strings.Contains(seen, "\x1b[31mRED"),
			strings.Contains(seen, "\x1b[?1049h"),
			pastedOK, viOK, topOK,
			tailOf(strings.TrimSpace(paste), 400),
		))

		if !viOK {
			t.Error("vi did not draw a screen and exit cleanly")
		}
		if !topOK {
			t.Error("the process viewer did not draw a screen and exit cleanly")
		}
	})

	// ── AT-021: signals and job control ────────────────────────────────────────
	t.Run("at021_signals_and_jobs", func(t *testing.T) {
		sess := daemon.createTerminal(t, vmA)
		term := daemon.openTerm(t, sess.ID, "signals")

		// Ctrl-C interrupts the foreground process and leaves the shell running.
		term.typeLine("sleep 300")
		time.Sleep(500 * time.Millisecond)
		term.typeKeys([]byte{0x03})
		alive := term.runGuest("echo still=alive", m1bCommandTimeout)
		ctrlCOK := strings.Contains(alive, "still=alive")

		// Ctrl-Z suspends it; bg resumes it in the background; jobs lists it; fg
		// brings it back. This is process-group behaviour a pipe cannot provide.
		term.typeLine("sleep 300")
		time.Sleep(500 * time.Millisecond)
		term.typeKeys([]byte{0x1a}) // Ctrl-Z
		time.Sleep(500 * time.Millisecond)
		suspended := term.runGuest("jobs", m1bCommandTimeout)
		term.runGuest("bg %1 2>/dev/null; true", m1bCommandTimeout)
		running := term.runGuest("jobs", m1bCommandTimeout)
		term.runGuest("kill %1 2>/dev/null; true", m1bCommandTimeout)

		// Ctrl-D on the shell's own stdin ends the session. This one has its own
		// terminal because there is no shell left afterwards.
		eofSess := daemon.createTerminal(t, vmA)
		eofTerm := daemon.openTerm(t, eofSess.ID, "eof")
		eofTerm.runGuest("echo ready", m1bCommandTimeout)
		eofTerm.typeKeys([]byte{0x04})
		closedMsg, gotClosed := eofTerm.waitControl("closed", m1bCommandTimeout)

		evidenceSubtest(t, &evidence, "at021_signals_and_jobs", fmt.Sprintf(
			"session=%s\nctrl-c interrupted the foreground process and left the shell alive=%v\n"+
				"ctrl-z jobs: %q\nafter bg, jobs: %q\n"+
				"ctrl-d on session %s closed it=%v reason=%q exit_code=%s",
			sess.ID, ctrlCOK,
			tailOf(strings.TrimSpace(suspended), 200), tailOf(strings.TrimSpace(running), 200),
			eofSess.ID, gotClosed, closedMsg.Reason, exitCodeOf(closedMsg),
		))

		if !ctrlCOK {
			t.Errorf("the shell did not survive Ctrl-C on a foreground process: %s", tailOf(alive, 500))
		}
		if !strings.Contains(suspended, "sleep") {
			t.Errorf("Ctrl-Z did not produce a suspended job: %s", tailOf(suspended, 500))
		}
		if !gotClosed {
			t.Errorf("Ctrl-D did not close the session; controls: %+v", eofTerm.controls())
		}
	})

	// ── AT-023: overflow the ring while detached ───────────────────────────────
	t.Run("at023_replay_gap", func(t *testing.T) {
		sess := daemon.createTerminal(t, vmA)
		term := daemon.openTerm(t, sess.ID, "gap-1")

		// A marker printed just before the disconnect. The guest's replay ring is
		// 256 KiB by default, so a flood many times that size must push this out.
		canary := "GAP-CANARY-4471"
		term.runGuest("echo "+canary, m1bCommandTimeout)
		// Start a bounded flood, then leave. The broker keeps draining the PTY
		// into the ring with nobody attached, which is the condition AT-023
		// describes. A megabyte wraps a 256 KiB ring four times, and `head -c`
		// stops it on its own so nothing is still shouting on reattach.
		term.typeLine("yes m1b-flood | head -c 1000000")
		time.Sleep(500 * time.Millisecond)
		term.close()
		time.Sleep(5 * time.Second)

		term2 := daemon.openTerm(t, sess.ID, "gap-2")
		att, ok := term2.waitControl("attached", m1bAttachTimeout)
		if !ok {
			t.Fatal("reattach produced no attached message")
		}
		resume, _ := strconv.ParseUint(att.ResumeOffset, 10, 64)

		// Let the ring's tail arrive before reading it.
		time.Sleep(2 * time.Second)
		replayed := term2.output()
		canaryReplayed := strings.Contains(replayed, canary)

		evidenceSubtest(t, &evidence, "at023_replay_gap", fmt.Sprintf(
			"session=%s gap=%v resume_offset=%s replay_bytes=%d\n"+
				"pre-disconnect canary %q still in the replay=%v (false is the point: it aged out)",
			sess.ID, att.Gap, att.ResumeOffset, len(replayed), canary, canaryReplayed,
		))

		if !att.Gap {
			t.Errorf("reattach after a ring overflow did not declare a gap: %+v", att)
		}
		if resume == 0 {
			t.Errorf("reattach after a ring overflow resumed at offset 0, claiming the whole history: %+v", att)
		}
		if canaryReplayed {
			t.Errorf("the replay still carried %q from before the overflow, so the ring did not wrap "+
				"and this run did not exercise AT-023", canary)
		}
	})

	// ── AT-024: two browsers, one session, one writer ──────────────────────────
	t.Run("at024_writer_lease", func(t *testing.T) {
		sess := daemon.createTerminal(t, vmA)
		first := daemon.openTerm(t, sess.ID, "lease-first")
		firstAtt, _ := first.waitControl("attached", m1bAttachTimeout)
		second := daemon.openTerm(t, sess.ID, "lease-second")
		secondAtt, _ := second.waitControl("attached", m1bAttachTimeout)

		if !firstAtt.Writer {
			t.Fatalf("the first attachment is not the writer: %+v", firstAtt)
		}
		if secondAtt.Writer {
			t.Fatalf("a second attachment took the writer lease without asking: %+v", secondAtt)
		}
		if secondAtt.Holder != firstAtt.ConnID {
			t.Errorf("the read-only view was not told who holds the shell: holder=%q, writer is %q",
				secondAtt.Holder, firstAtt.ConnID)
		}

		// A read-only connection's keystrokes are refused out loud, not dropped:
		// silence is indistinguishable from a hung shell (§8.2).
		refusedMark := "READONLY-MUST-NOT-RUN"
		beforeCtl := len(second.controls())
		second.typeLine("echo " + refusedMark)
		leaseMsg, _, gotRefusal := second.waitControlAfter("lease", beforeCtl, 5*time.Second)

		// The same for a resize.
		beforeResize := len(second.controls())
		second.resize(66, 166)
		_, _, resizeRefused := second.waitControlAfter("lease", beforeResize, 5*time.Second)

		// Nothing the read-only view typed reached the guest.
		size := lastLine(first.runGuest("stty size", m1bCommandTimeout))
		// The mark never crosses to the guest, so it can never be echoed back on
		// any attachment. Any occurrence at all is a leak.
		leaked := strings.Contains(first.output(), refusedMark)

		// A transfer takes the shell at that instant: the old writer is told, and
		// its next keystroke is refused.
		beforeSteal := len(first.controls())
		second.takeWriter()
		demote, _, demoted := first.waitControlAfter("lease", beforeSteal, 10*time.Second)

		beforeStale := len(first.controls())
		first.typeLine("echo STALE-WRITER")
		_, _, staleRefused := first.waitControlAfter("lease", beforeStale, 5*time.Second)

		evidenceSubtest(t, &evidence, "at024_writer_lease", fmt.Sprintf(
			"session=%s first_conn=%s second_conn=%s\n"+
				"second attached read-only, holder=%q\n"+
				"read-only input refused with a lease message=%v reason=%q\n"+
				"read-only resize refused with a lease message=%v\n"+
				"guest stty size after the refused resize=%q (unchanged)\n"+
				"steal demoted the old writer=%v writer_now=%v holder_now=%q\n"+
				"old writer's next keystroke refused=%v",
			sess.ID, firstAtt.ConnID, secondAtt.ConnID, secondAtt.Holder,
			gotRefusal, leaseMsg.Reason, resizeRefused, size,
			demoted, demote.Writer, demote.Holder, staleRefused,
		))

		if !gotRefusal {
			t.Errorf("a read-only connection's keystrokes vanished silently; controls: %+v", second.controls())
		}
		if leaked {
			t.Errorf("a read-only connection's keystrokes reached the guest (%q ran)", refusedMark)
		}
		if !resizeRefused {
			t.Errorf("a read-only connection's resize vanished silently; controls: %+v", second.controls())
		}
		if strings.Contains(size, "66 166") {
			t.Errorf("a read-only connection resized the guest pty: stty size = %q", size)
		}
		if !demoted || demote.Writer {
			t.Errorf("the old writer was not told the shell moved: demoted=%v msg=%+v", demoted, demote)
		}
		if !staleRefused {
			t.Errorf("a stale writer kept typing after the transfer; controls: %+v", first.controls())
		}
	})

	// ── AT-026: duplicate input frames ─────────────────────────────────────────
	t.Run("at026_duplicate_input", func(t *testing.T) {
		sess := daemon.createTerminal(t, vmA)
		term := daemon.openTerm(t, sess.ID, "dupes")
		term.runGuest("echo ready", m1bCommandTimeout)

		// One accepted frame, sent twice under the same sequence number. The
		// quote pair keeps the command's echo from matching the marker the
		// command prints, so the count below is of runs, not of keystrokes.
		start := term.received()
		seq := term.nextSeq()
		line := []byte("echo DUP\"\"MARK-2261\r")
		if err := term.sendInput(seq, line); err != nil {
			t.Fatalf("send input: %v", err)
		}
		if err := term.sendInput(seq, line); err != nil {
			t.Fatalf("resend input: %v", err)
		}
		if !term.waitForAfter("DUPMARK-2261", start, m1bCommandTimeout) {
			t.Fatalf("the command never ran: %s", tailOf(term.output()[start:], 800))
		}
		// Give a duplicate run time to appear before counting.
		time.Sleep(2 * time.Second)
		runs := strings.Count(term.output()[start:], "DUPMARK-2261")

		// The other half of §8.2: after a connection is lost, input is not
		// resent automatically. The browser (web/src/terminalSocket.ts) queues no
		// input and resends nothing; it reports the reconnect instead. The host's
		// own sequence high-water mark is per connection, not per session — see
		// the deviation recorded in PLAN.md — so this gate asserts the guarantee
		// §8.2 names (no duplicated typing, no blind resend) rather than the
		// mechanism it suggests.
		term.close()
		term2 := daemon.openTerm(t, sess.ID, "dupes-2")
		term2.takeWriter()
		afterReconnect := term2.received()
		term2.runGuest("echo AFTER\"\"-RECONNECT", m1bCommandTimeout)
		resent := strings.Count(term2.output()[afterReconnect:], "DUPMARK-2261")

		evidenceSubtest(t, &evidence, "at026_duplicate_input", fmt.Sprintf(
			"session=%s\nframe seq=%d sent twice; the command ran %d time(s)\n"+
				"after a reconnect the guest re-ran nothing: %d occurrence(s) of the marker\n"+
				"deviation: the host's input high-water mark is per connection "+
				"(internal/api/terminal_stream.go streamRelay.lastClientSeq); §8.2 describes it as per session. "+
				"The browser never resends input across a reconnect, so no duplicate typing is reachable.",
			sess.ID, seq, runs, resent,
		))

		if runs != 1 {
			t.Errorf("a retransmitted accepted frame typed the same text %d times", runs)
		}
		if resent != 0 {
			t.Errorf("input was replayed into the guest after a reconnect (%d times)", resent)
		}
	})

	// ── AT-027: a deliberately slow browser ────────────────────────────────────
	t.Run("at027_slow_browser", func(t *testing.T) {
		sess := daemon.createTerminal(t, vmA)
		term := daemon.openTerm(t, sess.ID, "slow")
		att, ok := term.waitControl("attached", m1bAttachTimeout)
		if !ok {
			t.Fatal("no attached message")
		}
		maxInflight, err := strconv.ParseInt(att.MaxInflightBytes, 10, 64)
		if err != nil || maxInflight <= 0 {
			t.Fatalf("attached did not name an in-flight ceiling: %q (%v)", att.MaxInflightBytes, err)
		}
		term.runGuest("echo ready", m1bCommandTimeout)

		// Stop acking. From here the host may send at most maxInflight bytes
		// beyond what this browser has already reported consuming.
		stalledAt := term.setAutoAck(false)
		term.typeLine("yes m1b-slow-flood | head -c 8000000")

		// Let the guest get far ahead of the window.
		time.Sleep(10 * time.Second)
		inflight := int64(term.received()) - int64(stalledAt)

		// The control channel is not starved by the flood: a lease request made
		// while the output window is full still gets an answer.
		beforeCtl := len(term.controls())
		term.lease("acquire")
		_, _, controlAnswered := term.waitControlAfter("lease", beforeCtl, 15*time.Second)

		// The guest declares what it lost rather than pretending continuity. The
		// broker's ring wraps behind the stalled host, and that range arrives as
		// a dropped message with both offsets.
		dropped, gotDrop := term.waitControl("dropped", 30*time.Second)

		// Acking again releases the window and the stream resumes.
		term.setAutoAck(true)
		resumedFrom := term.received()
		resumed := false
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			if term.received() > resumedFrom {
				resumed = true
				break
			}
			time.Sleep(200 * time.Millisecond)
		}

		evidenceSubtest(t, &evidence, "at027_slow_browser", fmt.Sprintf(
			"session=%s max_inflight_bytes=%d\n"+
				"bytes delivered to a browser that stopped acking: %d (ceiling %d)\n"+
				"control channel answered while the window was full=%v\n"+
				"guest declared a dropped range=%v from=%s to=%s\n"+
				"stream resumed once the browser acked again=%v",
			sess.ID, maxInflight, inflight, maxInflight,
			controlAnswered, gotDrop, dropped.FromOffset, dropped.ToOffset,
			resumed,
		))

		if inflight > maxInflight {
			t.Errorf("the host sent %d unacked bytes past a ceiling of %d", inflight, maxInflight)
		}
		if !controlAnswered {
			t.Errorf("a full output window starved the control channel; controls: %d", len(term.controls()))
		}
		if !gotDrop {
			t.Error("the guest never declared the output it dropped behind a stalled browser")
		}
		if !resumed {
			t.Error("the stream did not resume after the browser started acking again")
		}
	})

	// ── AT-029: hostile output crosses the relay as bytes, not as commands ─────
	t.Run("at029_hostile_output", func(t *testing.T) {
		sess := daemon.createTerminal(t, vmB)
		term := daemon.openTerm(t, sess.ID, "hostile")

		start := term.received()
		// HTML, an OSC 52 clipboard load, an OSC 8 hyperlink, an OSC 0 window
		// title and an OSC 52 "download" of a payload. Each is emitted by the
		// guest exactly as an attacker would emit it.
		term.runGuest(`printf '<img src=x onerror=alert(1)>\n'`, m1bCommandTimeout)
		term.runGuest(`printf '\033]52;c;bTFiLWNsaXBib2FyZA==\007\n'`, m1bCommandTimeout)
		term.runGuest(`printf '\033]8;;javascript:alert(1)\033\\link\033]8;;\033\\\n'`, m1bCommandTimeout)
		term.runGuest(`printf '\033]0;m1b-hostile-title\007\n'`, m1bCommandTimeout)
		seen := term.output()[start:]

		// The host is a relay: it delivers these bytes and interprets none of
		// them. Anything the host had acted on would be missing here.
		verbatim := map[string]bool{
			"<img src=x onerror=alert(1)>": strings.Contains(seen, "<img src=x onerror=alert(1)>"),
			"OSC 52 clipboard":             strings.Contains(seen, "\x1b]52;c;bTFiLWNsaXBib2FyZA=="),
			"OSC 8 javascript: hyperlink":  strings.Contains(seen, "\x1b]8;;javascript:alert(1)"),
			"OSC 0 window title":           strings.Contains(seen, "\x1b]0;m1b-hostile-title"),
		}

		// The two config switches §8.4 requires to be off by default, read back
		// from the daemon's own config file rather than assumed.
		cfg, cfgErr := os.ReadFile(daemon.configPath)
		clipboardOff := cfgErr == nil && strings.Contains(string(cfg), "automatic_clipboard_write: false")
		downloadOff := cfgErr == nil && strings.Contains(string(cfg), "automatic_download: false")

		var lines []string
		for k, v := range verbatim {
			lines = append(lines, fmt.Sprintf("  %s delivered verbatim=%v", k, v))
		}
		sort.Strings(lines)
		evidenceSubtest(t, &evidence, "at029_hostile_output", fmt.Sprintf(
			"session=%s (host half — the relay is byte-transparent and interprets nothing)\n%s\n"+
				"config automatic_clipboard_write=false: %v; automatic_download=false: %v\n"+
				"browser half: web/src/Terminal.test.tsx asserts against real xterm.js that OSC 52 never\n"+
				"reaches navigator.clipboard and that hostile output renders as text, never as markup.\n"+
				"This Go gate does not run a DOM and does not claim to.",
			sess.ID, strings.Join(lines, "\n"), clipboardOff, downloadOff,
		))

		for k, v := range verbatim {
			if !v {
				t.Errorf("the host altered or swallowed %s instead of relaying it", k)
			}
		}
		if !clipboardOff {
			t.Error("automatic_clipboard_write is not off in the daemon's config")
		}
		if !downloadOff {
			t.Error("automatic_download is not off in the daemon's config")
		}
	})

	// ── AT-028: lifecycle actions while a browser is attached ──────────────────
	t.Run("at028_lifecycle_while_attached", func(t *testing.T) {
		// vmA and vmB carry the other subtests; this one takes a VM through
		// pause, resume and a stop/start pair, so it gets one of its own. The
		// dispose registration comes first, so the VM is freed however this
		// subtest exits.
		daemon.disposeSubtestVMs(t)
		vmC := daemon.createVM(t, "m1b-lifecycle")
		lifeCtx, lifeCancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer lifeCancel()
		daemon.waitVMState(lifeCtx, t, vmC, "running")

		sess := daemon.createTerminal(t, vmC)
		term := daemon.openTerm(t, sess.ID, "lifecycle")
		term.runGuest("echo before=pause", m1bCommandTimeout)

		// Pause. The VM stops executing, so the shell stops answering; the UI's
		// distinction comes from the VM's own observed_state, which the fleet
		// page polls (web/src/VMDetail.tsx reads it on every refresh).
		//
		// This runtime may not implement it: internal/jailer/adapter.go answers
		// pause and resume with a typed missing_capability, a milestone scope
		// decision recorded in PLAN.md (M1a Task 10). So the gate asks for the
		// pause the way the UI's button does and records what the host did. When
		// pause is built, the first branch proves the vCPU really stopped; until
		// then the second proves the refusal is typed and leaves the attached
		// session alone — a refused action that broke the shell would be a bug
		// here, not a missing feature.
		pauseStatus, pauseCause, pauseMsg := daemon.tryVMAction(t, vmC, "pause")
		pauseImplemented := pauseStatus == http.StatusOK
		var (
			pausedState         string
			answeredWhilePaused bool
			resumedOK           bool
			afterResume         string
		)
		if pauseImplemented {
			daemon.waitVMState(lifeCtx, t, vmC, "paused")
			pausedState = daemon.vmState(t, vmC)
			pausedProgress := term.received()
			term.typeLine("echo during=pause")
			time.Sleep(3 * time.Second)
			answeredWhilePaused = term.received() > pausedProgress

			// Resume. The same shell picks up where it stopped, including the
			// keystrokes that sat in the pty while the vCPU was frozen.
			daemon.vmAction(t, vmC, "resume")
			daemon.waitVMState(lifeCtx, t, vmC, "running")
			resumedOK = term.waitForAfter("during=pause", pausedProgress, m1bCommandTimeout)
		} else {
			pausedState = daemon.vmState(t, vmC)
		}
		afterResume = term.runGuest("echo after=resume", m1bCommandTimeout)

		// Stop. Every session on the VM ends with it (§8.1).
		daemon.vmAction(t, vmC, "stop")
		daemon.waitVMState(lifeCtx, t, vmC, "stopped")
		_, streamEnded := term.closed()
		if !streamEnded {
			// The relay may take a moment to notice the runner is gone.
			deadline := time.Now().Add(30 * time.Second)
			for time.Now().Before(deadline) {
				if _, done := term.closed(); done {
					streamEnded = true
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
		}
		sessAfterStop, sessionStillListed := daemon.getTerminal(t, vmC, sess.ID)

		// A new boot. The old session id must not resolve onto the new shell.
		//
		// There is no reboot action in this build — Manager.doAction handles
		// start, pause, resume, stop and force_stop — so the new boot is made
		// the only way the API offers, with stop followed by start. The refusal's
		// cause is recorded as observed rather than predicted: the host attaches
		// without a boot id, so the runner or the guest is what refuses.
		daemon.vmAction(t, vmC, "start")
		daemon.waitVMState(lifeCtx, t, vmC, "running")
		staleStatus, staleCause, staleMsg := daemon.upgradeStatus(t, sess.ID, "http://"+daemon.addr)

		shellSurvived := strings.Contains(afterResume, "after=resume")
		pauseEvidence := fmt.Sprintf(
			"pause: observed_state=%q; the shell answered nothing while paused=%v\n"+
				"resume: the keystrokes typed while paused were executed=%v; shell still works=%v",
			pausedState, !answeredWhilePaused, resumedOK, shellSurvived)
		if !pauseImplemented {
			pauseEvidence = fmt.Sprintf(
				"pause: INCONCLUSIVE — this runtime does not implement VMM pause.\n"+
					"  POST /vms/%s/actions {action: pause} -> HTTP %d cause=%q message=%q\n"+
					"  The VM stayed %q and the attached session survived the refusal: shell still works=%v.\n"+
					"resume: INCONCLUSIVE — paired with pause (internal/jailer/adapter.go).",
				vmC, pauseStatus, pauseCause, pauseMsg, pausedState, shellSurvived)
		}

		evidenceSubtest(t, &evidence, "at028_lifecycle_while_attached", fmt.Sprintf(
			"vm=%s session=%s\n"+
				"%s\n"+
				"stop: the attached stream ended=%v; session still listed on the VM=%v state=%q\n"+
				"new boot via stop+start (this build has no reboot action): "+
				"reattach with the old session id -> HTTP %d cause=%q message=%q",
			vmC, sess.ID,
			pauseEvidence,
			streamEnded, sessionStillListed, sessAfterStop.State,
			staleStatus, staleCause, staleMsg,
		))

		if pauseImplemented {
			if pausedState != "paused" {
				t.Errorf("pause left the VM in %q", pausedState)
			}
			if answeredWhilePaused {
				t.Error("a paused VM's shell kept answering, so the vCPU was not actually stopped")
			}
			if !resumedOK {
				t.Error("resume did not deliver the keystrokes the paused pty was holding")
			}
		} else {
			if pauseStatus < 400 {
				t.Errorf("pause was neither performed nor refused: HTTP %d", pauseStatus)
			}
			if pauseCause == "" {
				t.Errorf("the pause refusal carried no typed cause (HTTP %d): %q", pauseStatus, pauseMsg)
			}
			if pausedState != "running" {
				t.Errorf("a refused pause left the VM in %q, not running", pausedState)
			}
		}
		if !shellSurvived {
			t.Errorf("the shell stopped working across the pause step: %s", tailOf(afterResume, 500))
		}
		if !streamEnded {
			t.Error("stopping the VM left the browser's stream open")
		}
		if staleStatus == http.StatusSwitchingProtocols {
			t.Errorf("the old session id attached to a new boot (HTTP %d); §8.2 says a reboot invalidates it",
				staleStatus)
		}
	})

	// ── AT-030: every denied upgrade, denied before a PTY exists ───────────────
	t.Run("at030_denied_upgrades", func(t *testing.T) {
		sess := daemon.createTerminal(t, vmB)
		before := daemon.openSessionCount(t, vmB)

		origin := "http://" + daemon.addr
		type denial struct {
			name   string
			status int
			cause  string
			msg    string
		}
		var denials []denial

		record := func(name string, status int, cause, msg string) {
			denials = append(denials, denial{name, status, cause, msg})
		}

		// 1. No credential at all.
		st, cause, msg := upgradeWith(t, daemon.addr, sess.ID, origin, nil, nil)
		record("unauthenticated", st, cause, msg)

		// 2. A logged-in session, but an Origin this host does not serve. §8.4
		//    validates the exact allowed Origin independently of CORS.
		st, cause, msg = daemon.upgradeStatus(t, sess.ID, "http://evil.example.invalid")
		record("wrong_origin", st, cause, msg)

		// 3. A valid credential belonging to somebody else. The store mints it
		//    directly, because the API offers no way to create another owner's
		//    token — which is itself the point.
		store, err := auth.OpenStore(daemon.credDir)
		if err != nil {
			t.Fatalf("open credential store: %v", err)
		}
		secret, rec, err := store.CreateToken("m1b-intruder", m1bIntruder, time.Hour)
		if err != nil {
			t.Fatalf("mint an intruder token: %v", err)
		}
		registerGateSecret(secret)
		st, cause, msg = upgradeWith(t, daemon.addr, sess.ID, origin,
			http.Header{"Authorization": []string{"Bearer " + secret}}, nil)
		record("wrong_owner", st, cause, msg)

		// 4. A session cookie that was valid and is not any more.
		expiredCookies, expiredCSRF := daemon.expiredSession(t)
		st, cause, msg = upgradeWith(t, daemon.addr, sess.ID, origin,
			http.Header{csrfHeaderName: []string{expiredCSRF}}, expiredCookies)
		record("expired_session", st, cause, msg)

		after := daemon.openSessionCount(t, vmB)

		var lines []string
		for _, d := range denials {
			lines = append(lines, fmt.Sprintf("  %-16s HTTP %d cause=%q message=%q", d.name, d.status, d.cause, d.msg))
		}
		evidenceSubtest(t, &evidence, "at030_denied_upgrades", fmt.Sprintf(
			"vm=%s existing session=%s intruder token id=%s\n%s\n"+
				"open sessions on the VM before=%d after=%d (no PTY was reached)",
			vmB, sess.ID, rec.ID, strings.Join(lines, "\n"), before, after,
		))

		for _, d := range denials {
			if d.status == http.StatusSwitchingProtocols || d.status < 400 {
				t.Errorf("%s upgrade was not denied: HTTP %d", d.name, d.status)
			}
		}
		if after != before {
			t.Errorf("denied upgrades changed the VM's open session count: %d -> %d", before, after)
		}
	})

	// Write evidence (only when the gate actually ran).
	evidencePath := filepath.Join(repoRoot, evidenceDir, fmt.Sprintf("m1b-gate-%s.txt", hostname))
	if err := os.MkdirAll(filepath.Join(repoRoot, evidenceDir), 0755); err != nil {
		t.Logf("write evidence: mkdir: %v", err)
	} else if err := os.WriteFile(evidencePath, []byte(evidence.String()), 0644); err != nil {
		t.Logf("write evidence: %v", err)
	} else {
		t.Logf("evidence written to %s", evidencePath)
	}
}

// ---------------------------------------------------------------------------
// Lifecycle and upgrade-denial helpers.
// ---------------------------------------------------------------------------

// vmAction posts one lifecycle action, carrying the revision the VM currently
// reports so the host's optimistic-concurrency check has something to check.
func (d *m1aDaemon) vmAction(t *testing.T, vmID, action string) {
	t.Helper()
	vm := d.apiGet(t, "/vms/"+vmID)
	rev, _ := vm["revision"].(string)
	status, body := d.apiPost(t, "/vms/"+vmID+"/actions", map[string]any{
		"action":            action,
		"expected_revision": rev,
	})
	if status != http.StatusOK {
		t.Fatalf("action %s on %s: expected 200, got %d: %v", action, vmID, status, body)
	}
}

// tryVMAction posts a lifecycle action and reports what came back, refusals
// included. vmAction is the strict form; this one is for the actions a build
// may legitimately not implement yet.
func (d *m1aDaemon) tryVMAction(t *testing.T, vmID, action string) (int, string, string) {
	t.Helper()
	vm := d.apiGet(t, "/vms/"+vmID)
	rev, _ := vm["revision"].(string)
	status, body := d.apiPost(t, "/vms/"+vmID+"/actions", map[string]any{
		"action":            action,
		"expected_revision": rev,
	})
	cause, _ := body["cause"].(string)
	msg, _ := body["message"].(string)
	return status, cause, msg
}

// vmState is the VM's observed lifecycle state.
func (d *m1aDaemon) vmState(t *testing.T, vmID string) string {
	t.Helper()
	vm := d.apiGet(t, "/vms/"+vmID)
	state, _ := vm["observed_state"].(string)
	return state
}

// upgradeStatus attempts a WebSocket upgrade with this daemon's own logged-in
// credentials and the given Origin, and reports what came back.
func (d *m1aDaemon) upgradeStatus(t *testing.T, sessionID, origin string) (int, string, string) {
	t.Helper()
	var cookies []*http.Cookie
	if d.httpClient.Jar != nil {
		cookies = d.httpClient.Jar.Cookies(mustParseURL(t, d.baseURL))
	}
	h := http.Header{}
	if d.csrf != "" {
		h.Set(csrfHeaderName, d.csrf)
	}
	return upgradeWith(t, d.addr, sessionID, origin, h, cookies)
}

// upgradeWith attempts one WebSocket upgrade by hand and returns the HTTP
// status with the typed cause and message the host answered.
//
// By hand rather than through websocket.Dial: every denial here happens before
// the upgrade, so the answer is an ordinary HTTP response with a typed error
// body — which is the proof that no PTY was reached. A dial library would
// report "bad handshake" and throw that body away.
func upgradeWith(t *testing.T, addr, sessionID, origin string, extra http.Header, cookies []*http.Cookie) (int, string, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+basePathForGate+"/terminals/"+sessionID+"/stream", nil)
	if err != nil {
		t.Fatalf("build upgrade request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	// A fixed key is fine: nothing here is expected to complete a handshake, and
	// the server only echoes it back when one does.
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	for k, vs := range extra {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}

	// No redirects, no cookie jar: this client carries exactly what the caller
	// handed it and nothing the rest of the gate accumulated.
	client := &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("upgrade request: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var body struct {
		Cause   string `json:"cause"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(raw, &body)
	return resp.StatusCode, body.Cause, body.Message
}

// basePathForGate mirrors internal/api's unexported basePath. Named here so a
// hand-built request reaches the same routes every helper above uses.
const basePathForGate = "/api/v1"

// expiredSession logs a second operator session in and immediately out, and
// returns the cookie and CSRF token that are now dead. The gate's own session
// is left alone: logging it out would end the run.
func (d *m1aDaemon) expiredSession(t *testing.T) ([]*http.Cookie, string) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("expiredSession: cookie jar: %v", err)
	}
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}

	reqBody, _ := json.Marshal(map[string]string{"username": m1bOperator, "password": m1bPassword})
	req, err := http.NewRequest(http.MethodPost, d.baseURL+"/auth/login", strings.NewReader(string(reqBody)))
	if err != nil {
		t.Fatalf("expiredSession: build login: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://"+d.addr)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("expiredSession: login: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expiredSession: login got %d: %s", resp.StatusCode, raw)
	}
	var out struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("expiredSession: login reply: %v", err)
	}
	registerGateSecret(out.CSRFToken)

	cookies := jar.Cookies(mustParseURL(t, d.baseURL))
	for _, c := range cookies {
		registerGateSecret(c.Value)
	}

	logout, err := http.NewRequest(http.MethodPost, d.baseURL+"/auth/logout", nil)
	if err != nil {
		t.Fatalf("expiredSession: build logout: %v", err)
	}
	logout.Header.Set("Origin", "http://"+d.addr)
	logout.Header.Set(csrfHeaderName, out.CSRFToken)
	lresp, err := client.Do(logout)
	if err != nil {
		t.Fatalf("expiredSession: logout: %v", err)
	}
	lraw, _ := io.ReadAll(lresp.Body)
	lresp.Body.Close()
	if lresp.StatusCode != http.StatusOK && lresp.StatusCode != http.StatusNoContent {
		t.Fatalf("expiredSession: logout got %d: %s", lresp.StatusCode, lraw)
	}
	return cookies, out.CSRFToken
}
