// ABOUTME: WebSocket terminal relay tests: every gate denies as plain HTTP
// ABOUTME: before an upgrade, and the relay is bounded, leased and honest (§8).
package api_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/2389-research/observatory/internal/api"
	"github.com/2389-research/observatory/internal/guest/proto"
	"github.com/2389-research/observatory/internal/store"
	"github.com/2389-research/observatory/internal/terminal"
)

// newStreamServer is newTerminalServer with a chosen in-flight ceiling, so a
// backpressure test can fill the window without moving a megabyte.
func newStreamServer(t *testing.T, maxInflight int64) (*httptest.Server, *store.Store, *fakeRunner, *terminal.Registry) {
	t.Helper()
	fr := newFakeRunner(t)
	reg := terminal.NewRegistry(terminal.Options{
		MaxReplayBytesPerSession: 256 << 10,
		MaxInflightBrowserBytes:  maxInflight,
		WriterLease:              30 * time.Second,
		Dial: func(ctx context.Context, vmID string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", fr.sockPath)
		},
	})
	srv, st, _ := newTemplateServerFull(t, nil, testAdmission(), reg, "")
	return srv, st, fr, reg
}

// streamURL is the ws:// address of one session's stream.
func streamURL(srvURL, sessionID string) string {
	return strings.Replace(srvURL, "http://", "ws://", 1) + "/api/v1/terminals/" + sessionID + "/stream"
}

// refuseUpgrade asks for an upgrade with plain HTTP and returns the typed error
// body. Plain HTTP is the point: a denial must answer as an ordinary response,
// never by upgrading and closing, which would tell a cross-origin page that the
// session exists.
func refuseUpgrade(t *testing.T, srvURL, sessionID string, header http.Header, wantStatus int) api.Error {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srvURL+"/api/v1/terminals/"+sessionID+"/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("upgrade request: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("status = %d, want %d\n%s", resp.StatusCode, wantStatus, raw)
	}
	var e api.Error
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatalf("decode error body: %v\n%s", err, raw)
	}
	return e
}

// openStream dials one session's stream from the server's own origin.
func openStream(t *testing.T, srvURL, sessionID string) (*websocket.Conn, *http.Response) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	c, resp, err := websocket.Dial(ctx, streamURL(srvURL, sessionID), &websocket.DialOptions{
		HTTPHeader: http.Header{"Origin": []string{srvURL}},
	})
	if err != nil {
		t.Fatalf("dial stream: %v", err)
	}
	t.Cleanup(func() { _ = c.CloseNow() })
	return c, resp
}

// streamMsg is one host-to-browser control message.
type streamMsg struct {
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

// readControl returns the next control message, failing on a binary one.
func readControl(t *testing.T, c *websocket.Conn) streamMsg {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	typ, raw, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("read control: %v", err)
	}
	if typ != websocket.MessageText {
		t.Fatalf("message type = %v, want text; got %q", typ, raw)
	}
	var m streamMsg
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode control %q: %v", raw, err)
	}
	return m
}

// readOutput returns the offset and bytes of the next PTY message.
func readOutput(t *testing.T, c *websocket.Conn) (uint64, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	typ, raw, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if typ != websocket.MessageBinary {
		t.Fatalf("message type = %v, want binary; got %q", typ, raw)
	}
	if len(raw) < 8 {
		t.Fatalf("output message %d bytes, want at least the 8-byte offset", len(raw))
	}
	return binary.BigEndian.Uint64(raw[:8]), string(raw[8:])
}

// sendInput writes one sequenced keystroke message.
func sendInput(t *testing.T, c *websocket.Conn, seq uint64, s string) {
	t.Helper()
	msg := make([]byte, 8+len(s))
	binary.BigEndian.PutUint64(msg[:8], seq)
	copy(msg[8:], s)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Write(ctx, websocket.MessageBinary, msg); err != nil {
		t.Fatalf("send input: %v", err)
	}
}

// sendControl writes one browser-to-host control message.
func sendControl(t *testing.T, c *websocket.Conn, m map[string]any) {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Write(ctx, websocket.MessageText, raw); err != nil {
		t.Fatalf("send control: %v", err)
	}
}

// guestOutput writes one PTY output frame from the guest end of a stream.
func guestOutput(t *testing.T, guest net.Conn, offset uint64, s string) {
	t.Helper()
	payload := make([]byte, 8+len(s))
	binary.BigEndian.PutUint64(payload[:8], offset)
	copy(payload[8:], s)
	if err := guest.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := proto.WriteFrame(guest, proto.FramePTY, payload); err != nil {
		t.Fatalf("guest output: %v", err)
	}
}

// openSession launches a VM and opens one terminal on it, returning both ids.
func openSession(t *testing.T, srvURL string) (vmID, sessionID string) {
	t.Helper()
	vmID = launchVM(t, srvURL, "stream-vm")
	got := createTerminal(t, srvURL, vmID, map[string]any{})
	sessionID, _ = got["session_id"].(string)
	if sessionID == "" {
		t.Fatalf("no session id in %v", got)
	}
	return vmID, sessionID
}

// noAttachReached fails if any attach reached the guest. Every denial has to
// stop before the runner is dialled: AT-029 and AT-030 turn on nothing being
// created by a request that was refused.
func noAttachReached(t *testing.T, fr *fakeRunner) {
	t.Helper()
	select {
	case <-fr.attached:
		t.Fatal("a denied upgrade still reached the guest")
	default:
	}
}

// §8.4, D3: a browser always sends Origin, so an absent one is not a browser
// and is refused. Today's mutation check passes an absent Origin; an upgrade
// must not.
func TestStreamRefusesAnUpgradeWithNoOrigin(t *testing.T) {
	srv, _, fr, _ := newStreamServer(t, 1<<20)
	_, sessionID := openSession(t, srv.URL)

	e := refuseUpgrade(t, srv.URL, sessionID, nil, http.StatusForbidden)
	requireTeaching(t, e, "forbidden")
	if e.Cause != "origin_rejected" {
		t.Errorf("cause = %q, want origin_rejected", e.Cause)
	}
	noAttachReached(t, fr)
}

func TestStreamRefusesAWrongOrigin(t *testing.T) {
	srv, _, fr, _ := newStreamServer(t, 1<<20)
	_, sessionID := openSession(t, srv.URL)

	e := refuseUpgrade(t, srv.URL, sessionID,
		http.Header{"Origin": []string{"http://evil.example"}}, http.StatusForbidden)
	requireTeaching(t, e, "forbidden")
	if e.Cause != "origin_rejected" {
		t.Errorf("cause = %q, want origin_rejected", e.Cause)
	}
	noAttachReached(t, fr)
}

// The origin gate runs before the identity gate, so a request with the right
// origin and no credentials reaches 401 rather than being masked by 403.
func TestStreamRefusesAnUnauthenticatedUpgrade(t *testing.T) {
	srv, _, _ := newAuthServer(t)

	e := refuseUpgrade(t, srv.URL, "any-session",
		http.Header{"Origin": []string{testOrigin}}, http.StatusUnauthorized)
	requireTeaching(t, e, "unauthenticated")
}

func TestStreamRefusesAnUnknownSession(t *testing.T) {
	srv, _, fr, _ := newStreamServer(t, 1<<20)

	e := refuseUpgrade(t, srv.URL, "0f1e2d3c-0000-4000-8000-000000000000",
		http.Header{"Origin": []string{srv.URL}}, http.StatusNotFound)
	requireTeaching(t, e, "not_found")
	if e.Cause != "terminal_session_unknown" {
		t.Errorf("cause = %q, want terminal_session_unknown", e.Cause)
	}
	noAttachReached(t, fr)
}

// A session that belongs to somebody else answers exactly as one that does not
// exist. A 403 here would be an existence oracle for a cross-origin page, which
// is the thing AT-079 forbids.
func TestStreamHidesAnotherOwnersSession(t *testing.T) {
	srv, st, fr, reg := newStreamServer(t, 1<<20)
	ctx := context.Background()
	foreignVM, _ := seedForeignVM(t, ctx, st)
	foreign, err := reg.Create(ctx, foreignVM, terminal.Spec{
		Owner: otherOwner, User: "root", Rows: 24, Cols: 80,
	})
	if err != nil {
		t.Fatalf("seed foreign session: %v", err)
	}

	denied := refuseUpgrade(t, srv.URL, foreign.ID,
		http.Header{"Origin": []string{srv.URL}}, http.StatusNotFound)
	requireTeaching(t, denied, "not_found")

	missing := refuseUpgrade(t, srv.URL, "0f1e2d3c-0000-4000-8000-000000000000",
		http.Header{"Origin": []string{srv.URL}}, http.StatusNotFound)
	if denied.Cause != missing.Cause || denied.Code != missing.Code {
		t.Errorf("another owner's session answers %s/%s and a missing one %s/%s; that is an existence oracle",
			denied.Code, denied.Cause, missing.Code, missing.Cause)
	}
	noAttachReached(t, fr)
}

// §8.2: a reboot ends the shell. The runner names the boot it supervises, so a
// session recorded under an older one is refused rather than reattached.
func TestStreamRefusesAStaleBoot(t *testing.T) {
	srv, _, fr, _ := newStreamServer(t, 1<<20)
	_, sessionID := openSession(t, srv.URL)

	fr.bootID = "9a8b7c6d-0000-4000-8000-00000000cafe"

	e := refuseUpgrade(t, srv.URL, sessionID,
		http.Header{"Origin": []string{srv.URL}}, http.StatusConflict)
	requireTeaching(t, e, "session_stale")
	if e.Cause != "session_stale" {
		t.Errorf("cause = %q, want session_stale", e.Cause)
	}
}

// The first message says where the stream resumes and whether this connection
// may type — a terminal that does not say so leaves the browser guessing.
func TestStreamAnnouncesTheAttachmentFirst(t *testing.T) {
	srv, _, fr, _ := newStreamServer(t, 1<<20)
	_, sessionID := openSession(t, srv.URL)
	fr.resumeOffset = "9007199254740993"

	c, resp := openStream(t, srv.URL, sessionID)
	guest := fr.nextAttach(t)

	// §7.4: never compress attacker-influenced bytes beside secrets.
	if ext := resp.Header.Get("Sec-WebSocket-Extensions"); ext != "" {
		t.Errorf("negotiated extensions = %q, want none", ext)
	}

	m := readControl(t, c)
	if m.Type != "attached" {
		t.Fatalf("first message type = %q, want attached", m.Type)
	}
	if m.SessionID != sessionID {
		t.Errorf("session_id = %q, want %q", m.SessionID, sessionID)
	}
	if m.ResumeOffset != "9007199254740993" {
		t.Errorf("resume_offset = %q, want the guest's own offset as a decimal string", m.ResumeOffset)
	}
	if !m.Writer {
		t.Error("the only attachment is not the writer")
	}
	if m.MaxInflightBytes != "1048576" {
		t.Errorf("max_inflight_bytes = %q, want 1048576", m.MaxInflightBytes)
	}

	guestOutput(t, guest, 9007199254740993, "hello")
	off, got := readOutput(t, c)
	if got != "hello" {
		t.Errorf("output = %q, want hello", got)
	}
	if off != 9007199254740993 {
		t.Errorf("output offset = %d, want the guest's", off)
	}
}

// This uses the real HTTP relay and its production heartbeat budget. The runner
// fixture owns only the guest-side socket; EOF proves the attachment was released.
func TestStreamHeartbeatReleasesUnresponsiveAttachment(t *testing.T) {
	srv, _, fr, reg := newStreamServer(t, 1<<20)
	_, sessionID := openSession(t, srv.URL)
	c, _ := openStream(t, srv.URL, sessionID)
	guest := fr.nextAttach(t)
	attached := readControl(t, c)
	if attached.Type != "attached" || !attached.Writer {
		t.Fatalf("first attachment = %+v", attached)
	}
	// Stop browser reads: coder/websocket answers ping only while reading.
	if err := guest.SetReadDeadline(time.Now().Add(45 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := guest.Read(b[:]); err != io.EOF {
		t.Fatalf("heartbeat did not close guest attachment: %v", err)
	}
	session, ok := reg.Get(sessionID)
	if !ok || session.State != terminal.StateOpen || session.WriterHolder != attached.ConnID {
		t.Fatalf("attachment timeout must preserve the session and writer grace window: %+v", session)
	}
	next, _ := openStream(t, srv.URL, sessionID)
	fr.nextAttach(t)
	if resumed := readControl(t, next); resumed.Type != "attached" || resumed.Writer || resumed.Holder != attached.ConnID {
		t.Fatalf("reconnect did not preserve writer grace: %+v", resumed)
	}
}

// A second viewer watches. Its keystrokes are refused out loud: input that
// vanishes silently is indistinguishable from a hung shell (§8.2).
func TestStreamSecondViewerIsReadOnlyAndToldSo(t *testing.T) {
	srv, _, fr, _ := newStreamServer(t, 1<<20)
	_, sessionID := openSession(t, srv.URL)

	first, _ := openStream(t, srv.URL, sessionID)
	guest := fr.nextAttach(t)
	firstAttached := readControl(t, first)
	if !firstAttached.Writer {
		t.Fatal("the first attachment is not the writer")
	}

	second, _ := openStream(t, srv.URL, sessionID)
	fr.nextAttach(t)
	m := readControl(t, second)
	if m.Type != "attached" {
		t.Fatalf("type = %q, want attached", m.Type)
	}
	if m.Writer {
		t.Error("two writers on one shell")
	}
	if m.Holder != firstAttached.ConnID {
		t.Errorf("holder = %q, want the first connection %q", m.Holder, firstAttached.ConnID)
	}

	sendInput(t, second, 1, "rm -rf /\n")
	drop := readControl(t, second)
	if drop.Type != "lease" {
		t.Fatalf("a dropped keystroke produced %q, want a lease message", drop.Type)
	}
	if drop.Writer {
		t.Error("the read-only viewer was told it may type")
	}
	if drop.Reason == "" {
		t.Error("a refusal with no reason teaches nothing")
	}

	// The writer's input still reaches the guest, and only the writer's.
	sendInput(t, first, 1, "echo hi\n")
	if _, got := readPTYInput(t, guest); got != "echo hi\n" {
		t.Errorf("the guest received %q, want only the writer's keystrokes", got)
	}
}

// §8.2's steal takes the shell at that instant. Both browsers have to be told,
// or one of them displays a writer badge that is a lie.
func TestStreamStealFlipsBothBadges(t *testing.T) {
	srv, _, fr, _ := newStreamServer(t, 1<<20)
	_, sessionID := openSession(t, srv.URL)

	first, _ := openStream(t, srv.URL, sessionID)
	fr.nextAttach(t)
	readControl(t, first)

	second, _ := openStream(t, srv.URL, sessionID)
	fr.nextAttach(t)
	secondAttached := readControl(t, second)
	if secondAttached.Writer {
		t.Fatal("the second attachment took the shell without asking")
	}

	sendControl(t, second, map[string]any{"type": "lease", "mode": "steal"})

	got := readControl(t, second)
	if got.Type != "lease" || !got.Writer {
		t.Errorf("the thief was told %+v, want a lease message making it the writer", got)
	}
	demoted := readControl(t, first)
	if demoted.Type != "lease" || demoted.Writer {
		t.Errorf("the old writer was told %+v, want a lease message taking the shell away", demoted)
	}
	if demoted.Holder != secondAttached.ConnID {
		t.Errorf("holder = %q, want the thief %q", demoted.Holder, secondAttached.ConnID)
	}
}

// §8.3: the host stops handing out bytes at the in-flight ceiling and starts
// again when the browser says it has read them. Nothing is dropped by the host.
func TestStreamStopsAtTheInflightCeilingAndResumesOnAck(t *testing.T) {
	srv, _, fr, _ := newStreamServer(t, 8)
	_, sessionID := openSession(t, srv.URL)

	c, _ := openStream(t, srv.URL, sessionID)
	guest := fr.nextAttach(t)
	if m := readControl(t, c); m.MaxInflightBytes != "8" {
		t.Fatalf("max_inflight_bytes = %q, want 8", m.MaxInflightBytes)
	}

	// Sixteen bytes against an eight-byte window: the second half waits.
	done := make(chan struct{})
	go func() {
		defer close(done)
		guestOutput(t, guest, 0, "aaaaaaaa")
		guestOutput(t, guest, 8, "bbbbbbbb")
	}()

	off, got := readOutput(t, c)
	if off != 0 || got != "aaaaaaaa" {
		t.Fatalf("first message = %d/%q", off, got)
	}

	// A read whose context is cancelled closes the connection in this library,
	// so the wait happens beside the read rather than inside it.
	next := asyncRead(c)
	select {
	case r := <-next:
		t.Fatalf("the host kept sending past the in-flight ceiling: %q (%v)", r.data, r.err)
	case <-time.After(300 * time.Millisecond):
	}

	sendControl(t, c, map[string]any{"type": "ack", "offset": "8"})
	select {
	case r := <-next:
		if r.err != nil {
			t.Fatalf("read after ack: %v", r.err)
		}
		if r.typ != websocket.MessageBinary {
			t.Fatalf("message type = %v, want binary", r.typ)
		}
		if off := binary.BigEndian.Uint64(r.data[:8]); off != 8 || string(r.data[8:]) != "bbbbbbbb" {
			t.Errorf("after the ack the browser got %d/%q, want 8/bbbbbbbb", off, r.data[8:])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the window never reopened after the ack")
	}
	<-done
}

// §8.2 requires a gap be shown, never papered over.
func TestStreamSurfacesAGuestDrop(t *testing.T) {
	srv, _, fr, _ := newStreamServer(t, 1<<20)
	_, sessionID := openSession(t, srv.URL)

	c, _ := openStream(t, srv.URL, sessionID)
	guest := fr.nextAttach(t)
	readControl(t, c)

	if err := proto.WriteControl(guest, proto.KindTerminalDropped, proto.TerminalDropped{
		FromOffset: "9007199254740993",
		ToOffset:   "9007199254745000",
	}); err != nil {
		t.Fatal(err)
	}

	m := readControl(t, c)
	if m.Type != "dropped" {
		t.Fatalf("type = %q, want dropped", m.Type)
	}
	if m.FromOffset != "9007199254740993" || m.ToOffset != "9007199254745000" {
		t.Errorf("gap = [%s, %s), want both offsets carried through as decimal strings",
			m.FromOffset, m.ToOffset)
	}
}

// A browser that resends after a hiccup must not type twice.
func TestStreamDeliversADuplicateInputOnce(t *testing.T) {
	srv, _, fr, _ := newStreamServer(t, 1<<20)
	_, sessionID := openSession(t, srv.URL)

	c, _ := openStream(t, srv.URL, sessionID)
	guest := fr.nextAttach(t)
	readControl(t, c)

	sendInput(t, c, 1, "ls\n")
	sendInput(t, c, 1, "ls\n")
	sendInput(t, c, 2, "pwd\n")

	if _, got := readPTYInput(t, guest); got != "ls\n" {
		t.Fatalf("first frame = %q", got)
	}
	if _, got := readPTYInput(t, guest); got != "pwd\n" {
		t.Errorf("second frame = %q; the repeated sequence was typed twice", got)
	}
}

// A resize from the writer reaches the guest as a control frame on the session
// stream, which is where §8.1 puts it.
func TestStreamForwardsAResize(t *testing.T) {
	srv, _, fr, _ := newStreamServer(t, 1<<20)
	_, sessionID := openSession(t, srv.URL)

	c, _ := openStream(t, srv.URL, sessionID)
	guest := fr.nextAttach(t)
	readControl(t, c)

	sendControl(t, c, map[string]any{"type": "resize", "rows": 40, "cols": 120})

	env := readControlFrame(t, guest)
	if env.Kind != proto.KindTerminalResize {
		t.Fatalf("guest received %q, want %q", env.Kind, proto.KindTerminalResize)
	}
	var rz proto.TerminalResize
	if err := json.Unmarshal(env.Data, &rz); err != nil {
		t.Fatal(err)
	}
	if rz.Rows != 40 || rz.Cols != 120 {
		t.Errorf("resize = %dx%d, want 40x120", rz.Rows, rz.Cols)
	}
}

// readMessage is one message a background reader picked up.
type readMessage struct {
	typ  websocket.MessageType
	data []byte
	err  error
}

// asyncRead reads one message beside the test rather than inside it. A Read
// with a cancelled context closes the connection in this library, so a test
// that wants to prove nothing arrived cannot use a timeout context.
func asyncRead(c *websocket.Conn) <-chan readMessage {
	out := make(chan readMessage, 1)
	go func() {
		typ, data, err := c.Read(context.Background())
		out <- readMessage{typ: typ, data: data, err: err}
	}()
	return out
}

// readPTYInput reads one host-to-guest PTY frame and returns its sequence and
// bytes.
func readPTYInput(t *testing.T, guest net.Conn) (uint64, string) {
	t.Helper()
	if err := guest.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	typ, payload, err := proto.ReadFrame(guest)
	if err != nil {
		t.Fatalf("read frame from guest: %v", err)
	}
	if typ != proto.FramePTY {
		t.Fatalf("frame type = %#x, want FramePTY", typ)
	}
	if len(payload) < 8 {
		t.Fatalf("payload %d bytes, want at least the 8-byte sequence", len(payload))
	}
	return binary.BigEndian.Uint64(payload[:8]), string(payload[8:])
}

// readControlFrame reads one host-to-guest control frame.
func readControlFrame(t *testing.T, guest net.Conn) proto.Envelope {
	t.Helper()
	if err := guest.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	typ, payload, err := proto.ReadFrame(guest)
	if err != nil {
		t.Fatalf("read frame from guest: %v", err)
	}
	if typ != proto.FrameControl {
		t.Fatalf("frame type = %#x, want FrameControl", typ)
	}
	var env proto.Envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	return env
}
