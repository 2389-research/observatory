// ABOUTME: Registry tests against a real runner ctl socket: sessions bind to a
// ABOUTME: boot, one attachment writes, and the rest watch.
package terminal_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/guest/proto"
	"github.com/2389-research/observatory-v2/internal/runner"
	"github.com/2389-research/observatory-v2/internal/terminal"
)

// fakeGuest stands in for the guest end of a session byte stream. It is not a
// mock of the registry's collaborators: the ctl server, its JSON wire, the
// relay and the frame codec are all the real ones. Only the thing on the far
// side of the vsock — a PTY — is replaced, because a test cannot have one.
type fakeGuest struct {
	t        *testing.T
	sockPath string
	srv      *runner.CtlServer

	created  []runner.TerminalCtlRequest
	closed   []string
	sessions map[string]bool

	resumeOffset string
	gap          bool

	// guestSide is the far end of the most recent attach's pipe.
	attached chan net.Conn
}

func newFakeGuest(t *testing.T) *fakeGuest {
	t.Helper()
	// Not t.TempDir(): it embeds the test's name, and a unix socket path is
	// capped at 104 bytes on darwin. A long test name would fail the bind
	// rather than the assertion.
	dir, err := os.MkdirTemp("", "vt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	g := &fakeGuest{
		t:            t,
		sockPath:     filepath.Join(dir, "runner.sock"),
		sessions:     map[string]bool{},
		resumeOffset: "0",
		attached:     make(chan net.Conn, 8),
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	srv, listenErr := runner.ListenCtl(ctx, g.sockPath, runner.CtlHandlers{
		TerminalCreate: func(_ context.Context, req runner.TerminalCtlRequest) (runner.TerminalCtlReply, error) {
			g.created = append(g.created, req)
			g.sessions[req.SessionID] = true
			return runner.TerminalCtlReply{SessionID: req.SessionID, PID: 4242, StartedAt: "2026-09-04T12:00:00.000000Z"}, nil
		},
		TerminalClose: func(_ context.Context, req runner.TerminalCtlRequest) (runner.TerminalCtlReply, error) {
			g.closed = append(g.closed, req.SessionID)
			delete(g.sessions, req.SessionID)
			return runner.TerminalCtlReply{SessionID: req.SessionID, Reason: "closed"}, nil
		},
		TerminalList: func(context.Context) (runner.TerminalCtlReply, error) {
			out := []proto.TerminalSession{}
			for id := range g.sessions {
				out = append(out, proto.TerminalSession{SessionID: id, PID: 4242, Rows: 24, Cols: 80,
					HeadOffset: "0", TailOffset: "0"})
			}
			return runner.TerminalCtlReply{Sessions: out}, nil
		},
		TerminalAttach: func(_ context.Context, req runner.TerminalCtlRequest) (*runner.Relay, runner.TerminalCtlReply, error) {
			hostSide, guestSide := net.Pipe()
			g.attached <- guestSide
			return runner.NewRelay(hostSide, 0), runner.TerminalCtlReply{
				SessionID:    req.SessionID,
				ResumeOffset: g.resumeOffset,
				Gap:          g.gap,
			}, nil
		},
	})
	if listenErr != nil {
		t.Fatalf("listen ctl: %v", listenErr)
	}
	g.srv = srv
	t.Cleanup(srv.Close)
	return g
}

// nextAttach returns the guest end of the connection the last attach opened.
func (g *fakeGuest) nextAttach() net.Conn {
	g.t.Helper()
	select {
	case c := <-g.attached:
		g.t.Cleanup(func() { c.Close() })
		return c
	case <-time.After(5 * time.Second):
		g.t.Fatal("no attach reached the guest")
		return nil
	}
}

func newRegistry(t *testing.T, g *fakeGuest) *terminal.Registry {
	t.Helper()
	return terminal.NewRegistry(terminal.Options{
		MaxReplayBytesPerSession: 256 << 10,
		MaxInflightBrowserBytes:  1 << 20,
		WriterLease:              30 * time.Second,
		Dial: func(ctx context.Context, vmID string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", g.sockPath)
		},
	})
}

func mustCreate(t *testing.T, r *terminal.Registry, vmID, bootID string) terminal.Session {
	t.Helper()
	s, err := r.Create(context.Background(), vmID, terminal.Spec{
		Owner: "operator", BootID: bootID, User: "root", Argv: []string{"/bin/sh"},
		Term: "xterm-256color", Rows: 24, Cols: 80,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return s
}

func TestCreateBindsTheSessionToItsVMAndBoot(t *testing.T) {
	g := newFakeGuest(t)
	r := newRegistry(t, g)

	s := mustCreate(t, r, "vm-1", "boot-a")
	if s.ID == "" {
		t.Fatal("a session with no id cannot be attached to")
	}
	if s.VMID != "vm-1" || s.BootID != "boot-a" || s.Owner != "operator" {
		t.Errorf("session = %+v", s)
	}
	if s.State != terminal.StateOpen {
		t.Errorf("state = %q, want %q", s.State, terminal.StateOpen)
	}
	if s.CreatedAt.IsZero() {
		t.Error("created_at is zero")
	}
	// The host mints the id and tells the guest; a guest-minted id could not be
	// addressed by the API that hands it out.
	if len(g.created) != 1 || g.created[0].SessionID != s.ID {
		t.Errorf("the guest was asked to create %+v, want session_id %q", g.created, s.ID)
	}
	if g.created[0].RingBytes != 256<<10 {
		t.Errorf("ring_bytes = %d, want the configured replay bound", g.created[0].RingBytes)
	}

	got, ok := r.Get(s.ID)
	if !ok || got.ID != s.ID {
		t.Fatalf("Get(%q) = %+v, %v", s.ID, got, ok)
	}
}

func TestListForVMShowsOnlyThatVM(t *testing.T) {
	g := newFakeGuest(t)
	r := newRegistry(t, g)

	a := mustCreate(t, r, "vm-1", "boot-a")
	b := mustCreate(t, r, "vm-1", "boot-a")
	other := mustCreate(t, r, "vm-2", "boot-b")

	got := r.ListForVM("vm-1")
	if len(got) != 2 {
		t.Fatalf("ListForVM(vm-1) returned %d sessions, want 2", len(got))
	}
	for _, s := range got {
		if s.ID == other.ID {
			t.Fatal("another VM's session leaked into the list")
		}
	}
	// Oldest first, so a cursor over this list stays stable as sessions are added.
	if got[0].ID != a.ID || got[1].ID != b.ID {
		t.Errorf("list order = %q, %q; want creation order %q, %q", got[0].ID, got[1].ID, a.ID, b.ID)
	}
	if len(r.ListForVM("vm-3")) != 0 {
		t.Error("a VM with no sessions returned some")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	g := newFakeGuest(t)
	r := newRegistry(t, g)
	s := mustCreate(t, r, "vm-1", "boot-a")

	if err := r.Close(context.Background(), s.ID); err != nil {
		t.Fatalf("close: %v", err)
	}
	got, ok := r.Get(s.ID)
	if !ok {
		t.Fatal("a closed session vanished; the API still has to answer for it")
	}
	if got.State != terminal.StateClosed {
		t.Errorf("state = %q, want %q", got.State, terminal.StateClosed)
	}

	// Second close: the caller's intent is already satisfied, so this is not an
	// error. It also must not ask the guest again.
	if err := r.Close(context.Background(), s.ID); err != nil {
		t.Fatalf("the second close failed: %v", err)
	}
	if len(g.closed) != 1 {
		t.Errorf("the guest was told to close %d times, want 1", len(g.closed))
	}
	if err := r.Close(context.Background(), "no-such-session"); err != nil {
		t.Errorf("closing an unknown session errored: %v", err)
	}
}

func TestAttachWithAStaleBootIDIsRefused(t *testing.T) {
	g := newFakeGuest(t)
	r := newRegistry(t, g)
	s := mustCreate(t, r, "vm-1", "boot-a")

	_, err := r.Attach(context.Background(), terminal.AttachRequest{
		SessionID: s.ID, BootID: "boot-b", ConnID: "conn-a",
	})
	if err == nil {
		t.Fatal("attach across a reboot succeeded; a fresh shell wearing the old session's name")
	}
	var te *terminal.Error
	if !errors.As(err, &te) {
		t.Fatalf("error %v is not typed; the API cannot teach from it", err)
	}
	if te.Cause != "session_stale" {
		t.Errorf("cause = %q, want session_stale", te.Cause)
	}
	if te.Message == "" {
		t.Error("a typed error with no message teaches nothing")
	}
}

func TestAttachToAnUnknownSessionIsRefused(t *testing.T) {
	g := newFakeGuest(t)
	r := newRegistry(t, g)

	_, err := r.Attach(context.Background(), terminal.AttachRequest{
		SessionID: "nope", BootID: "boot-a", ConnID: "conn-a",
	})
	var te *terminal.Error
	if !errors.As(err, &te) || te.Cause != "session_not_found" {
		t.Fatalf("err = %v, want a typed session_not_found", err)
	}
}

func TestAttachToAClosedSessionIsRefused(t *testing.T) {
	g := newFakeGuest(t)
	r := newRegistry(t, g)
	s := mustCreate(t, r, "vm-1", "boot-a")
	if err := r.Close(context.Background(), s.ID); err != nil {
		t.Fatal(err)
	}

	_, err := r.Attach(context.Background(), terminal.AttachRequest{
		SessionID: s.ID, BootID: "boot-a", ConnID: "conn-a",
	})
	var te *terminal.Error
	if !errors.As(err, &te) || te.Cause != "session_closed" {
		t.Fatalf("err = %v, want a typed session_closed", err)
	}
}

func TestTheFirstAttachWritesAndTheSecondWatches(t *testing.T) {
	g := newFakeGuest(t)
	r := newRegistry(t, g)
	s := mustCreate(t, r, "vm-1", "boot-a")

	first, err := r.Attach(context.Background(), terminal.AttachRequest{
		SessionID: s.ID, BootID: "boot-a", ConnID: "conn-a",
	})
	if err != nil {
		t.Fatalf("first attach: %v", err)
	}
	defer first.Close()
	guestA := g.nextAttach()
	if !first.IsWriter() {
		t.Fatal("the first attachment is not the writer")
	}

	second, err := r.Attach(context.Background(), terminal.AttachRequest{
		SessionID: s.ID, BootID: "boot-a", ConnID: "conn-b",
	})
	if err != nil {
		t.Fatalf("second attach: %v", err)
	}
	defer second.Close()
	g.nextAttach()

	if second.IsWriter() {
		t.Fatal("two writers on one shell")
	}
	if second.Holder() != "conn-a" {
		t.Errorf("holder = %q; a read-only viewer must be told who has the shell", second.Holder())
	}

	// A read-only attachment's input never reaches the guest.
	_, err = second.Write(ptyInput(t, 1, "rm -rf /\n"))
	if !errors.Is(err, terminal.ErrReadOnly) {
		t.Fatalf("a read-only write returned %v, want ErrReadOnly", err)
	}

	// The writer's does.
	input := ptyInput(t, 1, "echo hi\n")
	go func() { _, _ = first.Write(input) }()
	if got := readPTYFrame(t, guestA); got != "echo hi\n" {
		t.Errorf("the guest received %q", got)
	}
}

func TestStealTakesTheShellFromTheOldWriter(t *testing.T) {
	g := newFakeGuest(t)
	r := newRegistry(t, g)
	s := mustCreate(t, r, "vm-1", "boot-a")

	first, err := r.Attach(context.Background(), terminal.AttachRequest{
		SessionID: s.ID, BootID: "boot-a", ConnID: "conn-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	g.nextAttach()

	second, err := r.Attach(context.Background(), terminal.AttachRequest{
		SessionID: s.ID, BootID: "boot-a", ConnID: "conn-b", Steal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	guestB := g.nextAttach()

	if !second.IsWriter() {
		t.Fatal("the thief did not get the shell")
	}
	// §8.2: from that instant, not on the old writer's next reconnect.
	if first.IsWriter() {
		t.Fatal("the old writer still holds the shell after a steal")
	}
	if _, err := first.Write(ptyInput(t, 2, "still here\n")); !errors.Is(err, terminal.ErrReadOnly) {
		t.Fatalf("the demoted writer's input returned %v, want ErrReadOnly", err)
	}

	input := ptyInput(t, 1, "mine now\n")
	go func() { _, _ = second.Write(input) }()
	if got := readPTYFrame(t, guestB); got != "mine now\n" {
		t.Errorf("the guest received %q", got)
	}
}

func TestAttachCarriesTheResumeOffsetAndGap(t *testing.T) {
	g := newFakeGuest(t)
	g.resumeOffset = "9007199254740993"
	g.gap = true
	r := newRegistry(t, g)
	s := mustCreate(t, r, "vm-1", "boot-a")

	att, err := r.Attach(context.Background(), terminal.AttachRequest{
		SessionID: s.ID, BootID: "boot-a", ConnID: "conn-a", AfterOffset: 12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer att.Close()
	g.nextAttach()

	if att.ResumeOffset != 9007199254740993 {
		t.Errorf("resume offset = %d; the decimal string lost precision", att.ResumeOffset)
	}
	if !att.Gap {
		t.Error("the guest reported a gap and the attachment hid it")
	}
}

func TestGuestOutputReachesTheAttachment(t *testing.T) {
	g := newFakeGuest(t)
	r := newRegistry(t, g)
	s := mustCreate(t, r, "vm-1", "boot-a")

	att, err := r.Attach(context.Background(), terminal.AttachRequest{
		SessionID: s.ID, BootID: "boot-a", ConnID: "conn-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer att.Close()
	guest := g.nextAttach()

	payload := make([]byte, 8+len("hello"))
	binary.BigEndian.PutUint64(payload[:8], 100)
	copy(payload[8:], "hello")
	go func() { _ = proto.WriteFrame(guest, proto.FramePTY, payload) }()

	typ, got, err := proto.ReadFrame(att)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if typ != proto.FramePTY {
		t.Errorf("frame type = %#x, want FramePTY", typ)
	}
	if off := binary.BigEndian.Uint64(got[:8]); off != 100 {
		t.Errorf("offset = %d, want 100", off)
	}
	if string(got[8:]) != "hello" {
		t.Errorf("payload = %q", got[8:])
	}
}

// ptyInput builds one host→guest PTY frame: [seq: 8 BE][input bytes], through
// the real codec so a change to the wire breaks this test rather than passing it.
func ptyInput(t *testing.T, seq uint64, s string) []byte {
	t.Helper()
	head := make([]byte, 8)
	binary.BigEndian.PutUint64(head, seq)
	var buf bytes.Buffer
	if err := proto.WriteFrame(&buf, proto.FramePTY, append(head, s...)); err != nil {
		t.Fatalf("build pty frame: %v", err)
	}
	return buf.Bytes()
}

// readPTYFrame reads one frame off the guest side and returns its input bytes.
func readPTYFrame(t *testing.T, guest net.Conn) string {
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
		t.Fatalf("frame payload %d bytes, want at least the 8-byte seq", len(payload))
	}
	return string(payload[8:])
}

func TestRequestLeaseRoundTrip(t *testing.T) {
	g := newFakeGuest(t)
	r := newRegistry(t, g)
	s := mustCreate(t, r, "vm-1", "boot-a")

	got, err := r.RequestLease(s.ID, "conn-a", terminal.LeaseAcquire)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if !got.Writer || got.Holder != "conn-a" || got.Reason == "" {
		t.Errorf("acquire = %+v", got)
	}

	got, err = r.RequestLease(s.ID, "conn-b", terminal.LeaseAcquire)
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if got.Writer {
		t.Error("a second acquire granted the shell to two connections")
	}
	if got.Holder != "conn-a" {
		t.Errorf("holder = %q, want conn-a", got.Holder)
	}

	got, err = r.RequestLease(s.ID, "conn-b", terminal.LeaseSteal)
	if err != nil {
		t.Fatalf("steal: %v", err)
	}
	if !got.Writer || got.Holder != "conn-b" {
		t.Errorf("steal = %+v", got)
	}
	if !strings.Contains(got.Reason, "conn-a") {
		t.Errorf("reason %q does not name who lost the shell", got.Reason)
	}

	if _, err := r.RequestLease(s.ID, "conn-b", terminal.LeaseRelease); err != nil {
		t.Fatalf("release: %v", err)
	}

	var te *terminal.Error
	if _, err := r.RequestLease(s.ID, "conn-b", "seize"); !errors.As(err, &te) || te.Cause != "invalid_lease_mode" {
		t.Errorf("err = %v, want a typed invalid_lease_mode", err)
	}
	if _, err := r.RequestLease("nope", "conn-b", terminal.LeaseAcquire); !errors.As(err, &te) ||
		te.Cause != "session_not_found" {
		t.Errorf("err = %v, want a typed session_not_found", err)
	}
}

// Closing a session has to take its live attachments with it, or a runner
// connection outlives the shell it was opened for and nothing is left holding
// a reference to close it.
func TestClosingASessionClosesItsAttachments(t *testing.T) {
	g := newFakeGuest(t)
	r := newRegistry(t, g)
	s := mustCreate(t, r, "vm-1", "boot-a")

	att, err := r.Attach(context.Background(), terminal.AttachRequest{
		SessionID: s.ID, BootID: "boot-a", ConnID: "conn-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	g.nextAttach()

	if err := r.Close(context.Background(), s.ID); err != nil {
		t.Fatalf("close: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := att.Read(buf)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a read on a closed session's attachment succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the attachment outlived the session it belonged to")
	}
}
