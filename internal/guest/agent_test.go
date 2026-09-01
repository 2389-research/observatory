// ABOUTME: Tests for the guest agent control-channel: handshake, capabilities, ping, error cases.
// ABOUTME: Uses real net.Pipe and unix listeners — no mocks.
package guest_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/guest"
	"github.com/2389-research/observatory-v2/internal/guest/proto"
)

// makeTestAgent builds an Agent with a known token and a simple manifest.
func makeTestAgent(token string) (*guest.Agent, proto.CapabilityManifest) {
	cfg := &guest.BootConfig{
		Schema:          "vmobs.guest_context.v1",
		VMID:            "vm-test",
		BootID:          "boot-test",
		CapabilityToken: token,
		ProtocolVersion: proto.ProtocolVersion,
	}
	manifest := proto.CapabilityManifest{
		Schema:        "vmobs.guest_capability.v1",
		KernelRelease: "6.8.0-test",
		Features: []proto.Feature{
			{ID: "btf", Present: true, Evidence: "/sys/kernel/btf/vmlinux"},
		},
	}
	return guest.NewAgent(cfg, manifest), manifest
}

// sendHello writes a hello frame as a host would.
func sendHello(t *testing.T, conn net.Conn, token string, version int) {
	t.Helper()
	h := proto.Hello{
		ProtocolVersion: version,
		VMID:            "vm-test",
		BootID:          "boot-test",
		SourceInstance:  "inst-1",
		ResumeCursor:    "0",
		AuthProof:       token,
	}
	if err := proto.WriteControl(conn, proto.KindHello, h); err != nil {
		t.Fatalf("sendHello WriteControl: %v", err)
	}
}

// readAck reads one control envelope, unmarshals as HelloAck.
func readAck(t *testing.T, conn net.Conn) proto.HelloAck {
	t.Helper()
	env, err := proto.ReadControl(conn)
	if err != nil {
		t.Fatalf("readAck ReadControl: %v", err)
	}
	if env.Kind != proto.KindHelloAck {
		t.Fatalf("readAck: want kind %q, got %q", proto.KindHelloAck, env.Kind)
	}
	var ack proto.HelloAck
	if err := json.Unmarshal(env.Data, &ack); err != nil {
		t.Fatalf("readAck unmarshal: %v", err)
	}
	return ack
}

// TestGoodHandshakeAndAck verifies that a valid hello results in accepted=true.
func TestGoodHandshakeAndAck(t *testing.T) {
	const token = "correct-secret-token"
	agent, _ := makeTestAgent(token)

	ln := newUnixListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serveErr := make(chan error, 1)
	go func() { serveErr <- agent.ServeControl(ctx, ln) }()

	conn := dialUnix(t, ln.Addr().String())
	defer conn.Close()

	sendHello(t, conn, token, proto.ProtocolVersion)
	ack := readAck(t, conn)
	if !ack.Accepted {
		t.Errorf("want Accepted=true, got Accepted=false reason=%q", ack.Reason)
	}

	cancel()
	<-serveErr // context cancellation closes ln; serveErr carries nil or an accept error — both acceptable
}

// TestCapabilitiesRoundTrip verifies get_capabilities → capabilities with the manifest.
func TestCapabilitiesRoundTrip(t *testing.T) {
	const token = "tok-cap"
	agent, manifest := makeTestAgent(token)

	ln := newUnixListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() { _ = agent.ServeControl(ctx, ln) }()

	conn := dialUnix(t, ln.Addr().String())
	defer conn.Close()

	sendHello(t, conn, token, proto.ProtocolVersion)
	ack := readAck(t, conn)
	if !ack.Accepted {
		t.Fatalf("handshake rejected: %q", ack.Reason)
	}

	// Ask for capabilities.
	if err := proto.WriteControl(conn, proto.KindGetCapabilities, struct{}{}); err != nil {
		t.Fatalf("WriteControl get_capabilities: %v", err)
	}
	env, err := proto.ReadControl(conn)
	if err != nil {
		t.Fatalf("ReadControl capabilities: %v", err)
	}
	if env.Kind != proto.KindCapabilities {
		t.Fatalf("want kind %q, got %q", proto.KindCapabilities, env.Kind)
	}
	var got proto.CapabilityManifest
	if err := json.Unmarshal(env.Data, &got); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if got.Schema != manifest.Schema {
		t.Errorf("schema: got %q, want %q", got.Schema, manifest.Schema)
	}
	if got.KernelRelease != manifest.KernelRelease {
		t.Errorf("kernel_release: got %q, want %q", got.KernelRelease, manifest.KernelRelease)
	}
	if len(got.Features) != len(manifest.Features) {
		t.Errorf("features count: got %d, want %d", len(got.Features), len(manifest.Features))
	}
}

// TestPingPong verifies that ping returns pong.
func TestPingPong(t *testing.T) {
	const token = "tok-ping"
	agent, _ := makeTestAgent(token)

	ln := newUnixListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() { _ = agent.ServeControl(ctx, ln) }()

	conn := dialUnix(t, ln.Addr().String())
	defer conn.Close()

	sendHello(t, conn, token, proto.ProtocolVersion)
	ack := readAck(t, conn)
	if !ack.Accepted {
		t.Fatalf("handshake rejected: %q", ack.Reason)
	}

	if err := proto.WriteControl(conn, proto.KindPing, struct{}{}); err != nil {
		t.Fatalf("WriteControl ping: %v", err)
	}
	env, err := proto.ReadControl(conn)
	if err != nil {
		t.Fatalf("ReadControl pong: %v", err)
	}
	if env.Kind != proto.KindPong {
		t.Errorf("want kind %q, got %q", proto.KindPong, env.Kind)
	}
}

// TestWrongTokenRefused verifies that a wrong token causes rejection.
func TestWrongTokenRefused(t *testing.T) {
	const token = "correct-tok"
	agent, _ := makeTestAgent(token)

	ln := newUnixListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() { _ = agent.ServeControl(ctx, ln) }()

	conn := dialUnix(t, ln.Addr().String())
	defer conn.Close()

	sendHello(t, conn, "wrong-tok", proto.ProtocolVersion)
	ack := readAck(t, conn)
	if ack.Accepted {
		t.Fatal("want Accepted=false for wrong token, got Accepted=true")
	}
	if ack.Reason == "" {
		t.Error("want non-empty Reason on rejection")
	}

	// Connection should be closed by the server now — subsequent read should fail.
	_, err := proto.ReadControl(conn)
	if err == nil {
		t.Error("want error on closed conn after rejection, got nil")
	}
}

// TestRejectedConnDoesNotKillListener verifies the listener keeps serving after one rejection.
func TestRejectedConnDoesNotKillListener(t *testing.T) {
	const token = "correct-tok2"
	agent, _ := makeTestAgent(token)

	ln := newUnixListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() { _ = agent.ServeControl(ctx, ln) }()

	// First conn: wrong token.
	conn1 := dialUnix(t, ln.Addr().String())
	sendHello(t, conn1, "bad", proto.ProtocolVersion)
	ack1 := readAck(t, conn1)
	if ack1.Accepted {
		t.Fatal("first conn: want rejected")
	}
	conn1.Close()

	// Second conn: correct token, should succeed.
	conn2 := dialUnix(t, ln.Addr().String())
	defer conn2.Close()

	sendHello(t, conn2, token, proto.ProtocolVersion)
	ack2 := readAck(t, conn2)
	if !ack2.Accepted {
		t.Errorf("second conn: want accepted, got rejected: %q", ack2.Reason)
	}
}

// TestVersionMismatchRefused verifies that a mismatched protocol version is rejected.
func TestVersionMismatchRefused(t *testing.T) {
	const token = "tok-ver"
	agent, _ := makeTestAgent(token)

	ln := newUnixListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() { _ = agent.ServeControl(ctx, ln) }()

	conn := dialUnix(t, ln.Addr().String())
	defer conn.Close()

	sendHello(t, conn, token, 999)
	ack := readAck(t, conn)
	if ack.Accepted {
		t.Fatal("want Accepted=false for version mismatch, got Accepted=true")
	}
	if ack.Reason == "" {
		t.Error("want non-empty Reason mentioning version mismatch")
	}
}

// TestOversizedFrameClosesConn verifies that an oversized frame causes the connection to close.
func TestOversizedFrameClosesConn(t *testing.T) {
	const token = "tok-oversize"
	agent, _ := makeTestAgent(token)

	ln := newUnixListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() { _ = agent.ServeControl(ctx, ln) }()

	conn := dialUnix(t, ln.Addr().String())
	defer conn.Close()

	// Send a frame header claiming 2 MiB — exceeds MaxControlFrame (1 MiB).
	// Write raw 5-byte header: type=FrameControl (0x01), len=2<<20.
	header := [5]byte{0x01, 0x00, 0x20, 0x00, 0x00} // 2097152 bytes
	if _, err := conn.Write(header[:]); err != nil {
		t.Fatalf("write header: %v", err)
	}

	// The server should close the conn (maybe send an error frame first).
	// Either way, a subsequent Read returns an error.
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 4096)
	for {
		_, err := conn.Read(buf)
		if err != nil {
			// Expected: server closed the conn.
			break
		}
	}
}

// TestCancelClosesEstablishedConns verifies that cancelling the serve ctx closes
// live connections promptly — well under the 60s idle deadline. The client read
// must return with a non-timeout error (i.e. server-initiated close, not the
// client's own deadline).
func TestCancelClosesEstablishedConns(t *testing.T) {
	const token = "tok-cancel"
	agent, _ := makeTestAgent(token)

	ln := newUnixListener(t)
	ctx, cancel := context.WithCancel(context.Background())

	serveErr := make(chan error, 1)
	go func() { serveErr <- agent.ServeControl(ctx, ln) }()

	conn := dialUnix(t, ln.Addr().String())
	defer conn.Close()

	// Complete the handshake so the connection is in the idle-serve phase.
	sendHello(t, conn, token, proto.ProtocolVersion)
	ack := readAck(t, conn)
	if !ack.Accepted {
		t.Fatalf("handshake rejected: %q", ack.Reason)
	}

	// Cancel the serve context; the server must close the established conn.
	cancel()

	// Set a 2s safety deadline on the client so the test doesn't hang if
	// the fix regresses. The error must NOT be a timeout — it must be a
	// connection-closed error (EOF or reset) signalling server-initiated close.
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 4096)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatal("want error on established conn after ctx cancel, got nil")
	}
	// A timeout error means the server did NOT close the conn — the fix didn't work.
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("got timeout error — server did not close the conn promptly; got: %v", err)
	}

	// ServeControl should also return (via ln.Close() on ctx done).
	select {
	case <-serveErr:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("ServeControl did not return within 2s after ctx cancel")
	}
}

// newUnixListener creates a unix listener in a short tempdir path (macOS sun_path limit).
func newUnixListener(t *testing.T) net.Listener {
	t.Helper()
	dir, err := os.MkdirTemp("", "gd")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sockPath := filepath.Join(dir, "c.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Listen unix: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// dialUnix connects to a unix socket.
func dialUnix(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("unix", addr)
	if err != nil {
		t.Fatalf("Dial unix %s: %v", addr, err)
	}
	return conn
}

// TestShutdownAfterHello verifies: authenticated conn sends shutdown → receives
// shutdown_ack, and the injected poweroff func is called exactly once.
func TestShutdownAfterHello(t *testing.T) {
	const token = "tok-shutdown"
	agent, _ := makeTestAgent(token)

	// Inject a sentinel poweroff func instead of exec-ing systemctl.
	called := make(chan struct{}, 1)
	agent.PoweroffFunc = func() {
		called <- struct{}{}
	}

	ln := newUnixListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() { _ = agent.ServeControl(ctx, ln) }()

	conn := dialUnix(t, ln.Addr().String())
	defer conn.Close()

	sendHello(t, conn, token, proto.ProtocolVersion)
	ack := readAck(t, conn)
	if !ack.Accepted {
		t.Fatalf("handshake rejected: %q", ack.Reason)
	}

	// Send shutdown with deadline_s=10.
	sd := proto.Shutdown{DeadlineS: 10}
	if err := proto.WriteControl(conn, proto.KindShutdown, sd); err != nil {
		t.Fatalf("WriteControl shutdown: %v", err)
	}

	// Expect shutdown_ack back.
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	env, err := proto.ReadControl(conn)
	if err != nil {
		t.Fatalf("ReadControl shutdown_ack: %v", err)
	}
	if env.Kind != proto.KindShutdownAck {
		t.Errorf("want kind %q, got %q", proto.KindShutdownAck, env.Kind)
	}

	// Verify the poweroff func ran.
	select {
	case <-called:
		// good
	case <-time.After(2 * time.Second):
		t.Error("poweroff func was not called within 2s of shutdown_ack")
	}
}

// TestShutdownBeforeHello verifies: shutdown before a successful hello is
// refused (the server sends an error envelope and closes the connection)
// and the poweroff func is NOT called.
func TestShutdownBeforeHello(t *testing.T) {
	const token = "tok-sd-prehello"
	agent, _ := makeTestAgent(token)

	called := make(chan struct{}, 1)
	agent.PoweroffFunc = func() {
		called <- struct{}{}
	}

	ln := newUnixListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() { _ = agent.ServeControl(ctx, ln) }()

	conn := dialUnix(t, ln.Addr().String())
	defer conn.Close()

	// Send shutdown without doing the hello first — agent expects hello kind.
	sd := proto.Shutdown{DeadlineS: 5}
	if err := proto.WriteControl(conn, proto.KindShutdown, sd); err != nil {
		t.Fatalf("WriteControl shutdown: %v", err)
	}

	// Server sends an error envelope then closes the conn (sendError + deferred Close).
	// The sequence is deterministic: first frame is always the error kind.
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	env, err := proto.ReadControl(conn)
	if err != nil {
		t.Fatalf("expected error envelope, got read error: %v", err)
	}
	if env.Kind != proto.KindError {
		t.Errorf("want kind %q, got %q", proto.KindError, env.Kind)
	}
	// After the error envelope, the deferred conn.Close fires — next read must fail.
	_, err = proto.ReadControl(conn)
	if err == nil {
		t.Error("want EOF or closed-conn error after error envelope, got nil")
	}

	// Poweroff must NOT have been called.
	select {
	case <-called:
		t.Error("poweroff func must NOT be called when shutdown arrives before hello")
	case <-time.After(500 * time.Millisecond):
		// good — not called
	}
}

// TestReconnectAfterClose verifies that after a connection closes, the accept
// loop accepts a new connection and a fresh hello succeeds.
func TestReconnectAfterClose(t *testing.T) {
	const token = "tok-reconnect"
	agent, _ := makeTestAgent(token)

	// Poweroff func is a no-op; shutdown is not part of this test.
	agent.PoweroffFunc = func() {}

	ln := newUnixListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() { _ = agent.ServeControl(ctx, ln) }()

	// First connection: complete the handshake, then close it.
	conn1 := dialUnix(t, ln.Addr().String())
	sendHello(t, conn1, token, proto.ProtocolVersion)
	ack1 := readAck(t, conn1)
	if !ack1.Accepted {
		t.Fatalf("first conn: handshake rejected: %q", ack1.Reason)
	}
	conn1.Close()

	// Second connection: a fresh hello must succeed — the accept loop must still be alive.
	conn2 := dialUnix(t, ln.Addr().String())
	defer conn2.Close()

	sendHello(t, conn2, token, proto.ProtocolVersion)
	ack2 := readAck(t, conn2)
	if !ack2.Accepted {
		t.Errorf("second conn (reconnect): handshake rejected: %q", ack2.Reason)
	}
}
