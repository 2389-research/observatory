// ABOUTME: Agent: accepts control-channel connections, performs the hello handshake, serves capabilities/ping.
// ABOUTME: Transport-agnostic: takes a net.Listener; vsock wiring happens only in cmd/vmobs-guestd main.
package guest

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/2389-research/observatory-v2/internal/guest/proto"
)

const (
	handshakeTimeout = 10 * time.Second
	idleTimeout      = 60 * time.Second
	writeTimeout     = 10 * time.Second
)

// Agent serves the guest control channel. It is safe to call ServeControl on
// the same Agent from multiple goroutines (concurrent connections are independent).
type Agent struct {
	cfg      *BootConfig
	manifest proto.CapabilityManifest
	token    []byte // pre-converted for constant-time compare
}

// NewAgent constructs an Agent from a validated BootConfig and a capability manifest.
func NewAgent(cfg *BootConfig, manifest proto.CapabilityManifest) *Agent {
	return &Agent{
		cfg:      cfg,
		manifest: manifest,
		token:    []byte(cfg.CapabilityToken),
	}
}

// ServeControl accepts connections from ln until ctx is cancelled or ln is closed.
// Each connection runs in its own goroutine; the listener is NOT closed by ServeControl.
func (a *Agent) ServeControl(ctx context.Context, ln net.Listener) error {
	// Close ln when ctx is done so Accept unblocks.
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			// Distinguish a clean shutdown from a real error.
			if ctx.Err() != nil {
				return nil
			}
			// On a transient accept error, keep the listener open.
			var ne net.Error
			if errors.As(err, &ne) && ne.Temporary() { //nolint:staticcheck
				continue
			}
			return fmt.Errorf("accept: %w", err)
		}
		go a.handleConn(ctx, conn)
	}
}

// handleConn runs the per-connection protocol: handshake, then serve until idle or error.
func (a *Agent) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// Close the conn when ctx is cancelled so it doesn't coast until the
	// 60s idle deadline. Double-close is harmless.
	connDone := make(chan struct{})
	defer close(connDone)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close() // unblocks any pending read/write; double-close later is harmless
		case <-connDone:
		}
	}()

	// --- Phase 1: handshake (10s total deadline) ---
	handshakeDeadline := time.Now().Add(handshakeTimeout)
	if err := conn.SetDeadline(handshakeDeadline); err != nil {
		return
	}

	env, err := proto.ReadControl(conn)
	if err != nil {
		// Oversized or malformed frame: best-effort error envelope, then close.
		a.sendError(conn, fmt.Sprintf("read control frame: %v", err))
		return
	}

	if env.Kind != proto.KindHello {
		a.sendError(conn, fmt.Sprintf("expected kind %q, got %q", proto.KindHello, env.Kind))
		return
	}

	var hello proto.Hello
	if err := json.Unmarshal(env.Data, &hello); err != nil {
		a.sendError(conn, fmt.Sprintf("malformed hello: %v", err))
		return
	}

	// Check protocol version.
	if hello.ProtocolVersion != proto.ProtocolVersion {
		ack := proto.HelloAck{
			Accepted: false,
			Reason:   fmt.Sprintf("protocol version mismatch: got %d, want %d", hello.ProtocolVersion, proto.ProtocolVersion),
		}
		_ = a.writeControl(conn, proto.KindHelloAck, ack)
		return
	}

	// Constant-time token compare. Only compare when lengths are equal to
	// not leak length via timing — subtle.ConstantTimeCompare returns 0 on
	// length mismatch anyway, but making it explicit keeps the intent clear.
	proof := []byte(hello.AuthProof)
	var tokenOK bool
	if len(proof) == len(a.token) {
		tokenOK = subtle.ConstantTimeCompare(proof, a.token) == 1
	}
	if !tokenOK {
		ack := proto.HelloAck{Accepted: false, Reason: "authentication failed"}
		_ = a.writeControl(conn, proto.KindHelloAck, ack)
		return
	}

	// Handshake accepted.
	ack := proto.HelloAck{Accepted: true}
	if err := a.writeControl(conn, proto.KindHelloAck, ack); err != nil {
		return
	}

	// --- Phase 2: serve requests with 60s rolling idle timeout ---
	a.serveRequests(conn)
}

// serveRequests handles get_capabilities and ping until EOF, idle timeout, or error.
func (a *Agent) serveRequests(conn net.Conn) {
	for {
		if err := conn.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			return
		}
		env, err := proto.ReadControl(conn)
		if err != nil {
			// EOF or timeout: clean exit, no error envelope needed.
			return
		}
		switch env.Kind {
		case proto.KindGetCapabilities:
			if err := a.writeControl(conn, proto.KindCapabilities, a.manifest); err != nil {
				return
			}
		case proto.KindPing:
			if err := a.writeControl(conn, proto.KindPong, struct{}{}); err != nil {
				return
			}
		default:
			a.sendError(conn, fmt.Sprintf("unknown kind %q", env.Kind))
			return
		}
	}
}

// writeControl sets the write deadline, then writes an envelope.
func (a *Agent) writeControl(conn net.Conn, kind string, data any) error {
	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	return proto.WriteControl(conn, kind, data)
}

// sendError sends a best-effort error envelope. Errors are not logged to avoid
// leaking secrets (the token should never appear in any log or error message).
func (a *Agent) sendError(conn net.Conn, _ string) {
	// We deliberately discard the message string in the envelope — it is only
	// used internally to gate the send; the wire carries an opaque error kind.
	// This prevents any accidental inclusion of token material in error frames.
	_ = a.writeControl(conn, proto.KindError, struct{ Reason string }{Reason: "protocol error"})
}
