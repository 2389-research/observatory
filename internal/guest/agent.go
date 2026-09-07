// ABOUTME: Agent: accepts control-channel connections, performs the hello handshake, serves capabilities/ping/shutdown.
// ABOUTME: Transport-agnostic: takes a net.Listener; vsock wiring happens only in cmd/vmobs-guestd main.
package guest

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/2389-research/observatory/internal/guest/proto"
	"github.com/2389-research/observatory/internal/guest/pty"
	"github.com/2389-research/observatory/internal/guest/telemetry"
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
	broker   *pty.Broker

	// telemetry holds the bounded ring sensors push into and the health block
	// every heartbeat renders. It exists from construction so an event queued
	// before any host connects still has somewhere to go.
	telemetry *telemetry.Reporter

	// PoweroffFunc is called after the agent sends shutdown_ack. Tests override
	// this to avoid actually powering off the machine. Production default execs
	// "systemctl reboot", not poweroff — see defaultPoweroff below for why.
	// Must not be nil.
	PoweroffFunc func()
}

// defaultPoweroff is the production implementation. It runs "systemctl
// reboot", not poweroff, despite the name — this guest has no working
// poweroff path. Firecracker v1.16.1 hands it ACPI tables that advertise only
// S0, never S5 (soft-off), and "systemctl poweroff" then runs a complete, clean
// systemd shutdown and halts: the guest prints "reboot: System halted", the
// vCPU parks in HLT, and the VMM never exits. All of that was observed
// directly. The step between them — no S5 sleep-type data means no registered
// power-off handler, so sys_reboot downgrades POWER_OFF to HALT — is inferred
// from kernel source (drivers/acpi/sleep.c); the guest's handler list was never
// read. No grace period fixes any of it.
// Firecracker cannot reboot a guest, so a guest-initiated restart is the only
// exit door that exists: reboot=k (boot args) makes the kernel write the
// i8042 reset byte directly, which Firecracker catches and exits on. So this
// is the power-off path, not a restart — PoweroffFunc keeps its name because
// it describes what happens to the VM, not the mechanism.
func defaultPoweroff() {
	if err := exec.Command("systemctl", "reboot").Run(); err != nil {
		fmt.Fprintf(os.Stderr, "guestd: systemctl reboot failed: %v\n", err)
	}
}

// NewAgent constructs an Agent from a validated BootConfig and a capability manifest.
func NewAgent(cfg *BootConfig, manifest proto.CapabilityManifest) *Agent {
	return &Agent{
		cfg:      cfg,
		manifest: manifest,
		token:    []byte(cfg.CapabilityToken),
		broker:   pty.NewBroker(pty.BrokerConfig{}),
		telemetry: telemetry.NewReporter(telemetry.ReporterConfig{
			Version:           AgentVersion,
			RingCapacity:      telemetryRingCapacity,
			HeartbeatInterval: HeartbeatInterval,
		}),
		PoweroffFunc: defaultPoweroff,
	}
}

// ServeControl accepts connections from ln until ctx is cancelled or ln is closed.
// Each connection runs in its own goroutine; the listener is NOT closed by ServeControl.
func (a *Agent) ServeControl(ctx context.Context, ln net.Listener) error {
	return a.accept(ctx, ln, a.handleConn)
}

// accept runs one listener's accept loop until ctx is cancelled or ln is
// closed, handing each connection to handle in its own goroutine. The listener
// is NOT closed by accept.
func (a *Agent) accept(ctx context.Context, ln net.Listener, handle func(context.Context, net.Conn)) error {
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
		go handle(ctx, conn)
	}
}

// closeOnCancel closes conn when ctx is cancelled, so a connection does not
// coast to its own idle deadline after the agent is shutting down. The
// returned func stops the watcher; a double close of conn is harmless.
func closeOnCancel(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	return func() { close(done) }
}

// handleConn runs the per-connection protocol: handshake, then serve until idle or error.
func (a *Agent) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	defer closeOnCancel(ctx, conn)()

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

	if reason := a.authHello(hello); reason != "" {
		_ = a.writeControl(conn, proto.KindHelloAck, proto.HelloAck{Accepted: false, Reason: reason})
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

// authHello applies the connection admission rule to a hello: right protocol
// version, right capability token. It returns the refusal reason, or "" when
// the hello is good. Both the control channel and every session byte stream
// go through it, so the rule has one definition.
func (a *Agent) authHello(hello proto.Hello) string {
	if hello.ProtocolVersion != proto.ProtocolVersion {
		return fmt.Sprintf("protocol version mismatch: got %d, want %d", hello.ProtocolVersion, proto.ProtocolVersion)
	}
	// Constant-time token compare. Only compare when lengths are equal to
	// not leak length via timing — subtle.ConstantTimeCompare returns 0 on
	// length mismatch anyway, but making it explicit keeps the intent clear.
	proof := []byte(hello.AuthProof)
	if len(proof) != len(a.token) || subtle.ConstantTimeCompare(proof, a.token) != 1 {
		return "authentication failed"
	}
	return ""
}

// serveRequests handles authenticated verbs until EOF, idle timeout, or shutdown.
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
		case proto.KindShutdown:
			// Reply ack first, then invoke poweroff — the host runner waits for
			// the ack before its own grace deadline expires. Log a lost ack but
			// do NOT gate poweroff on delivery: the host escalates if the VM stays up.
			if err := a.writeControl(conn, proto.KindShutdownAck, struct{}{}); err != nil {
				fmt.Fprintf(os.Stderr, "guestd: shutdown_ack write failed: %v\n", err)
			}
			a.PoweroffFunc()
			return
		case proto.KindTerminalCreate, proto.KindTerminalClose, proto.KindTerminalList:
			// A terminal verb that fails answers terminal.error and the
			// channel stays up: one bad session id must not cost the VM its
			// control connection. Only a transport error ends the loop.
			if err := a.serveTerminal(conn, env); err != nil {
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
