// ABOUTME: The guest's telemetry port (vsock 10001): one authenticated stream that
// ABOUTME: drains the bounded ring to the host and forgets only what the host acknowledges.
package guest

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/2389-research/observatory-v2/internal/guest/proto"
	"github.com/2389-research/observatory-v2/internal/guest/telemetry"
)

// AgentVersion identifies the guest agent in its heartbeat. Nothing stamps a
// build id into this binary — no ldflags, no build info — so the only version
// fact the agent actually knows is the protocol it speaks. Saying that is
// honest; inventing a build number would not be. A real build stamp belongs
// here when one exists.
var AgentVersion = fmt.Sprintf("vmobs-guestd/proto-%d", proto.ProtocolVersion)

// HeartbeatInterval is how often the agent reports its own health. Every
// heartbeat carries this number, so the host derives staleness from what the
// guest actually does rather than from a constant the two must keep in step.
const HeartbeatInterval = 10 * time.Second

// telemetryRingCapacity bounds the guest's queue of unacknowledged events.
// Sized for a small guest: a heartbeat is a few hundred bytes, so a full ring
// is well under a megabyte, and it holds hours of heartbeats across a host
// outage. A sensor firehose will want its own number, measured rather than
// guessed.
const telemetryRingCapacity = 1024

// ServeTelemetry accepts telemetry connections. One host connects at a time in
// practice; a second gets its own drain loop and the ack cursor keeps both
// honest, since an item leaves the ring only when acknowledged.
func (a *Agent) ServeTelemetry(ctx context.Context, ln net.Listener) error {
	return a.accept(ctx, ln, a.handleTelemetry)
}

// Telemetry returns the agent's reporter: the ring sensors push into and the
// health block every heartbeat renders.
func (a *Agent) Telemetry() *telemetry.Reporter { return a.telemetry }

// RunHeartbeat queues a health report immediately and then on every tick until
// ctx ends. It runs whether or not a host is connected — the ring is where
// events wait, and a heartbeat the host missed is a drop the next heartbeat
// counts.
func (a *Agent) RunHeartbeat(ctx context.Context, interval time.Duration) {
	a.telemetry.Beat()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.telemetry.Beat()
		}
	}
}

func (a *Agent) handleTelemetry(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	defer closeOnCancel(ctx, conn)()

	if err := conn.SetReadDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return
	}
	env, err := proto.ReadControl(conn)
	if err != nil {
		return
	}
	if env.Kind != proto.KindHello {
		_ = a.writeControl(conn, proto.KindHelloAck, proto.HelloAck{
			Accepted: false,
			Reason:   fmt.Sprintf("expected %s, got %s", proto.KindHello, env.Kind),
		})
		return
	}
	var hello proto.Hello
	if err := json.Unmarshal(env.Data, &hello); err != nil {
		_ = a.writeControl(conn, proto.KindHelloAck, proto.HelloAck{
			Accepted: false,
			Reason:   fmt.Sprintf("malformed hello: %v", err),
		})
		return
	}
	if reason := a.authHello(hello); reason != "" {
		_ = a.writeControl(conn, proto.KindHelloAck, proto.HelloAck{Accepted: false, Reason: reason})
		return
	}

	// The host names the stream; the guest echoes the name back so the runner
	// can see whose identity these sequences are counted in. A confirmation,
	// not a negotiation.
	if err := a.writeControl(conn, proto.KindHelloAck, proto.HelloAck{
		Accepted:            true,
		TelemetryInstanceID: hello.SourceInstance,
	}); err != nil {
		return
	}

	ring := a.telemetry.Ring()
	ring.Rewind()

	// Acks arrive on their own schedule, so they get their own reader. It ends
	// when the connection does, which is also what ends the sender.
	acks := make(chan struct{})
	go func() {
		defer close(acks)
		a.readAcks(conn, ring)
	}()

	a.drainTelemetry(ctx, conn, ring, acks)
}

// readAcks folds the host's cumulative acknowledgements into the ring until the
// connection ends. A frame that is not an ack ends the connection: this port
// carries exactly one host-to-guest message, and a guest that shrugs at
// unexpected frames is a guest that cannot say what it is speaking.
func (a *Agent) readAcks(conn net.Conn, ring *telemetry.Ring) {
	// No idle deadline: a host with nothing to acknowledge is a host with
	// nothing to say, and the connection ending is what ends this loop.
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return
	}
	for {
		env, err := proto.ReadControl(conn)
		if err != nil {
			return
		}
		if env.Kind != proto.KindTelemetryAck {
			return
		}
		var ack proto.TelemetryAck
		if err := json.Unmarshal(env.Data, &ack); err != nil {
			return
		}
		ring.AckThrough(ack.ThroughSeq)
	}
}

// drainTelemetry writes queued events until the connection or the context ends.
// It advances past what it wrote and forgets nothing: AckThrough is the only
// thing that removes an item, so a connection that dies mid-flight costs a
// duplicate on the next one rather than a silent gap.
func (a *Agent) drainTelemetry(ctx context.Context, conn net.Conn, ring *telemetry.Ring, acks <-chan struct{}) {
	for {
		item, ok := ring.Next()
		if !ok {
			select {
			case <-ctx.Done():
				return
			case <-acks:
				return
			case <-ring.Waiting():
				continue
			}
		}
		if err := a.writeControl(conn, proto.KindTelemetryPush, proto.TelemetryPush{
			Seq:              item.Seq,
			Kind:             item.Kind,
			GuestWallAt:      item.GuestWallAt,
			GuestMonotonicNS: item.GuestMonotonicNS,
			Data:             item.Data,
		}); err != nil {
			// The item stays where it is. The next connection rewinds to it.
			return
		}
		ring.Advance()
	}
}
