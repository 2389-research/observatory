// ABOUTME: Tests the guest's telemetry port: it authenticates like every other
// ABOUTME: port, echoes the stream identity the host assigned, and never loses a queued event.
package guest_test

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/guest"
	"github.com/2389-research/observatory/internal/guest/proto"
)

func readPush(t *testing.T, conn net.Conn) proto.TelemetryPush {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	env, err := proto.ReadControl(conn)
	if err != nil {
		t.Fatalf("read push: %v", err)
	}
	if env.Kind != proto.KindTelemetryPush {
		t.Fatalf("kind = %q, want %q", env.Kind, proto.KindTelemetryPush)
	}
	push, err := proto.DecodeTelemetryPush(env.Data)
	if err != nil {
		t.Fatalf("decode push: %v", err)
	}
	return push
}

// The host names the stream. The guest echoes the name so the runner can see
// it is counting inside the identity the host assigned rather than one of its
// own choosing.
func TestTelemetryHandshakeEchoesTheAssignedIdentity(t *testing.T) {
	const token = "tok-telemetry"
	agent, _ := makeTestAgent(token)
	ln := newUnixListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _ = agent.ServeTelemetry(ctx, ln) }()

	conn := dialUnix(t, ln.Addr().String())
	defer conn.Close()
	sendHello(t, conn, token, proto.ProtocolVersion)

	ack := readAck(t, conn)
	if !ack.Accepted {
		t.Fatalf("handshake refused: %s", ack.Reason)
	}
	if ack.TelemetryInstanceID != "inst-1" {
		t.Errorf("telemetry_instance_id = %q, want the id the host sent (%q)", ack.TelemetryInstanceID, "inst-1")
	}
}

func TestTelemetryPortRefusesAWrongToken(t *testing.T) {
	agent, _ := makeTestAgent("right")
	ln := newUnixListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _ = agent.ServeTelemetry(ctx, ln) }()

	conn := dialUnix(t, ln.Addr().String())
	defer conn.Close()
	sendHello(t, conn, "wrong", proto.ProtocolVersion)
	if ack := readAck(t, conn); ack.Accepted {
		t.Fatal("a wrong token was accepted on the telemetry port")
	}
}

func TestTelemetryDeliversAQueuedHeartbeat(t *testing.T) {
	const token = "tok-beat"
	agent, _ := makeTestAgent(token)
	agent.Telemetry().Beat()

	ln := newUnixListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _ = agent.ServeTelemetry(ctx, ln) }()

	conn := dialUnix(t, ln.Addr().String())
	defer conn.Close()
	sendHello(t, conn, token, proto.ProtocolVersion)
	if ack := readAck(t, conn); !ack.Accepted {
		t.Fatalf("handshake refused: %s", ack.Reason)
	}

	push := readPush(t, conn)
	if push.Kind != "guest.sensor_health" {
		t.Errorf("kind = %q, want guest.sensor_health", push.Kind)
	}
	if push.Seq != "1" {
		t.Errorf("seq = %q, want 1 — the first event the agent queued", push.Seq)
	}
	if push.GuestWallAt == "" || push.GuestMonotonicNS == "" {
		t.Errorf("guest clocks missing: wall=%q mono=%q", push.GuestWallAt, push.GuestMonotonicNS)
	}
	var health struct {
		Sensors []json.RawMessage `json:"sensors"`
	}
	if err := json.Unmarshal(push.Data, &health); err != nil {
		t.Fatalf("unmarshal health: %v", err)
	}
	if health.Sensors == nil {
		t.Error("sensors is null; with none registered it must be an empty array")
	}
}

// A connection that breaks mid-send must not consume the event. The guest pops
// only after a write returns, so the next connection re-sends the same seq and
// the store's dedup absorbs the possible duplicate. Losing it silently instead
// would be exactly the unmeasured loss §507 forbids.
func TestTelemetryKeepsAnEventWhoseSendNeverCompleted(t *testing.T) {
	const token = "tok-resend"
	agent, _ := makeTestAgent(token)
	agent.Telemetry().Beat()

	ln := newUnixListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() { _ = agent.ServeTelemetry(ctx, ln) }()

	// First connection: handshake, then hang up without ever reading the push.
	first := dialUnix(t, ln.Addr().String())
	sendHello(t, first, token, proto.ProtocolVersion)
	if ack := readAck(t, first); !ack.Accepted {
		t.Fatalf("handshake refused: %s", ack.Reason)
	}
	first.Close()

	// Second connection: the event is still there, under the same seq.
	second := dialUnix(t, ln.Addr().String())
	defer second.Close()
	sendHello(t, second, token, proto.ProtocolVersion)
	if ack := readAck(t, second); !ack.Accepted {
		t.Fatalf("second handshake refused: %s", ack.Reason)
	}
	push := readPush(t, second)
	if push.Seq != "1" {
		t.Fatalf("seq = %q on the re-send, want 1 — a re-sent event must keep its seq or dedup cannot see it", push.Seq)
	}
}

// The ack is what releases an event. Once the host says it holds seq 1, a
// reconnect must start at 2 — otherwise every reconnect replays the whole ring
// and the guest can never forget anything.
func TestTelemetryStopsResendingOnceTheHostAcknowledges(t *testing.T) {
	const token = "tok-ack"
	agent, _ := makeTestAgent(token)
	agent.Telemetry().Beat()
	agent.Telemetry().Beat()

	ln := newUnixListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() { _ = agent.ServeTelemetry(ctx, ln) }()

	first := dialUnix(t, ln.Addr().String())
	sendHello(t, first, token, proto.ProtocolVersion)
	if ack := readAck(t, first); !ack.Accepted {
		t.Fatalf("handshake refused: %s", ack.Reason)
	}
	if got := readPush(t, first).Seq; got != "1" {
		t.Fatalf("first push seq = %q, want 1", got)
	}
	if err := proto.WriteControl(first, proto.KindTelemetryAck, proto.TelemetryAck{ThroughSeq: "1"}); err != nil {
		t.Fatalf("write ack: %v", err)
	}
	if got := readPush(t, first).Seq; got != "2" {
		t.Fatalf("second push seq = %q, want 2", got)
	}
	// Wait for the ack to land before hanging up: the reader folds it in on its
	// own goroutine, and a race here would test the wrong thing.
	waitForQueued(t, agent, 1)
	first.Close()

	second := dialUnix(t, ln.Addr().String())
	defer second.Close()
	sendHello(t, second, token, proto.ProtocolVersion)
	if ack := readAck(t, second); !ack.Accepted {
		t.Fatalf("second handshake refused: %s", ack.Reason)
	}
	if got := readPush(t, second).Seq; got != "2" {
		t.Fatalf("re-send started at seq %q, want 2 — an acknowledged event must not come back", got)
	}
}

// Nothing about a missing host may stop the agent observing. The ring fills,
// and the count of what piled up is the evidence that nobody was reading.
func TestHeartbeatRunsWithNoHostConnected(t *testing.T) {
	agent, _ := makeTestAgent("tok-run")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go agent.RunHeartbeat(ctx, 5*time.Millisecond)
	// At least three, not exactly three: the ticker does not wait for the test.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if agent.Telemetry().Ring().Stats().Queued >= 3 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("ring queued = %d after 5s, want at least 3 heartbeats with no host connected",
		agent.Telemetry().Ring().Stats().Queued)
}

func waitForQueued(t *testing.T, agent *guest.Agent, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := agent.Telemetry().Ring().Stats().Queued; got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("ring queued = %d after 5s, want %d", agent.Telemetry().Ring().Stats().Queued, want)
}
