// ABOUTME: Portable tests for the runner's telemetry client: a real guest agent behind a
// ABOUTME: port-routing vsock mux, plus fake guests that break the contract on purpose.
package runner_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/events"
	"github.com/2389-research/observatory-v2/internal/guest"
	"github.com/2389-research/observatory-v2/internal/guest/proto"
	"github.com/2389-research/observatory-v2/internal/runner"
	"github.com/2389-research/observatory-v2/internal/spool"
)

// controlPort is the guest's control vsock port, which the runner's supervision
// loop dials. Named here because the mux routes by port, and a telemetry test
// needs both ports live at once.
const controlPort = 10000

const (
	// The store requires lowercase UUIDs for these three, and this test
	// validates a spooled envelope, so they are real ones.
	telVMID      = "3f2b1a7c-5d4e-4a9b-8c11-2e6f0a5b7d38"
	telBootID    = "8c9d0e1f-2a3b-4c5d-9e6f-1a2b3c4d5e6f"
	telInstance  = "b1c2d3e4-f5a6-4b7c-8d9e-0f1a2b3c4d5e"
	telToken     = "telemetry-capability-token-1234"
	telSpoolWait = 10 * time.Second
)

// TestRunnerSpoolsWhatTheGuestReports drives the whole path with real parts: a
// real guest agent queues a heartbeat into its real ring, the real runner dials
// 10001 through a mux that routes the way Firecracker's vsock proxy does, and
// the envelope lands in a real spool segment. The assertions are about what the
// runner stamped, because that stamping is the trust boundary: the guest said
// what happened, the host says who observed it and when.
func TestRunnerSpoolsWhatTheGuestReports(t *testing.T) {
	h := newTelemetryHarness(t)
	agent := h.startGuest()
	h.serveRealTelemetry(agent)

	// One beat before the runner starts, so the ring has something waiting and
	// the test does not depend on the heartbeat ticker.
	agent.Telemetry().Beat()

	h.run()

	env := h.waitForKind("guest.sensor_health")
	if env == nil {
		t.Fatal("no guest.sensor_health envelope reached the spool")
	}

	if env.Provenance != events.GuestReported {
		t.Errorf("provenance: got %q, want %q", env.Provenance, events.GuestReported)
	}
	if env.Sensor != "guestd" {
		t.Errorf("sensor: got %q, want %q", env.Sensor, "guestd")
	}
	if env.SourceSeq != "1" {
		t.Errorf("source_seq: got %q, want %q", env.SourceSeq, "1")
	}
	// The host names the stream. It must be a lowercase UUID (the store
	// requires it) and it must not be the runner's own instance id, or the
	// guest's sequences would collide with the runner's own.
	if !events.UUIDString(env.SourceInstanceID) {
		t.Errorf("source_instance_id %q is not a lowercase uuid", env.SourceInstanceID)
	}
	if env.SourceInstanceID == telInstance {
		t.Error("guest telemetry was filed under the runner's own instance id")
	}
	if env.HostReceivedAt.IsZero() {
		t.Error("host_received_at is zero; the host clock is the host's to stamp")
	}
	if env.GuestWallAt == nil {
		t.Error("guest_wall_at was dropped; the guest's clock is carried through as reported")
	}
	if env.GuestMonotonicNS == nil || *env.GuestMonotonicNS == "" {
		t.Error("guest_monotonic_ns was dropped")
	}
	if err := env.Validate(); err != nil {
		t.Errorf("spooled envelope does not validate: %v", err)
	}

	// The heartbeat's own payload must survive the trip intact.
	if _, ok := env.Data["agent"]; !ok {
		t.Errorf("heartbeat payload lost its agent block: %v", env.Data)
	}

	// The runner acknowledged what it spooled, so the guest let it go. Until
	// the ack arrives the ring is right to keep it, which is what makes this
	// assertion the interesting half of at-least-once delivery.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if q := agent.Telemetry().Ring().Stats().Queued; q == 0 {
			break
		} else if time.Now().After(deadline) {
			t.Errorf("guest still holds %d unacknowledged events", q)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestRunnerRefusesAGuestThatRenamesItsStream covers the handshake's one real
// decision. The echo is a confirmation, not a negotiation: a guest answering
// with an id the host never sent is counting in some other stream, so nothing
// it pushes afterwards can be attributed to this one.
func TestRunnerRefusesAGuestThatRenamesItsStream(t *testing.T) {
	h := newTelemetryHarness(t)
	h.startGuest()
	h.serveFakeTelemetry(func(conn net.Conn) {
		if _, err := readHello(conn); err != nil {
			return
		}
		_ = proto.WriteControl(conn, proto.KindHelloAck, proto.HelloAck{
			Accepted:            true,
			TelemetryInstanceID: "inst-somebody-else",
			TelemetryEpoch:      "abcdef",
		})
		// A refused handshake must stop the runner reading. If it did not, this
		// perfectly well-formed event would be spooled under a stream identity
		// derived from an id the host never assigned.
		_ = writeFakePush(conn, "1", "guest.sensor_health", `{"agent":{}}`)
		io.Copy(io.Discard, conn) //nolint:errcheck
	})

	h.run()

	if env := h.pollForKind("guest.sensor_health", 2*time.Second); env != nil {
		t.Errorf("runner spooled telemetry after a refused handshake: %+v", env)
	}
}

// TestRunnerRecordsAFrameThatIsNotAPush pins the resynchronise path: a frame the
// runner cannot place in the stream ends the connection, and the reason is
// written down on the runner's own stream rather than the guest's.
func TestRunnerRecordsAFrameThatIsNotAPush(t *testing.T) {
	h := newTelemetryHarness(t)
	h.startGuest()
	h.serveFakeTelemetry(func(conn net.Conn) {
		hello, err := readHello(conn)
		if err != nil {
			return
		}
		_ = acceptHello(conn, hello)
		_ = proto.WriteControl(conn, proto.KindPing, map[string]any{})
		io.Copy(io.Discard, conn) //nolint:errcheck
	})

	h.run()

	env := h.waitForKind("telemetry.integrity_failure")
	if env == nil {
		t.Fatal("no telemetry.integrity_failure reached the spool")
	}
	if env.Provenance != events.HostObserved {
		t.Errorf("provenance: got %q, want %q", env.Provenance, events.HostObserved)
	}
	if env.SourceInstanceID != telInstance {
		t.Errorf("integrity failure filed under %q, want the runner's own stream %q",
			env.SourceInstanceID, telInstance)
	}
	if got, _ := env.Data["failure"].(string); got != "unexpected_frame" {
		t.Errorf("failure: got %q, want %q", got, "unexpected_frame")
	}
}

// TestRunnerRefusesAPushCarryingAHostAssignedField covers the allow-list. A
// guest that could set provenance could call its own claim a host observation.
func TestRunnerRefusesAPushCarryingAHostAssignedField(t *testing.T) {
	h := newTelemetryHarness(t)
	h.startGuest()
	h.serveFakeTelemetry(func(conn net.Conn) {
		hello, err := readHello(conn)
		if err != nil {
			return
		}
		_ = acceptHello(conn, hello)
		_ = proto.WriteControl(conn, proto.KindTelemetryPush, map[string]any{
			"seq":        "1",
			"kind":       "guest.sensor_health",
			"data":       map[string]any{},
			"provenance": "host_observed",
		})
		io.Copy(io.Discard, conn) //nolint:errcheck
	})

	h.run()

	env := h.waitForKind("telemetry.integrity_failure")
	if env == nil {
		t.Fatal("no telemetry.integrity_failure reached the spool")
	}
	if got, _ := env.Data["failure"].(string); got != "malformed_push" {
		t.Errorf("failure: got %q, want %q", got, "malformed_push")
	}
	if detail, _ := env.Data["detail"].(string); !strings.Contains(detail, "provenance") {
		t.Errorf("detail does not name the offending field: %q", detail)
	}
	if h.countKind("guest.sensor_health") != 0 {
		t.Error("the refused push was spooled anyway")
	}
}

// TestRunnerRefusesAKindTheGuestMayNotReport is the check that keeps a guest
// from wedging its own import. A host_observed kind stamped guest_reported is a
// hard Append error at the store, and the importer stops that VM's segment on
// one without advancing its cursor — so the refusal has to happen here.
func TestRunnerRefusesAKindTheGuestMayNotReport(t *testing.T) {
	h := newTelemetryHarness(t)
	h.startGuest()
	h.serveFakeTelemetry(func(conn net.Conn) {
		hello, err := readHello(conn)
		if err != nil {
			return
		}
		_ = acceptHello(conn, hello)
		_ = writeFakePush(conn, "1", "vm.vmm_exited", `{"graceful":true}`)
		_ = writeFakePush(conn, "2", "not.a.registered.kind", `{}`)
		io.Copy(io.Discard, conn) //nolint:errcheck
	})

	h.run()

	claim := h.waitForKind("telemetry.integrity_failure")
	if claim == nil {
		t.Fatal("no telemetry.integrity_failure for the host_observed kind")
	}
	if got, _ := claim.Data["failure"].(string); got != "guest_provenance_claim" {
		t.Errorf("failure: got %q, want %q", got, "guest_provenance_claim")
	}
	if got, _ := claim.Data["kind"].(string); got != "vm.vmm_exited" {
		t.Errorf("refusal names kind %q, want %q", got, "vm.vmm_exited")
	}
	if got, _ := claim.Data["registered_as"].(string); got != string(events.HostObserved) {
		t.Errorf("registered_as: got %q, want %q", got, events.HostObserved)
	}
	if got, _ := claim.Data["source_seq"].(string); got != "1" {
		t.Errorf("refusal names seq %q, want %q", got, "1")
	}

	// The connection stays up: a frame the runner understands exactly is
	// refused precisely, so the next one is still read.
	unreg := h.waitForKind("telemetry.unregistered_kind")
	if unreg == nil {
		t.Fatal("no telemetry.unregistered_kind for the unregistered kind")
	}
	if got, _ := unreg.Data["kind"].(string); got != "not.a.registered.kind" {
		t.Errorf("refusal names kind %q, want %q", got, "not.a.registered.kind")
	}

	if h.countKind("vm.vmm_exited") != 0 {
		t.Error("the guest's vm.vmm_exited was spooled as an event")
	}
}

// TestRunnerAcksADuplicateWithoutSpoolingItTwice covers the other half of
// at-least-once: a guest that never saw an ack re-sends, and those re-sends are
// expected rather than suspicious.
func TestRunnerAcksADuplicateWithoutSpoolingItTwice(t *testing.T) {
	h := newTelemetryHarness(t)
	h.startGuest()
	acked := make(chan string, 8)
	h.serveFakeTelemetry(func(conn net.Conn) {
		hello, err := readHello(conn)
		if err != nil {
			return
		}
		_ = acceptHello(conn, hello)
		for i := 0; i < 2; i++ {
			if err := writeFakePush(conn, "1", "guest.sensor_health", `{"agent":{}}`); err != nil {
				return
			}
			env, err := proto.ReadControl(conn)
			if err != nil {
				return
			}
			var ack proto.TelemetryAck
			if err := json.Unmarshal(env.Data, &ack); err != nil {
				return
			}
			acked <- ack.ThroughSeq
		}
		io.Copy(io.Discard, conn) //nolint:errcheck
	})

	h.run()

	for i := 0; i < 2; i++ {
		select {
		case seq := <-acked:
			if seq != "1" {
				t.Errorf("ack %d: got seq %q, want %q", i+1, seq, "1")
			}
		case <-time.After(telSpoolWait):
			t.Fatalf("only got %d acks; a re-send must be acknowledged too", i)
		}
	}

	// Both acks are in, so both pushes were decided. Exactly one is an event.
	if n := h.countKind("guest.sensor_health"); n != 1 {
		t.Errorf("spooled %d copies of seq 1, want 1", n)
	}
}

// --- harness ---------------------------------------------------------------

// telemetryHarness wires a runner to a fake VM: a unix socket standing in for
// the VM's v.sock, a mux that routes by vsock port, and a spool to read back.
type telemetryHarness struct {
	t        *testing.T
	dir      string
	spoolDir string
	vSock    string
	router   *vsockRouter
	ctx      context.Context
}

func newTelemetryHarness(t *testing.T) *telemetryHarness {
	t.Helper()
	dir := shortSockDir(t)
	h := &telemetryHarness{
		t:        t,
		dir:      dir,
		spoolDir: filepath.Join(dir, "spool"),
		vSock:    filepath.Join(dir, "v.sock"),
	}
	if err := os.MkdirAll(h.spoolDir, 0o700); err != nil {
		t.Fatalf("mkdir spool: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte(telToken), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h.ctx = ctx

	h.router = newVsockRouter(t, h.vSock, controlPort, proto.TelemetryPort)
	return h
}

// startGuest starts a real guest agent on the control port. The telemetry port
// is served separately, by exactly one of serveRealTelemetry or
// serveFakeTelemetry — two accept loops on one port would race for every
// connection and make the winner a coin toss.
func (h *telemetryHarness) startGuest() *guest.Agent {
	h.t.Helper()
	agent := guest.NewAgent(&guest.BootConfig{
		Schema:          "vmobs.guest_context.v1",
		VMID:            telVMID,
		BootID:          telBootID,
		CapabilityToken: telToken,
		ProtocolVersion: proto.ProtocolVersion,
	}, proto.CapabilityManifest{
		Schema:        "vmobs.guest_capability.v1",
		KernelRelease: "6.1.0-test",
	})
	go agent.ServeControl(h.ctx, h.router.listener(controlPort)) //nolint:errcheck
	return agent
}

// serveRealTelemetry puts the guest agent's own telemetry server on 10001.
func (h *telemetryHarness) serveRealTelemetry(agent *guest.Agent) {
	h.t.Helper()
	go agent.ServeTelemetry(h.ctx, h.router.listener(proto.TelemetryPort)) //nolint:errcheck
}

// serveFakeTelemetry puts a hand-written peer on the telemetry port. The fakes
// exist to send what a correct guest never would; they are peer implementations
// of the wire contract, not stand-ins for anything the runner owns.
func (h *telemetryHarness) serveFakeTelemetry(handle func(net.Conn)) {
	h.t.Helper()
	ln := h.router.listener(proto.TelemetryPort)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				handle(conn)
			}()
		}
	}()
}

// run starts runner.Run in the background. The VMM is reported alive for the
// whole test: this exercise is about the telemetry connection, not about exit
// detection, which the linux integration test covers with a real process.
func (h *telemetryHarness) run() {
	h.t.Helper()
	cfg := runner.Config{
		VMID:         telVMID,
		BootID:       telBootID,
		InstanceID:   telInstance,
		UDSPath:      h.vSock,
		TokenFile:    filepath.Join(h.dir, "token"),
		SpoolDir:     h.spoolDir,
		StateFile:    filepath.Join(h.dir, "runner-state.json"),
		CtlSock:      filepath.Join(h.dir, "runner.sock"),
		VMMPID:       os.Getpid(),
		VMMStartTime: "1",
		PingInterval: 500 * time.Millisecond,
		PIDAlive:     func(int, string) bool { return true },
	}
	ctx, cancel := context.WithCancel(h.ctx)
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx, cfg) }()
	h.t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			h.t.Error("runner.Run did not return within 5s of cancellation")
		}
	})
}

// waitForKind polls the spool until an envelope of this kind appears.
func (h *telemetryHarness) waitForKind(kind string) *events.Envelope {
	h.t.Helper()
	return h.pollForKind(kind, telSpoolWait)
}

func (h *telemetryHarness) pollForKind(kind string, timeout time.Duration) *events.Envelope {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		for _, env := range h.spooled() {
			if env.Kind == kind {
				return env
			}
		}
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (h *telemetryHarness) countKind(kind string) int {
	h.t.Helper()
	n := 0
	for _, env := range h.spooled() {
		if env.Kind == kind {
			n++
		}
	}
	return n
}

// spooled reads every envelope written so far. Segments are read mid-run, which
// works because Append durably lands each record before it returns.
func (h *telemetryHarness) spooled() []*events.Envelope {
	h.t.Helper()
	segs, _ := filepath.Glob(filepath.Join(h.spoolDir, "seg-*.vmsp"))
	var out []*events.Envelope
	for _, seg := range segs {
		iter, err := spool.ReadSegment(seg)
		if err != nil {
			continue
		}
		for {
			env, err := iter.Next()
			if err != nil {
				break
			}
			out = append(out, env)
		}
		iter.Close()
	}
	return out
}

// --- fake guest helpers ----------------------------------------------------

func readHello(conn net.Conn) (proto.Hello, error) {
	env, err := proto.ReadControl(conn)
	if err != nil {
		return proto.Hello{}, err
	}
	if env.Kind != proto.KindHello {
		return proto.Hello{}, fmt.Errorf("expected hello, got %q", env.Kind)
	}
	var hello proto.Hello
	if err := json.Unmarshal(env.Data, &hello); err != nil {
		return proto.Hello{}, err
	}
	return hello, nil
}

// acceptHello answers the way a correct guest does: echo the id the host sent,
// and name the sequence space these pushes are counted in.
func acceptHello(conn net.Conn, hello proto.Hello) error {
	return proto.WriteControl(conn, proto.KindHelloAck, proto.HelloAck{
		Accepted:            true,
		TelemetryInstanceID: hello.SourceInstance,
		TelemetryEpoch:      "fake-epoch",
	})
}

func writeFakePush(conn net.Conn, seq, kind, data string) error {
	return proto.WriteControl(conn, proto.KindTelemetryPush, proto.TelemetryPush{
		Seq:              seq,
		Kind:             kind,
		GuestWallAt:      time.Now().UTC().Format(time.RFC3339Nano),
		GuestMonotonicNS: "1000",
		Data:             json.RawMessage(data),
	})
}
