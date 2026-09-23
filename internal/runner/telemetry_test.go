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
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/events"
	"github.com/2389-research/observatory/internal/guest"
	"github.com/2389-research/observatory/internal/guest/proto"
	"github.com/2389-research/observatory/internal/runner"
	"github.com/2389-research/observatory/internal/spool"
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
	// fakeEpoch is what a well-behaved fake guest names its sequence space.
	// It has to satisfy guestEpochPattern, which is the point of naming it once.
	fakeEpoch = "fake-epoch"
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

// TestRunnerNeverAcksWhatItCouldNotSpool pins the ordering that gives an ack
// its meaning. The ack tells the guest the host holds the event durably, and
// the guest drops it on that word alone, so the ack can only follow an Append
// that returned. Acknowledge first and a refused push is lost by both sides at
// once: the guest released it, the host never wrote it, and nothing counted it.
func TestRunnerNeverAcksWhatItCouldNotSpool(t *testing.T) {
	h := newTelemetryHarness(t)
	h.startGuest()

	// What the guest heard back after the push the runner cannot spool.
	// Buffered, and written by the first connection only, so a redial cannot
	// overwrite the answer the test is waiting on.
	afterBadPush := make(chan string, 1)
	var served atomic.Int32
	h.serveFakeTelemetry(func(conn net.Conn) {
		hello, err := readHello(conn)
		if err != nil {
			return
		}
		_ = acceptHello(conn, hello)
		if served.Add(1) != 1 {
			io.Copy(io.Discard, conn) //nolint:errcheck
			return
		}

		// A push the runner can spool, first, so the ack path is proven live on
		// this connection before the interesting one goes out. Without it, "no
		// ack arrived" would also be what a dead connection looks like.
		if err := writeFakePush(conn, "1", "guest.sensor_health", `{"agent":{}}`); err != nil {
			return
		}
		env, err := proto.ReadControl(conn)
		if err != nil || env.Kind != proto.KindTelemetryAck {
			afterBadPush <- fmt.Sprintf("the spoolable push went unacknowledged (%v, %v)", env.Kind, err)
			return
		}

		// Now one the runner cannot write: data is a number where the envelope
		// needs an object. The wire contract passes it — that layer never reads
		// the payload — so the refusal happens where the append would have.
		if err := writeFakePush(conn, "2", "guest.sensor_health", `5`); err != nil {
			return
		}
		next, err := proto.ReadControl(conn)
		if err != nil {
			afterBadPush <- "closed"
			return
		}
		afterBadPush <- next.Kind
	})

	h.run()

	select {
	case got := <-afterBadPush:
		if got != "closed" {
			t.Errorf("after a push it could not spool the runner sent %q; the guest would "+
				"release an event no host holds", got)
		}
	case <-time.After(telSpoolWait):
		t.Fatal("the fake guest never got as far as the unspoolable push")
	}

	if n := h.countKind("guest.sensor_health"); n != 1 {
		t.Errorf("spooled %d events, want the 1 well-formed one", n)
	}
}

// TestRunnerRecordsLossAfterSpoolRecovers follows one full outage. A full spool
// refuses a push, the runner withholds the ack, and the guest resends once room
// returns. The resend succeeds, and the spool says what it refused in between:
// a telemetry.loss record written ahead of the resent event, so the gap is
// explicit rather than invisible.
func TestRunnerRecordsLossAfterSpoolRecovers(t *testing.T) {
	h := newTelemetryHarness(t)
	h.startGuest()

	// What each connection saw, reported once. Buffered, so a fake guest never
	// blocks on a test that has stopped listening.
	firstConn := make(chan string, 1)
	resent := make(chan string, 1)
	// Closed once the first connection is done with the ballast, so the resend
	// never races the removal that gives the spool its room back.
	ballastGone := make(chan struct{})
	ballast := filepath.Join(h.spoolDir, "ballast.vmsp")
	seq2Push := proto.TelemetryPush{
		Seq:              "2",
		Kind:             "guest.sensor_health",
		GuestWallAt:      time.Now().UTC().Format(time.RFC3339Nano),
		GuestMonotonicNS: "1000",
		Data:             json.RawMessage(`{"agent":{}}`),
	}
	var served atomic.Int32
	h.serveFakeTelemetry(func(conn net.Conn) {
		hello, err := readHello(conn)
		if err != nil {
			return
		}
		_ = acceptHello(conn, hello)
		switch served.Add(1) {
		case 1:
			defer close(ballastGone)
			firstConn <- refuseOnFullSpool(conn, ballast, seq2Push)
		case 2:
			<-ballastGone
			if err := writeFakePush(conn, "2", "guest.sensor_health", `{"agent":{}}`); err != nil {
				resent <- fmt.Sprintf("resend seq 2: %v", err)
				return
			}
			env, err := proto.ReadControl(conn)
			if err != nil || env.Kind != proto.KindTelemetryAck {
				resent <- fmt.Sprintf("the resent seq 2 went unacknowledged (%v, %v)", env.Kind, err)
				return
			}
			var ack proto.TelemetryAck
			if err := json.Unmarshal(env.Data, &ack); err != nil {
				resent <- fmt.Sprintf("unmarshal ack: %v", err)
				return
			}
			resent <- ack.ThroughSeq
			io.Copy(io.Discard, conn) //nolint:errcheck
		default:
			io.Copy(io.Discard, conn) //nolint:errcheck
		}
	})

	h.run()

	select {
	case got := <-firstConn:
		if got != "closed" {
			t.Fatalf("connection 1: %s", got)
		}
	case <-time.After(telSpoolWait):
		t.Fatal("the fake guest never got as far as the push the full spool refuses")
	}
	select {
	case got := <-resent:
		if got != "2" {
			t.Fatalf("connection 2: %s", got)
		}
	case <-time.After(telSpoolWait):
		t.Fatal("the runner never took the resent push")
	}

	// The ack for the resend follows its Append, so the spool already holds
	// everything this reads.
	lossAt, resentAt := -1, -1
	var loss *events.Envelope
	for i, env := range h.spooled() {
		if env.Kind == "telemetry.loss" && loss == nil {
			loss, lossAt = env, i
		}
		if env.Kind == "guest.sensor_health" && env.Provenance == events.GuestReported && env.SourceSeq == "2" {
			resentAt = i
		}
	}
	if loss == nil {
		t.Fatal("no telemetry.loss reached the spool; the refused push left no trace")
	}
	if resentAt < 0 {
		t.Fatal("the resent seq 2 is not in the spool")
	}
	if lossAt > resentAt {
		t.Errorf("telemetry.loss is record %d, after the resent seq 2 at %d; the loss must come first", lossAt, resentAt)
	}

	if loss.Provenance != events.HostObserved {
		t.Errorf("provenance: got %q, want %q", loss.Provenance, events.HostObserved)
	}
	if loss.Sensor != "runner" {
		t.Errorf("sensor: got %q, want %q", loss.Sensor, "runner")
	}
	if loss.SourceInstanceID != telInstance {
		t.Errorf("source_instance_id: got %q, want the runner's %q", loss.SourceInstanceID, telInstance)
	}
	if loss.VMID == nil || *loss.VMID != telVMID {
		t.Errorf("vm_id: got %v, want %q", loss.VMID, telVMID)
	}
	if loss.BootID == nil || *loss.BootID != telBootID {
		t.Errorf("boot_id: got %v, want %q", loss.BootID, telBootID)
	}
	if err := loss.Validate(); err != nil {
		t.Errorf("telemetry.loss does not validate: %v", err)
	}
	refused, _ := loss.Data["guest_pushes_refused"].(string)
	if n, err := strconv.ParseUint(refused, 10, 64); err != nil || n < 1 {
		t.Errorf("guest_pushes_refused: got %q, want a decimal string of at least 1", refused)
	}
	if got := loss.Data["guest_events_lost"]; got != "unknown" {
		t.Errorf("guest_events_lost: got %v, want %q", got, "unknown")
	}
	if cause, _ := loss.Data["cause"].(string); !strings.Contains(cause, "spool full") {
		t.Errorf("cause: got %q, want it to name the full spool", cause)
	}
}

// refuseOnFullSpool drives the first connection of an outage: one push the
// runner acknowledges, then a sparse ballast that puts the spool over its
// default quota, then push (the caller's seq 2) which the runner must refuse
// by closing the connection. It removes the ballast before it returns and
// reports "closed" when every step went as planned, or what went wrong
// instead. It takes push as a value, sent with proto.WriteControl, so a
// caller that resends it later on a second connection sends the identical
// bytes rather than a fresh push restamped by writeFakePush.
func refuseOnFullSpool(conn net.Conn, ballast string, push proto.TelemetryPush) string {
	if err := writeFakePush(conn, "1", "guest.sensor_health", `{"agent":{}}`); err != nil {
		return fmt.Sprintf("push seq 1: %v", err)
	}
	if env, err := proto.ReadControl(conn); err != nil || env.Kind != proto.KindTelemetryAck {
		return fmt.Sprintf("seq 1 went unacknowledged (%v, %v)", env.Kind, err)
	}

	f, err := os.Create(ballast)
	if err != nil {
		return fmt.Sprintf("create ballast: %v", err)
	}
	truncErr := f.Truncate(512 << 20)
	closeErr := f.Close()
	defer os.Remove(ballast)
	if truncErr != nil || closeErr != nil {
		return fmt.Sprintf("size ballast: %v, %v", truncErr, closeErr)
	}

	if err := proto.WriteControl(conn, proto.KindTelemetryPush, push); err != nil {
		return fmt.Sprintf("push seq 2: %v", err)
	}
	if env, err := proto.ReadControl(conn); err == nil {
		return fmt.Sprintf("the runner answered %q to a push the full spool refused", env.Kind)
	}
	if err := os.Remove(ballast); err != nil {
		return fmt.Sprintf("remove ballast: %v", err)
	}
	return "closed"
}

// TestRunnerResendReusesTheRefusedEnvelope follows the same outage as
// TestRunnerRecordsLossAfterSpoolRecovers, then asks the question that one
// does not: does the resend get back the same envelope? A frame the spool
// refused can still reach the store before its segment is trimmed, so a
// resend the runner re-stamps with a new host_received_at would read at the
// store as a different payload under the same (source_instance_id,
// source_seq) — a conflict the store cannot resolve. The guest's ring stamps
// an event once, at push time, so its resend is byte-identical on the wire;
// this pins that the runner's spooled envelope is identical too.
func TestRunnerResendReusesTheRefusedEnvelope(t *testing.T) {
	h := newTelemetryHarness(t)
	h.startGuest()

	// Built once and sent both times: writeFakePush restamps GuestWallAt on
	// every call, which would make every resend a "different" push and defeat
	// the test before it starts.
	push := proto.TelemetryPush{
		Seq:              "2",
		Kind:             "guest.sensor_health",
		GuestWallAt:      time.Now().UTC().Format(time.RFC3339Nano),
		GuestMonotonicNS: "1000",
		Data:             json.RawMessage(`{"agent":{}}`),
	}

	firstConn := make(chan string, 1)
	resent := make(chan string, 1)
	// Closed once connection 1 has recorded t2, so connection 2 never reads t2
	// before it is set. That close-then-receive pair is the happens-before
	// edge that makes reading t2 from the other goroutine race-free.
	ballastGone := make(chan struct{})
	ballast := filepath.Join(h.spoolDir, "ballast.vmsp")
	var t2 time.Time
	var served atomic.Int32
	h.serveFakeTelemetry(func(conn net.Conn) {
		hello, err := readHello(conn)
		if err != nil {
			return
		}
		_ = acceptHello(conn, hello)
		switch served.Add(1) {
		case 1:
			result := refuseOnFullSpool(conn, ballast, push)
			t2 = time.Now()
			close(ballastGone)
			firstConn <- result
		case 2:
			<-ballastGone
			// The spool truncates host_received_at to microseconds, so the
			// comparison against t2 needs a full second of headroom or
			// truncation could flip a genuinely-later timestamp to read as
			// earlier.
			if wait := time.Second - time.Since(t2); wait > 0 {
				time.Sleep(wait)
			}
			if err := proto.WriteControl(conn, proto.KindTelemetryPush, push); err != nil {
				resent <- fmt.Sprintf("resend seq 2: %v", err)
				return
			}
			env, err := proto.ReadControl(conn)
			if err != nil || env.Kind != proto.KindTelemetryAck {
				resent <- fmt.Sprintf("the resent seq 2 went unacknowledged (%v, %v)", env.Kind, err)
				return
			}
			var ack proto.TelemetryAck
			if err := json.Unmarshal(env.Data, &ack); err != nil {
				resent <- fmt.Sprintf("unmarshal ack: %v", err)
				return
			}
			resent <- ack.ThroughSeq
			io.Copy(io.Discard, conn) //nolint:errcheck
		default:
			io.Copy(io.Discard, conn) //nolint:errcheck
		}
	})

	h.run()

	select {
	case got := <-firstConn:
		if got != "closed" {
			t.Fatalf("connection 1: %s", got)
		}
	case <-time.After(telSpoolWait):
		t.Fatal("the fake guest never got as far as the push the full spool refuses")
	}
	select {
	case got := <-resent:
		if got != "2" {
			t.Fatalf("connection 2: %s", got)
		}
	case <-time.After(telSpoolWait):
		t.Fatal("the runner never took the resent push")
	}

	lossAt, resentAt := -1, -1
	var loss, resentEnv *events.Envelope
	seq2Count := 0
	for i, env := range h.spooled() {
		if env.Kind == "telemetry.loss" && loss == nil {
			loss, lossAt = env, i
		}
		if env.Kind == "guest.sensor_health" && env.Provenance == events.GuestReported && env.SourceSeq == "2" {
			resentAt, resentEnv = i, env
			seq2Count++
		}
	}
	if loss == nil {
		t.Fatal("no telemetry.loss reached the spool; the refused push left no trace")
	}
	if resentEnv == nil {
		t.Fatal("the resent seq 2 is not in the spool")
	}
	if seq2Count != 1 {
		t.Errorf("seq 2 appears %d times in the spool, want exactly 1", seq2Count)
	}
	if lossAt > resentAt {
		t.Errorf("telemetry.loss is record %d, after the resent seq 2 at %d; the loss must come first", lossAt, resentAt)
	}
	refused, _ := loss.Data["guest_pushes_refused"].(string)
	if n, err := strconv.ParseUint(refused, 10, 64); err != nil || n < 1 {
		t.Errorf("guest_pushes_refused: got %q, want a decimal string of at least 1", refused)
	}

	if !resentEnv.HostReceivedAt.Before(t2) {
		t.Errorf("resent seq 2's host_received_at %s is not before t2 %s; the runner stamped a fresh envelope instead of reusing the one it was refused with",
			resentEnv.HostReceivedAt.Format(time.RFC3339Nano), t2.Format(time.RFC3339Nano))
	}
}

// TestRunnerRefusesAnUnacceptableEpoch covers the guest's only contribution to
// the identity the host assigns. The epoch is opaque, so the runner cannot
// judge whether it is the right one — but it can insist it is a token, and it
// has to: the epoch is folded into a stream id and named in the handshake
// error, and an unbounded string from an untrusted guest belongs in neither.
func TestRunnerRefusesAnUnacceptableEpoch(t *testing.T) {
	h := newTelemetryHarness(t)
	h.startGuest()

	// Connections served, reported as they end. A progress signal, not a
	// ledger: the send never blocks, because a fake guest that outlives the
	// assertions must not hold the harness open.
	conns := make(chan int, 64)
	var served atomic.Int32
	h.serveFakeTelemetry(func(conn net.Conn) {
		n := int(served.Add(1))
		defer func() {
			select {
			case conns <- n:
			default:
			}
		}()
		hello, err := readHello(conn)
		if err != nil {
			return
		}
		epoch := fakeEpoch
		if n == 1 {
			// Spaces and traversal are exactly what the pattern exists to keep
			// out of a derived identity and out of the log line naming it.
			epoch = "../not an epoch"
		}
		if err := proto.WriteControl(conn, proto.KindHelloAck, proto.HelloAck{
			Accepted:            true,
			TelemetryInstanceID: hello.SourceInstance,
			TelemetryEpoch:      epoch,
		}); err != nil {
			return
		}
		if err := writeFakePush(conn, "1", "guest.sensor_health", `{"agent":{}}`); err != nil {
			return
		}
		// One read, so the connection outlives whatever the runner decides
		// about the push rather than racing its own close against the append.
		_, _ = proto.ReadControl(conn)
	})

	h.run()

	// Three connections: the refused one, the accepted one whose push is
	// spooled, and one more whose re-send of seq 1 the dedup absorbs. A stream
	// named from the refused epoch would have produced a second event by then,
	// because it is a different identity with its own sequence space.
	deadline := time.After(telSpoolWait)
	for seen := 0; seen < 3; {
		select {
		case <-conns:
			seen++
		case <-deadline:
			t.Fatalf("only %d telemetry connections in %s", seen, telSpoolWait)
		}
	}

	if n := h.countKind("guest.sensor_health"); n != 1 {
		t.Errorf("spooled %d events, want 1: an epoch the host refused must not name a stream", n)
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
		TelemetryEpoch:      fakeEpoch,
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
