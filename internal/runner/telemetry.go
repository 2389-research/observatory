// ABOUTME: The runner's telemetry client (vsock 10001): it names the guest's stream,
// ABOUTME: stamps guest_reported envelopes, spools them, and acknowledges what it stored.
package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/2389-research/observatory/internal/events"
	"github.com/2389-research/observatory/internal/guest/proto"
)

// telemetrySensor names the producer on every envelope this loop spools. The
// guest agent observed it; the runner only carried and stamped it.
const telemetrySensor = "guestd"

// telemetryStreamNamespace is a fixed, arbitrary UUID: the namespace for
// deriving a telemetry stream's identity. Fixed so the same runner instance and
// the same guest epoch always name the same stream, which is what lets a
// reconnect resume rather than fork.
var telemetryStreamNamespace = uuid.MustParse("6f5c2a1e-9b3d-4f8a-8c21-7d0e4a5b6c90")

// guestEpochPattern bounds what the guest may contribute to a stream identity.
// The epoch is opaque, so its only requirements are that it is short and that
// it cannot smuggle anything into a log line or a path.
var guestEpochPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// telemetryStreamID derives the stream identity from the runner's instance and
// the guest's epoch. The runner alone decides the identity — the guest hands
// over a token and learns nothing about what came out of it — which is what
// makes source_instance_id a host claim rather than a guest claim.
func telemetryStreamID(instanceID, guestEpoch string) string {
	return uuid.NewSHA1(telemetryStreamNamespace, []byte(instanceID+"\x00"+guestEpoch)).String()
}

// telemetryLoop dials the guest's telemetry port and keeps it dialed for the
// runner's lifetime. It is deliberately independent of the supervision loop: a
// guest that stops reporting telemetry is still a guest the host must be able
// to stop, and a control channel that drops must not throw away queued
// telemetry the guest is still holding.
func (r *runner) telemetryLoop(ctx context.Context) {
	// spooled records the highest sequence already written for each stream, so
	// the events a guest re-sends after an unacknowledged connection are
	// acknowledged again without being spooled twice. Owned by this goroutine.
	spooled := make(map[string]uint64)
	backoff := 1 * time.Second

	for {
		if ctx.Err() != nil {
			return
		}
		dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		conn, err := proto.DialHostVsock(dialCtx, r.cfg.UDSPath, proto.TelemetryPort)
		cancel()
		progressed := false
		if err == nil {
			progressed = r.serveTelemetry(ctx, conn, spooled)
			conn.Close()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		// Only a connection that carried a frame resets the backoff. A guest
		// that fails the handshake, or that dies on the same frame every time,
		// would otherwise be redialed once a second forever — and each attempt
		// spools the runner's complaint, so the loop would rotate the VM's real
		// history out of a bounded spool to make room for its own noise.
		if progressed {
			backoff = 1 * time.Second
		} else {
			backoff = clampDouble(backoff, dialMaxInterval)
		}
	}
}

// serveTelemetry handshakes and then reads pushes until the connection or the
// context ends. Every return path is a redial. It reports whether the
// connection carried at least one frame, which is what the dial backoff uses to
// tell a working guest from one it is pointlessly redialing.
func (r *runner) serveTelemetry(ctx context.Context, conn net.Conn, spooled map[string]uint64) bool {
	defer closeOnDone(ctx, conn)()

	streamID, err := r.telemetryHandshake(conn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "runner: telemetry handshake: %v\n", err)
		return false
	}

	progressed := false
	for {
		env, err := proto.ReadControl(conn)
		if err != nil {
			return progressed
		}
		if env.Kind != proto.KindTelemetryPush {
			r.appendTelemetryIntegrityFailure(streamID, "unexpected_frame",
				fmt.Sprintf("expected %s, got %s", proto.KindTelemetryPush, env.Kind))
			return progressed
		}
		push, err := proto.DecodeTelemetryPush(env.Data)
		if err != nil {
			// A frame the contract cannot parse leaves the runner unsure where
			// it is in the stream, so the only honest recovery is a new
			// connection. Contrast the refusal in spoolTelemetryPush, which
			// understands the frame exactly and so can refuse just that one.
			r.appendTelemetryIntegrityFailure(streamID, "malformed_push", err.Error())
			return progressed
		}
		seq, err := r.spoolTelemetryPush(streamID, push, spooled)
		if err != nil {
			fmt.Fprintf(os.Stderr, "runner: telemetry spool: %v\n", err)
			return progressed
		}
		progressed = true
		// The ack goes out only after Append returned, because the spool is the
		// host's durable boundary. Until then the guest is right to keep it.
		if err := proto.WriteControl(conn, proto.KindTelemetryAck, proto.TelemetryAck{ThroughSeq: seq}); err != nil {
			return progressed
		}
	}
}

// telemetryHandshake authenticates the connection and settles whose stream this
// is. It returns the stream identity the runner assigns.
func (r *runner) telemetryHandshake(conn net.Conn) (string, error) {
	hello := proto.Hello{
		ProtocolVersion: proto.ProtocolVersion,
		VMID:            r.cfg.VMID,
		BootID:          r.cfg.BootID,
		SourceInstance:  r.cfg.InstanceID,
		ResumeCursor:    "0",
		AuthProof:       r.token,
	}
	if err := proto.WriteControl(conn, proto.KindHello, hello); err != nil {
		return "", fmt.Errorf("write hello: %w", err)
	}
	ackEnv, err := proto.ReadControl(conn)
	if err != nil {
		return "", fmt.Errorf("read hello_ack: %w", err)
	}
	if ackEnv.Kind != proto.KindHelloAck {
		return "", fmt.Errorf("expected hello_ack, got %q", ackEnv.Kind)
	}
	var ack proto.HelloAck
	if err := json.Unmarshal(ackEnv.Data, &ack); err != nil {
		return "", fmt.Errorf("unmarshal hello_ack: %w", err)
	}
	if !ack.Accepted {
		return "", fmt.Errorf("handshake rejected: %s", ack.Reason)
	}
	// The echo is a confirmation, not a negotiation. A guest that answers with
	// a different id is not counting in the stream the host named, so nothing
	// it sends afterwards can be attributed.
	if ack.TelemetryInstanceID != r.cfg.InstanceID {
		return "", fmt.Errorf("guest echoed instance %q, host sent %q",
			ack.TelemetryInstanceID, r.cfg.InstanceID)
	}
	if !guestEpochPattern.MatchString(ack.TelemetryEpoch) {
		return "", fmt.Errorf("guest epoch %q is not an acceptable token", ack.TelemetryEpoch)
	}
	return telemetryStreamID(r.cfg.InstanceID, ack.TelemetryEpoch), nil
}

// spoolTelemetryPush stamps and writes one guest event, and returns the
// sequence to acknowledge. A sequence already written is acknowledged without
// being written twice: at-least-once delivery means the guest re-sends whatever
// it never saw acknowledged, and those re-sends are expected, not suspicious.
// Whether a re-send actually carries the same bytes is the store's question,
// and it already answers it with a seq/payload conflict.
func (r *runner) spoolTelemetryPush(streamID string, push proto.TelemetryPush, spooled map[string]uint64) (string, error) {
	seq, err := strconv.ParseUint(push.Seq, 10, 64)
	if err != nil {
		return "", fmt.Errorf("telemetry seq %q: %w", push.Seq, err)
	}
	if seq <= spooled[streamID] {
		return push.Seq, nil
	}

	// The registry decides what a guest may report, and the runner asks rather
	// than leaving it to the store. The store's refusal is a hard Append error,
	// and the importer breaks out of a VM's segment on one of those without
	// advancing its cursor — so one refused envelope would wedge that VM's
	// import for good, and every later event in its spool with it. Refusing
	// here costs the one event and records which one.
	info, registered := events.LookupKind(push.Kind)
	if !registered || info.Provenance != events.GuestReported {
		r.refuseTelemetryKind(streamID, push, info, registered)
		// The refusal is durable, so the sequence is decided: acknowledge it,
		// or the guest re-offers the same frame on every reconnect forever.
		spooled[streamID] = seq
		return push.Seq, nil
	}

	var data map[string]any
	if err := json.Unmarshal(push.Data, &data); err != nil {
		return "", fmt.Errorf("telemetry data for seq %s is not an object: %w", push.Seq, err)
	}

	env := r.newGuestEnvelope(streamID, push, data)
	if err := r.sw.Append(env); err != nil {
		return "", fmt.Errorf("append %s seq %s: %w", push.Kind, push.Seq, err)
	}
	spooled[streamID] = seq
	return push.Seq, nil
}

// newGuestEnvelope stamps a guest push. Provenance is the runner's word, not
// the guest's: the guest never sends a provenance field and could not be
// believed if it did. The guest's clocks are carried through as reported —
// they are the guest's claim about the guest, and relabelling them as anything
// firmer would be the lie the provenance model exists to prevent.
func (r *runner) newGuestEnvelope(streamID string, push proto.TelemetryPush, data map[string]any) *events.Envelope {
	vmID := r.cfg.VMID
	bootID := r.cfg.BootID
	env := &events.Envelope{
		SchemaVersion:    1,
		VMID:             &vmID,
		BootID:           &bootID,
		SourceInstanceID: streamID,
		SourceSeq:        push.Seq,
		Kind:             push.Kind,
		Provenance:       events.GuestReported,
		Sensor:           telemetrySensor,
		HostReceivedAt:   events.Timestamp{Time: time.Now().UTC()},
		Quality: events.Quality{
			PathResolution: events.PathNotApplicable,
			Attribution:    events.AttributionNotApplicable,
		},
		Data: data,
	}
	if push.GuestWallAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, push.GuestWallAt); err == nil {
			env.GuestWallAt = &events.Timestamp{Time: t}
		}
	}
	if push.GuestMonotonicNS != "" {
		ns := push.GuestMonotonicNS
		env.GuestMonotonicNS = &ns
	}
	return env
}

// refuseTelemetryKind records one guest event the runner will not spool. Two
// different records, because they are two different facts: a kind nobody
// registered is a version skew or a typo, while a registered host_observed kind
// arriving from a guest is a guest claiming an observation only the host can
// make. Each gets the data shape the store already writes for that kind — one
// shape per kind, whoever emits it.
func (r *runner) refuseTelemetryKind(streamID string, push proto.TelemetryPush, info events.KindInfo, registered bool) {
	if !registered {
		r.appendTelemetryHealth("telemetry.unregistered_kind", map[string]any{
			"kind":               push.Kind,
			"source_instance_id": streamID,
			"source_seq":         push.Seq,
			"observed_by":        telemetrySensor,
		})
		return
	}
	r.appendTelemetryHealth("telemetry.integrity_failure", map[string]any{
		"failure":            "guest_provenance_claim",
		"kind":               push.Kind,
		"registered_as":      string(info.Provenance),
		"source_instance_id": streamID,
		"source_seq":         push.Seq,
		"observed_by":        telemetrySensor,
	})
}

// appendTelemetryIntegrityFailure records a protocol violation: a frame the
// runner could not place in the stream, which is why it also carries the
// transport it arrived on.
func (r *runner) appendTelemetryIntegrityFailure(streamID, failure, detail string) {
	r.appendTelemetryHealth("telemetry.integrity_failure", map[string]any{
		"failure":     failure,
		"detail":      detail,
		"stream":      streamID,
		"transport":   "vsock",
		"port":        proto.TelemetryPort,
		"observed_by": telemetrySensor,
	})
}

// appendTelemetryHealth writes one of the runner's own observations about the
// telemetry channel. It goes on the runner's stream with host_observed
// provenance, never the guest's: the claim is the host's, about what the guest
// did, and it has to survive the guest's stream being the thing in question.
func (r *runner) appendTelemetryHealth(kind string, data map[string]any) {
	if err := r.sw.Append(r.newEnvelope(kind, data)); err != nil {
		fmt.Fprintf(os.Stderr, "runner: spool append (%s): %v\n", kind, err)
	}
}

// closeOnDone closes conn when ctx ends, so a blocked read unblocks. The
// returned func stops the watcher.
func closeOnDone(ctx context.Context, conn net.Conn) func() {
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
