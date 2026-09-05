// ABOUTME: The guest telemetry push frame (vsock 10001): what the guest may
// ABOUTME: state about an event, which is strictly less than an envelope holds.
package proto

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/2389-research/observatory-v2/internal/events"
)

// TelemetryPort is the guest vsock port carrying sensor telemetry, pushed guest
// to host. It gets its own port for the reason the session stream got 10002
// (terminal.go): the control channel is strictly request/response, and a sensor
// firehose sharing it would starve the ping cycle harder than a terminal does.
const TelemetryPort = 10001

// KindTelemetryPush is the control-message kind carrying one pushed event.
const KindTelemetryPush = "telemetry.push"

// MaxTelemetryPayload bounds one encoded push frame. Well under the 1 MiB
// control-frame ceiling ReadFrame enforces: a heartbeat is small, and a sensor
// that needs more than this should report a truncation rather than a bigger
// frame.
const MaxTelemetryPayload = 64 << 10

// TelemetryPush is one event the guest offers the host. It carries what the
// guest is the authority on — its own sequence, the kind it observed, its own
// clocks, and the payload — and nothing else. Provenance, the stream identity,
// the host clock and the quality block are the host's to assign, and a guest
// cannot smuggle one in: DecodeTelemetryPush admits these keys and no others.
type TelemetryPush struct {
	// Seq is the guest's monotonic counter within the stream identity the host
	// assigned at handshake. A decimal string: it can outlive 2^53.
	Seq string `json:"seq"`
	// Kind must be registered in internal/events, and registered as
	// guest_reported. The runner checks; the guest does not get the last word.
	Kind string `json:"kind"`
	// GuestWallAt and GuestMonotonicNS are the guest's own clocks, carried
	// through as reported. The host never treats them as authoritative — that
	// is what host_received_at is for.
	GuestWallAt      string `json:"guest_wall_at,omitempty"`
	GuestMonotonicNS string `json:"guest_monotonic_ns,omitempty"`
	// Data is the kind's payload, unread at this layer.
	Data json.RawMessage `json:"data"`
}

// telemetryPushKeys is an allow-list, deliberately. A deny-list naming the
// fields the host assigns would silently start permitting whichever field the
// envelope grows next; an allow-list refuses it until someone decides otherwise.
var telemetryPushKeys = map[string]struct{}{
	"seq":                {},
	"kind":               {},
	"guest_wall_at":      {},
	"guest_monotonic_ns": {},
	"data":               {},
}

// DecodeTelemetryPush parses one push frame from an untrusted guest. It bounds
// the input, refuses any key outside the allow-list, and validates the fields
// the guest owns. It does not check that Kind is registered — that needs the
// registry, and the runner owns that call.
func DecodeTelemetryPush(raw json.RawMessage) (TelemetryPush, error) {
	var zero TelemetryPush
	if len(raw) > MaxTelemetryPayload {
		return zero, fmt.Errorf("telemetry push is %d bytes, over the %d-byte limit", len(raw), MaxTelemetryPayload)
	}
	var keyed map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keyed); err != nil {
		return zero, fmt.Errorf("telemetry push is not an object: %w", err)
	}
	for k := range keyed {
		if _, ok := telemetryPushKeys[k]; !ok {
			return zero, fmt.Errorf("telemetry push carries %q, which the host assigns", k)
		}
	}

	var push TelemetryPush
	if err := json.Unmarshal(raw, &push); err != nil {
		return zero, fmt.Errorf("unmarshal telemetry push: %w", err)
	}
	if !events.DecimalString(push.Seq) {
		return zero, fmt.Errorf("telemetry push seq %q is not a decimal string", push.Seq)
	}
	if push.Kind == "" {
		return zero, fmt.Errorf("telemetry push names no kind")
	}
	if push.GuestMonotonicNS != "" && !events.DecimalString(push.GuestMonotonicNS) {
		return zero, fmt.Errorf("telemetry push guest_monotonic_ns %q is not a decimal string", push.GuestMonotonicNS)
	}
	if push.GuestWallAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, push.GuestWallAt); err != nil {
			return zero, fmt.Errorf("telemetry push guest_wall_at %q is not RFC3339: %w", push.GuestWallAt, err)
		}
	}
	return push, nil
}

// KindTelemetryAck is the host's cumulative acknowledgement, the only frame
// travelling host to guest on this port after the handshake.
const KindTelemetryAck = "telemetry.ack"

// TelemetryAck reports the highest sequence the host holds durably. It is
// cumulative: acking 41 releases 1 through 41. The guest keeps everything past
// it, so a host that stops acking makes the guest's bounded ring drop — and
// count — rather than losing events nobody counted.
type TelemetryAck struct {
	ThroughSeq string `json:"through_seq"`
}
