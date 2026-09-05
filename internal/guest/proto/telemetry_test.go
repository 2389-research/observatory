// ABOUTME: Tests the guest telemetry push frame: the port, the strict
// ABOUTME: allow-list on its top-level keys, and its bounded payload.
package proto_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/2389-research/observatory-v2/internal/guest/proto"
)

func TestTelemetryPortIsTheReservedOne(t *testing.T) {
	if proto.TelemetryPort != 10001 {
		t.Fatalf("telemetry port = %d, want 10001", proto.TelemetryPort)
	}
}

func TestTelemetryPushRoundTrips(t *testing.T) {
	var buf bytes.Buffer
	want := proto.TelemetryPush{
		Seq:              "41",
		Kind:             "guest.sensor_health",
		GuestWallAt:      "2026-09-05T00:00:00Z",
		GuestMonotonicNS: "9007199254740993",
		Data:             json.RawMessage(`{"sensors":[]}`),
	}
	if err := proto.WriteControl(&buf, proto.KindTelemetryPush, want); err != nil {
		t.Fatalf("write: %v", err)
	}
	env, err := proto.ReadControl(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if env.Kind != proto.KindTelemetryPush {
		t.Fatalf("kind = %q, want %q", env.Kind, proto.KindTelemetryPush)
	}
	got, err := proto.DecodeTelemetryPush(env.Data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Seq != want.Seq || got.Kind != want.Kind {
		t.Errorf("seq/kind = %q/%q, want %q/%q", got.Seq, got.Kind, want.Seq, want.Kind)
	}
	if got.GuestMonotonicNS != want.GuestMonotonicNS {
		t.Errorf("guest_monotonic_ns = %q, want %q — a counter past 2^53 must survive as a string",
			got.GuestMonotonicNS, want.GuestMonotonicNS)
	}
	if string(got.Data) != string(want.Data) {
		t.Errorf("data = %s, want %s", got.Data, want.Data)
	}
}

// A guest does not get to state what the host assigns. The frame permits an
// allow-list of keys, so a field the envelope grows later is refused by
// default rather than silently accepted.
func TestTelemetryPushRefusesKeysTheHostAssigns(t *testing.T) {
	for _, key := range []string{
		"provenance", "source_instance_id", "source_seq", "host_received_at",
		"event_id", "vm_id", "boot_id", "sensor", "quality", "schema_version",
		"host_boot_id", "host_monotonic_ns", "related_event_ids",
	} {
		raw := json.RawMessage(`{"seq":"1","kind":"guest.sensor_health","data":{},"` + key + `":"x"}`)
		_, err := proto.DecodeTelemetryPush(raw)
		if err == nil {
			t.Errorf("key %q was accepted; the host assigns it", key)
			continue
		}
		if !strings.Contains(err.Error(), key) {
			t.Errorf("key %q rejected with %q, which does not name the offending key", key, err)
		}
	}
}

func TestTelemetryPushRequiresSeqAndKind(t *testing.T) {
	for name, raw := range map[string]string{
		"no seq":                      `{"kind":"guest.sensor_health","data":{}}`,
		"no kind":                     `{"seq":"1","data":{}}`,
		"seq is not a decimal string": `{"seq":"0x1f","kind":"guest.sensor_health","data":{}}`,
		"seq is a number":             `{"seq":1,"kind":"guest.sensor_health","data":{}}`,
	} {
		if _, err := proto.DecodeTelemetryPush(json.RawMessage(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTelemetryPushPayloadIsBounded(t *testing.T) {
	big := strings.Repeat("x", proto.MaxTelemetryPayload)
	raw := json.RawMessage(`{"seq":"1","kind":"guest.sensor_health","data":{"pad":"` + big + `"}}`)
	if _, err := proto.DecodeTelemetryPush(raw); err == nil {
		t.Fatalf("a %d-byte frame was accepted; the cap is %d", len(raw), proto.MaxTelemetryPayload)
	}
}
