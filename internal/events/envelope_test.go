// ABOUTME: Tests the envelope against the canonical schema and example in docs/,
// ABOUTME: plus validation rejections and strict parsing of unknown fields.
package events_test

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/2389-research/observatory/internal/events"
)

func compileEnvelopeSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	sch, err := c.Compile("../../docs/schemas/event-envelope.schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return sch
}

func validEnvelope() *events.Envelope {
	vm := "1ed7fdbf-7007-43f3-b5b2-8071e96b2df5"
	boot := "10e6210d-d21f-4f8d-8c69-5370f1e6d44f"
	return &events.Envelope{
		SchemaVersion:    1,
		VMID:             &vm,
		BootID:           &boot,
		SourceInstanceID: "190be15a-9470-40c6-b7df-c1b541a8e005",
		SourceSeq:        "918",
		Kind:             "fs.modify",
		Provenance:       events.GuestReported,
		Sensor:           "fanotify",
		HostReceivedAt:   events.Timestamp{Time: time.Date(2026, 8, 30, 20, 0, 0, 0, time.UTC)},
		Quality: events.Quality{
			PathResolution: events.PathExactAtCapture,
			Attribution:    events.AttributionExact,
		},
		Data: map[string]any{"path_display": "/workspace/server.py"},
	}
}

func TestExampleEventParsesValidatesAndRoundTrips(t *testing.T) {
	raw, err := os.ReadFile("../../docs/examples/event.json")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	env, err := events.Parse(raw)
	if err != nil {
		t.Fatalf("parse example: %v", err)
	}
	if err := env.Validate(); err != nil {
		t.Fatalf("validate example: %v", err)
	}
	if env.EventID == nil || *env.EventID != "18442" {
		t.Errorf("event_id = %v, want 18442", env.EventID)
	}
	if env.VMID == nil || *env.VMID != "1ed7fdbf-7007-43f3-b5b2-8071e96b2df5" {
		t.Errorf("vm_id = %v", env.VMID)
	}
	if env.SourceSeq != "918" || env.Kind != "fs.modify" || env.Provenance != events.GuestReported {
		t.Errorf("core fields wrong: %+v", env)
	}
	if env.RunID != nil {
		t.Errorf("run_id should parse null as nil, got %v", *env.RunID)
	}
	if env.Quality.PathResolution != events.PathExactAtCapture || env.Quality.Truncated {
		t.Errorf("quality wrong: %+v", env.Quality)
	}

	out, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var inst any
	if err := json.Unmarshal(out, &inst); err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	if err := compileEnvelopeSchema(t).Validate(inst); err != nil {
		t.Errorf("marshaled envelope violates schema: %v", err)
	}
}

func TestMarshaledEnvelopeSatisfiesSchema(t *testing.T) {
	out, err := json.Marshal(validEnvelope())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var inst any
	if err := json.Unmarshal(out, &inst); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := compileEnvelopeSchema(t).Validate(inst); err != nil {
		t.Errorf("envelope violates schema: %v\njson: %s", err, out)
	}
}

func TestTimestampFormatMicrosecondsUTC(t *testing.T) {
	ts := events.Timestamp{Time: time.Date(2026, 8, 30, 20, 0, 0, 0, time.UTC)}
	b, err := json.Marshal(ts)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"2026-08-30T20:00:00.000000Z"` {
		t.Errorf("timestamp = %s", b)
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	raw, _ := json.Marshal(validEnvelope())
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["surprise"] = true
	tainted, _ := json.Marshal(m)
	if _, err := events.Parse(tainted); err == nil {
		t.Error("Parse accepted an undeclared envelope property")
	}
}

func TestValidateRejections(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*events.Envelope)
	}{
		{"wrong schema version", func(e *events.Envelope) { e.SchemaVersion = 2 }},
		{"leading-zero seq", func(e *events.Envelope) { e.SourceSeq = "018" }},
		{"empty seq", func(e *events.Envelope) { e.SourceSeq = "" }},
		{"non-decimal seq", func(e *events.Envelope) { e.SourceSeq = "12x" }},
		{"single-segment kind", func(e *events.Envelope) { e.Kind = "modify" }},
		{"uppercase kind", func(e *events.Envelope) { e.Kind = "FS.modify" }},
		{"unknown provenance", func(e *events.Envelope) { e.Provenance = "self_attested" }},
		{"empty sensor", func(e *events.Envelope) { e.Sensor = "" }},
		{"bad source uuid", func(e *events.Envelope) { e.SourceInstanceID = "not-a-uuid" }},
		{"uppercase uuid", func(e *events.Envelope) {
			e.SourceInstanceID = "190BE15A-9470-40C6-B7DF-C1B541A8E005"
		}},
		{"boot without vm", func(e *events.Envelope) { e.VMID = nil }},
		{"bad event id", func(e *events.Envelope) { s := "0042"; e.EventID = &s }},
		{"bad run uuid", func(e *events.Envelope) { s := "nope"; e.RunID = &s }},
		{"duplicate related ids", func(e *events.Envelope) { e.RelatedEventIDs = []string{"7", "7"} }},
		{"bad quality path_resolution", func(e *events.Envelope) { e.Quality.PathResolution = "guessed" }},
		{"bad quality attribution", func(e *events.Envelope) { e.Quality.Attribution = "vibes" }},
		{"nil data", func(e *events.Envelope) { e.Data = nil }},
		{"zero received time", func(e *events.Envelope) { e.HostReceivedAt = events.Timestamp{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := validEnvelope()
			tc.mutate(env)
			if err := env.Validate(); err == nil {
				t.Errorf("Validate accepted %s", tc.name)
			}
		})
	}
}

func TestValidateAcceptsPrebootAndHostWideScopes(t *testing.T) {
	env := validEnvelope()
	env.BootID = nil // preboot: vm set, boot null
	if err := env.Validate(); err != nil {
		t.Errorf("preboot scope rejected: %v", err)
	}
	env = validEnvelope()
	env.VMID, env.BootID = nil, nil // host-wide
	env.Kind = "telemetry.loss"
	env.Provenance = events.HostObserved
	env.Sensor = "ingress"
	if err := env.Validate(); err != nil {
		t.Errorf("host-wide scope rejected: %v", err)
	}
}
