// ABOUTME: Tests for Envelope/Hello/HelloAck/CapabilityManifest encode-decode and WriteControl/ReadControl.
// ABOUTME: Uses real net.Pipe — no test doubles.
package proto

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	env := Envelope{
		V:    ProtocolVersion,
		Kind: KindHello,
		Data: json.RawMessage(`{"protocol_version":1}`),
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Envelope
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.V != ProtocolVersion {
		t.Errorf("V: got %d, want %d", got.V, ProtocolVersion)
	}
	if got.Kind != KindHello {
		t.Errorf("Kind: got %q, want %q", got.Kind, KindHello)
	}
}

func TestEnvelopeJSONFieldNames(t *testing.T) {
	env := Envelope{V: 1, Kind: "hello", Data: json.RawMessage(`{}`)}
	b, _ := json.Marshal(env)
	s := string(b)
	if !strings.Contains(s, `"v":`) {
		t.Errorf("want field 'v', got: %s", s)
	}
	if !strings.Contains(s, `"kind":`) {
		t.Errorf("want field 'kind', got: %s", s)
	}
	if !strings.Contains(s, `"data":`) {
		t.Errorf("want field 'data', got: %s", s)
	}
}

func TestHelloJSONSnakeCase(t *testing.T) {
	h := Hello{
		ProtocolVersion: 1,
		VMID:            "vm-1",
		BootID:          "boot-1",
		SourceInstance:  "inst-1",
		ResumeCursor:    "0",
		AuthProof:       "tok",
	}
	b, _ := json.Marshal(h)
	s := string(b)
	for _, want := range []string{
		`"protocol_version"`, `"vm_id"`, `"boot_id"`,
		`"source_instance"`, `"resume_cursor"`, `"auth_proof"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("want field %s in JSON, got: %s", want, s)
		}
	}
}

func TestHelloResumeCursorIsString(t *testing.T) {
	h := Hello{ResumeCursor: "0"}
	b, _ := json.Marshal(h)
	// "0" must appear as a JSON string, not a number.
	if !strings.Contains(string(b), `"resume_cursor":"0"`) {
		t.Errorf("resume_cursor must be a JSON string, got: %s", b)
	}
}

func TestHelloAckRoundTrip(t *testing.T) {
	ack := HelloAck{Accepted: true, Reason: ""}
	b, _ := json.Marshal(ack)
	var got HelloAck
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.Accepted {
		t.Errorf("Accepted: got %v, want true", got.Accepted)
	}
}

func TestCapabilityManifestSchema(t *testing.T) {
	cm := CapabilityManifest{
		Schema:        "vmobs.guest_capability.v1",
		KernelRelease: "6.8.0",
		Features: []Feature{
			{ID: "btf", Present: true, Evidence: "ok"},
		},
	}
	b, _ := json.Marshal(cm)
	var got CapabilityManifest
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Schema != "vmobs.guest_capability.v1" {
		t.Errorf("Schema: got %q, want vmobs.guest_capability.v1", got.Schema)
	}
	if len(got.Features) != 1 || got.Features[0].ID != "btf" {
		t.Errorf("Features: unexpected: %+v", got.Features)
	}
}

func TestWriteReadControl(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	h := Hello{
		ProtocolVersion: ProtocolVersion,
		VMID:            "vm-abc",
		BootID:          "boot-xyz",
		SourceInstance:  "inst-1",
		ResumeCursor:    "0",
		AuthProof:       "secret",
	}

	done := make(chan error, 1)
	go func() {
		done <- WriteControl(c1, KindHello, h)
		c1.Close()
	}()

	env, err := ReadControl(c2)
	if err != nil {
		t.Fatalf("ReadControl: %v", err)
	}
	if env.Kind != KindHello {
		t.Errorf("Kind: got %q, want %q", env.Kind, KindHello)
	}
	if env.V != ProtocolVersion {
		t.Errorf("V: got %d, want %d", env.V, ProtocolVersion)
	}
	var got Hello
	if err := json.Unmarshal(env.Data, &got); err != nil {
		t.Fatalf("unmarshal Hello: %v", err)
	}
	if got.VMID != "vm-abc" {
		t.Errorf("VMID: got %q, want vm-abc", got.VMID)
	}
	if err := <-done; err != nil {
		t.Errorf("WriteControl: %v", err)
	}
}

func TestKindConstants(t *testing.T) {
	// Verify all expected kind constants are defined with the right string values.
	cases := map[string]string{
		"hello":            KindHello,
		"hello_ack":        KindHelloAck,
		"get_capabilities": KindGetCapabilities,
		"capabilities":     KindCapabilities,
		"ping":             KindPing,
		"pong":             KindPong,
		"error":            KindError,
	}
	for want, got := range cases {
		if want != got {
			t.Errorf("kind constant: want %q, got %q", want, got)
		}
	}
}
