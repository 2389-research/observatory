// ABOUTME: Handshake message types and control-frame encode/decode for the guest channel protocol.
// ABOUTME: Envelope wraps all control messages; Hello/HelloAck/CapabilityManifest are the M0 handshake types.
package proto

import (
	"encoding/json"
	"fmt"
	"io"
)

// ProtocolVersion is the current wire protocol version.
const ProtocolVersion = 1

// Control-message kind strings. Tasks 5 and 8 depend on these exact values.
const (
	KindHello           = "hello"
	KindHelloAck        = "hello_ack"
	KindGetCapabilities = "get_capabilities"
	KindCapabilities    = "capabilities"
	KindPing            = "ping"
	KindPong            = "pong"
	KindError           = "error"
)

// Envelope wraps every control-plane message. V is the protocol version, Kind
// is the message kind, and Data holds the kind-specific payload.
type Envelope struct {
	V    int             `json:"v"`
	Kind string          `json:"kind"`
	Data json.RawMessage `json:"data"`
}

// Hello is the first message sent by the host to the guest after the vsock
// connection is established. AuthProof is the per-boot token the host minted
// into the config device; the guest compares it constant-time.
type Hello struct {
	ProtocolVersion int    `json:"protocol_version"`
	VMID            string `json:"vm_id"`
	BootID          string `json:"boot_id"`
	SourceInstance  string `json:"source_instance"`
	// ResumeCursor is a decimal string. Counters that can exceed JS safe
	// integers are decimal strings in this repo; keep it a string everywhere.
	ResumeCursor string `json:"resume_cursor"`
	AuthProof    string `json:"auth_proof"`
}

// HelloAck is the guest's response to a Hello. If Accepted is false, Reason
// carries a human-readable explanation and the connection is closed.
type HelloAck struct {
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason,omitempty"`
}

// CapabilityManifest is the guest's response to get_capabilities. Schema is
// always "vmobs.guest_capability.v1".
type CapabilityManifest struct {
	Schema        string    `json:"schema"`
	KernelRelease string    `json:"kernel_release"`
	Features      []Feature `json:"features"`
}

// Feature is one capability the guest either has or lacks.
type Feature struct {
	ID       string `json:"id"`
	Present  bool   `json:"present"`
	Evidence string `json:"evidence,omitempty"`
}

// WriteControl marshals data as a JSON Envelope with the given kind, then writes
// it as a FrameControl frame.
func WriteControl(w io.Writer, kind string, data any) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal control payload: %w", err)
	}
	env := Envelope{
		V:    ProtocolVersion,
		Kind: kind,
		Data: json.RawMessage(payload),
	}
	envBytes, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	return WriteFrame(w, FrameControl, envBytes)
}

// ReadControl reads a FrameControl frame and decodes the Envelope it contains.
func ReadControl(r io.Reader) (Envelope, error) {
	typ, payload, err := ReadFrame(r)
	if err != nil {
		return Envelope{}, fmt.Errorf("read control frame: %w", err)
	}
	if typ != FrameControl {
		return Envelope{}, fmt.Errorf("expected control frame (0x%02X), got 0x%02X", FrameControl, typ)
	}
	var env Envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return Envelope{}, fmt.Errorf("unmarshal envelope: %w", err)
	}
	return env, nil
}
