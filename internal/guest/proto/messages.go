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
	KindShutdown        = "shutdown"
	KindShutdownAck     = "shutdown_ack"
)

// Terminal session control kinds (SPEC §8.1, §8.2). The first six ride the
// existing control port; resize, dropped and error ride a session's own byte
// stream, which is duplex and already authenticated.
const (
	KindTerminalCreate   = "terminal.create"
	KindTerminalCreated  = "terminal.created"
	KindTerminalClose    = "terminal.close"
	KindTerminalClosed   = "terminal.closed"
	KindTerminalList     = "terminal.list"
	KindTerminalSessions = "terminal.sessions"
	KindTerminalResize   = "terminal.resize"
	KindTerminalDropped  = "terminal.dropped"
	KindTerminalError    = "terminal.error"
)

// TerminalCreate asks the guest to allocate a PTY and start Argv on it.
// Argv is an argument array: SPEC §8.1 forbids a host shell anywhere in this
// chain, so the guest execs it directly and never interprets it.
type TerminalCreate struct {
	SessionID string   `json:"session_id"`
	User      string   `json:"user"`
	Cwd       string   `json:"cwd"`
	Argv      []string `json:"argv"`
	Term      string   `json:"term"`
	Rows      uint16   `json:"rows"`
	Cols      uint16   `json:"cols"`
	// RingBytes is the replay window the host asks for. The guest clamps it
	// to its own floor and ceiling rather than trusting a number off the wire.
	RingBytes int `json:"ring_bytes"`
}

// TerminalCreated is the guest's answer to a create it accepted.
type TerminalCreated struct {
	SessionID string `json:"session_id"`
	PID       int    `json:"pid"`
	StartedAt string `json:"started_at"`
}

// TerminalClose asks the guest to end a session and reap its child.
type TerminalClose struct {
	SessionID string `json:"session_id"`
}

// TerminalClosed reports how a session ended. Exactly one of ExitCode and
// Signal is set: a process either returns a status or is killed by a signal.
type TerminalClosed struct {
	SessionID string `json:"session_id"`
	ExitCode  *int   `json:"exit_code,omitempty"`
	Signal    string `json:"signal,omitempty"`
	Reason    string `json:"reason"`
}

// TerminalList asks for every session the guest still holds.
type TerminalList struct{}

// TerminalSessions is the guest's session inventory.
type TerminalSessions struct {
	Sessions []TerminalSession `json:"sessions"`
}

// TerminalSession is one session in that inventory. HeadOffset and
// TailOffset are decimal strings: a busy shell passes 2^53 bytes in days.
type TerminalSession struct {
	SessionID  string `json:"session_id"`
	PID        int    `json:"pid"`
	Rows       uint16 `json:"rows"`
	Cols       uint16 `json:"cols"`
	HeadOffset string `json:"head_offset"`
	TailOffset string `json:"tail_offset"`
}

// TerminalResize carries a new window size on a session's own byte stream.
// The session is the connection's, so it is not named again here.
type TerminalResize struct {
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
}

// TerminalDropped names output the guest's replay ring overwrote before the
// reader consumed it. SPEC §8.2 requires the gap be shown, never papered
// over: the range is [FromOffset, ToOffset), as decimal strings.
type TerminalDropped struct {
	FromOffset string `json:"from_offset"`
	ToOffset   string `json:"to_offset"`
}

// TerminalError is a session-scoped failure. Remediation is the host's to
// attach when it renders this for a browser; the guest knows the cause, not
// what an operator should do about it.
type TerminalError struct {
	Cause   string `json:"cause"`
	Message string `json:"message"`
}

// Shutdown is sent by the host runner to request guest shutdown.
// DeadlineS is the number of seconds the guest has to shut down gracefully.
type Shutdown struct {
	DeadlineS int `json:"deadline_s"`
}

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
