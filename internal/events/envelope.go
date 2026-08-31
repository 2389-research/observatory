// ABOUTME: Normalized event envelope v1 matching docs/schemas/event-envelope.schema.json.
// ABOUTME: Nullable scopes are pointers; counters that can exceed JS safe integers are decimal strings.
package events

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// Provenance identifies where evidence came from. Trusted ingress assigns it; a
// guest cannot self-label host_observed.
type Provenance string

const (
	HostObserved  Provenance = "host_observed"
	GuestReported Provenance = "guest_reported"
	Derived       Provenance = "derived"
)

// PathResolution states how a path in event data was established.
type PathResolution string

const (
	PathExactAtCapture PathResolution = "exact_at_capture"
	PathInferred       PathResolution = "inferred"
	PathUnresolved     PathResolution = "unresolved"
	PathNotApplicable  PathResolution = "not_applicable"
)

// Attribution states how confidently the event is tied to a process identity.
type Attribution string

const (
	AttributionExact         Attribution = "exact"
	AttributionInferred      Attribution = "inferred"
	AttributionUnknown       Attribution = "unknown"
	AttributionNotApplicable Attribution = "not_applicable"
)

// Timestamp marshals as RFC 3339 UTC with microsecond precision, the format
// used across the interchange contract.
type Timestamp struct {
	time.Time
}

func (t Timestamp) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.UTC().Format("2006-01-02T15:04:05.000000Z07:00"))
}

func (t *Timestamp) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return fmt.Errorf("timestamp %q: %w", s, err)
	}
	t.Time = parsed
	return nil
}

// Quality carries the honesty flags every event must state.
type Quality struct {
	PathResolution    PathResolution `json:"path_resolution"`
	Attribution       Attribution    `json:"attribution"`
	Truncated         bool           `json:"truncated"`
	Redacted          bool           `json:"redacted"`
	RedactionPolicyID string         `json:"redaction_policy_id,omitempty"`
	Notes             []string       `json:"notes,omitempty"`
}

// Envelope is the host-normalized event record. EventID is nil before indexing
// and assigned from the SQLite ingestion cursor; indexed API responses populate it.
type Envelope struct {
	SchemaVersion    int            `json:"schema_version"`
	EventID          *string        `json:"event_id,omitempty"`
	VMID             *string        `json:"vm_id"`
	BootID           *string        `json:"boot_id"`
	SourceInstanceID string         `json:"source_instance_id"`
	SourceSeq        string         `json:"source_seq"`
	Kind             string         `json:"kind"`
	Provenance       Provenance     `json:"provenance"`
	Sensor           string         `json:"sensor"`
	HostReceivedAt   Timestamp      `json:"host_received_at"`
	HostBootID       string         `json:"host_boot_id,omitempty"`
	HostMonotonicNS  string         `json:"host_monotonic_ns,omitempty"`
	GuestWallAt      *Timestamp     `json:"guest_wall_at,omitempty"`
	GuestMonotonicNS *string        `json:"guest_monotonic_ns,omitempty"`
	ProcessKey       *string        `json:"process_key,omitempty"`
	RunID            *string        `json:"run_id,omitempty"`
	RelatedEventIDs  []string       `json:"related_event_ids,omitempty"`
	Quality          Quality        `json:"quality"`
	Data             map[string]any `json:"data"`
}

// Parse decodes an envelope strictly: undeclared properties are rejected, as
// the schema's additionalProperties:false requires. Callers bound raw size
// before calling; JSON parsing alone is not a memory boundary.
func Parse(raw []byte) (*Envelope, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var env Envelope
	if err := dec.Decode(&env); err != nil {
		return nil, fmt.Errorf("envelope parse: %w", err)
	}
	return &env, nil
}
