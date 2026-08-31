// ABOUTME: Envelope validation mirroring the JSON Schema rules plus ingress
// ABOUTME: strictness: lowercase UUIDs, decimal-string counters, scope binding.
package events

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	kindPattern    = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
	decimalPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	// Lowercase only: this system generates lowercase UUIDs and dedup keys
	// compare as strings, so ingress normalization is strict by design.
	uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// DecimalString reports whether s is a canonical non-negative decimal integer
// string (no leading zeros), the wire form for large counters.
func DecimalString(s string) bool { return decimalPattern.MatchString(s) }

// UUIDString reports whether s is a lowercase RFC 4122 textual UUID.
func UUIDString(s string) bool { return uuidPattern.MatchString(s) }

// ValidationError lists every rule an envelope broke, for structured error details.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	return "envelope invalid: " + strings.Join(e.Problems, "; ")
}

// Validate checks the envelope against the interchange contract. It returns a
// *ValidationError listing all problems, or nil.
func (e *Envelope) Validate() error {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	if e.SchemaVersion != 1 {
		add("schema_version must be 1, got %d", e.SchemaVersion)
	}
	if e.EventID != nil && !DecimalString(*e.EventID) {
		add("event_id %q is not a decimal string", *e.EventID)
	}
	if e.VMID != nil && !UUIDString(*e.VMID) {
		add("vm_id %q is not a lowercase uuid", *e.VMID)
	}
	if e.BootID != nil && !UUIDString(*e.BootID) {
		add("boot_id %q is not a lowercase uuid", *e.BootID)
	}
	if e.VMID == nil && e.BootID != nil {
		add("boot_id requires vm_id: a boot-scoped event must carry its VM scope")
	}
	if !UUIDString(e.SourceInstanceID) {
		add("source_instance_id %q is not a lowercase uuid", e.SourceInstanceID)
	}
	if !DecimalString(e.SourceSeq) {
		add("source_seq %q is not a decimal string", e.SourceSeq)
	}
	if len(e.Kind) < 3 || len(e.Kind) > 96 || !kindPattern.MatchString(e.Kind) {
		add("kind %q does not match the kind pattern", e.Kind)
	}
	switch e.Provenance {
	case HostObserved, GuestReported, Derived:
	default:
		add("provenance %q is not host_observed, guest_reported or derived", e.Provenance)
	}
	if len(e.Sensor) < 1 || len(e.Sensor) > 64 {
		add("sensor must be 1..64 bytes, got %d", len(e.Sensor))
	}
	if e.HostReceivedAt.IsZero() {
		add("host_received_at is required")
	}
	if e.HostBootID != "" && !UUIDString(e.HostBootID) {
		add("host_boot_id %q is not a lowercase uuid", e.HostBootID)
	}
	if e.HostMonotonicNS != "" && !DecimalString(e.HostMonotonicNS) {
		add("host_monotonic_ns %q is not a decimal string", e.HostMonotonicNS)
	}
	if e.GuestMonotonicNS != nil && !DecimalString(*e.GuestMonotonicNS) {
		add("guest_monotonic_ns %q is not a decimal string", *e.GuestMonotonicNS)
	}
	if e.ProcessKey != nil && (len(*e.ProcessKey) < 1 || len(*e.ProcessKey) > 256) {
		add("process_key must be 1..256 bytes")
	}
	if e.RunID != nil && !UUIDString(*e.RunID) {
		add("run_id %q is not a lowercase uuid", *e.RunID)
	}
	if len(e.RelatedEventIDs) > 64 {
		add("related_event_ids exceeds 64 entries")
	}
	seen := make(map[string]bool, len(e.RelatedEventIDs))
	for _, id := range e.RelatedEventIDs {
		if !DecimalString(id) {
			add("related event id %q is not a decimal string", id)
		}
		if seen[id] {
			add("related event id %q repeated", id)
		}
		seen[id] = true
	}
	switch e.Quality.PathResolution {
	case PathExactAtCapture, PathInferred, PathUnresolved, PathNotApplicable:
	default:
		add("quality.path_resolution %q is not a known value", e.Quality.PathResolution)
	}
	switch e.Quality.Attribution {
	case AttributionExact, AttributionInferred, AttributionUnknown, AttributionNotApplicable:
	default:
		add("quality.attribution %q is not a known value", e.Quality.Attribution)
	}
	if len(e.Quality.Notes) > 16 {
		add("quality.notes exceeds 16 entries")
	}
	if e.Data == nil {
		add("data object is required")
	}

	if len(problems) > 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}
