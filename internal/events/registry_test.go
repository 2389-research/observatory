// ABOUTME: Tests the event-kind registry: pattern validity, family consistency,
// ABOUTME: lookup behavior, and presence of the kinds phase-1 code emits.
package events_test

import (
	"strings"
	"testing"

	"github.com/2389-research/observatory-v2/internal/events"
)

func TestRegistryKindsAreWellFormed(t *testing.T) {
	kinds := events.Kinds()
	if len(kinds) == 0 {
		t.Fatal("registry is empty")
	}
	seen := map[string]bool{}
	for _, k := range kinds {
		if seen[k.Kind] {
			t.Errorf("duplicate kind %q", k.Kind)
		}
		seen[k.Kind] = true
		if !strings.HasPrefix(k.Kind, k.Family+".") {
			t.Errorf("kind %q not under family %q", k.Kind, k.Family)
		}
		if k.Semantics == "" {
			t.Errorf("kind %q has no semantics", k.Kind)
		}
		if k.SchemaVersion != 1 {
			t.Errorf("kind %q schema version %d", k.Kind, k.SchemaVersion)
		}
		env := &events.Envelope{Kind: k.Kind}
		if err := env.Validate(); err != nil && strings.Contains(err.Error(), "kind") &&
			strings.Contains(err.Error(), "pattern") {
			t.Errorf("registered kind %q fails the envelope kind pattern", k.Kind)
		}
	}
}

func TestRegistryLookup(t *testing.T) {
	info, ok := events.LookupKind("fs.modify")
	if !ok {
		t.Fatal("fs.modify not registered")
	}
	if info.Family != "fs" || info.Provenance != events.GuestReported {
		t.Errorf("fs.modify info wrong: %+v", info)
	}
	if len(info.Caveats) == 0 {
		t.Error("fs.modify must carry its fanotify caveats (P-07)")
	}
	if _, ok := events.LookupKind("no.such_kind"); ok {
		t.Error("unregistered kind resolved")
	}
	for _, required := range []string{"telemetry.loss", "telemetry.integrity_failure", "telemetry.unregistered_kind"} {
		if _, ok := events.LookupKind(required); !ok {
			t.Errorf("health kind %q not registered", required)
		}
	}
}

func TestAttentionAndAnnotationKindsRegistered(t *testing.T) {
	// SPEC line ~681: attention.* and annotation.* families are host_observed.
	for _, kind := range []string{"attention.raised", "attention.queue_overflow", "annotation.created"} {
		info, ok := events.LookupKind(kind)
		if !ok {
			t.Errorf("%q not registered", kind)
			continue
		}
		if info.Provenance != events.HostObserved {
			t.Errorf("%q provenance = %q, want host_observed", kind, info.Provenance)
		}
		if info.Semantics == "" {
			t.Errorf("%q has no semantics", kind)
		}
	}
}

func TestFamiliesReturnsSortedDistinctList(t *testing.T) {
	// Families() must return a sorted, deduplicated list with at least the core set.
	families := events.Families()
	if len(families) == 0 {
		t.Fatal("Families() returned empty list")
	}
	// Check sorted.
	for i := 1; i < len(families); i++ {
		if families[i] <= families[i-1] {
			t.Errorf("Families() not sorted at index %d: %q <= %q", i, families[i], families[i-1])
		}
	}
	// Check deduplication.
	seen := map[string]bool{}
	for _, f := range families {
		if seen[f] {
			t.Errorf("Families() has duplicate entry: %q", f)
		}
		seen[f] = true
	}
	// Every family in Kinds() must appear in Families().
	for _, k := range events.Kinds() {
		if !seen[k.Family] {
			t.Errorf("Families() missing family %q (has kind %q)", k.Family, k.Kind)
		}
	}
}

func TestRunKindsRegistered(t *testing.T) {
	// §12.2: run.* family is host_observed except run.progress (guest_reported).
	cases := []struct {
		kind       string
		provenance events.Provenance
	}{
		{"run.created", events.HostObserved},
		{"run.state_changed", events.HostObserved},
		{"run.progress", events.GuestReported},
		{"run.result_recorded", events.HostObserved},
		{"run.submission_rejected", events.HostObserved},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			info, ok := events.LookupKind(tc.kind)
			if !ok {
				t.Fatalf("%q not registered", tc.kind)
			}
			if info.Family != "run" {
				t.Errorf("family = %q, want \"run\"", info.Family)
			}
			if info.SchemaVersion != 1 {
				t.Errorf("schema_version = %d, want 1", info.SchemaVersion)
			}
			if info.Provenance != tc.provenance {
				t.Errorf("provenance = %q, want %q", info.Provenance, tc.provenance)
			}
			if info.Semantics == "" {
				t.Error("semantics must not be empty")
			}
		})
	}
}
