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
