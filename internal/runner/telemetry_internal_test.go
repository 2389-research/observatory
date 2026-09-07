// ABOUTME: Unit tests for telemetry stream identity: derived by the host, stable
// ABOUTME: across reconnects, and refusing anything the guest should not smuggle in.
package runner

import (
	"strings"
	"testing"

	"github.com/2389-research/observatory/internal/events"
)

// A reconnect must land in the same stream, or the guest's sequences fork and
// the store's dedup has nothing to match against.
func TestTelemetryStreamIDIsStableForTheSameEpoch(t *testing.T) {
	a := telemetryStreamID("inst-1", "abc123")
	b := telemetryStreamID("inst-1", "abc123")
	if a != b {
		t.Fatalf("same instance and epoch gave %q then %q", a, b)
	}
}

// A restarted guest agent counts from one again. It must get its own stream, or
// every sequence it sends collides with one the old agent already spooled.
func TestTelemetryStreamIDChangesWithTheEpoch(t *testing.T) {
	if a, b := telemetryStreamID("inst-1", "abc123"), telemetryStreamID("inst-1", "def456"); a == b {
		t.Fatalf("two epochs shared a stream id: %q", a)
	}
	if a, b := telemetryStreamID("inst-1", "abc123"), telemetryStreamID("inst-2", "abc123"); a == b {
		t.Fatalf("two runner instances shared a stream id: %q", a)
	}
}

// source_instance_id is a lowercase UUID everywhere else in the system; a
// telemetry stream is not an exception the store would have to learn about.
func TestTelemetryStreamIDIsALowercaseUUID(t *testing.T) {
	id := telemetryStreamID("inst-1", "abc123")
	if !events.UUIDString(id) {
		t.Fatalf("stream id %q is not a lowercase uuid", id)
	}
}

func TestGuestEpochPatternRefusesWhatItShould(t *testing.T) {
	good := []string{"a", "abc123", strings.Repeat("x", 64), "a.b-c_d"}
	for _, s := range good {
		if !guestEpochPattern.MatchString(s) {
			t.Errorf("epoch %q refused, want accepted", s)
		}
	}
	bad := map[string]string{
		"empty":    "",
		"too long": strings.Repeat("x", 65),
		"newline":  "abc\ndef",
		"path":     "../../etc/passwd",
		"nul":      "abc\x00def",
		"space":    "abc def",
		// U+202E, right-to-left override: it makes a log line read as something
		// other than what it says.
		"bidi override": "abc\u202edef",
		"json escape":   `abc"def`,
	}
	for name, s := range bad {
		if guestEpochPattern.MatchString(s) {
			t.Errorf("%s epoch %q accepted, want refused", name, s)
		}
	}
}
