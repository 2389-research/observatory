// ABOUTME: Tests filesystem evidence quality across the real guest-ring and runner-spool path.
// ABOUTME: Untrusted path claims cannot upgrade late resolution to capture-time certainty.
package runner_test

import (
	"encoding/json"
	"testing"

	"github.com/2389-research/observatory/internal/events"
)

func TestRunnerSpoolsFilesystemQuality(t *testing.T) {
	for _, tc := range []struct {
		claim string
		want  events.PathResolution
	}{
		{"inferred", events.PathInferred},
		{"unresolved", events.PathUnresolved},
		{"exact_at_capture", events.PathUnresolved},
		{"", events.PathUnresolved},
	} {
		t.Run(tc.claim, func(t *testing.T) {
			h := newTelemetryHarness(t)
			agent := h.startGuest()
			h.serveRealTelemetry(agent)
			data, err := json.Marshal(map[string]any{"operation": "modify", "path_status": tc.claim})
			if err != nil {
				t.Fatal(err)
			}
			agent.Telemetry().Ring().Push("fs.modify", data)
			h.run()
			env := h.waitForKind("fs.modify")
			if env == nil {
				t.Fatal("no fs.modify reached the durable spool")
			}
			if env.Sensor != "filesystem" || env.Provenance != events.GuestReported || env.Quality.PathResolution != tc.want || env.Quality.Attribution != events.AttributionUnknown {
				t.Fatalf("filesystem provenance/quality lost: %+v", env)
			}
			if err := env.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
