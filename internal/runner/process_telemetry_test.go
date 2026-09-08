// ABOUTME: Exercises process identity normalization through the real guest ring and runner spool.
// ABOUTME: Boot mismatch and incomplete lifetime evidence cannot acquire an exact process key.
package runner_test

import (
	"encoding/json"
	"testing"

	"github.com/2389-research/observatory/internal/events"
)

func TestRunnerSpoolsProcessIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, kind, boot, start, generation string
		tgid                                float64
		exact                               bool
	}{
		{"exec", "proc.exec", telBootID, "9007199254740993", "2", 41, true},
		{"connect", "socket.connect_result", telBootID, "13", "2", 41, true},
		{"wrong_boot", "proc.exec", telVMID, "13", "2", 41, false},
		{"missing_start", "proc.exec", telBootID, "", "2", 41, false},
		{"zero_start", "proc.exec", telBootID, "0", "2", 41, false},
		{"fractional_pid", "proc.exec", telBootID, "13", "2", 41.5, false},
		{"overflow_start", "proc.exec", telBootID, "18446744073709551616", "2", 41, false},
		{"missing_generation", "proc.exec", telBootID, "13", "", 41, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTelemetryHarness(t)
			agent := h.startGuest()
			h.serveRealTelemetry(agent)
			data, err := json.Marshal(map[string]any{"process": map[string]any{"boot_id": tc.boot, "tgid": tc.tgid, "process_start_monotonic_ns": tc.start, "exec_generation": tc.generation}, "argv_truncated": true})
			if err != nil {
				t.Fatal(err)
			}
			agent.Telemetry().Ring().Push(tc.kind, data)
			h.run()
			env := h.waitForKind(tc.kind)
			if env == nil {
				t.Fatal("process event did not reach durable spool")
			}
			want := events.AttributionUnknown
			if tc.exact {
				want = events.AttributionExact
			}
			if env.Sensor != "process" || env.Provenance != events.GuestReported || env.Quality.Attribution != want || env.Quality.PathResolution != events.PathNotApplicable || !env.Quality.Truncated {
				t.Fatalf("process evidence normalization lost: %+v", env)
			}
			if tc.exact {
				if env.ProcessKey == nil || *env.ProcessKey != telBootID+":41:"+tc.start {
					t.Fatalf("wrong lifetime key: %v", env.ProcessKey)
				}
			} else if env.ProcessKey != nil {
				t.Fatal("incomplete identity received process key")
			}
			if err := env.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
