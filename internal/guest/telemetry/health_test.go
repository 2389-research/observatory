// ABOUTME: Tests the sensor-health heartbeat's shape: an empty sensor list is
// ABOUTME: an empty array, and a heartbeat is produced whether or not anyone reads it.
package telemetry_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/guest/telemetry"
)

// "sensors": null would read as "the agent does not know", which is a
// different claim from "no sensor is registered".
func TestHeartbeatWithNoSensorsRendersAnEmptyArray(t *testing.T) {
	rep := telemetry.NewReporter(telemetry.ReporterConfig{Version: "test", RingCapacity: 8})
	b, err := json.Marshal(rep.Health())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"sensors":[]`) {
		t.Fatalf("health = %s, want an empty sensors array", b)
	}
}

func TestHeartbeatReportsRegisteredSensors(t *testing.T) {
	rep := telemetry.NewReporter(telemetry.ReporterConfig{Version: "test", RingCapacity: 8})
	rep.Sensors().Set(telemetry.Sensor{ID: "process", State: telemetry.SensorDegraded, Dropped: "17"})
	h := rep.Health()
	if len(h.Sensors) != 1 || h.Sensors[0].ID != "process" || h.Sensors[0].State != telemetry.SensorDegraded {
		t.Fatalf("sensors = %+v, want one degraded process sensor", h.Sensors)
	}
}

// §507: the ring's loss is measured and reported, not inferred from silence.
func TestHeartbeatCarriesTheRingsDropCount(t *testing.T) {
	rep := telemetry.NewReporter(telemetry.ReporterConfig{Version: "test", RingCapacity: 1})
	for i := 0; i < 4; i++ {
		rep.Beat()
	}
	h := rep.Health()
	if h.Ring.Dropped == "0" || h.Ring.Dropped == "" {
		t.Fatalf("ring dropped = %q after overflowing a 1-slot ring", h.Ring.Dropped)
	}
	if h.Ring.Capacity != 1 {
		t.Errorf("capacity = %d, want 1", h.Ring.Capacity)
	}
}

// A heartbeat is produced on its own schedule. Nothing about a missing or slow
// host connection may stop it: the count of what piled up while nobody read is
// the evidence that nobody was reading.
func TestBeatFillsTheRingWithNoConnection(t *testing.T) {
	rep := telemetry.NewReporter(telemetry.ReporterConfig{Version: "test", RingCapacity: 4})
	for i := 0; i < 3; i++ {
		rep.Beat()
	}
	if got := rep.Health().Ring.Queued; got != 3 {
		t.Fatalf("queued = %d after three beats with no reader, want 3", got)
	}
}

func TestHeartbeatUptimeIsADecimalStringOfNanoseconds(t *testing.T) {
	started := time.Now().Add(-2 * time.Second)
	rep := telemetry.NewReporter(telemetry.ReporterConfig{Version: "test", RingCapacity: 4, StartedAt: started})
	h := rep.Health()
	if h.Agent.UptimeNS == "" {
		t.Fatal("uptime_ns is empty")
	}
	for _, c := range h.Agent.UptimeNS {
		if c < '0' || c > '9' {
			t.Fatalf("uptime_ns = %q is not a decimal string", h.Agent.UptimeNS)
		}
	}
	if h.Agent.StartedAt != started.UTC().Format(time.RFC3339Nano) {
		t.Errorf("started_at = %q, want %q", h.Agent.StartedAt, started.UTC().Format(time.RFC3339Nano))
	}
}
