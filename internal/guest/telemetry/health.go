// ABOUTME: The guest sensor-health heartbeat (SPEC §138-§139): what the agent
// ABOUTME: reports about itself and each sensor it has registered.
package telemetry

import (
	"encoding/json"
	"strconv"
	"sync"
	"time"
)

// Sensor states. A sensor that is present but losing events is degraded, not
// healthy: §133 says a VM may be running while its telemetry is degraded, and
// the same distinction applies one level down.
const (
	SensorHealthy     = "healthy"
	SensorDegraded    = "degraded"
	SensorUnavailable = "unavailable"
)

// Sensor is one registered sensor's self-report (§139: coverage, last event,
// observed drops, unknown loss intervals, exclusions, capture mode).
type Sensor struct {
	ID          string `json:"id"`
	State       string `json:"state"`
	LastEventAt string `json:"last_event_at,omitempty"`
	// Dropped is a decimal string for the same reason the ring's is.
	Dropped              string   `json:"dropped"`
	UnknownLossIntervals int      `json:"unknown_loss_intervals"`
	CaptureMode          string   `json:"capture_mode,omitempty"`
	Exclusions           []string `json:"exclusions,omitempty"`
}

// AgentInfo is the guest agent's own liveness. It answers "is guestd alive",
// which is a strictly smaller claim than "telemetry is working".
type AgentInfo struct {
	Version   string `json:"version"`
	StartedAt string `json:"started_at"`
	// UptimeNS is a decimal string of nanoseconds.
	UptimeNS string `json:"uptime_ns"`
	// HeartbeatIntervalNS is how often the agent intends to beat, as a decimal
	// string of nanoseconds. The guest reports it so the host derives staleness
	// from what the guest actually does; a threshold hardcoded on the host
	// silently becomes wrong the day the guest's interval changes.
	HeartbeatIntervalNS string `json:"heartbeat_interval_ns"`
}

// Health is the guest.sensor_health payload.
type Health struct {
	Agent   AgentInfo `json:"agent"`
	Ring    RingStats `json:"ring"`
	Sensors []Sensor  `json:"sensors"`
}

// Registry holds the sensors a heartbeat reports. It is empty in M2a — no
// sensor exists yet — and that empty list is the honest answer, rendered as
// [] rather than null so a reader cannot mistake "none registered" for "the
// agent does not know".
type Registry struct {
	mu      sync.Mutex
	sensors map[string]Sensor
	order   []string
}

// NewRegistry returns an empty sensor registry.
func NewRegistry() *Registry {
	return &Registry{sensors: make(map[string]Sensor)}
}

// Set records a sensor's current self-report, replacing any earlier one.
func (g *Registry) Set(s Sensor) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, seen := g.sensors[s.ID]; !seen {
		g.order = append(g.order, s.ID)
	}
	g.sensors[s.ID] = s
}

// Snapshot returns the registered sensors in registration order. Never nil.
func (g *Registry) Snapshot() []Sensor {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]Sensor, 0, len(g.order))
	for _, id := range g.order {
		out = append(out, g.sensors[id])
	}
	return out
}

// ReporterConfig configures the heartbeat producer.
type ReporterConfig struct {
	Version      string
	RingCapacity int
	// HeartbeatInterval is reported in every beat, not enforced here: the
	// reporter renders heartbeats, the caller decides when.
	HeartbeatInterval time.Duration
	// StartedAt defaults to now. Set it to the agent's real start so uptime
	// describes the agent rather than the reporter.
	StartedAt time.Time
	// Now defaults to time.Now.
	Now func() time.Time
}

// Reporter owns the ring, the sensor registry and the agent's start time, and
// turns them into heartbeats. It produces on its own schedule: nothing about a
// missing or slow host connection may stop a beat, because the count of what
// piled up while nobody read is the evidence that nobody was reading.
type Reporter struct {
	cfg     ReporterConfig
	ring    *Ring
	sensors *Registry
	started time.Time
	now     func() time.Time
}

// NewReporter returns a Reporter with an empty ring and no sensors.
func NewReporter(cfg ReporterConfig) *Reporter {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	started := cfg.StartedAt
	if started.IsZero() {
		started = now()
	}
	return &Reporter{
		cfg:     cfg,
		ring:    NewRing(cfg.RingCapacity),
		sensors: NewRegistry(),
		started: started,
		now:     now,
	}
}

// Ring returns the queue sensors push into and the sender drains.
func (r *Reporter) Ring() *Ring { return r.ring }

// Sensors returns the registry each sensor publishes its state into.
func (r *Reporter) Sensors() *Registry { return r.sensors }

// Health renders the current heartbeat payload without queueing it.
func (r *Reporter) Health() Health {
	now := r.now()
	return Health{
		Agent: AgentInfo{
			Version:             r.cfg.Version,
			StartedAt:           r.started.UTC().Format(time.RFC3339Nano),
			UptimeNS:            strconv.FormatInt(now.Sub(r.started).Nanoseconds(), 10),
			HeartbeatIntervalNS: strconv.FormatInt(r.cfg.HeartbeatInterval.Nanoseconds(), 10),
		},
		Ring:    r.ring.Stats(),
		Sensors: r.sensors.Snapshot(),
	}
}

// Beat queues one heartbeat. A heartbeat that cannot be marshalled is dropped
// rather than queued half-formed; the shape is fixed and closed, so this cannot
// happen from data the guest controls.
func (r *Reporter) Beat() {
	data, err := json.Marshal(r.Health())
	if err != nil {
		return
	}
	r.ring.Push("guest.sensor_health", data)
}
