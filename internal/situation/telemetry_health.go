// ABOUTME: Derives a VM's telemetry_health from its newest guest heartbeat —
// ABOUTME: the second health dimension (§138), never folded into lifecycle state.
package situation

import (
	"context"
	"strconv"
	"time"

	"github.com/2389-research/observatory-v2/internal/events"
	"github.com/2389-research/observatory-v2/internal/store"
)

// The telemetry health vocabulary (SPEC §133). A VM may be running while its
// telemetry is degraded; the two dimensions answer different questions and
// neither substitutes for the other (§138).
const (
	// TelemetryStarting: the boot has not finished, so no agent has yet had a
	// chance to report. Silence here is not a fault.
	TelemetryStarting = "starting"
	// TelemetryHealthy: a recent heartbeat, and every sensor in it says it is well.
	TelemetryHealthy = "healthy"
	// TelemetryDegraded: the agent is reporting but something in the picture is
	// wrong — the newest heartbeat is stale, or a sensor says it is not well.
	TelemetryDegraded = "degraded"
	// TelemetryUnavailable: there is nothing to observe. No heartbeat for this
	// boot at all, or a guest that is not executing. §952: a killed guestd makes
	// host health degraded or unavailable while egress enforcement stands.
	TelemetryUnavailable = "unavailable"
)

// HeartbeatKind is the guest's periodic self-report. Its absence is not an
// event — staleness is derived by comparing the newest one against the host
// clock, which is what this file does.
const HeartbeatKind = "guest.sensor_health"

const (
	// minHeartbeatInterval and maxHeartbeatInterval bound the interval the
	// guest reports. The guest is untrusted, and this number sets the host's
	// staleness threshold: unclamped, a guest could declare a one-nanosecond
	// interval and be permanently degraded, or a one-year interval and look
	// healthy forever after its agent died.
	minHeartbeatInterval = 1 * time.Second
	maxHeartbeatInterval = 5 * time.Minute
	// stalenessIntervals is how many beats may be missed before the host stops
	// reading the last one as evidence of health. Three tolerates a lost
	// connection and a reconnect without crying wolf.
	stalenessIntervals = 3
)

// TelemetryHealth is the observation-quality dimension for one VM.
type TelemetryHealth struct {
	// State is one of the four constants above.
	State string
	// LastHeartbeatAt is when the host received the newest heartbeat of this
	// VM's current boot, in the wire timestamp form. Empty when there is none —
	// which is a different fact from a heartbeat received at the zero time.
	LastHeartbeatAt string
	// SensorsDegraded counts sensors the newest heartbeat reports as degraded or
	// unavailable. Zero when there is no heartbeat to count from: what a silent
	// agent's sensors are doing is unknown, and State is where that is said.
	SensorsDegraded int
}

// VMTelemetryHealth derives one VM's telemetry health. It reads the store only
// for a running VM: every other lifecycle state answers the question by itself,
// because a guest that is not executing cannot report and a guest that has not
// finished booting has not been asked yet.
func (e *Engine) VMTelemetryHealth(ctx context.Context, vm *store.VM) (TelemetryHealth, error) {
	switch vm.ObservedState {
	case "provisioning", "starting":
		return TelemetryHealth{State: TelemetryStarting}, nil
	case "running":
	default:
		return TelemetryHealth{State: TelemetryUnavailable}, nil
	}
	if vm.CurrentBootID == "" {
		// Running with no boot identity: nothing can be scoped to this boot, so
		// there is no heartbeat this host is entitled to read as current.
		return TelemetryHealth{State: TelemetryUnavailable}, nil
	}
	hb, err := e.st.LatestForBoot(ctx, vm.VMID, vm.CurrentBootID, HeartbeatKind)
	if err != nil {
		return TelemetryHealth{}, err
	}
	return deriveTelemetryHealth(hb, time.Now()), nil
}

// deriveTelemetryHealth reads a running VM's newest heartbeat. now is the host
// clock: host_received_at is host-stamped, so both sides of the age comparison
// come from the same clock and a guest with a wrong idea of the time cannot
// argue with it.
func deriveTelemetryHealth(hb *events.Envelope, now time.Time) TelemetryHealth {
	if hb == nil {
		return TelemetryHealth{State: TelemetryUnavailable}
	}
	h := TelemetryHealth{
		State:           TelemetryHealthy,
		LastHeartbeatAt: hb.HostReceivedAt.UTC().Format(events.TimestampLayout),
		SensorsDegraded: countUnwellSensors(hb.Data),
	}
	stale := now.Sub(hb.HostReceivedAt.Time) > stalenessIntervals*heartbeatInterval(hb.Data)
	if stale || h.SensorsDegraded > 0 {
		h.State = TelemetryDegraded
	}
	return h
}

// heartbeatInterval is how often this agent says it beats, clamped into the
// range the host will act on. An agent that will not say, or says something
// unreadable, gets the most generous window the host allows: the widest benefit
// of the doubt, not an unbounded one.
func heartbeatInterval(data map[string]any) time.Duration {
	agent, ok := data["agent"].(map[string]any)
	if !ok {
		return maxHeartbeatInterval
	}
	raw, ok := agent["heartbeat_interval_ns"].(string)
	if !ok {
		return maxHeartbeatInterval
	}
	ns, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || ns <= 0 {
		// Not an interval. Treated the same as saying nothing rather than
		// clamped up from below, because clamping a nonsense number to the
		// strictest window turns garbage into an accusation.
		return maxHeartbeatInterval
	}
	return min(max(time.Duration(ns), minHeartbeatInterval), maxHeartbeatInterval)
}

// countUnwellSensors counts the sensors this heartbeat reports as degraded or
// unavailable. The heartbeat is guest_reported, so its sensors array is
// whatever an untrusted agent put there: an entry the host cannot read is not
// counted, because inventing a fault from a shape we do not understand is as
// dishonest as hiding one. Reading continues past a bad entry so that one piece
// of garbage cannot conceal the sensors that did answer.
func countUnwellSensors(data map[string]any) int {
	list, ok := data["sensors"].([]any)
	if !ok {
		return 0
	}
	n := 0
	for _, item := range list {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		switch entry["state"] {
		case "degraded", "unavailable":
			n++
		}
	}
	return n
}

// sensorsDegraded sums the unwell sensors reported across every running VM.
// It walks the registry through the same per-VM derivation the VM record
// publishes, so the fleet count and a VM's own telemetry_health can never
// disagree about the same heartbeat.
func (e *Engine) sensorsDegraded(ctx context.Context) (int, error) {
	total, after := 0, int64(0)
	for {
		vms, err := e.st.ListVMs(ctx, store.VMQuery{
			After: after, Limit: store.MaxPageLimit, States: []string{"running"},
		})
		if err != nil {
			return 0, err
		}
		if len(vms) == 0 {
			return total, nil
		}
		for _, vm := range vms {
			h, err := e.VMTelemetryHealth(ctx, vm)
			if err != nil {
				return 0, err
			}
			total += h.SensorsDegraded
			after = vm.RowID
		}
	}
}
