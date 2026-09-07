// ABOUTME: Tests telemetry_health derivation: what the newest heartbeat of the
// ABOUTME: current boot says, how old it is, and what a missing one means.
package situation_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/events"
	"github.com/2389-research/observatory/internal/situation"
	"github.com/2389-research/observatory/internal/store"
)

// runningVM creates a VM and walks it to running on a fresh boot, through the
// real transition machine rather than by writing the row. A VM whose row says
// "running" without having passed through the states that reach it is not a VM
// this derivation would ever meet. It returns the operation id so a test can
// keep transitioning the same VM under the same operation.
func runningVM(t *testing.T, st *store.Store, vmID, bootID string) (*store.VM, int64) {
	t.Helper()
	_, op := provisioningVM(t, st, vmID)
	if _, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vmID, To: "starting", Reason: "launch", OperationID: op, BootID: &bootID,
	}); err != nil {
		t.Fatalf("transition %s to starting: %v", vmID, err)
	}
	vm, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vmID, To: "running", Reason: "boot complete", OperationID: op,
	})
	if err != nil {
		t.Fatalf("transition %s to running: %v", vmID, err)
	}
	return vm, op
}

func provisioningVM(t *testing.T, st *store.Store, vmID string) (*store.VM, int64) {
	t.Helper()
	vm, op, _, err := st.CreateVMWithOperation(t.Context(), store.CreateVMInput{
		VMID:             vmID,
		Name:             "vm-" + vmID[len(vmID)-4:],
		Owner:            "test-owner",
		TemplateID:       "tmpl-001",
		TemplateDigest:   "sha256:abc123",
		VCPUCount:        2,
		MemoryMiB:        2048,
		RootDiskMiB:      8192,
		WorkspaceDiskMiB: 10240,
		MemoryTotalMiB:   2048 + 768,
		NetworkProfile:   "transport",
		NetworkPolicyID:  "transport-public-web",
		Labels:           map[string]string{},
		Kind:             "vm.create",
		RequestHash:      strings.Repeat("a", 64),
		Admit:            func(store.ReservationTotals) error { return nil },
	})
	if err != nil {
		t.Fatalf("create vm %s: %v", vmID, err)
	}
	return vm, op.OperationID
}

// stopVM walks a running VM down to stopped, the way a stop actually does it.
func stopVM(t *testing.T, st *store.Store, vmID string, op int64) *store.VM {
	t.Helper()
	var vm *store.VM
	for _, to := range []string{"stopping", "stopped"} {
		var err error
		vm, err = st.TransitionVM(t.Context(), store.TransitionInput{
			VMID: vmID, To: to, Reason: "test", OperationID: op, ReleaseCompute: to == "stopped",
		})
		if err != nil {
			t.Fatalf("transition %s to %s: %v", vmID, to, err)
		}
	}
	return vm
}

// heartbeat appends one guest.sensor_health the way the runner does: the host
// stamps host_received_at, so an old stamp is what an old heartbeat is. An
// empty intervalNS omits the field, which is how an agent that will not say how
// often it beats looks on the wire.
func heartbeat(t *testing.T, st *store.Store, vmID, bootID, source, seq string, receivedAt time.Time, sensors []map[string]any, intervalNS string) {
	t.Helper()
	vm, boot := vmID, bootID
	agent := map[string]any{
		"version":    "vmobs-guestd/proto-1",
		"started_at": receivedAt.UTC().Format(time.RFC3339Nano),
		"uptime_ns":  "60000000000",
	}
	if intervalNS != "" {
		agent["heartbeat_interval_ns"] = intervalNS
	}
	list := make([]any, 0, len(sensors))
	for _, s := range sensors {
		list = append(list, s)
	}
	if _, err := st.Append(t.Context(), &events.Envelope{
		SchemaVersion:    1,
		VMID:             &vm,
		BootID:           &boot,
		SourceInstanceID: source,
		SourceSeq:        seq,
		Kind:             "guest.sensor_health",
		Provenance:       events.GuestReported,
		Sensor:           "guestd",
		HostReceivedAt:   events.Timestamp{Time: receivedAt.UTC()},
		Quality: events.Quality{
			PathResolution: events.PathNotApplicable,
			Attribution:    events.AttributionNotApplicable,
		},
		Data: map[string]any{
			"agent":   agent,
			"ring":    map[string]any{"capacity": 1024, "queued": 0, "dropped": "0"},
			"sensors": list,
		},
	}); err != nil {
		t.Fatalf("append heartbeat seq %s: %v", seq, err)
	}
}

func sensor(id, state string) map[string]any {
	return map[string]any{"id": id, "state": state, "dropped": "0", "unknown_loss_intervals": 0}
}

func healthOf(t *testing.T, e *situation.Engine, vm *store.VM) situation.TelemetryHealth {
	t.Helper()
	h, err := e.VMTelemetryHealth(t.Context(), vm)
	if err != nil {
		t.Fatalf("derive telemetry health for %s: %v", vm.VMID, err)
	}
	return h
}

func TestRunningVMWithNoHeartbeatIsUnavailable(t *testing.T) {
	st := openStore(t)
	e := engineOver(st, allTriggers())
	vm, _ := runningVM(t, st, testUUID(1), testUUID(101))

	got := healthOf(t, e, vm)
	if got.State != situation.TelemetryUnavailable {
		t.Errorf("state = %q, want %q: a running VM whose agent has never reported has no telemetry, "+
			"and saying so is what §952 asks for", got.State, situation.TelemetryUnavailable)
	}
	if got.LastHeartbeatAt != "" {
		t.Errorf("last heartbeat = %q, want empty: there is none", got.LastHeartbeatAt)
	}
}

func TestFreshHeartbeatIsHealthy(t *testing.T) {
	st := openStore(t)
	e := engineOver(st, allTriggers())
	boot := testUUID(101)
	vm, _ := runningVM(t, st, testUUID(1), boot)
	heartbeat(t, st, vm.VMID, boot, testUUID(201), "1", time.Now().UTC(), nil, "10000000000")

	got := healthOf(t, e, vm)
	if got.State != situation.TelemetryHealthy {
		t.Errorf("state = %q, want %q", got.State, situation.TelemetryHealthy)
	}
	if got.LastHeartbeatAt == "" {
		t.Error("last heartbeat is empty: the derivation read a heartbeat it will not name")
	}
	if got.SensorsDegraded != 0 {
		t.Errorf("sensors degraded = %d, want 0: M2a registers no sensors", got.SensorsDegraded)
	}
}

func TestStaleHeartbeatIsDegradedWhileTheVMStaysRunning(t *testing.T) {
	st := openStore(t)
	e := engineOver(st, allTriggers())
	boot := testUUID(101)
	vm, _ := runningVM(t, st, testUUID(1), boot)
	// Ten intended beats ago, at the interval the guest itself reported.
	heartbeat(t, st, vm.VMID, boot, testUUID(201), "1", time.Now().UTC().Add(-100*time.Second), nil, "10000000000")

	got := healthOf(t, e, vm)
	if got.State != situation.TelemetryDegraded {
		t.Errorf("state = %q, want %q: a heartbeat ten intervals old is not evidence of health",
			got.State, situation.TelemetryDegraded)
	}
	if vm.ObservedState != "running" {
		t.Errorf("lifecycle = %q, want running: §133 keeps the two dimensions apart", vm.ObservedState)
	}
	if got.LastHeartbeatAt == "" {
		t.Error("last heartbeat is empty: degraded is a claim about a beat, so name it")
	}
}

func TestHeartbeatFromAPreviousBootDoesNotCount(t *testing.T) {
	st := openStore(t)
	e := engineOver(st, allTriggers())
	firstBoot := testUUID(101)
	vm, op := runningVM(t, st, testUUID(1), firstBoot)
	heartbeat(t, st, vm.VMID, firstBoot, testUUID(201), "1", time.Now().UTC(), nil, "10000000000")

	// Stop and boot again. That heartbeat is still the newest one this VM has,
	// and it describes a machine that no longer exists.
	stopVM(t, st, vm.VMID, op)
	secondBoot := testUUID(102)
	if _, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vm.VMID, To: "starting", Reason: "restart", OperationID: op, BootID: &secondBoot,
		AcquireCompute: true, Admit: func(store.ReservationTotals) error { return nil },
	}); err != nil {
		t.Fatalf("transition to starting on the second boot: %v", err)
	}
	vm, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vm.VMID, To: "running", Reason: "boot complete", OperationID: op,
	})
	if err != nil {
		t.Fatalf("transition to running on the second boot: %v", err)
	}

	got := healthOf(t, e, vm)
	if got.State != situation.TelemetryUnavailable {
		t.Errorf("state = %q, want %q: the newest heartbeat belongs to a boot that is over",
			got.State, situation.TelemetryUnavailable)
	}
	if got.LastHeartbeatAt != "" {
		t.Errorf("last heartbeat = %q, want empty: naming the old boot's beat here would date this "+
			"boot's telemetry from a machine that no longer exists", got.LastHeartbeatAt)
	}
}

func TestAFreshHeartbeatWithAnUnwellSensorIsDegraded(t *testing.T) {
	st := openStore(t)
	e := engineOver(st, allTriggers())
	boot := testUUID(101)
	vm, _ := runningVM(t, st, testUUID(1), boot)
	heartbeat(t, st, vm.VMID, boot, testUUID(201), "1", time.Now().UTC(), []map[string]any{
		sensor("process", "healthy"),
		sensor("fs", "degraded"),
		sensor("net", "unavailable"),
	}, "10000000000")

	got := healthOf(t, e, vm)
	if got.State != situation.TelemetryDegraded {
		t.Errorf("state = %q, want %q: the beat is fresh and says two of its sensors are not well",
			got.State, situation.TelemetryDegraded)
	}
	if got.SensorsDegraded != 2 {
		t.Errorf("sensors degraded = %d, want 2 (one degraded, one unavailable)", got.SensorsDegraded)
	}
}

func TestLifecycleStatesWithNoTelemetryToJudge(t *testing.T) {
	st := openStore(t)
	e := engineOver(st, allTriggers())
	vmID := testUUID(1)
	vm, op := provisioningVM(t, st, vmID)
	if got := healthOf(t, e, vm); got.State != situation.TelemetryStarting {
		t.Errorf("provisioning: state = %q, want %q: the boot has not finished, so nothing has "+
			"failed to report yet", got.State, situation.TelemetryStarting)
	}

	boot := testUUID(101)
	vm, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vmID, To: "starting", Reason: "launch", OperationID: op, BootID: &boot,
	})
	if err != nil {
		t.Fatalf("transition to starting: %v", err)
	}
	if got := healthOf(t, e, vm); got.State != situation.TelemetryStarting {
		t.Errorf("starting: state = %q, want %q", got.State, situation.TelemetryStarting)
	}

	vm, err = st.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vmID, To: "running", Reason: "boot complete", OperationID: op,
	})
	if err != nil {
		t.Fatalf("transition to running: %v", err)
	}
	heartbeat(t, st, vmID, boot, testUUID(201), "1", time.Now().UTC(), nil, "10000000000")
	if got := healthOf(t, e, vm); got.State != situation.TelemetryHealthy {
		t.Fatalf("running with a fresh beat: state = %q, want %q", got.State, situation.TelemetryHealthy)
	}

	// The same fresh heartbeat, now attached to a VM that is not executing. The
	// lifecycle answers for it, not the beat.
	for _, to := range []string{"stopping", "stopped"} {
		vm, err = st.TransitionVM(t.Context(), store.TransitionInput{
			VMID: vmID, To: to, Reason: "test", OperationID: op, ReleaseCompute: to == "stopped",
		})
		if err != nil {
			t.Fatalf("transition to %s: %v", to, err)
		}
		if got := healthOf(t, e, vm); got.State != situation.TelemetryUnavailable {
			t.Errorf("%s: state = %q, want %q: a guest that is winding down or gone cannot report",
				to, got.State, situation.TelemetryUnavailable)
		}
	}
}

// The interval rides the heartbeat because the guest owns it, which means an
// untrusted party owns the host's staleness threshold unless the host clamps
// it. Both ends are load-bearing: a tiny interval would make every beat
// instantly stale, and a huge one would make a dead agent look fine.
func TestTheGuestReportedIntervalIsClamped(t *testing.T) {
	cases := []struct {
		name      string
		interval  string
		age       time.Duration
		wantState string
	}{
		{"a one-nanosecond interval cannot make a fresh beat stale", "1", 2 * time.Second, situation.TelemetryHealthy},
		{"a one-year interval cannot make an hour-old beat fresh", "31536000000000000", time.Hour, situation.TelemetryDegraded},
		{"an unstated interval is not a free pass", "", time.Hour, situation.TelemetryDegraded},
		{"an unstated interval is not an accusation either", "", 2 * time.Second, situation.TelemetryHealthy},
		{"a negative interval is not an interval", "-5", time.Hour, situation.TelemetryDegraded},
		{"an unparseable interval is read as unstated", "banana", time.Hour, situation.TelemetryDegraded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := openStore(t)
			e := engineOver(st, allTriggers())
			boot := testUUID(101)
			vm, _ := runningVM(t, st, testUUID(1), boot)
			heartbeat(t, st, vm.VMID, boot, testUUID(201), "1", time.Now().UTC().Add(-tc.age), nil, tc.interval)

			if got := healthOf(t, e, vm); got.State != tc.wantState {
				t.Errorf("state = %q, want %q", got.State, tc.wantState)
			}
		})
	}
}

func TestSensorsDegradedCountsAcrossRunningVMs(t *testing.T) {
	st := openStore(t)
	e := engineOver(st, allTriggers())
	now := time.Now().UTC()

	bootA := testUUID(101)
	vmA, _ := runningVM(t, st, testUUID(1), bootA)
	heartbeat(t, st, vmA.VMID, bootA, testUUID(201), "1", now, []map[string]any{
		sensor("process", "degraded"), sensor("fs", "healthy"),
	}, "10000000000")

	bootB := testUUID(102)
	vmB, _ := runningVM(t, st, testUUID(2), bootB)
	heartbeat(t, st, vmB.VMID, bootB, testUUID(202), "1", now, []map[string]any{
		sensor("process", "unavailable"), sensor("fs", "unavailable"),
	}, "10000000000")

	// A stopped VM's sensors are nobody's current problem, and its last
	// heartbeat describes a machine that is no longer running.
	bootC := testUUID(103)
	vmC, opC := runningVM(t, st, testUUID(3), bootC)
	heartbeat(t, st, vmC.VMID, bootC, testUUID(203), "1", now, []map[string]any{
		sensor("process", "degraded"),
	}, "10000000000")
	stopVM(t, st, vmC.VMID, opC)

	snap, err := e.Snapshot(t.Context(), "")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snap.SensorsDegraded != 3 {
		t.Errorf("sensors_degraded = %d, want 3: one on vmA and two on vmB, none from the stopped vmC",
			snap.SensorsDegraded)
	}
}

func TestSensorsDegradedIsZeroWithNoSensorsRegistered(t *testing.T) {
	st := openStore(t)
	e := engineOver(st, allTriggers())
	boot := testUUID(101)
	vm, _ := runningVM(t, st, testUUID(1), boot)
	heartbeat(t, st, vm.VMID, boot, testUUID(201), "1", time.Now().UTC(), nil, "10000000000")

	snap, err := e.Snapshot(t.Context(), "")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snap.SensorsDegraded != 0 {
		t.Errorf("sensors_degraded = %d, want 0: M2a registers no sensors, and the honest count "+
			"of an empty list is zero", snap.SensorsDegraded)
	}
}

// The heartbeat is guest_reported, so the sensors array is whatever an
// untrusted agent put there. A shape the host cannot read is not a sensor
// claiming to be degraded: counting it would invent a fault, and giving up on
// the array would let one bad entry hide the real ones.
func TestAnUnreadableSensorEntryIsNotCountedAndDoesNotHideItsNeighbours(t *testing.T) {
	st := openStore(t)
	e := engineOver(st, allTriggers())
	boot := testUUID(101)
	vmID := testUUID(1)
	vm, _ := runningVM(t, st, vmID, boot)
	bootRef := boot
	var data map[string]any
	raw := `{"agent":{"heartbeat_interval_ns":"10000000000"},"ring":{},"sensors":[
		"not an object", {"id":"a","state":42}, {"id":"b"}, {"id":"c","state":"degraded"}]}`
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if _, err := st.Append(t.Context(), &events.Envelope{
		SchemaVersion: 1, VMID: &vmID, BootID: &bootRef,
		SourceInstanceID: testUUID(201), SourceSeq: "1",
		Kind: "guest.sensor_health", Provenance: events.GuestReported, Sensor: "guestd",
		HostReceivedAt: events.Timestamp{Time: time.Now().UTC()},
		Quality: events.Quality{
			PathResolution: events.PathNotApplicable,
			Attribution:    events.AttributionNotApplicable,
		},
		Data: data,
	}); err != nil {
		t.Fatalf("append heartbeat: %v", err)
	}

	got := healthOf(t, e, vm)
	if got.SensorsDegraded != 1 {
		t.Errorf("sensors degraded = %d, want 1: only the entry that says so counts", got.SensorsDegraded)
	}
	if got.State != situation.TelemetryDegraded {
		t.Errorf("state = %q, want %q", got.State, situation.TelemetryDegraded)
	}
}

// A guard against the derivation reading the newest heartbeat of the wrong VM.
func TestHeartbeatsAreScopedToTheirOwnVM(t *testing.T) {
	st := openStore(t)
	e := engineOver(st, allTriggers())
	bootA, bootB := testUUID(101), testUUID(102)
	vmA, _ := runningVM(t, st, testUUID(1), bootA)
	vmB, _ := runningVM(t, st, testUUID(2), bootB)
	heartbeat(t, st, vmB.VMID, bootB, testUUID(202), "1", time.Now().UTC(), nil, "10000000000")

	if got := healthOf(t, e, vmA); got.State != situation.TelemetryUnavailable {
		t.Errorf("vmA state = %q, want %q: vmB's heartbeat says nothing about vmA",
			got.State, situation.TelemetryUnavailable)
	}
	if got := healthOf(t, e, vmB); got.State != situation.TelemetryHealthy {
		t.Errorf("vmB state = %q, want %q", got.State, situation.TelemetryHealthy)
	}
}

// The newest heartbeat of the boot decides; an older one still in the stream
// does not.
func TestTheNewestHeartbeatOfTheBootDecides(t *testing.T) {
	st := openStore(t)
	e := engineOver(st, allTriggers())
	boot := testUUID(101)
	vm, _ := runningVM(t, st, testUUID(1), boot)
	source := testUUID(201)
	now := time.Now().UTC()
	heartbeat(t, st, vm.VMID, boot, source, "1", now.Add(-60*time.Second), []map[string]any{
		sensor("process", "degraded"),
	}, "10000000000")
	heartbeat(t, st, vm.VMID, boot, source, "2", now, nil, "10000000000")

	got := healthOf(t, e, vm)
	if got.State != situation.TelemetryHealthy {
		t.Errorf("state = %q, want %q: the sensor recovered and said so", got.State, situation.TelemetryHealthy)
	}
	if got.SensorsDegraded != 0 {
		t.Errorf("sensors degraded = %d, want 0", got.SensorsDegraded)
	}
	if want := now.Format(events.TimestampLayout); got.LastHeartbeatAt != want {
		t.Errorf("last heartbeat = %q, want %q", got.LastHeartbeatAt, want)
	}
}
