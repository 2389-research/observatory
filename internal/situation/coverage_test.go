// ABOUTME: Tests VM/boot-scoped capture coverage independently from channel health.
// ABOUTME: Empty sensors and host worker failures stay explicit rather than implying observation.
package situation_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/events"
	"github.com/2389-research/observatory/internal/situation"
	"github.com/2389-research/observatory/internal/store"
)

type coverageSource func(context.Context, *store.VM) ([]situation.CollectorCoverage, error)

func heartbeatWithData(t *testing.T, st *store.Store, vmID, bootID, source, seq string, data map[string]any) {
	t.Helper()
	if _, err := st.Append(t.Context(), &events.Envelope{
		SchemaVersion: 1, VMID: &vmID, BootID: &bootID, SourceInstanceID: source, SourceSeq: seq,
		Kind: "guest.sensor_health", Provenance: events.GuestReported, Sensor: "guestd",
		HostReceivedAt: events.Timestamp{Time: time.Now().UTC()},
		Quality:        events.Quality{PathResolution: events.PathNotApplicable, Attribution: events.AttributionNotApplicable}, Data: data,
	}); err != nil {
		t.Fatalf("append heartbeat: %v", err)
	}
}

func (f coverageSource) Coverage(ctx context.Context, vm *store.VM) ([]situation.CollectorCoverage, error) {
	return f(ctx, vm)
}

func collectorByID(t *testing.T, got situation.Coverage, id string) situation.CollectorCoverage {
	t.Helper()
	for _, collector := range got.Collectors {
		if collector.ID == id {
			return collector
		}
	}
	t.Fatalf("collector %q absent from %+v", id, got.Collectors)
	return situation.CollectorCoverage{}
}

func TestCoverageSeparatesHealthyChannelFromAbsentCapture(t *testing.T) {
	st := openStore(t)
	e := engineOver(st, allTriggers())
	boot := testUUID(101)
	vm, _ := runningVM(t, st, testUUID(1), boot)
	heartbeat(t, st, vm.VMID, boot, testUUID(201), "1", time.Now().UTC(), nil, "10000000000")

	got, err := e.VMCoverage(t.Context(), vm)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if got.Channel.State != situation.TelemetryHealthy {
		t.Errorf("channel = %q, want healthy", got.Channel.State)
	}
	for _, id := range []string{"filesystem", "process", "flow", "dns", "denial"} {
		if collector := collectorByID(t, got, id); collector.State != situation.CoverageUnavailable {
			t.Errorf("%s state = %q, want unavailable", id, collector.State)
		}
	}
	if request := collectorByID(t, got, "request"); request.State != situation.CoverageDisabled {
		t.Errorf("request state = %q, want disabled for transport profile", request.State)
	}
}

func TestCoverageReadsGuestSensorDetailsAndPreservesUnknownLoss(t *testing.T) {
	st := openStore(t)
	e := engineOver(st, allTriggers())
	boot := testUUID(101)
	vm, _ := runningVM(t, st, testUUID(1), boot)
	now := time.Now().UTC()
	heartbeat(t, st, vm.VMID, boot, testUUID(201), "1", now, []map[string]any{{
		"id": "filesystem", "state": "healthy", "dropped": "0", "unknown_loss_intervals": 0,
		"event_classes": []any{"fs.modify"}, "scope": []any{"/workspace"},
		"exclusions": []any{"/proc"}, "last_event_at": now.Format(time.RFC3339Nano),
		"last_success_at": now.Format(time.RFC3339Nano), "capture_mode": "fanotify",
	}}, "10000000000")

	got, err := e.VMCoverage(t.Context(), vm)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	fs := collectorByID(t, got, "filesystem")
	if fs.State != situation.CoverageHealthy || fs.ObservedDropped == nil || *fs.ObservedDropped != "0" {
		t.Errorf("filesystem = %+v, want healthy with observed zero drops", fs)
	}
	if len(fs.EventClasses) != 1 || fs.EventClasses[0] != "fs.modify" || len(fs.Scope) != 1 {
		t.Errorf("filesystem contract lost event classes/scope: %+v", fs)
	}
	process := collectorByID(t, got, "process")
	if process.ObservedDropped != nil {
		t.Errorf("missing process sensor observed_dropped = %v, want unknown", *process.ObservedDropped)
	}
}

func TestCoverageRejectsHostRecordsFromAnotherBoot(t *testing.T) {
	st := openStore(t)
	e := engineOver(st, allTriggers())
	boot := testUUID(101)
	vm, _ := runningVM(t, st, testUUID(1), boot)
	e.SetHostCoverageSource(coverageSource(func(context.Context, *store.VM) ([]situation.CollectorCoverage, error) {
		return []situation.CollectorCoverage{{
			ID: "flow", VMID: vm.VMID, BootID: testUUID(999), State: situation.CoverageHealthy,
			Source: "host", Provenance: "host_observed",
		}}, nil
	}))

	got, err := e.VMCoverage(t.Context(), vm)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if flow := collectorByID(t, got, "flow"); flow.State != situation.CoverageUnavailable {
		t.Errorf("cross-boot flow = %+v, want unavailable", flow)
	}
}

func TestCoverageMakesHostSourceFailureVisible(t *testing.T) {
	st := openStore(t)
	e := engineOver(st, allTriggers())
	vm, _ := runningVM(t, st, testUUID(1), testUUID(101))
	e.SetHostCoverageSource(coverageSource(func(context.Context, *store.VM) ([]situation.CollectorCoverage, error) {
		return nil, errors.New("worker registry unavailable")
	}))

	got, err := e.VMCoverage(t.Context(), vm)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	flow := collectorByID(t, got, "flow")
	if flow.State != situation.CoverageUnavailable || flow.Reason == "" {
		t.Errorf("flow after source failure = %+v, want unavailable with reason", flow)
	}
}

func TestStaleChannelDegradesPreviouslyHealthyGuestCapture(t *testing.T) {
	st := openStore(t)
	e := engineOver(st, allTriggers())
	boot := testUUID(101)
	vm, _ := runningVM(t, st, testUUID(1), boot)
	heartbeat(t, st, vm.VMID, boot, testUUID(201), "1", time.Now().UTC().Add(-time.Minute), []map[string]any{{
		"id": "filesystem", "state": "healthy", "dropped": "0", "unknown_loss_intervals": 0,
	}}, "10000000000")

	got, err := e.VMCoverage(t.Context(), vm)
	if err != nil {
		t.Fatal(err)
	}
	fs := collectorByID(t, got, "filesystem")
	if fs.State != situation.CoverageDegraded || fs.Reason == "" {
		t.Errorf("stale filesystem = %+v, want degraded with reason", fs)
	}
}

func TestDuplicateGuestSensorDoesNotLetOrderingClaimHealth(t *testing.T) {
	st := openStore(t)
	e := engineOver(st, allTriggers())
	boot := testUUID(101)
	vm, _ := runningVM(t, st, testUUID(1), boot)
	heartbeat(t, st, vm.VMID, boot, testUUID(201), "1", time.Now().UTC(), []map[string]any{
		{"id": "filesystem", "state": "unavailable"},
		{"id": "filesystem", "state": "healthy", "dropped": "0"},
	}, "10000000000")

	got, err := e.VMCoverage(t.Context(), vm)
	if err != nil {
		t.Fatal(err)
	}
	if fs := collectorByID(t, got, "filesystem"); fs.State != situation.CoverageUnavailable || fs.Reason == "" {
		t.Errorf("duplicate filesystem = %+v, want unavailable malformed report", fs)
	}
}

func TestFractionalUnknownLossIsNotTruncatedIntoAClaim(t *testing.T) {
	st := openStore(t)
	e := engineOver(st, allTriggers())
	boot := testUUID(101)
	vm, _ := runningVM(t, st, testUUID(1), boot)
	heartbeat(t, st, vm.VMID, boot, testUUID(201), "1", time.Now().UTC(), []map[string]any{{
		"id": "filesystem", "state": "degraded", "unknown_loss_intervals": 1.5,
	}}, "10000000000")

	got, err := e.VMCoverage(t.Context(), vm)
	if err != nil {
		t.Fatal(err)
	}
	if fs := collectorByID(t, got, "filesystem"); fs.UnknownLossIntervals != nil || fs.State != situation.CoverageDegraded {
		t.Errorf("fractional loss = %+v, want degraded malformed report with unknown count", fs)
	}
}

func TestMissingUnknownLossCountCannotClaimHealthyCapture(t *testing.T) {
	st := openStore(t)
	e := engineOver(st, allTriggers())
	boot := testUUID(101)
	vm, _ := runningVM(t, st, testUUID(1), boot)
	heartbeat(t, st, vm.VMID, boot, testUUID(201), "1", time.Now().UTC(), []map[string]any{{
		"id": "filesystem", "state": "healthy", "dropped": "0",
	}}, "10000000000")

	got, err := e.VMCoverage(t.Context(), vm)
	if err != nil {
		t.Fatal(err)
	}
	if fs := collectorByID(t, got, "filesystem"); fs.State != situation.CoverageDegraded || fs.UnknownLossIntervals != nil {
		t.Errorf("missing loss count = %+v, want degraded with unknown count", fs)
	}
}

func TestUnsafeJSONUnknownLossCountIsNotPublished(t *testing.T) {
	st := openStore(t)
	e := engineOver(st, allTriggers())
	boot := testUUID(101)
	vm, _ := runningVM(t, st, testUUID(1), boot)
	heartbeat(t, st, vm.VMID, boot, testUUID(201), "1", time.Now().UTC(), []map[string]any{{
		"id": "filesystem", "state": "healthy", "dropped": "0",
		"unknown_loss_intervals": float64(9007199254740992),
	}}, "10000000000")

	got, err := e.VMCoverage(t.Context(), vm)
	if err != nil {
		t.Fatal(err)
	}
	if fs := collectorByID(t, got, "filesystem"); fs.UnknownLossIntervals != nil || fs.State != situation.CoverageDegraded {
		t.Errorf("unsafe JSON loss count = %+v, want unknown degraded report", fs)
	}
}

func TestStoppedVMDoesNotPublishStaleHostCollectorAsHealthy(t *testing.T) {
	st := openStore(t)
	e := engineOver(st, allTriggers())
	boot := testUUID(101)
	vm, op := runningVM(t, st, testUUID(1), boot)
	e.SetHostCoverageSource(coverageSource(func(context.Context, *store.VM) ([]situation.CollectorCoverage, error) {
		return []situation.CollectorCoverage{{ID: "flow", VMID: vm.VMID, BootID: boot, State: situation.CoverageHealthy}}, nil
	}))
	vm = stopVM(t, st, vm.VMID, op)

	got, err := e.VMCoverage(t.Context(), vm)
	if err != nil {
		t.Fatal(err)
	}
	if flow := collectorByID(t, got, "flow"); flow.State != situation.CoverageUnavailable {
		t.Errorf("stopped flow = %+v, want unavailable", flow)
	}
}

func TestStaleGuestHeartbeatDoesNotDemoteIndependentHostCollector(t *testing.T) {
	st := openStore(t)
	e := engineOver(st, allTriggers())
	boot := testUUID(101)
	vm, _ := runningVM(t, st, testUUID(1), boot)
	heartbeat(t, st, vm.VMID, boot, testUUID(201), "1", time.Now().UTC().Add(-time.Minute), nil, "10000000000")
	e.SetHostCoverageSource(coverageSource(func(context.Context, *store.VM) ([]situation.CollectorCoverage, error) {
		return []situation.CollectorCoverage{{ID: "flow", VMID: vm.VMID, BootID: boot, State: situation.CoverageHealthy}}, nil
	}))

	got, err := e.VMCoverage(t.Context(), vm)
	if err != nil {
		t.Fatal(err)
	}
	if flow := collectorByID(t, got, "flow"); flow.State != situation.CoverageHealthy {
		t.Errorf("host flow = %+v, want healthy despite stale guest channel", flow)
	}
}

func TestRingDropIsReportedWithoutMakingRecoveredChannelPermanentlyDegraded(t *testing.T) {
	st := openStore(t)
	e := engineOver(st, allTriggers())
	boot := testUUID(101)
	vm, _ := runningVM(t, st, testUUID(1), boot)
	heartbeat(t, st, vm.VMID, boot, testUUID(201), "1", time.Now().UTC(), nil, "10000000000")
	// The helper writes a real stored envelope; update its ring block by appending
	// the next source sequence with the cumulative loss value.
	vmID := vm.VMID
	heartbeatWithData(t, st, vmID, boot, testUUID(201), "2", map[string]any{
		"agent":   map[string]any{"heartbeat_interval_ns": "10000000000"},
		"ring":    map[string]any{"capacity": float64(1024), "queued": float64(0), "dropped": "100"},
		"sensors": []any{},
	})

	got, err := e.VMCoverage(t.Context(), vm)
	if err != nil {
		t.Fatal(err)
	}
	if got.Channel.State != situation.TelemetryHealthy || got.Channel.ObservedDropped == nil || *got.Channel.ObservedDropped != "100" {
		t.Errorf("channel = %+v, want healthy recovered channel retaining cumulative drops", got.Channel)
	}
	if !slices.Contains(got.Gaps, "channel:observed_loss") {
		t.Errorf("gaps = %v, want retained channel loss", got.Gaps)
	}
}
