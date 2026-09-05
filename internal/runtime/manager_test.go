// ABOUTME: Manager integration tests: TDD over the full lifecycle (create, action,
// ABOUTME: delete, reconcile) using real SQLite and the runtimetest fake.
package runtime_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/2389-research/observatory-v2/internal/config"
	"github.com/2389-research/observatory-v2/internal/events"
	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/runtime/runtimetest"
	"github.com/2389-research/observatory-v2/internal/store"
)

// openStore creates a real SQLite store in t.TempDir().
func openStoreForManager(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "vmobs.sqlite"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// testTemplate returns a minimal Template for tests.
func testTemplate() runtime.Template {
	return runtime.Template{
		TemplateID:             "tmpl-test",
		Description:            "Test template",
		GuestPrivilegeProfiles: []string{"unprivileged"},
		Sensors:                []string{"fanotify"},
		ProtocolVersions:       map[string]string{"guestd": "1"},
		Digest:                 "sha256:" + fmt.Sprintf("%064d", 1),
	}
}

// defaultCfg returns a minimal ManagerConfig with 2 parallel provisions.
func defaultCfg() runtime.ManagerConfig {
	adm := config.Admission{
		AllowMemoryOvercommit:       false,
		CPUOvercommitRatio:          1.0,
		ReserveHostCPUCores:         0,
		ReserveHostMemoryMinMiB:     0,
		ReserveHostMemoryFraction:   0,
		ReservePerVMHostOverheadMiB: 768,
		ReserveInspectionSlots:      0,
		ReserveInspectorMemoryMiB:   0,
		ReserveInspectorCPUCores:    0,
		ReserveInspectorScratchMiB:  0,
		MaxParallelProvisions:       2,
	}
	return runtime.ManagerConfig{
		Admission: adm,
		VMDefaults: config.VMDefaults{
			VCPUCount:        2,
			MemoryMiB:        2048,
			RootDiskMiB:      8192,
			WorkspaceDiskMiB: 10240,
			NetworkProfile:   "transport",
			NetworkPolicyID:  "transport-public-web",
			StopGraceSeconds: 5,
		},
		Templates: map[string]runtime.Template{
			"tmpl-test": testTemplate(),
		},
		Host: runtime.HostResources{
			TotalMemoryMiB:   131072, // 128 GiB — plenty
			CPUCores:         64,
			StateDiskFreeMiB: 1 << 20, // 1 TiB
		},
	}
}

// newManager builds a manager with the given fake runtime.
func newManager(t *testing.T, st *store.Store, rt runtime.Runtime) *runtime.Manager {
	t.Helper()
	mgr, err := runtime.NewManager(st, rt, defaultCfg())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })
	return mgr
}

// createReq returns a CreateRequest with sensible defaults.
func createReq(name string) runtime.CreateRequest {
	return runtime.CreateRequest{
		Name:       name,
		TemplateID: "tmpl-test",
	}
}

func TestManagerCreateAndLaunchHappyPath(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm, op, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("alpha"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if vm == nil || op == nil {
		t.Fatal("expected vm and op, got nil")
	}
	if vm.ObservedState != "provisioning" {
		t.Errorf("initial observed_state = %q, want provisioning", vm.ObservedState)
	}

	// Wait for the async launch job to finish.
	mgr.Close()

	vm2, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM after launch: %v", err)
	}
	if vm2.ObservedState != "running" {
		t.Errorf("observed_state after launch = %q, want running", vm2.ObservedState)
	}
	if vm2.Revision < 3 { // provisioning(1) → starting(2) → running(3)
		t.Errorf("revision = %d, want ≥ 3", vm2.Revision)
	}

	// Check event trail: vm.created + two state_changed events (provisioning→starting→running).
	result, err := queryEvents(t, st, "vm.state_changed", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) < 2 {
		t.Errorf("expected ≥2 vm.state_changed events, got %d", len(result))
	}
	// boot_id must appear in the provisioning→starting event.
	var foundBootID bool
	for _, e := range result {
		if _, ok := e.Data["boot_id"].(string); ok {
			foundBootID = true
		}
	}
	if !foundBootID {
		t.Error("no boot_id found in vm.state_changed events")
	}

	// Operation must be succeeded.
	op2, err := st.GetOperation(t.Context(), op.OperationID)
	if err != nil {
		t.Fatalf("GetOperation: %v", err)
	}
	if op2.State != "succeeded" {
		t.Errorf("operation state = %q, want succeeded", op2.State)
	}

	// Runtime received Launch.
	calls := fk.CallsFor(vm.VMID)
	foundLaunch := false
	for _, c := range calls {
		if c.Method == "Launch" {
			foundLaunch = true
		}
	}
	if !foundLaunch {
		t.Error("Launch not called on fake runtime")
	}
}

func TestManagerLaunchFailure(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	// Plant a Launch failure; we'll look up the VMID after create returns.
	// Use a custom fake that fails all Launch calls.
	st2 := openStoreForManager(t)
	fk2 := runtimetest.NewFake()
	mgr2, err := runtime.NewManager(st2, fk2, defaultCfg())
	if err != nil {
		t.Fatal(err)
	}
	defer mgr2.Close()

	vm, op, _, createErr := mgr2.CreateVM(t.Context(), "local_operator", createReq("beta"))
	if createErr != nil {
		t.Fatalf("CreateVM: %v", createErr)
	}
	fk2.FailNext("Launch", vm.VMID, fmt.Errorf("hypervisor error"))

	mgr2.Close()
	_ = op
	_ = mgr // original unused; suppress linter

	vm2, err := st2.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM after failure: %v", err)
	}
	if vm2.ObservedState != "failed" {
		t.Errorf("observed_state = %q, want failed after launch failure", vm2.ObservedState)
	}
	if vm2.FailureStage == nil {
		t.Error("failure_stage is nil, want a stage name")
	}

	// Compute reservation released; disk kept.
	res, err := st2.GetReservation(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetReservation: %v", err)
	}
	if !res.ComputeReleased {
		t.Error("compute_released should be true after launch failure")
	}
	if res.Released {
		t.Error("released should be false — disk stays until deleted")
	}
}

func TestManagerRuntimeUnavailable(t *testing.T) {
	// AT-001: if the runtime is unavailable, CreateVM must fail with a typed
	// error and NOTHING persisted (no vm row, no operation, no reservation).
	st := openStoreForManager(t)
	mgr := newManager(t, st, runtime.ForHost()) // darwin → unavailable

	vm, op, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("gamma"))
	if err == nil {
		t.Fatal("expected error from unavailable runtime, got nil")
	}
	var ue *runtime.UnavailableError
	if !errors.As(err, &ue) {
		t.Errorf("expected *UnavailableError, got %T: %v", err, err)
	}
	if vm != nil || op != nil {
		t.Error("expected nil vm/op when runtime unavailable")
	}
	vms, _ := st.ListVMs(t.Context(), store.VMQuery{})
	if len(vms) != 0 {
		t.Errorf("expected 0 vm rows, got %d after unavailable runtime", len(vms))
	}
}

// TestForHostPreflightSummaryAppended (L0-R12): when a PreflightSummary hook
// is wired to ForHost and the summary is non-empty, the UnavailableError reason
// includes the preflight summary. Existing AT-001 test is unaffected (no hook).
func TestForHostPreflightSummaryAppended(t *testing.T) {
	rt := runtime.ForHost(func() string { return "fail (arch_kvm)" })
	err := rt.Availability(t.Context())
	if err == nil {
		t.Fatal("ForHost(preflight hook) Availability returned nil on non-Linux")
	}
	var ue *runtime.UnavailableError
	if !errors.As(err, &ue) {
		t.Fatalf("expected *UnavailableError, got %T: %v", err, err)
	}
	if !strings.Contains(ue.Reason, "preflight: fail (arch_kvm)") {
		t.Errorf("reason = %q; want preflight suffix", ue.Reason)
	}
}

// TestForHostPreflightEmptySummaryOmitted: an empty summary from the hook
// must NOT append a "; preflight: " suffix (no noise in the reason string).
func TestForHostPreflightEmptySummaryOmitted(t *testing.T) {
	rt := runtime.ForHost(func() string { return "" })
	err := rt.Availability(t.Context())
	if err == nil {
		t.Fatal("ForHost Availability returned nil on non-Linux")
	}
	var ue *runtime.UnavailableError
	if !errors.As(err, &ue) {
		t.Fatalf("expected *UnavailableError, got %T", err)
	}
	if strings.Contains(ue.Reason, "preflight:") {
		t.Errorf("reason contains 'preflight:' even though summary was empty: %q", ue.Reason)
	}
}

func TestManagerTemplateUnknown(t *testing.T) {
	st := openStoreForManager(t)
	mgr := newManager(t, st, runtimetest.NewFake())

	_, _, _, err := mgr.CreateVM(t.Context(), "local_operator", runtime.CreateRequest{
		Name:       "delta",
		TemplateID: "tmpl-no-such",
	})
	var te *runtime.ErrTemplateUnknown
	if !errors.As(err, &te) {
		t.Fatalf("expected *ErrTemplateUnknown, got %T: %v", err, err)
	}
	if te.Requested != "tmpl-no-such" {
		t.Errorf("Requested = %q, want tmpl-no-such", te.Requested)
	}
	if len(te.KnownIDs) == 0 {
		t.Error("KnownIDs is empty — remediation needs known IDs")
	}
}

func TestManagerDefaultsApplied(t *testing.T) {
	st := openStoreForManager(t)
	mgr := newManager(t, st, runtimetest.NewFake())

	// Zero-valued resources should pick up VMDefaults.
	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", runtime.CreateRequest{
		Name:       "defaults-check",
		TemplateID: "tmpl-test",
		// No VCPUCount, MemoryMiB, etc.
	})
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if vm.VCPUCount != 2 {
		t.Errorf("VCPUCount = %d, want 2 (default)", vm.VCPUCount)
	}
	if vm.MemoryMiB != 2048 {
		t.Errorf("MemoryMiB = %d, want 2048 (default)", vm.MemoryMiB)
	}
	if vm.RootDiskMiB != 8192 {
		t.Errorf("RootDiskMiB = %d, want 8192 (default)", vm.RootDiskMiB)
	}
}

// TestManagerActionsCarryDesiredState: desired_state is the operator's stated
// intent, and observed_state drifting away from it is the signal the fleet page
// raises. A desired_state written once at create and never again turns that
// signal into a lie: every deliberately stopped VM reads "want running" for ever,
// and an operator who sees the flag on healthy VMs stops reading it.
//
// Each action's terminal transition is the one place that knows what the caller
// asked for, so each carries the new intent.
func TestManagerActionsCarryDesiredState(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm := launchedVM(t, st, mgr, "desired-state")
	vmID := vm.VMID
	if vm.DesiredState != "running" {
		t.Fatalf("desired_state after create = %q, want running", vm.DesiredState)
	}

	for _, step := range []struct {
		action  string
		desired string
	}{
		{"pause", "paused"},
		{"resume", "running"},
		{"stop", "stopped"},
		{"start", "running"},
		{"force_stop", "stopped"},
	} {
		if _, _, err := mgr.Action(t.Context(), vmID, step.action, nil); err != nil {
			t.Fatalf("%s: %v", step.action, err)
		}
		got, err := st.GetVM(t.Context(), vmID)
		if err != nil {
			t.Fatalf("GetVM after %s: %v", step.action, err)
		}
		if got.DesiredState != step.desired {
			t.Errorf("desired_state after %s = %q, want %q", step.action, got.DesiredState, step.desired)
		}
		if got.ObservedState != step.desired {
			t.Errorf("observed_state after %s = %q, want %q", step.action, got.ObservedState, step.desired)
		}
	}
}

// TestInterruptedStopStillRecordsIntent: an action states its intent on the
// first transition it makes, so a stop that dies between "stopping" and
// "stopped" leaves a row that still says what was asked for. Recording intent
// only on the terminal write would strand this VM at "stopping" apparently
// wanting to run — and the operator would be looking for a fault that isn't there.
func TestInterruptedStopStillRecordsIntent(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm := launchedVM(t, st, mgr, "interrupted-stop")
	fk.FailNext("Stop", vm.VMID, errors.New("vmm unreachable"))

	if _, _, err := mgr.Action(t.Context(), vm.VMID, "stop", nil); err == nil {
		t.Fatal("stop should fail when the runtime call fails")
	}

	got, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ObservedState != "stopping" {
		t.Fatalf("observed_state = %q, want stopping", got.ObservedState)
	}
	if got.DesiredState != "stopped" {
		t.Errorf("desired_state = %q, want stopped", got.DesiredState)
	}
}

// TestVMMExitLeavesDesiredStateAlone: a guest that shuts itself down while the
// operator wanted it running is exactly the drift the flag exists to report.
// NotifyVMMExit records what happened; it must never rewrite what was wanted.
func TestVMMExitLeavesDesiredStateAlone(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm := launchedVM(t, st, mgr, "self-shutdown")
	if err := mgr.NotifyVMMExit(t.Context(), vm.VMID, "", "guest_shutdown", true); err != nil {
		t.Fatalf("NotifyVMMExit: %v", err)
	}

	got, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ObservedState != "stopped" {
		t.Fatalf("observed_state = %q, want stopped", got.ObservedState)
	}
	if got.DesiredState != "running" {
		t.Errorf("desired_state = %q, want running — a self-stopped VM is drift, not intent", got.DesiredState)
	}
}

// TestDeleteSetsDesiredStateDeleted: the same rule at the end of life — a
// deleted VM whose row still says the operator wants it running would show as
// drift for as long as the record survives.
func TestDeleteSetsDesiredStateDeleted(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm := launchedVM(t, st, mgr, "delete-desired")
	if _, err := mgr.Delete(t.Context(), vm.VMID, true, nil); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	got, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ObservedState != "deleted" {
		t.Fatalf("observed_state = %q, want deleted", got.ObservedState)
	}
	if got.DesiredState != "deleted" {
		t.Errorf("desired_state = %q, want deleted", got.DesiredState)
	}
}

func TestManagerActionPauseKeepsReservation(t *testing.T) {
	// AT-013: paused VMs retain memory/disk reservations.
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("pause-test"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	mgr.Close() // wait for launch
	vmID := vm.VMID

	// Pause the VM.
	paused, _, err := mgr.Action(t.Context(), vmID, "pause", nil)
	if err != nil {
		t.Fatalf("pause: %v", err)
	}
	if paused.ObservedState != "paused" {
		t.Errorf("state after pause = %q, want paused", paused.ObservedState)
	}

	// Reservation compute must NOT be released.
	res, err := st.GetReservation(t.Context(), vmID)
	if err != nil {
		t.Fatal(err)
	}
	if res.ComputeReleased {
		t.Error("compute_released should be false after pause — paused VMs retain compute")
	}
}

// TestManagerActionRecordsFailureAfterCallerContextDies: every non-launch branch
// of doAction routes its errors through failAction on the context the action was
// already running, and the commonest reason an action fails is that this very
// context expired. Writing the verdict onto it records nothing: the operation
// stays "running" for ever, describing work that is over.
//
// The launch branch derives its own recovery context at the call site and is
// covered by TestStartRecordsFailureAfterOperationContextDies. This covers the
// seven other branches at the one place they share — failAction itself — through
// pause, which reaches it straight off the runtime call.
func TestManagerActionRecordsFailureAfterCallerContextDies(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm := launchedVM(t, st, mgr, "pause-bookkeeping")

	// Pause blocks; cancelling the caller is what ends it, and the fake then
	// returns ctx.Err(). The channel is deliberately never closed: if both it and
	// the context were ready the fake's select would pick a winner at random, and
	// this test would assert on a coin flip.
	fk.Block("Pause", vm.VMID)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type actionResult struct {
		op  *store.Operation
		err error
	}
	done := make(chan actionResult, 1)
	go func() {
		_, op, err := mgr.Action(ctx, vm.VMID, "pause", nil)
		done <- actionResult{op: op, err: err}
	}()

	waitForFakeCallCount(t, fk, vm.VMID, "Pause", 1)
	cancel()
	res := <-done

	if res.err == nil {
		t.Fatal("pause returned no error after its caller's context was cancelled")
	}
	if res.op == nil {
		t.Fatal("pause returned no operation: failAction wrote nothing and read nothing back")
	}
	if res.op.State != "failed" {
		t.Errorf("returned operation state = %q, want failed", res.op.State)
	}

	// The stored row is what an operator sees, so assert on it directly rather
	// than trusting the value handed back.
	stored, err := st.GetOperation(context.Background(), res.op.OperationID)
	if err != nil {
		t.Fatalf("GetOperation %d: %v", res.op.OperationID, err)
	}
	if stored.State != "failed" {
		t.Errorf("stored operation %d state = %q, want failed", stored.OperationID, stored.State)
	}

	// And nothing may be left stranded mid-flight for this VM.
	running, err := st.ListOperationsByState(context.Background(), "running")
	if err != nil {
		t.Fatalf("ListOperationsByState(running): %v", err)
	}
	for _, op := range running {
		if op.VMID != nil && *op.VMID == vm.VMID {
			t.Errorf("operation %d (%s) left in %q after the action returned", op.OperationID, op.Phase, op.State)
		}
	}
}

func TestManagerStopRecordsGracefulVsForced(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	// --- graceful stop ---
	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("stop-graceful"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	mgr.Close()

	stopped, _, err := mgr.Action(t.Context(), vm.VMID, "stop", nil)
	if err != nil {
		t.Fatalf("graceful stop: %v", err)
	}
	if stopped.ObservedState != "stopped" {
		t.Errorf("state = %q, want stopped", stopped.ObservedState)
	}
	// Check the vm.state_changed event has reason "graceful_stop".
	events, _ := queryEvents(t, st, "vm.state_changed", 20)
	foundGraceful := false
	for _, e := range events {
		if to, ok := e.Data["to"].(string); ok && to == "stopped" {
			if reason, ok := e.Data["reason"].(string); ok && reason == "graceful_stop" {
				foundGraceful = true
			}
		}
	}
	if !foundGraceful {
		t.Error("no vm.state_changed event with reason=graceful_stop found")
	}

	// --- forced stop: inject ForcedStop sentinel ---
	st2 := openStoreForManager(t)
	fk2 := runtimetest.NewFake()
	mgr2, _ := runtime.NewManager(st2, fk2, defaultCfg())
	defer mgr2.Close()

	vm2, _, _, _ := mgr2.CreateVM(t.Context(), "local_operator", createReq("stop-forced"))
	mgr2.Close()
	fk2.FailNext("Stop", vm2.VMID, &runtimetest.ForcedStop{})
	_, _, err = mgr2.Action(t.Context(), vm2.VMID, "stop", nil)
	if err != nil {
		t.Fatalf("forced stop: %v", err)
	}
	events2, _ := queryEvents(t, st2, "vm.state_changed", 20)
	foundForced := false
	for _, e := range events2 {
		if to, ok := e.Data["to"].(string); ok && to == "stopped" {
			if reason, ok := e.Data["reason"].(string); ok && reason == "forced_stop" {
				foundForced = true
			}
		}
	}
	if !foundForced {
		t.Error("no vm.state_changed event with reason=forced_stop found")
	}
}

// TestManagerStopSpendsRevisionPinOnce: a stop carrying the caller's revision
// pin must succeed. The pin belongs to the first transition (running→stopping);
// once that transition has bumped the revision, re-checking the same pin on the
// stopped transition can only ever fail. Every stop issued over HTTP carries a
// pin (internal/api/vms.go), so a double-spend turns a VM that really stopped
// into a 409 revision_mismatch and a failed operation.
func TestManagerStopSpendsRevisionPinOnce(t *testing.T) {
	cases := []struct {
		action string
		reason string
	}{
		{"stop", "graceful_stop"},
		{"force_stop", "forced_stop"},
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			st := openStoreForManager(t)
			fk := runtimetest.NewFake()
			mgr := newManager(t, st, fk)

			vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq(tc.action+"-pinned"))
			if err != nil {
				t.Fatalf("CreateVM: %v", err)
			}
			mgr.Close() // drain the launch goroutine so the VM is settled in running

			// The caller reads the current revision, then pins it — exactly what
			// GET /vms/{id} followed by POST /vms/{id}/actions does.
			current, err := st.GetVM(t.Context(), vm.VMID)
			if err != nil {
				t.Fatalf("GetVM: %v", err)
			}
			rev := current.Revision

			stopped, op, err := mgr.Action(t.Context(), vm.VMID, tc.action, &rev)
			if err != nil {
				t.Fatalf("%s pinned at revision %d: %v", tc.action, rev, err)
			}
			if stopped.ObservedState != "stopped" {
				t.Errorf("state = %q, want stopped", stopped.ObservedState)
			}
			if op == nil {
				t.Fatalf("%s returned no operation", tc.action)
			}
			if op.State != "succeeded" {
				t.Errorf("operation state = %q, want succeeded (error: %v)", op.State, op.ErrorMessage)
			}

			evts, err := queryEvents(t, st, "vm.state_changed", 20)
			if err != nil {
				t.Fatalf("query events: %v", err)
			}
			found := false
			for _, e := range evts {
				to, _ := e.Data["to"].(string)
				reason, _ := e.Data["reason"].(string)
				if to == "stopped" && reason == tc.reason {
					found = true
				}
			}
			if !found {
				t.Errorf("no vm.state_changed event with to=stopped reason=%s", tc.reason)
			}
		})
	}
}

// TestManagerStopStalePinIsRefusedBeforeTheRuntimeIsTouched: the sibling of
// TestManagerStopSpendsRevisionPinOnce. That test proves the pin isn't spent
// twice; this one proves it's still spent at all. A stale pin must be refused
// with a typed *store.RevisionMismatchError before rt.Stop/rt.ForceStop ever
// runs, and the VM row must be left exactly as it was.
func TestManagerStopStalePinIsRefusedBeforeTheRuntimeIsTouched(t *testing.T) {
	cases := []struct {
		action string
	}{
		{"stop"},
		{"force_stop"},
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			st := openStoreForManager(t)
			fk := runtimetest.NewFake()
			mgr := newManager(t, st, fk)

			vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq(tc.action+"-stale"))
			if err != nil {
				t.Fatalf("CreateVM: %v", err)
			}
			mgr.Close() // drain the launch goroutine so the VM is settled in running

			current, err := st.GetVM(t.Context(), vm.VMID)
			if err != nil {
				t.Fatalf("GetVM: %v", err)
			}
			stale := current.Revision - 1

			_, _, err = mgr.Action(t.Context(), vm.VMID, tc.action, &stale)
			if err == nil {
				t.Fatalf("%s pinned at stale revision %d: got nil error, want refusal", tc.action, stale)
			}
			var mismatch *store.RevisionMismatchError
			if !errors.As(err, &mismatch) {
				t.Fatalf("error is %T (%v), want *store.RevisionMismatchError", err, err)
			}
			if mismatch.Current != current.Revision {
				t.Errorf("mismatch.Current = %d, want %d", mismatch.Current, current.Revision)
			}

			for _, c := range fk.CallsFor(vm.VMID) {
				if c.Method == "Stop" || c.Method == "ForceStop" {
					t.Errorf("runtime was asked to %s despite the refused pin; calls: %v", c.Method, fk.CallsFor(vm.VMID))
				}
			}
			after, err := st.GetVM(t.Context(), vm.VMID)
			if err != nil {
				t.Fatalf("GetVM after refusal: %v", err)
			}
			if after.ObservedState != "running" || after.Revision != current.Revision {
				t.Errorf("after refusal: state %q revision %d, want running at revision %d",
					after.ObservedState, after.Revision, current.Revision)
			}
		})
	}
}

// TestManagerActionWrongStateIsInvalidTransition: an action the VM's current
// state does not allow is a caller-side mistake, so it must carry the state
// pair that explains it. An untyped error falls through the API's mapping to a
// 500 with cause storage_failure — a lie about whose fault it is (P-06).
func TestManagerActionWrongStateIsInvalidTransition(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("already-running"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	mgr.Close() // drain the launch goroutine so the VM is settled in running

	_, _, err = mgr.Action(t.Context(), vm.VMID, "start", nil)
	if err == nil {
		t.Fatal("start on a running VM returned no error")
	}
	var txn *store.InvalidTransitionError
	if !errors.As(err, &txn) {
		t.Fatalf("error is %T (%v), want *store.InvalidTransitionError", err, err)
	}
	if txn.From != "running" || txn.To != "starting" {
		t.Errorf("transition = %s→%s, want running→starting", txn.From, txn.To)
	}
}

// TestDeleteReleaseFailureIsTyped: a release that fails leaves real resources on
// the host — a live VMM, a jail chroot, privd's ledger entry — and the row at
// "deleting" so the operator can see it. An untyped error reaches the API as a
// 500 blaming storage, which sends them to the database instead. Observed on
// aibox03: a delete answered {"cause":"storage_failure"} while two firecracker
// processes were still running.
func TestDeleteReleaseFailureIsTyped(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm := launchedVM(t, st, mgr, "release-fails")
	fk.FailNext("Release", vm.VMID, errors.New("privd: invalid_state"))

	_, err := mgr.Delete(t.Context(), vm.VMID, true, nil)
	if err == nil {
		t.Fatal("delete returned no error when release failed")
	}
	var rel *runtime.ErrReleaseFailed
	if !errors.As(err, &rel) {
		t.Fatalf("error is %T (%v), want *runtime.ErrReleaseFailed", err, err)
	}
	if rel.VMID != vm.VMID {
		t.Errorf("VMID = %q, want %q", rel.VMID, vm.VMID)
	}
	if !strings.Contains(rel.Reason, "invalid_state") {
		t.Errorf("Reason = %q, should carry the runtime's own words", rel.Reason)
	}

	// The row must stay at "deleting": that is the record that resources survive.
	got, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ObservedState != "deleting" {
		t.Errorf("observed_state = %q, want deleting", got.ObservedState)
	}
}

// TestManagerActionRuntimeVerbFailureIsTyped: when a host verb fails — the VMM
// will not launch, the guest will not stop, the hypervisor refuses a pause —
// the fault is on the machine. An untyped error reaches the API's catch-all as
// a 500 blaming storage, the same lie ErrReleaseFailed was added to stop, so
// every verb Action can call names itself and the VM it failed on.
func TestManagerActionRuntimeVerbFailureIsTyped(t *testing.T) {
	boom := errors.New("firecracker: vsock probe timed out")

	cases := []struct {
		action string
		verb   string // the runtime method the fake fails
		prep   string // action that puts the VM in the state this one needs
		wantOp string
	}{
		{action: "pause", verb: "Pause", wantOp: "pause"},
		{action: "stop", verb: "Stop", wantOp: "stop"},
		{action: "force_stop", verb: "ForceStop", wantOp: "force_stop"},
		{action: "resume", verb: "Resume", prep: "pause", wantOp: "resume"},
		{action: "start", verb: "Launch", prep: "stop", wantOp: "launch"},
	}

	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			st := openStoreForManager(t)
			fk := runtimetest.NewFake()
			mgr := newManager(t, st, fk)

			vm := launchedVM(t, st, mgr, "verb-"+tc.action)
			if tc.prep != "" {
				if _, _, err := mgr.Action(t.Context(), vm.VMID, tc.prep, nil); err != nil {
					t.Fatalf("%s (to reach the state %s needs): %v", tc.prep, tc.action, err)
				}
			}
			fk.FailNext(tc.verb, vm.VMID, boom)

			_, _, err := mgr.Action(t.Context(), vm.VMID, tc.action, nil)
			if err == nil {
				t.Fatalf("%s returned no error when the runtime's %s failed", tc.action, tc.verb)
			}
			var opErr *runtime.ErrRuntimeOpFailed
			if !errors.As(err, &opErr) {
				t.Fatalf("error is %T (%v), want *runtime.ErrRuntimeOpFailed", err, err)
			}
			if opErr.Op != tc.wantOp {
				t.Errorf("Op = %q, want %q", opErr.Op, tc.wantOp)
			}
			if opErr.VMID != vm.VMID {
				t.Errorf("VMID = %q, want %q", opErr.VMID, vm.VMID)
			}
			if !errors.Is(err, boom) {
				t.Errorf("error %q drops the runtime's own words", err)
			}
		})
	}
}

// TestRuntimeVerbFailureKeepsUnavailableVisible: a runtime that cannot run at
// all is a different answer from a host that tried and failed — 501 against
// 500 — and naming the verb must not bury that. The unavailable error stays
// reachable through the wrap.
func TestRuntimeVerbFailureKeepsUnavailableVisible(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm := launchedVM(t, st, mgr, "pause-unsupported")
	fk.FailNext("Pause", vm.VMID, &runtime.UnavailableError{Reason: "pause not supported in M1a"})

	_, _, err := mgr.Action(t.Context(), vm.VMID, "pause", nil)
	var unavail *runtime.UnavailableError
	if !errors.As(err, &unavail) {
		t.Fatalf("error is %T (%v); an unavailable runtime must stay visible through the verb wrap", err, err)
	}
	if unavail.Reason != "pause not supported in M1a" {
		t.Errorf("Reason = %q, want the runtime's own reason", unavail.Reason)
	}
}

func TestManagerForceStopFromPaused(t *testing.T) {
	// §5.2: force-stop from paused must not wait for guest cooperation.
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("force-paused"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	mgr.Close()

	if _, _, err := mgr.Action(t.Context(), vm.VMID, "pause", nil); err != nil {
		t.Fatalf("pause: %v", err)
	}

	stopped, _, err := mgr.Action(t.Context(), vm.VMID, "force_stop", nil)
	if err != nil {
		t.Fatalf("force_stop from paused: %v", err)
	}
	if stopped.ObservedState != "stopped" {
		t.Errorf("state = %q, want stopped", stopped.ObservedState)
	}
}

func TestManagerRevisionMismatch(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("rev-check"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	mgr.Close()

	stale := int64(1) // revision is higher after launch
	_, _, err = mgr.Action(t.Context(), vm.VMID, "pause", &stale)
	if err == nil {
		t.Fatal("expected RevisionMismatchError, got nil")
	}
	var rm *store.RevisionMismatchError
	if !errors.As(err, &rm) {
		t.Errorf("expected *RevisionMismatchError, got %T: %v", err, err)
	}
	if rm.Current <= 1 {
		t.Errorf("current revision = %d, want > 1", rm.Current)
	}
}

func TestManagerStopDuringLaunchCleansUp(t *testing.T) {
	// §5.2: a stop request during provisioning cancels the launch.
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	cfg := defaultCfg()
	cfg.Admission.MaxParallelProvisions = 4
	mgr, err := runtime.NewManager(st, fk, cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Close()

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("race-stop"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	vmID := vm.VMID

	// Block the Launch call so the goroutine is mid-flight.
	launchGate := fk.Block("Launch", vmID)

	// Give the goroutine time to acquire the semaphore and start transitioning.
	time.Sleep(20 * time.Millisecond)

	// The stop action transitions provisioning→stopping atomically.
	// The launch goroutine will find ErrInvalidTransition on its next step.
	stopDone := make(chan error, 1)
	go func() {
		_, _, err := mgr.Action(t.Context(), vmID, "stop", nil)
		stopDone <- err
	}()

	// Unblock the launch.
	close(launchGate)

	// Wait for both goroutines.
	if err := <-stopDone; err != nil {
		// stop might fail if the launch goroutine won the race and got to "running".
		// Both outcomes are valid as long as we end in stopped or running (not stuck).
		t.Logf("stop action returned (may be racing): %v", err)
	}
	mgr.Close()

	vm2, err := st.GetVM(t.Context(), vmID)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	// Valid terminal states: stopped (stop won), running (launch won), or failed.
	switch vm2.ObservedState {
	case "stopped", "running", "failed":
	default:
		t.Errorf("unexpected state after race: %q", vm2.ObservedState)
	}
}

func TestManagerDeleteIdempotency(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("delete-test"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	mgr.Close()

	// Stop first, then delete twice.
	if _, _, err := mgr.Action(t.Context(), vm.VMID, "stop", nil); err != nil {
		t.Fatalf("stop: %v", err)
	}
	del1, err := mgr.Delete(t.Context(), vm.VMID, false, nil)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if del1.ObservedState != "deleted" {
		t.Errorf("state = %q, want deleted", del1.ObservedState)
	}
	// Second delete is idempotent.
	del2, err := mgr.Delete(t.Context(), vm.VMID, false, nil)
	if err != nil {
		t.Fatalf("second delete: %v", err)
	}
	if del2.ObservedState != "deleted" {
		t.Errorf("second delete state = %q, want deleted", del2.ObservedState)
	}

	// History (vm row) still exists.
	hist, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM after delete: %v", err)
	}
	if hist == nil {
		t.Error("vm row disappeared after delete — history must survive (SPEC §5.4)")
	}

	// vm.deleted event was emitted.
	events, _ := queryEvents(t, st, "vm.deleted", 5)
	if len(events) != 1 {
		t.Errorf("expected 1 vm.deleted event, got %d", len(events))
	}
}

func TestManagerDeleteLiveVMRequiresForce(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("delete-live"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	mgr.Close()

	// Delete running VM without force → ErrVMLive.
	_, err = mgr.Delete(t.Context(), vm.VMID, false, nil)
	if !errors.Is(err, store.ErrVMLive) {
		t.Errorf("expected ErrVMLive, got %v", err)
	}

	// Delete with force → succeeds.
	del, err := mgr.Delete(t.Context(), vm.VMID, true, nil)
	if err != nil {
		t.Fatalf("force delete: %v", err)
	}
	if del.ObservedState != "deleted" {
		t.Errorf("force delete state = %q, want deleted", del.ObservedState)
	}
}

// TestManagerForceDeleteSpendsRevisionPinOnce: a force delete carrying the VM's
// current revision must succeed. The pin is a precondition checked once, on the
// first transition the call makes (running→stopping); hanging it on the later
// →deleting transition — after two earlier transitions already bumped the
// revision — could only ever answer revision_mismatch.
func TestManagerForceDeleteSpendsRevisionPinOnce(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("delete-pinned"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	mgr.Close() // drain the launch goroutine so the revision below is settled

	current, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	rev := current.Revision

	del, err := mgr.Delete(t.Context(), vm.VMID, true, &rev)
	if err != nil {
		t.Fatalf("force delete pinned at revision %d: %v", rev, err)
	}
	if del.ObservedState != "deleted" {
		t.Errorf("force delete state = %q, want deleted", del.ObservedState)
	}
}

// TestManagerForceDeleteStalePinRefused: the pin must stay a precondition, not
// decoration — and a precondition is checked before the destructive act, not
// after. A revision that has already moved on is refused with a typed
// *store.RevisionMismatchError, the runtime is never asked to force-stop, and
// the VM row is left exactly as it was.
func TestManagerForceDeleteStalePinRefused(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("delete-stale"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	mgr.Close()

	current, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	stale := current.Revision - 1

	if _, err = mgr.Delete(t.Context(), vm.VMID, true, &stale); err == nil {
		t.Fatalf("force delete pinned at stale revision %d: got nil error, want refusal", stale)
	}
	var mismatch *store.RevisionMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("error is %T (%v), want *store.RevisionMismatchError", err, err)
	}
	if mismatch.Current != current.Revision {
		t.Errorf("mismatch.Current = %d, want %d", mismatch.Current, current.Revision)
	}

	for _, c := range fk.CallsFor(vm.VMID) {
		if c.Method == "ForceStop" {
			t.Errorf("runtime was asked to ForceStop despite the refused pin; calls: %v", fk.CallsFor(vm.VMID))
			break
		}
	}
	after, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM after refusal: %v", err)
	}
	if after.ObservedState != "running" || after.Revision != current.Revision {
		t.Errorf("after refusal: state %q revision %d, want running at revision %d",
			after.ObservedState, after.Revision, current.Revision)
	}
}

// TestManagerForceDeleteRuntimeFailureLeavesStopping: when rt.ForceStop fails
// for real, the row is already at "stopping" — the honest record of "we asked
// the VM to die and do not know how it ended". Deliberate, per the ordering
// rule: the state transition precedes the runtime side effect, exactly as
// doAction's stop does. Reconcile owns the recovery.
func TestManagerForceDeleteRuntimeFailureLeavesStopping(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("delete-rtfail"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	mgr.Close()

	fk.FailNext("ForceStop", vm.VMID, errors.New("kvm said no"))

	if _, err = mgr.Delete(t.Context(), vm.VMID, true, nil); err == nil {
		t.Fatalf("force delete with failing ForceStop: got nil error, want failure")
	}
	var opErr *runtime.ErrRuntimeOpFailed
	if !errors.As(err, &opErr) {
		t.Fatalf("error is %T (%v), want *runtime.ErrRuntimeOpFailed", err, err)
	}
	if opErr.Op != "force_stop" || opErr.VMID != vm.VMID {
		t.Errorf("error names %s on %s, want force_stop on %s", opErr.Op, opErr.VMID, vm.VMID)
	}
	if !strings.Contains(opErr.Error(), "kvm said no") {
		t.Errorf("error = %q, should carry the runtime's own words", opErr.Error())
	}

	after, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM after failed force-stop: %v", err)
	}
	if after.ObservedState != "stopping" {
		t.Errorf("state after failed force-stop = %q, want stopping", after.ObservedState)
	}
}

func TestManagerReconcile(t *testing.T) {
	// Simulate VMs left in various transitional states by a crashed controller,
	// then start a new manager and verify Reconcile cleans them up.
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()

	// Insert VMs directly via CreateVM (which leaves them in provisioning),
	// then manually transition to various states before starting the manager.
	createRaw := func(name string) string {
		vm, _, _, err := st.CreateVMWithOperation(t.Context(), store.CreateVMInput{
			VMID:             uuid.NewString(),
			Name:             name,
			Owner:            "local_operator",
			TemplateID:       "tmpl-test",
			TemplateDigest:   "sha256:" + fmt.Sprintf("%064d", 1),
			VCPUCount:        2,
			MemoryMiB:        2048,
			RootDiskMiB:      8192,
			WorkspaceDiskMiB: 10240,
			MemoryTotalMiB:   2048 + 768,
			NetworkProfile:   "transport",
			NetworkPolicyID:  "transport-public-web",
			Labels:           map[string]string{},
			Kind:             "vm.create",
			RequestHash:      uuid.NewString(),
			Admit:            func(store.ReservationTotals) error { return nil },
		})
		if err != nil {
			t.Fatalf("createRaw %s: %v", name, err)
		}
		return vm.VMID
	}

	transition := func(vmID, to, reason string, releaseC, releaseAll bool) {
		if _, err := st.TransitionVM(t.Context(), store.TransitionInput{
			VMID:           vmID,
			To:             to,
			Reason:         reason,
			OperationID:    0,
			ReleaseCompute: releaseC,
			ReleaseAll:     releaseAll,
		}); err != nil {
			t.Fatalf("transition %s→%s: %v", vmID, to, err)
		}
	}

	// Prepare VMs in various states.
	provID := createRaw("provisioning-vm") // stays in provisioning
	startID := createRaw("starting-vm")    // advance to starting
	runID := createRaw("running-vm")       // advance to running
	pausedID := createRaw("paused-vm")     // advance to paused
	stoppingID := createRaw("stopping-vm") // advance to stopping
	deletingID := createRaw("deleting-vm") // advance to deleting

	transition(startID, "starting", "launch", false, false)
	transition(runID, "starting", "launch", false, false)
	transition(runID, "running", "launch_complete", false, false)
	transition(pausedID, "starting", "launch", false, false)
	transition(pausedID, "running", "launch_complete", false, false)
	transition(pausedID, "paused", "pause", false, false)
	transition(stoppingID, "starting", "launch", false, false)
	transition(stoppingID, "running", "launch_complete", false, false)
	transition(stoppingID, "stopping", "stop_requested", false, false)
	transition(deletingID, "starting", "launch", false, false)
	transition(deletingID, "running", "launch_complete", false, false)
	transition(deletingID, "stopping", "stop_requested", false, false)
	transition(deletingID, "stopped", "graceful_stop", true, false)
	transition(deletingID, "deleting", "delete_requested", false, false)

	// Start a fresh manager — Reconcile runs in NewManager.
	mgr, err := runtime.NewManager(st, fk, defaultCfg())
	if err != nil {
		t.Fatalf("NewManager (reconcile): %v", err)
	}
	defer mgr.Close()

	check := func(vmID, wantState string) {
		t.Helper()
		vm, err := st.GetVM(t.Context(), vmID)
		if err != nil {
			t.Fatalf("GetVM %s: %v", vmID, err)
		}
		if vm.ObservedState != wantState {
			t.Errorf("vm %s: state = %q, want %q", vmID, vm.ObservedState, wantState)
		}
	}

	check(provID, "failed")
	check(startID, "failed")
	check(runID, "failed")
	check(pausedID, "failed")
	check(stoppingID, "stopped")
	check(deletingID, "deleted")

	// R1 invariant: a delete finalized by Reconcile must release the runtime's
	// resources first, exactly as Delete does. Without the release the row reads
	// "deleted" while the network allocation, the stage dir and
	// <StateDir>/vms/<id>/ survive it, and every surviving manifest burns a slot
	// against MaxSlots that no later restart returns.
	if !calledFor(fk, deletingID, "Release") {
		t.Errorf("Reconcile finalized the delete without calling Release (calls: %v)", fk.MethodCalls())
	}
}

// calledFor reports whether fk recorded a call of method against vmID.
func calledFor(fk *runtimetest.Fake, vmID, method string) bool {
	for _, c := range fk.CallsFor(vmID) {
		if c.Method == method {
			return true
		}
	}
	return false
}

// newDeletingVM creates a VM and walks it to "deleting", the state a controller
// crash mid-delete leaves behind. Returns its vm_id.
func newDeletingVM(t *testing.T, st *store.Store, name string) string {
	t.Helper()
	vm, _, _, err := st.CreateVMWithOperation(t.Context(), store.CreateVMInput{
		VMID:             uuid.NewString(),
		Name:             name,
		Owner:            "local_operator",
		TemplateID:       "tmpl-test",
		TemplateDigest:   "sha256:" + fmt.Sprintf("%064d", 1),
		VCPUCount:        2,
		MemoryMiB:        2048,
		RootDiskMiB:      8192,
		WorkspaceDiskMiB: 10240,
		MemoryTotalMiB:   2048 + 768,
		NetworkProfile:   "transport",
		NetworkPolicyID:  "transport-public-web",
		Labels:           map[string]string{},
		Kind:             "vm.create",
		RequestHash:      uuid.NewString(),
		Admit:            func(store.ReservationTotals) error { return nil },
	})
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	steps := []struct {
		to       string
		reason   string
		releaseC bool
	}{
		{"starting", "launch", false},
		{"running", "launch_complete", false},
		{"stopping", "stop_requested", false},
		{"stopped", "graceful_stop", true},
		{"deleting", "delete_requested", false},
	}
	for _, s := range steps {
		if _, err := st.TransitionVM(t.Context(), store.TransitionInput{
			VMID:           vm.VMID,
			To:             s.to,
			Reason:         s.reason,
			OperationID:    0,
			ReleaseCompute: s.releaseC,
		}); err != nil {
			t.Fatalf("transition %s\u2192%s: %v", vm.VMID, s.to, err)
		}
	}
	return vm.VMID
}

// TestManagerReconcileDeletingToleratesUnavailableRelease: Reconcile runs at
// startup, when the runtime may legitimately be absent. An *UnavailableError
// from Release must not wedge the delete — the row still reaches "deleted",
// matching Delete's own tolerance.
func TestManagerReconcileDeletingToleratesUnavailableRelease(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	vmID := newDeletingVM(t, st, "reconcile-release-unavailable")

	// Inject before NewManager: Reconcile runs inside it.
	fk.FailNext("Release", vmID, &runtime.UnavailableError{Reason: "test: runtime unavailable"})

	mgr, err := runtime.NewManager(st, fk, defaultCfg())
	if err != nil {
		t.Fatalf("NewManager (reconcile): %v", err)
	}
	defer mgr.Close()

	if !calledFor(fk, vmID, "Release") {
		t.Errorf("Reconcile did not attempt Release (calls: %v)", fk.MethodCalls())
	}
	vm, err := st.GetVM(t.Context(), vmID)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.ObservedState != "deleted" {
		t.Errorf("state = %q, want deleted (UnavailableError must be tolerated)", vm.ObservedState)
	}
}

// TestManagerReconcileDeletingKeepsRowOnReleaseError: any other Release failure
// leaves the row at "deleting" for the next restart to retry. A "deleted" row
// written over surviving jail resources is the lie this test exists to prevent.
func TestManagerReconcileDeletingKeepsRowOnReleaseError(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	vmID := newDeletingVM(t, st, "reconcile-release-error")

	fk.FailNext("Release", vmID, errors.New("disk full"))

	mgr, err := runtime.NewManager(st, fk, defaultCfg())
	if err != nil {
		t.Fatalf("NewManager (reconcile): %v", err)
	}
	defer mgr.Close()

	if !calledFor(fk, vmID, "Release") {
		t.Errorf("Reconcile did not attempt Release (calls: %v)", fk.MethodCalls())
	}
	vm, err := st.GetVM(t.Context(), vmID)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.ObservedState != "deleting" {
		t.Errorf("state = %q, want deleting (a failed release must not finalize the delete)", vm.ObservedState)
	}
}

func TestManagerParallelLaunchCapped(t *testing.T) {
	// MaxParallelProvisions=2: with 5 blocked launches, at most 2 should ever be in
	// "starting" (= holding a semaphore slot) at the same time.
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	cfg := defaultCfg()
	cfg.Admission.MaxParallelProvisions = 2
	mgr, err := runtime.NewManager(st, fk, cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Close()

	const n = 5
	gates := make([]chan struct{}, n)
	for i := range n {
		vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq(fmt.Sprintf("parallel-%d", i)))
		if err != nil {
			t.Fatalf("CreateVM %d: %v", i, err)
		}
		gates[i] = fk.Block("Launch", vm.VMID)
	}

	// Poll until the semaphore is visibly full (MaxParallelProvisions VMs reach
	// "starting"), then snapshot the peak. A VM enters "starting" after acquiring
	// the semaphore slot and before calling Launch; with blocked gates it stays
	// there until we unblock.
	max := cfg.Admission.MaxParallelProvisions
	deadline := time.Now().Add(2 * time.Second)
	var peakStarting int
	for time.Now().Before(deadline) {
		vms, err := st.ListVMs(t.Context(), store.VMQuery{Limit: 10})
		if err != nil {
			t.Fatalf("ListVMs: %v", err)
		}
		starting := 0
		for _, v := range vms {
			if v.ObservedState == "starting" {
				starting++
			}
		}
		if starting > peakStarting {
			peakStarting = starting
		}
		if peakStarting >= max {
			break // semaphore is full — enough evidence
		}
		time.Sleep(5 * time.Millisecond)
	}
	if peakStarting > max {
		t.Errorf("peak concurrent in-semaphore launches = %d, want ≤ %d", peakStarting, max)
	}

	// Unblock all gates so Close() can drain cleanly.
	for _, g := range gates {
		close(g)
	}
}

func TestManagerCapacity(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	cap0, err := mgr.Capacity(t.Context())
	if err != nil {
		t.Fatalf("Capacity: %v", err)
	}
	if cap0.UsableMemoryMiB <= 0 {
		t.Errorf("UsableMemoryMiB = %d, want > 0", cap0.UsableMemoryMiB)
	}
	if cap0.ReservedMemoryMiB != 0 {
		t.Errorf("ReservedMemoryMiB = %d, want 0 before any create", cap0.ReservedMemoryMiB)
	}

	// Create a VM; capacity changes.
	_, _, _, err = mgr.CreateVM(t.Context(), "local_operator", createReq("cap-check"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	cap1, err := mgr.Capacity(t.Context())
	if err != nil {
		t.Fatalf("Capacity after create: %v", err)
	}
	if cap1.ReservedMemoryMiB <= 0 {
		t.Errorf("ReservedMemoryMiB after create = %d, want > 0", cap1.ReservedMemoryMiB)
	}
	if cap1.FreeMemoryMiB >= cap0.FreeMemoryMiB {
		t.Errorf("FreeMemoryMiB %d >= initial %d — free should decrease after create",
			cap1.FreeMemoryMiB, cap0.FreeMemoryMiB)
	}
}

// queryEvents returns events of the given kind, for assertions.
func queryEvents(t *testing.T, st *store.Store, kind string, limit int) ([]*events.Envelope, error) {
	t.Helper()
	result, err := st.Query(t.Context(), store.Query{Kind: kind, Limit: limit})
	if err != nil {
		return nil, err
	}
	return result.Events, nil
}

// TestCloseGateStopsNewWork: goroutines enqueued after Close starts must not
// start; goroutines enqueued before must complete. Run with -race.
func TestCloseGateStopsNewWork(t *testing.T) {
	m := newManager(t, openStoreForManager(t), runtimetest.NewFake())
	started := make(chan struct{})
	release := make(chan struct{})
	if ok := m.GoTracked(func() { close(started); <-release }); !ok {
		t.Fatal("goTracked refused work before Close")
	}
	<-started

	closeDone := make(chan struct{})
	go func() { close(release); m.Close(); close(closeDone) }()
	<-closeDone

	if ok := m.GoTracked(func() { t.Error("work started after Close") }); ok {
		t.Fatal("goTracked accepted work after Close")
	}
}

func TestManagerCreateVMReplayNoRelaunch(t *testing.T) {
	// AT-006 corollary: a replayed create returns the stored result and must
	// not enqueue another launch — a relaunch could revive a stopped VM.
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	ikey := "vm-replay-key"
	req := createReq("replay-vm")
	req.IdempotencyKey = &ikey

	vm1, _, replayed1, err := mgr.CreateVM(t.Context(), "local_operator", req)
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if replayed1 {
		t.Error("first CreateVM replayed = true, want false")
	}

	vm2, _, replayed2, err := mgr.CreateVM(t.Context(), "local_operator", req)
	if err != nil {
		t.Fatalf("CreateVM replay: %v", err)
	}
	if !replayed2 {
		t.Error("second CreateVM replayed = false, want true")
	}
	if vm2.VMID != vm1.VMID {
		t.Errorf("replay VMID %s != original %s", vm2.VMID, vm1.VMID)
	}

	mgr.Close() // drain launch goroutines before counting
	launches := 0
	for _, m := range fk.MethodCalls() {
		if m == "Launch" {
			launches++
		}
	}
	if launches != 1 {
		t.Errorf("Launch calls = %d, want 1 (none from the replay)", launches)
	}
}

// TestManagerDeleteCallsRelease: Delete must call Release on every delete path
// (R1 controller ruling). Verifies Release is called once for stopped→deleted.
func TestManagerDeleteCallsRelease(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("release-on-delete"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	mgr.Close()

	// Stop then delete — Release must be called.
	if _, _, err := mgr.Action(t.Context(), vm.VMID, "stop", nil); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if _, err := mgr.Delete(t.Context(), vm.VMID, false, nil); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Fake must have recorded a Release call.
	gotRelease := false
	for _, c := range fk.Calls {
		if c.Method == "Release" && c.VMID == vm.VMID {
			gotRelease = true
			break
		}
	}
	if !gotRelease {
		t.Errorf("Delete did not call Release (calls: %v)", fk.MethodCalls())
	}
}

// TestManagerDeleteForceCallsRelease: force-delete on a live VM must also call Release.
func TestManagerDeleteForceCallsRelease(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("release-force-delete"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	mgr.Close()

	if _, err := mgr.Delete(t.Context(), vm.VMID, true, nil); err != nil {
		t.Fatalf("force delete: %v", err)
	}

	gotRelease := false
	for _, c := range fk.Calls {
		if c.Method == "Release" && c.VMID == vm.VMID {
			gotRelease = true
			break
		}
	}
	if !gotRelease {
		t.Errorf("Force-delete did not call Release (calls: %v)", fk.MethodCalls())
	}
}

// TestManagerDeleteToleratesUnavailableRelease: if Release returns *UnavailableError,
// delete must still succeed (tolerate unavailable runtime per R1 ruling).
func TestManagerDeleteToleratesUnavailableRelease(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("release-unavailable"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	mgr.Close()

	if _, _, err := mgr.Action(t.Context(), vm.VMID, "stop", nil); err != nil {
		t.Fatalf("stop: %v", err)
	}

	// Inject *UnavailableError for Release.
	fk.FailNext("Release", vm.VMID, &runtime.UnavailableError{Reason: "test: runtime unavailable"})

	del, err := mgr.Delete(t.Context(), vm.VMID, false, nil)
	if err != nil {
		t.Errorf("Delete should tolerate UnavailableError from Release, got: %v", err)
	}
	if del != nil && del.ObservedState != "deleted" {
		t.Errorf("state = %q, want deleted", del.ObservedState)
	}
}

// TestManagerDeleteFailsOnReleaseError: if Release returns a non-Unavailable error,
// delete must fail (VM row must not reach deleted while jail resources remain).
func TestManagerDeleteFailsOnReleaseError(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("release-error"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	mgr.Close()

	if _, _, err := mgr.Action(t.Context(), vm.VMID, "stop", nil); err != nil {
		t.Fatalf("stop: %v", err)
	}

	// Inject a real error for Release.
	releaseErr := errors.New("disk full")
	fk.FailNext("Release", vm.VMID, releaseErr)

	_, err = mgr.Delete(t.Context(), vm.VMID, false, nil)
	if err == nil {
		t.Error("Delete should fail when Release returns a non-Unavailable error")
	}

	// VM must not be in deleted state.
	vmAfter, _ := st.GetVM(t.Context(), vm.VMID)
	if vmAfter != nil && vmAfter.ObservedState == "deleted" {
		t.Error("VM reached deleted state despite Release error — jail resources may remain")
	}
}

// TestNotifyVMMExitRunningToFailed verifies that NotifyVMMExit on a running VM
// with graceful=false transitions it to failed with the failure stage, the
// reason and the compute release all recorded.
//
// Pattern: create+launch on one manager, drain workers with Close(), then call
// NotifyVMMExit on the same manager (synchronous, no goroutines needed — the
// close gate does not affect synchronous store writes).
func TestNotifyVMMExitRunningToFailed(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr, err := runtime.NewManager(st, fk, defaultCfg())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("notify-failed"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	// Drain the launch goroutine.
	mgr.Close()

	vm2, _ := st.GetVM(t.Context(), vm.VMID)
	if vm2.ObservedState != "running" {
		t.Fatalf("pre-condition: want running, got %q", vm2.ObservedState)
	}

	// mgr is closed (goroutines drained) but the store is still open.
	// NotifyVMMExit is synchronous and does not require the close gate.
	reason := "reconcile: vmm pid 1234 gone"
	if err := mgr.NotifyVMMExit(t.Context(), vm.VMID, "", reason, false); err != nil {
		t.Fatalf("NotifyVMMExit: %v", err)
	}

	vm3, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM after notify: %v", err)
	}
	if vm3.ObservedState != "failed" {
		t.Errorf("state after non-graceful exit: want failed, got %q", vm3.ObservedState)
	}
	// The reason is the caller's string stored verbatim — nothing generated in
	// it, no timestamp or ID — so pin the whole string. A substring match also
	// accepts a reason the manager wrapped or truncated on the way through.
	if vm3.FailureReason == nil || *vm3.FailureReason != reason {
		t.Errorf("failure_reason: want %q, got %s", reason, quoteStr(vm3.FailureReason))
	}
	if vm3.FailureStage == nil || *vm3.FailureStage != "vmm_exit" {
		t.Errorf("failure_stage: want %q, got %s", "vmm_exit", quoteStr(vm3.FailureStage))
	}
	res, err := st.GetReservation(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetReservation: %v", err)
	}
	if !res.ComputeReleased {
		t.Error("compute_released should be true once the VM failed — a failed VM holds no compute")
	}
}

// TestNotifyVMMExitRunningToStopped verifies that graceful=true transitions to
// stopped and releases the VM's compute reservation — reaching stopped while
// still holding compute would leak host capacity and is the failure this guards.
func TestNotifyVMMExitRunningToStopped(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr, err := runtime.NewManager(st, fk, defaultCfg())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("notify-stopped"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	mgr.Close()

	vm2, _ := st.GetVM(t.Context(), vm.VMID)
	if vm2.ObservedState != "running" {
		t.Fatalf("pre-condition: want running, got %q", vm2.ObservedState)
	}

	if err := mgr.NotifyVMMExit(t.Context(), vm.VMID, "", "clean shutdown", true); err != nil {
		t.Fatalf("NotifyVMMExit graceful: %v", err)
	}

	vm3, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM after graceful notify: %v", err)
	}
	if vm3.ObservedState != "stopped" {
		t.Errorf("state after graceful exit: want stopped, got %q", vm3.ObservedState)
	}
	res, err := st.GetReservation(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetReservation: %v", err)
	}
	if !res.ComputeReleased {
		t.Error("compute_released should be true once the VM stopped — a stopped VM holds no compute")
	}
}

// TestNotifyVMMExitPausedToStopped verifies that a paused VM reporting a
// graceful exit still reaches stopped with its compute reservation released.
// §5.2 has no direct paused→stopped edge, so this rides the same
// through-stopping path the running case uses; a paused VM holds its compute
// until it goes terminal (AT-013), which is why the release is asserted and not
// just the state.
func TestNotifyVMMExitPausedToStopped(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("notify-paused-stopped"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	mgr.Close() // wait for launch

	paused, _, err := mgr.Action(t.Context(), vm.VMID, "pause", nil)
	if err != nil {
		t.Fatalf("pause: %v", err)
	}
	if paused.ObservedState != "paused" {
		t.Fatalf("pre-condition: want paused, got %q", paused.ObservedState)
	}

	if err := mgr.NotifyVMMExit(t.Context(), vm.VMID, "", "clean shutdown while paused", true); err != nil {
		t.Fatalf("NotifyVMMExit graceful: %v", err)
	}

	after, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM after graceful notify: %v", err)
	}
	if after.ObservedState != "stopped" {
		t.Errorf("state after graceful exit from paused: want stopped, got %q", after.ObservedState)
	}
	res, err := st.GetReservation(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetReservation: %v", err)
	}
	if !res.ComputeReleased {
		t.Error("compute_released should be true once the VM stopped — a stopped VM holds no compute")
	}
}

// TestNotifyVMMExitPausedToFailed verifies that a paused VM whose VMM exit was
// not graceful reaches failed with the stage and reason recorded, and its
// compute released. The failure stage is what tells an operator the VM died at
// the VMM rather than during provisioning, so it is part of the contract.
func TestNotifyVMMExitPausedToFailed(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("notify-paused-failed"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	mgr.Close() // wait for launch

	paused, _, err := mgr.Action(t.Context(), vm.VMID, "pause", nil)
	if err != nil {
		t.Fatalf("pause: %v", err)
	}
	if paused.ObservedState != "paused" {
		t.Fatalf("pre-condition: want paused, got %q", paused.ObservedState)
	}

	reason := "vmm_exited observed by runner: pid gone while paused"
	if err := mgr.NotifyVMMExit(t.Context(), vm.VMID, "", reason, false); err != nil {
		t.Fatalf("NotifyVMMExit non-graceful: %v", err)
	}

	after, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM after non-graceful notify: %v", err)
	}
	if after.ObservedState != "failed" {
		t.Errorf("state after non-graceful exit from paused: want failed, got %q", after.ObservedState)
	}
	if after.FailureStage == nil || *after.FailureStage != "vmm_exit" {
		t.Errorf("failure_stage: want %q, got %s", "vmm_exit", quoteStr(after.FailureStage))
	}
	if after.FailureReason == nil || *after.FailureReason != reason {
		t.Errorf("failure_reason: want %q, got %s", reason, quoteStr(after.FailureReason))
	}
	res, err := st.GetReservation(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetReservation: %v", err)
	}
	if !res.ComputeReleased {
		t.Error("compute_released should be true once the VM failed — a failed VM holds no compute")
	}
}

// TestNotifyVMMExitSecondCallNoOp verifies that a second NotifyVMMExit on an
// already-terminal VM returns nil and does not change state.
func TestNotifyVMMExitSecondCallNoOp(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr, err := runtime.NewManager(st, fk, defaultCfg())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("notify-noop"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	mgr.Close()

	// First call: non-graceful exit → failed.
	if err := mgr.NotifyVMMExit(t.Context(), vm.VMID, "", "first exit", false); err != nil {
		t.Fatalf("first NotifyVMMExit: %v", err)
	}
	vm2, _ := st.GetVM(t.Context(), vm.VMID)
	firstState := vm2.ObservedState

	// Second call on already-terminal: must return nil, state unchanged.
	if err := mgr.NotifyVMMExit(t.Context(), vm.VMID, "", "replay", false); err != nil {
		t.Errorf("second NotifyVMMExit (terminal) should be no-op, got: %v", err)
	}
	vm3, _ := st.GetVM(t.Context(), vm.VMID)
	if vm3.ObservedState != firstState {
		t.Errorf("state changed after second call: was %q, now %q", firstState, vm3.ObservedState)
	}
}

// TestNotifyVMMExitProvisioningGracefulGoesToFailed verifies that a provisioning-state VM
// routes to failed regardless of graceful=true (§5.2: provisioning→stopped is not a valid
// transition; the VMM never reached running so failed is the honest outcome).
func TestNotifyVMMExitEarlyLifecycleGracefulGoesToFailed(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr, err := runtime.NewManager(st, fk, defaultCfg())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("notify-early-graceful"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}

	// Park the launch worker inside rt.Launch. The worker writes
	// provisioning→starting BEFORE calling Launch, so once the Launch call is
	// visible in the fake's log the VM is frozen in "starting" until unblock.
	unblock := fk.Block("Launch", vm.VMID)
	launchSeen := func() bool {
		return slices.ContainsFunc(fk.CallsFor(vm.VMID), func(c runtimetest.Call) bool {
			return c.Method == "Launch"
		})
	}
	deadline := time.Now().Add(5 * time.Second)
	for !launchSeen() {
		if time.Now().After(deadline) {
			t.Fatal("launch worker never reached rt.Launch")
		}
		time.Sleep(2 * time.Millisecond)
	}
	vmNow, _ := st.GetVM(t.Context(), vm.VMID)
	if vmNow == nil || vmNow.ObservedState != "starting" {
		t.Fatalf("pre-condition: want starting (parked in Launch), got %+v", vmNow)
	}

	// graceful=true on an early-lifecycle VM must still route to failed, not
	// stopped — the VM never reached running, so the launch did not complete.
	if err := mgr.NotifyVMMExit(t.Context(), vm.VMID, "", "early exit", true); err != nil {
		t.Fatalf("NotifyVMMExit: %v", err)
	}

	vmAfter, _ := st.GetVM(t.Context(), vm.VMID)
	if vmAfter.ObservedState != "failed" {
		t.Errorf("provisioning + graceful=true: want failed, got %q", vmAfter.ObservedState)
	}
	if vmAfter.FailureReason == nil {
		t.Error("failure_reason should be set, got nil")
	}

	// Unblock and drain so the test doesn't leak the goroutine.
	close(unblock)
	mgr.Close()
}

// TestNotifyVMMExitIgnoresPreviousBoot reproduces what the M1 gate hit: a VM
// stopped and started again inside one importer poll interval. The spool
// importer delivers the first boot's vmm_exited seconds after the second boot
// has already begun, and a boot-blind reader fails a VM that is starting
// perfectly well. The notice names the boot it observed; a boot that is over
// says nothing about the one running now.
func TestNotifyVMMExitIgnoresPreviousBoot(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr, err := runtime.NewManager(st, fk, defaultCfg())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(mgr.Close)

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("notify-stale-boot"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	running := waitVMState(t, st, vm.VMID, "running")
	firstBoot := running.CurrentBootID
	if firstBoot == "" {
		t.Fatal("pre-condition: the launched VM records no boot id")
	}

	if _, _, err := mgr.Action(t.Context(), vm.VMID, "stop", nil); err != nil {
		t.Fatalf("stop: %v", err)
	}

	// Park the restart inside rt.Launch so the VM sits in "starting" on its
	// second boot — exactly where the gate's VM was when the stale notice landed.
	unblock := fk.Block("Launch", vm.VMID)
	startDone := make(chan error, 1)
	go func() {
		_, _, actErr := mgr.Action(context.Background(), vm.VMID, "start", nil)
		startDone <- actErr
	}()
	starting := waitVMState(t, st, vm.VMID, "starting")
	if starting.CurrentBootID == firstBoot {
		t.Fatalf("pre-condition: restart reused boot id %q", firstBoot)
	}

	// The first boot's exit, arriving late. It is true, and it is old.
	if err := mgr.NotifyVMMExit(t.Context(), vm.VMID, firstBoot, "vmm_exited observed by pidfile_stat", true); err != nil {
		t.Fatalf("NotifyVMMExit: %v", err)
	}
	after, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if after.ObservedState != "starting" {
		t.Errorf("state after a previous boot's exit notice: want starting, got %q (reason %s)", after.ObservedState, quoteStr(after.FailureReason))
	}

	// The current boot's exit is still acted on: this is a filter on staleness,
	// not a mute button.
	if err := mgr.NotifyVMMExit(t.Context(), vm.VMID, after.CurrentBootID, "vmm_exited observed by pidfile_stat", true); err != nil {
		t.Fatalf("NotifyVMMExit current boot: %v", err)
	}
	current, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM after current-boot notice: %v", err)
	}
	if current.ObservedState != "failed" {
		t.Errorf("state after the current boot's exit notice: want failed, got %q", current.ObservedState)
	}

	close(unblock)
	<-startDone
}

// TestNotifyVMMExitWithoutBootIDStillActs covers the observer that names no
// boot: Reconcile stats the runner that is live right now, so its findings are
// about whatever boot is current and must not be filtered away.
func TestNotifyVMMExitWithoutBootIDStillActs(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr, err := runtime.NewManager(st, fk, defaultCfg())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("notify-no-boot"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	mgr.Close()

	if err := mgr.NotifyVMMExit(t.Context(), vm.VMID, "", "reconcile: vmm pid 1234 gone", false); err != nil {
		t.Fatalf("NotifyVMMExit: %v", err)
	}
	after, _ := st.GetVM(t.Context(), vm.VMID)
	if after.ObservedState != "failed" {
		t.Errorf("state after a boot-less exit notice: want failed, got %q", after.ObservedState)
	}
}

// waitVMState polls the store until vmID reaches state, and fails the test if
// it does not. The manager runs launches on workers, so the caller cannot read
// the row immediately after the call that starts one.
func waitVMState(t *testing.T, st *store.Store, vmID, state string) *store.VM {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last *store.VM
	for time.Now().Before(deadline) {
		vm, err := st.GetVM(context.Background(), vmID)
		if err != nil {
			t.Fatalf("GetVM: %v", err)
		}
		if vm.ObservedState == state {
			return vm
		}
		last = vm
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("vm %s never reached %q (last %q)", vmID, state, last.ObservedState)
	return nil
}

// quoteStr renders a *string for a failure message: the quoted value, or
// "<nil>". Printing the pointer gives an address, which says nothing about what
// the manager actually recorded.
func quoteStr(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%q", *p)
}

// waitForFakeCall blocks until the fake records a call of method against vmID.
// Pair it with fk.Block(method, vmID): once the call is in the log, the manager
// is parked inside that runtime call and every write it makes beforehand has
// committed.
func waitForFakeCall(t *testing.T, fk *runtimetest.Fake, vmID, method string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if slices.ContainsFunc(fk.CallsFor(vmID), func(c runtimetest.Call) bool {
			return c.Method == method
		}) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("runtime never reached %s for vm %s", method, vmID)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// waitForObservedState blocks until vmID's observed_state reaches want. Unlike
// mgr.Close(), it leaves the manager alive: the start action runs on a context
// detached from its parent but still tied to the manager's, so a closed manager
// cancels every later start before its first query.
func waitForObservedState(t *testing.T, st *store.Store, vmID, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	last := ""
	for {
		vm, err := st.GetVM(t.Context(), vmID)
		if err != nil {
			t.Fatalf("GetVM while waiting for %s: %v", want, err)
		}
		if vm.ObservedState == want {
			return
		}
		last = vm.ObservedState
		if time.Now().After(deadline) {
			t.Fatalf("vm %s never reached %s (last observed %s)", vmID, want, last)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// lastStateChangeReason returns the reason of the newest vm.state_changed event
// among the first 100 for vmID — the query orders ascending, so the newest event
// is the last of that page rather than of the whole history. Test VMs never reach
// 100 state changes. Store-synthesized vm.* events ride the host stream with a
// NULL vm_id column; store.Query matches data.vm_id as well, so the VMID filter
// finds them.
func lastStateChangeReason(t *testing.T, st *store.Store, vmID string) string {
	t.Helper()
	res, err := st.Query(t.Context(), store.Query{VMID: &vmID, Kind: "vm.state_changed", Limit: 100})
	if err != nil {
		t.Fatalf("Query vm.state_changed: %v", err)
	}
	if len(res.Events) == 0 {
		t.Fatalf("no vm.state_changed events for vm %s", vmID)
	}
	last := res.Events[len(res.Events)-1]
	reason, _ := last.Data["reason"].(string)
	return reason
}

// parkStopInRuntime starts a stop action on vmID and returns once the manager is
// parked inside rt.Stop — the VM frozen in "stopping", the action still owning
// the row. release() unblocks rt.Stop and returns the action's outcome.
func parkStopInRuntime(t *testing.T, st *store.Store, mgr *runtime.Manager, fk *runtimetest.Fake, vmID string) (parked *store.VM, release func() (*store.Operation, error)) {
	t.Helper()
	gate := fk.Block("Stop", vmID)
	type outcome struct {
		op  *store.Operation
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		_, op, err := mgr.Action(t.Context(), vmID, "stop", nil)
		done <- outcome{op: op, err: err}
	}()
	waitForFakeCall(t, fk, vmID, "Stop")

	// doAction writes running→stopping before calling rt.Stop, so the row is
	// already parked by the time the Stop call shows up in the fake's log.
	parked, err := st.GetVM(t.Context(), vmID)
	if err != nil {
		t.Fatalf("GetVM while parked in rt.Stop: %v", err)
	}
	if parked.ObservedState != "stopping" {
		t.Fatalf("pre-condition: want stopping (parked in rt.Stop), got %q", parked.ObservedState)
	}
	return parked, func() (*store.Operation, error) {
		close(gate)
		res := <-done
		return res.op, res.err
	}
}

// TestNotifyVMMExitStoppingIsNoOp verifies the importer leaves a "stopping" VM
// alone. A stopping VM has an initiator — an action, a delete, or a batch wave —
// which holds the graceful-vs-forced determination and will record the terminal
// transition itself. NotifyVMMExit exists to catch VMM exits nobody asked for.
func TestNotifyVMMExitStoppingIsNoOp(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm := launchedVM(t, st, mgr, "notify-stopping")
	parked, release := parkStopInRuntime(t, st, mgr, fk, vm.VMID)

	if err := mgr.NotifyVMMExit(t.Context(), vm.VMID, "", "vmm_exited observed by runner", true); err != nil {
		t.Fatalf("NotifyVMMExit on a stopping VM: %v", err)
	}

	after, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM after notify: %v", err)
	}
	if after.ObservedState != "stopping" {
		t.Errorf("state after notify: want stopping (untouched), got %q", after.ObservedState)
	}
	if after.Revision != parked.Revision {
		t.Errorf("revision after notify: want %d (untouched), got %d", parked.Revision, after.Revision)
	}
	if after.LastEventID != parked.LastEventID {
		t.Errorf("last_event_id after notify: want %d (no event written), got %d", parked.LastEventID, after.LastEventID)
	}
	if got := lastStateChangeReason(t, st, vm.VMID); got != "stop_requested" {
		t.Errorf("newest state-change reason: want stop_requested (the initiator's), got %q", got)
	}

	if _, err := release(); err != nil {
		t.Fatalf("stop action after the notice: %v", err)
	}
}

// TestStopActionOutlivesConcurrentVMMExitNotice is the live-gate race made
// deterministic: rt.Stop holds the window open for seconds tearing down the
// jail while the spool importer ticks and sees the guest's vm.vmm_exited
// envelope. The action must still succeed, still end stopped, and still record
// its own graceful-vs-forced determination.
func TestStopActionOutlivesConcurrentVMMExitNotice(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm := launchedVM(t, st, mgr, "stop-vs-importer")
	_, release := parkStopInRuntime(t, st, mgr, fk, vm.VMID)

	// The importer fires while the action is inside rt.Stop.
	if err := mgr.NotifyVMMExit(t.Context(), vm.VMID, "", "vmm_exited observed by runner", true); err != nil {
		t.Fatalf("NotifyVMMExit during rt.Stop: %v", err)
	}

	op, err := release()
	if err != nil {
		t.Fatalf("stop action lost the race with the importer: %v", err)
	}
	if op == nil || op.State != "succeeded" {
		t.Errorf("stop operation state: want succeeded, got %+v", op)
	}

	final, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM after stop: %v", err)
	}
	if final.ObservedState != "stopped" {
		t.Errorf("state after stop: want stopped, got %q", final.ObservedState)
	}
	// The determination only rt.Stop knows must survive on the terminal transition.
	if got := lastStateChangeReason(t, st, vm.VMID); got != "graceful_stop" {
		t.Errorf("terminal state-change reason: want graceful_stop, got %q", got)
	}
}

func TestManagerStopStartRestoresCapacity(t *testing.T) {
	// A stop hands the VM's compute back to admission and a start must take it
	// again. Left unfixed, every stop/start round trip permanently hides one
	// VM's RAM and vCPU from the check that keeps the host from overcommitting.
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("cycle"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	waitForObservedState(t, st, vm.VMID, "running")
	vmID := vm.VMID

	capacity := func(when string) runtime.CapacitySnapshot {
		t.Helper()
		snap, err := mgr.Capacity(t.Context())
		if err != nil {
			t.Fatalf("Capacity %s: %v", when, err)
		}
		return snap
	}

	running := capacity("while running")
	if _, _, err := mgr.Action(t.Context(), vmID, "stop", nil); err != nil {
		t.Fatalf("stop: %v", err)
	}
	stopped := capacity("while stopped")
	if stopped.ReservedMemoryMiB >= running.ReservedMemoryMiB {
		t.Fatalf("stop released nothing: reserved memory %d MiB before, %d MiB after",
			running.ReservedMemoryMiB, stopped.ReservedMemoryMiB)
	}

	if _, _, err := mgr.Action(t.Context(), vmID, "start", nil); err != nil {
		t.Fatalf("start: %v", err)
	}
	restarted := capacity("after the restart")

	if restarted.ReservedMemoryMiB != running.ReservedMemoryMiB {
		t.Errorf("reserved memory after restart = %d MiB, want %d MiB",
			restarted.ReservedMemoryMiB, running.ReservedMemoryMiB)
	}
	if restarted.ReservedVCPU != running.ReservedVCPU {
		t.Errorf("reserved vcpu after restart = %d, want %d",
			restarted.ReservedVCPU, running.ReservedVCPU)
	}
	if restarted.FreeMemoryMiB != running.FreeMemoryMiB {
		t.Errorf("free memory after restart = %d MiB, want %d MiB — the page and the "+
			"admission check read this number", restarted.FreeMemoryMiB, running.FreeMemoryMiB)
	}
	if restarted.ActiveVMs != running.ActiveVMs {
		t.Errorf("active_vms after restart = %d, want %d", restarted.ActiveVMs, running.ActiveVMs)
	}

	res, err := st.GetReservation(t.Context(), vmID)
	if err != nil {
		t.Fatalf("GetReservation: %v", err)
	}
	if res.ComputeReleased {
		t.Error("compute_released is still set on a running VM")
	}
}

func TestManagerStartRefusedWhenCapacityWentElsewhere(t *testing.T) {
	// The memory a stop released is real, free memory: another VM may take it.
	// The start that wants it back has to ask, and a refusal must leave the VM
	// stopped with a durable operation naming the shortfall — not parked in
	// "starting" with a launch already under way.
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()

	// Room for exactly two VMs of the default size (2048 + 768 overhead each).
	cfg := defaultCfg()
	cfg.Host.TotalMemoryMiB = 2 * (2048 + 768)
	mgr, err := runtime.NewManager(st, fk, cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })

	first, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("first"))
	if err != nil {
		t.Fatalf("CreateVM first: %v", err)
	}
	second, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("second"))
	if err != nil {
		t.Fatalf("CreateVM second: %v", err)
	}
	waitForObservedState(t, st, first.VMID, "running")
	waitForObservedState(t, st, second.VMID, "running")

	// Stop the first, then spend its memory on a third VM.
	if _, _, err := mgr.Action(t.Context(), first.VMID, "stop", nil); err != nil {
		t.Fatalf("stop first: %v", err)
	}
	if _, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("third")); err != nil {
		t.Fatalf("CreateVM third should fit in the memory the stop released: %v", err)
	}

	_, op, err := mgr.Action(t.Context(), first.VMID, "start", nil)
	var refusal *store.AdmissionRefusal
	if !errors.As(err, &refusal) {
		t.Fatalf("start err = %v, want *store.AdmissionRefusal — the host has no room left", err)
	}
	if !strings.Contains(refusal.Message, "memory") {
		t.Errorf("refusal names %q, want the memory dimension", refusal.Message)
	}

	back, err := st.GetVM(t.Context(), first.VMID)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if back.ObservedState != "stopped" {
		t.Errorf("observed_state after a refused start = %q, want stopped", back.ObservedState)
	}
	if op == nil {
		t.Fatal("a refused start recorded no operation")
	}
	if op.State != "failed" {
		t.Errorf("operation state = %q, want failed", op.State)
	}
	if op.ErrorCause == nil || *op.ErrorCause != "insufficient_capacity" {
		got := "<nil>"
		if op.ErrorCause != nil {
			got = *op.ErrorCause
		}
		t.Errorf("operation error_cause = %s, want insufficient_capacity", got)
	}
}

func TestManagerStartDoesNotDoubleCountDisk(t *testing.T) {
	// A stop releases compute and keeps disk, so the reservation row still holds
	// this VM's disk while it is stopped. The start must ask admission for
	// memory and vCPU only: asking for the disk again would count it twice and
	// refuse a restart that fits on a host with no spare disk at all.
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()

	cfg := defaultCfg()
	// Room for exactly one VM's disk (8192 root + 10240 workspace) and nothing more.
	cfg.Host.StateDiskFreeMiB = cfg.VMDefaults.RootDiskMiB + cfg.VMDefaults.WorkspaceDiskMiB
	mgr, err := runtime.NewManager(st, fk, cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("tight-disk"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	waitForObservedState(t, st, vm.VMID, "running")

	if _, _, err := mgr.Action(t.Context(), vm.VMID, "stop", nil); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if _, _, err := mgr.Action(t.Context(), vm.VMID, "start", nil); err != nil {
		t.Fatalf("start on a disk-full host: %v — the VM's own disk was never released, "+
			"so the start must not ask for it again", err)
	}

	snap, err := mgr.Capacity(t.Context())
	if err != nil {
		t.Fatalf("Capacity: %v", err)
	}
	wantDisk := cfg.VMDefaults.RootDiskMiB + cfg.VMDefaults.WorkspaceDiskMiB
	if snap.ReservedDiskMiB != wantDisk {
		t.Errorf("reserved disk after a stop/start = %d MiB, want %d MiB", snap.ReservedDiskMiB, wantDisk)
	}
}
