// ABOUTME: Manager integration tests: TDD over the full lifecycle (create, action,
// ABOUTME: delete, reconcile) using real SQLite and the runtimetest fake.
package runtime_test

import (
	"errors"
	"fmt"
	"path/filepath"
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
		KernelImage:            "/images/vmlinux",
		RootImage:              "/images/rootfs.img",
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
// with graceful=false transitions it to failed with the reason recorded.
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
	if err := mgr.NotifyVMMExit(t.Context(), vm.VMID, reason, false); err != nil {
		t.Fatalf("NotifyVMMExit: %v", err)
	}

	vm3, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM after notify: %v", err)
	}
	if vm3.ObservedState != "failed" {
		t.Errorf("state after non-graceful exit: want failed, got %q", vm3.ObservedState)
	}
	if vm3.FailureReason == nil || !strings.Contains(*vm3.FailureReason, "reconcile") {
		t.Errorf("failure_reason should contain reason, got %v", vm3.FailureReason)
	}
}

// TestNotifyVMMExitRunningToStopped verifies that graceful=true transitions to stopped.
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

	if err := mgr.NotifyVMMExit(t.Context(), vm.VMID, "clean shutdown", true); err != nil {
		t.Fatalf("NotifyVMMExit graceful: %v", err)
	}

	vm3, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM after graceful notify: %v", err)
	}
	if vm3.ObservedState != "stopped" {
		t.Errorf("state after graceful exit: want stopped, got %q", vm3.ObservedState)
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
	if err := mgr.NotifyVMMExit(t.Context(), vm.VMID, "first exit", false); err != nil {
		t.Fatalf("first NotifyVMMExit: %v", err)
	}
	vm2, _ := st.GetVM(t.Context(), vm.VMID)
	firstState := vm2.ObservedState

	// Second call on already-terminal: must return nil, state unchanged.
	if err := mgr.NotifyVMMExit(t.Context(), vm.VMID, "replay", false); err != nil {
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
func TestNotifyVMMExitProvisioningGracefulGoesToFailed(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr, err := runtime.NewManager(st, fk, defaultCfg())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("notify-prov-graceful"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}

	// Block Launch so the VM stays in provisioning.
	unblock := fk.Block("Launch", vm.VMID)

	// Confirm provisioning before we call NotifyVMMExit.
	vmNow, _ := st.GetVM(t.Context(), vm.VMID)
	if vmNow == nil || vmNow.ObservedState != "provisioning" {
		t.Fatalf("pre-condition: want provisioning, got %q", vmNow.ObservedState)
	}

	// graceful=true on a provisioning VM must still route to failed, not stopped.
	if err := mgr.NotifyVMMExit(t.Context(), vm.VMID, "early exit", true); err != nil {
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
