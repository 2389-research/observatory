// ABOUTME: Exercises live cleanup retries against SQLite and the owned runtime boundary.
// ABOUTME: Stalled work must recover without changing active operation outcomes.
package runtime_test

import (
	"context"
	"errors"
	"fmt"
	"github.com/2389-research/observatory/internal/runtime"
	"github.com/2389-research/observatory/internal/runtime/runtimetest"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestCleanupRetryResumesDeleteWithoutRestart(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	vmID, _ := failedVMAfterLaunch(t, st, fk, "retry-delete")
	mgr := newManager(t, st, fk)
	fk.FailNext("Release", vmID, errors.New("temporary release failure"))
	if _, err := mgr.Delete(t.Context(), vmID, false, nil); err == nil {
		t.Fatal("expected stalled release")
	}
	if err := mgr.RetryCleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	vm, err := st.GetVM(t.Context(), vmID)
	if err != nil {
		t.Fatal(err)
	}
	if vm.ObservedState != "deleted" {
		t.Fatalf("state = %s; want deleted", vm.ObservedState)
	}
	r, err := st.GetReservation(t.Context(), vmID)
	if err != nil || !r.Released {
		t.Fatalf("reservation = %+v, %v", r, err)
	}
}

func TestCleanupRetryReleasesFailedLaunchDebt(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	vmID, _ := failedVMAfterLaunch(t, st, fk, "retry-failed")
	mgr := newManager(t, st, fk)
	if err := mgr.RetryCleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	vm, err := st.GetVM(t.Context(), vmID)
	if err != nil || vm.ObservedState != "failed" {
		t.Fatalf("VM = %+v, %v", vm, err)
	}
	r, err := st.GetReservation(t.Context(), vmID)
	if err != nil || !r.Released {
		t.Fatalf("reservation = %+v, %v", r, err)
	}
}

func TestCleanupRetryLeavesActiveStopOperationAlone(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)
	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("retry-active-stop"))
	if err != nil {
		t.Fatal(err)
	}
	mgr.WaitForTest()
	unblock := fk.Block("ForceStop", vm.VMID)
	done := make(chan error, 1)
	go func() { _, _, err := mgr.Action(t.Context(), vm.VMID, "force_stop", nil); done <- err }()
	waitForObservedState(t, st, vm.VMID, "stopping")
	if err := mgr.RetryCleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	current, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil || current.ObservedState != "stopping" {
		t.Fatalf("active stop changed: %+v %v", current, err)
	}
	select {
	case err := <-done:
		t.Fatalf("active stop completed early: %v", err)
	default:
	}
	close(unblock)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCleanupRetryUsesFreshProofAndRetainsReservation(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)
	vmID := stoppingVM(t, st, "fresh-proof")
	fk.FailNext("ForceStop", vmID, &runtime.ErrStopNotProven{VMID: vmID, Reason: "identity unknown"})
	if err := mgr.RetryCleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	vm, _ := st.GetVM(t.Context(), vmID)
	reservation, _ := st.GetReservation(t.Context(), vmID)
	if vm.ObservedState != "stopping" || reservation.ComputeReleased {
		t.Fatalf("unproven stop settled: %+v %+v", vm, reservation)
	}
	if len(cleanupFailures(t, st, vmID)) != 1 {
		t.Fatal("missing actionable failure")
	}
	if err := mgr.RetryCleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	vm, _ = st.GetVM(t.Context(), vmID)
	if vm.ObservedState != "stopped" {
		t.Fatalf("state = %s", vm.ObservedState)
	}
}

func TestCleanupRetryShutdownCancelsHostWork(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)
	vmID := stoppingVM(t, st, "retry-shutdown")
	unblock := fk.Block("ForceStop", vmID)
	defer close(unblock)
	done := make(chan error, 1)
	go func() { done <- mgr.RetryCleanup(context.Background()) }()
	deadline := time.After(time.Second)
	for !calledFor(fk, vmID, "ForceStop") {
		select {
		case <-deadline:
			t.Fatal("retry did not enter host work")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	mgr.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("retry outlived manager drain")
	}
	if err := mgr.RetryCleanup(t.Context()); err == nil {
		t.Fatalf("closed retry = %v", err)
	}
}

func TestCleanupRetryTimerRecoversWithoutRestart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := openStoreForManager(t)
		fk := runtimetest.NewFake()
		mgr := newManager(t, st, fk)
		vmID := stoppingVM(t, st, "automatic-retry")
		time.Sleep(31 * time.Second)
		synctest.Wait()
		vm, err := st.GetVM(t.Context(), vmID)
		if err != nil || vm.ObservedState != "stopped" {
			t.Fatalf("timer did not settle stop: %+v %v", vm, err)
		}
		mgr.Close()
	})
}

func TestCleanupRetryDoesNotFailActiveLaunch(t *testing.T) {
	st := openStoreForManager(t)
	rt := &cancellationRuntime{Runtime: runtimetest.NewFake(), entered: make(chan context.Context, 1), rescue: make(chan struct{})}
	mgr, err := runtime.NewManager(st, rt, defaultCfg())
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	vm, op, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("retry-active-launch"))
	if err != nil {
		t.Fatal(err)
	}
	<-rt.entered
	if err := mgr.RetryCleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	current, err := st.GetOperation(t.Context(), op.OperationID)
	if err != nil || current.State != "running" {
		t.Fatalf("active operation changed: %+v %v", current, err)
	}
	currentVM, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil || currentVM.ObservedState != "starting" {
		t.Fatalf("active VM changed: %+v %v", currentVM, err)
	}
}

func TestCleanupRetrySkipsDeleteOwner(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	vmID, _ := failedVMAfterLaunch(t, st, fk, "retry-owned-delete")
	mgr := newManager(t, st, fk)
	unblock := fk.Block("Release", vmID)
	done := make(chan error, 1)
	go func() { _, err := mgr.Delete(t.Context(), vmID, false, nil); done <- err }()
	deadline := time.After(time.Second)
	for !calledFor(fk, vmID, "Release") {
		select {
		case <-deadline:
			close(unblock)
			t.Fatal("delete did not enter release")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	before := len(fk.CallsFor(vmID))
	if err := mgr.RetryCleanup(t.Context()); err != nil {
		close(unblock)
		t.Fatal(err)
	}
	if got := len(fk.CallsFor(vmID)); got != before {
		t.Errorf("retry entered owned delete: calls %d -> %d", before, got)
	}
	close(unblock)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type staleCleanupRuntime struct {
	runtime.Runtime
	entered chan struct{}
	once    sync.Once
}

func (r *staleCleanupRuntime) ForceStop(ctx context.Context, vmID string) error {
	stale := false
	r.once.Do(func() { stale = true; close(r.entered) })
	if stale {
		<-ctx.Done()
		return nil // A successful host result can race cancellation.
	}
	return r.Runtime.ForceStop(ctx, vmID)
}

func TestCleanupRetryYieldsToForegroundAndDiscardsStaleResult(t *testing.T) {
	st := openStoreForManager(t)
	rt := &staleCleanupRuntime{Runtime: runtimetest.NewFake(), entered: make(chan struct{})}
	mgr, err := runtime.NewManager(st, rt, defaultCfg())
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	vmID := stoppingVM(t, st, "retry-yield")
	vm, _ := st.GetVM(t.Context(), vmID)
	done := make(chan error, 1)
	go func() { done <- mgr.RetryCleanup(t.Context()) }()
	<-rt.entered
	// The foreground claim cancels retry, then reads current state. The retry's
	// late nil result must not spend the revision supplied by this caller.
	result, op, err := mgr.Action(t.Context(), vmID, "force_stop", &vm.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if result.ObservedState != "stopped" || op.State != "succeeded" {
		t.Fatalf("foreground result: %+v %+v", result, op)
	}
	<-done
}

func TestCleanupRetryPagesStalledWork(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)
	var last string
	for i := 0; i < 17; i++ {
		last = stoppingVM(t, st, fmt.Sprintf("retry-page-%d", i))
	}
	if err := mgr.RetryCleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	vm, _ := st.GetVM(t.Context(), last)
	if vm.ObservedState != "stopping" {
		t.Fatal("one pass exceeded its 16-row bound")
	}
	if err := mgr.RetryCleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	vm, _ = st.GetVM(t.Context(), last)
	if vm.ObservedState != "stopped" {
		t.Fatal("next page did not reach stalled VM")
	}
}

func TestCleanupRetrySettlesStoppedDebtWithoutDiscardingRestartDisks(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)
	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("retry-stopped-debt"))
	if err != nil {
		t.Fatal(err)
	}
	mgr.WaitForTest()
	fk.FailNext("ForceStop", vm.VMID, &runtime.ErrCleanupPending{VMID: vm.VMID, Resource: "jail", Reason: "busy"})
	if _, _, err := mgr.Action(t.Context(), vm.VMID, "force_stop", nil); err != nil {
		t.Fatal(err)
	}
	mgr.Close()
	mgr = newManager(t, st, fk) // The debt marker survives manager replacement.
	before := len(fk.CallsFor(vm.VMID))
	if err := mgr.RetryCleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	verbs := verbsSince(fk, vm.VMID, before)
	if len(verbs) != 1 || verbs[0] != "ForceStop" {
		t.Fatalf("stopped debt retry = %v, want ForceStop only", verbs)
	}
	reservation, _ := st.GetReservation(t.Context(), vm.VMID)
	if reservation.Released || !reservation.ComputeReleased {
		t.Fatalf("restart reservations changed: %+v", reservation)
	}
	before = len(fk.CallsFor(vm.VMID))
	if err := mgr.RetryCleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := len(fk.CallsFor(vm.VMID)); got != before {
		t.Fatal("settled debt retried again")
	}
}

func TestDeleteUnavailableDoesNotReleaseLiveCompute(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)
	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("delete-unavailable"))
	if err != nil {
		t.Fatal(err)
	}
	mgr.WaitForTest()
	fk.FailNext("ForceStop", vm.VMID, &runtime.UnavailableError{Reason: "privd socket missing"})
	if _, err := mgr.Delete(t.Context(), vm.VMID, true, nil); err == nil {
		t.Fatal("delete claimed success without host evidence")
	}
	r, _ := st.GetReservation(t.Context(), vm.VMID)
	if r.ComputeReleased || r.Released {
		t.Fatalf("unavailable released resources: %+v", r)
	}
}

func TestCleanupRetryBoundsFailureReason(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)
	vmID := stoppingVM(t, st, "bounded-cleanup-reason")
	fk.FailNext("ForceStop", vmID, errors.New(strings.Repeat("x", 10000)))
	if err := mgr.RetryCleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	records := cleanupFailures(t, st, vmID)
	if len(records) != 1 {
		t.Fatalf("records=%d", len(records))
	}
	if reason := records[0]["reason"].(string); len(reason) > 2048 {
		t.Fatalf("reason bytes=%d", len(reason))
	}
}
