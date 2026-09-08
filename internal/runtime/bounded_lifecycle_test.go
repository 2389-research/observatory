// ABOUTME: Shutdown and launch deadline regressions against real SQLite.
// ABOUTME: The owned runtime seam exposes cancellation and cleanup evidence.
package runtime_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/2389-research/observatory/internal/lock"
	"github.com/2389-research/observatory/internal/runtime"
	"github.com/2389-research/observatory/internal/runtime/runtimetest"
	"github.com/2389-research/observatory/internal/store"
)

type cancellationRuntime struct {
	runtime.Runtime
	entered chan context.Context
	rescue  chan struct{}
}

func (r *cancellationRuntime) Launch(ctx context.Context, _ runtime.VMSpec) (*lock.Images, error) {
	r.entered <- ctx
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.rescue:
		return nil, context.Canceled
	}
}

func TestCloseCancelsActiveAndQueuedLaunches(t *testing.T) {
	st := openStoreForManager(t)
	rt := &cancellationRuntime{Runtime: runtimetest.NewFake(), entered: make(chan context.Context, 2), rescue: make(chan struct{})}
	cfg := defaultCfg()
	cfg.Admission.MaxParallelProvisions = 1
	mgr, err := runtime.NewManager(st, rt, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	first, firstOp, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("active"))
	if err != nil {
		t.Fatal(err)
	}
	launchCtx := <-rt.entered
	if _, ok := launchCtx.Deadline(); !ok {
		t.Error("initial launch has no deadline")
	}
	second, secondOp, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("queued"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { mgr.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		close(rt.rescue)
		<-done
		t.Fatal("Close did not cancel active launch before draining")
	}
	for _, id := range []string{first.VMID, second.VMID} {
		vm, err := st.GetVM(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		if vm.ObservedState != "failed" {
			t.Errorf("%s state=%s", id, vm.ObservedState)
		}
	}
	for _, id := range []int64{firstOp.OperationID, secondOp.OperationID} {
		op, err := st.GetOperation(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		if op.State != "failed" {
			t.Errorf("op %d state=%s", id, op.State)
		}
	}
}

func TestClosingManagerRejectsSynchronousMutations(t *testing.T) {
	st := openStoreForManager(t)
	mgr := newManager(t, st, runtimetest.NewFake())
	mgr.Close()
	if _, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("too-late")); err == nil {
		t.Fatal("create admitted after Close")
	}
}

func TestLaunchCleanupFailureKeepsCompute(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	fk.FailCall("Launch", 1, context.DeadlineExceeded)
	fk.FailCall("ForceStop", 1, &runtime.ErrStopNotProven{VMID: "unknown", Reason: "host request pending"})
	mgr := newManager(t, st, fk)
	vm, op, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("uncertain"))
	if err != nil {
		t.Fatal(err)
	}
	waitForObservedState(t, st, vm.VMID, "failed")
	res, err := st.GetReservation(t.Context(), vm.VMID)
	if err != nil {
		t.Fatal(err)
	}
	if res.ComputeReleased || res.Released {
		t.Fatal("unproven cleanup released reservation")
	}
	_ = op
}

func TestBatchCloseFinalizesMembersRunsAndOperation(t *testing.T) {
	st := openStoreForManager(t)
	rt := &cancellationRuntime{Runtime: runtimetest.NewFake(), entered: make(chan context.Context, 2), rescue: make(chan struct{})}
	mgr := newBatchManager(t, st, rt, 1)
	req := batchReq("keep_successful", "active", "queued")
	for i := range req.Members {
		req.Members[i].Run = &store.RunAttachment{Goal: "observe shutdown", CriteriaType: "operator_verdict", OnCompletion: "keep_running"}
	}
	result, err := mgr.CreateBatch(t.Context(), "local_operator", req)
	if err != nil {
		t.Fatal(err)
	}
	launchCtx := <-rt.entered
	if _, ok := launchCtx.Deadline(); !ok {
		t.Error("batch launch missing budget")
	}
	mgr.Close()
	for _, member := range result.Members {
		op, err := st.GetOperation(t.Context(), member.Operation.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		if op.State != "failed" {
			t.Errorf("member op state=%s", op.State)
		}
		run, err := st.RunForVM(t.Context(), member.VM.VMID)
		if err != nil {
			t.Fatal(err)
		}
		if run.Phase != "inconclusive" {
			t.Errorf("run phase=%s", run.Phase)
		}
	}
	op, err := st.GetOperation(t.Context(), result.BatchOp.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if op.State != "failed" {
		t.Errorf("batch op state=%s", op.State)
	}
}

func TestDrainRetainsStorageForUninterruptibleSynchronousMutation(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)
	vmID := stoppedVM(t, st, mgr, "late-start")
	release := fk.BlockUninterruptible("Launch", vmID)
	done := make(chan error, 1)
	go func() { _, _, err := mgr.Action(context.Background(), vmID, "start", nil); done <- err }()
	waitForFakeCallCount(t, fk, vmID, "Launch", 2)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	if err := mgr.Drain(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Drain=%v", err)
	}
	// A failed Drain explicitly withholds permission to close SQLite.
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	mgr.Close()
	vm, err := st.GetVM(t.Context(), vmID)
	if err != nil {
		t.Fatal(err)
	}
	if vm.ObservedState != "running" {
		t.Errorf("late success state=%s", vm.ObservedState)
	}
}

func TestReconcileUncertainStartRetainsCompute(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)
	vmID := stoppedVM(t, st, mgr, "restart-pending")
	_, err := st.TransitionVM(t.Context(), store.TransitionInput{VMID: vmID, To: "starting", Reason: "host start pending", AcquireCompute: true, Admit: func(store.ReservationTotals) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	mgr.Close()
	fk.FailNext("ForceStop", vmID, &runtime.ErrStopNotProven{VMID: vmID, Reason: "start operation pending"})
	next, err := runtime.NewManager(st, fk, defaultCfg())
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	res, err := st.GetReservation(t.Context(), vmID)
	if err != nil {
		t.Fatal(err)
	}
	if res.ComputeReleased {
		t.Fatal("restart released compute without proving pending start gone")
	}
}

func TestBatchStopWaveKeepsUnprovenCompute(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	fk.FailCall("Launch", 2, errors.New("launch failed"))
	fk.FailCall("Stop", 1, &runtime.ErrStopNotProven{Reason: "VMM alive"})
	mgr := newBatchManager(t, st, fk, 1)
	result, err := mgr.CreateBatch(t.Context(), "local_operator", batchReq("stop_successful", "one", "two"))
	if err != nil {
		t.Fatal(err)
	}
	mgr.WaitForTest()
	found := false
	for _, member := range result.Members {
		op, err := st.GetOperation(t.Context(), member.Operation.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		if op.State != "succeeded" {
			continue
		}
		found = true
		res, err := st.GetReservation(t.Context(), member.VM.VMID)
		if err != nil {
			t.Fatal(err)
		}
		if res.ComputeReleased {
			t.Fatal("stop wave released live sibling compute")
		}
	}
	if !found {
		t.Fatal("no successful sibling launched")
	}
}

func TestCloseCancelsSynchronousStopWithoutCallerContext(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)
	vm := launchedVM(t, st, mgr, "stop-close")
	release := fk.Block("Stop", vm.VMID)
	done := make(chan error, 1)
	go func() { _, _, err := mgr.Action(context.Background(), vm.VMID, "stop", nil); done <- err }()
	waitForFakeCall(t, fk, vm.VMID, "Stop")
	mgr.BeginClose()
	select {
	case err := <-done:
		if err == nil {
			t.Error("cancelled stop succeeded")
		}
	case <-time.After(time.Second):
		close(release)
		<-done
		t.Fatal("manager did not cancel synchronous stop")
	}
	mgr.Close()
}

func TestInitialAndBatchLaunchDeadlineFinalizers(t *testing.T) {
	for _, batch := range []bool{false, true} {
		t.Run(fmt.Sprintf("batch=%v", batch), func(t *testing.T) {
			st := openStoreForManager(t)
			synctest.Test(t, func(t *testing.T) {
				rt := &cancellationRuntime{Runtime: runtimetest.NewFake(), entered: make(chan context.Context, 2), rescue: make(chan struct{})}
				mgr := newBatchManager(t, st, rt, 1)
				var vmID string
				var opID int64
				if batch {
					result, err := mgr.CreateBatch(t.Context(), "local_operator", batchReq("keep_successful", "deadline"))
					if err != nil {
						t.Fatal(err)
					}
					vmID = result.Members[0].VM.VMID
					opID = result.Members[0].Operation.OperationID
				} else {
					vm, op, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("deadline"))
					if err != nil {
						t.Fatal(err)
					}
					vmID = vm.VMID
					opID = op.OperationID
				}
				launchCtx := <-rt.entered
				// The synthetic clock expires the real production budget while SQLite
				// remains real. No manager close substitutes cancellation for a deadline.
				mgr.WaitForTest()
				if !errors.Is(launchCtx.Err(), context.DeadlineExceeded) {
					t.Errorf("launch context=%v", launchCtx.Err())
				}
				op, err := st.GetOperation(t.Context(), opID)
				if err != nil {
					t.Fatal(err)
				}
				if op.State != "failed" {
					t.Errorf("op state=%s", op.State)
				}
				vm, err := st.GetVM(t.Context(), vmID)
				if err != nil {
					t.Fatal(err)
				}
				if vm.ObservedState != "failed" {
					t.Errorf("vm state=%s", vm.ObservedState)
				}
			})
		})
	}
}

type lateDeadlineRuntime struct{ runtime.Runtime }

func (r lateDeadlineRuntime) Launch(ctx context.Context, _ runtime.VMSpec) (*lock.Images, error) {
	time.Sleep(5 * time.Minute)
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, errors.New("launch deadline was not exhausted")
	}
	return &lock.Images{}, nil
}

func TestInitialAndBatchLateSuccessPersists(t *testing.T) {
	for _, batch := range []bool{false, true} {
		t.Run(fmt.Sprintf("batch=%v", batch), func(t *testing.T) {
			st := openStoreForManager(t)
			synctest.Test(t, func(t *testing.T) {
				mgr := newBatchManager(t, st, lateDeadlineRuntime{runtimetest.NewFake()}, 1)
				attachment := &store.RunAttachment{Goal: "late host success", CriteriaType: "operator_verdict", OnCompletion: "keep_running"}
				var vmID string
				var opID int64
				if batch {
					req := batchReq("keep_successful", "late")
					req.Members[0].Run = attachment
					result, err := mgr.CreateBatch(t.Context(), "local_operator", req)
					if err != nil {
						t.Fatal(err)
					}
					vmID = result.Members[0].VM.VMID
					opID = result.Members[0].Operation.OperationID
				} else {
					req := createReq("late")
					req.Run = attachment
					vm, op, _, err := mgr.CreateVM(t.Context(), "local_operator", req)
					if err != nil {
						t.Fatal(err)
					}
					vmID = vm.VMID
					opID = op.OperationID
				}
				mgr.WaitForTest()
				vm, err := st.GetVM(t.Context(), vmID)
				if err != nil {
					t.Fatal(err)
				}
				if vm.ObservedState != "running" {
					t.Errorf("late vm state=%s", vm.ObservedState)
				}
				op, err := st.GetOperation(t.Context(), opID)
				if err != nil {
					t.Fatal(err)
				}
				if op.State != "succeeded" {
					t.Errorf("late operation state=%s", op.State)
				}
				run, err := st.RunForVM(t.Context(), vmID)
				if err != nil {
					t.Fatal(err)
				}
				if run.Phase != "running" {
					t.Errorf("late run phase=%s", run.Phase)
				}
				res, err := st.GetReservation(t.Context(), vmID)
				if err != nil {
					t.Fatal(err)
				}
				if res.ComputeReleased || res.Released {
					t.Fatal("late live VM lost reservations")
				}
			})
		})
	}
}

type exhaustedCleanupRuntime struct{ runtime.Runtime }

func (r exhaustedCleanupRuntime) Launch(context.Context, runtime.VMSpec) (*lock.Images, error) {
	return nil, context.DeadlineExceeded
}
func (r exhaustedCleanupRuntime) ForceStop(ctx context.Context, _ string) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestCleanupDeadlineLeavesTimeToRecordLaunchFailure(t *testing.T) {
	st := openStoreForManager(t)
	synctest.Test(t, func(t *testing.T) {
		mgr := newBatchManager(t, st, exhaustedCleanupRuntime{runtimetest.NewFake()}, 1)
		vm, op, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("cleanup-deadline"))
		if err != nil {
			t.Fatal(err)
		}
		mgr.WaitForTest()
		result, err := st.GetOperation(t.Context(), op.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		if result.State != "failed" {
			t.Errorf("operation state=%s after cleanup deadline", result.State)
		}
		res, err := st.GetReservation(t.Context(), vm.VMID)
		if err != nil {
			t.Fatal(err)
		}
		if res.ComputeReleased {
			t.Fatal("unproven cleanup released compute")
		}
	})
}

func TestQueuedLaunchDeadlineExpiresBeforeHostSlotFrees(t *testing.T) {
	st := openStoreForManager(t)
	synctest.Test(t, func(t *testing.T) {
		mgr := newBatchManager(t, st, lateDeadlineRuntime{runtimetest.NewFake()}, 1)
		result, err := mgr.CreateBatch(t.Context(), "local_operator", batchReq("keep_successful", "slow", "queued"))
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(4*time.Minute + time.Second)
		synctest.Wait()
		states := memberVMStates(t, st, result)
		if states["starting"] != 1 || states["failed"] != 1 {
			t.Errorf("states before slot released=%v", states)
		}
		mgr.WaitForTest()
	})
}

func TestPendingHostLaunchDoesNotSpendCleanupBudgetOrReservations(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	fk.FailCall("Launch", 1, &runtime.ErrLaunchPending{VMID: "pending", BootID: "boot", Err: context.DeadlineExceeded})
	mgr := newManager(t, st, fk)
	vm, op, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("pending"))
	if err != nil {
		t.Fatal(err)
	}
	mgr.WaitForTest()
	if calledFor(fk, vm.VMID, "ForceStop") {
		t.Fatal("pending lock owner was synchronously waited on again")
	}
	res, err := st.GetReservation(t.Context(), vm.VMID)
	if err != nil {
		t.Fatal(err)
	}
	if res.ComputeReleased || res.Released {
		t.Fatal("pending host effects lost reservations")
	}
	result, err := st.GetOperation(t.Context(), op.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != "failed" || result.Phase != "launch_pending" {
		t.Errorf("pending op=%+v", result)
	}
}
