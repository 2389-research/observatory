// ABOUTME: Tests the contexts a start action runs on: the launch budget it gets
// ABOUTME: instead of the caller's, and the bookkeeping that outlives that budget.
package runtime_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/runtime"
	"github.com/2389-research/observatory/internal/runtime/runtimetest"
	"github.com/2389-research/observatory/internal/store"
)

// TestStartRecordsFailureAfterOperationContextDies: a failed launch must be
// recorded even when the operation context died first — which is the ordinary
// case, because the expiry is usually what makes the launch fail. Bookkeeping
// that runs on the context whose death it is reporting does nothing at all, and
// the VM is left in "starting" with the operation still "running": the exact
// stranding an operation budget exists to prevent.
func TestStartRecordsFailureAfterOperationContextDies(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vmID := stoppedVM(t, st, mgr, "start-bookkeeping")

	// The launch blocks until the test releases it, and then fails. The caller's
	// context is cancelled while it is in flight, so the failure and the dead
	// context arrive together.
	release := fk.Block("Launch", vmID)
	fk.FailNext("Launch", vmID, errors.New("staging disk full"))

	opCtx, cancelOp := context.WithCancel(context.Background())
	defer cancelOp()
	type actionResult struct {
		op  *store.Operation
		err error
	}
	done := make(chan actionResult, 1)
	go func() {
		_, op, err := mgr.Action(opCtx, vmID, "start", nil)
		done <- actionResult{op: op, err: err}
	}()

	waitForFakeCallCount(t, fk, vmID, "Launch", 2) // 1 = the create-path launch
	cancelOp()
	close(release)
	res := <-done

	if res.err == nil {
		t.Error("start returned no error after the launch failed")
	}
	vm := waitForVMState(t, st, vmID, "failed")
	if vm.Revision < 1 {
		t.Errorf("revision = %d", vm.Revision)
	}
	if res.op == nil {
		t.Fatal("start returned no operation; the failure was never read back")
	}
	if res.op.State != "failed" {
		t.Errorf("operation state = %q, want failed", res.op.State)
	}
}

// TestStartLaunchOutlivesCallerCancellation: a start action's launch runs on a
// context detached from the caller's, so an HTTP client that hangs up mid-launch
// does not abort a launch that is behaving perfectly and leave the VM in
// "starting" with staging already on disk.
//
// This observes cancellation only. That the launch also gets a *longer* budget
// than the caller's stop-derived one is a separate claim with its own test
// below: this one would pass with launchBudget set to 50ms.
func TestStartLaunchOutlivesCallerCancellation(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vmID := stoppedVM(t, st, mgr, "start-budget")

	release := fk.Block("Launch", vmID)

	opCtx, cancelOp := context.WithCancel(context.Background())
	defer cancelOp()
	done := make(chan error, 1)
	go func() {
		_, _, err := mgr.Action(opCtx, vmID, "start", nil)
		done <- err
	}()

	waitForFakeCallCount(t, fk, vmID, "Launch", 2)
	cancelOp() // the caller's operation budget expires mid-launch
	close(release)

	if err := <-done; err != nil {
		t.Errorf("start failed after its caller's context died: %v", err)
	}
	waitForVMState(t, st, vmID, "running")
}

// TestStartLaunchGetsMoreBudgetThanTheStopDerivedOne: the operation budget is
// derived from the stop path — a grace period plus fixed ctl and signal
// timeouts. A launch copies and hashes gigabytes and then waits up to 60s for
// the guest to attach, so it needs its own, larger budget. Riding the stop
// budget aborts a launch that is doing exactly what it should.
//
// The deadline the launch actually runs under is the claim, and the fake
// records it: asserting the launch merely survives the caller proves nothing
// about how long it gets.
func TestStartLaunchGetsMoreBudgetThanTheStopDerivedOne(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vmID := stoppedVM(t, st, mgr, "start-budget-deadline")

	// The production shape: the HTTP handler hands Action the stop-derived
	// operation context (internal/api/vms.go), so that is what the start branch
	// has to beat.
	opCtx, cancelOp := mgr.OperationContext(context.Background())
	defer cancelOp()
	opDeadline, ok := opCtx.Deadline()
	if !ok {
		t.Fatal("OperationContext carries no deadline; there is no budget to compare against")
	}

	if _, _, err := mgr.Action(opCtx, vmID, "start", nil); err != nil {
		t.Fatalf("start: %v", err)
	}

	launch := lastCallFor(t, fk, vmID, "Launch")
	if launch.Deadline.IsZero() {
		t.Fatal("the launch ran on a context with no deadline: unbounded, not budgeted")
	}
	// launchBudget is 240s against a 125s operation budget in this config, so the
	// gap is ~115s. A floor well under that still fails when the launch is handed
	// the operation context itself (gap 0), and does not pin the test to either
	// constant.
	if gap := launch.Deadline.Sub(opDeadline); gap < 30*time.Second {
		t.Errorf("the launch ran only %v past the stop-derived operation deadline; that is not a budget of its own", gap)
	}
}

// TestStartRecordsLaunchFailureAfterTheLaunchContextDies: when a launch fails
// with its own context already gone, the branch that records the failure and
// cleans up must not ride that context — it would write nothing, leaving a dead
// VM reading "starting" behind an operation that reads "running" for ever.
//
// The launch context dies two ways: launchBudget expires, or the manager
// closes. This test uses the second because a unit test cannot wait out four
// minutes; the branch under test cannot tell them apart. The launch itself is
// uninterruptible, as the real one largely is, so it returns its own failure
// rather than the context's.
func TestStartRecordsLaunchFailureAfterTheLaunchContextDies(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vmID := stoppedVM(t, st, mgr, "start-launch-ctx-dead")

	release := fk.BlockUninterruptible("Launch", vmID)
	fk.FailNext("Launch", vmID, errors.New("staging disk full"))

	done := make(chan error, 1)
	go func() {
		_, _, err := mgr.Action(context.Background(), vmID, "start", nil)
		done <- err
	}()

	waitForFakeCallCount(t, fk, vmID, "Launch", 2) // 1 = the create-path launch
	mgr.Close()                                    // cancels the manager context, and with it the launch's
	close(release)

	if err := <-done; err == nil {
		t.Error("start returned no error after the launch failed")
	}
	waitForVMState(t, st, vmID, "failed")

	running, err := st.ListOperationsByState(context.Background(), "running")
	if err != nil {
		t.Fatalf("ListOperationsByState(running): %v", err)
	}
	for _, op := range running {
		if op.VMID != nil && *op.VMID == vmID {
			t.Errorf("operation %d (%s) left in %q after the launch failed", op.OperationID, op.Phase, op.State)
		}
	}
}

// TestStartRecordsSuccessAfterTheLaunchContextDies: a launch that returns nil
// with its own context already spent has left a live, healthy VM behind, and
// the writes that record it must not ride that context. They would do nothing,
// and Firecracker would be running underneath a row that reads "starting" with
// an operation that reads "running".
//
// Nothing repairs that while the daemon is up, and reconcile makes it worse on
// the next start: it marks a "starting" VM failed and releases its compute, for
// a VM that is up.
func TestStartRecordsSuccessAfterTheLaunchContextDies(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vmID := stoppedVM(t, st, mgr, "start-success-ctx-dead")

	// Uninterruptible, like the real launch: it finishes the work it started and
	// returns success whatever its context did meanwhile.
	release := fk.BlockUninterruptible("Launch", vmID)

	type actionResult struct {
		op  *store.Operation
		err error
	}
	done := make(chan actionResult, 1)
	go func() {
		_, op, err := mgr.Action(context.Background(), vmID, "start", nil)
		done <- actionResult{op: op, err: err}
	}()

	waitForFakeCallCount(t, fk, vmID, "Launch", 2) // 1 = the create-path launch
	mgr.Close()                                    // cancels the manager context, and with it the launch's
	close(release)

	res := <-done
	if res.err != nil {
		t.Errorf("start returned an error after the launch succeeded: %v", res.err)
	}
	waitForVMState(t, st, vmID, "running")
	if res.op == nil {
		t.Fatal("start returned no operation")
	}
	if res.op.State != "succeeded" {
		t.Errorf("operation state = %q, want succeeded", res.op.State)
	}
}

// TestStopRecordsOutcomeAfterTheOperationContextDies: the shared tail of every
// non-start action has the same shape on the operation context. Its budget is
// sized for the runtime call plus these writes, but only just — at the
// documented stop grace the worst case leaves 5s of it (see operationSlack) —
// and a host slower than that model spends the lot.
//
// What the tail writes is the terminal state *and* the compute release, so
// losing it strands the VM in "stopping" with its memory still reserved against
// admission until the next controller restart.
func TestStopRecordsOutcomeAfterTheOperationContextDies(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm := launchedVM(t, st, mgr, "stop-tail-ctx-dead")

	release := fk.BlockUninterruptible("Stop", vm.VMID)

	// The production caller shape: the handler hands Action the operation
	// context, which dies with the manager.
	opCtx, cancelOp := mgr.OperationContext(context.Background())
	defer cancelOp()

	type actionResult struct {
		op  *store.Operation
		err error
	}
	done := make(chan actionResult, 1)
	go func() {
		_, op, err := mgr.Action(opCtx, vm.VMID, "stop", nil)
		done <- actionResult{op: op, err: err}
	}()

	waitForFakeCallCount(t, fk, vm.VMID, "Stop", 1)
	mgr.Close()
	close(release)

	res := <-done
	if res.err != nil {
		t.Errorf("stop returned an error after the runtime stopped the VM: %v", res.err)
	}
	waitForVMState(t, st, vm.VMID, "stopped")
	if res.op == nil {
		t.Fatal("stop returned no operation")
	}
	if res.op.State != "succeeded" {
		t.Errorf("operation state = %q, want succeeded", res.op.State)
	}

	// The release is the half that leaks: a reservation held for a VM that is
	// gone is capacity admission will never hand out again.
	resv, err := st.GetReservation(context.Background(), vm.VMID)
	if err != nil {
		t.Fatalf("GetReservation: %v", err)
	}
	if !resv.ComputeReleased {
		t.Error("compute_released is false after a completed stop: the reservation is stranded")
	}
}

// stoppedVM creates a VM, waits for the create-path launch to finish, then
// stops it — the only state a start action is legal from.
func stoppedVM(t *testing.T, st *store.Store, mgr *runtime.Manager, name string) string {
	t.Helper()
	vm := launchedVM(t, st, mgr, name)
	if _, _, err := mgr.Action(t.Context(), vm.VMID, "stop", nil); err != nil {
		t.Fatalf("stop %s: %v", vm.VMID, err)
	}
	waitForVMState(t, st, vm.VMID, "stopped")
	return vm.VMID
}

// waitForFakeCallCount waits until the fake has seen at least n calls of method
// for vmID. Every VM reaches "stopped" through a create-path launch, so a start
// action's launch is the second one.
func waitForFakeCallCount(t *testing.T, fk *runtimetest.Fake, vmID, method string, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := len(slices.DeleteFunc(fk.CallsFor(vmID), func(c runtimetest.Call) bool {
			return c.Method != method
		}))
		if got >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("runtime saw %d %s calls for vm %s, want %d", got, method, vmID, n)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// lastCallFor returns the most recent recorded call of method for vmID.
func lastCallFor(t *testing.T, fk *runtimetest.Fake, vmID, method string) runtimetest.Call {
	t.Helper()
	calls := slices.DeleteFunc(fk.CallsFor(vmID), func(c runtimetest.Call) bool {
		return c.Method != method
	})
	if len(calls) == 0 {
		t.Fatalf("runtime saw no %s call for vm %s", method, vmID)
	}
	return calls[len(calls)-1]
}
