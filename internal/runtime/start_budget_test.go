// ABOUTME: Tests that a start action survives the death of its caller's context.
// ABOUTME: A launch is bounded by launch work, and a failure is recorded whatever happens.
package runtime_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/runtime/runtimetest"
	"github.com/2389-research/observatory-v2/internal/store"
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

// TestStartLaunchOutlivesTheStopDerivedBudget: the operation budget is derived
// from the stop path — a grace period plus fixed ctl and signal timeouts. A
// launch copies and hashes gigabytes and then waits up to 60s for the guest to
// attach, so it needs its own budget. Riding the stop budget aborts a launch
// that is doing exactly what it should, and the VM lands in "starting" with
// staging already on disk.
func TestStartLaunchOutlivesTheStopDerivedBudget(t *testing.T) {
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
