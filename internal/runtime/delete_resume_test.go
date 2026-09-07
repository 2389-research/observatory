// ABOUTME: A delete that stalled leaves the row at "deleting"; a later DELETE must
// ABOUTME: resume it rather than answer success and do nothing.
package runtime_test

import (
	"errors"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/runtime/runtimetest"
)

// TestDeleteResumesARowParkedAtDeleting is the operator-facing half of the
// stranding ffxv described. A delete whose release was refused leaves the row at
// "deleting" with the resources still on the host; every later DELETE used to
// return early with success and attempt nothing, so the only retry was a daemon
// restart. Nothing in that answer distinguished "already gone" from "stuck".
func TestDeleteResumesARowParkedAtDeleting(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	// The setup's call count is not the offset this test wants: the refused
	// delete below runs between the two, so the offset is taken after it.
	vmID, _ := failedVMAfterLaunch(t, st, fk, "resume-parked-delete")

	mgr := newManager(t, st, fk)
	defer mgr.Close()

	// privd's own answer while the VM's process is alive.
	fk.FailNext("Release", vmID, errors.New("privd: invalid_state: vm process is still alive; signal first"))
	if _, err := mgr.Delete(t.Context(), vmID, false, nil); err == nil {
		t.Fatal("delete succeeded although the release was refused")
	}
	parked, err := st.GetVM(t.Context(), vmID)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if parked.ObservedState != "deleting" {
		t.Fatalf("state after a refused release = %q, want deleting", parked.ObservedState)
	}
	n := len(fk.CallsFor(vmID))

	// The retry an operator would actually make.
	after, err := mgr.Delete(t.Context(), vmID, false, nil)
	if err != nil {
		t.Fatalf("second delete on the parked row: %v", err)
	}
	verbs := verbsSince(fk, vmID, n)
	if !signalPrecedesRelease(verbs) {
		t.Errorf("retry ran %v; a parked row must be signalled and released, not answered from the row", verbs)
	}
	if after.ObservedState != "deleted" {
		t.Errorf("state after the retry = %q, want deleted", after.ObservedState)
	}
}

// TestDeleteOfADeletedVMTouchesNothing: idempotency for the state that really is
// finished. "deleted" is terminal and its resources are gone, so a repeat call
// must answer from the row without asking the runtime for anything.
func TestDeleteOfADeletedVMTouchesNothing(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)
	defer mgr.Close()

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("delete-twice"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	waitForObservedState(t, st, vm.VMID, "running")
	if _, err := mgr.Delete(t.Context(), vm.VMID, true, nil); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	n := len(fk.CallsFor(vm.VMID))

	again, err := mgr.Delete(t.Context(), vm.VMID, false, nil)
	if err != nil {
		t.Fatalf("second delete: %v", err)
	}
	if again.ObservedState != "deleted" {
		t.Errorf("state = %q, want deleted", again.ObservedState)
	}
	if verbs := verbsSince(fk, vm.VMID, n); len(verbs) != 0 {
		t.Errorf("second delete on a deleted VM ran %v, want nothing", verbs)
	}
}

// TestConcurrentDeleteDoesNotDuplicateWork: "in progress" must mean a Delete call
// is running right now, not "the row says deleting" — the row says that for a
// parked delete too, and the two need opposite answers. A second caller arriving
// while the first is inside Release waits for nothing and asks the runtime for
// nothing; the first call owns the work.
func TestConcurrentDeleteDoesNotDuplicateWork(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	vmID, _ := failedVMAfterLaunch(t, st, fk, "concurrent-delete")

	mgr := newManager(t, st, fk)
	defer mgr.Close()

	release := fk.Block("Release", vmID)
	n := len(fk.CallsFor(vmID))

	done := make(chan error, 1)
	go func() {
		_, err := mgr.Delete(t.Context(), vmID, false, nil)
		done <- err
	}()

	// Wait until the first delete is inside Release.
	deadline := time.Now().Add(5 * time.Second)
	for !calledFor(fk, vmID, "Release") {
		if time.Now().After(deadline) {
			close(release)
			t.Fatal("first delete never reached Release")
		}
		time.Sleep(2 * time.Millisecond)
	}
	mid := len(fk.CallsFor(vmID))

	second, err := mgr.Delete(t.Context(), vmID, false, nil)
	if err != nil {
		t.Errorf("concurrent delete: %v — a delete already in flight owns the work", err)
	}
	if second != nil && second.ObservedState != "deleting" {
		t.Errorf("concurrent delete reported %q, want the in-flight state deleting", second.ObservedState)
	}
	if verbs := verbsSince(fk, vmID, mid); len(verbs) != 0 {
		t.Errorf("concurrent delete ran %v, want nothing — the in-flight call owns the runtime", verbs)
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first delete: %v", err)
	}
	final, err := st.GetVM(t.Context(), vmID)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if final.ObservedState != "deleted" {
		t.Errorf("state = %q, want deleted", final.ObservedState)
	}
	if !signalPrecedesRelease(verbsSince(fk, vmID, n)) {
		t.Errorf("the owning delete ran %v; Release must be preceded by ForceStop", verbsSince(fk, vmID, n))
	}
}
