// ABOUTME: Delete and Reconcile must signal a VM's process before releasing its
// ABOUTME: jail resources — a terminal row is not proof the VMM is gone.
package runtime_test

import (
	"errors"
	"testing"

	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/runtime/runtimetest"
	"github.com/2389-research/observatory-v2/internal/store"
)

// verbsSince returns the ordered method names the fake recorded against vmID
// after the first n calls, so a delete's verbs can be read without the setup's.
func verbsSince(fk *runtimetest.Fake, vmID string, n int) []string {
	calls := fk.CallsFor(vmID)
	if n > len(calls) {
		n = len(calls)
	}
	out := make([]string, 0, len(calls)-n)
	for _, c := range calls[n:] {
		out = append(out, c.Method)
	}
	return out
}

// signalPrecedesRelease reports whether ForceStop was called and every Release
// came after it. Both halves matter: a Release with no ForceStop in front of it
// is the bug, and so is a ForceStop that arrives too late to have done anything.
func signalPrecedesRelease(verbs []string) bool {
	signalled := false
	for _, v := range verbs {
		switch v {
		case "ForceStop":
			signalled = true
		case "Release":
			if !signalled {
				return false
			}
		}
	}
	return signalled
}

// failedVMAfterLaunch drives a VM through a launch that fails and whose
// best-effort ForceStop cleanup also fails, which is how a `failed` row is left
// behind a process nobody ever confirmed dead (internal/runtime/manager.go
// discards that cleanup's error). Returns the vm_id and the number of calls the
// fake has already recorded against it, so a later delete's verbs stand alone.
func failedVMAfterLaunch(t *testing.T, st *store.Store, fk *runtimetest.Fake, name string) (string, int) {
	t.Helper()
	mgr, err := runtime.NewManager(st, fk, defaultCfg())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	fk.FailCall("Launch", 1, errors.New("vsock probe timed out"))
	fk.FailCall("ForceStop", 1, errors.New("privd unreachable during rollback"))

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq(name))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	mgr.Close() // drains the launch worker

	after, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if after.ObservedState != "failed" {
		t.Fatalf("state after a failed launch = %q, want failed", after.ObservedState)
	}
	return vm.VMID, len(fk.CallsFor(vm.VMID))
}

// TestDeleteFailedVMSignalsBeforeRelease is the invariant this file exists for.
// A `failed` row is a record, not a reading of the host: the launch-rollback
// paths write it and then discard the error from their best-effort ForceStop, so
// the VMM behind it may well be running. Deleting such a VM used to go straight
// to Release, and privd answers release_vm with invalid_state "vm process is
// still alive; signal first" — the row parked at "deleting" and only the root
// helper got it back. Observed on aibox03 2026-09-04.
func TestDeleteFailedVMSignalsBeforeRelease(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	vmID, n := failedVMAfterLaunch(t, st, fk, "delete-failed-vm")

	mgr := newManager(t, st, fk)
	defer mgr.Close()

	if _, err := mgr.Delete(t.Context(), vmID, false, nil); err != nil {
		t.Fatalf("delete a failed VM: %v", err)
	}
	verbs := verbsSince(fk, vmID, n)
	if !signalPrecedesRelease(verbs) {
		t.Errorf("delete of a failed VM ran %v; Release must be preceded by ForceStop, "+
			"or privd refuses it while the process is alive", verbs)
	}
}

// TestDeleteStoppedVMSignalsBeforeRelease: `stopped` carries the same lie.
// doStop's forced path drops its SignalVM errors and writes "stopped"
// regardless (internal/jailer/stop.go), and Reconcile settles a `stopping` row
// at "stopped" without observing anything. Either can leave a live VMM behind
// the row, so the delete must signal here too.
func TestDeleteStoppedVMSignalsBeforeRelease(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)
	defer mgr.Close()

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("delete-stopped-vm"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	waitForObservedState(t, st, vm.VMID, "running")
	if _, _, err := mgr.Action(t.Context(), vm.VMID, "stop", nil); err != nil {
		t.Fatalf("stop: %v", err)
	}
	n := len(fk.CallsFor(vm.VMID))

	if _, err := mgr.Delete(t.Context(), vm.VMID, false, nil); err != nil {
		t.Fatalf("delete a stopped VM: %v", err)
	}
	verbs := verbsSince(fk, vm.VMID, n)
	if !signalPrecedesRelease(verbs) {
		t.Errorf("delete of a stopped VM ran %v; Release must be preceded by ForceStop", verbs)
	}
}

// TestForceDeleteSignalsExactlyOnce: the live path already force-stops between
// its "stopping" and "stopped" transitions, and that call must not be doubled by
// the pre-release guard. A second ForceStop is not merely wasteful — its budget
// is a 10s signal plus a 35s finalize plus a 10s release, spent again on a VM
// already known dead.
func TestForceDeleteSignalsExactlyOnce(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)
	defer mgr.Close()

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("force-delete-once"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	waitForObservedState(t, st, vm.VMID, "running")
	n := len(fk.CallsFor(vm.VMID))

	if _, err := mgr.Delete(t.Context(), vm.VMID, true, nil); err != nil {
		t.Fatalf("force delete: %v", err)
	}
	verbs := verbsSince(fk, vm.VMID, n)
	signals := 0
	for _, v := range verbs {
		if v == "ForceStop" {
			signals++
		}
	}
	if signals != 1 {
		t.Errorf("force delete ran %v: %d ForceStop calls, want exactly 1", verbs, signals)
	}
	if !signalPrecedesRelease(verbs) {
		t.Errorf("force delete ran %v; Release must be preceded by ForceStop", verbs)
	}
}

// TestReconcileDeletingSignalsBeforeRelease: Reconcile's "deleting" case is the
// only retry a stalled delete gets — Delete itself returns early for that state,
// and Reconcile runs at startup only. If it releases without signalling, a row
// parked by a live VMM fails identically on every restart, which is exactly what
// aibox03 did until the root helper killed the process by hand.
func TestReconcileDeletingSignalsBeforeRelease(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	vmID := newDeletingVM(t, st, "reconcile-deleting-signal")

	mgr, err := runtime.NewManager(st, fk, defaultCfg())
	if err != nil {
		t.Fatalf("NewManager (reconcile): %v", err)
	}
	defer mgr.Close()

	verbs := verbsSince(fk, vmID, 0)
	if !signalPrecedesRelease(verbs) {
		t.Errorf("reconcile of a deleting row ran %v; Release must be preceded by ForceStop", verbs)
	}
	vm, err := st.GetVM(t.Context(), vmID)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.ObservedState != "deleted" {
		t.Errorf("state = %q, want deleted", vm.ObservedState)
	}
}

// TestStrandedDeleteRecoversOnRestart replays the aibox03 incident end to end. A
// failed VM whose process is still alive: privd refuses the release, the delete
// fails and the row parks at "deleting". The next startup must signal and finish
// it — without a human running jail-stop as root.
func TestStrandedDeleteRecoversOnRestart(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	vmID, _ := failedVMAfterLaunch(t, st, fk, "stranded-delete")

	// privd's own answer while the VM's process is alive.
	stillAlive := errors.New("privd: invalid_state: vm process is still alive; signal first")
	fk.FailNext("Release", vmID, stillAlive)

	mgr := newManager(t, st, fk)
	_, err := mgr.Delete(t.Context(), vmID, false, nil)
	if err == nil {
		t.Fatal("delete succeeded while privd refused the release")
	}
	var relErr *runtime.ErrReleaseFailed
	if !errors.As(err, &relErr) {
		t.Fatalf("error is %T (%v), want *runtime.ErrReleaseFailed", err, err)
	}
	parked, err := st.GetVM(t.Context(), vmID)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if parked.ObservedState != "deleting" {
		t.Fatalf("state after a refused release = %q, want deleting", parked.ObservedState)
	}
	mgr.Close()
	n := len(fk.CallsFor(vmID))

	// Restart: Reconcile owns the retry.
	mgr2, err := runtime.NewManager(st, fk, defaultCfg())
	if err != nil {
		t.Fatalf("NewManager (restart): %v", err)
	}
	defer mgr2.Close()

	verbs := verbsSince(fk, vmID, n)
	if !signalPrecedesRelease(verbs) {
		t.Errorf("restart ran %v; the stranded row needs a signal before its release", verbs)
	}
	final, err := st.GetVM(t.Context(), vmID)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if final.ObservedState != "deleted" {
		t.Errorf("state after restart = %q, want deleted (verbs: %v)", final.ObservedState, verbs)
	}
}
