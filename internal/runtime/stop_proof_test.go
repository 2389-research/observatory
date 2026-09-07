// ABOUTME: A stop that proved the VMM dead settles the row even when a host
// ABOUTME: resource is left behind; a stop that proved nothing settles nothing.
package runtime_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/2389-research/observatory/internal/runtime"
	"github.com/2389-research/observatory/internal/runtime/runtimetest"
)

// fakeStopMethod maps an action name to the Runtime method the fake records it
// under, so the two stop actions can be driven through one table.
var fakeStopMethod = map[string]string{"stop": "Stop", "force_stop": "ForceStop"}

// TestAStopThatLeftCleanupBehindStillSettlesTheRowAndRecordsTheDebt.
//
// Compute and disk are freed by different evidence. The memory and vCPU come
// back the moment the VMM process ends, and the runtime does not say a stop
// succeeded until it has watched that happen. The jail chroot comes back only
// when privd's release call succeeds, and that call can fail on its own — a
// busy mount, a directory privd will not unlink — with the VMM already gone.
//
// Treating that as a failed stop parks the row at "stopping" and holds a dead
// VM's memory against admission over a directory nobody is using. So the
// action settles, the compute is released, and the outstanding cleanup becomes
// a record an operator can find rather than a return value nobody kept.
func TestAStopThatLeftCleanupBehindStillSettlesTheRowAndRecordsTheDebt(t *testing.T) {
	for _, action := range []string{"stop", "force_stop"} {
		t.Run(action, func(t *testing.T) {
			st := openStoreForManager(t)
			fk := runtimetest.NewFake()
			// The manager is built before the VM row exists: its startup
			// Reconcile would otherwise fail a "running" row no adoption
			// finding accounts for, and this test is about the stop path.
			mgr := newManager(t, st, fk)
			vmID := liveVM(t, st, "debt-"+action, "running")

			before, err := st.ReservationTotals(t.Context())
			if err != nil {
				t.Fatalf("ReservationTotals (before): %v", err)
			}

			fk.FailNext(fakeStopMethod[action], vmID, &runtime.ErrCleanupPending{
				VMID:     vmID,
				Resource: "jail chroot",
				Reason:   "privd: exec_failed: rm -rf: Device or resource busy",
			})
			if _, _, err := mgr.Action(t.Context(), vmID, action, nil); err != nil {
				t.Fatalf("%s returned %v; the VMM was proven gone, so the stop happened", action, err)
			}

			if got := stateOf(t, st, vmID).ObservedState; got != "stopped" {
				t.Errorf("state = %q, want stopped: the process ended and that is what the state names", got)
			}
			after, err := st.ReservationTotals(t.Context())
			if err != nil {
				t.Fatalf("ReservationTotals (after): %v", err)
			}
			if after.MemoryMiB != 0 || after.VCPU != 0 {
				t.Errorf("reservations %+v → %+v; a dead VMM's memory and vCPU are the host's again",
					before, after)
			}
			if after.DiskMiB != before.DiskMiB {
				t.Errorf("disk %d → %d; a stopped VM keeps its disk, and this one's is still on the host",
					before.DiskMiB, after.DiskMiB)
			}

			recs := cleanupFailures(t, st, vmID)
			if len(recs) != 1 {
				t.Fatalf("vm.cleanup_failed records = %d, want 1: cleanup left undone with no record "+
					"is a jail directory nobody will ever be told about", len(recs))
			}
			if got, _ := recs[0]["state"].(string); got != "stopped" {
				t.Errorf("record state = %q, want stopped — the state the row actually reached", got)
			}
			reason, _ := recs[0]["reason"].(string)
			if !strings.Contains(reason, "jail chroot") || !strings.Contains(reason, "busy") {
				t.Errorf("reason = %q, want the resource and the runtime's own explanation", reason)
			}
		})
	}
}

// TestAStopThatCouldNotProveDeathFailsAndHoldsTheCompute is the other half, and
// the expensive one to get wrong. Sending a signal is not watching a process
// end: privd can accept a SIGKILL and the VMM can still be there a second
// later, and until M2 the adapter reported that as a successful stop. The row
// went to "stopped", its memory went back to admission, and the microVM kept
// running on memory the host had promised to something else.
//
// A runtime that cannot prove the death now says so, and every one of those
// facts has to not happen.
func TestAStopThatCouldNotProveDeathFailsAndHoldsTheCompute(t *testing.T) {
	for _, action := range []string{"stop", "force_stop"} {
		t.Run(action, func(t *testing.T) {
			st := openStoreForManager(t)
			fk := runtimetest.NewFake()
			mgr := newManager(t, st, fk)
			vmID := liveVM(t, st, "unproven-"+action, "running")

			before, err := st.ReservationTotals(t.Context())
			if err != nil {
				t.Fatalf("ReservationTotals (before): %v", err)
			}

			fk.FailNext(fakeStopMethod[action], vmID, &runtime.ErrStopNotProven{
				VMID:   vmID,
				Reason: "vmm pid 4242 start time 88170 is alive",
			})
			_, _, err = mgr.Action(t.Context(), vmID, action, nil)
			if err == nil {
				t.Fatal("action succeeded on a stop the runtime could not prove")
			}
			// The typed cause has to survive the manager's wrapping: the API maps
			// it to a cause and a remediation, and an operator told only "stop
			// failed" retries the same stop against the same live VMM.
			var notProven *runtime.ErrStopNotProven
			if !errors.As(err, &notProven) {
				t.Fatalf("error %v does not unwrap to *ErrStopNotProven", err)
			}
			if !strings.Contains(notProven.Reason, "is alive") {
				t.Errorf("reason = %q, want the runtime's own account of what it saw", notProven.Reason)
			}

			if got := stateOf(t, st, vmID).ObservedState; got != "stopping" {
				t.Errorf("state = %q, want stopping: nothing observed this VM stop", got)
			}
			after, err := st.ReservationTotals(t.Context())
			if err != nil {
				t.Fatalf("ReservationTotals (after): %v", err)
			}
			if after.MemoryMiB != before.MemoryMiB || after.VCPU != before.VCPU {
				t.Errorf("reservations %+v → %+v; a VM that may still be running still holds them",
					before, after)
			}
		})
	}
}

// TestReconcileSettlesAnAdoptedStopThatLeftCleanupBehind carries the same split
// into the startup path, where it is decided by different code. Reconcile
// finishes an adopted VM's interrupted stop with a force-stop, and it already
// distinguished "it worked" from "it failed". Pending cleanup is a third
// answer: the VMM is gone — so the row settles and the memory goes back — and
// the jail is not, so the debt is recorded against "stopped", the state the row
// reaches, rather than "stopping", the state a plain failure holds it at.
func TestReconcileSettlesAnAdoptedStopThatLeftCleanupBehind(t *testing.T) {
	st := openStoreForManager(t)
	vmID := stoppingVM(t, st, "adopted-stop-debt")

	rt := runtimetest.NewFake()
	rt.FailNext("ForceStop", vmID, &runtime.ErrCleanupPending{
		VMID:     vmID,
		Resource: "jail chroot",
		Reason:   "privd: exec_failed: rmdir: Directory not empty",
	})
	cfg := defaultCfg()
	cfg.AdoptedVMs = map[string]bool{vmID: true}

	mgr, err := runtime.NewManager(st, rt, cfg)
	if err != nil {
		t.Fatalf("NewManager (reconcile): %v", err)
	}
	defer mgr.Close()

	if got := stateOf(t, st, vmID).ObservedState; got != "stopped" {
		t.Errorf("state = %q, want stopped: the force-stop proved the VMM gone", got)
	}
	totals, err := st.ReservationTotals(t.Context())
	if err != nil {
		t.Fatalf("ReservationTotals: %v", err)
	}
	if totals.MemoryMiB != 0 || totals.VCPU != 0 {
		t.Errorf("reservations = %+v; the VMM is gone and its compute is the host's again", totals)
	}

	recs := cleanupFailures(t, st, vmID)
	if len(recs) != 1 {
		t.Fatalf("vm.cleanup_failed records = %d, want 1", len(recs))
	}
	if got, _ := recs[0]["state"].(string); got != "stopped" {
		t.Errorf("record state = %q, want stopped — a plain failure records stopping, "+
			"and the two must not read alike", got)
	}
}

// TestReconcileHoldsAnAdoptedStopItCouldNotProve pins the boundary from the
// other side: an unproven stop is not a debt, and Reconcile must leave the row
// where it found it. Without this the ErrCleanupPending branch could be widened
// to swallow every runtime error and nothing would notice.
func TestReconcileHoldsAnAdoptedStopItCouldNotProve(t *testing.T) {
	st := openStoreForManager(t)
	vmID := stoppingVM(t, st, "adopted-stop-unproven")

	rt := runtimetest.NewFake()
	rt.FailNext("ForceStop", vmID, &runtime.ErrStopNotProven{
		VMID:   vmID,
		Reason: "vmm pid 91 start time 4410 is alive",
	})
	cfg := defaultCfg()
	cfg.AdoptedVMs = map[string]bool{vmID: true}

	mgr, err := runtime.NewManager(st, rt, cfg)
	if err != nil {
		t.Fatalf("NewManager (reconcile): %v", err)
	}
	defer mgr.Close()

	if got := stateOf(t, st, vmID).ObservedState; got != "stopping" {
		t.Errorf("state = %q, want stopping", got)
	}
	totals, err := st.ReservationTotals(t.Context())
	if err != nil {
		t.Fatalf("ReservationTotals: %v", err)
	}
	if totals.MemoryMiB == 0 || totals.VCPU == 0 {
		t.Errorf("reservations = %+v; a VM that may still be running still holds them", totals)
	}
	recs := cleanupFailures(t, st, vmID)
	if len(recs) != 1 {
		t.Fatalf("vm.cleanup_failed records = %d, want 1", len(recs))
	}
	if got, _ := recs[0]["state"].(string); got != "stopping" {
		t.Errorf("record state = %q, want stopping", got)
	}
}
