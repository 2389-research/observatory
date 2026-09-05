// ABOUTME: Reconcile must tell a controller restart from a fleet outage: a VM whose
// ABOUTME: runner survived is adopted, and every VM it cannot account for still fails.
package runtime_test

import (
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/runtime/runtimetest"
	"github.com/2389-research/observatory-v2/internal/store"
)

// liveVM creates a VM and walks it to state through the real transition machine.
func liveVM(t *testing.T, st *store.Store, name, state string) string {
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
	if state == "provisioning" {
		return vm.VMID
	}
	for _, to := range []string{"starting", "running", "paused"} {
		if _, err := st.TransitionVM(t.Context(), store.TransitionInput{
			VMID:        vm.VMID,
			To:          to,
			Reason:      "test_setup",
			OperationID: 0,
		}); err != nil {
			t.Fatalf("transition %s→%s: %v", name, to, err)
		}
		if to == state {
			return vm.VMID
		}
	}
	t.Fatalf("liveVM: %q is not a state this helper walks to", state)
	return ""
}

func stateOf(t *testing.T, st *store.Store, vmID string) *store.VM {
	t.Helper()
	vm, err := st.GetVM(t.Context(), vmID)
	if err != nil {
		t.Fatalf("GetVM %s: %v", vmID, err)
	}
	return vm
}

// TestReconcileAdoptsAVMWhoseRunnerSurvived is the whole point: firecracker is
// started daemonized and reparented to init, so a controller restart leaves live
// microVMs behind. Failing their rows records a fleet outage that did not happen,
// and the operator's next move on a "failed" VM is to delete it.
func TestReconcileAdoptsAVMWhoseRunnerSurvived(t *testing.T) {
	st := openStoreForManager(t)
	adopted := liveVM(t, st, "survivor", "running")
	pausedSurvivor := liveVM(t, st, "paused-survivor", "paused")
	lost := liveVM(t, st, "casualty", "running")

	cfg := defaultCfg()
	cfg.AdoptedVMs = map[string]bool{adopted: true, pausedSurvivor: true}

	mgr, err := runtime.NewManager(st, runtimetest.NewFake(), cfg)
	if err != nil {
		t.Fatalf("NewManager (reconcile): %v", err)
	}
	defer mgr.Close()

	if got := stateOf(t, st, adopted).ObservedState; got != "running" {
		t.Errorf("adopted VM: state = %q, want running", got)
	}
	if got := stateOf(t, st, pausedSurvivor).ObservedState; got != "paused" {
		t.Errorf("adopted paused VM: state = %q, want paused", got)
	}
	if got := stateOf(t, st, lost).ObservedState; got != "failed" {
		t.Errorf("unadopted VM: state = %q, want failed", got)
	}
}

// TestAdoptionLeavesTheRowUntouched: adoption is the absence of a write, not a
// write of its own. A revision bump would invalidate every pin an operator holds
// across a restart, and a new transition row would claim something happened.
func TestAdoptionLeavesTheRowUntouched(t *testing.T) {
	st := openStoreForManager(t)
	vmID := liveVM(t, st, "survivor", "running")
	before := stateOf(t, st, vmID)

	cfg := defaultCfg()
	cfg.AdoptedVMs = map[string]bool{vmID: true}
	mgr, err := runtime.NewManager(st, runtimetest.NewFake(), cfg)
	if err != nil {
		t.Fatalf("NewManager (reconcile): %v", err)
	}
	defer mgr.Close()

	after := stateOf(t, st, vmID)
	if after.Revision != before.Revision {
		t.Errorf("revision moved %d → %d; adoption writes nothing", before.Revision, after.Revision)
	}
	if after.MemoryMiB != before.MemoryMiB || after.VCPUCount != before.VCPUCount {
		t.Errorf("compute changed on adoption: %d MiB/%d vCPU → %d MiB/%d vCPU",
			before.MemoryMiB, before.VCPUCount, after.MemoryMiB, after.VCPUCount)
	}
}

// TestAdoptionKeepsTheVMsComputeReserved: an adopted VM is still consuming the
// host. Releasing its reservation would let admission hand the same memory out
// twice — the failure mode is a second VM that will not boot, blamed on the host.
func TestAdoptionKeepsTheVMsComputeReserved(t *testing.T) {
	st := openStoreForManager(t)
	vmID := liveVM(t, st, "survivor", "running")

	cfg := defaultCfg()
	cfg.AdoptedVMs = map[string]bool{vmID: true}
	mgr, err := runtime.NewManager(st, runtimetest.NewFake(), cfg)
	if err != nil {
		t.Fatalf("NewManager (reconcile): %v", err)
	}
	defer mgr.Close()

	totals, err := st.ReservationTotals(t.Context())
	if err != nil {
		t.Fatalf("ReservationTotals: %v", err)
	}
	if totals.MemoryMiB == 0 || totals.VCPU == 0 {
		t.Errorf("adopted VM holds no reservation: %+v; its microVM is still running", totals)
	}
}

// TestAdoptionDoesNotReachOtherStates: the findings say a VM's runner is alive,
// which is not a claim about a delete that was in flight. Those rows have their
// own recovery, and adopting them would strand resources.
func TestAdoptionDoesNotReachOtherStates(t *testing.T) {
	st := openStoreForManager(t)
	provisioning := liveVM(t, st, "provisioning-vm", "provisioning")
	starting := liveVM(t, st, "starting-vm", "starting")

	cfg := defaultCfg()
	cfg.AdoptedVMs = map[string]bool{provisioning: true, starting: true}
	mgr, err := runtime.NewManager(st, runtimetest.NewFake(), cfg)
	if err != nil {
		t.Fatalf("NewManager (reconcile): %v", err)
	}
	defer mgr.Close()

	if got := stateOf(t, st, provisioning).ObservedState; got != "failed" {
		t.Errorf("provisioning VM: state = %q, want failed", got)
	}
	if got := stateOf(t, st, starting).ObservedState; got != "failed" {
		t.Errorf("starting VM: state = %q, want failed", got)
	}
}

// TestReconcileWithoutFindingsFailsEverythingRunning: a runtime that cannot
// observe a previous run's VMs — the portable core, an absent host — supplies no
// findings, and Reconcile must keep answering as it did rather than assume the
// best about VMs nobody looked at.
func TestReconcileWithoutFindingsFailsEverythingRunning(t *testing.T) {
	st := openStoreForManager(t)
	running := liveVM(t, st, "running-vm", "running")
	paused := liveVM(t, st, "paused-vm", "paused")

	mgr, err := runtime.NewManager(st, runtimetest.NewFake(), defaultCfg())
	if err != nil {
		t.Fatalf("NewManager (reconcile): %v", err)
	}
	defer mgr.Close()

	for _, vmID := range []string{running, paused} {
		vm := stateOf(t, st, vmID)
		if vm.ObservedState != "failed" {
			t.Errorf("vm %s: state = %q, want failed with no findings", vmID, vm.ObservedState)
		}
	}
}
