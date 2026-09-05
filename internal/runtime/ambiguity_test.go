// ABOUTME: A runtime that looked at the host and could not tell must not have its
// ABOUTME: silence read as a verdict: ambiguous findings settle no row at startup.
package runtime_test

import (
	"strings"
	"testing"

	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/runtime/runtimetest"
	"github.com/2389-research/observatory-v2/internal/store"
)

// ambiguities returns the vm.reconcile_ambiguous events recorded for vmID.
func ambiguities(t *testing.T, st *store.Store, vmID string) []map[string]any {
	t.Helper()
	res, err := st.Query(t.Context(), store.Query{VMID: &vmID, Kind: "vm.reconcile_ambiguous"})
	if err != nil {
		t.Fatalf("query vm.reconcile_ambiguous: %v", err)
	}
	out := make([]map[string]any, 0, len(res.Events))
	for _, e := range res.Events {
		out = append(out, e.Data)
	}
	return out
}

// TestReconcileLeavesARunningRowAloneWhenTheRuntimeCannotAccountForIt.
//
// The startup scan has three verdicts and the manager was told about one. A VM
// the scan could not classify -- an unreadable manifest, a runner whose recorded
// VMM identity does not match the manifest's -- arrived at Reconcile
// indistinguishable from a VM the scan proved gone, and the row was failed with
// reason "vmm_disappeared_on_restart" and its compute handed back to admission.
// Nobody observed it disappear. §5.5 quarantines an ambiguous VM at the runtime
// layer; the row above it has to be quarantined too, or the quarantine ends at
// the package boundary.
func TestReconcileLeavesARunningRowAloneWhenTheRuntimeCannotAccountForIt(t *testing.T) {
	st := openStoreForManager(t)
	vmID := liveVM(t, st, "unaccountable", "running")

	before, err := st.ReservationTotals(t.Context())
	if err != nil {
		t.Fatalf("ReservationTotals (before): %v", err)
	}

	cfg := defaultCfg()
	cfg.AmbiguousVMs = map[string]string{vmID: "unreadable manifest: unexpected end of JSON input"}

	mgr, err := runtime.NewManager(st, runtimetest.NewFake(), cfg)
	if err != nil {
		t.Fatalf("NewManager (reconcile): %v", err)
	}
	defer mgr.Close()

	if got := stateOf(t, st, vmID).ObservedState; got != "running" {
		t.Errorf("state = %q, want running: nothing observed this VM stop, so nothing may say it did", got)
	}
	after, err := st.ReservationTotals(t.Context())
	if err != nil {
		t.Fatalf("ReservationTotals (after): %v", err)
	}
	if after.MemoryMiB != before.MemoryMiB || after.VCPU != before.VCPU {
		t.Errorf("reservations %+v → %+v; compute was released on a VM nobody could account for",
			before, after)
	}

	recs := ambiguities(t, st, vmID)
	if len(recs) != 1 {
		t.Fatalf("vm.reconcile_ambiguous records = %d, want 1: a row held back with no record "+
			"is a VM that silently stopped being reconciled", len(recs))
	}
	if got, _ := recs[0]["state"].(string); got != "running" {
		t.Errorf("record state = %q, want running", got)
	}
	if detail, _ := recs[0]["detail"].(string); !strings.Contains(detail, "unreadable manifest") {
		t.Errorf("record detail = %q, want the runtime's own account of what it could not tell", detail)
	}
}

// TestReconcileLeavesAStoppingRowAloneWhenTheRuntimeCannotAccountForIt is the
// same rule on the stop path, where the cost is the one M2a's adoption findings
// were introduced to stop: "stopped" over a live microVM, its memory handed to
// admission twice. Adoption closed that for the VMs the scan proved alive. A VM
// it could not classify took the other branch and settled anyway.
func TestReconcileLeavesAStoppingRowAloneWhenTheRuntimeCannotAccountForIt(t *testing.T) {
	st := openStoreForManager(t)
	vmID := stoppingVM(t, st, "unaccountable-stop")

	rt := runtimetest.NewFake()
	cfg := defaultCfg()
	cfg.AmbiguousVMs = map[string]string{vmID: "runner vmm identity mismatch: runner=(41,900) manifest=(41,120)"}

	mgr, err := runtime.NewManager(st, rt, cfg)
	if err != nil {
		t.Fatalf("NewManager (reconcile): %v", err)
	}
	defer mgr.Close()

	if got := stateOf(t, st, vmID).ObservedState; got != "stopping" {
		t.Errorf("state = %q, want stopping: the stop was never observed to finish", got)
	}
	totals, err := st.ReservationTotals(t.Context())
	if err != nil {
		t.Fatalf("ReservationTotals: %v", err)
	}
	if totals.MemoryMiB == 0 || totals.VCPU == 0 {
		t.Errorf("reservations = %+v; a VM that may still be running still holds them", totals)
	}
	// Nothing is signalled: the scan could not say which process this row names,
	// and a stop aimed at a VM nobody can identify is the signal this whole
	// package refuses to send.
	if calls := rt.CallsFor(vmID); len(calls) != 0 {
		t.Errorf("calls for %s = %v, want none on a VM the runtime could not classify", vmID, calls)
	}
	if recs := ambiguities(t, st, vmID); len(recs) != 1 {
		t.Fatalf("vm.reconcile_ambiguous records = %d, want 1", len(recs))
	}
}

// TestReconcileStillFailsARunningRowTheRuntimeSaysIsGone keeps the answer that
// was always right. A scan that looked and found no VMM is evidence, and the row
// is failed with its compute released, exactly as before.
func TestReconcileStillFailsARunningRowTheRuntimeSaysIsGone(t *testing.T) {
	st := openStoreForManager(t)
	vmID := liveVM(t, st, "really-gone", "running")

	mgr, err := runtime.NewManager(st, runtimetest.NewFake(), defaultCfg())
	if err != nil {
		t.Fatalf("NewManager (reconcile): %v", err)
	}
	defer mgr.Close()

	if got := stateOf(t, st, vmID).ObservedState; got != "failed" {
		t.Errorf("state = %q, want failed: no finding at all is the documented deviation, "+
			"and it is not what this test changed", got)
	}
	if recs := ambiguities(t, st, vmID); len(recs) != 0 {
		t.Errorf("vm.reconcile_ambiguous records = %d, want 0: nothing was ambiguous here", len(recs))
	}
}
