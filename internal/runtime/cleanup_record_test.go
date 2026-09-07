// ABOUTME: A cleanup the controller could not finish at startup must leave the
// ABOUTME: operator a record of why, not a row parked with no explanation.
package runtime_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/2389-research/observatory/internal/runtime"
	"github.com/2389-research/observatory/internal/runtime/runtimetest"
	"github.com/2389-research/observatory/internal/store"
)

// cleanupFailures returns the vm.cleanup_failed events recorded for vmID.
func cleanupFailures(t *testing.T, st *store.Store, vmID string) []map[string]any {
	t.Helper()
	res, err := st.Query(t.Context(), store.Query{VMID: &vmID, Kind: "vm.cleanup_failed"})
	if err != nil {
		t.Fatalf("query vm.cleanup_failed: %v", err)
	}
	out := make([]map[string]any, 0, len(res.Events))
	for _, e := range res.Events {
		out = append(out, e.Data)
	}
	return out
}

// TestAStalledDeleteRecordsWhyItStalled covers the half of the cleanup contract
// the parked row cannot carry. SPEC §5.3 asks for cleanup failures to be
// recorded and retried; Reconcile retries, and until now recorded nothing. The
// synchronous DELETE answers its caller with a typed cause and a remediation,
// but that answer is a response body: an operator who was not holding the
// request open — which is everyone, after a restart — finds a row at "deleting"
// and no statement of what is still on the host or why.
func TestAStalledDeleteRecordsWhyItStalled(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	vmID, _ := failedVMAfterLaunch(t, st, fk, "stalled-delete-record")

	stillAlive := errors.New("privd: invalid_state: vm process is still alive; signal first")
	fk.FailNext("Release", vmID, stillAlive)
	mgr := newManager(t, st, fk)
	if _, err := mgr.Delete(t.Context(), vmID, false, nil); err == nil {
		t.Fatal("delete succeeded while privd refused the release")
	}
	mgr.Close()

	// The restart retries and fails the same way.
	fk.FailNext("Release", vmID, stillAlive)
	mgr2, err := runtime.NewManager(st, fk, defaultCfg())
	if err != nil {
		t.Fatalf("NewManager (restart): %v", err)
	}
	defer mgr2.Close()

	// Two attempts, two records. The DELETE and the restart's retry are separate
	// failures and each one is a fact about the host at the time it happened; a
	// single collapsed record would say a cleanup is outstanding without saying
	// it has now been refused twice.
	recs := cleanupFailures(t, st, vmID)
	if len(recs) != 2 {
		t.Fatalf("a delete that failed twice recorded %d vm.cleanup_failed events, want 2", len(recs))
	}
	last := recs[len(recs)-1]
	if got, _ := last["vm_id"].(string); got != vmID {
		t.Errorf("vm_id = %q, want %q", got, vmID)
	}
	if got, _ := last["state"].(string); got != "deleting" {
		t.Errorf("state = %q, want deleting — the state the row is retained in", got)
	}
	reason, _ := last["reason"].(string)
	if !strings.Contains(reason, "still alive") {
		t.Errorf("reason = %q, want the runtime's own explanation", reason)
	}
}

// TestAStalledStopRecordsWhyItStalled is the same contract on the other retained
// state. Reconcile finishes an adopted VM's interrupted stop; when the force-stop
// will not take, the row stays at "stopping" with its compute still reserved and
// the reason is just as invisible to the operator as a stalled delete's was.
func TestAStalledStopRecordsWhyItStalled(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	vmID := stoppingVM(t, st, "stalled-stop-record")

	wontDie := errors.New("privd: internal: SIGKILL delivered, process still present")
	fk.FailNext("ForceStop", vmID, wontDie)
	cfg := defaultCfg()
	cfg.AdoptedVMs = map[string]bool{vmID: true}
	mgr, err := runtime.NewManager(st, fk, cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Close()

	recs := cleanupFailures(t, st, vmID)
	if len(recs) == 0 {
		t.Fatal("a stop that would not take recorded no vm.cleanup_failed event")
	}
	last := recs[len(recs)-1]
	if got, _ := last["state"].(string); got != "stopping" {
		t.Errorf("state = %q, want stopping", got)
	}
	reason, _ := last["reason"].(string)
	if !strings.Contains(reason, "still present") {
		t.Errorf("reason = %q, want the runtime's own explanation", reason)
	}
}
