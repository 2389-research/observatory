// ABOUTME: Manager batch tests: on_failure semantics (AT-014), replay without
// ABOUTME: relaunch (AT-015), using real SQLite and the runtimetest fake.
package runtime_test

import (
	"errors"
	"testing"

	"github.com/2389-research/observatory/internal/runtime"
	"github.com/2389-research/observatory/internal/runtime/runtimetest"
	"github.com/2389-research/observatory/internal/store"
)

// newBatchManager builds a manager whose semaphore admits maxParallel launches
// at a time. maxParallel=1 serializes member launches, which makes stop-wave
// ordering deterministic: the failing member runs its wave inside its slot,
// before any queued sibling can acquire one.
func newBatchManager(t *testing.T, st *store.Store, rt runtime.Runtime, maxParallel int) *runtime.Manager {
	t.Helper()
	cfg := defaultCfg()
	cfg.Admission.MaxParallelProvisions = maxParallel
	mgr, err := runtime.NewManager(st, rt, cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })
	return mgr
}

func batchReq(onFailure string, names ...string) runtime.CreateBatchRequest {
	members := make([]runtime.BatchMemberRequest, len(names))
	for i, n := range names {
		members[i] = runtime.BatchMemberRequest{Name: n, TemplateID: "tmpl-test"}
	}
	return runtime.CreateBatchRequest{
		Members:         members,
		ReservationMode: "atomic_reservation",
		OnFailure:       onFailure,
	}
}

// launchCalls counts Launch invocations recorded by the fake.
func launchCalls(fk *runtimetest.Fake) int {
	n := 0
	for _, m := range fk.MethodCalls() {
		if m == "Launch" {
			n++
		}
	}
	return n
}

// memberOpStates re-reads every member operation and buckets them by
// (state, error_cause). Key format: "state" or "state/cause".
func memberOpStates(t *testing.T, st *store.Store, result *store.CreateVMBatchResult) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, m := range result.Members {
		if m.Operation == nil {
			continue
		}
		op, err := st.GetOperation(t.Context(), m.Operation.OperationID)
		if err != nil {
			t.Fatalf("GetOperation(%d): %v", m.Operation.OperationID, err)
		}
		k := op.State
		if op.ErrorCause != nil {
			k += "/" + *op.ErrorCause
		}
		out[k]++
	}
	return out
}

// memberVMStates re-reads every member VM and buckets by observed state.
func memberVMStates(t *testing.T, st *store.Store, result *store.CreateVMBatchResult) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, m := range result.Members {
		if m.VM == nil {
			continue
		}
		vm, err := st.GetVM(t.Context(), m.VM.VMID)
		if err != nil {
			t.Fatalf("GetVM(%s): %v", m.VM.VMID, err)
		}
		out[vm.ObservedState]++
	}
	return out
}

func TestBatchOnFailureDefaultsKeepSuccessful(t *testing.T) {
	// SPEC §6.3: on_failure is keep_successful by default.
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newBatchManager(t, st, fk, 2)

	req := batchReq("", "vm-default-a")
	result, err := mgr.CreateBatch(t.Context(), "local_operator", req)
	if err != nil {
		t.Fatalf("CreateBatch with empty on_failure: %v", err)
	}
	if result.Batch.OnFailure != "keep_successful" {
		t.Errorf("stored on_failure = %q, want keep_successful", result.Batch.OnFailure)
	}
}

func TestBatchStopSuccessfulStopsSiblingsAndQueued(t *testing.T) {
	// AT-014: with maxParallel=1 and the first Launch failing, the stop wave
	// runs while both siblings are still queued in provisioning. They must be
	// parked stopped — not launched after the wave, and not left provisioning.
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newBatchManager(t, st, fk, 1)

	fk.FailCall("Launch", 1, errors.New("injected launch failure"))

	result, err := mgr.CreateBatch(t.Context(), "local_operator", batchReq("stop_successful", "vm-a", "vm-b", "vm-c"))
	if err != nil {
		t.Fatalf("CreateBatch: %v", err)
	}
	mgr.Close() // wait for all member goroutines and the wave

	if got := launchCalls(fk); got != 1 {
		t.Errorf("Launch calls = %d, want 1 (queued siblings must not launch after the wave)", got)
	}

	ops := memberOpStates(t, st, result)
	if ops["failed/launch_failed"] != 1 {
		t.Errorf("ops failed/launch_failed = %d, want 1 (buckets: %v)", ops["failed/launch_failed"], ops)
	}
	if ops["failed/batch_stop_successful"] != 2 {
		t.Errorf("ops failed/batch_stop_successful = %d, want 2 (buckets: %v)", ops["failed/batch_stop_successful"], ops)
	}

	vms := memberVMStates(t, st, result)
	if vms["failed"] != 1 || vms["stopped"] != 2 {
		t.Errorf("vm states = %v, want 1 failed + 2 stopped", vms)
	}

	batchOp, err := st.GetOperation(t.Context(), result.BatchOp.OperationID)
	if err != nil {
		t.Fatalf("GetOperation(batch): %v", err)
	}
	if batchOp.State != "failed" {
		t.Errorf("batch op state = %q, want failed", batchOp.State)
	}
	if batchOp.ErrorCause == nil || *batchOp.ErrorCause != "member_failed" {
		t.Errorf("batch op cause = %v, want member_failed", batchOp.ErrorCause)
	}
}

func TestBatchStopSuccessfulPreservesSucceededOp(t *testing.T) {
	// AT-014 honesty: a member that launched successfully before the wave keeps
	// its succeeded operation — the wave stops its VM but must not rewrite
	// evidence of a launch that did succeed.
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newBatchManager(t, st, fk, 1)

	fk.FailCall("Launch", 2, errors.New("injected launch failure"))

	result, err := mgr.CreateBatch(t.Context(), "local_operator", batchReq("stop_successful", "vm-a", "vm-b"))
	if err != nil {
		t.Fatalf("CreateBatch: %v", err)
	}
	mgr.Close()

	ops := memberOpStates(t, st, result)
	if ops["succeeded"] != 1 {
		t.Errorf("ops succeeded = %d, want 1 — the wave must not flip a succeeded op (buckets: %v)", ops["succeeded"], ops)
	}
	if ops["failed/launch_failed"] != 1 {
		t.Errorf("ops failed/launch_failed = %d, want 1 (buckets: %v)", ops["failed/launch_failed"], ops)
	}

	// The succeeded member's VM is still stopped by the wave.
	vms := memberVMStates(t, st, result)
	if vms["stopped"] != 1 || vms["failed"] != 1 {
		t.Errorf("vm states = %v, want 1 stopped + 1 failed", vms)
	}

	batchOp, err := st.GetOperation(t.Context(), result.BatchOp.OperationID)
	if err != nil {
		t.Fatalf("GetOperation(batch): %v", err)
	}
	if batchOp.State != "failed" {
		t.Errorf("batch op state = %q, want failed — stop_successful with a failure is not a batch success", batchOp.State)
	}
}

func TestBatchKeepSuccessfulLeavesSurvivors(t *testing.T) {
	// AT-014 counterpart: keep_successful leaves the survivor running and the
	// batch op succeeds because at least one member completed.
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newBatchManager(t, st, fk, 1)

	fk.FailCall("Launch", 2, errors.New("injected launch failure"))

	result, err := mgr.CreateBatch(t.Context(), "local_operator", batchReq("keep_successful", "vm-a", "vm-b"))
	if err != nil {
		t.Fatalf("CreateBatch: %v", err)
	}
	mgr.Close()

	vms := memberVMStates(t, st, result)
	if vms["running"] != 1 || vms["failed"] != 1 {
		t.Errorf("vm states = %v, want 1 running + 1 failed", vms)
	}

	ops := memberOpStates(t, st, result)
	if ops["succeeded"] != 1 || ops["failed/launch_failed"] != 1 {
		t.Errorf("op buckets = %v, want 1 succeeded + 1 failed/launch_failed", ops)
	}

	batchOp, err := st.GetOperation(t.Context(), result.BatchOp.OperationID)
	if err != nil {
		t.Fatalf("GetOperation(batch): %v", err)
	}
	if batchOp.State != "succeeded" {
		t.Errorf("batch op state = %q, want succeeded (a member survived)", batchOp.State)
	}
}

func TestBatchManagerReplayNoRelaunch(t *testing.T) {
	// AT-015: a replayed batch returns the original members and enqueues no
	// new launches.
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newBatchManager(t, st, fk, 2)

	ikey := "batch-replay-key"
	req := batchReq("keep_successful", "vm-a", "vm-b")
	req.IdempotencyKey = &ikey

	first, err := mgr.CreateBatch(t.Context(), "local_operator", req)
	if err != nil {
		t.Fatalf("CreateBatch: %v", err)
	}

	second, err := mgr.CreateBatch(t.Context(), "local_operator", req)
	if err != nil {
		t.Fatalf("CreateBatch replay: %v", err)
	}
	if !second.IsReplay {
		t.Error("second CreateBatch IsReplay = false, want true")
	}
	if second.Batch.BatchID != first.Batch.BatchID {
		t.Errorf("replay batch_id %d != original %d", second.Batch.BatchID, first.Batch.BatchID)
	}
	for i := range first.Members {
		if first.Members[i].VM == nil || second.Members[i].VM == nil {
			t.Fatalf("member %d missing VM in one of the results", i)
		}
		if first.Members[i].VM.VMID != second.Members[i].VM.VMID {
			t.Errorf("member %d VMID differs: %s vs %s", i, first.Members[i].VM.VMID, second.Members[i].VM.VMID)
		}
	}

	mgr.Close() // drain every launch goroutine before counting
	if got := launchCalls(fk); got != 2 {
		t.Errorf("Launch calls = %d, want 2 (one per member, none from the replay)", got)
	}
}
