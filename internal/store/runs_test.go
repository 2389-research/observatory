// ABOUTME: TDD tests for runs table: phase machine, idempotent create, and
// ABOUTME: VM last_event_id updates. Real SQLite; no mocks.
package store_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/2389-research/observatory-v2/internal/store"
)

var runVMCounter atomic.Int64

// runVMID returns a unique VM ID for run tests.
func runVMID() string {
	n := runVMCounter.Add(1)
	return fmt.Sprintf("runvm-%012d-0000-0000-0000-000000000000", n)
}

// mustCreateRunVM creates a VM in the running state (required for standalone runs).
func mustCreateRunVM(t *testing.T, st *store.Store) string {
	t.Helper()
	vmID := runVMID()
	_, op := mustCreateVM(t, st, vmID, "run-test-vm", nil)
	// Advance: provisioning → starting → running
	from1 := "provisioning"
	if _, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vmID, From: &from1, To: "starting", OperationID: op.OperationID,
	}); err != nil {
		t.Fatalf("transition to starting: %v", err)
	}
	from2 := "starting"
	if _, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vmID, From: &from2, To: "running", OperationID: op.OperationID,
	}); err != nil {
		t.Fatalf("transition to running: %v", err)
	}
	return vmID
}

// baseRunInput returns a minimal valid CreateRunInput for the given VM.
func baseRunInput(vmID string) store.CreateRunInput {
	return store.CreateRunInput{
		VMID:           vmID,
		Owner:          "test-owner",
		Goal:           "check that the sky is blue",
		CriteriaType:   "operator_verdict",
		OnCompletion:   "keep_running",
		ProgressEvents: false,
		IdempotencyKey: nil,
		RequestHash:    strings.Repeat("b", 64),
		InitialPhase:   "running",
	}
}

// --- CreateRun tests ---

func TestCreateRunRunningPhase(t *testing.T) {
	st := openStore(t)
	vmID := mustCreateRunVM(t, st)

	run, isReplay, err := st.CreateRun(t.Context(), baseRunInput(vmID))
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	if isReplay {
		t.Error("fresh create returned isReplay=true")
	}
	if run == nil {
		t.Fatal("run is nil")
	}
	if run.Phase != "running" {
		t.Errorf("phase = %q, want running", run.Phase)
	}
	if run.StartedAt == "" {
		t.Error("started_at not set for running initial phase")
	}
	if run.ConcludedAt != "" {
		t.Error("concluded_at should be empty for non-terminal run")
	}
	if run.CreatedEventID == 0 {
		t.Error("created_event_id must be non-zero")
	}

	// Verify run.created event was emitted and links back correctly.
	ctx := context.Background()
	res, err := st.Query(ctx, store.Query{Kind: "run.created"})
	if err != nil {
		t.Fatalf("query run.created: %v", err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("want 1 run.created event, got %d", len(res.Events))
	}
	ev := res.Events[0]
	if ev.VMID != nil {
		t.Errorf("run.created envelope vm_id should be nil (host-wide), got %v", ev.VMID)
	}
	data := ev.Data
	if data["run_id"] != run.RunID {
		t.Errorf("event data run_id = %v, want %q", data["run_id"], run.RunID)
	}
	if data["phase"] != "running" {
		t.Errorf("event data phase = %v, want running", data["phase"])
	}
	if data["vm_id"] != vmID {
		t.Errorf("event data vm_id = %v, want %q", data["vm_id"], vmID)
	}

	// CreatedEventID must match the emitted event's event_id.
	if ev.EventID == nil {
		t.Fatal("event has no EventID")
	}
	if fmt.Sprintf("%d", run.CreatedEventID) != *ev.EventID {
		t.Errorf("run.CreatedEventID = %d, event_id = %s", run.CreatedEventID, *ev.EventID)
	}
}

func TestCreateRunPendingPhase(t *testing.T) {
	st := openStore(t)
	// For pending, the VM doesn't need to be running yet.
	vmID := runVMID()
	mustCreateVM(t, st, vmID, "pending-test-vm", nil)

	in := baseRunInput(vmID)
	in.InitialPhase = "pending"
	run, _, err := st.CreateRun(t.Context(), in)
	if err != nil {
		t.Fatalf("CreateRun pending: %v", err)
	}
	if run.Phase != "pending" {
		t.Errorf("phase = %q, want pending", run.Phase)
	}
	if run.StartedAt != "" {
		t.Error("started_at should be empty for pending phase")
	}
}

func TestCreateRunIdempotencyReplay(t *testing.T) {
	st := openStore(t)
	vmID := mustCreateRunVM(t, st)

	key := "idem-key-1"
	in := baseRunInput(vmID)
	in.IdempotencyKey = &key

	run1, isReplay1, err := st.CreateRun(t.Context(), in)
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	if isReplay1 {
		t.Error("first create returned isReplay=true")
	}

	run2, isReplay2, err := st.CreateRun(t.Context(), in)
	if err != nil {
		t.Fatalf("replay create: %v", err)
	}
	if !isReplay2 {
		t.Error("replay create returned isReplay=false")
	}
	if run2.RunID != run1.RunID {
		t.Errorf("replay run_id = %q, want %q", run2.RunID, run1.RunID)
	}

	// No second event should have been emitted.
	res, _ := st.Query(context.Background(), store.Query{Kind: "run.created"})
	if len(res.Events) != 1 {
		t.Errorf("want 1 run.created after replay, got %d", len(res.Events))
	}
}

func TestCreateRunIdempotencyConflict(t *testing.T) {
	st := openStore(t)
	vmID := mustCreateRunVM(t, st)

	key := "idem-key-conflict"
	in := baseRunInput(vmID)
	in.IdempotencyKey = &key

	if _, _, err := st.CreateRun(t.Context(), in); err != nil {
		t.Fatalf("first create: %v", err)
	}

	// Same key, different request hash.
	in2 := in
	in2.RequestHash = strings.Repeat("c", 64)
	_, _, err := st.CreateRun(t.Context(), in2)
	if !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Errorf("different hash with same key: err = %v, want ErrIdempotencyConflict", err)
	}
}

func TestCreateRunNullKeyNeverReplays(t *testing.T) {
	st := openStore(t)
	// Create two VMs so two runs can coexist (one VM, one active run constraint).
	vmID1 := mustCreateRunVM(t, st)
	vmID2 := mustCreateRunVM(t, st)

	in1 := baseRunInput(vmID1)
	in1.IdempotencyKey = nil
	run1, _, err := st.CreateRun(t.Context(), in1)
	if err != nil {
		t.Fatalf("first create: %v", err)
	}

	in2 := baseRunInput(vmID2)
	in2.IdempotencyKey = nil
	in2.RequestHash = in1.RequestHash // same everything but different VM
	run2, _, err := st.CreateRun(t.Context(), in2)
	if err != nil {
		t.Fatalf("second create: %v", err)
	}

	if run1.RunID == run2.RunID {
		t.Error("null-key creates returned the same run_id (must not replay)")
	}
}

func TestCreateRunActiveRunExists(t *testing.T) {
	st := openStore(t)
	vmID := mustCreateRunVM(t, st)

	// First run — running.
	if _, _, err := st.CreateRun(t.Context(), baseRunInput(vmID)); err != nil {
		t.Fatalf("first run: %v", err)
	}

	// Second run on the same VM while first is still active → ErrActiveRunExists.
	_, _, err := st.CreateRun(t.Context(), baseRunInput(vmID))
	if !errors.Is(err, store.ErrActiveRunExists) {
		t.Errorf("second create on active VM: err = %v, want ErrActiveRunExists", err)
	}
}

func TestCreateRunAfterTerminalAllowed(t *testing.T) {
	st := openStore(t)
	vmID := mustCreateRunVM(t, st)

	run, _, err := st.CreateRun(t.Context(), baseRunInput(vmID))
	if err != nil {
		t.Fatalf("first run: %v", err)
	}

	// Conclude the first run: running → concluding → inconclusive.
	if _, err := st.TransitionRun(t.Context(), store.RunTransitionInput{
		RunID: run.RunID, From: "running", To: "concluding",
	}); err != nil {
		t.Fatalf("running→concluding: %v", err)
	}
	if _, err := st.TransitionRun(t.Context(), store.RunTransitionInput{
		RunID:       run.RunID,
		From:        "concluding",
		To:          "inconclusive",
		EvaluatedBy: "system",
		Reason:      "operator did not submit a verdict",
	}); err != nil {
		t.Fatalf("concluding→inconclusive: %v", err)
	}

	// Now a second run on the same VM should succeed.
	in2 := baseRunInput(vmID)
	in2.RequestHash = strings.Repeat("d", 64)
	run2, _, err := st.CreateRun(t.Context(), in2)
	if err != nil {
		t.Fatalf("second run after terminal: %v", err)
	}
	if run2.RunID == run.RunID {
		t.Error("second run returned same run_id")
	}
}

// --- TransitionRun tests ---

func TestTransitionRunLegalEdges(t *testing.T) {
	// Legal edges from the phase machine:
	//   pending → running
	//   pending → concluding
	//   running → concluding
	//   concluding → succeeded|failed|inconclusive|aborted
	tests := []struct {
		name        string
		from        string
		to          string
		evaluatedBy string
		reason      string
	}{
		{"pending->running", "pending", "running", "", ""},
		{"pending->concluding", "pending", "concluding", "", ""},
		{"running->concluding", "running", "concluding", "", ""},
		{"concluding->succeeded", "concluding", "succeeded", "operator", "all good"},
		{"concluding->failed", "concluding", "failed", "system", "did not converge"},
		{"concluding->inconclusive", "concluding", "inconclusive", "system", "no verdict"},
		{"concluding->aborted", "concluding", "aborted", "operator", "user requested abort"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := openStore(t)
			vmID := mustCreateRunVM(t, st)

			// Advance run to tc.from by driving necessary transitions.
			run := mustAdvanceRunToPhase(t, st, vmID, tc.from)

			after, err := st.TransitionRun(t.Context(), store.RunTransitionInput{
				RunID:       run.RunID,
				From:        tc.from,
				To:          tc.to,
				EvaluatedBy: tc.evaluatedBy,
				Reason:      tc.reason,
			})
			if err != nil {
				t.Fatalf("TransitionRun %s→%s: %v", tc.from, tc.to, err)
			}
			if after.Phase != tc.to {
				t.Errorf("phase = %q, want %q", after.Phase, tc.to)
			}

			// run.state_changed event must carry from/to.
			res, _ := st.Query(context.Background(), store.Query{Kind: "run.state_changed"})
			found := false
			for _, ev := range res.Events {
				if ev.Data["from"] == tc.from && ev.Data["to"] == tc.to {
					found = true
					if ev.VMID != nil {
						t.Error("run.state_changed envelope vm_id must be nil")
					}
					if ev.Data["run_id"] != run.RunID {
						t.Errorf("event run_id = %v", ev.Data["run_id"])
					}
					break
				}
			}
			if !found {
				t.Errorf("no run.state_changed event with from=%q to=%q", tc.from, tc.to)
			}
		})
	}
}

func TestTransitionRunTerminalSetsFields(t *testing.T) {
	st := openStore(t)
	vmID := mustCreateRunVM(t, st)
	run := mustAdvanceRunToPhase(t, st, vmID, "concluding")

	after, err := st.TransitionRun(t.Context(), store.RunTransitionInput{
		RunID:       run.RunID,
		From:        "concluding",
		To:          "succeeded",
		EvaluatedBy: "operator",
		Reason:      "looks great",
	})
	if err != nil {
		t.Fatalf("terminal transition: %v", err)
	}
	if after.ConcludedAt == "" {
		t.Error("concluded_at not set on terminal transition")
	}
	if after.ConcludedEventID == 0 {
		t.Error("concluded_event_id not set on terminal transition")
	}
	if after.EvaluatedBy != "operator" {
		t.Errorf("evaluated_by = %q, want operator", after.EvaluatedBy)
	}
	if after.Reason != "looks great" {
		t.Errorf("reason = %q", after.Reason)
	}

	// Verify concluded_event_id matches the last run.state_changed.
	res, _ := st.Query(context.Background(), store.Query{Kind: "run.state_changed"})
	if len(res.Events) == 0 {
		t.Fatal("no run.state_changed events")
	}
	lastEv := res.Events[len(res.Events)-1]
	if fmt.Sprintf("%d", after.ConcludedEventID) != *lastEv.EventID {
		t.Errorf("concluded_event_id %d != last state_changed event_id %s", after.ConcludedEventID, *lastEv.EventID)
	}
}

func TestTransitionRunIllegalEdges(t *testing.T) {
	// from is the phase we drive the run to before attempting the rejected call.
	// pinFrom is the From pin we pass to TransitionRun; for most rows it equals
	// from, but "bogus" cannot be a real stored phase so we pin "bogus" on a run
	// that is actually in "running" — this tests rejection via From-pin mismatch,
	// which still returns InvalidRunTransitionError.
	illegal := []struct {
		from, to, pinFrom string
	}{
		{"pending", "succeeded", "pending"},
		{"running", "succeeded", "running"},
		{"succeeded", "running", "succeeded"},
		{"concluding", "running", "concluding"},
		{"inconclusive", "pending", "inconclusive"},
		// Self-transition: legal from the phase machine's perspective only if it
		// were listed — it isn't, so this must be rejected.
		{"running", "running", "running"},
		// Unknown from-phase: "bogus" is not a stored phase; the run is in "running"
		// but we pin From:"bogus", causing the From-pin check to reject the call.
		{"running", "running", "bogus"},
	}

	for _, tc := range illegal {
		name := tc.pinFrom + "->" + tc.to
		t.Run(name, func(t *testing.T) {
			st := openStore(t)
			vmID := mustCreateRunVM(t, st)
			run := mustAdvanceRunToPhase(t, st, vmID, tc.from)

			// Count run.state_changed events BEFORE the rejected call.
			beforeRes, err := st.Query(t.Context(), store.Query{Kind: "run.state_changed"})
			if err != nil {
				t.Fatalf("pre-count run.state_changed: %v", err)
			}
			beforeCount := len(beforeRes.Events)

			_, err = st.TransitionRun(t.Context(), store.RunTransitionInput{
				RunID:       run.RunID,
				From:        tc.pinFrom,
				To:          tc.to,
				EvaluatedBy: "operator",
				Reason:      "test",
			})
			var ite *store.InvalidRunTransitionError
			if !errors.As(err, &ite) {
				t.Errorf("illegal pin=%s→%s: err = %v, want InvalidRunTransitionError", tc.pinFrom, tc.to, err)
			}

			// Phase must be unchanged.
			refetched, ferr := st.GetRun(t.Context(), run.RunID)
			if ferr != nil {
				t.Fatalf("GetRun after rejected transition: %v", ferr)
			}
			if refetched.Phase != run.Phase {
				t.Errorf("phase changed after rejected transition: was %q, now %q", run.Phase, refetched.Phase)
			}

			// No new run.state_changed event must have been emitted.
			afterRes, qerr := st.Query(t.Context(), store.Query{Kind: "run.state_changed"})
			if qerr != nil {
				t.Fatalf("post-count run.state_changed: %v", qerr)
			}
			if len(afterRes.Events) != beforeCount {
				t.Errorf("rejected transition emitted %d new run.state_changed event(s); want 0",
					len(afterRes.Events)-beforeCount)
			}
		})
	}
}

func TestTransitionRunFromPinMismatch(t *testing.T) {
	st := openStore(t)
	vmID := mustCreateRunVM(t, st)

	run, _, err := st.CreateRun(t.Context(), baseRunInput(vmID))
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	// run.Phase = "running". Pin From="pending" (stale caller).

	// Count run.state_changed events before the rejected call.
	beforeRes, err := st.Query(t.Context(), store.Query{Kind: "run.state_changed"})
	if err != nil {
		t.Fatalf("pre-count run.state_changed: %v", err)
	}
	beforeCount := len(beforeRes.Events)

	_, err = st.TransitionRun(t.Context(), store.RunTransitionInput{
		RunID: run.RunID, From: "pending", To: "concluding",
	})
	var ite *store.InvalidRunTransitionError
	if !errors.As(err, &ite) {
		t.Errorf("from pin mismatch: err = %v, want InvalidRunTransitionError", err)
	}

	// Phase must be unchanged (still "running").
	refetched, ferr := st.GetRun(t.Context(), run.RunID)
	if ferr != nil {
		t.Fatalf("GetRun after rejected transition: %v", ferr)
	}
	if refetched.Phase != run.Phase {
		t.Errorf("phase changed after rejected transition: was %q, now %q", run.Phase, refetched.Phase)
	}

	// No new run.state_changed event must have been emitted.
	afterRes, qerr := st.Query(t.Context(), store.Query{Kind: "run.state_changed"})
	if qerr != nil {
		t.Fatalf("post-count run.state_changed: %v", qerr)
	}
	if len(afterRes.Events) != beforeCount {
		t.Errorf("rejected transition emitted %d new run.state_changed event(s); want 0",
			len(afterRes.Events)-beforeCount)
	}
}

func TestTransitionRunBumpsVMLastEventID(t *testing.T) {
	st := openStore(t)
	vmID := mustCreateRunVM(t, st)

	// Capture VM's last_event_id before any run activity.
	vmBefore, err := st.GetVM(t.Context(), vmID)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}

	run, _, err := st.CreateRun(t.Context(), baseRunInput(vmID))
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}

	// Transition: running → concluding.
	after, err := st.TransitionRun(t.Context(), store.RunTransitionInput{
		RunID: run.RunID, From: "running", To: "concluding",
	})
	if err != nil {
		t.Fatalf("TransitionRun: %v", err)
	}

	// VM last_event_id must have advanced.
	vmAfter, err := st.GetVM(t.Context(), vmID)
	if err != nil {
		t.Fatalf("GetVM after: %v", err)
	}
	if vmAfter.LastEventID <= vmBefore.LastEventID {
		t.Errorf("last_event_id did not advance: before=%d after=%d", vmBefore.LastEventID, vmAfter.LastEventID)
	}

	// For terminal: concluded_event_id must equal VM's last_event_id.
	_, err = st.TransitionRun(t.Context(), store.RunTransitionInput{
		RunID: after.RunID, From: "concluding", To: "inconclusive",
		EvaluatedBy: "system", Reason: "no verdict",
	})
	if err != nil {
		t.Fatalf("terminal transition: %v", err)
	}
	vmTerminal, _ := st.GetVM(t.Context(), vmID)
	termRun, _ := st.GetRun(t.Context(), run.RunID)
	if termRun.ConcludedEventID != vmTerminal.LastEventID {
		t.Errorf("concluded_event_id %d != vm last_event_id %d", termRun.ConcludedEventID, vmTerminal.LastEventID)
	}
}

// --- Read method tests ---

func TestGetRun(t *testing.T) {
	st := openStore(t)
	vmID := mustCreateRunVM(t, st)
	run, _, err := st.CreateRun(t.Context(), baseRunInput(vmID))
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	got, err := st.GetRun(t.Context(), run.RunID)
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got.RunID != run.RunID {
		t.Errorf("RunID = %q, want %q", got.RunID, run.RunID)
	}
}

func TestGetRunNotFound(t *testing.T) {
	st := openStore(t)
	_, err := st.GetRun(t.Context(), "no-such-run")
	if !errors.Is(err, store.ErrRunNotFound) {
		t.Errorf("err = %v, want ErrRunNotFound", err)
	}
}

func TestActiveRunForVM(t *testing.T) {
	st := openStore(t)
	vmID := mustCreateRunVM(t, st)

	// No run yet.
	got, err := st.ActiveRunForVM(t.Context(), vmID)
	if err != nil {
		t.Fatalf("ActiveRunForVM (empty): %v", err)
	}
	if got != nil {
		t.Error("expected nil when no active run")
	}

	// Create a run.
	run, _, err := st.CreateRun(t.Context(), baseRunInput(vmID))
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	got, err = st.ActiveRunForVM(t.Context(), vmID)
	if err != nil {
		t.Fatalf("ActiveRunForVM: %v", err)
	}
	if got == nil || got.RunID != run.RunID {
		t.Errorf("ActiveRunForVM = %v", got)
	}
}

func TestListRunsKeysetPagination(t *testing.T) {
	st := openStore(t)

	// Create three VMs and one run each (to get three distinct runs).
	for i := 0; i < 3; i++ {
		vmID := mustCreateRunVM(t, st)
		in := baseRunInput(vmID)
		in.RequestHash = fmt.Sprintf("%064d", i)
		if _, _, err := st.CreateRun(t.Context(), in); err != nil {
			t.Fatalf("CreateRun %d: %v", i, err)
		}
	}

	// Page 1: limit 2.
	page1, next1, err := st.ListRuns(t.Context(), store.RunQuery{Limit: 2})
	if err != nil {
		t.Fatalf("ListRuns page1: %v", err)
	}
	if len(page1) != 2 {
		t.Fatalf("page1 has %d runs, want 2", len(page1))
	}
	if next1 == "" {
		t.Error("page1 next cursor must not be empty")
	}

	// Page 2 using cursor.
	page2, _, err := st.ListRuns(t.Context(), store.RunQuery{After: next1})
	if err != nil {
		t.Fatalf("ListRuns page2: %v", err)
	}
	if len(page2) != 1 {
		t.Fatalf("page2 has %d runs, want 1", len(page2))
	}
}

func TestListRunsFilterByVMAndPhase(t *testing.T) {
	st := openStore(t)
	vmA := mustCreateRunVM(t, st)
	vmB := mustCreateRunVM(t, st)

	// Run on vmA.
	inA := baseRunInput(vmA)
	inA.RequestHash = strings.Repeat("e", 64)
	runA, _, err := st.CreateRun(t.Context(), inA)
	if err != nil {
		t.Fatalf("run A: %v", err)
	}

	// Run on vmB.
	inB := baseRunInput(vmB)
	inB.RequestHash = strings.Repeat("f", 64)
	if _, _, err := st.CreateRun(t.Context(), inB); err != nil {
		t.Fatalf("run B: %v", err)
	}

	// Filter by vmA only.
	runsA, _, err := st.ListRuns(t.Context(), store.RunQuery{VMID: vmA})
	if err != nil {
		t.Fatalf("ListRuns vmA: %v", err)
	}
	if len(runsA) != 1 || runsA[0].RunID != runA.RunID {
		t.Errorf("vmA filter: %v", runsA)
	}

	// Filter by phase.
	runsRunning, _, err := st.ListRuns(t.Context(), store.RunQuery{Phase: "running"})
	if err != nil {
		t.Fatalf("ListRuns running: %v", err)
	}
	if len(runsRunning) != 2 {
		t.Errorf("running phase filter: got %d, want 2", len(runsRunning))
	}
}

func TestListRunsInPhases(t *testing.T) {
	st := openStore(t)
	vmID := mustCreateRunVM(t, st)

	run, _, err := st.CreateRun(t.Context(), baseRunInput(vmID))
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}

	// running phase should appear.
	active, err := st.ListRunsInPhases(t.Context(), "running", "pending")
	if err != nil {
		t.Fatalf("ListRunsInPhases: %v", err)
	}
	found := false
	for _, r := range active {
		if r.RunID == run.RunID {
			found = true
		}
	}
	if !found {
		t.Error("run not found in ListRunsInPhases(running,pending)")
	}

	// After terminal, should not appear.
	if _, err := st.TransitionRun(t.Context(), store.RunTransitionInput{
		RunID: run.RunID, From: "running", To: "concluding",
	}); err != nil {
		t.Fatalf("concluding: %v", err)
	}
	if _, err := st.TransitionRun(t.Context(), store.RunTransitionInput{
		RunID: run.RunID, From: "concluding", To: "inconclusive",
		EvaluatedBy: "system", Reason: "no verdict",
	}); err != nil {
		t.Fatalf("inconclusive: %v", err)
	}
	active2, _ := st.ListRunsInPhases(t.Context(), "running", "pending")
	for _, r := range active2 {
		if r.RunID == run.RunID {
			t.Error("terminal run still appears in ListRunsInPhases")
		}
	}
}

// --- helpers ---

// mustAdvanceRunToPhase creates a run on vmID (initial phase "running") and
// transitions it to the named target phase. Each invocation creates exactly
// one run — no recursive create calls — so it is safe to call with any vmID
// that has no active run at the time of the call.
func mustAdvanceRunToPhase(t *testing.T, st *store.Store, vmID, phase string) *store.Run {
	t.Helper()
	in := baseRunInput(vmID)
	if phase == "pending" {
		in.InitialPhase = "pending"
	}
	run, _, err := st.CreateRun(t.Context(), in)
	if err != nil {
		t.Fatalf("CreateRun for phase %q: %v", phase, err)
	}
	run = driveRunToPhase(t, st, run, phase)
	return run
}

// driveRunToPhase advances an existing run to the target phase without creating
// a new run. Used by mustAdvanceRunToPhase to avoid double-create on recursive paths.
func driveRunToPhase(t *testing.T, st *store.Store, run *store.Run, phase string) *store.Run {
	t.Helper()
	var err error
	switch phase {
	case "running", "pending":
		return run // already there after CreateRun
	case "concluding":
		run, err = st.TransitionRun(t.Context(), store.RunTransitionInput{
			RunID: run.RunID, From: run.Phase, To: "concluding",
		})
		if err != nil {
			t.Fatalf("→concluding: %v", err)
		}
	case "succeeded":
		run = driveRunToPhase(t, st, run, "concluding")
		run, err = st.TransitionRun(t.Context(), store.RunTransitionInput{
			RunID: run.RunID, From: "concluding", To: "succeeded",
			EvaluatedBy: "operator", Reason: "test",
		})
		if err != nil {
			t.Fatalf("→succeeded: %v", err)
		}
	case "failed":
		run = driveRunToPhase(t, st, run, "concluding")
		run, err = st.TransitionRun(t.Context(), store.RunTransitionInput{
			RunID: run.RunID, From: "concluding", To: "failed",
			EvaluatedBy: "system", Reason: "test",
		})
		if err != nil {
			t.Fatalf("→failed: %v", err)
		}
	case "inconclusive":
		run = driveRunToPhase(t, st, run, "concluding")
		run, err = st.TransitionRun(t.Context(), store.RunTransitionInput{
			RunID: run.RunID, From: "concluding", To: "inconclusive",
			EvaluatedBy: "system", Reason: "test",
		})
		if err != nil {
			t.Fatalf("→inconclusive: %v", err)
		}
	case "aborted":
		run = driveRunToPhase(t, st, run, "concluding")
		run, err = st.TransitionRun(t.Context(), store.RunTransitionInput{
			RunID: run.RunID, From: "concluding", To: "aborted",
			EvaluatedBy: "operator", Reason: "test abort",
		})
		if err != nil {
			t.Fatalf("→aborted: %v", err)
		}
	default:
		t.Fatalf("driveRunToPhase: unknown target phase %q", phase)
	}
	return run
}
