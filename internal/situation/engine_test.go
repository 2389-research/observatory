// ABOUTME: Tests the trigger engine and situation snapshot: honest active set,
// ABOUTME: crash-safe lazy evaluation, duplicate collapse, quiet-with-watch-scope.
package situation_test

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/events"
	"github.com/2389-research/observatory-v2/internal/situation"
	"github.com/2389-research/observatory-v2/internal/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "events.sqlite"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func testUUID(n int) string {
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", n)
}

func allTriggers() map[string]bool {
	return map[string]bool{
		"lifecycle_failed": true, "run_concluded": true, "telemetry_degraded": true,
		"spool_threshold": true, "disk_reserve_threshold": true,
		"policy_denial_anomaly": true, "capacity_exhausted": true,
		"reconciliation_surprise": true,
	}
}

func engineOver(s *store.Store, triggers map[string]bool) *situation.Engine {
	return situation.New(s, situation.Config{
		Triggers:           triggers,
		QueueMaxItems:      500,
		CollapseDuplicates: true,
	})
}

func fsModify(source, seq string, vm *string) *events.Envelope {
	return &events.Envelope{
		SchemaVersion:    1,
		VMID:             vm,
		SourceInstanceID: source,
		SourceSeq:        seq,
		Kind:             "fs.modify",
		Provenance:       events.GuestReported,
		Sensor:           "fanotify",
		HostReceivedAt:   events.Timestamp{Time: time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)},
		Quality: events.Quality{
			PathResolution: events.PathExactAtCapture,
			Attribution:    events.AttributionExact,
		},
		Data: map[string]any{"path_display": "/workspace/app.py"},
	}
}

// breakTelemetry provokes a real telemetry.unregistered_kind health event via
// the store's own rejection path — no synthetic health events.
func breakTelemetry(t *testing.T, s *store.Store, source, seq string) {
	t.Helper()
	env := fsModify(source, seq, nil)
	env.Kind = "made.up_kind"
	if _, err := s.Append(t.Context(), env); !errors.Is(err, store.ErrUnregisteredKind) {
		t.Fatalf("expected unregistered kind rejection, got %v", err)
	}
}

func TestActiveClassesIsEnabledIntersectImplemented(t *testing.T) {
	s := openStore(t)

	// Five classes are now implemented (run_concluded added in Task 9).
	wantAll := []string{"capacity_exhausted", "lifecycle_failed", "reconciliation_surprise", "run_concluded", "telemetry_degraded"}
	got := engineOver(s, allTriggers()).ActiveClasses()
	if len(got) != len(wantAll) {
		t.Errorf("active = %v, want %v", got, wantAll)
	} else {
		for i, c := range wantAll {
			if got[i] != c {
				t.Errorf("active[%d] = %q, want %q", i, got[i], c)
			}
		}
	}

	off := allTriggers()
	off["telemetry_degraded"] = false
	if got := engineOver(s, off).ActiveClasses(); len(got) != 4 {
		t.Errorf("disabled class still active or missing: %v", got)
	}

	// A configured-but-unknown class never appears: presence would claim a
	// watch that no code performs (P-03).
	if got := engineOver(s, map[string]bool{"telemetry_degraded": true, "sharknado_warning": true}).ActiveClasses(); len(got) != 1 {
		t.Errorf("unknown class leaked into active set: %v", got)
	}
}

func TestEvaluateRaisesOnTelemetryDegradation(t *testing.T) {
	s := openStore(t)
	eng := engineOver(s, allTriggers())
	ctx := t.Context()

	breakTelemetry(t, s, testUUID(91), "1")
	if err := eng.Evaluate(ctx); err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	items, err := s.ListAttention(ctx, store.AttentionQuery{Limit: 10})
	if err != nil || len(items) != 1 {
		t.Fatalf("items = %+v, %v", items, err)
	}
	it := items[0]
	if it.TriggerClass != "telemetry_degraded" || it.Severity != store.SeverityNeedsDecision {
		t.Errorf("item = %+v", it)
	}
	if it.Summary == "" || it.SystemAction == "" || len(it.EvidenceLinks) == 0 {
		t.Errorf("item lacks summary/action/evidence: %+v", it)
	}

	// Re-evaluating raises nothing new: the cursor moved past the source event.
	if err := eng.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.ListAttention(ctx, store.AttentionQuery{Limit: 10}); len(again) != 1 {
		t.Errorf("re-evaluate re-raised: %d items", len(again))
	}
}

func TestEvaluateSurvivesRestartWithoutReRaise(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.sqlite")
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	breakTelemetry(t, s, testUUID(91), "1")
	if err := engineOver(s, allTriggers()).Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// A fresh process (new store handle, new engine) must not re-raise: the
	// engine cursor is durable state, not process memory.
	s2, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	if err := engineOver(s2, allTriggers()).Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	items, err := s2.ListAttention(ctx, store.AttentionQuery{Limit: 10})
	if err != nil || len(items) != 1 {
		t.Fatalf("after restart: %d items, %v", len(items), err)
	}
}

func TestEvaluateCollapsesRepeatedDegradation(t *testing.T) {
	s := openStore(t)
	eng := engineOver(s, allTriggers())
	ctx := t.Context()

	breakTelemetry(t, s, testUUID(91), "1")
	breakTelemetry(t, s, testUUID(91), "2")
	if err := eng.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	items, err := s.ListAttention(ctx, store.AttentionQuery{Limit: 10})
	if err != nil || len(items) != 1 {
		t.Fatalf("items = %+v, %v", items, err)
	}
	if items[0].Count != 2 {
		t.Errorf("count = %d, want 2 (collapsed)", items[0].Count)
	}
}

func TestEvaluateRespectsDisabledClass(t *testing.T) {
	s := openStore(t)
	off := allTriggers()
	off["telemetry_degraded"] = false
	eng := engineOver(s, off)
	ctx := t.Context()

	breakTelemetry(t, s, testUUID(91), "1")
	if err := eng.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	if items, _ := s.ListAttention(ctx, store.AttentionQuery{Limit: 10}); len(items) != 0 {
		t.Errorf("disabled class raised: %+v", items)
	}
	// The cursor still advances: disabled is a choice, not a stall.
	cur, err := s.ReadEngineCursor(ctx, situation.CursorName)
	if err != nil || cur == 0 {
		t.Errorf("cursor = %d, %v; want advanced past scanned events", cur, err)
	}
}

func TestSnapshotEmptyStoreIsMonitoredCalm(t *testing.T) {
	s := openStore(t)
	eng := engineOver(s, allTriggers())

	snap, err := eng.Snapshot(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	if snap.AsOfCursor != "0" || !snap.Quiet {
		t.Errorf("snapshot = %+v, want as_of 0 and quiet", snap)
	}
	// Quiet must carry the watch scope: calm is only meaningful when the
	// response says who was watching (P-03). Now 5 classes are implemented.
	if len(snap.ActiveClasses) != 5 {
		t.Errorf("quiet without watch scope: %+v", snap.ActiveClasses)
	}
	if snap.VMsRunning != 0 || snap.VMsTotal != 0 || len(snap.Head) != 0 {
		t.Errorf("empty host misreported: %+v", snap)
	}
}

func TestSnapshotSinceDeltaAndOpenAttention(t *testing.T) {
	s := openStore(t)
	eng := engineOver(s, allTriggers())
	ctx := t.Context()
	vm := "00000000-0000-4000-8000-000000000001"

	res, err := s.Append(ctx, fsModify(testUUID(92), "1", &vm))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := eng.Snapshot(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if snap.Quiet != true || snap.AsOfCursor != res.EventID {
		t.Errorf("no attention yet, snapshot = %+v", snap)
	}

	// since = as_of and nothing new: quiet delta.
	delta, err := eng.Snapshot(ctx, snap.AsOfCursor)
	if err != nil {
		t.Fatal(err)
	}
	if !delta.Quiet || delta.SinceCursor != snap.AsOfCursor {
		t.Errorf("delta = %+v, want quiet echoing since", delta)
	}

	// New events after since: not quiet.
	breakTelemetry(t, s, testUUID(91), "1")
	if err := eng.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	loud, err := eng.Snapshot(ctx, snap.AsOfCursor)
	if err != nil {
		t.Fatal(err)
	}
	if loud.Quiet {
		t.Error("events and open attention after since, still quiet")
	}
	if loud.AttentionOpen != 1 || len(loud.Head) != 1 {
		t.Errorf("head = %+v open = %d", loud.Head, loud.AttentionOpen)
	}
	if loud.Head[0].TriggerClass != "telemetry_degraded" {
		t.Errorf("head item = %+v", loud.Head[0])
	}

	// Bad cursor teaches, not 500s.
	if _, err := eng.Snapshot(ctx, "not-a-cursor"); !errors.Is(err, store.ErrInvalidCursor) {
		t.Errorf("bad since error = %v", err)
	}
}

// makeTestVM creates a VM in "provisioning" state and returns its VMID.
// Caller is responsible for transitioning further.
func makeTestVM(t *testing.T, s *store.Store, vmID string) {
	t.Helper()
	_, _, _, err := s.CreateVMWithOperation(t.Context(), store.CreateVMInput{
		VMID:             vmID,
		Name:             "trigger-test-vm",
		Owner:            "local_operator",
		TemplateID:       "tmpl-test",
		TemplateDigest:   "sha256:" + fmt.Sprintf("%064d", 0),
		VCPUCount:        2,
		MemoryMiB:        2048,
		MemoryTotalMiB:   2816,
		RootDiskMiB:      8192,
		WorkspaceDiskMiB: 10240,
		Labels:           map[string]string{},
		Kind:             "vm.create",
		RequestHash:      vmID,
		Admit:            func(store.ReservationTotals) error { return nil },
	})
	if err != nil {
		t.Fatalf("makeTestVM: %v", err)
	}
}

func TestEvaluateRaisesOnLifecycleFailed(t *testing.T) {
	// lifecycle_failed fires when a VM transitions to "failed" for a reason
	// that is NOT a reconciliation reason (unexpected operational failure).
	s := openStore(t)
	eng := engineOver(s, allTriggers())
	ctx := t.Context()

	vmID := testUUID(100)
	makeTestVM(t, s, vmID)

	stage := "launch"
	_, err := s.TransitionVM(ctx, store.TransitionInput{
		VMID:           vmID,
		To:             "failed",
		Reason:         "launch_error",
		OperationID:    0,
		ReleaseCompute: true,
		FailureStage:   &stage,
		FailureReason:  &stage,
	})
	if err != nil {
		t.Fatalf("TransitionVM to failed: %v", err)
	}

	if err := eng.Evaluate(ctx); err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	items, err := s.ListAttention(ctx, store.AttentionQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, it := range items {
		if it.TriggerClass == "lifecycle_failed" {
			found = true
			if it.Summary == "" || it.SystemAction == "" {
				t.Errorf("lifecycle_failed item lacks summary/action: %+v", it)
			}
		}
		if it.TriggerClass == "reconciliation_surprise" {
			t.Errorf("reconciliation_surprise should NOT fire for non-reconciliation reason; item: %+v", it)
		}
	}
	if !found {
		t.Errorf("lifecycle_failed not raised; items: %+v", items)
	}
}

func TestEvaluateRaisesOnReconciliationSurprise(t *testing.T) {
	// reconciliation_surprise fires when the controller marks a VM failed with
	// a reconciliation reason (controller_restart or vmm_disappeared_on_restart).
	s := openStore(t)
	eng := engineOver(s, allTriggers())
	ctx := t.Context()

	vmID := testUUID(101)
	makeTestVM(t, s, vmID)

	stage := "provisioning"
	_, err := s.TransitionVM(ctx, store.TransitionInput{
		VMID:           vmID,
		To:             "failed",
		Reason:         "controller_restart",
		OperationID:    0,
		ReleaseCompute: true,
		FailureStage:   &stage,
		FailureReason:  &stage,
	})
	if err != nil {
		t.Fatalf("TransitionVM to failed: %v", err)
	}

	if err := eng.Evaluate(ctx); err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	items, err := s.ListAttention(ctx, store.AttentionQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, it := range items {
		if it.TriggerClass == "reconciliation_surprise" {
			found = true
		}
		if it.TriggerClass == "lifecycle_failed" {
			t.Errorf("lifecycle_failed should NOT fire for reconciliation reason; item: %+v", it)
		}
	}
	if !found {
		t.Errorf("reconciliation_surprise not raised; items: %+v", items)
	}
}

func TestEvaluateRaisesOnCapacityExhausted(t *testing.T) {
	// capacity_exhausted fires when a create is refused with insufficient_capacity.
	s := openStore(t)
	eng := engineOver(s, allTriggers())
	ctx := t.Context()

	_, _, _, err := s.CreateVMWithOperation(ctx, store.CreateVMInput{
		VMID:             testUUID(102),
		Name:             "over-capacity",
		Owner:            "local_operator",
		TemplateID:       "tmpl-test",
		TemplateDigest:   "sha256:" + fmt.Sprintf("%064d", 0),
		VCPUCount:        2,
		MemoryMiB:        2048,
		MemoryTotalMiB:   2816,
		RootDiskMiB:      8192,
		WorkspaceDiskMiB: 10240,
		Labels:           map[string]string{},
		Kind:             "vm.create",
		RequestHash:      testUUID(102),
		Admit: func(store.ReservationTotals) error {
			return &store.AdmissionRefusal{
				Cause:   "insufficient_capacity",
				Message: "memory: need 2816 MiB, only 0 MiB free",
			}
		},
	})
	// CreateVMWithOperation returns an error when Admit fails.
	if err == nil {
		t.Fatal("expected AdmissionRefusal, got nil")
	}

	if evalErr := eng.Evaluate(ctx); evalErr != nil {
		t.Fatalf("evaluate: %v", evalErr)
	}

	items, err := s.ListAttention(ctx, store.AttentionQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, it := range items {
		if it.TriggerClass == "capacity_exhausted" {
			found = true
			if it.Summary == "" {
				t.Errorf("capacity_exhausted item has empty summary: %+v", it)
			}
		}
	}
	if !found {
		t.Errorf("capacity_exhausted not raised; items: %+v", items)
	}
}

// makeTestRun creates a VM and a run, then transitions the run to the given
// terminal phase. Returns the vmID and runID.
func makeTestRunTerminal(t *testing.T, s *store.Store, vmID string, to string) (runID string) {
	t.Helper()
	makeTestVM(t, s, vmID)
	// Drive VM through provisioning→starting→running (SPEC §5.2 state machine).
	_, err := s.TransitionVM(t.Context(), store.TransitionInput{
		VMID:   vmID,
		To:     "starting",
		Reason: "launching",
	})
	if err != nil {
		t.Fatalf("TransitionVM to starting: %v", err)
	}
	_, err = s.TransitionVM(t.Context(), store.TransitionInput{
		VMID:   vmID,
		To:     "running",
		Reason: "launched",
	})
	if err != nil {
		t.Fatalf("TransitionVM to running: %v", err)
	}

	run, _, err := s.CreateRun(t.Context(), store.CreateRunInput{
		VMID:         vmID,
		Owner:        "local_operator",
		Goal:         "test goal",
		CriteriaType: "operator_verdict",
		OnCompletion: "keep_running",
		InitialPhase: "running",
		RequestHash:  vmID + "-run",
	})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}

	// Transition through concluding then to the terminal phase.
	_, err = s.TransitionRun(t.Context(), store.RunTransitionInput{
		RunID: run.RunID,
		From:  "running",
		To:    "concluding",
	})
	if err != nil {
		t.Fatalf("TransitionRun to concluding: %v", err)
	}
	_, err = s.TransitionRun(t.Context(), store.RunTransitionInput{
		RunID:       run.RunID,
		From:        "concluding",
		To:          to,
		EvaluatedBy: "operator",
		Reason:      "test reason",
	})
	if err != nil {
		t.Fatalf("TransitionRun to %s: %v", to, err)
	}
	return run.RunID
}

func TestEvaluateRaisesRunConcludedSucceeded(t *testing.T) {
	// succeeded → severity info; item carries trigger_class run_concluded,
	// vm_id, run_id, evidence links (run + report paths), suggested actions.
	s := openStore(t)
	eng := engineOver(s, allTriggers())
	ctx := t.Context()

	vmID := testUUID(200)
	runID := makeTestRunTerminal(t, s, vmID, "succeeded")

	if err := eng.Evaluate(ctx); err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	items, err := s.ListAttention(ctx, store.AttentionQuery{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	var found *store.AttentionItem
	for _, it := range items {
		if it.TriggerClass == "run_concluded" {
			found = it
		}
	}
	if found == nil {
		t.Fatalf("run_concluded not raised; items: %+v", items)
	}
	if found.Severity != store.SeverityInfo {
		t.Errorf("succeeded run severity = %q, want info", found.Severity)
	}
	if found.VMID == nil || *found.VMID != vmID {
		t.Errorf("vm_id = %v, want %q", found.VMID, vmID)
	}
	if found.RunID == nil || *found.RunID != runID {
		t.Errorf("run_id = %v, want %q", found.RunID, runID)
	}
	if found.Summary == "" || found.SystemAction == "" {
		t.Errorf("item lacks summary/action: %+v", found)
	}
	// Evidence links must point at run and report API paths.
	if len(found.EvidenceLinks) < 2 {
		t.Errorf("expected at least 2 evidence links (run+report), got %v", found.EvidenceLinks)
	}
	var hasRun, hasReport bool
	for _, l := range found.EvidenceLinks {
		if strings.Contains(l, "/api/v1/runs/"+runID) && !strings.Contains(l, "/report") {
			hasRun = true
		}
		if strings.Contains(l, "/api/v1/runs/"+runID+"/report") {
			hasReport = true
		}
	}
	if !hasRun || !hasReport {
		t.Errorf("evidence links missing run or report path: %v", found.EvidenceLinks)
	}
	// Suggested actions must include at least get_report.
	var hasGetReport bool
	for _, a := range found.SuggestedActions {
		if a.Action == "get" {
			if path, ok := a.Params["path"].(string); ok && strings.Contains(path, "/report") {
				hasGetReport = true
			}
		}
	}
	if !hasGetReport {
		t.Errorf("suggested actions missing get_report action: %+v", found.SuggestedActions)
	}
}

func TestEvaluateRaisesRunConcludedFailedNeedsDecision(t *testing.T) {
	// failed/inconclusive/aborted → severity needs_decision.
	for _, phase := range []string{"failed", "inconclusive", "aborted"} {
		phase := phase
		t.Run(phase, func(t *testing.T) {
			s := openStore(t)
			eng := engineOver(s, allTriggers())
			ctx := t.Context()

			vmID := testUUID(210 + len(phase))
			makeTestRunTerminal(t, s, vmID, phase)

			if err := eng.Evaluate(ctx); err != nil {
				t.Fatalf("evaluate: %v", err)
			}

			items, err := s.ListAttention(ctx, store.AttentionQuery{Limit: 20})
			if err != nil {
				t.Fatal(err)
			}
			var found *store.AttentionItem
			for _, it := range items {
				if it.TriggerClass == "run_concluded" {
					found = it
				}
			}
			if found == nil {
				t.Fatalf("run_concluded not raised for %s; items: %+v", phase, items)
			}
			if found.Severity != store.SeverityNeedsDecision {
				t.Errorf("%s run severity = %q, want needs_decision", phase, found.Severity)
			}
		})
	}
}

func TestEvaluateRunConcludedNonTerminalRaisesNothing(t *testing.T) {
	// Non-terminal transitions (pending→running, running→concluding) must not raise.
	s := openStore(t)
	eng := engineOver(s, allTriggers())
	ctx := t.Context()

	vmID := testUUID(220)
	makeTestVM(t, s, vmID)
	_, err := s.TransitionVM(ctx, store.TransitionInput{
		VMID:   vmID,
		To:     "starting",
		Reason: "launching",
	})
	if err != nil {
		t.Fatalf("TransitionVM to starting: %v", err)
	}
	_, err = s.TransitionVM(ctx, store.TransitionInput{
		VMID:   vmID,
		To:     "running",
		Reason: "launched",
	})
	if err != nil {
		t.Fatalf("TransitionVM to running: %v", err)
	}

	run, _, err := s.CreateRun(ctx, store.CreateRunInput{
		VMID:         vmID,
		Owner:        "local_operator",
		Goal:         "test goal",
		CriteriaType: "operator_verdict",
		OnCompletion: "keep_running",
		InitialPhase: "running",
		RequestHash:  vmID + "-run",
	})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}

	// Only transition to concluding — non-terminal, must not raise run_concluded.
	_, err = s.TransitionRun(ctx, store.RunTransitionInput{
		RunID: run.RunID,
		From:  "running",
		To:    "concluding",
	})
	if err != nil {
		t.Fatalf("TransitionRun to concluding: %v", err)
	}

	if err := eng.Evaluate(ctx); err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	items, err := s.ListAttention(ctx, store.AttentionQuery{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if it.TriggerClass == "run_concluded" {
			t.Errorf("run_concluded raised for non-terminal transition: %+v", it)
		}
	}
}

func TestEvaluateRunConcludedDisabledClass(t *testing.T) {
	// When run_concluded is disabled in config, the trigger does not fire.
	s := openStore(t)
	off := allTriggers()
	off["run_concluded"] = false
	eng := engineOver(s, off)
	ctx := t.Context()

	vmID := testUUID(230)
	makeTestRunTerminal(t, s, vmID, "succeeded")

	if err := eng.Evaluate(ctx); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	items, err := s.ListAttention(ctx, store.AttentionQuery{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if it.TriggerClass == "run_concluded" {
			t.Errorf("disabled run_concluded still raised: %+v", it)
		}
	}
	// run_concluded must not appear in ActiveClasses when disabled.
	for _, c := range eng.ActiveClasses() {
		if c == "run_concluded" {
			t.Error("disabled run_concluded appears in ActiveClasses")
		}
	}
}

// TestEvaluateRaisesOnStalledCleanup: a cleanup the controller could not finish
// leaves host resources owned by a VM the operator has already asked it to let
// go. The row retains that fact, but a row is something you have to go and look
// at; the attention queue is what tells an operator there is something to look
// at. The item has to name the VM, carry the runtime's own reason, and say what
// to do about it — a stalled cleanup's remedy is not obvious from its summary.
func TestEvaluateRaisesOnStalledCleanup(t *testing.T) {
	s := openStore(t)
	eng := engineOver(s, allTriggers())
	ctx := t.Context()

	vmID := testUUID(140)
	makeTestVM(t, s, vmID)

	reason := "privd: invalid_state: vm process is still alive; signal first"
	if err := s.RecordCleanupFailure(ctx, vmID, "deleting", reason); err != nil {
		t.Fatalf("RecordCleanupFailure: %v", err)
	}
	if err := eng.Evaluate(ctx); err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	items, err := s.ListAttention(ctx, store.AttentionQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, it := range items {
		if it.TriggerClass != "lifecycle_failed" {
			continue
		}
		found = true
		if !strings.Contains(it.Summary, vmID) || !strings.Contains(it.Summary, "still alive") {
			t.Errorf("summary %q must name the VM and carry the runtime's reason", it.Summary)
		}
		if it.SystemAction == "" {
			t.Errorf("stalled cleanup item lacks a system action: %+v", it)
		}
		if len(it.SuggestedActions) == 0 {
			t.Errorf("stalled cleanup item suggests no action: %+v", it)
		}
	}
	if !found {
		t.Errorf("no attention raised for a stalled cleanup; items: %+v", items)
	}
}
