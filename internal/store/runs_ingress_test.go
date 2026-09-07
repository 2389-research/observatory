// ABOUTME: TDD tests for guest submission ingress (progress, result), launch-attached
// ABOUTME: runs, batch member runs, and run_reports round-trips (P4, Task 4).
package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/2389-research/observatory/internal/store"
)

// --- helpers ---

// runningRun creates a VM in running state and a run in running phase.
func runningRun(t *testing.T, st *store.Store, progressEvents bool) (string, *store.Run) {
	t.Helper()
	vmID := mustCreateRunVM(t, st)
	in := store.CreateRunInput{
		VMID:           vmID,
		Owner:          "test-owner",
		Goal:           "mission critical stuff",
		CriteriaType:   "guest_result",
		OnCompletion:   "keep_running",
		ProgressEvents: progressEvents,
		InitialPhase:   "running",
		RequestHash:    strings.Repeat("7", 64),
	}
	run, _, err := st.CreateRun(t.Context(), in)
	if err != nil {
		t.Fatalf("CreateRun running: %v", err)
	}
	return vmID, run
}

// countEvents counts events of a given kind.
func countEvents(t *testing.T, st *store.Store, kind string) int {
	t.Helper()
	res, err := st.Query(context.Background(), store.Query{Kind: kind})
	if err != nil {
		t.Fatalf("count events %s: %v", kind, err)
	}
	return len(res.Events)
}

// --- Launch-attach tests ---

func TestCreateVMWithRunAttachment(t *testing.T) {
	st := openStore(t)
	vmID := runVMID()

	vm, op, isReplay, err := st.CreateVMWithOperation(t.Context(), store.CreateVMInput{
		VMID:             vmID,
		Name:             "launch-run-vm",
		Owner:            "test-owner",
		TemplateID:       "tmpl-001",
		TemplateDigest:   "sha256:abc999",
		VCPUCount:        2,
		MemoryMiB:        2048,
		RootDiskMiB:      8192,
		WorkspaceDiskMiB: 10240,
		MemoryTotalMiB:   2048 + 768,
		NetworkProfile:   "transport",
		NetworkPolicyID:  "transport-public-web",
		Labels:           map[string]string{},
		Kind:             "vm.create",
		RequestHash:      strings.Repeat("r", 64),
		Admit:            func(store.ReservationTotals) error { return nil },
		Run: &store.RunAttachment{
			Goal:           "boot and report",
			CriteriaType:   "guest_result",
			OnCompletion:   "keep_running",
			ProgressEvents: true,
		},
	})
	if err != nil {
		t.Fatalf("CreateVMWithOperation: %v", err)
	}
	if isReplay {
		t.Error("fresh create returned isReplay=true")
	}
	if vm == nil || op == nil {
		t.Fatal("vm or op is nil")
	}

	// run.created event must exist.
	if countEvents(t, st, "run.created") != 1 {
		t.Error("want 1 run.created event after launch-attach")
	}

	// RunForVM returns the pending run.
	run, err := st.RunForVM(t.Context(), vmID)
	if err != nil {
		t.Fatalf("RunForVM: %v", err)
	}
	if run.Phase != "pending" {
		t.Errorf("phase = %q, want pending", run.Phase)
	}
	if run.Goal != "boot and report" {
		t.Errorf("goal = %q", run.Goal)
	}
}

func TestCreateVMWithRunAttachmentIdempotentReplay(t *testing.T) {
	st := openStore(t)
	vmID := runVMID()
	key := "idem-launch-run"

	input := store.CreateVMInput{
		VMID:             vmID,
		Name:             "launch-idem-vm",
		Owner:            "test-owner",
		TemplateID:       "tmpl-001",
		TemplateDigest:   "sha256:abc000",
		VCPUCount:        2,
		MemoryMiB:        2048,
		RootDiskMiB:      8192,
		WorkspaceDiskMiB: 10240,
		MemoryTotalMiB:   2048 + 768,
		NetworkProfile:   "transport",
		NetworkPolicyID:  "transport-public-web",
		Labels:           map[string]string{},
		Kind:             "vm.create",
		IdempotencyKey:   &key,
		RequestHash:      strings.Repeat("s", 64),
		Admit:            func(store.ReservationTotals) error { return nil },
		Run: &store.RunAttachment{
			Goal:           "idempotent run",
			CriteriaType:   "guest_result",
			OnCompletion:   "keep_running",
			ProgressEvents: false,
		},
	}

	// First create.
	_, _, _, err := st.CreateVMWithOperation(t.Context(), input)
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	run1, err := st.RunForVM(t.Context(), vmID)
	if err != nil {
		t.Fatalf("RunForVM first: %v", err)
	}

	// Idempotent replay.
	_, _, isReplay, err := st.CreateVMWithOperation(t.Context(), input)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !isReplay {
		t.Error("replay returned isReplay=false")
	}
	run2, err := st.RunForVM(t.Context(), vmID)
	if err != nil {
		t.Fatalf("RunForVM replay: %v", err)
	}
	if run2.RunID != run1.RunID {
		t.Errorf("replay returned different run_id: %q vs %q", run2.RunID, run1.RunID)
	}

	// Only one run.created event.
	if countEvents(t, st, "run.created") != 1 {
		t.Errorf("want 1 run.created after replay, got %d", countEvents(t, st, "run.created"))
	}
}

func TestCreateVMWithRunAttachmentAdmissionRefusalNoRun(t *testing.T) {
	st := openStore(t)
	vmID := runVMID()

	_, _, _, err := st.CreateVMWithOperation(t.Context(), store.CreateVMInput{
		VMID:             vmID,
		Name:             "refused-run-vm",
		Owner:            "test-owner",
		TemplateID:       "tmpl-001",
		TemplateDigest:   "sha256:aaa111",
		VCPUCount:        2,
		MemoryMiB:        2048,
		RootDiskMiB:      8192,
		WorkspaceDiskMiB: 10240,
		MemoryTotalMiB:   2048 + 768,
		NetworkProfile:   "transport",
		NetworkPolicyID:  "transport-public-web",
		Labels:           map[string]string{},
		Kind:             "vm.create",
		RequestHash:      strings.Repeat("q", 64),
		Admit: func(store.ReservationTotals) error {
			return &store.AdmissionRefusal{Cause: "insufficient_capacity", Message: "no room"}
		},
		Run: &store.RunAttachment{
			Goal:           "should not be created",
			CriteriaType:   "guest_result",
			OnCompletion:   "keep_running",
			ProgressEvents: false,
		},
	})
	// The error is the admission refusal (non-nil); that is expected.
	var ref *store.AdmissionRefusal
	if !errors.As(err, &ref) {
		t.Fatalf("expected AdmissionRefusal, got %v", err)
	}

	// No run row must exist.
	_, runErr := st.RunForVM(t.Context(), vmID)
	if !errors.Is(runErr, store.ErrRunNotFound) {
		t.Errorf("RunForVM after refusal: got %v, want ErrRunNotFound", runErr)
	}
	if countEvents(t, st, "run.created") != 0 {
		t.Error("run.created emitted after admission refusal")
	}
}

func TestRunForVMNotFound(t *testing.T) {
	st := openStore(t)
	_, err := st.RunForVM(t.Context(), "no-such-vm")
	if !errors.Is(err, store.ErrRunNotFound) {
		t.Errorf("RunForVM unknown vm: err = %v, want ErrRunNotFound", err)
	}
}

// --- Batch member runs ---

func TestBatchMembersWithRunGetPendingRuns(t *testing.T) {
	st := openStore(t)

	m1 := batchMember("bm-run-1")
	m2 := batchMember("bm-run-2")
	m1.Run = &store.RunAttachment{
		Goal:           "batch member goal 1",
		CriteriaType:   "guest_result",
		OnCompletion:   "keep_running",
		ProgressEvents: true,
	}
	m2.Run = &store.RunAttachment{
		Goal:           "batch member goal 2",
		CriteriaType:   "guest_result",
		OnCompletion:   "keep_running",
		ProgressEvents: false,
	}

	result, err := st.CreateVMBatch(t.Context(), store.CreateVMBatchInput{
		Owner:           "test-owner",
		RequestHash:     "hash-batch-runs",
		ReservationMode: "atomic_reservation",
		OnFailure:       "keep_successful",
		Members:         []store.BatchMemberInput{m1, m2},
		AdmitBatch:      func(_ store.ReservationTotals) error { return nil },
	})
	if err != nil {
		t.Fatalf("CreateVMBatch: %v", err)
	}

	// Both admitted members must have a pending run.
	for _, m := range result.Members {
		if m.VM == nil {
			t.Errorf("member %d: VM nil", m.Position)
			continue
		}
		run, err := st.RunForVM(t.Context(), m.VM.VMID)
		if err != nil {
			t.Errorf("member %d RunForVM: %v", m.Position, err)
			continue
		}
		if run.Phase != "pending" {
			t.Errorf("member %d: phase = %q, want pending", m.Position, run.Phase)
		}
	}

	if countEvents(t, st, "run.created") != 2 {
		t.Errorf("want 2 run.created events, got %d", countEvents(t, st, "run.created"))
	}
}

func TestBatchRefusedMembersGetNoRun(t *testing.T) {
	st := openStore(t)
	callCount := 0

	m1 := batchMember("bm-ok")
	m2 := batchMember("bm-refused")
	m1.Run = &store.RunAttachment{Goal: "ok", CriteriaType: "guest_result", OnCompletion: "keep_running"}
	m2.Run = &store.RunAttachment{Goal: "refused", CriteriaType: "guest_result", OnCompletion: "keep_running"}

	refusal := &store.AdmissionRefusal{Cause: "insufficient_capacity", Message: "no room for m2"}

	result, err := st.CreateVMBatch(t.Context(), store.CreateVMBatchInput{
		Owner:           "test-owner",
		RequestHash:     "hash-batch-partial-runs",
		ReservationMode: "best_effort",
		OnFailure:       "keep_successful",
		Members:         []store.BatchMemberInput{m1, m2},
		AdmitMember: func(_ store.ReservationTotals, _ int64, _ int, _ int64) error {
			callCount++
			if callCount == 2 {
				return refusal
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("CreateVMBatch: %v", err)
	}

	// Member 0 admitted → has run.
	m0 := result.Members[0]
	if m0.VM == nil {
		t.Fatal("member 0 VM nil")
	}
	run0, err := st.RunForVM(t.Context(), m0.VM.VMID)
	if err != nil {
		t.Errorf("member 0 RunForVM: %v", err)
	} else if run0.Phase != "pending" {
		t.Errorf("member 0 phase = %q, want pending", run0.Phase)
	}

	// Member 1 refused → no run.
	m1r := result.Members[1]
	if m1r.RefusalCause == nil {
		t.Error("member 1 should be refused")
	}
	if m1r.VM != nil {
		// RunForVM for a refused VM would also be ErrRunNotFound; just check directly.
		_, runErr := st.RunForVM(t.Context(), m2.VMID)
		if !errors.Is(runErr, store.ErrRunNotFound) {
			t.Errorf("refused member run: %v, want ErrRunNotFound", runErr)
		}
	}

	// Only 1 run.created event.
	if countEvents(t, st, "run.created") != 1 {
		t.Errorf("want 1 run.created (only admitted member), got %d", countEvents(t, st, "run.created"))
	}
}

// --- SubmitRunProgress tests ---

func TestSubmitRunProgressHappyPath(t *testing.T) {
	st := openStore(t)
	_, run := runningRun(t, st, true)

	payload := json.RawMessage(`{"pct":42}`)
	seq, err := st.SubmitRunProgress(t.Context(), store.SubmitProgressInput{
		RunID:    run.RunID,
		Payload:  payload,
		MaxBytes: 1024,
	})
	if err != nil {
		t.Fatalf("SubmitRunProgress: %v", err)
	}
	if seq != 1 {
		t.Errorf("seq = %d, want 1", seq)
	}

	// run.progress event must exist with correct fields.
	res, err := st.Query(context.Background(), store.Query{Kind: "run.progress"})
	if err != nil {
		t.Fatalf("query run.progress: %v", err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("want 1 run.progress event, got %d", len(res.Events))
	}
	ev := res.Events[0]
	if ev.Data["run_id"] != run.RunID {
		t.Errorf("event data run_id = %v, want %q", ev.Data["run_id"], run.RunID)
	}
	if fmt.Sprintf("%v", ev.Data["seq"]) != "1" {
		t.Errorf("event data seq = %v, want 1", ev.Data["seq"])
	}

	// payload must be present and round-trip as the submitted JSON object.
	rawPayload, ok := ev.Data["payload"]
	if !ok {
		t.Fatal("event data missing payload field")
	}
	// The stored payload should be a JSON object (decoded as map[string]any by the
	// event scanner), not a string or base64 blob.
	payloadMap, ok := rawPayload.(map[string]any)
	if !ok {
		t.Fatalf("event data payload is %T, want map[string]any", rawPayload)
	}
	if pct, ok := payloadMap["pct"]; !ok || fmt.Sprintf("%v", pct) != "42" {
		t.Errorf("event data payload[pct] = %v, want 42", pct)
	}
}

func TestSubmitRunProgressSeqIncrements(t *testing.T) {
	st := openStore(t)
	_, run := runningRun(t, st, true)

	for i := int64(1); i <= 3; i++ {
		payload := json.RawMessage(fmt.Sprintf(`{"i":%d}`, i))
		seq, err := st.SubmitRunProgress(t.Context(), store.SubmitProgressInput{
			RunID:    run.RunID,
			Payload:  payload,
			MaxBytes: 1024,
		})
		if err != nil {
			t.Fatalf("SubmitRunProgress %d: %v", i, err)
		}
		if seq != i {
			t.Errorf("call %d: seq = %d, want %d", i, seq, i)
		}
	}
	if countEvents(t, st, "run.progress") != 3 {
		t.Errorf("want 3 run.progress events, got %d", countEvents(t, st, "run.progress"))
	}
}

func TestSubmitRunProgressOversizedRejected(t *testing.T) {
	st := openStore(t)
	_, run := runningRun(t, st, true)

	before := countEvents(t, st, "run.progress")
	rejBefore := countEvents(t, st, "run.submission_rejected")

	payload := json.RawMessage(`{"x":"` + strings.Repeat("A", 200) + `"}`)
	_, err := st.SubmitRunProgress(t.Context(), store.SubmitProgressInput{
		RunID:    run.RunID,
		Payload:  payload,
		MaxBytes: 50,
	})
	if !errors.Is(err, store.ErrSubmissionRejected) {
		t.Errorf("oversized progress: err = %v, want ErrSubmissionRejected", err)
	}

	// No run.progress event emitted.
	if countEvents(t, st, "run.progress") != before {
		t.Error("run.progress event emitted on rejection")
	}
	// run.submission_rejected event emitted.
	if countEvents(t, st, "run.submission_rejected") != rejBefore+1 {
		t.Error("run.submission_rejected event not emitted on oversized rejection")
	}
}

func TestSubmitRunProgressInvalidJSONRejected(t *testing.T) {
	st := openStore(t)
	_, run := runningRun(t, st, true)

	rejBefore := countEvents(t, st, "run.submission_rejected")

	_, err := st.SubmitRunProgress(t.Context(), store.SubmitProgressInput{
		RunID:    run.RunID,
		Payload:  json.RawMessage(`not json`),
		MaxBytes: 1024,
	})
	if !errors.Is(err, store.ErrSubmissionRejected) {
		t.Errorf("invalid JSON progress: err = %v, want ErrSubmissionRejected", err)
	}
	if countEvents(t, st, "run.submission_rejected") != rejBefore+1 {
		t.Error("run.submission_rejected event not emitted on invalid JSON")
	}
}

func TestSubmitRunProgressDisabledRejected(t *testing.T) {
	st := openStore(t)
	_, run := runningRun(t, st, false) // progress_events=false

	rejBefore := countEvents(t, st, "run.submission_rejected")

	_, err := st.SubmitRunProgress(t.Context(), store.SubmitProgressInput{
		RunID:    run.RunID,
		Payload:  json.RawMessage(`{"ok":true}`),
		MaxBytes: 1024,
	})
	if !errors.Is(err, store.ErrSubmissionRejected) {
		t.Errorf("progress on disabled run: err = %v, want ErrSubmissionRejected", err)
	}
	// Disabled progress_events → rejection event recorded.
	if countEvents(t, st, "run.submission_rejected") != rejBefore+1 {
		t.Error("run.submission_rejected not emitted when progress_events disabled")
	}
}

func TestSubmitRunProgressTerminalRejectsWithNoEvent(t *testing.T) {
	st := openStore(t)
	_, run := runningRun(t, st, true)

	// Drive to terminal: running → concluding → inconclusive.
	run = driveRunToPhase(t, st, run, "inconclusive")

	before := countEvents(t, st, "run.submission_rejected")
	_, err := st.SubmitRunProgress(t.Context(), store.SubmitProgressInput{
		RunID:    run.RunID,
		Payload:  json.RawMessage(`{"x":1}`),
		MaxBytes: 1024,
	})
	if !errors.Is(err, store.ErrRunNotAcceptingSubmissions) {
		t.Errorf("terminal run progress: err = %v, want ErrRunNotAcceptingSubmissions", err)
	}
	// No submission_rejected event for terminal runs (they are not accepting, not rejecting format).
	if countEvents(t, st, "run.submission_rejected") != before {
		t.Error("run.submission_rejected should not be emitted for terminal-phase rejection")
	}
}

func TestSubmitRunProgressConcludingRejectsWithNoEvent(t *testing.T) {
	st := openStore(t)
	_, run := runningRun(t, st, true)

	// Drive to concluding.
	run = driveRunToPhase(t, st, run, "concluding")

	before := countEvents(t, st, "run.submission_rejected")
	_, err := st.SubmitRunProgress(t.Context(), store.SubmitProgressInput{
		RunID:    run.RunID,
		Payload:  json.RawMessage(`{"x":1}`),
		MaxBytes: 1024,
	})
	if !errors.Is(err, store.ErrRunNotAcceptingSubmissions) {
		t.Errorf("concluding run progress: err = %v, want ErrRunNotAcceptingSubmissions", err)
	}
	if countEvents(t, st, "run.submission_rejected") != before {
		t.Error("run.submission_rejected should not be emitted for concluding-phase rejection")
	}
}

// --- SubmitRunResult tests ---

func TestSubmitRunResultHappyPath(t *testing.T) {
	st := openStore(t)
	_, run := runningRun(t, st, false)

	result := json.RawMessage(`{"status":"succeeded","detail":"all good"}`)
	updated, err := st.SubmitRunResult(t.Context(), store.SubmitResultInput{
		RunID:    run.RunID,
		Result:   result,
		MaxBytes: 4096,
	})
	if err != nil {
		t.Fatalf("SubmitRunResult: %v", err)
	}
	if updated.ResultStatus != "succeeded" {
		t.Errorf("ResultStatus = %q, want succeeded", updated.ResultStatus)
	}
	if updated.ResultJSON == "" {
		t.Error("ResultJSON empty after submit")
	}
	// Phase is UNCHANGED (conclusion is Manager's job).
	if updated.Phase != "running" {
		t.Errorf("Phase = %q after result submit, want running (unchanged)", updated.Phase)
	}

	// run.result_recorded event.
	res, err := st.Query(context.Background(), store.Query{Kind: "run.result_recorded"})
	if err != nil {
		t.Fatalf("query run.result_recorded: %v", err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("want 1 run.result_recorded, got %d", len(res.Events))
	}
	ev := res.Events[0]
	if ev.Data["run_id"] != run.RunID {
		t.Errorf("event run_id = %v", ev.Data["run_id"])
	}
	if ev.Data["status"] != "succeeded" {
		t.Errorf("event status = %v", ev.Data["status"])
	}
}

func TestSubmitRunResultFailedStatus(t *testing.T) {
	st := openStore(t)
	_, run := runningRun(t, st, false)

	result := json.RawMessage(`{"status":"failed","detail":"broke"}`)
	updated, err := st.SubmitRunResult(t.Context(), store.SubmitResultInput{
		RunID:    run.RunID,
		Result:   result,
		MaxBytes: 4096,
	})
	if err != nil {
		t.Fatalf("SubmitRunResult failed: %v", err)
	}
	if updated.ResultStatus != "failed" {
		t.Errorf("ResultStatus = %q, want failed", updated.ResultStatus)
	}
}

func TestSubmitRunResultMissingStatusRejected(t *testing.T) {
	st := openStore(t)
	_, run := runningRun(t, st, false)

	before := countEvents(t, st, "run.result_recorded")
	rejBefore := countEvents(t, st, "run.submission_rejected")

	_, err := st.SubmitRunResult(t.Context(), store.SubmitResultInput{
		RunID:    run.RunID,
		Result:   json.RawMessage(`{"detail":"oops"}`),
		MaxBytes: 4096,
	})
	if !errors.Is(err, store.ErrSubmissionRejected) {
		t.Errorf("missing status: err = %v, want ErrSubmissionRejected", err)
	}
	if countEvents(t, st, "run.result_recorded") != before {
		t.Error("run.result_recorded emitted on rejection")
	}
	if countEvents(t, st, "run.submission_rejected") != rejBefore+1 {
		t.Error("run.submission_rejected not emitted on missing status")
	}
}

func TestSubmitRunResultInvalidStatusRejected(t *testing.T) {
	st := openStore(t)
	_, run := runningRun(t, st, false)

	_, err := st.SubmitRunResult(t.Context(), store.SubmitResultInput{
		RunID:    run.RunID,
		Result:   json.RawMessage(`{"status":"winning","detail":"nope"}`),
		MaxBytes: 4096,
	})
	if !errors.Is(err, store.ErrSubmissionRejected) {
		t.Errorf("invalid status: err = %v, want ErrSubmissionRejected", err)
	}
}

func TestSubmitRunResultOversizedRejected(t *testing.T) {
	st := openStore(t)
	_, run := runningRun(t, st, false)

	bigResult := json.RawMessage(`{"status":"succeeded","detail":"` + strings.Repeat("X", 500) + `"}`)
	_, err := st.SubmitRunResult(t.Context(), store.SubmitResultInput{
		RunID:    run.RunID,
		Result:   bigResult,
		MaxBytes: 100,
	})
	if !errors.Is(err, store.ErrSubmissionRejected) {
		t.Errorf("oversized result: err = %v, want ErrSubmissionRejected", err)
	}
}

func TestSubmitRunResultDetailOver1024Rejected(t *testing.T) {
	st := openStore(t)
	_, run := runningRun(t, st, false)

	bigDetail := strings.Repeat("Z", 1025)
	result := json.RawMessage(`{"status":"succeeded","detail":"` + bigDetail + `"}`)
	_, err := st.SubmitRunResult(t.Context(), store.SubmitResultInput{
		RunID:    run.RunID,
		Result:   result,
		MaxBytes: 1024 * 1024,
	})
	if !errors.Is(err, store.ErrSubmissionRejected) {
		t.Errorf("detail over 1024: err = %v, want ErrSubmissionRejected", err)
	}
}

func TestSubmitRunResultSecondResultRejected(t *testing.T) {
	st := openStore(t)
	_, run := runningRun(t, st, false)

	first := json.RawMessage(`{"status":"succeeded","detail":"first"}`)
	if _, err := st.SubmitRunResult(t.Context(), store.SubmitResultInput{
		RunID:    run.RunID,
		Result:   first,
		MaxBytes: 4096,
	}); err != nil {
		t.Fatalf("first result: %v", err)
	}

	// Verify first result is stored.
	r, _ := st.GetRun(t.Context(), run.RunID)
	if r.ResultStatus != "succeeded" {
		t.Fatalf("first result not stored: %q", r.ResultStatus)
	}

	second := json.RawMessage(`{"status":"failed","detail":"second attempt"}`)
	_, err := st.SubmitRunResult(t.Context(), store.SubmitResultInput{
		RunID:    run.RunID,
		Result:   second,
		MaxBytes: 4096,
	})
	if !errors.Is(err, store.ErrSubmissionRejected) {
		t.Errorf("second result: err = %v, want ErrSubmissionRejected", err)
	}

	// First result unchanged.
	r2, _ := st.GetRun(t.Context(), run.RunID)
	if r2.ResultStatus != "succeeded" {
		t.Errorf("first result overwritten: status = %q", r2.ResultStatus)
	}
}

func TestSubmitRunResultTerminalRejectsWithNotAccepting(t *testing.T) {
	st := openStore(t)
	_, run := runningRun(t, st, false)

	run = driveRunToPhase(t, st, run, "inconclusive")

	before := countEvents(t, st, "run.submission_rejected")
	_, err := st.SubmitRunResult(t.Context(), store.SubmitResultInput{
		RunID:    run.RunID,
		Result:   json.RawMessage(`{"status":"succeeded","detail":"late"}`),
		MaxBytes: 4096,
	})
	if !errors.Is(err, store.ErrRunNotAcceptingSubmissions) {
		t.Errorf("terminal run result: err = %v, want ErrRunNotAcceptingSubmissions", err)
	}
	if countEvents(t, st, "run.submission_rejected") != before {
		t.Error("run.submission_rejected should not be emitted for terminal-phase result")
	}
}

// --- PutRunReport / GetRunReport tests ---

func TestPutAndGetRunReport(t *testing.T) {
	st := openStore(t)
	_, run := runningRun(t, st, false)

	reportJSON := `{"run_id":"` + run.RunID + `","status":"succeeded"}`
	digest := "sha256:abcdef123456"

	if err := st.PutRunReport(t.Context(), run.RunID, reportJSON, digest, 42); err != nil {
		t.Fatalf("PutRunReport: %v", err)
	}

	got, err := st.GetRunReport(t.Context(), run.RunID)
	if err != nil {
		t.Fatalf("GetRunReport: %v", err)
	}
	if got.RunID != run.RunID {
		t.Errorf("RunID = %q, want %q", got.RunID, run.RunID)
	}
	if got.Digest != digest {
		t.Errorf("Digest = %q, want %q", got.Digest, digest)
	}
	if got.ReportJSON != reportJSON {
		t.Errorf("ReportJSON = %q, want %q", got.ReportJSON, reportJSON)
	}
	if got.OperationID != 42 {
		t.Errorf("OperationID = %d, want 42", got.OperationID)
	}
	if got.GeneratedAt == "" {
		t.Error("GeneratedAt is empty")
	}
}

func TestGetRunReportNotFound(t *testing.T) {
	st := openStore(t)
	_, err := st.GetRunReport(t.Context(), "no-such-run")
	if !errors.Is(err, store.ErrReportNotFound) {
		t.Errorf("err = %v, want ErrReportNotFound", err)
	}
}

func TestPutRunReportImmutable(t *testing.T) {
	st := openStore(t)
	_, run := runningRun(t, st, false)

	if err := st.PutRunReport(t.Context(), run.RunID, `{"v":1}`, "sha256:first", 1); err != nil {
		t.Fatalf("first PutRunReport: %v", err)
	}

	// Second put must be refused.
	err := st.PutRunReport(t.Context(), run.RunID, `{"v":2}`, "sha256:second", 2)
	if err == nil {
		t.Error("second PutRunReport should fail (immutable)")
	}
	// Error must mention the existing digest.
	if !strings.Contains(err.Error(), "sha256:first") {
		t.Errorf("error does not mention existing digest: %v", err)
	}

	// Original report unchanged: both Digest and ReportJSON must be byte-identical to the first Put.
	got, _ := st.GetRunReport(t.Context(), run.RunID)
	if got.Digest != "sha256:first" {
		t.Errorf("original digest overwritten: %q", got.Digest)
	}
	if got.ReportJSON != `{"v":1}` {
		t.Errorf("original ReportJSON overwritten: %q", got.ReportJSON)
	}
}
