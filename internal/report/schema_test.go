// ABOUTME: Schema validation tests for generated run reports (AT-092/AT-094).
// ABOUTME: Tests four terminal run shapes against the JSON schema using real components.
package report_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/2389-research/observatory-v2/internal/report"
	"github.com/2389-research/observatory-v2/internal/store"
)

func loadSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	// Locate the repo root relative to this file's location.
	_, thisFile, _, _ := runtime.Caller(0)
	// thisFile is .../internal/report/schema_test.go
	// schema is at .../docs/schemas/run-report.schema.json
	schemaPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "docs", "schemas", "run-report.schema.json")
	schemaPath, err := filepath.Abs(schemaPath)
	if err != nil {
		t.Fatalf("abs schema path: %v", err)
	}
	if _, err := os.Stat(schemaPath); err != nil {
		t.Fatalf("schema not found at %s: %v", schemaPath, err)
	}
	c := jsonschema.NewCompiler()
	sch, err := c.Compile(schemaPath)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return sch
}

func validateReport(t *testing.T, sch *jsonschema.Schema, raw json.RawMessage) {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if err := sch.Validate(v); err != nil {
		t.Fatalf("schema validation failed: %v\nreport: %s", err, string(raw))
	}
}

// --- scenario builder ---

// scenarioKind selects which terminal shape to build.
type scenarioKind int

const (
	scenarioGuestResultSucceeded scenarioKind = iota
	scenarioAborted
	scenarioLaunchFailed // never booted — boot_ids empty
	scenarioOperatorVerdict
)

// buildScenario creates a terminal run in st using the given scenario shape.
// Returns the run_id of the terminal run.
func buildScenario(t *testing.T, st *store.Store, kind scenarioKind) string {
	t.Helper()
	ctx := t.Context()

	vmID := mustCreateRunningVM(t, st)

	switch kind {
	case scenarioGuestResultSucceeded:
		// Standalone run: guest_result criteria, submit progress x2, submit result succeeded.
		run, _, err := st.CreateRun(ctx, store.CreateRunInput{
			VMID: vmID, Owner: "test", Goal: "validate schema guest-result",
			CriteriaType: "guest_result", OnCompletion: "keep_running",
			ProgressEvents: true,
			RequestHash:    "hash-gr",
			InitialPhase:   "running",
		})
		if err != nil {
			t.Fatalf("CreateRun: %v", err)
		}
		for i := 0; i < 2; i++ {
			payload, _ := json.Marshal(map[string]any{"step": i + 1, "ok": true})
			if _, err := st.SubmitRunProgress(ctx, store.SubmitProgressInput{
				RunID: run.RunID, Payload: payload, MaxBytes: 1 << 20,
			}); err != nil {
				t.Fatalf("SubmitRunProgress: %v", err)
			}
		}
		result, _ := json.Marshal(map[string]any{"status": "succeeded", "detail": "all good"})
		if _, err := st.SubmitRunResult(ctx, store.SubmitResultInput{
			RunID: run.RunID, Result: result, MaxBytes: 1 << 20,
		}); err != nil {
			t.Fatalf("SubmitRunResult: %v", err)
		}
		mustTransitionRun(t, st, run.RunID, "running", "concluding", "", "")
		mustTransitionRun(t, st, run.RunID, "concluding", "succeeded", "guest_result", "guest reported success")
		return run.RunID

	case scenarioAborted:
		run, _, err := st.CreateRun(ctx, store.CreateRunInput{
			VMID: vmID, Owner: "test", Goal: "validate schema aborted",
			CriteriaType: "guest_result", OnCompletion: "keep_running",
			RequestHash: "hash-aborted", InitialPhase: "running",
		})
		if err != nil {
			t.Fatalf("CreateRun: %v", err)
		}
		mustTransitionRun(t, st, run.RunID, "running", "concluding", "", "operator abort")
		mustTransitionRun(t, st, run.RunID, "concluding", "aborted", "operator", "operator aborted the run")
		return run.RunID

	case scenarioLaunchFailed:
		// Launch-failed: run starts in pending, never reaches running, concludes inconclusive.
		run, _, err := st.CreateRun(ctx, store.CreateRunInput{
			VMID: vmID, Owner: "test", Goal: "validate schema launch-failed",
			CriteriaType: "operator_verdict", OnCompletion: "keep_running",
			RequestHash: "hash-lf", InitialPhase: "pending",
		})
		if err != nil {
			t.Fatalf("CreateRun: %v", err)
		}
		mustTransitionRun(t, st, run.RunID, "pending", "concluding", "", "vm launch failed before the run started")
		mustTransitionRun(t, st, run.RunID, "concluding", "inconclusive", "system", "vm launch failed before the run started")
		return run.RunID

	case scenarioOperatorVerdict:
		run, _, err := st.CreateRun(ctx, store.CreateRunInput{
			VMID: vmID, Owner: "test", Goal: "validate schema operator-verdict",
			CriteriaType: "operator_verdict", OnCompletion: "keep_running",
			RequestHash: "hash-ov", InitialPhase: "running",
		})
		if err != nil {
			t.Fatalf("CreateRun: %v", err)
		}
		mustTransitionRun(t, st, run.RunID, "running", "concluding", "", "operator verdict")
		mustTransitionRun(t, st, run.RunID, "concluding", "succeeded", "operator", "operator verdict: succeeded")
		return run.RunID
	}
	t.Fatalf("unknown scenario kind %d", kind)
	return ""
}

// mustTransitionRun transitions a run and fatals on error.
func mustTransitionRun(t *testing.T, st *store.Store, runID, from, to, evaluatedBy, reason string) {
	t.Helper()
	if _, err := st.TransitionRun(t.Context(), store.RunTransitionInput{
		RunID: runID, From: from, To: to,
		EvaluatedBy: evaluatedBy, Reason: reason,
	}); err != nil {
		t.Fatalf("TransitionRun %s→%s: %v", from, to, err)
	}
}

// mustCreateRunningVM inserts a minimal VM directly into the store in the
// "running" state without going through the manager, so these tests have zero
// fake runtime dependency. Returns the vm_id.
func mustCreateRunningVM(t *testing.T, st *store.Store) string {
	t.Helper()
	vmID := fmt.Sprintf("00000000-0000-4000-8000-%012d", mustSeq(t))
	_, _, _, err := st.CreateVMWithOperation(t.Context(), store.CreateVMInput{
		VMID:             vmID,
		Name:             "test-vm-" + vmID[:8],
		Owner:            "test",
		TemplateID:       "tmpl-test",
		TemplateDigest:   fmt.Sprintf("sha256:%064d", 1),
		VCPUCount:        2,
		MemoryMiB:        2048,
		RootDiskMiB:      8192,
		WorkspaceDiskMiB: 10240,
		MemoryTotalMiB:   2048 + 768,
		NetworkProfile:   "transport",
		NetworkPolicyID:  "transport-public-web",
		Labels:           map[string]string{},
		Kind:             "vm.create",
		RequestHash:      fmt.Sprintf("hash-%s", vmID),
		Admit:            func(store.ReservationTotals) error { return nil },
	})
	if err != nil {
		t.Fatalf("CreateVMWithOperation: %v", err)
	}
	// Transition to running (provisioning → starting → running).
	starting := "provisioning"
	if _, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vmID, From: &starting, To: "starting", Reason: "test_launch",
	}); err != nil {
		t.Fatalf("→starting: %v", err)
	}
	if _, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vmID, To: "running", Reason: "test_launch_complete",
	}); err != nil {
		t.Fatalf("→running: %v", err)
	}
	return vmID
}

// mustSeq is a simple monotonic counter for unique IDs within a test run.
var seqCounter int64

func mustSeq(t *testing.T) int64 {
	t.Helper()
	seqCounter++
	return seqCounter
}

// TestSchemaValidation_FourTerminalShapes validates that generated reports for
// all four terminal run shapes pass the JSON schema (AT-092/AT-094 shape).
func TestSchemaValidation_FourTerminalShapes(t *testing.T) {
	sch := loadSchema(t)
	opts := report.Options{TailMaxBytes: 4096}

	scenarios := []struct {
		name string
		kind scenarioKind
	}{
		{"guest_result_succeeded", scenarioGuestResultSucceeded},
		{"aborted", scenarioAborted},
		{"launch_failed_never_booted", scenarioLaunchFailed},
		{"operator_verdict", scenarioOperatorVerdict},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			st := openStore(t)
			runID := buildScenario(t, st, sc.kind)
			raw, digest, err := report.Generate(t.Context(), st, runID, opts)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if !isValidDigest(digest) {
				t.Errorf("digest format wrong: %q", digest)
			}
			validateReport(t, sch, raw)
		})
	}
}

// TestSchemaValidation_Determinism checks that generating twice on the same
// store produces byte-identical JSON and identical digest.
func TestSchemaValidation_Determinism(t *testing.T) {
	st := openStore(t)
	runID := buildScenario(t, st, scenarioGuestResultSucceeded)

	raw1, digest1, err := report.Generate(t.Context(), st, runID, report.Options{})
	if err != nil {
		t.Fatalf("Generate (1st): %v", err)
	}
	raw2, digest2, err := report.Generate(t.Context(), st, runID, report.Options{})
	if err != nil {
		t.Fatalf("Generate (2nd): %v", err)
	}
	if string(raw1) != string(raw2) {
		t.Errorf("non-deterministic: JSON differs between calls")
	}
	if digest1 != digest2 {
		t.Errorf("non-deterministic: digest differs: %q vs %q", digest1, digest2)
	}
}

// TestSchemaValidation_NonTerminalReturnsError asserts that Generate refuses
// to generate for a non-terminal run.
func TestSchemaValidation_NonTerminalReturnsError(t *testing.T) {
	st := openStore(t)
	vmID := mustCreateRunningVM(t, st)
	run, _, err := st.CreateRun(t.Context(), store.CreateRunInput{
		VMID: vmID, Owner: "test", Goal: "non-terminal guard test",
		CriteriaType: "guest_result", OnCompletion: "keep_running",
		RequestHash: "hash-nt", InitialPhase: "running",
	})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}

	_, _, err = report.Generate(t.Context(), st, run.RunID, report.Options{})
	if err == nil {
		t.Fatal("expected error for non-terminal run, got nil")
	}
}

// isValidDigest checks the sha256:<hex64> pattern.
func isValidDigest(d string) bool {
	if len(d) != 7+64 { // "sha256:" + 64 hex chars
		return false
	}
	if d[:7] != "sha256:" {
		return false
	}
	for _, c := range d[7:] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// openStore opens a real SQLite store in the test's temp dir.
func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}
