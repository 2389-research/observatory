// ABOUTME: Tests for runs API endpoints: create, list, get, conclude, report.
// ABOUTME: TDD per task-8 brief; every contract bullet has at least one test.
package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/api"
	"github.com/2389-research/observatory-v2/internal/config"
	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/runtime/runtimetest"
	"github.com/2389-research/observatory-v2/internal/situation"
	"github.com/2389-research/observatory-v2/internal/store"
)

// newRunServer builds a VM-capable server with runs support. Returns the
// server URL, the store, the fake runtime.
func newRunServer(t *testing.T) (string, *store.Store, *runtimetest.Fake) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "events.sqlite"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	eng := situation.New(st, situation.Config{
		Triggers:                  map[string]bool{"lifecycle_failed": true, "run_concluded": true},
		QueueMaxItems:             500,
		CollapseDuplicates:        true,
		SituationMaxResponseBytes: 65536,
	})
	fake := runtimetest.NewFake()
	mgr, err := runtime.NewManager(st, fake, runtime.ManagerConfig{
		Admission: config.Admission{
			CPUOvercommitRatio:    4.0,
			MaxParallelProvisions: 2,
		},
		VMDefaults: config.VMDefaults{
			MemoryMiB:        512,
			VCPUCount:        1,
			RootDiskMiB:      4096,
			WorkspaceDiskMiB: 8192,
		},
		Owner:     "local_operator",
		Templates: map[string]runtime.Template{testTemplateDef.TemplateID: testTemplateDef},
		Host:      runtime.HostResources{TotalMemoryMiB: 8192, CPUCores: 8, StateDiskFreeMiB: 100 * 1024},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })
	srv := httptest.NewServer(api.New(st, eng, mgr))
	t.Cleanup(srv.Close)
	return srv.URL, st, fake
}

// createRunningVM creates a VM and polls until it's observed_state=running.
func createRunningVM(t *testing.T, srvURL string, fake *runtimetest.Fake) string {
	t.Helper()
	_ = fake
	var resp map[string]any
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms", map[string]any{
		"name":        "test-vm",
		"template_id": testTemplateDef.TemplateID,
	}, http.StatusCreated, &resp)

	vmID, _ := resp["vm"].(map[string]any)["vm_id"].(string)
	opID, _ := resp["operation"].(map[string]any)["operation_id"].(string)
	pollOpState(t, srvURL, opID, "succeeded")

	var vmResp map[string]any
	getJSON(t, srvURL+"/api/v1/vms/"+vmID, http.StatusOK, &vmResp)
	if state, _ := vmResp["observed_state"].(string); state != "running" {
		t.Fatalf("VM %s in state %q, want running", vmID, state)
	}
	return vmID
}

// --- /meta assertions ---

func TestMetaRunsFeatureAndLink(t *testing.T) {
	// Once runs are built, features.runs must be true and links.runs must work.
	srvURL, _, _ := newRunServer(t)

	var meta map[string]any
	getJSON(t, srvURL+"/api/v1/meta", http.StatusOK, &meta)

	features, _ := meta["features"].(map[string]any)
	if got, ok := features["runs"]; !ok || got != true {
		t.Errorf("features.runs = %v, want true", got)
	}

	// Extract links (may be map[string]any or map[string]string depending on decoding).
	linksRaw, _ := meta["links"].(map[string]any)
	runsLinkRaw, ok := linksRaw["runs"]
	if !ok {
		t.Fatal("meta links missing runs")
	}
	runsLink, _ := runsLinkRaw.(string)
	if runsLink == "" {
		t.Fatal("meta links.runs is empty")
	}
	resp, err := http.Get(srvURL + runsLink)
	if err != nil {
		t.Fatalf("runs link GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("runs link %s answers %d, want 200", runsLink, resp.StatusCode)
	}
}

// --- POST /vms/{id}/runs ---

func TestCreateRunBasic(t *testing.T) {
	srvURL, _, fake := newRunServer(t)
	vmID := createRunningVM(t, srvURL, fake)

	var resp map[string]any
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/runs", map[string]any{
		"goal":             "test the thing",
		"success_criteria": map[string]any{"type": "operator_verdict"},
		"on_completion":    "keep_running",
	}, http.StatusCreated, &resp)

	run, _ := resp["run"].(map[string]any)
	if run == nil {
		t.Fatalf("response missing run: %v", resp)
	}
	for _, f := range []string{"run_id", "phase", "goal", "vm_id"} {
		if run[f] == nil {
			t.Errorf("run missing field %q", f)
		}
	}
	if run["row_id"] != nil {
		t.Error("row_id must not be serialized")
	}
}

func TestCreateRunIdempotencyReplay(t *testing.T) {
	srvURL, _, fake := newRunServer(t)
	vmID := createRunningVM(t, srvURL, fake)
	key := "idempotency-key-1"

	body := map[string]any{
		"goal":             "first run",
		"success_criteria": map[string]any{"type": "operator_verdict"},
		"on_completion":    "keep_running",
		"idempotency_key":  key,
	}
	var first map[string]any
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/runs", body, http.StatusCreated, &first)
	if first["is_replay"] != nil {
		t.Error("first create must not set is_replay")
	}

	var second map[string]any
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/runs", body, http.StatusCreated, &second)
	if second["is_replay"] != true {
		t.Errorf("second create: is_replay = %v, want true", second["is_replay"])
	}
}

func TestCreateRunStopAndFinalizeRefused(t *testing.T) {
	// R2: on_completion=stop_and_finalize → 501 missing_capability / capability_not_built.
	srvURL, _, fake := newRunServer(t)
	vmID := createRunningVM(t, srvURL, fake)

	var e api.Error
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/runs", map[string]any{
		"goal":             "test",
		"success_criteria": map[string]any{"type": "operator_verdict"},
		"on_completion":    "stop_and_finalize",
	}, http.StatusNotImplemented, &e)
	requireTeaching(t, e, "missing_capability")
	if e.Cause != "capability_not_built" {
		t.Errorf("cause = %q, want capability_not_built", e.Cause)
	}
	// Remediation must offer keep_running and stop as alternatives.
	var foundKeepRunning, foundStop bool
	for _, r := range e.Remediation {
		p := fmt.Sprint(r.Params)
		a := fmt.Sprint(r.Action)
		all := p + a
		if strings.Contains(all, "keep_running") {
			foundKeepRunning = true
		}
		if strings.Contains(all, "stop") && !strings.Contains(all, "stop_and_finalize") {
			foundStop = true
		}
	}
	if !foundKeepRunning || !foundStop {
		t.Errorf("remediation must offer keep_running and stop; got: %+v", e.Remediation)
	}
}

func TestCreateRunVMNotRunning409(t *testing.T) {
	// Create a VM, let it reach running, stop it, then try to create a run.
	// We retry the stop action if revision changed (revision race is benign here).
	srvURL, _, _ := newRunServer(t)

	var createResp map[string]any
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms", map[string]any{
		"name":        "stop-me",
		"template_id": testTemplateDef.TemplateID,
	}, http.StatusCreated, &createResp)
	vmID, _ := createResp["vm"].(map[string]any)["vm_id"].(string)
	opID, _ := createResp["operation"].(map[string]any)["operation_id"].(string)
	pollOpState(t, srvURL, opID, "succeeded")

	// Retry stop until it succeeds (revision may change between reads).
	var stopOpID string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var vmResp map[string]any
		getJSON(t, srvURL+"/api/v1/vms/"+vmID, http.StatusOK, &vmResp)
		rev, _ := vmResp["revision"].(string)

		var actionResp map[string]any
		rawAction := doRequestRaw(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/actions", map[string]any{
			"action": "stop", "expected_revision": rev,
		})
		if rawAction.status == http.StatusOK {
			if err := json.Unmarshal(rawAction.body, &actionResp); err == nil {
				stopOpID, _ = actionResp["operation"].(map[string]any)["operation_id"].(string)
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
	}
	if stopOpID == "" {
		t.Fatal("could not stop VM within deadline")
	}
	pollOpState(t, srvURL, stopOpID, "succeeded")

	var e api.Error
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/runs", map[string]any{
		"goal":             "test",
		"success_criteria": map[string]any{"type": "operator_verdict"},
		"on_completion":    "keep_running",
	}, http.StatusConflict, &e)
	requireTeaching(t, e, "conflict")
	if e.Cause != "vm_not_running" {
		t.Errorf("cause = %q, want vm_not_running", e.Cause)
	}
}

type rawResponse struct {
	status int
	body   []byte
}

func doRequestRaw(t *testing.T, method, url string, body any) rawResponse {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(t.Context(), method, url, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return rawResponse{status: resp.StatusCode, body: raw}
}

func TestCreateRunActiveRunConflict409(t *testing.T) {
	srvURL, _, fake := newRunServer(t)
	vmID := createRunningVM(t, srvURL, fake)

	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/runs", map[string]any{
		"goal":             "first",
		"success_criteria": map[string]any{"type": "operator_verdict"},
		"on_completion":    "keep_running",
	}, http.StatusCreated, nil)

	var e api.Error
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/runs", map[string]any{
		"goal":             "second",
		"success_criteria": map[string]any{"type": "operator_verdict"},
		"on_completion":    "keep_running",
	}, http.StatusConflict, &e)
	requireTeaching(t, e, "conflict")
	if e.Cause != "active_run_exists" {
		t.Errorf("cause = %q, want active_run_exists", e.Cause)
	}
	if e.Details["run_id"] == nil {
		t.Error("active_run_exists must carry run_id in details")
	}
}

func TestCreateRunValidationGoalEmpty(t *testing.T) {
	srvURL, _, fake := newRunServer(t)
	vmID := createRunningVM(t, srvURL, fake)

	var e api.Error
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/runs", map[string]any{
		"goal":             "",
		"success_criteria": map[string]any{"type": "operator_verdict"},
		"on_completion":    "keep_running",
	}, http.StatusBadRequest, &e)
	requireTeaching(t, e, "malformed_request")
}

func TestCreateRunValidationBadCriteriaType(t *testing.T) {
	srvURL, _, fake := newRunServer(t)
	vmID := createRunningVM(t, srvURL, fake)

	var e api.Error
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/runs", map[string]any{
		"goal":             "test",
		"success_criteria": map[string]any{"type": "bad_type"},
		"on_completion":    "keep_running",
	}, http.StatusBadRequest, &e)
	requireTeaching(t, e, "malformed_request")
}

func TestCreateRunValidationBadOnCompletion(t *testing.T) {
	srvURL, _, fake := newRunServer(t)
	vmID := createRunningVM(t, srvURL, fake)

	var e api.Error
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/runs", map[string]any{
		"goal":             "test",
		"success_criteria": map[string]any{"type": "operator_verdict"},
		"on_completion":    "delete_universe",
	}, http.StatusBadRequest, &e)
	requireTeaching(t, e, "malformed_request")
}

func TestCreateRunVMUnknown404(t *testing.T) {
	srvURL, _, _ := newRunServer(t)
	var e api.Error
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/no-such-vm/runs", map[string]any{
		"goal":             "test",
		"success_criteria": map[string]any{"type": "operator_verdict"},
		"on_completion":    "keep_running",
	}, http.StatusNotFound, &e)
	requireTeaching(t, e, "not_found")
}

// --- GET /runs ---

func TestListRunsEmpty(t *testing.T) {
	srvURL, _, _ := newRunServer(t)
	var resp map[string]any
	getJSON(t, srvURL+"/api/v1/runs", http.StatusOK, &resp)
	runs, _ := resp["runs"].([]any)
	if runs == nil {
		t.Error("runs must be [], not null")
	}
	if resp["next_after"] == nil {
		t.Error("list runs must carry next_after")
	}
}

func TestListRunsFiltersAndPagination(t *testing.T) {
	srvURL, _, fake := newRunServer(t)
	vmA := createRunningVM(t, srvURL, fake)
	vmB := createRunningVM(t, srvURL, fake)

	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmA+"/runs", map[string]any{
		"goal":             "run-a",
		"success_criteria": map[string]any{"type": "operator_verdict"},
		"on_completion":    "keep_running",
	}, http.StatusCreated, nil)
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmB+"/runs", map[string]any{
		"goal":             "run-b",
		"success_criteria": map[string]any{"type": "operator_verdict"},
		"on_completion":    "keep_running",
	}, http.StatusCreated, nil)

	// All runs.
	var all map[string]any
	getJSON(t, srvURL+"/api/v1/runs", http.StatusOK, &all)
	if allRuns, _ := all["runs"].([]any); len(allRuns) != 2 {
		t.Errorf("all runs: got %d, want 2", len(allRuns))
	}

	// Filter by vm_id.
	var byVM map[string]any
	getJSON(t, srvURL+"/api/v1/runs?vm_id="+vmA, http.StatusOK, &byVM)
	if vmRuns, _ := byVM["runs"].([]any); len(vmRuns) != 1 {
		t.Errorf("runs for vmA: got %d, want 1", len(vmRuns))
	}

	// Filter by phase.
	var byPhase map[string]any
	getJSON(t, srvURL+"/api/v1/runs?phase=running", http.StatusOK, &byPhase)
	if phaseRuns, _ := byPhase["runs"].([]any); len(phaseRuns) != 2 {
		t.Errorf("running runs: got %d, want 2", len(phaseRuns))
	}
}

func TestListRunsBadLimitRejects(t *testing.T) {
	srvURL, _, _ := newRunServer(t)
	var e api.Error
	getJSON(t, srvURL+"/api/v1/runs?limit=9999", http.StatusBadRequest, &e)
	requireTeaching(t, e, "malformed_request")
}

// --- GET /runs/{id} ---

func TestGetRunShape(t *testing.T) {
	srvURL, _, fake := newRunServer(t)
	vmID := createRunningVM(t, srvURL, fake)

	var createResp map[string]any
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/runs", map[string]any{
		"goal":             "inspect me",
		"success_criteria": map[string]any{"type": "operator_verdict"},
		"on_completion":    "keep_running",
	}, http.StatusCreated, &createResp)
	runID, _ := createResp["run"].(map[string]any)["run_id"].(string)

	var run map[string]any
	getJSON(t, srvURL+"/api/v1/runs/"+runID, http.StatusOK, &run)
	for _, field := range []string{"run_id", "vm_id", "goal", "phase", "progress_seq", "links"} {
		if run[field] == nil {
			t.Errorf("run missing field %q", field)
		}
	}
	if run["row_id"] != nil {
		t.Error("row_id must not be serialized")
	}
	links, _ := run["links"].(map[string]any)
	if links["events"] == nil {
		t.Error("run links must include events")
	}
	if links["report"] == nil {
		t.Error("run links must include report")
	}
}

func TestGetRunNotFound(t *testing.T) {
	srvURL, _, _ := newRunServer(t)
	var e api.Error
	getJSON(t, srvURL+"/api/v1/runs/no-such-run", http.StatusNotFound, &e)
	requireTeaching(t, e, "not_found")
}

// --- POST /runs/{id}/conclude ---

func TestConcludeRunSucceeded(t *testing.T) {
	srvURL, _, fake := newRunServer(t)
	vmID := createRunningVM(t, srvURL, fake)

	var createResp map[string]any
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/runs", map[string]any{
		"goal":             "conclude me",
		"success_criteria": map[string]any{"type": "operator_verdict"},
		"on_completion":    "keep_running",
	}, http.StatusCreated, &createResp)
	runID, _ := createResp["run"].(map[string]any)["run_id"].(string)

	var concludeResp map[string]any
	doRequest(t, http.MethodPost, srvURL+"/api/v1/runs/"+runID+"/conclude", map[string]any{
		"verdict": "succeeded",
	}, http.StatusOK, &concludeResp)

	run, _ := concludeResp["run"].(map[string]any)
	if phase, _ := run["phase"].(string); phase != "succeeded" {
		t.Errorf("phase = %q, want succeeded", phase)
	}
}

func TestConcludeRunAbort(t *testing.T) {
	srvURL, _, fake := newRunServer(t)
	vmID := createRunningVM(t, srvURL, fake)

	var createResp map[string]any
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/runs", map[string]any{
		"goal":             "abort me",
		"success_criteria": map[string]any{"type": "operator_verdict"},
		"on_completion":    "keep_running",
	}, http.StatusCreated, &createResp)
	runID, _ := createResp["run"].(map[string]any)["run_id"].(string)

	var concludeResp map[string]any
	doRequest(t, http.MethodPost, srvURL+"/api/v1/runs/"+runID+"/conclude", map[string]any{
		"abort":  true,
		"reason": "testing abort",
	}, http.StatusOK, &concludeResp)

	run, _ := concludeResp["run"].(map[string]any)
	if phase, _ := run["phase"].(string); phase != "aborted" {
		t.Errorf("phase = %q, want aborted", phase)
	}
}

func TestConcludeAlreadyConcluded409(t *testing.T) {
	srvURL, _, fake := newRunServer(t)
	vmID := createRunningVM(t, srvURL, fake)

	var createResp map[string]any
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/runs", map[string]any{
		"goal":             "conclude twice",
		"success_criteria": map[string]any{"type": "operator_verdict"},
		"on_completion":    "keep_running",
	}, http.StatusCreated, &createResp)
	runID, _ := createResp["run"].(map[string]any)["run_id"].(string)

	doRequest(t, http.MethodPost, srvURL+"/api/v1/runs/"+runID+"/conclude", map[string]any{
		"verdict": "succeeded",
	}, http.StatusOK, nil)

	var e api.Error
	doRequest(t, http.MethodPost, srvURL+"/api/v1/runs/"+runID+"/conclude", map[string]any{
		"verdict": "failed",
	}, http.StatusConflict, &e)
	requireTeaching(t, e, "conflict")
	if e.Cause != "already_concluded" {
		t.Errorf("cause = %q, want already_concluded", e.Cause)
	}
	if e.Details["outcome"] == nil {
		t.Error("already_concluded must carry outcome in details")
	}
}

func TestConcludeVerdictCriteriaMismatch409(t *testing.T) {
	srvURL, _, fake := newRunServer(t)
	vmID := createRunningVM(t, srvURL, fake)

	var createResp map[string]any
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/runs", map[string]any{
		"goal":             "guest will decide",
		"success_criteria": map[string]any{"type": "guest_result"},
		"on_completion":    "keep_running",
	}, http.StatusCreated, &createResp)
	runID, _ := createResp["run"].(map[string]any)["run_id"].(string)

	var e api.Error
	doRequest(t, http.MethodPost, srvURL+"/api/v1/runs/"+runID+"/conclude", map[string]any{
		"verdict": "succeeded",
	}, http.StatusConflict, &e)
	requireTeaching(t, e, "conflict")
	if e.Cause != "criteria_mismatch" {
		t.Errorf("cause = %q, want criteria_mismatch", e.Cause)
	}
	if len(e.Remediation) == 0 {
		t.Error("criteria_mismatch must offer abort remediation")
	}
}

func TestConcludeBothVerdictAndAbortRejects(t *testing.T) {
	srvURL, _, fake := newRunServer(t)
	vmID := createRunningVM(t, srvURL, fake)

	var createResp map[string]any
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/runs", map[string]any{
		"goal":             "bad conclude",
		"success_criteria": map[string]any{"type": "operator_verdict"},
		"on_completion":    "keep_running",
	}, http.StatusCreated, &createResp)
	runID, _ := createResp["run"].(map[string]any)["run_id"].(string)

	var e api.Error
	doRequest(t, http.MethodPost, srvURL+"/api/v1/runs/"+runID+"/conclude", map[string]any{
		"verdict": "succeeded",
		"abort":   true,
		"reason":  "nope",
	}, http.StatusBadRequest, &e)
	requireTeaching(t, e, "malformed_request")
}

func TestConcludeNeitherVerdictNorAbortRejects(t *testing.T) {
	srvURL, _, fake := newRunServer(t)
	vmID := createRunningVM(t, srvURL, fake)

	var createResp map[string]any
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/runs", map[string]any{
		"goal":             "bad conclude",
		"success_criteria": map[string]any{"type": "operator_verdict"},
		"on_completion":    "keep_running",
	}, http.StatusCreated, &createResp)
	runID, _ := createResp["run"].(map[string]any)["run_id"].(string)

	var e api.Error
	doRequest(t, http.MethodPost, srvURL+"/api/v1/runs/"+runID+"/conclude", map[string]any{
		"reason": "only a reason, no verdict or abort",
	}, http.StatusBadRequest, &e)
	requireTeaching(t, e, "malformed_request")
}

func TestConcludeRunNotFound(t *testing.T) {
	srvURL, _, _ := newRunServer(t)
	var e api.Error
	doRequest(t, http.MethodPost, srvURL+"/api/v1/runs/no-such-run/conclude", map[string]any{
		"verdict": "succeeded",
	}, http.StatusNotFound, &e)
	requireTeaching(t, e, "not_found")
}

// --- GET /runs/{id}/report ---

func TestGetReportUnknownRun404(t *testing.T) {
	srvURL, _, _ := newRunServer(t)
	var e api.Error
	getJSON(t, srvURL+"/api/v1/runs/no-such-run/report", http.StatusNotFound, &e)
	requireTeaching(t, e, "not_found")
}

func TestGetReportPendingBeforeGeneration(t *testing.T) {
	// A terminal run with no stored report and no op → status pending.
	srvURL, _, fake := newRunServer(t)
	vmID := createRunningVM(t, srvURL, fake)

	var createResp map[string]any
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/runs", map[string]any{
		"goal":             "pending report",
		"success_criteria": map[string]any{"type": "operator_verdict"},
		"on_completion":    "keep_running",
	}, http.StatusCreated, &createResp)
	runID, _ := createResp["run"].(map[string]any)["run_id"].(string)

	doRequest(t, http.MethodPost, srvURL+"/api/v1/runs/"+runID+"/conclude", map[string]any{
		"verdict": "succeeded",
	}, http.StatusOK, nil)

	var report map[string]any
	getJSON(t, srvURL+"/api/v1/runs/"+runID+"/report", http.StatusOK, &report)
	status, _ := report["status"].(string)
	if status != "pending" && status != "failed" {
		t.Errorf("report status = %q, want pending or failed", status)
	}
}

func TestGetReportGenerated(t *testing.T) {
	srvURL, st, fake := newRunServer(t)
	vmID := createRunningVM(t, srvURL, fake)

	var createResp map[string]any
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/runs", map[string]any{
		"goal":             "generate a report",
		"success_criteria": map[string]any{"type": "operator_verdict"},
		"on_completion":    "keep_running",
	}, http.StatusCreated, &createResp)
	runID, _ := createResp["run"].(map[string]any)["run_id"].(string)

	doRequest(t, http.MethodPost, srvURL+"/api/v1/runs/"+runID+"/conclude", map[string]any{
		"verdict": "succeeded",
	}, http.StatusOK, nil)

	// Manually store a report, simulating what a real generator does.
	ctx := context.Background()
	if err := st.PutRunReport(ctx, runID, `{"schema_version":1}`, "sha256:"+strings.Repeat("a", 64), 1); err != nil {
		t.Fatalf("put report: %v", err)
	}

	var report map[string]any
	getJSON(t, srvURL+"/api/v1/runs/"+runID+"/report", http.StatusOK, &report)
	if status, _ := report["status"].(string); status != "generated" {
		t.Errorf("report status = %q, want generated", status)
	}
	if report["generated_at"] == nil {
		t.Error("generated response must carry generated_at")
	}
	if report["digest"] == nil {
		t.Error("generated response must carry digest")
	}
	if report["report"] == nil {
		t.Error("generated response must embed report JSON")
	}
}

// --- R2: stop_and_finalize refusal at all three ingress points ---

func TestCreateVMWithRunStopAndFinalizeRefused(t *testing.T) {
	// R2: POST /vms with run.on_completion=stop_and_finalize → 501.
	srvURL, _, _ := newRunServer(t)
	var e api.Error
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms", map[string]any{
		"name":        "run-vm",
		"template_id": testTemplateDef.TemplateID,
		"run": map[string]any{
			"goal":             "test",
			"success_criteria": map[string]any{"type": "operator_verdict"},
			"on_completion":    "stop_and_finalize",
		},
	}, http.StatusNotImplemented, &e)
	requireTeaching(t, e, "missing_capability")
	if e.Cause != "capability_not_built" {
		t.Errorf("cause = %q, want capability_not_built", e.Cause)
	}
}

func TestCreateBatchMemberWithRunStopAndFinalizeRefused(t *testing.T) {
	// R2: batch member with run.on_completion=stop_and_finalize → refusal on that member.
	srvURL, _, _ := newRunServer(t)
	var resp map[string]any
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vm-batches", map[string]any{
		"members": []any{
			map[string]any{
				"name":        "ok-member",
				"template_id": testTemplateDef.TemplateID,
			},
			map[string]any{
				"name":        "bad-member",
				"template_id": testTemplateDef.TemplateID,
				"run": map[string]any{
					"goal":             "test",
					"success_criteria": map[string]any{"type": "operator_verdict"},
					"on_completion":    "stop_and_finalize",
				},
			},
		},
		"reservation_mode": "best_effort",
	}, http.StatusCreated, &resp)

	members, _ := resp["members"].([]any)
	if len(members) < 2 {
		t.Fatalf("expected 2 members, got %d", len(members))
	}

	var badMember map[string]any
	for _, m := range members {
		mm, _ := m.(map[string]any)
		pos, _ := mm["position"].(float64)
		if int(pos) == 1 {
			badMember = mm
			break
		}
	}
	if badMember == nil {
		t.Fatal("bad member (position 1) not found in response")
	}
	refusal, _ := badMember["refusal"].(map[string]any)
	if refusal == nil {
		t.Errorf("bad member must have refusal; got: %v", badMember)
	}
	cause, _ := refusal["cause"].(string)
	if cause != "capability_not_built" {
		t.Errorf("refusal cause = %q, want capability_not_built", cause)
	}
}

// --- End-to-end: create → conclude → GET run shows outcome → GET report ---

func TestE2ERunConcludeAndReport(t *testing.T) {
	srvURL, st, fake := newRunServer(t)
	vmID := createRunningVM(t, srvURL, fake)

	// Create run.
	var createResp map[string]any
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/runs", map[string]any{
		"goal":             "e2e test run",
		"success_criteria": map[string]any{"type": "operator_verdict"},
		"on_completion":    "keep_running",
	}, http.StatusCreated, &createResp)
	runID, _ := createResp["run"].(map[string]any)["run_id"].(string)

	// Conclude.
	var concludeResp map[string]any
	doRequest(t, http.MethodPost, srvURL+"/api/v1/runs/"+runID+"/conclude", map[string]any{
		"verdict": "succeeded",
	}, http.StatusOK, &concludeResp)

	// GET run shows outcome.
	var run map[string]any
	getJSON(t, srvURL+"/api/v1/runs/"+runID, http.StatusOK, &run)
	if phase, _ := run["phase"].(string); phase != "succeeded" {
		t.Errorf("run phase = %q, want succeeded", phase)
	}

	// Store a report manually (simulating the generator).
	ctx := context.Background()
	if err := st.PutRunReport(ctx, runID, `{"schema_version":1}`, "sha256:"+strings.Repeat("c", 64), 1); err != nil {
		t.Fatalf("store report: %v", err)
	}

	// Poll store until report is readable (should be immediate since we just wrote it).
	deadline := time.Now().Add(2 * time.Second)
	var rpt *store.RunReport
	var err error
	for time.Now().Before(deadline) {
		rpt, err = st.GetRunReport(ctx, runID)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("report not found in store: %v", err)
	}
	if rpt.RunID != runID {
		t.Errorf("stored report run_id = %q, want %q", rpt.RunID, runID)
	}

	// Verify via API.
	var reportResp map[string]any
	getJSON(t, srvURL+"/api/v1/runs/"+runID+"/report", http.StatusOK, &reportResp)
	if status, _ := reportResp["status"].(string); status != "generated" {
		t.Errorf("report status = %q, want generated", status)
	}
}

// --- POST /vms (launch-attached run) threading ---

func TestCreateVMWithRunThreads(t *testing.T) {
	// POST /vms with a valid run block creates a VM; run is pending.
	srvURL, _, _ := newRunServer(t)

	var resp map[string]any
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms", map[string]any{
		"name":        "vm-with-run",
		"template_id": testTemplateDef.TemplateID,
		"run": map[string]any{
			"goal":             "launch-attached run",
			"success_criteria": map[string]any{"type": "guest_result"},
			"on_completion":    "keep_running",
		},
	}, http.StatusCreated, &resp)

	vmID, _ := resp["vm"].(map[string]any)["vm_id"].(string)
	if vmID == "" {
		t.Fatal("response missing vm_id")
	}
	// After the VM is running, the run should be visible in GET /runs?vm_id=...
	opID, _ := resp["operation"].(map[string]any)["operation_id"].(string)
	pollOpState(t, srvURL, opID, "succeeded")

	var runsResp map[string]any
	getJSON(t, srvURL+"/api/v1/runs?vm_id="+vmID, http.StatusOK, &runsResp)
	runs, _ := runsResp["runs"].([]any)
	if len(runs) != 1 {
		t.Errorf("expected 1 run for VM, got %d", len(runs))
	}
}

// --- Fix round 1 tests ---

// newRunServerWithReportGen builds a VM-capable server whose manager has a wired
// reportGen stub so EnqueueReport can actually proceed past the nil guard.
// Returns the server URL, the store, the fake runtime, and a channel that
// receives every runID passed to the stub generator.
func newRunServerWithReportGen(t *testing.T) (string, *store.Store, *runtimetest.Fake, <-chan string) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "events.sqlite"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	eng := situation.New(st, situation.Config{
		Triggers:                  map[string]bool{"lifecycle_failed": true, "run_concluded": true},
		QueueMaxItems:             500,
		CollapseDuplicates:        true,
		SituationMaxResponseBytes: 65536,
	})
	fake := runtimetest.NewFake()
	generated := make(chan string, 64)
	mgr, err := runtime.NewManagerWithReportGen(st, fake, runtime.ManagerConfig{
		Admission: config.Admission{
			CPUOvercommitRatio:    4.0,
			MaxParallelProvisions: 2,
		},
		VMDefaults: config.VMDefaults{
			MemoryMiB:        512,
			VCPUCount:        1,
			RootDiskMiB:      4096,
			WorkspaceDiskMiB: 8192,
		},
		Owner:     "local_operator",
		Templates: map[string]runtime.Template{testTemplateDef.TemplateID: testTemplateDef},
		Host:      runtime.HostResources{TotalMemoryMiB: 8192, CPUCores: 8, StateDiskFreeMiB: 100 * 1024},
	}, func(runID string) {
		generated <- runID
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })
	srv := httptest.NewServer(api.New(st, eng, mgr))
	t.Cleanup(srv.Close)
	return srv.URL, st, fake, generated
}

// F1: GET /runs/{id}/report on a non-terminal run must return pending without enqueueing.
// Uses a server with reportGen wired so the bug (spurious enqueue) would show up.
func TestGetReportNonTerminalRunNoPollution(t *testing.T) {
	srvURL, st, fake, generated := newRunServerWithReportGen(t)
	vmID := createRunningVM(t, srvURL, fake)

	var createResp map[string]any
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/runs", map[string]any{
		"goal":             "non-terminal report guard",
		"success_criteria": map[string]any{"type": "operator_verdict"},
		"on_completion":    "keep_running",
	}, http.StatusCreated, &createResp)
	runID, _ := createResp["run"].(map[string]any)["run_id"].(string)

	// Run is now in "running" phase (non-terminal). GET /report must return pending.
	var report map[string]any
	getJSON(t, srvURL+"/api/v1/runs/"+runID+"/report", http.StatusOK, &report)
	if status, _ := report["status"].(string); status != "pending" {
		t.Errorf("non-terminal report status = %q, want pending", status)
	}
	if report["operation_id"] != nil {
		t.Error("non-terminal report must not carry operation_id")
	}

	// Allow any goroutine that might have been enqueued to settle.
	time.Sleep(80 * time.Millisecond)

	// The stub generator must NOT have been called for a non-terminal run.
	// In production, the generator creates the op; the stub doesn't, so we
	// check the channel directly — any entry means EnqueueReport fired.
	select {
	case gotRunID := <-generated:
		t.Errorf("non-terminal GET /report must not enqueue report generation; got enqueue for run %s", gotRunID)
	default:
		// Correct: nothing enqueued.
	}

	// Also verify no operation was created (defensive: stub doesn't create ops,
	// but belt-and-suspenders check for production-like callers).
	ctx := context.Background()
	op, err := st.GetLatestReportOperation(ctx, runID)
	if err == nil {
		t.Errorf("non-terminal GET /report must not create a report operation; got op state=%s", op.State)
	}
}

// F2: GET /runs/{id} after SubmitRunResult must carry result.received_at.
func TestGetRunResultReceivedAtDirect(t *testing.T) {
	srvURL, st, fake := newRunServer(t)
	vmID := createRunningVM(t, srvURL, fake)

	var createResp map[string]any
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/runs", map[string]any{
		"goal":             "guest-result received_at",
		"success_criteria": map[string]any{"type": "guest_result"},
		"on_completion":    "keep_running",
		"progress_events":  true,
	}, http.StatusCreated, &createResp)
	runID, _ := createResp["run"].(map[string]any)["run_id"].(string)

	// Submit result directly via store (R10: not HTTP).
	ctx := context.Background()
	_, err := st.SubmitRunResult(ctx, store.SubmitResultInput{
		RunID:    runID,
		Result:   json.RawMessage(`{"status":"succeeded"}`),
		MaxBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("SubmitRunResult: %v", err)
	}

	// GET /runs/{id} must carry result with received_at.
	var run map[string]any
	getJSON(t, srvURL+"/api/v1/runs/"+runID, http.StatusOK, &run)
	result, _ := run["result"].(map[string]any)
	if result == nil {
		t.Fatalf("run.result is nil after SubmitRunResult")
	}
	receivedAt, _ := result["received_at"].(string)
	if receivedAt == "" {
		t.Errorf("result.received_at is empty; want non-empty RFC3339 timestamp")
	}
	// Basic RFC3339 sanity: must parse.
	if _, err := time.Parse(time.RFC3339, receivedAt); err != nil {
		t.Errorf("result.received_at %q is not RFC3339: %v", receivedAt, err)
	}
}

// F3: GET /runs?phase=<unknown> must return 400 with cause phase_unknown.
func TestListRunsUnknownPhase400(t *testing.T) {
	srvURL, _, _ := newRunServer(t)
	var e api.Error
	getJSON(t, srvURL+"/api/v1/runs?phase=nonexistent_phase", http.StatusBadRequest, &e)
	requireTeaching(t, e, "malformed_request")
	if e.Cause != "phase_unknown" {
		t.Errorf("cause = %q, want phase_unknown", e.Cause)
	}
	if len(e.Remediation) == 0 {
		t.Error("phase_unknown must carry remediation naming valid phases")
	}
}

// --- TestUnbuiltEndpointsTeachCapability: runs must NOT appear as unbuilt after implementation ---

func TestRunsEndpointsAreBuilt(t *testing.T) {
	// After implementation, the five runs routes must answer real responses, not 501.
	srvURL, _, fake := newRunServer(t)
	vmID := createRunningVM(t, srvURL, fake)

	// GET /runs → 200.
	resp, _ := http.Get(srvURL + "/api/v1/runs")
	if resp != nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotImplemented {
			t.Error("GET /runs must not be 501 after implementation")
		}
	}

	// POST /vms/{id}/runs → 201 (valid body).
	var createResp map[string]any
	raw := doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/runs", map[string]any{
		"goal":             "built test",
		"success_criteria": map[string]any{"type": "operator_verdict"},
		"on_completion":    "keep_running",
	}, http.StatusCreated, &createResp)
	runID, _ := createResp["run"].(map[string]any)["run_id"].(string)
	_ = raw

	// GET /runs/{id} → 200.
	var runGet map[string]any
	getJSON(t, srvURL+"/api/v1/runs/"+runID, http.StatusOK, &runGet)

	// POST /runs/{id}/conclude → 200.
	doRequest(t, http.MethodPost, srvURL+"/api/v1/runs/"+runID+"/conclude", map[string]any{
		"verdict": "succeeded",
	}, http.StatusOK, nil)

	// GET /runs/{id}/report → 200.
	var reportResp map[string]any
	getJSON(t, srvURL+"/api/v1/runs/"+runID+"/report", http.StatusOK, &reportResp)
}
