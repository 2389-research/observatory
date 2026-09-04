// ABOUTME: Cross-owner access denial tests (AT-079 API slice): foreign resources
// ABOUTME: return the same 404 as missing resources, with zero side effects.
package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/2389-research/observatory-v2/internal/api"
	"github.com/2389-research/observatory-v2/internal/auth"
	"github.com/2389-research/observatory-v2/internal/config"
	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/runtime/runtimetest"
	"github.com/2389-research/observatory-v2/internal/situation"
	"github.com/2389-research/observatory-v2/internal/store"
)

const (
	otherOwner = "other_operator"
)

// newScopeServer creates a server with auth enabled and a bearer token for
// local_operator. Returns the server URL, store, and bearer token secret.
func newScopeServer(t *testing.T) (srvURL string, st *store.Store, secret string) {
	t.Helper()
	dir := t.TempDir()
	credDir := filepath.Join(dir, "creds")
	credStore, err := auth.InitStore(credDir, testOperator, testPassword)
	if err != nil {
		t.Fatalf("init cred store: %v", err)
	}

	st, err = store.Open(filepath.Join(dir, "events.sqlite"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	eng := situation.New(st, situation.Config{
		Triggers:                  map[string]bool{"lifecycle_failed": true},
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
		Templates: map[string]runtime.Template{testTemplateDef.TemplateID: testTemplateDef},
		Host:      runtime.HostResources{TotalMemoryMiB: 8192, CPUCores: 8, StateDiskFreeMiB: 100 * 1024},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })

	sessions := auth.NewSessions(time.Hour)
	ac := api.AuthConfig{
		Enabled:        true,
		Creds:          credStore,
		Sessions:       sessions,
		PublicOrigin:   testOrigin,
		CookieSameSite: http.SameSiteStrictMode,
		CookieSecure:   false,
		LoginDelay:     time.Millisecond,
	}

	srv := httptest.NewServer(api.New(st, eng, mgr, ac, nil, nil))
	t.Cleanup(srv.Close)
	srvURL = srv.URL

	// Mint a bearer token for local_operator via session.
	csrfToken, client := loginAndGetSession(t, srvURL)
	createResp := doWithCSRF(t, client, http.MethodPost, srvURL+"/api/v1/auth/tokens",
		csrfToken, bytes.NewReader([]byte(`{"name":"test"}`)), "application/json")
	defer createResp.Body.Close()
	raw, _ := io.ReadAll(createResp.Body)
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create token: %d\n%s", createResp.StatusCode, raw)
	}
	var tokenResp struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(raw, &tokenResp); err != nil {
		t.Fatalf("decode token: %v", err)
	}
	return srvURL, st, tokenResp.Secret
}

// seedForeignVM inserts a VM row directly through the store (trusted ingress),
// owned by otherOwner. Returns the VMID and the numeric operation ID.
func seedForeignVM(t *testing.T, ctx context.Context, st *store.Store) (vmID string, opID int64) {
	t.Helper()
	vmID = uuid.NewString()
	vm, op, _, err := st.CreateVMWithOperation(ctx, store.CreateVMInput{
		VMID:             vmID,
		Name:             "foreign-vm",
		Owner:            otherOwner,
		TemplateID:       testTemplateDef.TemplateID,
		TemplateDigest:   testTemplateDef.Digest,
		VCPUCount:        1,
		MemoryMiB:        512,
		RootDiskMiB:      4096,
		WorkspaceDiskMiB: 8192,
		MemoryTotalMiB:   512,
		Kind:             "vm.create",
		RequestHash:      "testhash-" + vmID,
		Admit:            func(store.ReservationTotals) error { return nil },
	})
	if err != nil {
		t.Fatalf("seed foreign VM: %v", err)
	}
	return vm.VMID, op.OperationID
}

// seedForeignRun inserts a run through the store, owned by otherOwner,
// in "running" phase so conclude can be attempted.
func seedForeignRun(t *testing.T, ctx context.Context, st *store.Store, vmID string) string {
	t.Helper()
	run, _, err := st.CreateRun(ctx, store.CreateRunInput{
		VMID:         vmID,
		Owner:        otherOwner,
		Goal:         "foreign run goal",
		CriteriaType: "operator_verdict",
		OnCompletion: "keep_running",
		RequestHash:  "runhash-" + uuid.NewString(),
		InitialPhase: "running",
	})
	if err != nil {
		t.Fatalf("seed foreign run: %v", err)
	}
	return run.RunID
}

// seedForeignBatch inserts an empty batch through the store, owned by otherOwner.
func seedForeignBatch(t *testing.T, ctx context.Context, st *store.Store) string {
	t.Helper()
	result, err := st.CreateVMBatch(ctx, store.CreateVMBatchInput{
		Owner:           otherOwner,
		RequestHash:     "batchhash-" + uuid.NewString(),
		ReservationMode: "best_effort",
		OnFailure:       "keep_successful",
		Members:         []store.BatchMemberInput{},
	})
	if err != nil {
		t.Fatalf("seed foreign batch: %v", err)
	}
	return fmt.Sprintf("batch-%06d", result.Batch.BatchID)
}

// doBearer sends a request with Bearer authorization.
func doBearer(t *testing.T, method, url, secret string, body io.Reader, contentType string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

// missingVMError returns the code+cause for a nonexistent VM, to compare with cross-owner denial.
func missingVMError(t *testing.T, srvURL, secret string) (code, cause string) {
	t.Helper()
	resp := doBearer(t, http.MethodGet, srvURL+"/api/v1/vms/"+uuid.NewString(), secret, nil, "")
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("nonexistent VM: want 404, got %d\n%s", resp.StatusCode, raw)
	}
	var e api.Error
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatalf("decode: %v\n%s", err, raw)
	}
	return e.Code, e.Cause
}

// missingOperationError returns the code+cause for a nonexistent operation, to compare with cross-owner denial.
func missingOperationError(t *testing.T, srvURL, secret string) (code, cause string) {
	t.Helper()
	resp := doBearer(t, http.MethodGet, srvURL+"/api/v1/operations/op-999999", secret, nil, "")
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("nonexistent operation: want 404, got %d\n%s", resp.StatusCode, raw)
	}
	var e api.Error
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatalf("decode: %v\n%s", err, raw)
	}
	return e.Code, e.Cause
}

// missingBatchError returns the code+cause for a nonexistent batch, to compare with cross-owner denial.
func missingBatchError(t *testing.T, srvURL, secret string) (code, cause string) {
	t.Helper()
	resp := doBearer(t, http.MethodGet, srvURL+"/api/v1/vm-batches/batch-999999", secret, nil, "")
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("nonexistent batch: want 404, got %d\n%s", resp.StatusCode, raw)
	}
	var e api.Error
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatalf("decode: %v\n%s", err, raw)
	}
	return e.Code, e.Cause
}

// missingRunError returns the code+cause for a nonexistent run, to compare with cross-owner denial.
func missingRunError(t *testing.T, srvURL, secret string) (code, cause string) {
	t.Helper()
	resp := doBearer(t, http.MethodGet, srvURL+"/api/v1/runs/"+uuid.NewString(), secret, nil, "")
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("nonexistent run: want 404, got %d\n%s", resp.StatusCode, raw)
	}
	var e api.Error
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatalf("decode: %v\n%s", err, raw)
	}
	return e.Code, e.Cause
}

// TestCrossOwnerDenied verifies AT-079: cross-owner access is denied without side effects,
// indistinguishable from a missing resource.
//
// AT-079 (API slice): cross-owner access is denied without side effects,
// indistinguishable from a missing resource.
func TestCrossOwnerDenied(t *testing.T) {
	srvURL, st, secret := newScopeServer(t)
	ctx := context.Background()

	// Seed foreign resources directly through the store (trusted ingress path).
	foreignVMID, foreignOpID := seedForeignVM(t, ctx, st)
	foreignRunID := seedForeignRun(t, ctx, st, foreignVMID)
	foreignBatchID := seedForeignBatch(t, ctx, st)
	foreignOpWireID := fmt.Sprintf("op-%06d", foreignOpID)

	// Capture the reference 404 bodies (missing resource) for each resource type.
	wantVMCode, wantVMCause := missingVMError(t, srvURL, secret)
	wantOpCode, wantOpCause := missingOperationError(t, srvURL, secret)
	wantBatchCode, wantBatchCause := missingBatchError(t, srvURL, secret)
	wantRunCode, wantRunCause := missingRunError(t, srvURL, secret)

	// --- AT-079 (1): GET /vms/{foreignID} → 404 identical to GET /vms/nonexistent ---
	t.Run("GET_foreign_VM", func(t *testing.T) {
		resp := doBearer(t, http.MethodGet, srvURL+"/api/v1/vms/"+foreignVMID, secret, nil, "")
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("want 404, got %d\n%s", resp.StatusCode, raw)
		}
		var e api.Error
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatalf("decode: %v\n%s", err, raw)
		}
		if e.Code != wantVMCode || e.Cause != wantVMCause {
			t.Errorf("code/cause = %q/%q, want %q/%q (must be identical to missing resource)", e.Code, e.Cause, wantVMCode, wantVMCause)
		}
	})

	// --- AT-079 (2): POST /vms/{foreignID}/actions → 404; VM state unchanged; no new ops ---
	t.Run("POST_foreign_VM_actions_no_side_effects", func(t *testing.T) {
		vmBefore, err := st.GetVM(ctx, foreignVMID)
		if err != nil {
			t.Fatalf("get vm before: %v", err)
		}
		opsBefore, err := st.ListOperationsByState(ctx, "running")
		if err != nil {
			t.Fatalf("list ops before: %v", err)
		}
		evsBefore, err := st.Query(ctx, store.Query{Limit: 1})
		if err != nil {
			t.Fatalf("query events before: %v", err)
		}

		actionBody := fmt.Sprintf(`{"action":"stop","expected_revision":"%d"}`, vmBefore.Revision)
		resp := doBearer(t, http.MethodPost, srvURL+"/api/v1/vms/"+foreignVMID+"/actions",
			secret, bytes.NewReader([]byte(actionBody)), "application/json")
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("actions: want 404, got %d\n%s", resp.StatusCode, raw)
		}

		// State must be unchanged (no side effects).
		vmAfter, err := st.GetVM(ctx, foreignVMID)
		if err != nil {
			t.Fatalf("get vm after: %v", err)
		}
		if vmAfter.ObservedState != vmBefore.ObservedState || vmAfter.Revision != vmBefore.Revision {
			t.Errorf("VM state/revision changed despite denial: %q/%d → %q/%d",
				vmBefore.ObservedState, vmBefore.Revision, vmAfter.ObservedState, vmAfter.Revision)
		}
		// No new operation rows.
		opsAfter, err := st.ListOperationsByState(ctx, "running")
		if err != nil {
			t.Fatalf("list ops after: %v", err)
		}
		if len(opsAfter) != len(opsBefore) {
			t.Errorf("operations created despite denial: before=%d after=%d", len(opsBefore), len(opsAfter))
		}
		// Event stream must be unchanged (no events emitted).
		evsAfter, err := st.Query(ctx, store.Query{Limit: 1})
		if err != nil {
			t.Fatalf("query events after: %v", err)
		}
		if evsAfter.LatestEventID != evsBefore.LatestEventID {
			t.Errorf("event stream advanced despite denial: latest before=%q after=%q",
				evsBefore.LatestEventID, evsAfter.LatestEventID)
		}
	})

	// --- AT-079 (3): DELETE /vms/{foreignID} → 404; VM still present ---
	t.Run("DELETE_foreign_VM", func(t *testing.T) {
		resp := doBearer(t, http.MethodDelete, srvURL+"/api/v1/vms/"+foreignVMID, secret, nil, "")
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("delete: want 404, got %d\n%s", resp.StatusCode, raw)
		}
		if _, err := st.GetVM(ctx, foreignVMID); err != nil {
			t.Errorf("VM was deleted despite denial: %v", err)
		}
	})

	// --- AT-079 (4): GET /operations/{foreignOpID} → 404; GET /vm-batches/{foreignBatchID} → 404 ---
	t.Run("GET_foreign_operation", func(t *testing.T) {
		resp := doBearer(t, http.MethodGet, srvURL+"/api/v1/operations/"+foreignOpWireID, secret, nil, "")
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("get op: want 404, got %d\n%s", resp.StatusCode, raw)
		}
		var e api.Error
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatalf("decode: %v\n%s", err, raw)
		}
		if e.Code != wantOpCode || e.Cause != wantOpCause {
			t.Errorf("code/cause = %q/%q, want %q/%q (must be identical to missing operation)", e.Code, e.Cause, wantOpCode, wantOpCause)
		}
	})

	t.Run("GET_foreign_batch", func(t *testing.T) {
		resp := doBearer(t, http.MethodGet, srvURL+"/api/v1/vm-batches/"+foreignBatchID, secret, nil, "")
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("get batch: want 404, got %d\n%s", resp.StatusCode, raw)
		}
		var e api.Error
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatalf("decode: %v\n%s", err, raw)
		}
		if e.Code != wantBatchCode || e.Cause != wantBatchCause {
			t.Errorf("code/cause = %q/%q, want %q/%q (must be identical to missing batch)", e.Code, e.Cause, wantBatchCode, wantBatchCause)
		}
	})

	// --- AT-079 (5): Run endpoints → 404; run phase unchanged on conclude attempt ---
	t.Run("GET_foreign_run", func(t *testing.T) {
		resp := doBearer(t, http.MethodGet, srvURL+"/api/v1/runs/"+foreignRunID, secret, nil, "")
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("get run: want 404, got %d\n%s", resp.StatusCode, raw)
		}
		var e api.Error
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatalf("decode: %v\n%s", err, raw)
		}
		if e.Code != wantRunCode || e.Cause != wantRunCause {
			t.Errorf("code/cause = %q/%q, want %q/%q (must be identical to missing run)", e.Code, e.Cause, wantRunCode, wantRunCause)
		}
	})

	t.Run("GET_foreign_run_report", func(t *testing.T) {
		resp := doBearer(t, http.MethodGet, srvURL+"/api/v1/runs/"+foreignRunID+"/report", secret, nil, "")
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("get run report: want 404, got %d\n%s", resp.StatusCode, raw)
		}
		var e api.Error
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatalf("decode: %v\n%s", err, raw)
		}
		if e.Code != wantRunCode || e.Cause != wantRunCause {
			t.Errorf("code/cause = %q/%q, want %q/%q (must be identical to missing run)", e.Code, e.Cause, wantRunCode, wantRunCause)
		}
	})

	t.Run("POST_foreign_run_conclude_no_side_effects", func(t *testing.T) {
		runBefore, err := st.GetRun(ctx, foreignRunID)
		if err != nil {
			t.Fatalf("get run before: %v", err)
		}

		resp := doBearer(t, http.MethodPost, srvURL+"/api/v1/runs/"+foreignRunID+"/conclude",
			secret, bytes.NewReader([]byte(`{"abort":true,"reason":"denied"}`)), "application/json")
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("conclude: want 404, got %d\n%s", resp.StatusCode, raw)
		}
		var e api.Error
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatalf("decode: %v\n%s", err, raw)
		}
		if e.Code != wantRunCode || e.Cause != wantRunCause {
			t.Errorf("code/cause = %q/%q, want %q/%q (must be identical to missing run)", e.Code, e.Cause, wantRunCode, wantRunCause)
		}
		// Run phase must be unchanged (no side effects).
		runAfter, err := st.GetRun(ctx, foreignRunID)
		if err != nil {
			t.Fatalf("get run after: %v", err)
		}
		if runAfter.Phase != runBefore.Phase {
			t.Errorf("run phase changed despite denial: %q → %q", runBefore.Phase, runAfter.Phase)
		}
	})

	// --- AT-079 (6): POST /vms/{foreignID}/runs → 404 ---
	t.Run("POST_foreign_VM_runs", func(t *testing.T) {
		runBody := `{"goal":"test","success_criteria":{"type":"operator_verdict"},"on_completion":"keep_running"}`
		resp := doBearer(t, http.MethodPost, srvURL+"/api/v1/vms/"+foreignVMID+"/runs",
			secret, bytes.NewReader([]byte(runBody)), "application/json")
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("create run on foreign VM: want 404, got %d\n%s", resp.StatusCode, raw)
		}
	})

	// --- AT-079 (7): GET /vms and GET /runs exclude foreign rows entirely ---
	t.Run("list_vms_excludes_foreign", func(t *testing.T) {
		resp := doBearer(t, http.MethodGet, srvURL+"/api/v1/vms", secret, nil, "")
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list vms: want 200, got %d\n%s", resp.StatusCode, raw)
		}
		var body struct {
			VMs []struct {
				VMID  string `json:"vm_id"`
				Owner string `json:"owner"`
			} `json:"vms"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		for _, vm := range body.VMs {
			if vm.VMID == foreignVMID {
				t.Errorf("foreign VM %s (owner=%s) appears in local_operator list", vm.VMID, vm.Owner)
			}
		}
	})

	t.Run("list_runs_excludes_foreign", func(t *testing.T) {
		resp := doBearer(t, http.MethodGet, srvURL+"/api/v1/runs", secret, nil, "")
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list runs: want 200, got %d\n%s", resp.StatusCode, raw)
		}
		var body struct {
			Runs []struct {
				RunID string `json:"run_id"`
				Owner string `json:"owner"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		for _, run := range body.Runs {
			if run.RunID == foreignRunID {
				t.Errorf("foreign run %s (owner=%s) appears in local_operator list", run.RunID, run.Owner)
			}
		}
	})
}

// TestOwnerScopedAccess verifies AT-079 (8): owned resources are fully accessible to their owner.
func TestOwnerScopedAccess(t *testing.T) {
	srvURL, st, secret := newScopeServer(t)
	ctx := context.Background()

	// Create a VM as local_operator through the API.
	createBody := fmt.Sprintf(`{"name":"owned-vm","template_id":"%s","vcpu_count":1,"memory_mib":512,"root_disk_mib":4096,"workspace_disk_mib":8192}`,
		testTemplateDef.TemplateID)
	createResp := doBearer(t, http.MethodPost, srvURL+"/api/v1/vms",
		secret, bytes.NewReader([]byte(createBody)), "application/json")
	createRaw, _ := io.ReadAll(createResp.Body)
	createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create VM: want 201, got %d\n%s", createResp.StatusCode, createRaw)
	}
	var createResult struct {
		VM struct {
			VMID  string `json:"vm_id"`
			Owner string `json:"owner"`
		} `json:"vm"`
	}
	if err := json.Unmarshal(createRaw, &createResult); err != nil {
		t.Fatalf("decode: %v", err)
	}
	vmID := createResult.VM.VMID
	if vmID == "" {
		t.Fatal("create VM: no vm_id in response")
	}

	// AT-079 (9): Created VM carries the authenticated owner, not a request body field.
	t.Run("created_VM_owner_from_identity", func(t *testing.T) {
		if createResult.VM.Owner != testOperator {
			t.Errorf("VM owner = %q, want %q (must come from identity)", createResult.VM.Owner, testOperator)
		}
		vm, err := st.GetVM(ctx, vmID)
		if err != nil {
			t.Fatalf("get from store: %v", err)
		}
		if vm.Owner != testOperator {
			t.Errorf("store VM owner = %q, want %q", vm.Owner, testOperator)
		}
	})

	// Own VM is accessible.
	t.Run("GET_own_VM", func(t *testing.T) {
		resp := doBearer(t, http.MethodGet, srvURL+"/api/v1/vms/"+vmID, secret, nil, "")
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET own VM: want 200, got %d\n%s", resp.StatusCode, raw)
		}
	})

	// Own VM appears in list.
	t.Run("list_vms_includes_own", func(t *testing.T) {
		resp := doBearer(t, http.MethodGet, srvURL+"/api/v1/vms", secret, nil, "")
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list VMs: want 200, got %d\n%s", resp.StatusCode, raw)
		}
		var body struct {
			VMs []struct {
				VMID string `json:"vm_id"`
			} `json:"vms"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		found := false
		for _, vm := range body.VMs {
			if vm.VMID == vmID {
				found = true
			}
		}
		if !found {
			t.Errorf("own VM %s not found in list", vmID)
		}
	})
}

// TestAnnotationAuthorFromIdentity verifies AT-079 (9): annotation author comes
// from the authenticated identity, never from a request field.
func TestAnnotationAuthorFromIdentity(t *testing.T) {
	srvURL, st, secret := newScopeServer(t)
	ctx := context.Background()

	annBody := `{"target_ref":"host:main","text":"scoping test"}`
	resp := doBearer(t, http.MethodPost, srvURL+"/api/v1/annotations",
		secret, bytes.NewReader([]byte(annBody)), "application/json")
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create annotation: want 201, got %d\n%s", resp.StatusCode, raw)
	}
	var annResp struct {
		Author string `json:"author"`
	}
	if err := json.Unmarshal(raw, &annResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if annResp.Author != testOperator {
		t.Errorf("annotation author = %q, want %q (must come from identity)", annResp.Author, testOperator)
	}

	// Verify in the event stream: annotation.created event must carry the correct author.
	result, err := st.Query(ctx, store.Query{Kind: "annotation.created", Limit: 10})
	if err != nil {
		t.Fatalf("query annotation events: %v", err)
	}
	if len(result.Events) == 0 {
		t.Fatal("no annotation.created event found")
	}
}
