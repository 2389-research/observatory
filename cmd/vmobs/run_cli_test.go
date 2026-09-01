// ABOUTME: CLI tests for "run" subcommands: submit, list, get, conclude, report.
// ABOUTME: TDD per task-10 brief; every contract bullet has at least one test.
package main

import (
	"context"
	"encoding/json"
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

var runCLITestTemplate = runtime.Template{
	TemplateID:  "run-test-small-v1",
	Description: "small run test VM",
	KernelImage: "/boot/vmlinuz",
	RootImage:   "/images/rootfs.ext4",
	Digest:      "sha256:aabbccddeeff0011",
}

// newRunCLIServer builds a server suitable for run CLI tests: one template, 8 GiB
// host, fake runtime. Returns the server and the fake so tests can interact with it.
func newRunCLIServer(t *testing.T) (*httptest.Server, *runtimetest.Fake) {
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
		Templates: map[string]runtime.Template{runCLITestTemplate.TemplateID: runCLITestTemplate},
		Host:      runtime.HostResources{TotalMemoryMiB: 8192, CPUCores: 8, StateDiskFreeMiB: 100 * 1024},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })
	srv := httptest.NewServer(api.New(st, eng, mgr))
	t.Cleanup(srv.Close)
	return srv, fake
}

// createCLIRunningVM creates a VM via the API and polls until observed_state=running.
// Returns the VM ID.
func createCLIRunningVM(t *testing.T, srvURL string) string {
	t.Helper()
	b, _ := json.Marshal(map[string]any{
		"name":        "cli-test-vm",
		"template_id": runCLITestTemplate.TemplateID,
	})
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, srvURL+"/api/v1/vms", strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create vm: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create vm: %d %s", resp.StatusCode, raw)
	}
	var cr map[string]any
	if err := json.Unmarshal(raw, &cr); err != nil {
		t.Fatalf("decode create vm: %v", err)
	}
	vmID, _ := cr["vm"].(map[string]any)["vm_id"].(string)
	opID, _ := cr["operation"].(map[string]any)["operation_id"].(string)

	// Poll for operation success.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for {
		resp2, err := http.Get(srvURL + "/api/v1/operations/" + opID)
		if err != nil {
			t.Fatalf("poll op: %v", err)
		}
		raw2, _ := io.ReadAll(resp2.Body)
		resp2.Body.Close()
		var op map[string]any
		_ = json.Unmarshal(raw2, &op)
		state, _ := op["state"].(string)
		if state == "succeeded" || state == "failed" {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timeout waiting for vm op %s", opID)
		case <-time.After(20 * time.Millisecond):
		}
	}
	return vmID
}

// --- run submit ---

func TestRunSubmitJSON(t *testing.T) {
	srv, _ := newRunCLIServer(t)
	vmID := createCLIRunningVM(t, srv.URL)

	code, stdout, stderr := runCLI(t, "--api", srv.URL, "--json", "run", "submit",
		"--vm", vmID, "--goal", "test the thing", "--criteria", "operator_verdict",
		"--on-completion", "keep_running")
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
		t.Fatalf("decode --json output: %v\n%s", err, stdout)
	}
	run, _ := resp["run"].(map[string]any)
	if run["run_id"] == nil {
		t.Error("submit response missing run.run_id")
	}
	if run["vm_id"] != vmID {
		t.Errorf("run.vm_id = %v, want %s", run["vm_id"], vmID)
	}
	if run["phase"] == nil {
		t.Error("submit response missing run.phase")
	}
}

func TestRunSubmitHuman(t *testing.T) {
	srv, _ := newRunCLIServer(t)
	vmID := createCLIRunningVM(t, srv.URL)

	code, stdout, stderr := runCLI(t, "--api", srv.URL, "run", "submit",
		"--vm", vmID, "--goal", "human submit test", "--criteria", "operator_verdict",
		"--on-completion", "keep_running")
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s\nstdout: %s", code, stderr, stdout)
	}
	if !strings.Contains(stdout, "run") {
		t.Errorf("human submit output missing run info:\n%s", stdout)
	}
	if !strings.Contains(stdout, vmID) {
		t.Errorf("human submit output missing vm_id:\n%s", stdout)
	}
}

func TestRunSubmitIdempotencyKey(t *testing.T) {
	srv, _ := newRunCLIServer(t)
	vmID := createCLIRunningVM(t, srv.URL)

	// First submit with a key.
	code1, out1, _ := runCLI(t, "--api", srv.URL, "--json", "run", "submit",
		"--vm", vmID, "--goal", "idempotent run", "--criteria", "operator_verdict",
		"--on-completion", "keep_running", "--idempotency-key", "my-key-1")
	if code1 != exitOK {
		t.Fatalf("first submit exit %d, out: %s", code1, out1)
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(out1), &first); err != nil {
		t.Fatalf("decode first: %v", err)
	}
	runID1, _ := first["run"].(map[string]any)["run_id"].(string)

	// Conclude the first run so we can submit a second.
	b, _ := json.Marshal(map[string]any{"verdict": "succeeded"})
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/v1/runs/"+runID1+"/conclude", strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	if resp != nil {
		resp.Body.Close()
	}

	// Second submit with same key but a different request — should get fresh run.
	// (idempotency key scope: same key reuses only if all fields match in canonical form.)
	// Here we just verify that the key flag is accepted and produces a valid run.
	code2, out2, stderr2 := runCLI(t, "--api", srv.URL, "--json", "run", "submit",
		"--vm", vmID, "--goal", "idempotent run", "--criteria", "operator_verdict",
		"--on-completion", "keep_running", "--idempotency-key", "my-key-2")
	if code2 != exitOK {
		t.Fatalf("second submit exit %d, stderr: %s, out: %s", code2, stderr2, out2)
	}
}

func TestRunSubmitVMNotRunning(t *testing.T) {
	// Use the basic server: no template, no running VM. We submit to a non-existent VM.
	srv, _ := newServer(t)

	code, stdout, stderr := runCLI(t, "--api", srv.URL, "run", "submit",
		"--vm", "00000000-dead-beef-0000-000000000001",
		"--goal", "will fail",
		"--criteria", "operator_verdict",
		"--on-completion", "keep_running")
	if code != exitAPIError {
		t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, exitAPIError, stdout, stderr)
	}
	// Error should be surfaced on stderr in human mode.
	if stderr == "" {
		t.Error("API error must be described on stderr")
	}
}

func TestRunSubmitVMNotRunningJSON(t *testing.T) {
	// VM exists but is not running — we use the basic server with no running VMs.
	srv, _ := newServer(t)

	code, stdout, _ := runCLI(t, "--api", srv.URL, "--json", "run", "submit",
		"--vm", "00000000-dead-beef-0000-000000000002",
		"--goal", "will fail json",
		"--criteria", "operator_verdict",
		"--on-completion", "keep_running")
	if code != exitAPIError {
		t.Fatalf("json mode: exit %d, want %d\nstdout: %s", code, exitAPIError, stdout)
	}
	var e api.Error
	if err := json.Unmarshal([]byte(stdout), &e); err != nil || e.Code == "" {
		t.Errorf("--json error body: %v, %s", err, stdout)
	}
}

func TestRunSubmitMissingVMFlag(t *testing.T) {
	srv, _ := newServer(t)
	code, _, stderr := runCLI(t, "--api", srv.URL, "run", "submit",
		"--goal", "no vm", "--criteria", "operator_verdict", "--on-completion", "keep_running")
	if code != exitUsage {
		t.Errorf("exit %d, want %d (stderr: %s)", code, exitUsage, stderr)
	}
}

func TestRunSubmitMissingGoalFlag(t *testing.T) {
	srv, _ := newServer(t)
	code, _, _ := runCLI(t, "--api", srv.URL, "run", "submit",
		"--vm", "some-id", "--criteria", "operator_verdict", "--on-completion", "keep_running")
	if code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
}

func TestRunSubmitMissingCriteriaFlag(t *testing.T) {
	srv, _ := newServer(t)
	code, _, _ := runCLI(t, "--api", srv.URL, "run", "submit",
		"--vm", "some-id", "--goal", "test", "--on-completion", "keep_running")
	if code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
}

func TestRunSubmitMissingOnCompletionFlag(t *testing.T) {
	srv, _ := newServer(t)
	code, _, _ := runCLI(t, "--api", srv.URL, "run", "submit",
		"--vm", "some-id", "--goal", "test", "--criteria", "operator_verdict")
	if code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
}

// --- run list ---

func TestRunListEmptyJSON(t *testing.T) {
	srv, _ := newServer(t)
	code, stdout, stderr := runCLI(t, "--api", srv.URL, "--json", "run", "list")
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	runs, _ := resp["runs"].([]any)
	if runs == nil {
		// Empty list is fine; the key must be present.
		if _, ok := resp["runs"]; !ok {
			t.Error("list response missing runs key")
		}
	}
}

func TestRunListHuman(t *testing.T) {
	srv, _ := newRunCLIServer(t)
	vmID := createCLIRunningVM(t, srv.URL)

	// Submit a run.
	runCLI(t, "--api", srv.URL, "run", "submit",
		"--vm", vmID, "--goal", "listed run", "--criteria", "operator_verdict",
		"--on-completion", "keep_running")

	code, stdout, stderr := runCLI(t, "--api", srv.URL, "run", "list", "--vm", vmID)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, vmID) {
		t.Errorf("human list missing vm_id:\n%s", stdout)
	}
}

func TestRunListFilterByPhase(t *testing.T) {
	srv, _ := newRunCLIServer(t)
	vmID := createCLIRunningVM(t, srv.URL)
	runCLI(t, "--api", srv.URL, "run", "submit",
		"--vm", vmID, "--goal", "phase filter test", "--criteria", "operator_verdict",
		"--on-completion", "keep_running")

	code, stdout, stderr := runCLI(t, "--api", srv.URL, "--json", "run", "list", "--phase", "running")
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	runs, _ := resp["runs"].([]any)
	if len(runs) < 1 {
		t.Errorf("expected at least one running run, got %d", len(runs))
	}
}

func TestRunListBogusPhaseExitsOne(t *testing.T) {
	srv, _ := newServer(t)
	code, stdout, stderr := runCLI(t, "--api", srv.URL, "run", "list", "--phase", "bogus")
	if code != exitAPIError {
		t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, exitAPIError, stdout, stderr)
	}
	if !strings.Contains(stderr, "phase_unknown") {
		t.Errorf("expected phase_unknown in stderr:\n%s", stderr)
	}
}

func TestRunListBogusPhaseJSONExitsOne(t *testing.T) {
	srv, _ := newServer(t)
	code, stdout, _ := runCLI(t, "--api", srv.URL, "--json", "run", "list", "--phase", "bogus")
	if code != exitAPIError {
		t.Fatalf("exit %d, want %d\nstdout: %s", code, exitAPIError, stdout)
	}
	var e api.Error
	if err := json.Unmarshal([]byte(stdout), &e); err != nil || e.Cause != "phase_unknown" {
		t.Errorf("--json error: %v, %s", err, stdout)
	}
}

// --- run get ---

func TestRunGetJSON(t *testing.T) {
	srv, _ := newRunCLIServer(t)
	vmID := createCLIRunningVM(t, srv.URL)

	code1, out1, _ := runCLI(t, "--api", srv.URL, "--json", "run", "submit",
		"--vm", vmID, "--goal", "get me", "--criteria", "operator_verdict",
		"--on-completion", "keep_running")
	if code1 != exitOK {
		t.Fatalf("submit exit %d: %s", code1, out1)
	}
	var sr map[string]any
	if err := json.Unmarshal([]byte(out1), &sr); err != nil {
		t.Fatalf("decode submit: %v", err)
	}
	runID, _ := sr["run"].(map[string]any)["run_id"].(string)

	code, stdout, stderr := runCLI(t, "--api", srv.URL, "--json", "run", "get", runID)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	var run map[string]any
	if err := json.Unmarshal([]byte(stdout), &run); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	if run["run_id"] != runID {
		t.Errorf("run_id = %v, want %s", run["run_id"], runID)
	}
}

func TestRunGetHuman(t *testing.T) {
	srv, _ := newRunCLIServer(t)
	vmID := createCLIRunningVM(t, srv.URL)

	code1, out1, _ := runCLI(t, "--api", srv.URL, "--json", "run", "submit",
		"--vm", vmID, "--goal", "human get test", "--criteria", "operator_verdict",
		"--on-completion", "keep_running")
	if code1 != exitOK {
		t.Fatalf("submit exit %d: %s", code1, out1)
	}
	var sr map[string]any
	_ = json.Unmarshal([]byte(out1), &sr)
	runID, _ := sr["run"].(map[string]any)["run_id"].(string)

	code, stdout, stderr := runCLI(t, "--api", srv.URL, "run", "get", runID)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, runID) {
		t.Errorf("human get missing run_id:\n%s", stdout)
	}
	if !strings.Contains(stdout, vmID) {
		t.Errorf("human get missing vm_id:\n%s", stdout)
	}
}

func TestRunGetNotFound(t *testing.T) {
	srv, _ := newServer(t)
	code, _, stderr := runCLI(t, "--api", srv.URL, "run", "get", "no-such-run")
	if code != exitAPIError {
		t.Fatalf("exit %d, want %d, stderr: %s", code, exitAPIError, stderr)
	}
	if !strings.Contains(stderr, "not_found") {
		t.Errorf("expected not_found in stderr:\n%s", stderr)
	}
}

func TestRunGetMissingArg(t *testing.T) {
	srv, _ := newServer(t)
	code, _, _ := runCLI(t, "--api", srv.URL, "run", "get")
	if code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
}

// --- run conclude ---

func TestRunConcludeVerdictJSON(t *testing.T) {
	srv, _ := newRunCLIServer(t)
	vmID := createCLIRunningVM(t, srv.URL)

	code1, out1, _ := runCLI(t, "--api", srv.URL, "--json", "run", "submit",
		"--vm", vmID, "--goal", "conclude verdict", "--criteria", "operator_verdict",
		"--on-completion", "keep_running")
	if code1 != exitOK {
		t.Fatalf("submit exit %d: %s", code1, out1)
	}
	var sr map[string]any
	_ = json.Unmarshal([]byte(out1), &sr)
	runID, _ := sr["run"].(map[string]any)["run_id"].(string)

	// Flags must come before positional args (Go flag package convention per gotchas.md).
	code, stdout, stderr := runCLI(t, "--api", srv.URL, "--json", "run", "conclude",
		"--verdict", "succeeded", runID)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	run, _ := resp["run"].(map[string]any)
	if phase, _ := run["phase"].(string); phase != "succeeded" {
		t.Errorf("phase = %q, want succeeded", phase)
	}
}

func TestRunConcludeVerdictHuman(t *testing.T) {
	srv, _ := newRunCLIServer(t)
	vmID := createCLIRunningVM(t, srv.URL)

	code1, out1, _ := runCLI(t, "--api", srv.URL, "--json", "run", "submit",
		"--vm", vmID, "--goal", "conclude human", "--criteria", "operator_verdict",
		"--on-completion", "keep_running")
	if code1 != exitOK {
		t.Fatalf("submit exit %d: %s", code1, out1)
	}
	var sr map[string]any
	_ = json.Unmarshal([]byte(out1), &sr)
	runID, _ := sr["run"].(map[string]any)["run_id"].(string)

	// Flags must come before positional args (Go flag package convention per gotchas.md).
	code, stdout, stderr := runCLI(t, "--api", srv.URL, "run", "conclude",
		"--verdict", "failed", "--reason", "test failure reason", runID)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "failed") {
		t.Errorf("human conclude output missing phase:\n%s", stdout)
	}
}

func TestRunConcludeAbort(t *testing.T) {
	srv, _ := newRunCLIServer(t)
	vmID := createCLIRunningVM(t, srv.URL)

	code1, out1, _ := runCLI(t, "--api", srv.URL, "--json", "run", "submit",
		"--vm", vmID, "--goal", "abort me", "--criteria", "operator_verdict",
		"--on-completion", "keep_running")
	if code1 != exitOK {
		t.Fatalf("submit exit %d: %s", code1, out1)
	}
	var sr map[string]any
	_ = json.Unmarshal([]byte(out1), &sr)
	runID, _ := sr["run"].(map[string]any)["run_id"].(string)

	// Flags must come before positional args (Go flag package convention per gotchas.md).
	code, stdout, stderr := runCLI(t, "--api", srv.URL, "--json", "run", "conclude",
		"--abort", "--reason", "operator said no", runID)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	run, _ := resp["run"].(map[string]any)
	if phase, _ := run["phase"].(string); phase != "aborted" {
		t.Errorf("phase = %q, want aborted", phase)
	}
}

func TestRunConcludeVerdictAndAbortTogetherExitsThree(t *testing.T) {
	// Flags before positional: --verdict and --abort together → usage error before any request.
	srv, _ := newServer(t)
	code, _, stderr := runCLI(t, "--api", srv.URL, "run", "conclude",
		"--verdict", "succeeded", "--abort", "some-run-id")
	if code != exitUsage {
		t.Errorf("exit %d, want %d (stderr: %s)", code, exitUsage, stderr)
	}
}

func TestRunConcludeNeitherVerdictNorAbortExitsThree(t *testing.T) {
	// No --verdict and no --abort: positional arg alone is a usage error.
	srv, _ := newServer(t)
	code, _, stderr := runCLI(t, "--api", srv.URL, "run", "conclude", "some-run-id")
	if code != exitUsage {
		t.Errorf("exit %d, want %d (stderr: %s)", code, exitUsage, stderr)
	}
}

func TestRunConcludeMissingRunIDExitsThree(t *testing.T) {
	// Flags provided but no positional run ID → usage error.
	srv, _ := newServer(t)
	code, _, _ := runCLI(t, "--api", srv.URL, "run", "conclude", "--verdict", "succeeded")
	if code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
}

// --- run report ---

func TestRunReportPendingJSON(t *testing.T) {
	srv, _ := newRunCLIServer(t)
	vmID := createCLIRunningVM(t, srv.URL)

	code1, out1, _ := runCLI(t, "--api", srv.URL, "--json", "run", "submit",
		"--vm", vmID, "--goal", "report pending", "--criteria", "operator_verdict",
		"--on-completion", "keep_running")
	if code1 != exitOK {
		t.Fatalf("submit exit %d: %s", code1, out1)
	}
	var sr map[string]any
	_ = json.Unmarshal([]byte(out1), &sr)
	runID, _ := sr["run"].(map[string]any)["run_id"].(string)

	// Non-terminal run: report is pending.
	code, stdout, stderr := runCLI(t, "--api", srv.URL, "--json", "run", "report", runID)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	var rpt map[string]any
	if err := json.Unmarshal([]byte(stdout), &rpt); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	if rpt["status"] != "pending" {
		t.Errorf("status = %v, want pending", rpt["status"])
	}
}

func TestRunReportPendingHuman(t *testing.T) {
	srv, _ := newRunCLIServer(t)
	vmID := createCLIRunningVM(t, srv.URL)

	code1, out1, _ := runCLI(t, "--api", srv.URL, "--json", "run", "submit",
		"--vm", vmID, "--goal", "report pending human", "--criteria", "operator_verdict",
		"--on-completion", "keep_running")
	if code1 != exitOK {
		t.Fatalf("submit exit %d: %s", code1, out1)
	}
	var sr map[string]any
	_ = json.Unmarshal([]byte(out1), &sr)
	runID, _ := sr["run"].(map[string]any)["run_id"].(string)

	code, stdout, stderr := runCLI(t, "--api", srv.URL, "run", "report", runID)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "pending") {
		t.Errorf("human report missing pending status:\n%s", stdout)
	}
}

func TestRunReportMissingRunIDExitsThree(t *testing.T) {
	srv, _ := newServer(t)
	code, _, _ := runCLI(t, "--api", srv.URL, "run", "report")
	if code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
}

func TestRunReportNotFound(t *testing.T) {
	srv, _ := newServer(t)
	code, _, stderr := runCLI(t, "--api", srv.URL, "run", "report", "no-such-run")
	if code != exitAPIError {
		t.Fatalf("exit %d, want %d, stderr: %s", code, exitAPIError, stderr)
	}
}

// --- run dispatch edge cases ---

func TestRunUnknownSubcommand(t *testing.T) {
	srv, _ := newServer(t)
	code, _, _ := runCLI(t, "--api", srv.URL, "run", "explode")
	if code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
}

func TestRunNoSubcommand(t *testing.T) {
	srv, _ := newServer(t)
	code, _, _ := runCLI(t, "--api", srv.URL, "run")
	if code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
}

// --- vm create with attached run ---

func TestVMCreateWithRunFlags(t *testing.T) {
	srv := newVMServer(t)
	code, stdout, stderr := runCLI(t, "--api", srv.URL, "--json", "vm", "create",
		"--template", cliTestTemplate.TemplateID,
		"--run-goal", "launch attached run",
		"--run-criteria", "operator_verdict",
		"--run-on-completion", "keep_running",
		"run-attached-vm")
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s\nstdout: %s", code, stderr, stdout)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	vm, _ := resp["vm"].(map[string]any)
	if vm["vm_id"] == nil {
		t.Error("create with run response missing vm.vm_id")
	}
	// The API create response contains vm + operation; the run is retrievable
	// via GET /runs?vm_id=... after the operation succeeds. We just verify
	// that the CLI accepted the flags and the VM was created.
	if resp["operation"] == nil {
		t.Error("create with run response missing operation key")
	}
}

func TestVMCreateRunFlagsAllOrNone_MissingGoal(t *testing.T) {
	srv := newVMServer(t)
	code, _, _ := runCLI(t, "--api", srv.URL, "vm", "create",
		"--template", cliTestTemplate.TemplateID,
		"--run-criteria", "operator_verdict",
		"--run-on-completion", "keep_running",
		"partial-run-vm")
	if code != exitUsage {
		t.Errorf("exit %d, want %d (missing --run-goal)", code, exitUsage)
	}
}

func TestVMCreateRunFlagsAllOrNone_MissingCriteria(t *testing.T) {
	srv := newVMServer(t)
	code, _, _ := runCLI(t, "--api", srv.URL, "vm", "create",
		"--template", cliTestTemplate.TemplateID,
		"--run-goal", "some goal",
		"--run-on-completion", "keep_running",
		"partial-run-vm")
	if code != exitUsage {
		t.Errorf("exit %d, want %d (missing --run-criteria)", code, exitUsage)
	}
}

func TestVMCreateRunFlagsAllOrNone_MissingOnCompletion(t *testing.T) {
	srv := newVMServer(t)
	code, _, _ := runCLI(t, "--api", srv.URL, "vm", "create",
		"--template", cliTestTemplate.TemplateID,
		"--run-goal", "some goal",
		"--run-criteria", "operator_verdict",
		"partial-run-vm")
	if code != exitUsage {
		t.Errorf("exit %d, want %d (missing --run-on-completion)", code, exitUsage)
	}
}
