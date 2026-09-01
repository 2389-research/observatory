// ABOUTME: Round-trip and manager wiring tests for report generation (P-05, Task 7).
// ABOUTME: The round-trip test reproduces every counted field via its reproduce_query.
package report_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/api"
	"github.com/2389-research/observatory-v2/internal/config"
	"github.com/2389-research/observatory-v2/internal/report"
	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/runtime/runtimetest"
	"github.com/2389-research/observatory-v2/internal/situation"
	"github.com/2389-research/observatory-v2/internal/store"
)

// --- helpers ---

// newAPIServer builds a test httptest.Server over a real store + manager.
func newAPIServer(t *testing.T, st *store.Store, mgr *runtime.Manager) *httptest.Server {
	t.Helper()
	eng := situation.New(st, situation.Config{
		Triggers: map[string]bool{},
	})
	srv := httptest.NewServer(api.New(st, eng, mgr, api.AuthConfig{Enabled: false}))
	t.Cleanup(srv.Close)
	return srv
}

// newManagerWithStore creates a Manager over st with the fake runtime.
func newManagerWithStore(t *testing.T, st *store.Store) *runtime.Manager {
	t.Helper()
	mgr, err := runtime.NewManager(st, runtimetest.NewFake(), runtime.ManagerConfig{
		Admission:  config.Admission{CPUOvercommitRatio: 4.0},
		VMDefaults: config.VMDefaults{},
		Templates:  map[string]runtime.Template{},
		Host:       runtime.HostResources{TotalMemoryMiB: 8192, CPUCores: 4, StateDiskFreeMiB: 100 * 1024},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })
	return mgr
}

// --- round-trip test ---

// TestRoundTrip_AllCountedFieldsReproduce is the P-05 test. For every counted
// field and every event_rollup entry in a generated report, it executes the
// reproduce_query against a real httptest.Server and pages through to count,
// then asserts equality with the report value.
func TestRoundTrip_AllCountedFieldsReproduce(t *testing.T) {
	st := openStore(t)
	mgr := newManagerWithStore(t, st)
	srv := newAPIServer(t, st, mgr)

	// Build a scenario with some events in the window.
	vmID := mustCreateRunningVM(t, st)

	// Create and conclude a guest_result run.
	run, _, err := st.CreateRun(t.Context(), store.CreateRunInput{
		VMID: vmID, Owner: "test", Goal: "round-trip reproducibility test",
		CriteriaType: "guest_result", OnCompletion: "keep_running",
		ProgressEvents: true,
		RequestHash:    "hash-rt",
		InitialPhase:   "running",
	})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}

	// Submit two progress events (run family).
	for i := 0; i < 2; i++ {
		payload, _ := json.Marshal(map[string]any{"step": i + 1})
		if _, err := st.SubmitRunProgress(t.Context(), store.SubmitProgressInput{
			RunID: run.RunID, Payload: payload, MaxBytes: 1 << 20,
		}); err != nil {
			t.Fatalf("SubmitRunProgress: %v", err)
		}
	}

	result, _ := json.Marshal(map[string]any{"status": "succeeded"})
	if _, err := st.SubmitRunResult(t.Context(), store.SubmitResultInput{
		RunID: run.RunID, Result: result, MaxBytes: 1 << 20,
	}); err != nil {
		t.Fatalf("SubmitRunResult: %v", err)
	}

	mustTransitionRun(t, st, run.RunID, "running", "concluding", "", "")
	mustTransitionRun(t, st, run.RunID, "concluding", "succeeded", "guest_result", "guest reported success")

	raw, _, err := report.Generate(t.Context(), st, run.RunID, report.Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Walk the report JSON generically: find every object holding both
	// "count" and "reproduce_query" and verify the query reproduces the count.
	counted := extractCounted(t, raw)
	if len(counted) == 0 {
		t.Fatal("no counted fields found in report — report structure changed?")
	}
	t.Logf("checking %d counted fields", len(counted))

	for path, entry := range counted {
		t.Run(path, func(t *testing.T) {
			reproduced := pageAndCount(t, srv.URL, entry.reproduceQuery)
			if reproduced != entry.count {
				t.Errorf("reproduce_query %q: got count %d, report says %d",
					entry.reproduceQuery, reproduced, entry.count)
			}
		})
	}

	// F9: event_rollup must contain a "run" family row with count > 0.
	var rep struct {
		EventRollup []struct {
			Family string `json:"family"`
			Count  int64  `json:"count"`
		} `json:"event_rollup"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("unmarshal for event_rollup check: %v", err)
	}
	foundRun := false
	for _, row := range rep.EventRollup {
		if row.Family == "run" && row.Count > 0 {
			foundRun = true
			break
		}
	}
	if !foundRun {
		t.Error("event_rollup has no 'run' family row with count > 0 — rollup regression")
	}
}

// TestTerminalEvidenceLinkReturnsOneEvent verifies that the terminal evidence link
// in the report returns exactly 1 run.state_changed event with a terminal "to"
// phase when executed against the real API server. This is the F2 regression test:
// the link uses family=run (not kind=) so the vm_id= filter applies the two-clause
// match (column OR data.vm_id), which is required for run.* events that ride the
// host-wide stream with a NULL vm_id column.
func TestTerminalEvidenceLinkReturnsOneEvent(t *testing.T) {
	st := openStore(t)
	mgr := newManagerWithStore(t, st)
	srv := newAPIServer(t, st, mgr)

	vmID := mustCreateRunningVM(t, st)
	run, _, err := st.CreateRun(t.Context(), store.CreateRunInput{
		VMID: vmID, Owner: "test", Goal: "terminal evidence link test",
		CriteriaType: "operator_verdict", OnCompletion: "keep_running",
		RequestHash: "hash-evlink", InitialPhase: "running",
	})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	mustTransitionRun(t, st, run.RunID, "running", "concluding", "", "operator verdict")
	mustTransitionRun(t, st, run.RunID, "concluding", "succeeded", "operator", "operator verdict: succeeded")

	raw, _, err := report.Generate(t.Context(), st, run.RunID, report.Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Extract the first evidence link from outcome.evidence_links.
	var rep struct {
		Outcome struct {
			EvidenceLinks []string `json:"evidence_links"`
		} `json:"outcome"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if len(rep.Outcome.EvidenceLinks) == 0 {
		t.Fatal("no evidence_links in report outcome")
	}
	terminalLink := rep.Outcome.EvidenceLinks[0]
	t.Logf("terminal evidence link: %s", terminalLink)

	// Execute the link against the server.
	resp, err := http.Get(srv.URL + terminalLink)
	if err != nil {
		t.Fatalf("GET %s: %v", terminalLink, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", terminalLink, resp.StatusCode, body)
	}

	var page struct {
		Events []json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatalf("decode events page: %v\nbody: %s", err, body)
	}
	if len(page.Events) != 1 {
		t.Fatalf("terminal evidence link returned %d events, want exactly 1\nbody: %s", len(page.Events), body)
	}

	// Confirm the event is run.state_changed with a terminal "to".
	var ev struct {
		Kind string `json:"kind"`
		Data struct {
			To string `json:"to"`
		} `json:"data"`
	}
	if err := json.Unmarshal(page.Events[0], &ev); err != nil {
		t.Fatalf("decode event: %v", err)
	}
	if ev.Kind != "run.state_changed" {
		t.Errorf("event kind = %q, want run.state_changed", ev.Kind)
	}
	terminalPhases := map[string]bool{
		"succeeded": true, "failed": true, "inconclusive": true, "aborted": true,
	}
	if !terminalPhases[ev.Data.To] {
		t.Errorf("event data.to = %q, want a terminal phase", ev.Data.To)
	}
}

// countedEntry is a {count, reproduce_query} pair found in the report.
type countedEntry struct {
	count          int64
	reproduceQuery string
}

// extractCounted walks a JSON report recursively and returns all objects that
// have both "count" (integer) and "reproduce_query" (string). The key is a
// dotted path like "network_summary.flows" for traceability.
func extractCounted(t *testing.T, raw json.RawMessage) map[string]countedEntry {
	t.Helper()
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	result := map[string]countedEntry{}
	walkForCounted("", root, result)
	return result
}

func walkForCounted(prefix string, v any, out map[string]countedEntry) {
	m, ok := v.(map[string]any)
	if !ok {
		// arrays
		if arr, ok := v.([]any); ok {
			for i, item := range arr {
				walkForCounted(fmt.Sprintf("%s[%d]", prefix, i), item, out)
			}
		}
		return
	}
	// Check if this object is itself a counted shape.
	countRaw, hasCount := m["count"]
	queryRaw, hasQuery := m["reproduce_query"]
	if hasCount && hasQuery {
		count, okC := countRaw.(float64) // JSON numbers decode as float64
		query, okQ := queryRaw.(string)
		if okC && okQ {
			key := prefix
			if key == "" {
				key = "root"
			}
			out[key] = countedEntry{count: int64(count), reproduceQuery: query}
		}
	}
	// Recurse into child fields.
	for k, child := range m {
		childKey := k
		if prefix != "" {
			childKey = prefix + "." + k
		}
		walkForCounted(childKey, child, out)
	}
}

// pageAndCount executes the reproduce_query against the test server, paging
// through all results and counting events. The query is the path+query part
// (e.g. "/api/v1/events?..."). The paging contract: supply until= on every
// page; next_after can walk past until.
func pageAndCount(t *testing.T, baseURL, query string) int64 {
	t.Helper()

	// Parse the query to extract until= value if present.
	untilVal := extractParam(query, "until")

	total := int64(0)
	afterCursor := extractParam(query, "after")
	if afterCursor == "" {
		afterCursor = "0"
	}
	// Build base URL without after= (we manage it ourselves for paging).
	baseQuery := stripParam(query, "after")

	const pageSize = 200
	for {
		pageQuery := appendParam(baseQuery, "after", afterCursor)
		pageQuery = appendParam(pageQuery, "limit", strconv.Itoa(pageSize))

		url := baseURL + pageQuery
		resp, err := http.Get(url)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d: %s", url, resp.StatusCode, body)
		}

		var page struct {
			Events    []json.RawMessage `json:"events"`
			NextAfter string            `json:"next_after"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			t.Fatalf("decode events page: %v\nbody: %s", err, body)
		}

		total += int64(len(page.Events))

		// Stop when the page is smaller than the limit (last page).
		if len(page.Events) < pageSize {
			break
		}

		// Re-supply until on every page (brief paging contract).
		nextAfter := page.NextAfter
		if untilVal != "" {
			untilInt, _ := strconv.ParseInt(untilVal, 10, 64)
			nextInt, _ := strconv.ParseInt(nextAfter, 10, 64)
			// If next_after walked past until, we're done.
			if nextInt >= untilInt {
				break
			}
		}
		afterCursor = nextAfter
	}
	return total
}

// extractParam extracts the value of the first occurrence of param= in a URL path.
func extractParam(query, param string) string {
	idx := strings.Index(query, "?")
	if idx < 0 {
		return ""
	}
	qs := query[idx+1:]
	for _, part := range strings.Split(qs, "&") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 && kv[0] == param {
			return kv[1]
		}
	}
	return ""
}

// stripParam removes all occurrences of param= from the query string in a URL path.
func stripParam(query, param string) string {
	idx := strings.Index(query, "?")
	if idx < 0 {
		return query
	}
	path := query[:idx]
	qs := query[idx+1:]
	var parts []string
	for _, part := range strings.Split(qs, "&") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) >= 1 && kv[0] != param {
			parts = append(parts, part)
		}
	}
	if len(parts) == 0 {
		return path
	}
	return path + "?" + strings.Join(parts, "&")
}

// appendParam adds param=value to a URL path's query string.
func appendParam(query, param, value string) string {
	if strings.Contains(query, "?") {
		return query + "&" + param + "=" + value
	}
	return query + "?" + param + "=" + value
}

// --- manager wiring test ---

// TestManagerWiring_TerminalRunTriggersReportOp verifies that a terminal run
// causes a run.report_generate operation to be created and succeed, and that
// GetRunReport returns the stored report.
func TestManagerWiring_TerminalRunTriggersReportOp(t *testing.T) {
	st := openStore(t)
	fk := runtimetest.NewFake()

	// Use NewManagerWithReportGen to wire the real generator before reconcile.
	reportGenFn := report.MakeReportGenFn(st, report.Options{})
	mgr, err := runtime.NewManagerWithReportGen(st, fk, runtime.ManagerConfig{
		Admission: config.Admission{CPUOvercommitRatio: 4.0},
		VMDefaults: config.VMDefaults{
			VCPUCount: 2, MemoryMiB: 2048,
			RootDiskMiB: 8192, WorkspaceDiskMiB: 10240,
			NetworkProfile: "transport", NetworkPolicyID: "net-pub",
			StopGraceSeconds: 1,
		},
		Templates: map[string]runtime.Template{
			"tmpl-test": {
				TemplateID:       "tmpl-test",
				Description:      "test",
				KernelImage:      "/k",
				RootImage:        "/r",
				Digest:           fmt.Sprintf("sha256:%064d", 1),
				ProtocolVersions: map[string]string{"guestd": "1"},
			},
		},
		Host: runtime.HostResources{
			TotalMemoryMiB:   131072,
			CPUCores:         64,
			StateDiskFreeMiB: 1 << 20,
		},
	}, reportGenFn)
	if err != nil {
		t.Fatalf("NewManagerWithReportGen: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })

	// Create a VM and wait for it to reach running.
	vm, _, _, err := mgr.CreateVM(t.Context(), "test", runtime.CreateRequest{
		Name: "wiring-test-vm", TemplateID: "tmpl-test",
	})
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	waitForVMState(t, st, vm.VMID, "running")

	// Create a standalone run.
	run, _, err := mgr.CreateRun(t.Context(), runtime.RunRequest{
		VMID: vm.VMID, Owner: "test", Goal: "manager wiring test",
		CriteriaType: "operator_verdict", OnCompletion: "keep_running",
	})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}

	// Conclude it with an operator verdict.
	v := "succeeded"
	if _, err := mgr.ConcludeRun(t.Context(), run.RunID, &v, false, "operator verdict: succeeded"); err != nil {
		t.Fatalf("ConcludeRun: %v", err)
	}

	// Wait for the report to appear (the report goroutine is async).
	deadline := time.Now().Add(5 * time.Second)
	var storedReport *store.RunReport
	for time.Now().Before(deadline) {
		r, err := st.GetRunReport(t.Context(), run.RunID)
		if err == nil {
			storedReport = r
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if storedReport == nil {
		t.Fatalf("report never stored for run %s within timeout", run.RunID)
	}
	if !isValidDigest(storedReport.Digest) {
		t.Errorf("stored digest format wrong: %q", storedReport.Digest)
	}
}

// TestManagerWiring_ReconcileReEnqueues tests the R7 reconcile path: seed a
// terminal run with no report, create a new Manager with the real generator
// wired via NewManagerWithReportGen → reconcile fires → report appears.
func TestManagerWiring_ReconcileReEnqueues(t *testing.T) {
	st := openStore(t)

	// Seed a terminal run with no report directly via the store.
	vmID := mustCreateRunningVM(t, st)
	runID := buildScenario(t, st, scenarioOperatorVerdict)
	_ = vmID
	_ = runID // ensure it compiled

	// Confirm no report stored yet.
	if _, err := st.GetRunReport(t.Context(), runID); err == nil {
		t.Fatal("expected no report before manager starts")
	}

	reportGenFn := report.MakeReportGenFn(st, report.Options{})
	mgr, err := runtime.NewManagerWithReportGen(st, runtimetest.NewFake(), runtime.ManagerConfig{
		Admission:  config.Admission{CPUOvercommitRatio: 4.0},
		VMDefaults: config.VMDefaults{},
		Templates:  map[string]runtime.Template{},
		Host:       runtime.HostResources{TotalMemoryMiB: 8192, CPUCores: 4, StateDiskFreeMiB: 100 * 1024},
	}, reportGenFn)
	if err != nil {
		t.Fatalf("NewManagerWithReportGen: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })

	// Report should appear from reconcile.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := st.GetRunReport(t.Context(), runID); err == nil {
			return // success
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("report never appeared via reconcile for run %s", runID)
}

// TestManagerWiring_ReconcileGuard asserts the guard outcome: after reconcile
// on a terminal run that had a pre-seeded running report op, exactly one report
// row exists and exactly one succeeded op was recorded for that run.
//
// Reconcile fails ALL running operations at startup (controller_restart),
// including the pre-seeded one. Then category 2 re-enqueues generation via
// the MakeReportGenFn guard (HasRunningReportOp is now false), which creates
// exactly one new op. No duplicate op is created because MakeReportGenFn's own
// HasRunningReportOp guard runs before InsertReportOperation.
func TestManagerWiring_ReconcileGuard(t *testing.T) {
	st := openStore(t)

	// Seed a terminal run.
	runID := buildScenario(t, st, scenarioAborted)
	vmID := mustRunVMID(t, st, runID)

	// Pre-seed a running report op to simulate one already in flight.
	preOpID, err := st.InsertReportOperation(t.Context(), "test", vmID, runID)
	if err != nil {
		t.Fatalf("InsertReportOperation: %v", err)
	}
	t.Logf("pre-seeded report op %d for run %s", preOpID, runID)

	// Create manager — reconcile fires. The guard must see the running op and skip
	// re-enqueueing, leaving exactly one report op for this run.
	reportGenFn := report.MakeReportGenFn(st, report.Options{})
	mgr, err := runtime.NewManagerWithReportGen(st, runtimetest.NewFake(), runtime.ManagerConfig{
		Admission:  config.Admission{CPUOvercommitRatio: 4.0},
		VMDefaults: config.VMDefaults{},
		Templates:  map[string]runtime.Template{},
		Host:       runtime.HostResources{TotalMemoryMiB: 8192, CPUCores: 4, StateDiskFreeMiB: 100 * 1024},
	}, reportGenFn)
	if err != nil {
		t.Fatalf("NewManagerWithReportGen: %v", err)
	}
	mgr.Close()

	// Reconcile fails ALL running operations at startup (controller_restart). The
	// pre-seeded running op is therefore failed (1 failed op). After that,
	// HasRunningReportOp returns false, so reconcile re-enqueues generation.
	// MakeReportGenFn creates one new op and stores the report synchronously during
	// reconcile (gotcha: reconcile report gen stays synchronous). By the time
	// NewManagerWithReportGen + Close return, the report is stored.
	//
	// The guard invariant: at no point were two ops IN FLIGHT simultaneously. We
	// verify the outcome: exactly one op is in "succeeded" state for this run,
	// and the report exists.
	succeededOps := 0
	ops, err := st.ListOperationsByState(t.Context(), "succeeded")
	if err != nil {
		t.Fatalf("ListOperationsByState(succeeded): %v", err)
	}
	for _, op := range ops {
		if op.Kind == "run.report_generate" && op.RequestHash == runID {
			succeededOps++
		}
	}
	if succeededOps != 1 {
		t.Errorf("expected exactly 1 succeeded report op for run %s, got %d",
			runID, succeededOps)
	}

	// Report must exist.
	if _, err := st.GetRunReport(t.Context(), runID); err != nil {
		t.Errorf("GetRunReport: expected stored report, got %v", err)
	}
}

// mustRunVMID reads the vm_id for a run from the store.
func mustRunVMID(t *testing.T, st *store.Store, runID string) string {
	t.Helper()
	run, err := st.GetRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetRun(%s): %v", runID, err)
	}
	return run.VMID
}

// TestP05_VMFamilyRoundTrip_LaunchAttachedBoot is the P-05 regression test for
// the critical finding in fix round 2: a launch-attached run where the VM boots
// INSIDE the run window produces a family=vm event_rollup row with count > 0.
// The reproduce_query (/api/v1/events?vm_id=X&family=vm&after=A&until=B) must
// return that same count when executed against the real httptest API server.
//
// Before the fix: vm_id= applied only a column-equality match; vm.state_changed
// events ride the host-wide stream with a NULL vm_id column (VM linkage in
// data.vm_id), so the API returned 0 while the report stored count > 0 — a
// live P-05 violation.
//
// After the fix: vm_id= always applies the two-clause match (column OR
// data.vm_id); the API returns the same count the report stored.
func TestP05_VMFamilyRoundTrip_LaunchAttachedBoot(t *testing.T) {
	st := openStore(t)
	mgr := newManagerWithStore(t, st)
	srv := newAPIServer(t, st, mgr)

	bootID := "00000000-0000-4000-8000-cccccccccccc"

	// Create the VM, stopping at provisioning so the boot lands inside the run window.
	vmID := fmt.Sprintf("00000000-0000-4000-8000-%012d", mustSeq(t))
	_, _, _, err := st.CreateVMWithOperation(t.Context(), store.CreateVMInput{
		VMID:             vmID,
		Name:             "test-vm-p05-" + vmID[:8],
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
		RequestHash:      fmt.Sprintf("hash-p05-%s", vmID),
		Admit:            func(store.ReservationTotals) error { return nil },
	})
	if err != nil {
		t.Fatalf("CreateVMWithOperation: %v", err)
	}

	// Create the run while the VM is still in "provisioning" — this is the
	// launch-attached case. CreatedEventID is anchored BEFORE any boot events.
	run, _, err := st.CreateRun(t.Context(), store.CreateRunInput{
		VMID: vmID, Owner: "test", Goal: "p05 vm-family round-trip test",
		CriteriaType: "operator_verdict", OnCompletion: "keep_running",
		RequestHash: "hash-p05-run", InitialPhase: "pending",
	})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}

	// Boot the VM — vm.state_changed events land inside the run window.
	// These events ride the host-wide stream (vm_id column NULL; data.vm_id = vmID).
	starting := "provisioning"
	if _, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vmID, From: &starting, To: "starting", Reason: "launch",
		BootID: &bootID,
	}); err != nil {
		t.Fatalf("→starting: %v", err)
	}
	if _, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vmID, To: "running", Reason: "launch_complete",
	}); err != nil {
		t.Fatalf("→running: %v", err)
	}

	// Conclude the run; the boot events are inside the window.
	mustTransitionRun(t, st, run.RunID, "pending", "concluding", "", "operator verdict")
	mustTransitionRun(t, st, run.RunID, "concluding", "succeeded", "operator", "operator verdict: succeeded")

	raw, _, err := report.Generate(t.Context(), st, run.RunID, report.Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Find the family=vm row in the event_rollup.
	var rep struct {
		EventRollup []struct {
			Family         string `json:"family"`
			Count          int64  `json:"count"`
			ReproduceQuery string `json:"reproduce_query"`
		} `json:"event_rollup"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	var vmRow *struct {
		Family         string `json:"family"`
		Count          int64  `json:"count"`
		ReproduceQuery string `json:"reproduce_query"`
	}
	for i := range rep.EventRollup {
		if rep.EventRollup[i].Family == "vm" {
			vmRow = &rep.EventRollup[i]
			break
		}
	}
	if vmRow == nil {
		t.Fatal("event_rollup has no 'vm' family row — CountEventsForReport failed to find vm.state_changed events; check data.vm_id matching")
	}
	if vmRow.Count == 0 {
		t.Fatal("event_rollup 'vm' family row has count 0 — boot events not counted; check vm_id column-or-data.vm_id matching in store")
	}
	t.Logf("report: family=vm count=%d reproduce_query=%s", vmRow.Count, vmRow.ReproduceQuery)

	// P-05: execute the reproduce_query against the real API and page through.
	reproduced := pageAndCount(t, srv.URL, vmRow.ReproduceQuery)
	if reproduced != vmRow.Count {
		t.Errorf("P-05 VIOLATION: reproduce_query %q returned %d events from API, report stored %d — family=vm vm_id matching is broken",
			vmRow.ReproduceQuery, reproduced, vmRow.Count)
	}
}

// waitForVMState polls until the VM reaches wantState.
func waitForVMState(t *testing.T, st *store.Store, vmID, wantState string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		vm, err := st.GetVM(t.Context(), vmID)
		if err != nil {
			t.Fatalf("GetVM: %v", err)
		}
		if vm.ObservedState == wantState {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	vm, _ := st.GetVM(context.Background(), vmID)
	t.Fatalf("vm %s: state never reached %q (current: %q)", vmID, wantState, vm.ObservedState)
}
