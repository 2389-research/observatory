// ABOUTME: VM lifecycle API tests: create, list, get, actions, delete, host
// ABOUTME: status, templates, and situation VM-count enrichment. TDD per SPEC §14.
package api_test

import (
	"bytes"
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

var testTemplateDef = runtime.Template{
	TemplateID:  "test-small-v1",
	Description: "small test VM",
	KernelImage: "/boot/vmlinuz",
	RootImage:   "/images/rootfs.ext4",
	Digest:      "sha256:aabbcc0011223344",
}

// newTemplateServer builds a server with one template, 8 GiB host, and a fake
// runtime. The fake is returned so callers can inject errors or block calls.
func newTemplateServer(t *testing.T) (*httptest.Server, *store.Store, *runtimetest.Fake) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "events.sqlite"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	eng := situation.New(st, situation.Config{
		Triggers: map[string]bool{
			"capacity_exhausted": true, "lifecycle_failed": true,
		},
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
	return srv, st, fake
}

// doRequest issues method to url with an optional JSON body. Checks wantStatus
// and decodes the response into into (if non-nil).
func doRequest(t *testing.T, method, url string, body any, wantStatus int, into any) []byte {
	t.Helper()
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reqBody = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(t.Context(), method, url, reqBody)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("%s %s = %d, want %d\nbody: %s", method, url, resp.StatusCode, wantStatus, raw)
	}
	if into != nil {
		if err := json.Unmarshal(raw, into); err != nil {
			t.Fatalf("decode response from %s %s: %v\nbody: %s", method, url, err, raw)
		}
	}
	return raw
}

// pollOpState polls GET /operations/{id} until state reaches want or a terminal
// state, or 3 seconds elapse. Returns the final state string.
func pollOpState(t *testing.T, srvURL, opID, want string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for {
		var op map[string]any
		resp, err := http.Get(srvURL + "/api/v1/operations/" + opID)
		if err != nil {
			t.Fatalf("poll operation: %v", err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		_ = json.Unmarshal(b, &op)
		state, _ := op["state"].(string)
		if state == want || state == "succeeded" || state == "failed" {
			return state
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for op %s to reach %q (last: %q)", opID, want, state)
			return state
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// --- host/status ---

func TestHostStatusShape(t *testing.T) {
	srv, _, _ := newTemplateServer(t)
	var got map[string]any
	getJSON(t, srv.URL+"/api/v1/host/status", http.StatusOK, &got)

	cap, _ := got["capacity"].(map[string]any)
	if cap == nil {
		t.Fatal("host/status missing capacity block")
	}
	for _, field := range []string{
		"usable_memory_mib", "reserved_memory_mib", "free_memory_mib",
		"usable_vcpu", "active_vms",
	} {
		if _, ok := cap[field]; !ok {
			t.Errorf("capacity missing field %q", field)
		}
	}

	rt, _ := got["runtime"].(map[string]any)
	if rt == nil {
		t.Fatal("host/status missing runtime block")
	}
	avail, _ := rt["available"].(bool)
	if !avail {
		t.Error("runtime.available should be true with fake runtime")
	}

	if got["storage"] == nil || got["vms"] == nil {
		t.Error("host/status missing storage or vms block")
	}
}

func TestHostStatusRuntimeUnavailable(t *testing.T) {
	srv, _, fake := newTemplateServer(t)
	// Inject an unavailable error into the Availability call used by /host/status.
	// The create-VM path also calls Availability; we inject multiple times.
	fake.FailNext("Availability", "", &runtime.UnavailableError{Reason: "kvm module not loaded"})
	fake.FailNext("Availability", "", &runtime.UnavailableError{Reason: "kvm module not loaded"})

	var got map[string]any
	getJSON(t, srv.URL+"/api/v1/host/status", http.StatusOK, &got)

	rt, _ := got["runtime"].(map[string]any)
	if avail, _ := rt["available"].(bool); avail {
		t.Error("runtime.available should be false when UnavailableError injected")
	}
	reason, _ := rt["reason"].(string)
	if !strings.Contains(reason, "kvm") {
		t.Errorf("runtime.reason = %q, want kvm mention", reason)
	}
}

// --- templates ---

func TestTemplatesEmpty(t *testing.T) {
	srv, _ := newServer(t)
	var got map[string]any
	getJSON(t, srv.URL+"/api/v1/templates", http.StatusOK, &got)

	tpls, _ := got["templates"].([]any)
	if tpls == nil {
		t.Fatal("templates response missing templates key or not an array")
	}
	if len(tpls) != 0 {
		t.Errorf("templates = %d items, want 0", len(tpls))
	}
}

func TestTemplatesSorted(t *testing.T) {
	srv, _, _ := newTemplateServer(t)
	var got map[string]any
	getJSON(t, srv.URL+"/api/v1/templates", http.StatusOK, &got)

	tpls, _ := got["templates"].([]any)
	if len(tpls) != 1 {
		t.Fatalf("templates = %d items, want 1", len(tpls))
	}
	tpl := tpls[0].(map[string]any)
	if tpl["template_id"] != testTemplateDef.TemplateID {
		t.Errorf("template_id = %v, want %q", tpl["template_id"], testTemplateDef.TemplateID)
	}
	if tpl["digest"] == nil || tpl["digest"] == "" {
		t.Error("template missing digest")
	}
	if tpl["description"] == nil {
		t.Error("template missing description")
	}
}

// --- create VM ---

func TestCreateVMUnknownTemplate(t *testing.T) {
	srv, _, _ := newTemplateServer(t)
	var e api.Error
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms",
		map[string]any{"name": "myvm", "template_id": "does-not-exist"},
		http.StatusBadRequest, &e)
	requireTeaching(t, e, "template_unknown")
	// Must point at /templates so the caller can list valid IDs (P-06).
	found := false
	for _, r := range e.Remediation {
		if p, _ := r.Params["path"].(string); strings.Contains(p, "templates") {
			found = true
		}
	}
	if !found {
		t.Error("template_unknown must point at /templates in remediation")
	}
}

func TestCreateVMUnavailableRuntime(t *testing.T) {
	srv, _, fake := newTemplateServer(t)
	fake.FailNext("Availability", "", &runtime.UnavailableError{Reason: "kvm not present"})

	var e api.Error
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms",
		map[string]any{"name": "myvm", "template_id": testTemplateDef.TemplateID},
		http.StatusNotImplemented, &e)
	requireTeaching(t, e, "missing_capability")
	if e.Cause != "runtime_unavailable" {
		t.Errorf("cause = %q, want runtime_unavailable", e.Cause)
	}
}

func TestCreateVMShape(t *testing.T) {
	srv, _, _ := newTemplateServer(t)
	var got map[string]any
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms",
		map[string]any{"name": "shape-test", "template_id": testTemplateDef.TemplateID},
		http.StatusCreated, &got)

	vm, _ := got["vm"].(map[string]any)
	if vm == nil {
		t.Fatal("create response missing vm")
	}
	if vm["vm_id"] == "" || vm["vm_id"] == nil {
		t.Error("vm.vm_id missing")
	}
	if vm["name"] != "shape-test" {
		t.Errorf("vm.name = %v", vm["name"])
	}
	rev, _ := vm["revision"].(string)
	if rev == "" {
		t.Error("vm.revision must be a decimal string")
	}
	// Decimal string: must parse as an integer.
	if !isDecimalString(rev) {
		t.Errorf("vm.revision = %q is not a decimal string", rev)
	}
	links, _ := vm["links"].(map[string]any)
	if links["events"] == nil {
		t.Error("vm.links.events missing")
	}

	op, _ := got["operation"].(map[string]any)
	if op == nil {
		t.Fatal("create response missing operation")
	}
	opID, _ := op["operation_id"].(string)
	if !strings.HasPrefix(opID, "op-") {
		t.Errorf("operation.operation_id = %q, want op- prefix", opID)
	}
	if op["kind"] != "vm.create" {
		t.Errorf("operation.kind = %v, want vm.create", op["kind"])
	}

	// GET /operations/{id} must return the same operation.
	state := pollOpState(t, srv.URL, opID, "succeeded")
	if state != "succeeded" {
		t.Errorf("operation reached %q, want succeeded", state)
	}

	// After launch completes, GET /vms/{id} reflects the terminal state.
	vmID, _ := vm["vm_id"].(string)
	var vmGot map[string]any
	getJSON(t, srv.URL+"/api/v1/vms/"+vmID, http.StatusOK, &vmGot)
	if vmGot["observed_state"] != "running" {
		t.Errorf("observed_state = %v, want running", vmGot["observed_state"])
	}
}

func TestCreateVMIdempotentReplay(t *testing.T) {
	// AT-006: identical idempotency_key returns original vm_id and op_id.
	srv, _, _ := newTemplateServer(t)
	ikey := "idem-key-1"
	body := map[string]any{
		"name":            "idem-test",
		"template_id":     testTemplateDef.TemplateID,
		"idempotency_key": ikey,
	}

	var first, second map[string]any
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms", body, http.StatusCreated, &first)
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms", body, http.StatusCreated, &second)

	firstVM := first["vm"].(map[string]any)
	secondVM := second["vm"].(map[string]any)
	if firstVM["vm_id"] != secondVM["vm_id"] {
		t.Errorf("idempotent replay returned different vm_id: %v vs %v", firstVM["vm_id"], secondVM["vm_id"])
	}
	firstOp := first["operation"].(map[string]any)
	secondOp := second["operation"].(map[string]any)
	if firstOp["operation_id"] != secondOp["operation_id"] {
		t.Errorf("idempotent replay returned different operation_id: %v vs %v",
			firstOp["operation_id"], secondOp["operation_id"])
	}
}

func TestCreateVMAdmissionRefusal(t *testing.T) {
	// Tiny host: one 512 MiB VM fills all memory.
	st, err := store.Open(filepath.Join(t.TempDir(), "events.sqlite"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	eng := situation.New(st, situation.Config{
		QueueMaxItems: 10, SituationMaxResponseBytes: 65536,
	})
	fake := runtimetest.NewFake()
	mgr, err := runtime.NewManager(st, fake, runtime.ManagerConfig{
		Admission: config.Admission{
			CPUOvercommitRatio:    4.0,
			MaxParallelProvisions: 1,
		},
		VMDefaults: config.VMDefaults{MemoryMiB: 512, VCPUCount: 1, RootDiskMiB: 1024, WorkspaceDiskMiB: 1024},
		Owner:      "local_operator",
		Templates:  map[string]runtime.Template{testTemplateDef.TemplateID: testTemplateDef},
		Host:       runtime.HostResources{TotalMemoryMiB: 512, CPUCores: 4, StateDiskFreeMiB: 100 * 1024},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })
	srv := httptest.NewServer(api.New(st, eng, mgr))
	t.Cleanup(srv.Close)

	body := map[string]any{"name": "fill-vm", "template_id": testTemplateDef.TemplateID}

	// First create succeeds.
	var got map[string]any
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms", body, http.StatusCreated, &got)

	// Second create is refused: memory exhausted.
	ikey := "refused-key-1"
	body2 := map[string]any{
		"name": "overflow-vm", "template_id": testTemplateDef.TemplateID,
		"idempotency_key": ikey,
	}
	var e api.Error
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms", body2, http.StatusConflict, &e)
	requireTeaching(t, e, "insufficient_capacity")

	// AT-006: replay of the refused create returns the same 409.
	var e2 api.Error
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms", body2, http.StatusConflict, &e2)
	requireTeaching(t, e2, "insufficient_capacity")
}

// --- list / get ---

func TestListVMs(t *testing.T) {
	srv, _, _ := newTemplateServer(t)

	// Empty store.
	var empty map[string]any
	getJSON(t, srv.URL+"/api/v1/vms", http.StatusOK, &empty)
	vmsArr, _ := empty["vms"].([]any)
	if vmsArr == nil {
		t.Fatal("GET /vms: vms key missing or not an array")
	}
	if len(vmsArr) != 0 {
		t.Errorf("empty store: %d VMs, want 0", len(vmsArr))
	}

	// Create one VM.
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms",
		map[string]any{"name": "list-vm", "template_id": testTemplateDef.TemplateID},
		http.StatusCreated, nil)

	var after map[string]any
	getJSON(t, srv.URL+"/api/v1/vms", http.StatusOK, &after)
	vmsArr, _ = after["vms"].([]any)
	if len(vmsArr) != 1 {
		t.Errorf("after create: %d VMs, want 1", len(vmsArr))
	}
	nextAfter, _ := after["next_after"].(string)
	if nextAfter == "" {
		t.Error("next_after must be set when VMs exist")
	}
}

func TestGetVMNotFound(t *testing.T) {
	srv, _, _ := newTemplateServer(t)
	var e api.Error
	getJSON(t, srv.URL+"/api/v1/vms/00000000-dead-beef-0000-000000000001",
		http.StatusNotFound, &e)
	requireTeaching(t, e, "not_found")
}

// --- actions ---

func TestVMActionRequiresRevision(t *testing.T) {
	srv, _, _ := newTemplateServer(t)
	var created map[string]any
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms",
		map[string]any{"name": "action-vm", "template_id": testTemplateDef.TemplateID},
		http.StatusCreated, &created)
	vmID, _ := created["vm"].(map[string]any)["vm_id"].(string)

	// Action without expected_revision → 400.
	var e api.Error
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms/"+vmID+"/actions",
		map[string]any{"action": "pause"},
		http.StatusBadRequest, &e)
	requireTeaching(t, e, "malformed_request")
}

func TestVMActionUnknownAction(t *testing.T) {
	srv, _, _ := newTemplateServer(t)
	var created map[string]any
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms",
		map[string]any{"name": "action-vm2", "template_id": testTemplateDef.TemplateID},
		http.StatusCreated, &created)
	vm := created["vm"].(map[string]any)
	vmID, _ := vm["vm_id"].(string)

	var e api.Error
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms/"+vmID+"/actions",
		map[string]any{"action": "explode", "expected_revision": vm["revision"]},
		http.StatusBadRequest, &e)
	requireTeaching(t, e, "malformed_request")
}

// --- delete ---

func TestDeleteVMNotFound(t *testing.T) {
	srv, _, _ := newTemplateServer(t)
	var e api.Error
	doRequest(t, http.MethodDelete,
		srv.URL+"/api/v1/vms/00000000-dead-0000-0000-000000000001?force=true",
		nil, http.StatusNotFound, &e)
	requireTeaching(t, e, "not_found")
}

// --- operations ---

func TestGetOperationMalformedID(t *testing.T) {
	srv, _, _ := newTemplateServer(t)
	var e api.Error
	getJSON(t, srv.URL+"/api/v1/operations/not-an-op-id", http.StatusBadRequest, &e)
	requireTeaching(t, e, "malformed_request")
}

func TestGetOperationNotFound(t *testing.T) {
	srv, _, _ := newTemplateServer(t)
	var e api.Error
	getJSON(t, srv.URL+"/api/v1/operations/op-999999", http.StatusNotFound, &e)
	requireTeaching(t, e, "not_found")
}

// --- situation enrichment ---

func TestSituationVMCounts(t *testing.T) {
	srv, _, _ := newTemplateServer(t)

	// Before any VMs: counts should be zero.
	var before map[string]any
	getJSON(t, srv.URL+"/api/v1/situation", http.StatusOK, &before)
	host := before["host"].(map[string]any)
	if host["vms_total"] != float64(0) {
		t.Errorf("vms_total before create = %v, want 0", host["vms_total"])
	}

	// Create a VM and let it reach running.
	var created map[string]any
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms",
		map[string]any{"name": "sit-vm", "template_id": testTemplateDef.TemplateID},
		http.StatusCreated, &created)
	opID := created["operation"].(map[string]any)["operation_id"].(string)
	pollOpState(t, srv.URL, opID, "succeeded")

	// After: vms_total=1, capacity_free_mib < 8192 (some reserved).
	var after map[string]any
	getJSON(t, srv.URL+"/api/v1/situation", http.StatusOK, &after)
	host = after["host"].(map[string]any)
	if host["vms_total"] != float64(1) {
		t.Errorf("vms_total after create = %v, want 1", host["vms_total"])
	}
	freeMiB, _ := host["capacity_free_mib"].(float64)
	if freeMiB >= 8192 {
		t.Errorf("capacity_free_mib = %v, want < 8192 (should reflect reservation)", freeMiB)
	}
}

func TestSituationChangedVMs(t *testing.T) {
	srv, _, _ := newTemplateServer(t)

	// Create a VM and wait for it to reach running.
	var created map[string]any
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms",
		map[string]any{"name": "delta-vm", "template_id": testTemplateDef.TemplateID},
		http.StatusCreated, &created)
	opID := created["operation"].(map[string]any)["operation_id"].(string)
	pollOpState(t, srv.URL, opID, "succeeded")

	// GET /situation?since=0 — must include changed_vms.
	var got map[string]any
	getJSON(t, srv.URL+"/api/v1/situation?since=0", http.StatusOK, &got)
	changed, _ := got["changed_vms"].([]any)
	if len(changed) == 0 {
		t.Fatal("changed_vms should be non-empty after create")
	}
	entry := changed[0].(map[string]any)
	if entry["vm_id"] == nil || entry["lifecycle_state"] == nil {
		t.Errorf("changed_vm entry missing required fields: %v", entry)
	}
	links, _ := entry["links"].(map[string]any)
	if links["vm"] == nil {
		t.Error("changed_vm.links.vm missing")
	}
	// telemetry_health must be a known value (not omitted).
	if entry["telemetry_health"] == nil {
		t.Error("changed_vm.telemetry_health must be present (P-03 monitored calm)")
	}
}

// --- helpers ---

// isDecimalString returns true if s is a non-empty sequence of ASCII digits.
func isDecimalString(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
