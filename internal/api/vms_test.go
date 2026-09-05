// ABOUTME: VM lifecycle API tests: create, list, get, actions, delete, host
// ABOUTME: status, templates, and situation VM-count enrichment. TDD per SPEC §14.
package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	sysruntime "runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/api"
	"github.com/2389-research/observatory-v2/internal/config"
	"github.com/2389-research/observatory-v2/internal/preflight"
	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/runtime/runtimetest"
	"github.com/2389-research/observatory-v2/internal/situation"
	"github.com/2389-research/observatory-v2/internal/store"
	"github.com/2389-research/observatory-v2/internal/terminal"
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

// testAdmission is the admission config the shared harness admits on. The
// per-VM overhead is deliberately non-zero: with zero, an assertion that
// reservations charge the published overhead would pass while proving nothing.
func testAdmission() config.Admission {
	return config.Admission{
		AllowMemoryOvercommit:       false,
		CPUOvercommitRatio:          4.0,
		ReservePerVMHostOverheadMiB: 256,
		MaxParallelProvisions:       2,
		MaxBatchSize:                8,
	}
}

// testVMDefaults gives the harness non-empty guest_privilege and
// network_profile: the launch form renders those two as disabled controls at
// their effective value, and empty strings would let a handler that published
// nothing pass.
func testVMDefaults() config.VMDefaults {
	return config.VMDefaults{
		MemoryMiB:           512,
		VCPUCount:           1,
		RootDiskMiB:         4096,
		WorkspaceDiskMiB:    8192,
		GuestPrivilege:      "unprivileged",
		NetworkProfile:      "transport",
		MaxTerminalSessions: 2,
		StopGraceSeconds:    30,
	}
}

func newTemplateServer(t *testing.T) (*httptest.Server, *store.Store, *runtimetest.Fake) {
	t.Helper()
	return newTemplateServerWrapped(t, nil)
}

// newTemplateServerAdmission is newTemplateServer on a host with different
// admission settings, for tests about what those settings change.
func newTemplateServerAdmission(t *testing.T, adm config.Admission) (*httptest.Server, *store.Store, *runtimetest.Fake) {
	t.Helper()
	return newTemplateServerFull(t, nil, adm, nil)
}

// newTemplateServerWrapped is newTemplateServer with a middleware hook. wrap is
// applied to the API handler before it is served; nil means serve it unwrapped.
// Tests that need to observe the request context itself (client disconnect) use
// the hook instead of guessing at timing.
func newTemplateServerWrapped(t *testing.T, wrap func(http.Handler) http.Handler) (*httptest.Server, *store.Store, *runtimetest.Fake) {
	t.Helper()
	return newTemplateServerFull(t, wrap, testAdmission(), nil)
}

func newTemplateServerFull(
	t *testing.T,
	wrap func(http.Handler) http.Handler,
	adm config.Admission,
	tr *terminal.Registry,
) (*httptest.Server, *store.Store, *runtimetest.Fake) {
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
		Admission:  adm,
		VMDefaults: testVMDefaults(),
		Templates:  map[string]runtime.Template{testTemplateDef.TemplateID: testTemplateDef},
		Host:       runtime.HostResources{TotalMemoryMiB: 8192, CPUCores: 8, StateDiskFreeMiB: 100 * 1024},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })
	// Unstarted first: the listener is already bound, so the server can be told
	// its own public origin. A WebSocket upgrade is refused unless Origin
	// matches it exactly, and a harness with no origin could not test that.
	srv := httptest.NewUnstartedServer(nil)
	t.Cleanup(srv.Close)
	h := api.New(st, eng, mgr, api.AuthConfig{
		Enabled:      false,
		PublicOrigin: "http://" + srv.Listener.Addr().String(),
	}, nil, tr)
	if wrap != nil {
		h = wrap(h)
	}
	srv.Config.Handler = h
	srv.Start()
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

// --- host/status preflight block ---

// newPreflightServer builds a server with the preflight hook wired.
func newPreflightServer(t *testing.T, pfRunner *preflight.Runner) (*httptest.Server, *store.Store, *runtimetest.Fake) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "events.sqlite"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	eng := situation.New(st, situation.Config{
		Triggers:                  map[string]bool{},
		QueueMaxItems:             500,
		CollapseDuplicates:        true,
		SituationMaxResponseBytes: 65536,
	})
	fake := runtimetest.NewFake()
	mgr, err := runtime.NewManager(st, fake, runtime.ManagerConfig{
		Admission:  config.Admission{CPUOvercommitRatio: 4.0, MaxParallelProvisions: 2},
		VMDefaults: config.VMDefaults{MemoryMiB: 512, VCPUCount: 1, RootDiskMiB: 4096, WorkspaceDiskMiB: 8192},
		Templates:  map[string]runtime.Template{},
		Host:       runtime.HostResources{TotalMemoryMiB: 8192, CPUCores: 8, StateDiskFreeMiB: 100 * 1024},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })

	pf := api.PreflightFunc(func(_ context.Context, _ bool) preflight.Report {
		return pfRunner.Run(t.Context())
	})
	srv := httptest.NewServer(api.New(st, eng, mgr, api.AuthConfig{Enabled: false}, pf, nil))
	t.Cleanup(srv.Close)
	return srv, st, fake
}

// TestHostStatusPreflightAbsent: when preflight hook is nil, /host/status omits
// the "preflight" key — never an empty fake block.
func TestHostStatusPreflightAbsent(t *testing.T) {
	srv, _, _ := newTemplateServer(t) // newTemplateServer passes nil for preflight
	var got map[string]any
	getJSON(t, srv.URL+"/api/v1/host/status", http.StatusOK, &got)

	if _, ok := got["preflight"]; ok {
		t.Error("preflight key present in /host/status when hook is nil — must be absent")
	}
}

// TestHostStatusPreflightBlock: when preflight hook is wired, /host/status
// includes a "preflight" block with the required fields.
func TestHostStatusPreflightBlock(t *testing.T) {
	pfRunner := preflight.New(preflight.Config{
		DataDir:     t.TempDir(),
		APIMode:     "loopback_only",
		RequireAuth: false,
	})
	srv, _, _ := newPreflightServer(t, pfRunner)

	var got map[string]any
	getJSON(t, srv.URL+"/api/v1/host/status", http.StatusOK, &got)

	pf, ok := got["preflight"].(map[string]any)
	if !ok {
		t.Fatal("host/status preflight block absent or not an object")
	}
	for _, field := range []string{"ran_at", "overall", "arch", "kernel_release", "checks"} {
		if _, ok := pf[field]; !ok {
			t.Errorf("preflight block missing field %q", field)
		}
	}

	checks, _ := pf["checks"].([]any)
	if len(checks) == 0 {
		t.Error("preflight block checks array is empty")
	}
}

// TestHostStatusPreflightRefresh: ?refresh=1 re-runs the checks (smoke test —
// verifies the param is forwarded; not a timing test).
func TestHostStatusPreflightRefresh(t *testing.T) {
	pfRunner := preflight.New(preflight.Config{
		DataDir:     t.TempDir(),
		APIMode:     "loopback_only",
		RequireAuth: false,
	})
	srv, _, _ := newPreflightServer(t, pfRunner)

	var got map[string]any
	getJSON(t, srv.URL+"/api/v1/host/status?refresh=1", http.StatusOK, &got)

	if _, ok := got["preflight"]; !ok {
		t.Error("host/status?refresh=1 missing preflight block")
	}
}

// TestHostStatusPreflightGuestChannelPresent: guest_channel is always present.
// On non-Linux it is not_implemented; on Linux with no PrivdSocket configured it fails.
// Either is an honest result — the check must never be absent.
func TestHostStatusPreflightGuestChannelPresent(t *testing.T) {
	pfRunner := preflight.New(preflight.Config{
		DataDir:     t.TempDir(),
		APIMode:     "loopback_only",
		RequireAuth: false,
	})
	srv, _, _ := newPreflightServer(t, pfRunner)

	var got map[string]any
	getJSON(t, srv.URL+"/api/v1/host/status", http.StatusOK, &got)

	pf, _ := got["preflight"].(map[string]any)
	checks, _ := pf["checks"].([]any)

	var guestChannel map[string]any
	for _, raw := range checks {
		ch, _ := raw.(map[string]any)
		if id, _ := ch["id"].(string); id == "guest_channel" {
			guestChannel = ch
			break
		}
	}
	if guestChannel == nil {
		t.Fatal("guest_channel check absent from preflight block")
	}
	st, _ := guestChannel["status"].(string)
	if sysruntime.GOOS == "linux" {
		// Linux with no PrivdSocket configured → fail.
		if st != "fail" {
			t.Errorf("guest_channel status = %q on linux with no PrivdSocket, want fail", st)
		}
	} else {
		// Non-Linux: not_implemented.
		if st != "not_implemented" {
			t.Errorf("guest_channel status = %q on non-linux, want not_implemented", st)
		}
	}
	t.Logf("guest_channel status on this platform: %s", st)
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

	// AT-001: the refusal precedes persistence — no VM row, no operation row.
	var list map[string]any
	getJSON(t, srv.URL+"/api/v1/vms", http.StatusOK, &list)
	if vms, _ := list["vms"].([]any); len(vms) != 0 {
		t.Errorf("VM persisted after refused create: %v", vms)
	}
	doRequest(t, http.MethodGet, srv.URL+"/api/v1/operations/op-000001", nil, http.StatusNotFound, nil)
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
	// The replay is marked honestly; the original is not.
	if _, present := first["is_replay"]; present {
		t.Errorf("first response carries is_replay = %v, want absent", first["is_replay"])
	}
	if second["is_replay"] != true {
		t.Errorf("second response is_replay = %v, want true", second["is_replay"])
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
		Templates:  map[string]runtime.Template{testTemplateDef.TemplateID: testTemplateDef},
		Host:       runtime.HostResources{TotalMemoryMiB: 512, CPUCores: 4, StateDiskFreeMiB: 100 * 1024},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })
	srv := httptest.NewServer(api.New(st, eng, mgr, api.AuthConfig{Enabled: false}, nil, nil))
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

	// A refused create still records an operation carrying the refusal, so the
	// refusal names it. The replay must name the SAME one: an idempotent retry
	// answers from one record, and pointing at a second would invent a history
	// the store does not have.
	if e.OperationID == "" {
		t.Fatal("the refusal records an operation but names none")
	}
	if e2.OperationID != e.OperationID {
		t.Errorf("replay named %q, original named %q; both answer from one record",
			e2.OperationID, e.OperationID)
	}
	var op map[string]any
	getJSON(t, srv.URL+"/api/v1/operations/"+e.OperationID, http.StatusOK, &op)
	opErr, _ := op["error"].(map[string]any)
	if cause, _ := opErr["cause"].(string); cause != "insufficient_capacity" {
		t.Errorf("operation error.cause = %q, want insufficient_capacity", cause)
	}
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

// TestVMActionStopWithRevisionSucceeds: the wire shape every stop takes —
// GET for the revision, then POST the stop action pinned to it. The pin is
// spent on the running→stopping transition; re-spending it on the stopped
// transition answered 409 revision_mismatch for a VM that had really stopped.
func TestVMActionStopWithRevisionSucceeds(t *testing.T) {
	srv, _, fake := newTemplateServer(t)
	vmID := createRunningVM(t, srv.URL, fake)

	var vm map[string]any
	getJSON(t, srv.URL+"/api/v1/vms/"+vmID, http.StatusOK, &vm)

	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms/"+vmID+"/actions",
		map[string]any{"action": "stop", "expected_revision": vm["revision"]},
		http.StatusOK, nil)

	var after map[string]any
	getJSON(t, srv.URL+"/api/v1/vms/"+vmID, http.StatusOK, &after)
	if state, _ := after["observed_state"].(string); state != "stopped" {
		t.Errorf("observed_state after stop = %q, want stopped", state)
	}
}

// TestVMActionWrongStateTeaches: starting an already-running VM is the
// caller's mistake, and the answer must say so — 409 invalid_transition naming
// the state pair, not a 500 blaming storage.
func TestVMActionWrongStateTeaches(t *testing.T) {
	srv, _, fake := newTemplateServer(t)
	vmID := createRunningVM(t, srv.URL, fake)

	var vm map[string]any
	getJSON(t, srv.URL+"/api/v1/vms/"+vmID, http.StatusOK, &vm)

	var e api.Error
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms/"+vmID+"/actions",
		map[string]any{"action": "start", "expected_revision": vm["revision"]},
		http.StatusConflict, &e)
	requireTeaching(t, e, "invalid_transition")
	if from, _ := e.Details["from"].(string); from != "running" {
		t.Errorf("details.from = %v, want running (details: %v)", e.Details["from"], e.Details)
	}
	if to, _ := e.Details["to"].(string); to != "starting" {
		t.Errorf("details.to = %v, want starting (details: %v)", e.Details["to"], e.Details)
	}
}

// --- delete ---

// TestDeleteVMForceWithRevisionSucceeds: a force delete carrying the VM's
// current revision must succeed. The pin rides the first transition the delete
// makes (running→stopping); attaching it to the later →deleting transition,
// after two transitions already bumped the revision, answers 409 every time.
func TestDeleteVMForceWithRevisionSucceeds(t *testing.T) {
	srv, _, fake := newTemplateServer(t)
	vmID := createRunningVM(t, srv.URL, fake)

	var vm map[string]any
	getJSON(t, srv.URL+"/api/v1/vms/"+vmID, http.StatusOK, &vm)
	rev, _ := vm["revision"].(string)

	var resp map[string]any
	doRequest(t, http.MethodDelete,
		srv.URL+"/api/v1/vms/"+vmID+"?force=true&expected_revision="+rev,
		nil, http.StatusOK, &resp)

	deleted, _ := resp["vm"].(map[string]any)
	if state, _ := deleted["observed_state"].(string); state != "deleted" {
		t.Errorf("observed_state after force delete = %q, want deleted", state)
	}
}

// TestDeleteVMForceStalePinRefused: the pin stays a precondition, and a
// precondition is checked before the VM is killed. A revision that has moved on
// is refused with 409 revision_mismatch — the typed store error survives the
// manager's wrapping and reaches writeVMError intact — with the runtime never
// asked to force-stop and the VM still running.
func TestDeleteVMForceStalePinRefused(t *testing.T) {
	srv, _, fake := newTemplateServer(t)
	vmID := createRunningVM(t, srv.URL, fake)

	var vm map[string]any
	getJSON(t, srv.URL+"/api/v1/vms/"+vmID, http.StatusOK, &vm)
	rev, err := strconv.ParseInt(vm["revision"].(string), 10, 64)
	if err != nil {
		t.Fatalf("parse revision %v: %v", vm["revision"], err)
	}

	var e api.Error
	doRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/api/v1/vms/%s?force=true&expected_revision=%d", srv.URL, vmID, rev-1),
		nil, http.StatusConflict, &e)
	requireTeaching(t, e, "revision_mismatch")

	for _, c := range fake.CallsFor(vmID) {
		if c.Method == "ForceStop" {
			t.Errorf("runtime was asked to ForceStop despite the refused pin; calls: %v", fake.CallsFor(vmID))
			break
		}
	}
	var after map[string]any
	getJSON(t, srv.URL+"/api/v1/vms/"+vmID, http.StatusOK, &after)
	if state, _ := after["observed_state"].(string); state != "running" {
		t.Errorf("observed_state after refused delete = %q, want running", state)
	}
}

// TestDeleteVMReleaseFailureTeaches: when the runtime cannot release a VM's
// resources, something is still on the host — a live VMM, a jail chroot, a
// ledger entry — and the row stays at "deleting" to say so. The answer has to
// name that, not fall through to the catch-all 500 that blames storage and
// sends the operator to the database. Seen for real on aibox03.
func TestDeleteVMReleaseFailureTeaches(t *testing.T) {
	srv, _, fake := newTemplateServer(t)
	vmID := createRunningVM(t, srv.URL, fake)
	fake.FailNext("Release", vmID, errors.New("privd: invalid_state"))

	var e api.Error
	doRequest(t, http.MethodDelete, srv.URL+"/api/v1/vms/"+vmID+"?force=true",
		nil, http.StatusInternalServerError, &e)
	requireTeaching(t, e, "internal")
	if e.Cause != "resource_release_failed" {
		t.Errorf("cause = %q, want resource_release_failed", e.Cause)
	}
	if !e.Retryable {
		t.Error("a release failure is retryable once its cause is cleared")
	}
	if len(e.Remediation) == 0 {
		t.Error("a release failure must tell the operator what to do next")
	}
	if !strings.Contains(e.Message, "invalid_state") {
		t.Errorf("message %q should carry the runtime's own words", e.Message)
	}

	var after map[string]any
	getJSON(t, srv.URL+"/api/v1/vms/"+vmID, http.StatusOK, &after)
	if state, _ := after["observed_state"].(string); state != "deleting" {
		t.Errorf("observed_state = %q, want deleting — the row is the record that resources survive", state)
	}
}

// TestDeleteVMReleaseFailureRetryActuallyRetries walks the remediation the
// previous test only reads. `retryable: true` and a "delete again" remediation
// were both being answered by an early return for the "deleting" state: every
// retry replied 200 with the row untouched and the host resources still there,
// and only a daemon restart moved it. The contract is only honest if the retry
// the error names does the work.
func TestDeleteVMReleaseFailureRetryActuallyRetries(t *testing.T) {
	srv, _, fake := newTemplateServer(t)
	vmID := createRunningVM(t, srv.URL, fake)
	fake.FailNext("Release", vmID, errors.New("privd: invalid_state"))

	var e api.Error
	doRequest(t, http.MethodDelete, srv.URL+"/api/v1/vms/"+vmID+"?force=true",
		nil, http.StatusInternalServerError, &e)
	if !e.Retryable {
		t.Fatal("a release failure claims to be retryable")
	}
	retry := ""
	for _, rem := range e.Remediation {
		if rem.Action == "delete" {
			path, _ := rem.Params["path"].(string)
			retry = strings.Replace(path, "{id}", vmID, 1)
		}
	}
	if retry == "" {
		t.Fatal("the release failure names no delete to retry")
	}

	var body map[string]any
	doRequest(t, http.MethodDelete, srv.URL+retry, nil, http.StatusOK, &body)
	vm, _ := body["vm"].(map[string]any)
	if state, _ := vm["observed_state"].(string); state != "deleted" {
		t.Errorf("observed_state after the retry the error asked for = %q, want deleted", state)
	}
}

// TestActionRuntimeFailureTeaches: a guest that will not stop is a fault on the
// machine, and the answer has to say so. The catch-all used to call it a
// storage failure — with the store perfectly healthy and the VMM still alive —
// which is the same lie a failed release told before it was named. The
// operation row keeps the runtime's own words for whoever reads it later.
func TestActionRuntimeFailureTeaches(t *testing.T) {
	srv, _, fake := newTemplateServer(t)
	vmID := createRunningVM(t, srv.URL, fake)
	fake.FailNext("Stop", vmID, errors.New("guest ignored the shutdown request"))

	var vm map[string]any
	getJSON(t, srv.URL+"/api/v1/vms/"+vmID, http.StatusOK, &vm)

	var e api.Error
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms/"+vmID+"/actions",
		map[string]any{"action": "stop", "expected_revision": vm["revision"]},
		http.StatusInternalServerError, &e)
	requireTeaching(t, e, "internal")
	if e.Cause != "runtime_operation_failed" {
		t.Errorf("cause = %q, want runtime_operation_failed", e.Cause)
	}
	if got, _ := e.Details["runtime_operation"].(string); got != "stop" {
		t.Errorf("details.runtime_operation = %q, want stop", got)
	}
	if !strings.Contains(e.Message, "ignored the shutdown") {
		t.Errorf("message %q should carry the runtime's own words", e.Message)
	}
	if !e.Retryable {
		t.Error("the VM is still there to stop; asking again is the recovery")
	}

	// The remediation says to read the operation. An operator can only do that
	// if the error names which one, so the name is part of the answer — and it
	// has to resolve to the durable record of this failure, not just be present.
	if e.OperationID == "" {
		t.Fatal("the error tells the operator to read the operation but names none")
	}
	var op map[string]any
	getJSON(t, srv.URL+"/api/v1/operations/"+e.OperationID, http.StatusOK, &op)
	if op["state"] != "failed" {
		t.Errorf("operation %s state = %v, want failed", e.OperationID, op["state"])
	}
	if op["vm_id"] != vmID {
		t.Errorf("operation %s vm_id = %v, want %s", e.OperationID, op["vm_id"], vmID)
	}
	opErr, _ := op["error"].(map[string]any)
	if msg, _ := opErr["message"].(string); !strings.Contains(msg, "ignored the shutdown") {
		t.Errorf("operation error.message = %q, want the runtime's own words", msg)
	}
}

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

func TestSituationChangedVMsAttentionOpen(t *testing.T) {
	srv, st, _ := newTemplateServer(t)

	var created map[string]any
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms",
		map[string]any{"name": "doomed-vm", "template_id": testTemplateDef.TemplateID},
		http.StatusCreated, &created)
	opID := created["operation"].(map[string]any)["operation_id"].(string)
	pollOpState(t, srv.URL, opID, "succeeded")
	vmID := created["vm"].(map[string]any)["vm_id"].(string)

	// The same transition the manager records when a VMM dies; lifecycle_failed
	// is enabled in this server's trigger config, so an attention item raises.
	stage := "runtime"
	if _, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID:           vmID,
		To:             "failed",
		Reason:         "vmm_exited",
		ReleaseCompute: true,
		FailureStage:   &stage,
		FailureReason:  &stage,
	}); err != nil {
		t.Fatalf("TransitionVM to failed: %v", err)
	}

	// Queue truth first: how many open items reference this VM.
	var attn map[string]any
	getJSON(t, srv.URL+"/api/v1/attention", http.StatusOK, &attn)
	open := 0
	items, _ := attn["items"].([]any)
	for _, it := range items {
		m := it.(map[string]any)
		if v, _ := m["vm_id"].(string); v == vmID && m["acked"] == false {
			open++
		}
	}
	if open == 0 {
		t.Fatal("precondition failed: no open attention item for the failed VM")
	}

	var got map[string]any
	getJSON(t, srv.URL+"/api/v1/situation?since=0", http.StatusOK, &got)
	var entry map[string]any
	changed, _ := got["changed_vms"].([]any)
	for _, c := range changed {
		e := c.(map[string]any)
		if e["vm_id"] == vmID {
			entry = e
		}
	}
	if entry == nil {
		t.Fatalf("changed_vms has no entry for %s: %v", vmID, changed)
	}
	// attention_open must report the queue's count, not an invented zero.
	if entry["attention_open"] != float64(open) {
		t.Errorf("attention_open = %v, want %d (open items in the queue)", entry["attention_open"], open)
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

// TestHostStatusPublishesAdmissionParams pins D8's server half: the launch
// form's reservation preview may restate only numbers the API published, so
// the API has to publish them. Every value here is read from the manager's
// live config, not from a copy the handler keeps.
func TestHostStatusPublishesAdmissionParams(t *testing.T) {
	srv, _, _ := newTemplateServer(t)
	defer srv.Close()

	var body struct {
		Admission struct {
			ReservePerVMHostOverheadMiB int64   `json:"reserve_per_vm_host_overhead_mib"`
			CPUOvercommitRatio          float64 `json:"cpu_overcommit_ratio"`
			AllowMemoryOvercommit       bool    `json:"allow_memory_overcommit"`
			MaxBatchSize                int     `json:"max_batch_size"`
			MaxParallelProvisions       int     `json:"max_parallel_provisions"`
		} `json:"admission"`
	}
	getJSON(t, srv.URL+"/api/v1/host/status", http.StatusOK, &body)

	want := testAdmission()
	if body.Admission.ReservePerVMHostOverheadMiB != want.ReservePerVMHostOverheadMiB {
		t.Errorf("reserve_per_vm_host_overhead_mib = %d; want %d",
			body.Admission.ReservePerVMHostOverheadMiB, want.ReservePerVMHostOverheadMiB)
	}
	if body.Admission.CPUOvercommitRatio != want.CPUOvercommitRatio {
		t.Errorf("cpu_overcommit_ratio = %v; want %v", body.Admission.CPUOvercommitRatio, want.CPUOvercommitRatio)
	}
	if body.Admission.AllowMemoryOvercommit != want.AllowMemoryOvercommit {
		t.Errorf("allow_memory_overcommit = %v; want %v",
			body.Admission.AllowMemoryOvercommit, want.AllowMemoryOvercommit)
	}
	if body.Admission.MaxBatchSize != want.MaxBatchSize {
		t.Errorf("max_batch_size = %d; want %d", body.Admission.MaxBatchSize, want.MaxBatchSize)
	}
	if body.Admission.MaxParallelProvisions != want.MaxParallelProvisions {
		t.Errorf("max_parallel_provisions = %d; want %d",
			body.Admission.MaxParallelProvisions, want.MaxParallelProvisions)
	}
}

// TestHostStatusPublishesVMDefaults pins the other half of what the launch
// form needs: the resource values a create request gets when it omits them,
// and the two fields the form can only display. Without these the browser
// would prefill numbers of its own invention.
func TestHostStatusPublishesVMDefaults(t *testing.T) {
	srv, _, _ := newTemplateServer(t)
	defer srv.Close()

	var body struct {
		VMDefaults struct {
			VCPUCount        int    `json:"vcpu_count"`
			MemoryMiB        int64  `json:"memory_mib"`
			RootDiskMiB      int64  `json:"root_disk_mib"`
			WorkspaceDiskMiB int64  `json:"workspace_disk_mib"`
			GuestPrivilege   string `json:"guest_privilege"`
			NetworkProfile   string `json:"network_profile"`
			StopGraceSeconds int    `json:"stop_grace_seconds"`
		} `json:"vm_defaults"`
	}
	getJSON(t, srv.URL+"/api/v1/host/status", http.StatusOK, &body)

	want := testVMDefaults()
	got := body.VMDefaults
	if got.VCPUCount != want.VCPUCount || got.MemoryMiB != want.MemoryMiB ||
		got.RootDiskMiB != want.RootDiskMiB || got.WorkspaceDiskMiB != want.WorkspaceDiskMiB {
		t.Errorf("resources = %+v; want vcpu=%d mem=%d root=%d ws=%d", got,
			want.VCPUCount, want.MemoryMiB, want.RootDiskMiB, want.WorkspaceDiskMiB)
	}
	if got.GuestPrivilege != want.GuestPrivilege {
		t.Errorf("guest_privilege = %q; want %q", got.GuestPrivilege, want.GuestPrivilege)
	}
	if got.NetworkProfile != want.NetworkProfile {
		t.Errorf("network_profile = %q; want %q", got.NetworkProfile, want.NetworkProfile)
	}
	if got.StopGraceSeconds != want.StopGraceSeconds {
		t.Errorf("stop_grace_seconds = %d; want %d", got.StopGraceSeconds, want.StopGraceSeconds)
	}
}

// TestHostStatusDefaultsAreTheDefaultsApplied is the honesty assertion for the
// defaults block: a VM created with every resource omitted comes back holding
// exactly the numbers /host/status published.
func TestHostStatusDefaultsAreTheDefaultsApplied(t *testing.T) {
	srv, _, _ := newTemplateServer(t)
	defer srv.Close()

	var status struct {
		VMDefaults struct {
			VCPUCount        int   `json:"vcpu_count"`
			MemoryMiB        int64 `json:"memory_mib"`
			RootDiskMiB      int64 `json:"root_disk_mib"`
			WorkspaceDiskMiB int64 `json:"workspace_disk_mib"`
		} `json:"vm_defaults"`
	}
	getJSON(t, srv.URL+"/api/v1/host/status", http.StatusOK, &status)

	var created struct {
		VM struct {
			Resources struct {
				VCPUCount        int   `json:"vcpu_count"`
				MemoryMiB        int64 `json:"memory_mib"`
				RootDiskMiB      int64 `json:"root_disk_mib"`
				WorkspaceDiskMiB int64 `json:"workspace_disk_mib"`
			} `json:"resources"`
		} `json:"vm"`
	}
	postJSON(t, srv.URL+"/api/v1/vms", map[string]any{
		"name":        "defaults-only",
		"template_id": testTemplateDef.TemplateID,
	}, http.StatusCreated, &created)

	got := created.VM.Resources
	pub := status.VMDefaults
	if got.VCPUCount != pub.VCPUCount || got.MemoryMiB != pub.MemoryMiB ||
		got.RootDiskMiB != pub.RootDiskMiB || got.WorkspaceDiskMiB != pub.WorkspaceDiskMiB {
		t.Errorf("created VM resources %+v do not match published defaults %+v", got, pub)
	}
}

// TestHostStatusAdmissionMatchesReservationMath is the honesty assertion: the
// overhead the API publishes is the overhead the manager actually charges. If
// these ever diverge, the launch preview lies and this test says so.
func TestHostStatusAdmissionMatchesReservationMath(t *testing.T) {
	srv, _, _ := newTemplateServer(t)
	defer srv.Close()

	type statusBody struct {
		Capacity struct {
			ReservedMemoryMiB int64 `json:"reserved_memory_mib"`
		} `json:"capacity"`
		Admission struct {
			ReservePerVMHostOverheadMiB int64 `json:"reserve_per_vm_host_overhead_mib"`
		} `json:"admission"`
	}
	var before statusBody
	getJSON(t, srv.URL+"/api/v1/host/status", http.StatusOK, &before)

	const memoryMiB = 512
	postJSON(t, srv.URL+"/api/v1/vms", map[string]any{
		"name":               "reservation-math",
		"template_id":        "test-small-v1",
		"vcpu_count":         1,
		"memory_mib":         memoryMiB,
		"root_disk_mib":      1024,
		"workspace_disk_mib": 512,
	}, http.StatusCreated, nil)

	var after statusBody
	getJSON(t, srv.URL+"/api/v1/host/status", http.StatusOK, &after)

	grew := after.Capacity.ReservedMemoryMiB - before.Capacity.ReservedMemoryMiB
	want := int64(memoryMiB) + before.Admission.ReservePerVMHostOverheadMiB
	if grew != want {
		t.Errorf("reserved memory grew by %d MiB; want %d (%d requested + %d published overhead)",
			grew, want, memoryMiB, before.Admission.ReservePerVMHostOverheadMiB)
	}
}

// TestVMStartRefusedWhenMemoryWentElsewhere: the memory a stop releases is real
// free memory that another VM may take, so the start that wants it back can be
// refused. The refusal must reach the caller as the same 409 a create gets —
// insufficient_capacity, naming the shortfall — not a 500 and not a silent
// success that leaves the host overcommitted.
func TestVMStartRefusedWhenMemoryWentElsewhere(t *testing.T) {
	// Tiny host: exactly two 512 MiB VMs fit.
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
		Templates:  map[string]runtime.Template{testTemplateDef.TemplateID: testTemplateDef},
		Host:       runtime.HostResources{TotalMemoryMiB: 1024, CPUCores: 4, StateDiskFreeMiB: 100 * 1024},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })
	srv := httptest.NewServer(api.New(st, eng, mgr, api.AuthConfig{Enabled: false}, nil, nil))
	t.Cleanup(srv.Close)

	create := func(name string) string {
		t.Helper()
		var resp map[string]any
		doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms",
			map[string]any{"name": name, "template_id": testTemplateDef.TemplateID},
			http.StatusCreated, &resp)
		vmID, _ := resp["vm"].(map[string]any)["vm_id"].(string)
		opID, _ := resp["operation"].(map[string]any)["operation_id"].(string)
		pollOpState(t, srv.URL, opID, "succeeded")
		return vmID
	}
	revisionOf := func(vmID string) any {
		t.Helper()
		var vm map[string]any
		getJSON(t, srv.URL+"/api/v1/vms/"+vmID, http.StatusOK, &vm)
		return vm["revision"]
	}

	first := create("first")
	create("second") // host memory now full

	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms/"+first+"/actions",
		map[string]any{"action": "stop", "expected_revision": revisionOf(first)},
		http.StatusOK, nil)

	// The freed 512 MiB is genuinely free: a new VM takes it.
	create("third")

	var e api.Error
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms/"+first+"/actions",
		map[string]any{"action": "start", "expected_revision": revisionOf(first)},
		http.StatusConflict, &e)
	requireTeaching(t, e, "insufficient_capacity")
	if !strings.Contains(e.Message, "memory") {
		t.Errorf("refusal message = %q, want the memory dimension named", e.Message)
	}
	// failAction wrote a failed operation for this refusal; naming it is what
	// lets the operator see the shortfall again after the response is gone.
	if e.OperationID == "" {
		t.Error("a refused start records a failed operation; the refusal must name it")
	}

	// A refused start leaves the VM where it was, not parked in "starting".
	var after map[string]any
	getJSON(t, srv.URL+"/api/v1/vms/"+first, http.StatusOK, &after)
	if state, _ := after["observed_state"].(string); state != "stopped" {
		t.Errorf("observed_state after a refused start = %q, want stopped", state)
	}
}

// TestHostStatusSurvivesStopStart: the shape of the defect a real browser found
// on 2026-09-04 — three running VMs, two VMs' worth of reserved memory. Every
// number GET /host/status publishes must come back to where it started after a
// VM makes a full stop/start round trip, because that is the page operators read
// and the sum admission charges against.
func TestHostStatusSurvivesStopStart(t *testing.T) {
	srv, _, fake := newTemplateServer(t)
	vmID := createRunningVM(t, srv.URL, fake)

	capacity := func(when string) map[string]any {
		t.Helper()
		var got map[string]any
		getJSON(t, srv.URL+"/api/v1/host/status", http.StatusOK, &got)
		cap, ok := got["capacity"].(map[string]any)
		if !ok {
			t.Fatalf("host/status %s: missing capacity block", when)
		}
		return cap
	}
	revisionOf := func() any {
		t.Helper()
		var vm map[string]any
		getJSON(t, srv.URL+"/api/v1/vms/"+vmID, http.StatusOK, &vm)
		return vm["revision"]
	}

	before := capacity("while running")

	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms/"+vmID+"/actions",
		map[string]any{"action": "stop", "expected_revision": revisionOf()},
		http.StatusOK, nil)
	stopped := capacity("while stopped")
	if fmt.Sprint(stopped["reserved_memory_mib"]) == fmt.Sprint(before["reserved_memory_mib"]) {
		t.Fatalf("stop released no memory: reserved_memory_mib stayed %v", stopped["reserved_memory_mib"])
	}

	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms/"+vmID+"/actions",
		map[string]any{"action": "start", "expected_revision": revisionOf()},
		http.StatusOK, nil)
	after := capacity("after the restart")

	for _, field := range []string{
		"usable_memory_mib", "reserved_memory_mib", "free_memory_mib",
		"usable_vcpu", "reserved_vcpu", "free_vcpu",
		"usable_disk_mib", "reserved_disk_mib", "free_disk_mib",
		"active_vms",
	} {
		if fmt.Sprint(after[field]) != fmt.Sprint(before[field]) {
			t.Errorf("%s after a stop/start = %v, want %v", field, after[field], before[field])
		}
	}
}
