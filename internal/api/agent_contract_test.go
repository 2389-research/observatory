// ABOUTME: Exercises agent discovery and recovery over real HTTP and SQLite.
// ABOUTME: The runtime fixture isolates this API contract from the Linux/KVM gate.
package api_test

import (
	"encoding/json"
	"github.com/2389-research/observatory/internal/api"
	"github.com/2389-research/observatory/internal/runtime"
	"github.com/2389-research/observatory/internal/runtime/runtimetest"
	"github.com/2389-research/observatory/internal/situation"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2389-research/observatory/internal/store"
)

func TestAgentManifestDescribesMutationAndResume(t *testing.T) {
	srv, _, _ := newTemplateServer(t)
	var meta struct {
		Routes []struct {
			Method, Path, Feature string
			Built                 bool
			RequestExample        map[string]any `json:"request_example"`
			Purpose               string
		}
		Agent map[string]any
	}
	getJSON(t, srv.URL+"/api/v1/meta", 200, &meta)
	if len(meta.Routes) == 0 {
		t.Fatal("cold agent has no route catalog")
	}
	found := map[string]bool{}
	for _, r := range meta.Routes {
		if r.Built && r.Method == "POST" && r.Path == "/api/v1/vms" {
			found["launch"] = true
			if r.RequestExample["idempotency_key"] == nil || r.RequestExample["run"] == nil {
				t.Fatalf("launch lacks executable safe retry/run shape: %+v", r)
			}
		}
		if r.Built && r.Method == "POST" && r.Path == "/api/v1/vms/{id}/actions" {
			found["action"] = true
			if r.RequestExample["expected_revision"] == nil {
				t.Fatal("action lacks revision binding")
			}
		}
		if r.Feature == "events_stream" && r.Built {
			t.Fatal("unbuilt stream advertised")
		}
	}
	if !found["launch"] || !found["action"] || meta.Agent["resume"] == nil {
		t.Fatalf("incomplete discovery: %v %+v", found, meta.Agent)
	}
}

func TestAgentSnapshotReportsOmissions(t *testing.T) {
	srv, st := newServer(t)
	for i := 0; i < 15; i++ {
		vm := testUUID(100 + i)
		_, err := st.RaiseAttention(t.Context(), store.RaiseInput{TriggerClass: "telemetry_degraded", Severity: store.SeverityNeedsDecision, VMID: &vm, Summary: "needs inspection", SystemAction: "recorded", QueueMax: 500})
		if err != nil {
			t.Fatal(err)
		}
	}
	var snap struct {
		AttentionOpen int64             `json:"attention_open"`
		AttentionHead []json.RawMessage `json:"attention_head"`
		Omitted       map[string]struct {
			Count  int64
			Expand string
		}
	}
	getJSON(t, srv.URL+"/api/v1/situation", http.StatusOK, &snap)
	if snap.AttentionOpen != 15 {
		t.Fatalf("attention_open=%d, want 15", snap.AttentionOpen)
	}
	omitted := snap.Omitted["attention_head"]
	if omitted.Count != 15-int64(len(snap.AttentionHead)) || omitted.Expand == "" {
		t.Fatalf("silent omission: %+v", snap)
	}
}

func TestAgentErrorsDeclareSafeRecovery(t *testing.T) {
	srv, _, _ := newTemplateServer(t)
	for _, tc := range []struct{ path, strategy string }{{"/api/v1/events?after=bad", "after_refresh"}, {"/api/v1/events/stream", "never"}, {"/api/v1/events?limit=1001", "after_precondition"}} {
		resp, err := http.Get(srv.URL + tc.path)
		if err != nil {
			t.Fatal(err)
		}
		var e map[string]any
		err = json.NewDecoder(resp.Body).Decode(&e)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if e["retry_strategy"] != tc.strategy {
			t.Errorf("%s recovery=%v want %s", tc.path, e["retry_strategy"], tc.strategy)
		}
	}
}

func TestAgentLaunchCarriesExecutableLinks(t *testing.T) {
	srv, _, _ := newTemplateServer(t)
	var meta struct {
		Routes []struct {
			Purpose, Path  string
			RequestExample map[string]any `json:"request_example"`
		}
	}
	getJSON(t, srv.URL+"/api/v1/meta", 200, &meta)
	var launchPath string
	var body map[string]any
	for _, r := range meta.Routes {
		if r.Purpose == "launch" {
			launchPath = r.Path
			body = r.RequestExample
		}
	}
	if body == nil {
		t.Fatal("launch undiscoverable")
	}
	body["name"] = "agent-links"
	body["template_id"] = testTemplateDef.TemplateID
	body["idempotency_key"] = "agent-links-key"
	body["run"].(map[string]any)["goal"] = "verify links"
	raw, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+launchPath, "application/json", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	err = json.NewDecoder(resp.Body).Decode(&result)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 201 {
		t.Fatalf("launch %d: %+v", resp.StatusCode, result)
	}
	for _, name := range []string{"vm", "operation"} {
		resource := result[name].(map[string]any)
		links, ok := resource["links"].(map[string]any)
		if !ok {
			t.Fatalf("%s missing links", name)
		}
		self, ok := links["self"].(string)
		if !ok {
			t.Fatalf("%s has no self link", name)
		}
		var found map[string]any
		getJSON(t, srv.URL+self, 200, &found)
	}
}

func TestAgentStaleRevisionRecoveryUsesConcreteRead(t *testing.T) {
	srv, _, _ := newTemplateServer(t)
	var created map[string]any
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms", map[string]any{"name": "agent-stale", "template_id": testTemplateDef.TemplateID}, 201, &created)
	vm := created["vm"].(map[string]any)
	pollOpState(t, srv.URL, created["operation"].(map[string]any)["operation_id"].(string), "succeeded")
	vmID := vm["vm_id"].(string)
	var e map[string]any
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms/"+vmID+"/actions", map[string]string{"action": "stop", "expected_revision": "0"}, 409, &e)
	if e["retry_strategy"] != "after_refresh" {
		t.Fatalf("stale revision recovery: %v", e)
	}
	concrete := false
	for _, raw := range e["remediation"].([]any) {
		entry := raw.(map[string]any)
		params := entry["params"].(map[string]any)
		if params["path"] == "/api/v1/vms/"+vmID {
			concrete = true
		}
	}
	if !concrete {
		t.Fatalf("refresh cannot execute: %v", e)
	}
}

func TestAgentChangedVMOmissionsAreLowerBounded(t *testing.T) {
	srv, st := newServer(t)
	for i := 0; i < 60; i++ {
		id := testUUID(300 + i)
		_, _, _, err := st.CreateVMWithOperation(t.Context(), store.CreateVMInput{VMID: id, Name: id, Owner: "operator", TemplateID: "fixture", TemplateDigest: "sha256:fixture", Kind: "vm.create", RequestHash: id, Admit: func(store.ReservationTotals) error { return nil }})
		if err != nil {
			t.Fatal(err)
		}
	}
	var snap struct {
		ChangedVMs []json.RawMessage `json:"changed_vms"`
		Omitted    map[string]struct {
			Count   int
			AtLeast bool `json:"at_least"`
			Expand  string
		}
	}
	getJSON(t, srv.URL+"/api/v1/situation?since=0", 200, &snap)
	omitted := snap.Omitted["changed_vms"]
	if omitted.Count < 1 || !omitted.AtLeast || omitted.Expand != "/api/v1/vms" {
		t.Fatalf("bounded delta concealed additional VMs: %+v", omitted)
	}
	if len(snap.ChangedVMs) > 50 {
		t.Fatalf("unbounded delta: %d", len(snap.ChangedVMs))
	}
}

func TestAgentSituationRefusesImpossibleByteCeiling(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "events.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	eng := situation.New(st, situation.Config{SituationMaxResponseBytes: 100})
	mgr, err := runtime.NewManager(st, runtimetest.NewFake(), runtime.ManagerConfig{Host: runtime.HostResources{TotalMemoryMiB: 8192, CPUCores: 4, StateDiskFreeMiB: 100 * 1024}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mgr.Close() })
	srv := httptest.NewServer(api.New(st, eng, mgr, api.AuthConfig{}, nil, nil))
	t.Cleanup(srv.Close)
	var e map[string]any
	getJSON(t, srv.URL+"/api/v1/situation", http.StatusServiceUnavailable, &e)
	if e["cause"] != "situation_envelope_exceeds_bound" || e["retry_strategy"] != "after_precondition" {
		t.Fatalf("impossible bound is not actionable: %v", e)
	}
}
