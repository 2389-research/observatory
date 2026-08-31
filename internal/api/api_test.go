// ABOUTME: Tests the HTTP API against a real store via httptest: honest /meta,
// ABOUTME: registry serving, bounded event pages, and errors that teach.
package api_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/api"
	"github.com/2389-research/observatory-v2/internal/config"
	"github.com/2389-research/observatory-v2/internal/events"
	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/runtime/runtimetest"
	"github.com/2389-research/observatory-v2/internal/situation"
	"github.com/2389-research/observatory-v2/internal/store"
)

func newServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "events.sqlite"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	eng := situation.New(st, situation.Config{
		Triggers: map[string]bool{
			"lifecycle_failed": true, "run_concluded": true, "telemetry_degraded": true,
			"spool_threshold": true, "disk_reserve_threshold": true,
			"policy_denial_anomaly": true, "capacity_exhausted": true,
			"reconciliation_surprise": true,
		},
		QueueMaxItems:             500,
		CollapseDuplicates:        true,
		SituationMaxResponseBytes: 65536,
	})
	mgr, err := runtime.NewManager(st, runtimetest.NewFake(), runtime.ManagerConfig{
		Admission:  config.Admission{},
		VMDefaults: config.VMDefaults{},
		Owner:      "local_operator",
		Templates:  map[string]runtime.Template{},
		Host:       runtime.HostResources{TotalMemoryMiB: 8192, CPUCores: 4, StateDiskFreeMiB: 100 * 1024},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })
	srv := httptest.NewServer(api.New(st, eng, mgr))
	t.Cleanup(srv.Close)
	return srv, st
}

func testUUID(n int) string {
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", n)
}

func seedEvent(t *testing.T, st *store.Store, source, seq string, vm string) {
	t.Helper()
	boot := testUUID(2)
	env := &events.Envelope{
		SchemaVersion:    1,
		VMID:             &vm,
		BootID:           &boot,
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
	if _, err := st.Append(t.Context(), env); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func getJSON(t *testing.T, url string, wantStatus int, into any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("GET %s = %d, want %d\nbody: %s", url, resp.StatusCode, wantStatus, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("GET %s content-type = %q", url, ct)
	}
	if err := json.Unmarshal(body, into); err != nil {
		t.Fatalf("GET %s: decode: %v\nbody: %s", url, err, body)
	}
}

// requireTeaching asserts the invariants every structured error must hold (P-06).
func requireTeaching(t *testing.T, e api.Error, wantCode string) {
	t.Helper()
	if e.Code != wantCode {
		t.Errorf("code = %q, want %q", e.Code, wantCode)
	}
	if e.Message == "" || e.Cause == "" {
		t.Errorf("error must carry message and cause: %+v", e)
	}
	for _, r := range e.Remediation {
		if r.Action == "" || r.Rationale == "" {
			t.Errorf("remediation must be typed with rationale: %+v", r)
		}
	}
}

type metaResponse struct {
	Service                 string            `json:"service"`
	Version                 string            `json:"version"`
	APIVersion              string            `json:"api_version"`
	Features                map[string]bool   `json:"features"`
	Limits                  map[string]int    `json:"limits"`
	AttentionTriggerClasses []string          `json:"attention_trigger_classes"`
	Links                   map[string]string `json:"links"`
}

func TestMetaIsHonest(t *testing.T) {
	srv, _ := newServer(t)
	var meta metaResponse
	getJSON(t, srv.URL+"/api/v1/meta", http.StatusOK, &meta)

	if meta.Service != "vmobsd" || meta.APIVersion != "v1" || meta.Version == "" {
		t.Errorf("identity wrong: %+v", meta)
	}
	for feature, want := range map[string]bool{
		"meta": true, "events": true,
		"situation": true, "attention": true, "annotations": true,
		"host_status": true, "templates": true, "vms": true, "operations": true,
		"vm_batches": true,
		"runs":       false, "terminals": false, "execs": false,
		"events_stream": false,
	} {
		got, present := meta.Features[feature]
		if !present {
			t.Errorf("feature %q missing from manifest", feature)
		} else if got != want {
			t.Errorf("feature %q = %v, want %v (manifest must not overclaim)", feature, got, want)
		}
	}
	if meta.Limits["events_page_default"] != store.DefaultPageLimit ||
		meta.Limits["events_page_max"] != store.MaxPageLimit {
		t.Errorf("limits = %v, want store bounds", meta.Limits)
	}
	if meta.Limits["annotation_text_max_bytes"] != store.AnnotationTextMaxBytes ||
		meta.Limits["attention_queue_max_items"] != 500 ||
		meta.Limits["situation_max_response_bytes"] != 65536 ||
		meta.Limits["max_batch_size"] != api.MaxBatchSize {
		t.Errorf("working-set limits missing: %v", meta.Limits)
	}
	// The active set is enabled-intersect-implemented, never the raw config.
	// Four classes are now implemented: capacity_exhausted, lifecycle_failed,
	// reconciliation_surprise, telemetry_degraded.
	if len(meta.AttentionTriggerClasses) != 4 {
		t.Errorf("attention classes = %v, want exactly the implemented+enabled set", meta.AttentionTriggerClasses)
	}
	if len(meta.Links) == 0 {
		t.Fatal("meta has no links")
	}
	for name, target := range meta.Links {
		resp, err := http.Get(srv.URL + target)
		if err != nil {
			t.Fatalf("link %q: %v", name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("link %q -> %s answers %d: manifests must not link to the unbuilt", name, target, resp.StatusCode)
		}
	}
}

func TestMetaEventKindsServesRegistry(t *testing.T) {
	srv, _ := newServer(t)
	var got struct {
		Kinds []events.KindInfo `json:"kinds"`
	}
	getJSON(t, srv.URL+"/api/v1/meta/event-kinds", http.StatusOK, &got)
	if len(got.Kinds) != len(events.Kinds()) {
		t.Errorf("served %d kinds, registry has %d", len(got.Kinds), len(events.Kinds()))
	}
	found := false
	for _, k := range got.Kinds {
		if k.Kind == "fs.modify" {
			found = true
			if len(k.Caveats) == 0 || k.Provenance != events.GuestReported {
				t.Errorf("fs.modify served without its caveats: %+v", k)
			}
		}
	}
	if !found {
		t.Error("fs.modify not served")
	}
}

type eventsResponse struct {
	Events        []json.RawMessage `json:"events"`
	NextAfter     string            `json:"next_after"`
	LatestEventID string            `json:"latest_event_id"`
}

func TestEventsEmptyStoreIsEvidence(t *testing.T) {
	srv, _ := newServer(t)
	var got eventsResponse
	getJSON(t, srv.URL+"/api/v1/events", http.StatusOK, &got)
	if got.Events == nil {
		t.Error("events must be [], not null")
	}
	if len(got.Events) != 0 || got.LatestEventID != "" || got.NextAfter != "" {
		t.Errorf("empty store response: %+v", got)
	}
}

func TestEventsPagination(t *testing.T) {
	srv, st := newServer(t)
	vm := testUUID(1)
	for i := 1; i <= 250; i++ {
		seedEvent(t, st, testUUID(9), strconv.Itoa(i), vm)
	}

	var page1 eventsResponse
	getJSON(t, srv.URL+"/api/v1/events", http.StatusOK, &page1)
	if len(page1.Events) != store.DefaultPageLimit || page1.NextAfter != "200" || page1.LatestEventID != "250" {
		t.Fatalf("page1: %d events, next %q, latest %q", len(page1.Events), page1.NextAfter, page1.LatestEventID)
	}
	var env events.Envelope
	if err := json.Unmarshal(page1.Events[0], &env); err != nil || env.EventID == nil || *env.EventID != "1" {
		t.Errorf("first event: %v, err %v", env.EventID, err)
	}

	var page2 eventsResponse
	getJSON(t, srv.URL+"/api/v1/events?after="+page1.NextAfter+"&limit=100", http.StatusOK, &page2)
	if len(page2.Events) != 50 || page2.NextAfter != "250" {
		t.Errorf("page2: %d events, next %q", len(page2.Events), page2.NextAfter)
	}

	var caughtUp eventsResponse
	getJSON(t, srv.URL+"/api/v1/events?after=250", http.StatusOK, &caughtUp)
	if len(caughtUp.Events) != 0 || caughtUp.NextAfter != "250" || caughtUp.LatestEventID != "250" {
		t.Errorf("caught up: %+v", caughtUp)
	}
}

func TestEventsFilters(t *testing.T) {
	srv, st := newServer(t)
	vmA, vmB := testUUID(1), testUUID(3)
	seedEvent(t, st, testUUID(9), "1", vmA)
	seedEvent(t, st, testUUID(8), "1", vmB)
	seedEvent(t, st, testUUID(9), "2", vmA)

	var byVM eventsResponse
	getJSON(t, srv.URL+"/api/v1/events?vm_id="+vmA, http.StatusOK, &byVM)
	if len(byVM.Events) != 2 {
		t.Errorf("vm filter returned %d events", len(byVM.Events))
	}

	var byKind eventsResponse
	getJSON(t, srv.URL+"/api/v1/events?kind=fs.modify", http.StatusOK, &byKind)
	if len(byKind.Events) != 3 {
		t.Errorf("kind filter returned %d events", len(byKind.Events))
	}

	var badVM api.Error
	getJSON(t, srv.URL+"/api/v1/events?vm_id=not-a-uuid", http.StatusBadRequest, &badVM)
	requireTeaching(t, badVM, "malformed_request")

	var badKind api.Error
	getJSON(t, srv.URL+"/api/v1/events?kind=no.such_kind", http.StatusBadRequest, &badKind)
	requireTeaching(t, badKind, "malformed_request")
	foundRegistryPointer := false
	for _, r := range badKind.Remediation {
		if strings.Contains(fmt.Sprint(r.Params), "event-kinds") {
			foundRegistryPointer = true
		}
	}
	if !foundRegistryPointer {
		t.Errorf("unknown-kind error should point at the registry: %+v", badKind.Remediation)
	}
}

func TestEventsBoundsTeach(t *testing.T) {
	srv, _ := newServer(t)

	var notInt api.Error
	getJSON(t, srv.URL+"/api/v1/events?limit=abc", http.StatusBadRequest, &notInt)
	requireTeaching(t, notInt, "malformed_request")

	var tooBig api.Error
	getJSON(t, srv.URL+"/api/v1/events?limit=1001", http.StatusBadRequest, &tooBig)
	requireTeaching(t, tooBig, "limit_exceeded")
	if tooBig.Retryable {
		t.Error("limit_exceeded is not retryable as sent")
	}
	if len(tooBig.Remediation) == 0 {
		t.Error("limit_exceeded must offer remediation (P-06)")
	}

	var badCursor api.Error
	getJSON(t, srv.URL+"/api/v1/events?after=zzz", http.StatusBadRequest, &badCursor)
	requireTeaching(t, badCursor, "malformed_request")
}

func TestUnbuiltEndpointsTeachCapability(t *testing.T) {
	srv, _ := newServer(t)
	for _, probe := range []struct {
		method, path, feature string
	}{
		{http.MethodGet, "/api/v1/events/stream", "events_stream"},
		{http.MethodGet, "/api/v1/runs", "runs"},
		{http.MethodGet, "/api/v1/vms/" + testUUID(1) + "/coverage", "coverage"},
	} {
		req, _ := http.NewRequest(probe.method, srv.URL+probe.path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", probe.method, probe.path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotImplemented {
			t.Errorf("%s %s = %d, want 501\nbody: %s", probe.method, probe.path, resp.StatusCode, body)
			continue
		}
		var e api.Error
		if err := json.Unmarshal(body, &e); err != nil {
			t.Fatalf("decode 501 body: %v", err)
		}
		requireTeaching(t, e, "missing_capability")
		if e.Details["feature"] != probe.feature {
			t.Errorf("%s: details.feature = %v, want %q", probe.path, e.Details["feature"], probe.feature)
		}
	}
}

func TestUnknownPathIsStructured404(t *testing.T) {
	srv, _ := newServer(t)
	var e api.Error
	getJSON(t, srv.URL+"/api/v1/nope", http.StatusNotFound, &e)
	requireTeaching(t, e, "not_found")
}

func TestWrongMethodIsStructured405(t *testing.T) {
	srv, _ := newServer(t)
	resp, err := http.Post(srv.URL+"/api/v1/meta", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /meta = %d\nbody: %s", resp.StatusCode, body)
	}
	var e api.Error
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatalf("decode 405: %v\nbody: %s", err, body)
	}
	requireTeaching(t, e, "method_not_allowed")
}
