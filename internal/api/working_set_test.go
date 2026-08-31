// ABOUTME: Tests the operator working set over HTTP: situation snapshots,
// ABOUTME: attention list/ack, annotations — quiet is monitored, actions execute as returned.
package api_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/api"
	"github.com/2389-research/observatory-v2/internal/config"
	"github.com/2389-research/observatory-v2/internal/events"
	"github.com/2389-research/observatory-v2/internal/redact"
	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/runtime/runtimetest"
	"github.com/2389-research/observatory-v2/internal/situation"
	"github.com/2389-research/observatory-v2/internal/store"
)

// breakTelemetry provokes a real telemetry.unregistered_kind health event.
func breakTelemetry(t *testing.T, st *store.Store, seq string) {
	t.Helper()
	boot := testUUID(2)
	vm := testUUID(1)
	env := &events.Envelope{
		SchemaVersion: 1, VMID: &vm, BootID: &boot,
		SourceInstanceID: testUUID(91), SourceSeq: seq,
		Kind: "made.up_kind", Provenance: events.GuestReported, Sensor: "fanotify",
		HostReceivedAt: events.Timestamp{Time: time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)},
		Quality: events.Quality{
			PathResolution: events.PathExactAtCapture,
			Attribution:    events.AttributionExact,
		},
		Data: map[string]any{"path_display": "/workspace/app.py"},
	}
	if _, err := st.Append(t.Context(), env); !errors.Is(err, store.ErrUnregisteredKind) {
		t.Fatalf("expected unregistered-kind rejection, got %v", err)
	}
}

func postJSON(t *testing.T, url string, body any, wantStatus int, into any) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(url, "application/json", &buf)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf("POST %s = %d, want %d: %s", url, resp.StatusCode, wantStatus, raw)
	}
	if into != nil {
		if err := json.Unmarshal(raw, into); err != nil {
			t.Fatalf("decode %s: %v", raw, err)
		}
	}
	return raw
}

type situationResponse struct {
	AsOfCursor  string `json:"as_of_cursor"`
	SinceCursor string `json:"since_cursor"`
	Quiet       bool   `json:"quiet"`
	Host        struct {
		VMsRunning int `json:"vms_running"`
		VMsTotal   int `json:"vms_total"`
		Watch      struct {
			TriggerClassesActive []string `json:"trigger_classes_active"`
			SensorsDegraded      int      `json:"sensors_degraded"`
		} `json:"watch"`
	} `json:"host"`
	ChangedVMs    []map[string]any `json:"changed_vms"`
	AttentionHead []attentionItem  `json:"attention_head"`
}

type attentionItem struct {
	AttentionID      string           `json:"attention_id"`
	Cursor           string           `json:"cursor"`
	Severity         string           `json:"severity"`
	Kind             string           `json:"kind"`
	VMID             string           `json:"vm_id"`
	Summary          string           `json:"summary"`
	SystemAction     string           `json:"system_action"`
	Count            string           `json:"count"`
	Acked            bool             `json:"acked"`
	EvidenceLinks    []string         `json:"evidence_links"`
	SuggestedActions []map[string]any `json:"suggested_actions"`
}

type attentionListResponse struct {
	Items     []attentionItem `json:"items"`
	NextAfter string          `json:"next_after"`
}

func TestSituationEmptyStoreIsMonitoredCalm(t *testing.T) {
	srv, _ := newServer(t)
	var got situationResponse
	getJSON(t, srv.URL+"/api/v1/situation", http.StatusOK, &got)

	if got.AsOfCursor != "0" || !got.Quiet {
		t.Errorf("situation = %+v, want as_of 0 and quiet", got)
	}
	// P-03: quiet must state the watch scope, or calm is indistinguishable
	// from blindness. Four classes are now implemented.
	if len(got.Host.Watch.TriggerClassesActive) != 4 {
		t.Errorf("watch scope = %v", got.Host.Watch.TriggerClassesActive)
	}
	if got.ChangedVMs == nil || len(got.ChangedVMs) != 0 {
		t.Errorf("changed_vms = %v, want present empty list", got.ChangedVMs)
	}
	if got.AttentionHead == nil || len(got.AttentionHead) != 0 {
		t.Errorf("attention_head = %v, want present empty list", got.AttentionHead)
	}
}

func TestSituationServesAttentionRaisedFromStream(t *testing.T) {
	srv, st := newServer(t)
	breakTelemetry(t, st, "1")

	// The GET itself evaluates triggers: no background process required.
	var got situationResponse
	getJSON(t, srv.URL+"/api/v1/situation", http.StatusOK, &got)
	if got.Quiet {
		t.Error("open attention but quiet")
	}
	if len(got.AttentionHead) != 1 {
		t.Fatalf("head = %+v", got.AttentionHead)
	}
	item := got.AttentionHead[0]
	if item.AttentionID != "att-000001" || item.Kind != "telemetry_degraded" ||
		item.Severity != "needs_decision" || item.Acked {
		t.Errorf("item = %+v", item)
	}
	if item.Cursor == "" || item.Count != "1" || item.Summary == "" || item.SystemAction == "" {
		t.Errorf("item incomplete: %+v", item)
	}

	// Suggested actions execute as returned (P-06): the ack carries the id.
	var ack map[string]any
	for _, a := range item.SuggestedActions {
		if a["action"] == "ack" {
			ack = a
		}
	}
	if ack == nil {
		t.Fatalf("no ack action: %+v", item.SuggestedActions)
	}
	params, _ := ack["params"].(map[string]any)
	if params["attention_id"] != "att-000001" {
		t.Errorf("ack params = %+v", params)
	}

	// Evidence links resolve on this same API.
	if len(item.EvidenceLinks) == 0 {
		t.Fatal("no evidence links")
	}
	resp, err := http.Get(srv.URL + item.EvidenceLinks[0])
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("evidence link %q: %v %d", item.EvidenceLinks[0], err, resp.StatusCode)
	}
	resp.Body.Close()

	// Bad since cursor teaches.
	var apiErr api.Error
	getJSON(t, srv.URL+"/api/v1/situation?since=banana", http.StatusBadRequest, &apiErr)
	if apiErr.Code != "malformed_request" {
		t.Errorf("bad since = %+v", apiErr)
	}
}

func TestSituationSinceDeltaQuietAfterAck(t *testing.T) {
	srv, st := newServer(t)
	breakTelemetry(t, st, "1")

	var full situationResponse
	getJSON(t, srv.URL+"/api/v1/situation", http.StatusOK, &full)
	if full.Quiet || len(full.AttentionHead) != 1 {
		t.Fatalf("setup: %+v", full)
	}

	postJSON(t, srv.URL+"/api/v1/attention/att-000001/ack", map[string]any{}, http.StatusOK, nil)

	var delta situationResponse
	getJSON(t, srv.URL+"/api/v1/situation?since="+full.AsOfCursor, http.StatusOK, &delta)
	if !delta.Quiet || delta.SinceCursor != full.AsOfCursor {
		t.Errorf("acked and nothing new, delta = %+v", delta)
	}
	if len(delta.Host.Watch.TriggerClassesActive) == 0 {
		t.Error("quiet delta dropped its watch scope")
	}
}

func TestAttentionListAckLifecycle(t *testing.T) {
	srv, st := newServer(t)
	breakTelemetry(t, st, "1")

	var list attentionListResponse
	getJSON(t, srv.URL+"/api/v1/attention", http.StatusOK, &list)
	if len(list.Items) != 1 || list.Items[0].Acked {
		t.Fatalf("list = %+v", list)
	}
	id := list.Items[0].AttentionID

	var acked attentionItem
	postJSON(t, srv.URL+"/api/v1/attention/"+id+"/ack", map[string]any{}, http.StatusOK, &acked)
	if !acked.Acked || acked.AttentionID != id {
		t.Errorf("acked = %+v", acked)
	}
	// Idempotent: same call, same answer.
	postJSON(t, srv.URL+"/api/v1/attention/"+id+"/ack", map[string]any{}, http.StatusOK, &acked)
	if !acked.Acked {
		t.Errorf("second ack = %+v", acked)
	}

	getJSON(t, srv.URL+"/api/v1/attention", http.StatusOK, &list)
	if len(list.Items) != 0 {
		t.Errorf("default view shows acked: %+v", list.Items)
	}
	getJSON(t, srv.URL+"/api/v1/attention?include_acked=true", http.StatusOK, &list)
	if len(list.Items) != 1 || !list.Items[0].Acked {
		t.Errorf("include_acked = %+v", list.Items)
	}

	var apiErr api.Error
	postJSON(t, srv.URL+"/api/v1/attention/att-999999/ack", map[string]any{}, http.StatusNotFound, &apiErr)
	if apiErr.Code != "not_found" || len(apiErr.Remediation) == 0 {
		t.Errorf("unknown ack = %+v", apiErr)
	}
	postJSON(t, srv.URL+"/api/v1/attention/banana/ack", map[string]any{}, http.StatusBadRequest, &apiErr)
	if apiErr.Code != "malformed_request" {
		t.Errorf("malformed ack = %+v", apiErr)
	}
}

type annotationResponse struct {
	AnnotationID      string            `json:"annotation_id"`
	TargetRef         string            `json:"target_ref"`
	Author            string            `json:"author"`
	Text              string            `json:"text"`
	Tags              map[string]string `json:"tags"`
	Redacted          bool              `json:"redacted"`
	RedactionPolicyID string            `json:"redaction_policy_id"`
	EventID           string            `json:"event_id"`
	CreatedAt         string            `json:"created_at"`
}

func TestAnnotationsPostAndListByRef(t *testing.T) {
	srv, _ := newServer(t)
	ref := "vm:" + testUUID(1)

	var ann annotationResponse
	postJSON(t, srv.URL+"/api/v1/annotations",
		map[string]any{"target_ref": ref, "text": "looks healthy", "tags": map[string]string{"verdict": "pass"}},
		http.StatusCreated, &ann)
	if ann.AnnotationID != "ann-000001" || ann.TargetRef != ref || ann.Text != "looks healthy" {
		t.Errorf("annotation = %+v", ann)
	}
	// Identity comes from the trusted boundary, not the payload.
	if ann.Author != "local_operator" {
		t.Errorf("author = %q, want local_operator", ann.Author)
	}
	if ann.EventID == "" || ann.CreatedAt == "" {
		t.Errorf("annotation lacks event linkage: %+v", ann)
	}

	postJSON(t, srv.URL+"/api/v1/annotations",
		map[string]any{"target_ref": "event:1", "text": "other"}, http.StatusCreated, nil)

	var list struct {
		Annotations []annotationResponse `json:"annotations"`
		NextAfter   string               `json:"next_after"`
	}
	getJSON(t, srv.URL+"/api/v1/annotations?ref="+ref, http.StatusOK, &list)
	if len(list.Annotations) != 1 || list.Annotations[0].TargetRef != ref {
		t.Errorf("by ref = %+v", list.Annotations)
	}
	getJSON(t, srv.URL+"/api/v1/annotations", http.StatusOK, &list)
	if len(list.Annotations) != 2 {
		t.Errorf("all = %+v", list.Annotations)
	}
}

func TestAnnotationsRejectClientAuthorAndBadInput(t *testing.T) {
	srv, _ := newServer(t)
	var apiErr api.Error

	// A client-supplied author is an identity claim; refuse it loudly rather
	// than silently overwriting.
	postJSON(t, srv.URL+"/api/v1/annotations",
		map[string]any{"target_ref": "host:self", "text": "x", "author": "mallory"},
		http.StatusBadRequest, &apiErr)
	if apiErr.Code != "malformed_request" {
		t.Errorf("author claim = %+v", apiErr)
	}

	postJSON(t, srv.URL+"/api/v1/annotations",
		map[string]any{"target_ref": "spaceship:1", "text": "x"}, http.StatusBadRequest, &apiErr)
	if apiErr.Code != "malformed_request" || apiErr.Cause != "target_ref_invalid" {
		t.Errorf("bad ref = %+v", apiErr)
	}

	postJSON(t, srv.URL+"/api/v1/annotations",
		map[string]any{"target_ref": "host:self", "text": strings.Repeat("x", store.AnnotationTextMaxBytes+1)},
		http.StatusBadRequest, &apiErr)
	if apiErr.Code != "limit_exceeded" {
		t.Errorf("oversized text = %+v", apiErr)
	}
}

func TestAnnotationsRedactBeforeServing(t *testing.T) {
	srv, _ := newServer(t)
	var ann annotationResponse
	raw := postJSON(t, srv.URL+"/api/v1/annotations",
		map[string]any{"target_ref": "host:self", "text": "used Authorization: Bearer sk-live-supersecret99"},
		http.StatusCreated, &ann)
	if bytes.Contains(raw, []byte("sk-live-supersecret99")) {
		t.Fatalf("secret served back: %s", raw)
	}
	if !ann.Redacted || ann.RedactionPolicyID != redact.PolicyID {
		t.Errorf("redaction not declared: %+v", ann)
	}
}

func TestSituationResponseByteBound(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "events.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	eng := situation.New(st, situation.Config{
		Triggers:                  map[string]bool{"telemetry_degraded": true},
		QueueMaxItems:             500,
		CollapseDuplicates:        true,
		SituationMaxResponseBytes: 700,
	})
	mgr, err := runtime.NewManager(st, runtimetest.NewFake(), runtime.ManagerConfig{
		Admission:  config.Admission{},
		VMDefaults: config.VMDefaults{},
		Owner:      "local_operator",
		Templates:  map[string]runtime.Template{},
		Host:       runtime.HostResources{TotalMemoryMiB: 8192, CPUCores: 4, StateDiskFreeMiB: 100 * 1024},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mgr.Close() })
	srv := httptest.NewServer(api.New(st, eng, mgr))
	t.Cleanup(srv.Close)

	// Distinct VMs so items do not collapse; the head alone would exceed the
	// byte bound.
	for i := 0; i < 8; i++ {
		vm := testUUID(10 + i)
		if _, err := st.RaiseAttention(t.Context(), store.RaiseInput{
			TriggerClass: "telemetry_degraded",
			Severity:     store.SeverityNeedsDecision,
			VMID:         &vm,
			Summary:      strings.Repeat("telemetry degraded on this vm; ", 4),
			SystemAction: "recorded",
			Collapse:     true,
			QueueMax:     500,
		}); err != nil {
			t.Fatal(err)
		}
	}

	resp, err := http.Get(srv.URL + "/api/v1/situation")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, raw)
	}
	if len(raw) > 700 {
		t.Errorf("response %d bytes exceeds situation_max_response_bytes 700", len(raw))
	}
	var got situationResponse
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	// Shrinking the head must not hide the queue: the full set stays
	// reachable via GET /attention.
	if len(got.AttentionHead) >= 8 {
		t.Errorf("head not shrunk: %d items in %d bytes", len(got.AttentionHead), len(raw))
	}
}
