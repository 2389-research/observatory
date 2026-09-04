// ABOUTME: API tests for POST /vm-batches and GET /vm-batches/{id}.
// ABOUTME: Covers admission, refusal, idempotency, replay, and error shapes.
package api_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/2389-research/observatory-v2/internal/api"
	"github.com/2389-research/observatory-v2/internal/runtime"
)

// batchBody builds a valid minimal batch body for the named template.
func batchBody(mode, onFailure string, names ...string) map[string]any {
	members := make([]map[string]any, len(names))
	for i, n := range names {
		members[i] = map[string]any{
			"name":        n,
			"template_id": testTemplateDef.TemplateID,
		}
	}
	return map[string]any{
		"members":          members,
		"reservation_mode": mode,
		"on_failure":       onFailure,
	}
}

func TestCreateBatchAtomicAdmit(t *testing.T) {
	srv, _, _ := newTemplateServer(t)

	var resp map[string]any
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vm-batches",
		batchBody("atomic_reservation", "keep_successful", "vm-alpha", "vm-beta"),
		http.StatusCreated, &resp)

	batchID, _ := resp["batch"].(map[string]any)["batch_id"].(string)
	if batchID == "" {
		t.Fatalf("response missing batch.batch_id: %v", resp)
	}
	op, _ := resp["operation"].(map[string]any)
	if op["state"] != "running" {
		t.Errorf("batch op state = %v, want running", op["state"])
	}
	members, _ := resp["members"].([]any)
	if len(members) != 2 {
		t.Fatalf("members count = %d, want 2", len(members))
	}
	for i, raw := range members {
		m := raw.(map[string]any)
		if m["vm"] == nil {
			t.Errorf("member %d: vm should be present after admission", i)
		}
		if m["refusal"] != nil {
			t.Errorf("member %d: unexpected refusal %v", i, m["refusal"])
		}
	}
}

func TestCreateBatchUnavailableRuntime(t *testing.T) {
	srv, _, fake := newTemplateServer(t)

	fake.FailNext("Availability", "", &runtime.UnavailableError{Reason: "test-unavailable"})

	// Same contract as single-VM create (AT-001): an unavailable runtime is a
	// missing capability (501), not a transient 503.
	var e api.Error
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vm-batches",
		batchBody("atomic_reservation", "keep_successful", "vm-x"),
		http.StatusNotImplemented, &e)
	requireTeaching(t, e, "missing_capability")
}

func TestCreateBatchUnknownTemplate(t *testing.T) {
	srv, _, _ := newTemplateServer(t)

	body := map[string]any{
		"members":          []any{map[string]any{"name": "vm-x", "template_id": "no-such-tpl"}},
		"reservation_mode": "atomic_reservation",
		"on_failure":       "keep_successful",
	}
	// Same contract as single-VM create: unknown template is a 400.
	var e api.Error
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vm-batches", body,
		http.StatusBadRequest, &e)
	requireTeaching(t, e, "template_unknown")
}

func TestCreateBatchTooLarge(t *testing.T) {
	srv, _, _ := newTemplateServer(t)

	names := make([]string, api.DefaultMaxBatchSize+1)
	for i := range names {
		names[i] = "vm"
	}
	var e api.Error
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vm-batches",
		batchBody("atomic_reservation", "keep_successful", names...),
		http.StatusBadRequest, &e)
	requireTeaching(t, e, "malformed_request")
}

// TestBatchSizeCapIsTheConfiguredOne pins SPEC §6.3's limits table ("Batch
// size limit: 8 per request") to the host's own admission config rather than a
// constant in this package. Two different numbers under the name
// max_batch_size — one in GET /meta, one in GET /host/status — would leave the
// UI warning at a threshold the daemon does not enforce.
func TestBatchSizeCapIsTheConfiguredOne(t *testing.T) {
	adm := testAdmission()
	adm.MaxBatchSize = 3
	srv, _, _ := newTemplateServerAdmission(t, adm)

	var meta struct {
		Limits map[string]int64 `json:"limits"`
	}
	getJSON(t, srv.URL+"/api/v1/meta", http.StatusOK, &meta)
	if meta.Limits["max_batch_size"] != 3 {
		t.Errorf("meta limits max_batch_size = %d; want the configured 3", meta.Limits["max_batch_size"])
	}

	var status struct {
		Admission struct {
			MaxBatchSize int `json:"max_batch_size"`
		} `json:"admission"`
	}
	getJSON(t, srv.URL+"/api/v1/host/status", http.StatusOK, &status)
	if int64(status.Admission.MaxBatchSize) != meta.Limits["max_batch_size"] {
		t.Errorf("host/status says %d and meta says %d; one name, one number",
			status.Admission.MaxBatchSize, meta.Limits["max_batch_size"])
	}

	var e api.Error
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vm-batches",
		batchBody("atomic_reservation", "keep_successful", "a", "b", "c", "d"),
		http.StatusBadRequest, &e)
	requireTeaching(t, e, "malformed_request")
	if e.Cause != "batch_too_large" {
		t.Errorf("cause = %q; want batch_too_large", e.Cause)
	}

	// Exactly at the cap is admitted: the refusal is for more than the cap.
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vm-batches",
		batchBody("atomic_reservation", "keep_successful", "a", "b", "c"),
		http.StatusCreated, nil)
}

// TestBatchSizeCapUnconfiguredIsTheSpecDefault covers the host that never set
// max_batch_size. The published number must be the one the API enforces, so a
// zero in the config cannot become a zero on the wire.
func TestBatchSizeCapUnconfiguredIsTheSpecDefault(t *testing.T) {
	adm := testAdmission()
	adm.MaxBatchSize = 0
	srv, _, _ := newTemplateServerAdmission(t, adm)

	var status struct {
		Admission struct {
			MaxBatchSize int `json:"max_batch_size"`
		} `json:"admission"`
	}
	getJSON(t, srv.URL+"/api/v1/host/status", http.StatusOK, &status)
	if status.Admission.MaxBatchSize != api.DefaultMaxBatchSize {
		t.Errorf("host/status max_batch_size = %d; want the enforced default %d",
			status.Admission.MaxBatchSize, api.DefaultMaxBatchSize)
	}

	var meta struct {
		Limits map[string]int64 `json:"limits"`
	}
	getJSON(t, srv.URL+"/api/v1/meta", http.StatusOK, &meta)
	if meta.Limits["max_batch_size"] != int64(api.DefaultMaxBatchSize) {
		t.Errorf("meta max_batch_size = %d; want %d", meta.Limits["max_batch_size"], api.DefaultMaxBatchSize)
	}

	names := make([]string, api.DefaultMaxBatchSize+1)
	for i := range names {
		names[i] = fmt.Sprintf("vm-%d", i)
	}
	var e api.Error
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vm-batches",
		batchBody("atomic_reservation", "keep_successful", names...),
		http.StatusBadRequest, &e)
	if e.Cause != "batch_too_large" {
		t.Errorf("cause = %q; want batch_too_large", e.Cause)
	}
	// JSON numbers decode as float64; compare as text so 8 and 8.0 agree.
	if got := e.Details["max_batch_size"]; fmt.Sprint(got) != fmt.Sprint(api.DefaultMaxBatchSize) {
		t.Errorf("error details max_batch_size = %v; want %d", got, api.DefaultMaxBatchSize)
	}
}

func TestCreateBatchEmpty(t *testing.T) {
	srv, _, _ := newTemplateServer(t)

	var e api.Error
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vm-batches",
		map[string]any{"members": []any{}, "reservation_mode": "atomic_reservation", "on_failure": "keep_successful"},
		http.StatusBadRequest, &e)
	requireTeaching(t, e, "malformed_request")
}

func TestCreateBatchIdempotentReplay(t *testing.T) {
	srv, _, _ := newTemplateServer(t)
	body := batchBody("atomic_reservation", "keep_successful", "vm-idem-a")
	ikey := "test-batch-idem"
	body["idempotency_key"] = ikey

	var first map[string]any
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vm-batches", body, http.StatusCreated, &first)

	// Replays are retry-transparent: same 201 as the original, is_replay in
	// the body carries the truth.
	var second map[string]any
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vm-batches", body, http.StatusCreated, &second)

	if second["is_replay"] != true {
		t.Errorf("second response is_replay = %v, want true", second["is_replay"])
	}
	firstID := first["batch"].(map[string]any)["batch_id"]
	secondID := second["batch"].(map[string]any)["batch_id"]
	if firstID != secondID {
		t.Errorf("replay batch_id %v != original %v", secondID, firstID)
	}
}

func TestCreateBatchIdempotencyConflict(t *testing.T) {
	srv, _, _ := newTemplateServer(t)
	ikey := "conflict-batch-key"

	body1 := batchBody("atomic_reservation", "keep_successful", "vm-conflict-a")
	body1["idempotency_key"] = ikey
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vm-batches", body1, http.StatusCreated, nil)

	body2 := batchBody("best_effort", "stop_successful", "vm-conflict-b")
	body2["idempotency_key"] = ikey
	var e api.Error
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vm-batches", body2,
		http.StatusConflict, &e)
	requireTeaching(t, e, "idempotency_conflict")
}

func TestGetBatchFound(t *testing.T) {
	srv, _, _ := newTemplateServer(t)

	var created map[string]any
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vm-batches",
		batchBody("atomic_reservation", "keep_successful", "vm-get-a"),
		http.StatusCreated, &created)

	batchID := created["batch"].(map[string]any)["batch_id"].(string)

	var got map[string]any
	doRequest(t, http.MethodGet, srv.URL+"/api/v1/vm-batches/"+batchID, nil, http.StatusOK, &got)

	if got["batch"].(map[string]any)["batch_id"] != batchID {
		t.Errorf("GET returned different batch_id: %v", got)
	}
	if len(got["members"].([]any)) != 1 {
		t.Errorf("GET members = %d, want 1", len(got["members"].([]any)))
	}
}

func TestGetBatchNotFound(t *testing.T) {
	srv, _, _ := newTemplateServer(t)

	var e api.Error
	doRequest(t, http.MethodGet, srv.URL+"/api/v1/vm-batches/batch-999999", nil,
		http.StatusNotFound, &e)
	requireTeaching(t, e, "not_found")
}

func TestGetBatchMalformedID(t *testing.T) {
	srv, _, _ := newTemplateServer(t)

	var e api.Error
	doRequest(t, http.MethodGet, srv.URL+"/api/v1/vm-batches/not-a-batch-id", nil,
		http.StatusNotFound, &e)
	requireTeaching(t, e, "not_found")
}
