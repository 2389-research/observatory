// ABOUTME: API tests for POST /vm-batches and GET /vm-batches/{id}.
// ABOUTME: Covers admission, refusal, idempotency, replay, and error shapes.
package api_test

import (
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

	var e api.Error
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vm-batches",
		batchBody("atomic_reservation", "keep_successful", "vm-x"),
		http.StatusServiceUnavailable, &e)
	requireTeaching(t, e, "runtime_unavailable")
}

func TestCreateBatchUnknownTemplate(t *testing.T) {
	srv, _, _ := newTemplateServer(t)

	body := map[string]any{
		"members":          []any{map[string]any{"name": "vm-x", "template_id": "no-such-tpl"}},
		"reservation_mode": "atomic_reservation",
		"on_failure":       "keep_successful",
	}
	var e api.Error
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vm-batches", body,
		http.StatusUnprocessableEntity, &e)
	requireTeaching(t, e, "template_unknown")
}

func TestCreateBatchTooLarge(t *testing.T) {
	srv, _, _ := newTemplateServer(t)

	names := make([]string, api.MaxBatchSize+1)
	for i := range names {
		names[i] = "vm"
	}
	var e api.Error
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vm-batches",
		batchBody("atomic_reservation", "keep_successful", names...),
		http.StatusBadRequest, &e)
	requireTeaching(t, e, "malformed_request")
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

	var second map[string]any
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vm-batches", body, http.StatusOK, &second)

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
