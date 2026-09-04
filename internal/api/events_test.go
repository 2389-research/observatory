// ABOUTME: API tests for GET /events — the identifiers it publishes must be the
// ABOUTME: ones every other endpoint publishes, or nothing can be joined to anything.
package api_test

import (
	"net/http"
	"testing"
)

// TestOperationEventNamesTheOperationTheAPIPublishes pins the identifier in an
// operation.state_changed event to the one every operation reply carries. Two
// spellings of one operation — "9" in the stream and "op-000009" in the create
// reply — leave a reader unable to join an event to the operation it describes,
// and a UI showing both would be inventing the link (SPEC §13, P-03).
func TestOperationEventNamesTheOperationTheAPIPublishes(t *testing.T) {
	srv, _, _ := newTemplateServer(t)

	var created struct {
		Operation struct {
			OperationID string `json:"operation_id"`
		} `json:"operation"`
	}
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms",
		map[string]any{"name": "op-id-vm", "template_id": testTemplateDef.TemplateID},
		http.StatusCreated, &created)
	if created.Operation.OperationID == "" {
		t.Fatal("create reply carried no operation id")
	}

	var page struct {
		Events []struct {
			Kind string         `json:"kind"`
			Data map[string]any `json:"data"`
		} `json:"events"`
	}
	getJSON(t, srv.URL+"/api/v1/events?kind=operation.state_changed&limit=50", http.StatusOK, &page)
	if len(page.Events) == 0 {
		t.Fatal("no operation.state_changed events after a create")
	}

	found := false
	for _, e := range page.Events {
		if e.Data["operation_id"] == created.Operation.OperationID {
			found = true
		}
	}
	if !found {
		ids := make([]any, 0, len(page.Events))
		for _, e := range page.Events {
			ids = append(ids, e.Data["operation_id"])
		}
		t.Errorf("no event names operation %q; the stream says %v",
			created.Operation.OperationID, ids)
	}
}
