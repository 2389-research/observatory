// ABOUTME: API tests for GET /events — the identifiers it publishes must be the
// ABOUTME: ones every other endpoint publishes, or nothing can be joined to anything.
package api_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/2389-research/observatory-v2/internal/api"
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

// TestEventsTailReturnsTheNewestPage covers the read a "recent operations"
// panel makes. Without it the panel's only honest options are to show the
// oldest page under the word "recent" or to walk the entire history, and a
// bounded API exists precisely so nobody has to do the second one.
func TestEventsTailReturnsTheNewestPage(t *testing.T) {
	srv, _, _ := newTemplateServer(t)

	for i := 0; i < 4; i++ {
		doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms",
			map[string]any{"name": fmt.Sprintf("tail-vm-%d", i), "template_id": testTemplateDef.TemplateID},
			http.StatusCreated, nil)
	}

	// Provisioning keeps emitting while this test runs, so both reads are
	// bounded by the same cursor: the tail of a fixed range, not a moving one.
	var all, tail eventsPage
	getJSON(t, srv.URL+"/api/v1/events?limit=1000", http.StatusOK, &all)
	if len(all.Events) < 5 {
		t.Fatalf("only %d events after four creates; nothing to take a tail of", len(all.Events))
	}
	bound := all.NextAfter
	getJSON(t, srv.URL+"/api/v1/events?tail=true&limit=3&until="+bound, http.StatusOK, &tail)

	if len(tail.Events) != 3 {
		t.Fatalf("tail page = %d events, want 3", len(tail.Events))
	}
	want := all.Events[len(all.Events)-3:]
	for i := range want {
		if tail.Events[i].EventID != want[i].EventID {
			t.Errorf("tail[%d] = %s, want %s; a tail page is the last events, oldest-first",
				i, tail.Events[i].EventID, want[i].EventID)
		}
	}
	if tail.NextAfter != bound {
		t.Errorf("tail next_after = %q, want %q: the cursor must point past the newest event on the page",
			tail.NextAfter, bound)
	}

	// tail is a boolean; a value that is not one teaches rather than guessing.
	var e api.Error
	getJSON(t, srv.URL+"/api/v1/events?tail=yes", http.StatusBadRequest, &e)
	requireTeaching(t, e, "malformed_request")
}

type eventsPage struct {
	Events []struct {
		EventID string         `json:"event_id"`
		Kind    string         `json:"kind"`
		Data    map[string]any `json:"data"`
	} `json:"events"`
	NextAfter     string `json:"next_after"`
	LatestEventID string `json:"latest_event_id"`
}
