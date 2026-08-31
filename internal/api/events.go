// ABOUTME: GET /events: bounded keyset pages over the store, with query errors
// ABOUTME: mapped to structured teaching responses.
package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/2389-research/observatory-v2/internal/events"
	"github.com/2389-research/observatory-v2/internal/store"
)

type eventsResponse struct {
	Events        []*events.Envelope `json:"events"`
	NextAfter     string             `json:"next_after"`
	LatestEventID string             `json:"latest_event_id"`
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := store.Query{}
	params := r.URL.Query()

	if vm := params.Get("vm_id"); vm != "" {
		if !events.UUIDString(vm) {
			writeError(w, http.StatusBadRequest, Error{
				Code:      "malformed_request",
				Message:   fmt.Sprintf("vm_id %q is not a lowercase uuid", vm),
				Retryable: false,
				Cause:     "query_parameter_invalid",
			})
			return
		}
		q.VMID = &vm
	}
	if kind := params.Get("kind"); kind != "" {
		if _, ok := events.LookupKind(kind); !ok {
			writeError(w, http.StatusBadRequest, Error{
				Code:      "malformed_request",
				Message:   fmt.Sprintf("kind %q is not registered, so no event can match it", kind),
				Retryable: false,
				Cause:     "kind_unregistered",
				Remediation: []Remediation{{
					Action:    "get",
					Params:    map[string]any{"path": basePath + "/meta/event-kinds"},
					Rationale: "the registry lists every kind this build can store, with semantics and caveats",
				}},
			})
			return
		}
		q.Kind = kind
	}
	if raw := params.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, Error{
				Code:      "malformed_request",
				Message:   fmt.Sprintf("limit %q is not an integer", raw),
				Retryable: false,
				Cause:     "query_parameter_invalid",
			})
			return
		}
		q.Limit = limit
	}
	q.After = params.Get("after")

	result, err := s.store.Query(r.Context(), q)
	if err != nil {
		writeQueryError(w, err)
		return
	}
	resp := eventsResponse{
		Events:        result.Events,
		NextAfter:     result.NextAfter,
		LatestEventID: result.LatestEventID,
	}
	if resp.Events == nil {
		resp.Events = []*events.Envelope{}
	}
	writeJSON(w, http.StatusOK, resp)
}

func writeQueryError(w http.ResponseWriter, err error) {
	var bound *store.BoundError
	switch {
	case errors.As(err, &bound):
		writeError(w, http.StatusBadRequest, Error{
			Code:      "limit_exceeded",
			Message:   err.Error(),
			Retryable: false,
			Cause:     "limit_out_of_bounds",
			Details:   map[string]any{"requested": bound.Requested, "max": bound.Max},
			Remediation: []Remediation{{
				Action:    "retry_with_limit",
				Params:    map[string]any{"limit": bound.Max},
				Rationale: "pages are bounded; walk larger ranges with repeated after cursors",
			}},
		})
	case errors.Is(err, store.ErrInvalidCursor):
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   err.Error(),
			Retryable: false,
			Cause:     "cursor_invalid",
			Remediation: []Remediation{{
				Action:    "retry_with_cursor",
				Params:    map[string]any{"after": "next_after from a previous page"},
				Rationale: "cursors are opaque decimal event ids issued by the store, not client-invented values",
			}},
		})
	default:
		writeError(w, http.StatusInternalServerError, Error{
			Code:      "internal",
			Message:   "event query failed in storage",
			Retryable: true,
			Cause:     "storage_failure",
		})
	}
}
