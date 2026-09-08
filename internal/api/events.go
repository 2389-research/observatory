// ABOUTME: GET /events: bounded keyset pages over the store, with query errors
// ABOUTME: mapped to structured teaching responses.
package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/2389-research/observatory/internal/events"
	"github.com/2389-research/observatory/internal/store"
)

type eventsResponse struct {
	Events        []*events.Envelope `json:"events"`
	NextAfter     string             `json:"next_after"`
	LatestEventID string             `json:"latest_event_id"`
}

func parseEventQuery(w http.ResponseWriter, r *http.Request) (store.Query, bool) {
	q := store.Query{}
	params := r.URL.Query()

	for _, filter := range []struct {
		name   string
		target **string
	}{{"vm_id", &q.VMID}, {"boot_id", &q.BootID}} {
		if value := params.Get(filter.name); value != "" {
			if !events.UUIDString(value) {
				writeError(w, http.StatusBadRequest, Error{
					Code: "malformed_request", Message: fmt.Sprintf("%s %q is not a lowercase uuid", filter.name, value),
					Retryable: false, Cause: "query_parameter_invalid",
				})
				return q, false
			}
			*filter.target = &value
		}
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
			return q, false
		}
		q.Kind = kind
	}
	if family := params.Get("family"); family != "" {
		if q.Kind != "" {
			writeError(w, http.StatusBadRequest, Error{
				Code:      "malformed_request",
				Message:   "kind and family are mutually exclusive; set one axis at a time",
				Retryable: false,
				Cause:     "conflicting_filters",
				Remediation: []Remediation{{
					Action:    "get",
					Params:    map[string]any{"path": basePath + "/meta/event-kinds"},
					Rationale: "each kind entry lists its family; filter by kind for a single kind or by family for all kinds in a group",
				}},
			})
			return q, false
		}
		if events.KindsByFamily(family) == nil {
			writeError(w, http.StatusBadRequest, Error{
				Code:      "malformed_request",
				Message:   fmt.Sprintf("family %q has no registered kinds, so no event can match it", family),
				Retryable: false,
				Cause:     "family_unknown",
				Remediation: []Remediation{{
					Action:    "get",
					Params:    map[string]any{"path": basePath + "/meta/event-kinds"},
					Rationale: "the registry lists every kind and its family; only registered families match events",
				}},
			})
			return q, false
		}
		q.Family = family
	}
	if raw := params.Get("until"); raw != "" {
		if !events.DecimalString(raw) {
			writeError(w, http.StatusBadRequest, Error{
				Code:      "malformed_request",
				Message:   fmt.Sprintf("until %q is not a decimal event_id", raw),
				Retryable: false,
				Cause:     "query_parameter_invalid",
				Remediation: []Remediation{{
					Action:    "retry_with_cursor",
					Params:    map[string]any{"until": "latest_event_id from a previous page"},
					Rationale: "cursors are opaque decimal event ids issued by the store, not client-invented values",
				}},
			})
			return q, false
		}
		q.Until = raw
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
			return q, false
		}
		q.Limit = limit
	}
	// Strict, unlike the destructive force= flag whose safe reading of a typo
	// is "no". A misspelled tail= that quietly meant false would hand back the
	// oldest page to a caller who asked for the newest, and nothing in the
	// response would say so.
	if raw := params.Get("tail"); raw != "" {
		switch raw {
		case "true":
			q.Tail = true
		case "false":
		default:
			writeError(w, http.StatusBadRequest, Error{
				Code:      "malformed_request",
				Message:   fmt.Sprintf("tail %q is not true or false", raw),
				Retryable: false,
				Cause:     "query_parameter_invalid",
				Remediation: []Remediation{{
					Action:    "get",
					Params:    map[string]any{"path": basePath + "/events", "tail": "true"},
					Rationale: "tail=true returns the newest page in the range; leaving it off pages forward from after",
				}},
			})
			return q, false
		}
	}
	q.After = params.Get("after")

	return q, true
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q, ok := parseEventQuery(w, r)
	if !ok {
		return
	}

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
	case errors.Is(err, store.ErrUnknownFamily):
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   err.Error(),
			Retryable: false,
			Cause:     "family_unknown",
			Remediation: []Remediation{{
				Action:    "get",
				Params:    map[string]any{"path": basePath + "/meta/event-kinds"},
				Rationale: "the registry lists every kind and its family; only registered families match events",
			}},
		})
	case errors.Is(err, store.ErrConflictingFilters):
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   err.Error(),
			Retryable: false,
			Cause:     "conflicting_filters",
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
