// ABOUTME: Delivers bounded SSE replay/live events from the durable ingestion cursor.
// ABOUTME: Revalidates credentials and bounds concurrent readers and blocked writes.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/2389-research/observatory/internal/auth"
	"github.com/2389-research/observatory/internal/store"
)

const (
	eventStreamPageLimit    = 32
	eventStreamConnections  = 32
	eventStreamPoll         = 250 * time.Millisecond
	eventStreamHeartbeat    = 15 * time.Second
	eventStreamWriteTimeout = 5 * time.Second
	// One frame at a time; this allows framing/HTML escaping above the spool's
	// 256 KiB body limit and rejects unexpectedly large host-generated events.
	eventStreamFrameLimit = 1 << 20
)

func (s *Server) handleEventsStream(w http.ResponseWriter, r *http.Request) {
	q, ok := parseEventQuery(w, r)
	if !ok {
		return
	}
	if q.Until != "" {
		writeError(w, http.StatusBadRequest, Error{Code: "malformed_request", Message: "until freezes history; use /events for a finite page", Cause: "conflicting_filters"})
		return
	}
	if q.Limit == 0 {
		q.Limit = eventStreamPageLimit
	}
	if q.Limit < 1 || q.Limit > eventStreamPageLimit {
		writeQueryError(w, &store.BoundError{Requested: q.Limit, Max: eventStreamPageLimit})
		return
	}
	// EventSource retains the URL across reconnects. Its latest dispatched id
	// supersedes the URL's original starting cursor; never rewind to that URL.
	if cursor := r.Header.Get("Last-Event-ID"); cursor != "" {
		q.After = cursor
		q.Tail = false
	}
	if s.eventStreams.Add(1) > eventStreamConnections {
		s.eventStreams.Add(-1)
		writeError(w, http.StatusServiceUnavailable, Error{Code: "capacity_exhausted", Message: "too many event streams; close an existing stream before reconnecting", Cause: "event_stream_limit", Retryable: true, Details: map[string]any{"max": eventStreamConnections}})
		return
	}
	defer s.eventStreams.Add(-1)
	page, err := s.store.Query(r.Context(), q)
	if err != nil {
		writeQueryError(w, err)
		return
	}
	rc := http.NewResponseController(w)
	if err := rc.SetWriteDeadline(time.Now().Add(eventStreamWriteTimeout)); err != nil {
		writeError(w, http.StatusServiceUnavailable, Error{Code: "missing_capability", Message: "this HTTP transport cannot bound stream writes", Cause: "stream_deadline_unsupported"})
		return
	}
	defer func() { _ = rc.SetWriteDeadline(time.Time{}) }()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := writeEventFrame(w, rc, ": connected\n\n"); err != nil {
		return
	}
	ticker := time.NewTicker(eventStreamPoll)
	defer ticker.Stop()
	heartbeat := time.Now().Add(eventStreamHeartbeat)
	for {
		for _, env := range page.Events {
			if r.Context().Err() != nil {
				return
			}
			if !s.eventStreamAuthenticated(r) {
				writeStreamFailure(w, rc, "unauthenticated", "stream credentials are no longer valid", "credentials_invalid", false)
				return
			}
			body, err := json.Marshal(env)
			if err != nil || len(body)+len(*env.EventID)+len("id: \ndata: \n\n") > eventStreamFrameLimit {
				writeStreamFailure(w, rc, "limit_exceeded", "an event exceeds the stream frame bound", "event_stream_frame_limit", false)
				return
			}
			// Store.Query supplies decimal IDs, and JSON escapes embedded newlines.
			// Advance only after the complete frame flushes. Reconnect uses the last
			// frame the client dispatched, so a partially sent event is replayed.
			if err := writeEventFrame(w, rc, "id: "+*env.EventID+"\ndata: "+string(body)+"\n\n"); err != nil {
				return
			}
			q.After = *env.EventID
		}
		q.Tail = false
		if r.Context().Err() != nil {
			return
		}
		if !s.eventStreamAuthenticated(r) {
			writeStreamFailure(w, rc, "unauthenticated", "stream credentials are no longer valid", "credentials_invalid", false)
			return
		}
		if len(page.Events) < q.Limit {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
			}
		}
		if time.Now().After(heartbeat) {
			// Comments carry no id: quiet or filtered-out events never advance the
			// consumer's durable cursor or claim it processed data it has not seen.
			if err := writeEventFrame(w, rc, ": keepalive\n\n"); err != nil {
				return
			}
			heartbeat = time.Now().Add(eventStreamHeartbeat)
		}
		page, err = s.store.Query(r.Context(), q)
		if err != nil {
			if r.Context().Err() == nil {
				writeStreamFailure(w, rc, "internal", "event query failed in storage", "storage_failure", true)
			}
			return
		}
	}
}

func writeEventFrame(w http.ResponseWriter, rc *http.ResponseController, frame string) error {
	if err := rc.SetWriteDeadline(time.Now().Add(eventStreamWriteTimeout)); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, frame); err != nil {
		return err
	}
	if err := rc.Flush(); err != nil {
		return err
	}
	// Do not leave an expired deadline on an idle HTTP/2 stream. Each later
	// frame installs its own deadline instead of inheriting the server timeout.
	return rc.SetWriteDeadline(time.Time{})
}
func writeStreamFailure(w http.ResponseWriter, rc *http.ResponseController, code, message, cause string, retry bool) {
	strategy := "never"
	if retry {
		strategy = "same_request"
	}
	body, _ := json.Marshal(Error{Code: code, Message: message, Cause: cause, Retryable: retry, RetryStrategy: strategy})
	_ = writeEventFrame(w, rc, "event: stream_error\ndata: "+string(body)+"\n\n")
}

// Event reads deliberately retain the established shared-host scope. Credential
// rechecks prevent an expired/revoked session or token outliving authentication.
func (s *Server) eventStreamAuthenticated(r *http.Request) bool {
	if !s.auth.ac.Enabled {
		return true
	}
	ident, ok := auth.IdentityFrom(r.Context())
	if !ok {
		return false
	}
	switch ident.Method {
	case "session":
		sess, ok := s.auth.ac.Sessions.Get(ident.SessionID)
		return ok && sess.Owner == ident.Owner
	case "token":
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			return false
		}
		token, err := s.auth.ac.Creds.VerifyToken(strings.TrimPrefix(header, "Bearer "))
		return err == nil && token.ID == ident.TokenID && token.Owner == ident.Owner
	default:
		return false
	}
}
