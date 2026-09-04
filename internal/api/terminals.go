// ABOUTME: The terminal session routes — create, list, close and writer lease —
// ABOUTME: over the host's one terminal registry (SPEC §8.1, §8.2, §14).
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/2389-research/observatory-v2/internal/auth"
	"github.com/2389-research/observatory-v2/internal/events"
	"github.com/2389-research/observatory-v2/internal/terminal"
)

const (
	// defaultTerminalRows and defaultTerminalCols are the window a caller that
	// names none gets. The guest refuses a zero-sized PTY, so this is a real
	// default rather than a placeholder.
	defaultTerminalRows uint16 = 24
	defaultTerminalCols uint16 = 80

	// defaultTerminalTerm is what the guest advertises in TERM. xterm-256color
	// is what xterm.js implements, and this API's only browser is xterm.js.
	defaultTerminalTerm = "xterm-256color"

	// terminalListDefaultLimit and terminalListMaxLimit bound the session list.
	// They are small because the per-VM cap is small: a page larger than the
	// cap could never fill.
	terminalListDefaultLimit = 50
	terminalListMaxLimit     = 200
)

// defaultTerminalArgv is the shell a create without an argv gets. The guest
// broker requires an absolute path and execs the array directly — no host or
// guest shell interprets it (§8.1) — so the default names the one shell a
// POSIX image is guaranteed to have at a fixed path. A caller wanting bash
// asks for bash.
func defaultTerminalArgv() []string { return []string{"/bin/sh", "-i"} }

// terminalCreateBody is POST /vms/{id}/terminals. Every field is optional;
// what a browser must supply is nothing, and what it may supply is the shell.
type terminalCreateBody struct {
	Rows uint16   `json:"rows"`
	Cols uint16   `json:"cols"`
	Argv []string `json:"argv"`
	User string   `json:"user"`
	Cwd  string   `json:"cwd"`
	Term string   `json:"term"`
}

// terminalLeaseBody is POST /terminals/{id}/lease. ConnID is required: the
// lease is held by a connection (§8.2), and a request naming no connection
// could only hand the shell to nobody.
type terminalLeaseBody struct {
	Mode   string `json:"mode"`
	ConnID string `json:"conn_id"`
}

// wireTerminal is one session as the API publishes it. The byte counts are
// decimal strings: a busy shell passes 2^53 bytes in days (P-06).
type wireTerminal struct {
	SessionID string   `json:"session_id"`
	VMID      string   `json:"vm_id"`
	BootID    string   `json:"boot_id"`
	Owner     string   `json:"owner"`
	State     string   `json:"state"`
	Rows      uint16   `json:"rows"`
	Cols      uint16   `json:"cols"`
	Argv      []string `json:"argv"`
	PID       int      `json:"pid"`
	CreatedAt string   `json:"created_at"`

	OutputBytes string `json:"output_bytes"`
	InputBytes  string `json:"input_bytes"`

	// WriterHolder names the connection that may type, and WriterAvailable
	// says whether a new connection could take the lease without stealing.
	WriterHolder    string `json:"writer_holder"`
	WriterAvailable bool   `json:"writer_available"`

	ClosedAt string `json:"closed_at,omitempty"`
	Reason   string `json:"reason,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
	Signal   string `json:"signal,omitempty"`

	Links map[string]string `json:"links"`
}

func renderTerminal(s terminal.Session) wireTerminal {
	out := wireTerminal{
		SessionID:       s.ID,
		VMID:            s.VMID,
		BootID:          s.BootID,
		Owner:           s.Owner,
		State:           string(s.State),
		Rows:            s.Rows,
		Cols:            s.Cols,
		Argv:            s.Argv,
		PID:             s.PID,
		CreatedAt:       s.CreatedAt.Format(time.RFC3339Nano),
		OutputBytes:     strconv.FormatUint(s.OutputBytes, 10),
		InputBytes:      strconv.FormatUint(s.InputBytes, 10),
		WriterHolder:    s.WriterHolder,
		WriterAvailable: s.WriterHolder == "" && s.State == terminal.StateOpen,
		Reason:          s.Reason,
		ExitCode:        s.ExitCode,
		Signal:          s.Signal,
		Links: map[string]string{
			"self":   basePath + "/terminals/" + s.ID,
			"stream": basePath + "/terminals/" + s.ID + "/stream",
			"lease":  basePath + "/terminals/" + s.ID + "/lease",
			"vm":     basePath + "/vms/" + s.VMID,
		},
	}
	if out.Argv == nil {
		out.Argv = []string{}
	}
	if !s.ClosedAt.IsZero() {
		out.ClosedAt = s.ClosedAt.Format(time.RFC3339Nano)
	}
	return out
}

// --- handlers ---

func (s *Server) handleCreateTerminal(w http.ResponseWriter, r *http.Request) {
	vmID := r.PathValue("id")

	// Fetch, then check ownership, then read the body: a denied request must
	// have created nothing and asked the guest for nothing (AT-079).
	vm, err := s.store.GetVM(r.Context(), vmID)
	if err != nil {
		writeVMError(w, err)
		return
	}
	if !s.resourceOwner(w, r, vm.Owner) {
		return
	}
	if vm.ObservedState != "running" {
		writeError(w, http.StatusConflict, Error{
			Code:      "vm_not_running",
			Message:   fmt.Sprintf("VM %s is %s; a terminal needs a running guest to allocate a PTY in", vmID, vm.ObservedState),
			Retryable: false,
			Cause:     "vm_state_conflict",
			Details: map[string]any{
				"observed_state": vm.ObservedState,
				"desired_state":  vm.DesiredState,
			},
			Remediation: []Remediation{{
				Action:    "post",
				Params:    map[string]any{"path": basePath + "/vms/" + vmID + "/actions", "body": map[string]string{"action": "start"}},
				Rationale: "start the VM, then open the terminal once it reports running",
			}},
		})
		return
	}

	body, ok := decodeTerminalBody[terminalCreateBody](w, r, "terminal create")
	if !ok {
		return
	}
	spec := terminal.Spec{
		Owner: vm.Owner,
		User:  body.User,
		Cwd:   body.Cwd,
		Argv:  body.Argv,
		Term:  body.Term,
		Rows:  body.Rows,
		Cols:  body.Cols,
	}
	if len(spec.Argv) == 0 {
		spec.Argv = defaultTerminalArgv()
	}
	if spec.Term == "" {
		spec.Term = defaultTerminalTerm
	}
	if spec.Rows == 0 {
		spec.Rows = defaultTerminalRows
	}
	if spec.Cols == 0 {
		spec.Cols = defaultTerminalCols
	}

	// The cap counts sessions that are open now. A closed session holds no
	// guest PTY, so counting it would refuse a terminal the host can serve.
	max := s.manager.DefaultParams().MaxTerminalSessions
	open := 0
	for _, existing := range s.terminals.ListForVM(vmID) {
		if existing.State == terminal.StateOpen {
			open++
		}
	}
	if max > 0 && open >= max {
		writeError(w, http.StatusConflict, Error{
			Code:      "terminal_limit_reached",
			Message:   fmt.Sprintf("VM %s already has %d of %d terminal sessions open", vmID, open, max),
			Retryable: false,
			Cause:     "terminal_session_cap",
			Details: map[string]any{
				"max_terminal_sessions": max,
				"open_sessions":         open,
			},
			Remediation: []Remediation{{
				Action:    "delete",
				Params:    map[string]any{"path": basePath + "/terminals/{id}"},
				Rationale: "close a session you are done with; list them at " + basePath + "/vms/" + vmID + "/terminals",
			}},
		})
		return
	}

	// A create that reached the guest must finish recording the PTY it started
	// even if the browser hangs up mid-flight; otherwise the session runs with
	// nobody holding its id.
	opCtx, cancel := s.manager.OperationContext(r.Context())
	defer cancel()
	sess, err := s.terminals.Create(opCtx, vmID, spec)
	if err != nil {
		writeTerminalError(w, "", err)
		return
	}

	if err := s.appendTerminalEvent(opCtx, "terminal.session_opened", sess, map[string]any{
		"session_id": sess.ID,
		"owner":      sess.Owner,
		"rows":       int(sess.Rows),
		"cols":       int(sess.Cols),
		"argv":       sess.Argv,
	}); err != nil {
		// The session exists whether or not its event landed. Losing the reply
		// would leave a live PTY nobody can address, which is worse than a gap
		// in the log that the log itself will show.
		logTerminalEventFailure("terminal.session_opened", sess.ID, err)
	}

	writeJSON(w, http.StatusCreated, renderTerminal(sess))
}

func (s *Server) handleListTerminals(w http.ResponseWriter, r *http.Request) {
	vmID := r.PathValue("id")
	vm, err := s.store.GetVM(r.Context(), vmID)
	if err != nil {
		writeVMError(w, err)
		return
	}
	if !s.resourceOwner(w, r, vm.Owner) {
		return
	}

	params := r.URL.Query()
	limit := terminalListDefaultLimit
	if raw := params.Get("limit"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, Error{
				Code:      "malformed_request",
				Message:   fmt.Sprintf("limit %q must be an integer", raw),
				Retryable: false,
				Cause:     "query_parameter_invalid",
				Remediation: []Remediation{{
					Action:    "get",
					Params:    map[string]any{"path": basePath + "/vms/" + vmID + "/terminals", "query": map[string]any{"limit": terminalListDefaultLimit}},
					Rationale: "limit is a count of sessions, at most " + strconv.Itoa(terminalListMaxLimit),
				}},
			})
			return
		}
		if v < 1 || v > terminalListMaxLimit {
			writeError(w, http.StatusBadRequest, Error{
				Code:      "malformed_request",
				Message:   fmt.Sprintf("limit %d outside 1..%d", v, terminalListMaxLimit),
				Retryable: false,
				Cause:     "limit_out_of_bounds",
				Details:   map[string]any{"requested": v, "max": terminalListMaxLimit},
				Remediation: []Remediation{{
					Action:    "get",
					Params:    map[string]any{"path": basePath + "/vms/" + vmID + "/terminals", "query": map[string]any{"limit": terminalListMaxLimit}},
					Rationale: "ask for at most the maximum and page with after",
				}},
			})
			return
		}
		limit = v
	}

	sessions := s.terminals.ListForVM(vmID)

	// The cursor is a session id from a previous page. An id this VM never had
	// is a caller reading someone else's cursor, and silently starting over
	// would hand back a page they already have.
	if after := params.Get("after"); after != "" {
		idx := -1
		for i, sess := range sessions {
			if sess.ID == after {
				idx = i
				break
			}
		}
		if idx < 0 {
			writeError(w, http.StatusBadRequest, Error{
				Code:      "malformed_request",
				Message:   fmt.Sprintf("after %q is not a session on VM %s", after, vmID),
				Retryable: false,
				Cause:     "cursor_invalid",
				Remediation: []Remediation{{
					Action:    "get",
					Params:    map[string]any{"path": basePath + "/vms/" + vmID + "/terminals"},
					Rationale: "read the first page and resume from its next_after",
				}},
			})
			return
		}
		sessions = sessions[idx+1:]
	}

	nextAfter := ""
	if len(sessions) > limit {
		sessions = sessions[:limit]
		nextAfter = sessions[len(sessions)-1].ID
	}

	out := make([]wireTerminal, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, renderTerminal(sess))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"terminals":  out,
		"next_after": nextAfter,
		"limit":      limit,
	})
}

func (s *Server) handleCloseTerminal(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	sess, ok := s.terminals.Get(sessionID)
	if !ok {
		writeTerminalNotFound(w, sessionID)
		return
	}
	if !s.terminalOwner(w, r, sess) {
		return
	}

	// Already closed: the caller's intent is satisfied. Asking the guest again
	// would be a round trip for a PTY that no longer exists, and emitting a
	// second closed event would double-count the session.
	if sess.State == terminal.StateClosed {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// A close that reached the guest must finish reaping the child even if the
	// browser hangs up: see Manager.OperationContext.
	opCtx, cancel := s.manager.OperationContext(r.Context())
	defer cancel()
	if err := s.terminals.Close(opCtx, sessionID); err != nil {
		writeTerminalError(w, sessionID, err)
		return
	}

	closed, ok := s.terminals.Get(sessionID)
	if !ok {
		closed = sess
	}
	data := map[string]any{
		"session_id": closed.ID,
		"reason":     closed.Reason,
		// Decimal strings: a busy shell passes 2^53 bytes in days (P-06).
		"output_bytes": strconv.FormatUint(closed.OutputBytes, 10),
		"input_bytes":  strconv.FormatUint(closed.InputBytes, 10),
	}
	// dropped_bytes has no source until the relay counts them (Task 12). An
	// absent field is honest; a fabricated zero is not.
	if closed.ExitCode != nil {
		data["exit_code"] = *closed.ExitCode
	}
	if closed.Signal != "" {
		data["signal"] = closed.Signal
	}
	if err := s.appendTerminalEvent(opCtx, "terminal.session_closed", closed, data); err != nil {
		logTerminalEventFailure("terminal.session_closed", closed.ID, err)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleTerminalLease(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	sess, ok := s.terminals.Get(sessionID)
	if !ok {
		writeTerminalNotFound(w, sessionID)
		return
	}
	if !s.terminalOwner(w, r, sess) {
		return
	}

	body, ok := decodeTerminalBody[terminalLeaseBody](w, r, "lease request")
	if !ok {
		return
	}
	if body.ConnID == "" {
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   "conn_id is required: the writer lease is held by a connection, and a request naming none could only grant it to nobody",
			Retryable: false,
			Cause:     "body_invalid",
			Remediation: []Remediation{{
				Action:    "post",
				Params:    map[string]any{"path": basePath + "/terminals/" + sessionID + "/lease", "body": map[string]string{"mode": "acquire", "conn_id": "{your connection id}"}},
				Rationale: "use the conn_id this client sends on its stream connection, so the lease follows the connection that types",
			}},
		})
		return
	}
	mode := terminal.LeaseMode(body.Mode)
	switch mode {
	case terminal.LeaseAcquire, terminal.LeaseSteal, terminal.LeaseRelease:
	default:
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   fmt.Sprintf("mode %q is not one of acquire, steal or release", body.Mode),
			Retryable: false,
			Cause:     "body_invalid",
			Details:   map[string]any{"modes": []string{"acquire", "steal", "release"}},
			Remediation: []Remediation{{
				Action:    "post",
				Params:    map[string]any{"path": basePath + "/terminals/" + sessionID + "/lease", "body": map[string]string{"mode": "acquire", "conn_id": body.ConnID}},
				Rationale: "acquire takes a free lease, steal takes it from its holder, release hands it back",
			}},
		})
		return
	}

	res, err := s.terminals.RequestLease(sessionID, body.ConnID, mode)
	if err != nil {
		writeTerminalError(w, sessionID, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": sessionID,
		"writer":     res.Writer,
		"holder":     res.Holder,
		"reason":     res.Reason,
	})
}

// --- shared plumbing ---

// decodeTerminalBody reads a bounded, strictly-typed request body. An absent
// body decodes to the zero value: every field on these requests is optional,
// so "no body" is a legitimate request rather than an error to teach about.
func decodeTerminalBody[T any](w http.ResponseWriter, r *http.Request, what string) (T, bool) {
	var body T
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   fmt.Sprintf("cannot decode %s body: %v", what, err),
			Retryable: false,
			Cause:     "body_invalid",
			Remediation: []Remediation{{
				Action:    "get",
				Params:    map[string]any{"path": basePath + "/meta"},
				Rationale: "the body is strict: unknown fields are rejected rather than ignored",
			}},
		})
		return body, false
	}
	return body, true
}

// terminalOwner denies a session belonging to another owner with exactly the
// answer an unknown session id gets. The sameness is the point: a distinct
// "forbidden" would tell a stranger which session ids exist (AT-079).
func (s *Server) terminalOwner(w http.ResponseWriter, r *http.Request, sess terminal.Session) bool {
	ident, ok := auth.IdentityFrom(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, Error{
			Code:      "internal",
			Message:   "no identity in context",
			Retryable: false,
			Cause:     "no_identity",
		})
		return false
	}
	if ident.Owner != sess.Owner {
		writeTerminalNotFound(w, sess.ID)
		return false
	}
	return true
}

// writeTerminalNotFound is the one 404 every session-addressed route uses.
func writeTerminalNotFound(w http.ResponseWriter, sessionID string) {
	writeError(w, http.StatusNotFound, Error{
		Code:      "not_found",
		Message:   fmt.Sprintf("no terminal session %s on this host", sessionID),
		Retryable: false,
		Cause:     "terminal_session_unknown",
		Remediation: []Remediation{{
			Action:    "get",
			Params:    map[string]any{"path": basePath + "/vms/{id}/terminals"},
			Rationale: "sessions live on a VM; list that VM's sessions to find the id. Sessions do not survive a host restart",
		}},
	})
}

// writeTerminalError maps a registry error's cause to a status. The cause is
// the registry's contract; this function is the only place it becomes HTTP.
func writeTerminalError(w http.ResponseWriter, sessionID string, err error) {
	var te *terminal.Error
	if !errors.As(err, &te) {
		writeError(w, http.StatusInternalServerError, Error{
			Code:      "internal",
			Message:   "terminal operation failed",
			Retryable: true,
			Cause:     "terminal_failure",
		})
		return
	}

	switch te.Cause {
	case "session_not_found":
		writeTerminalNotFound(w, sessionID)
	case "session_closed":
		writeError(w, http.StatusConflict, Error{
			Code:      "session_closed",
			Message:   te.Message,
			Retryable: false,
			Cause:     te.Cause,
			Remediation: []Remediation{{
				Action:    "post",
				Params:    map[string]any{"path": basePath + "/vms/{id}/terminals"},
				Rationale: "a closed session cannot be reopened; create a new one",
			}},
		})
	case "session_stale":
		writeError(w, http.StatusConflict, Error{
			Code:      "session_stale",
			Message:   te.Message,
			Retryable: false,
			Cause:     te.Cause,
			Remediation: []Remediation{{
				Action:    "post",
				Params:    map[string]any{"path": basePath + "/vms/{id}/terminals"},
				Rationale: "the VM rebooted; the shell that session named is gone, so create a session on the current boot",
			}},
		})
	case "runner_unreachable", "runner_refused", "attach_refused":
		writeError(w, http.StatusServiceUnavailable, Error{
			Code:      "terminal_unavailable",
			Message:   te.Message,
			Retryable: true,
			Cause:     te.Cause,
			Remediation: []Remediation{{
				Action:    "get",
				Params:    map[string]any{"path": basePath + "/vms/{id}"},
				Rationale: "the runner supervising the VM answers the terminal control socket; check the VM is still running before retrying",
			}},
		})
	default:
		writeError(w, http.StatusInternalServerError, Error{
			Code:      "internal",
			Message:   te.Message,
			Retryable: true,
			Cause:     te.Cause,
		})
	}
}

// appendTerminalEvent records a session lifecycle event on the API's own source
// stream. vm_id and boot_id ride the envelope, where every reader already looks
// for them; the data block carries what is specific to the session.
func (s *Server) appendTerminalEvent(ctx context.Context, kind string, sess terminal.Session, data map[string]any) error {
	stream := s.terminalStream(sess.VMID)
	seq := stream.seq.Add(1)
	env := &events.Envelope{
		SchemaVersion:    1,
		VMID:             &sess.VMID,
		SourceInstanceID: stream.instanceID,
		SourceSeq:        strconv.FormatInt(seq, 10),
		Kind:             kind,
		Provenance:       events.HostObserved,
		Sensor:           "api",
		HostReceivedAt:   events.Timestamp{Time: time.Now().UTC()},
		Quality: events.Quality{
			PathResolution: events.PathNotApplicable,
			Attribution:    events.AttributionNotApplicable,
		},
		Data: data,
	}
	// boot_id requires vm_id, and a session with no recorded boot would make
	// the envelope claim a boot scope it cannot name.
	if sess.BootID != "" {
		boot := sess.BootID
		env.BootID = &boot
	}
	_, err := s.store.Append(ctx, env)
	return err
}

// logTerminalEventFailure records a lost lifecycle event where an operator will
// see it. The request still succeeds: the PTY exists either way, and a reply
// withheld would leave a live session nobody can address.
func logTerminalEventFailure(kind, sessionID string, err error) {
	slog.Error("terminal lifecycle event not recorded",
		"kind", kind, "session_id", sessionID, "error", err)
}
