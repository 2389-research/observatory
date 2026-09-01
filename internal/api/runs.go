// ABOUTME: Run lifecycle handlers: create, list, get, conclude, and report
// ABOUTME: (SPEC §12, P4 Task 8). One validation func enforces R2 at all call sites.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/store"
)

// RunGoalMaxBytes is the wire-layer limit on run goal text. 2048 bytes matches
// the launch-request.schema.json maxLength for the goal field.
const RunGoalMaxBytes = 2048

// validRunPhases is the complete set of phases a run can be in. Used to
// validate the ?phase filter on GET /runs — an unknown phase always returns
// an empty list silently, which is confusing; 400 is more honest (matches
// the family_unknown pattern in GET /events).
var validRunPhases = map[string]bool{
	"pending":      true,
	"running":      true,
	"concluding":   true,
	"succeeded":    true,
	"failed":       true,
	"inconclusive": true,
	"aborted":      true,
}

// validCriteriaTypes is the closed set accepted at all run ingress points.
var validCriteriaTypes = map[string]bool{
	"exec_exit_zero":   true,
	"guest_result":     true,
	"operator_verdict": true,
}

// validOnCompletion is the set accepted at run creation. stop_and_finalize is
// NOT in this set — it is refused by validateRunBlock (R2).
var validOnCompletion = map[string]bool{
	"keep_running": true,
	"stop":         true,
}

// --- wire types ---

type wireRunOutcome struct {
	Status      string `json:"status"`
	EvaluatedBy string `json:"evaluated_by"`
	Reason      string `json:"reason,omitempty"`
}

type wireRunResult struct {
	Provenance string          `json:"provenance"`
	Status     string          `json:"status"`
	Detail     string          `json:"detail,omitempty"`
	Data       json.RawMessage `json:"data,omitempty"`
	ReceivedAt string          `json:"received_at,omitempty"`
}

type wireRun struct {
	RunID          string            `json:"run_id"`
	VMID           string            `json:"vm_id"`
	Owner          string            `json:"owner"`
	Goal           string            `json:"goal"`
	CriteriaType   string            `json:"criteria_type"`
	OnCompletion   string            `json:"on_completion"`
	ProgressEvents bool              `json:"progress_events"`
	Phase          string            `json:"phase"`
	Outcome        *wireRunOutcome   `json:"outcome,omitempty"`
	Result         *wireRunResult    `json:"result,omitempty"`
	ProgressSeq    int64             `json:"progress_seq"`
	IdempotencyKey *string           `json:"idempotency_key,omitempty"`
	CreatedAt      string            `json:"created_at"`
	StartedAt      *string           `json:"started_at,omitempty"`
	ConcludedAt    *string           `json:"concluded_at,omitempty"`
	UpdatedAt      string            `json:"updated_at"`
	Links          map[string]string `json:"links"`
}

// terminalRunPhases duplicates the store's set so the API layer can classify
// phases without importing store internals.
var terminalRunPhases = map[string]bool{
	"succeeded":    true,
	"failed":       true,
	"inconclusive": true,
	"aborted":      true,
}

func renderRun(r *store.Run) wireRun {
	w := wireRun{
		RunID:          r.RunID,
		VMID:           r.VMID,
		Owner:          r.Owner,
		Goal:           r.Goal,
		CriteriaType:   r.CriteriaType,
		OnCompletion:   r.OnCompletion,
		ProgressEvents: r.ProgressEvents,
		Phase:          r.Phase,
		ProgressSeq:    r.ProgressSeq,
		IdempotencyKey: r.IdempotencyKey,
		CreatedAt:      r.CreatedAt,
		UpdatedAt:      r.UpdatedAt,
		Links: map[string]string{
			"events": basePath + "/events?vm_id=" + r.VMID,
			"report": basePath + "/runs/" + r.RunID + "/report",
		},
	}

	// started_at: empty string → omit.
	if r.StartedAt != "" {
		sa := r.StartedAt
		w.StartedAt = &sa
	}

	// concluded_at / outcome: only present on terminal phases.
	if terminalRunPhases[r.Phase] {
		if r.ConcludedAt != "" {
			ca := r.ConcludedAt
			w.ConcludedAt = &ca
		}
		w.Outcome = &wireRunOutcome{
			Status:      r.Phase,
			EvaluatedBy: r.EvaluatedBy,
			Reason:      r.Reason,
		}
	}

	// result: only present when a guest result was recorded.
	if r.ResultJSON != "" {
		wr := &wireRunResult{
			Provenance: "guest_reported", // R3: fixed by trusted ingress, never from input
			Status:     r.ResultStatus,
			ReceivedAt: r.ResultReceivedAt,
		}
		// Parse the stored JSON to extract detail/data. If the parse fails we
		// still serve provenance+status — the raw JSON stays in the store.
		var parsed map[string]json.RawMessage
		if err := json.Unmarshal([]byte(r.ResultJSON), &parsed); err == nil {
			if d, ok := parsed["detail"]; ok {
				var s string
				if err := json.Unmarshal(d, &s); err == nil {
					wr.Detail = s
				}
			}
			if d, ok := parsed["data"]; ok {
				wr.Data = d
			}
		}
		w.Result = wr
	}

	return w
}

// --- R2 validation ---

// runBlockBody is the shape of the "run" block common to all three ingress points.
type runBlockBody struct {
	Goal            string `json:"goal"`
	SuccessCriteria struct {
		Type string `json:"type"`
	} `json:"success_criteria"`
	OnCompletion   string `json:"on_completion"`
	ProgressEvents bool   `json:"progress_events"`
}

// validateRunBlock validates the common run block and returns a 501 error if
// on_completion=stop_and_finalize is present (R2), or a 400 for other
// validation failures. Returns nil if the block is valid.
//
// This is the single validation function called from all three ingress points
// (POST /vms/{id}/runs, POST /vms run block, batch member run block) so the
// R2 refusal is structurally impossible to bypass.
func validateRunBlock(rb *runBlockBody) *Error {
	// R2: stop_and_finalize is unbuilt — refuse before any other check so the
	// error is always 501, never confused with a 400 for an otherwise-wrong field.
	if rb.OnCompletion == "stop_and_finalize" {
		return &Error{
			Code:      "missing_capability",
			Message:   "on_completion=stop_and_finalize is not built: filesystem finalization is not yet available; use keep_running or stop",
			Retryable: false,
			Cause:     "capability_not_built",
			Remediation: []Remediation{
				{
					Action:    "set on_completion=keep_running",
					Rationale: "the VM keeps running after the run concludes; no filesystem capture",
				},
				{
					Action:    "set on_completion=stop",
					Rationale: "the VM is stopped after the run concludes; no filesystem capture",
				},
			},
		}
	}
	if rb.Goal == "" {
		return &Error{
			Code: "malformed_request", Message: "goal is required",
			Retryable: false, Cause: "body_invalid",
		}
	}
	if len(rb.Goal) > RunGoalMaxBytes {
		return &Error{
			Code:      "malformed_request",
			Message:   fmt.Sprintf("goal exceeds maximum %d bytes", RunGoalMaxBytes),
			Retryable: false, Cause: "body_invalid",
		}
	}
	if !validCriteriaTypes[rb.SuccessCriteria.Type] {
		return &Error{
			Code:      "malformed_request",
			Message:   fmt.Sprintf("success_criteria.type must be one of: exec_exit_zero, guest_result, operator_verdict; got %q", rb.SuccessCriteria.Type),
			Retryable: false, Cause: "body_invalid",
		}
	}
	if !validOnCompletion[rb.OnCompletion] {
		return &Error{
			Code:      "malformed_request",
			Message:   fmt.Sprintf("on_completion must be keep_running or stop; got %q", rb.OnCompletion),
			Retryable: false, Cause: "body_invalid",
		}
	}
	return nil
}

// validateRunBlockHTTP writes the error to w and returns false if the block is
// invalid. Returns true (and writes nothing) if the block is valid.
func validateRunBlockHTTP(w http.ResponseWriter, rb *runBlockBody) bool {
	if err := validateRunBlock(rb); err != nil {
		if err.Cause == "capability_not_built" {
			writeError(w, http.StatusNotImplemented, *err)
		} else {
			writeError(w, http.StatusBadRequest, *err)
		}
		return false
	}
	return true
}

// writeRunError maps run/store sentinel errors to API error shapes.
func writeRunError(w http.ResponseWriter, err error) {
	// 404: run not found.
	if errors.Is(err, store.ErrRunNotFound) {
		writeError(w, http.StatusNotFound, Error{
			Code:      "not_found",
			Message:   "run not found",
			Retryable: false,
			Cause:     "run_unknown",
			Remediation: []Remediation{{
				Action:    "get",
				Params:    map[string]any{"path": basePath + "/runs"},
				Rationale: "list all runs",
			}},
		})
		return
	}
	// 409: VM not in running state.
	if errors.Is(err, runtime.ErrVMNotRunning) {
		writeError(w, http.StatusConflict, Error{
			Code:      "conflict",
			Message:   "the VM is not in running state; standalone runs require a running VM",
			Retryable: false,
			Cause:     "vm_not_running",
			Remediation: []Remediation{{
				Action:    "get",
				Params:    map[string]any{"path": basePath + "/vms/{id}"},
				Rationale: "check the VM's observed_state before creating a run",
			}},
		})
		return
	}
	// 409: run already concluded.
	if errors.Is(err, runtime.ErrRunConcluded) {
		writeError(w, http.StatusConflict, Error{
			Code:      "conflict",
			Message:   "run is already in a terminal phase",
			Retryable: false,
			Cause:     "already_concluded",
		})
		return
	}
	// 409: verdict on non-operator_verdict criteria.
	if errors.Is(err, runtime.ErrVerdictCriteriaMismatch) {
		writeError(w, http.StatusConflict, Error{
			Code:      "conflict",
			Message:   "verdict can only be supplied for operator_verdict runs; for other criteria types, use abort",
			Retryable: false,
			Cause:     "criteria_mismatch",
			Remediation: []Remediation{{
				Action:    "post",
				Params:    map[string]any{"path": basePath + "/runs/{id}/conclude", "body": map[string]any{"abort": true, "reason": "operator abort"}},
				Rationale: "abort concludes any run regardless of criteria type",
			}},
		})
		return
	}
	// 409: active run already exists for this VM.
	if errors.Is(err, store.ErrActiveRunExists) {
		writeError(w, http.StatusConflict, Error{
			Code:      "conflict",
			Message:   "a non-terminal run already exists for this VM; conclude it before creating another",
			Retryable: false,
			Cause:     "active_run_exists",
			Remediation: []Remediation{{
				Action:    "get",
				Params:    map[string]any{"path": basePath + "/runs?vm_id={id}&phase=running"},
				Rationale: "find the active run for this VM",
			}},
		})
		return
	}
	// Fall through to the VM-level error mapper (handles ErrVMUnknown, admission, etc.).
	writeVMError(w, err)
}

// --- handlers ---

// handleCreateRunForVM handles POST /vms/{id}/runs.
func (s *Server) handleCreateRunForVM(w http.ResponseWriter, r *http.Request) {
	vmID := r.PathValue("id")
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var body struct {
		Goal            string `json:"goal"`
		SuccessCriteria struct {
			Type string `json:"type"`
		} `json:"success_criteria"`
		OnCompletion   string  `json:"on_completion"`
		ProgressEvents bool    `json:"progress_events"`
		IdempotencyKey *string `json:"idempotency_key"`
	}
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, Error{
			Code: "malformed_request", Message: fmt.Sprintf("cannot decode request body: %v", err),
			Retryable: false, Cause: "body_invalid",
		})
		return
	}

	rb := &runBlockBody{
		Goal:           body.Goal,
		OnCompletion:   body.OnCompletion,
		ProgressEvents: body.ProgressEvents,
	}
	rb.SuccessCriteria.Type = body.SuccessCriteria.Type
	if !validateRunBlockHTTP(w, rb) {
		return
	}

	run, isReplay, err := s.manager.CreateRun(r.Context(), runtime.RunRequest{
		VMID:           vmID,
		Owner:          s.manager.Owner(),
		Goal:           body.Goal,
		CriteriaType:   body.SuccessCriteria.Type,
		OnCompletion:   body.OnCompletion,
		ProgressEvents: body.ProgressEvents,
		IdempotencyKey: body.IdempotencyKey,
	})
	if err != nil {
		// active_run_exists: look up existing run to include run_id in details.
		if errors.Is(err, store.ErrActiveRunExists) {
			existing, _ := s.store.ActiveRunForVM(r.Context(), vmID)
			if existing != nil {
				writeError(w, http.StatusConflict, Error{
					Code:      "conflict",
					Message:   "a non-terminal run already exists for this VM",
					Retryable: false,
					Cause:     "active_run_exists",
					Details:   map[string]any{"run_id": existing.RunID},
					Remediation: []Remediation{{
						Action:    "get",
						Params:    map[string]any{"path": basePath + "/runs/" + existing.RunID},
						Rationale: "inspect or conclude the active run before creating another",
					}},
				})
				return
			}
		}
		writeRunError(w, err)
		return
	}

	resp := map[string]any{"run": renderRun(run)}
	if isReplay {
		resp["is_replay"] = true
	}
	writeJSON(w, http.StatusCreated, resp)
}

// handleListRuns handles GET /runs.
func (s *Server) handleListRuns(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	q := store.RunQuery{}

	if raw := params.Get("vm_id"); raw != "" {
		q.VMID = raw
	}
	if raw := params.Get("phase"); raw != "" {
		if !validRunPhases[raw] {
			writeError(w, http.StatusBadRequest, Error{
				Code:      "malformed_request",
				Message:   fmt.Sprintf("phase %q is not a valid run phase", raw),
				Retryable: false,
				Cause:     "phase_unknown",
				Remediation: []Remediation{{
					Action:    "get",
					Params:    map[string]any{"path": basePath + "/runs"},
					Rationale: "valid phases: pending, running, concluding, succeeded, failed, inconclusive, aborted",
				}},
			})
			return
		}
		q.Phase = raw
	}
	if raw := params.Get("after"); raw != "" {
		q.After = raw
	}
	if raw := params.Get("limit"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, Error{
				Code: "malformed_request", Message: "limit must be an integer",
				Retryable: false, Cause: "query_parameter_invalid",
			})
			return
		}
		q.Limit = v
	}

	runs, nextAfter, err := s.store.ListRuns(r.Context(), q)
	if err != nil {
		var be *store.BoundError
		if errors.As(err, &be) {
			writeError(w, http.StatusBadRequest, Error{
				Code:      "malformed_request",
				Message:   fmt.Sprintf("limit %d exceeds maximum %d", be.Requested, be.Max),
				Retryable: false,
				Cause:     "limit_out_of_bounds",
			})
			return
		}
		if errors.Is(err, store.ErrInvalidCursor) {
			writeError(w, http.StatusBadRequest, Error{
				Code:      "malformed_request",
				Message:   "after cursor must be a decimal row_id",
				Retryable: false,
				Cause:     "query_parameter_invalid",
			})
			return
		}
		writeError(w, http.StatusInternalServerError, Error{
			Code: "internal", Message: "list runs failed", Retryable: true, Cause: "storage_failure",
		})
		return
	}

	wireRuns := make([]wireRun, 0, len(runs))
	for _, rn := range runs {
		wireRuns = append(wireRuns, renderRun(rn))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"runs":       wireRuns,
		"next_after": nextAfter,
	})
}

// handleGetRun handles GET /runs/{id}.
func (s *Server) handleGetRun(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("id")
	run, err := s.store.GetRun(r.Context(), runID)
	if err != nil {
		writeRunError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, renderRun(run))
}

// concludeRunBody is the allowed body for POST /runs/{id}/conclude.
// Exactly one of verdict or abort must be set.
type concludeRunBody struct {
	Verdict *string `json:"verdict"` // "succeeded" | "failed"
	Abort   bool    `json:"abort"`
	Reason  string  `json:"reason"`
}

// handleConcludeRun handles POST /runs/{id}/conclude.
func (s *Server) handleConcludeRun(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("id")
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var body concludeRunBody
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, Error{
			Code: "malformed_request", Message: fmt.Sprintf("cannot decode conclude body: %v", err),
			Retryable: false, Cause: "body_invalid",
		})
		return
	}

	// verdict and abort are mutually exclusive; supplying both is a wire error.
	// Supplying neither is a semantic error handled by ConcludeRun (→ ErrConcludeArgsMissing).
	hasVerdict := body.Verdict != nil
	hasAbort := body.Abort
	if hasVerdict && hasAbort {
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   "verdict and abort are mutually exclusive; supply exactly one",
			Retryable: false,
			Cause:     "body_invalid",
		})
		return
	}

	// Validate verdict values.
	if hasVerdict && *body.Verdict != "succeeded" && *body.Verdict != "failed" {
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   `verdict must be "succeeded" or "failed"`,
			Retryable: false,
			Cause:     "body_invalid",
		})
		return
	}

	// We need the current run to populate details on error responses.
	currentRun, _ := s.store.GetRun(r.Context(), runID)

	run, err := s.manager.ConcludeRun(r.Context(), runID, body.Verdict, body.Abort, body.Reason)
	if err != nil {
		if errors.Is(err, store.ErrRunNotFound) {
			writeRunError(w, err)
			return
		}
		if errors.Is(err, runtime.ErrRunConcluded) {
			// Include the current terminal phase in details.
			outcome := ""
			if currentRun != nil {
				outcome = currentRun.Phase
			}
			// Re-fetch for the latest state.
			if latest, fetchErr := s.store.GetRun(r.Context(), runID); fetchErr == nil {
				outcome = latest.Phase
			}
			writeError(w, http.StatusConflict, Error{
				Code:      "conflict",
				Message:   "run is already in a terminal phase",
				Retryable: false,
				Cause:     "already_concluded",
				Details:   map[string]any{"outcome": outcome},
			})
			return
		}
		if errors.Is(err, runtime.ErrConcludeArgsMissing) {
			writeError(w, http.StatusBadRequest, Error{
				Code:      "validation_failed",
				Message:   "conclude requires a verdict or abort:true",
				Retryable: false,
				Cause:     "conclude_args_missing",
				Details:   map[string]any{"run_id": runID},
			})
			return
		}
		writeRunError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"run": renderRun(run)})
}

// handleGetRunReport handles GET /runs/{id}/report.
func (s *Server) handleGetRunReport(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("id")
	ctx := r.Context()

	// Verify the run exists before checking the report.
	run, err := s.store.GetRun(ctx, runID)
	if err != nil {
		writeRunError(w, err)
		return
	}

	// Non-terminal runs never have a report. Return pending without enqueueing —
	// enqueueing a non-terminal run produces a spurious failed op (Generate returns
	// ErrNotTerminal, op is marked failed, pollutes the operations table).
	if !terminalRunPhases[run.Phase] {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":    "pending",
			"retryable": true,
		})
		return
	}

	// Stored report? Serve it.
	rpt, err := s.store.GetRunReport(ctx, runID)
	if err == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":       "generated",
			"generated_at": rpt.GeneratedAt,
			"digest":       rpt.Digest,
			"report":       json.RawMessage(rpt.ReportJSON),
		})
		return
	}
	if !errors.Is(err, store.ErrReportNotFound) {
		writeError(w, http.StatusInternalServerError, Error{
			Code: "internal", Message: "get report failed", Retryable: true, Cause: "storage_failure",
		})
		return
	}

	// No stored report. Find the latest report operation to determine status.
	op, opErr := s.store.GetLatestReportOperation(ctx, runID)

	// No op at all: pending with no operation_id.
	if opErr != nil {
		// Try to kick off generation (R7: re-enqueue on GET of a missing/failed report).
		s.manager.EnqueueReport(runID)
		writeJSON(w, http.StatusOK, map[string]any{
			"status":    "pending",
			"retryable": true,
		})
		return
	}

	// Op exists: surface its state.
	opID := renderOperationID(op.OperationID)
	if op.State == "failed" {
		// R7: re-enqueue exactly one attempt on a failed report.
		s.manager.EnqueueReport(runID)
		writeJSON(w, http.StatusOK, map[string]any{
			"status":       "failed",
			"operation_id": opID,
			"retryable":    true,
		})
		return
	}
	// running or pending op.
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "pending",
		"operation_id": opID,
		"retryable":    true,
	})
}
