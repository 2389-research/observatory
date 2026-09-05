// ABOUTME: HTTP handlers for batch VM creation (SPEC §6.3, AT-014/AT-015).
// ABOUTME: POST /vm-batches creates, GET /vm-batches/{id} retrieves a batch.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/2389-research/observatory-v2/internal/auth"
	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/store"
)

// DefaultMaxBatchSize is SPEC §6.3's published batch size limit, applied when
// a host's admission config leaves max_batch_size unset. A host that sets it
// gets its own number: the cap the API enforces, the cap GET /meta publishes
// and the cap GET /host/status publishes are one number, so a UI that warns
// before submitting warns at the threshold the daemon actually applies.
const DefaultMaxBatchSize = 8

// maxBatchSize is the members-per-request cap this host enforces.
func (s *Server) maxBatchSize() int {
	if n := s.manager.AdmissionParams().MaxBatchSize; n > 0 {
		return n
	}
	return DefaultMaxBatchSize
}

func renderBatchID(id int64) string { return fmt.Sprintf("batch-%06d", id) }

func parseBatchID(raw string) (int64, bool) {
	s := strings.TrimPrefix(raw, "batch-")
	if s == "" || len(s) > 18 {
		return 0, false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	return v, err == nil
}

// wireBatch is the API representation of one batch row.
type wireBatch struct {
	BatchID         string            `json:"batch_id"`
	Owner           string            `json:"owner"`
	IdempotencyKey  *string           `json:"idempotency_key,omitempty"`
	ReservationMode string            `json:"reservation_mode"`
	OnFailure       string            `json:"on_failure"`
	CreatedAt       string            `json:"created_at"`
	UpdatedAt       string            `json:"updated_at"`
	Links           map[string]string `json:"links"`
}

// wireBatchMember is the API representation of one batch member outcome.
type wireBatchMember struct {
	Position  int                `json:"position"`
	Name      string             `json:"name"`
	VM        *wireVM            `json:"vm,omitempty"`
	Operation *wireOperation     `json:"operation,omitempty"`
	Refusal   *wireMemberRefusal `json:"refusal,omitempty"`
}

type wireMemberRefusal struct {
	Cause   string `json:"cause"`
	Message string `json:"message"`
}

type wireBatchResponse struct {
	Batch     wireBatch         `json:"batch"`
	Operation *wireOperation    `json:"operation,omitempty"`
	Members   []wireBatchMember `json:"members"`
	IsReplay  bool              `json:"is_replay,omitempty"`
}

func renderBatch(b *store.Batch) wireBatch {
	wb := wireBatch{
		BatchID:         renderBatchID(b.BatchID),
		Owner:           b.Owner,
		IdempotencyKey:  b.IdempotencyKey,
		ReservationMode: b.ReservationMode,
		OnFailure:       b.OnFailure,
		CreatedAt:       b.CreatedAt,
		UpdatedAt:       b.UpdatedAt,
		Links: map[string]string{
			"self": basePath + "/vm-batches/" + renderBatchID(b.BatchID),
		},
	}
	return wb
}

func (s *Server) renderBatchMember(ctx context.Context, m *store.BatchMemberResult) (wireBatchMember, error) {
	wm := wireBatchMember{
		Position: m.Position,
		Name:     m.Name,
	}
	if m.VM != nil {
		health, err := s.engine.VMTelemetryHealth(ctx, m.VM)
		if err != nil {
			return wireBatchMember{}, err
		}
		v := renderVM(m.VM, health.State)
		wm.VM = &v
	}
	if m.Operation != nil {
		o := renderOperation(m.Operation)
		wm.Operation = &o
	}
	if m.RefusalCause != nil {
		msg := ""
		if m.RefusalMessage != nil {
			msg = *m.RefusalMessage
		}
		wm.Refusal = &wireMemberRefusal{Cause: *m.RefusalCause, Message: msg}
	}
	return wm, nil
}

func (s *Server) renderBatchResult(ctx context.Context, result *store.CreateVMBatchResult) (wireBatchResponse, error) {
	members := make([]wireBatchMember, len(result.Members))
	for i, m := range result.Members {
		wm, err := s.renderBatchMember(ctx, m)
		if err != nil {
			return wireBatchResponse{}, err
		}
		members[i] = wm
	}
	resp := wireBatchResponse{
		Batch:    renderBatch(result.Batch),
		Members:  members,
		IsReplay: result.IsReplay,
	}
	if result.BatchOp != nil {
		o := renderOperation(result.BatchOp)
		resp.Operation = &o
	}
	return resp, nil
}

// writeBatchResult renders a batch reply, turning a store failure during
// rendering into the same typed 500 every other read surface returns.
func (s *Server) writeBatchResult(w http.ResponseWriter, r *http.Request, status int, result *store.CreateVMBatchResult) {
	resp, err := s.renderBatchResult(r.Context(), result)
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{
			Code: "internal", Message: "telemetry health query failed", Retryable: true, Cause: "storage_failure",
		})
		return
	}
	writeJSON(w, status, resp)
}

// createBatchBody is the JSON body for POST /vm-batches.
type createBatchBody struct {
	Members         []createBatchMember `json:"members"`
	ReservationMode string              `json:"reservation_mode"`
	OnFailure       string              `json:"on_failure"`
	IdempotencyKey  *string             `json:"idempotency_key"`
}

type createBatchMember struct {
	Name             string            `json:"name"`
	TemplateID       string            `json:"template_id"`
	VCPUCount        int               `json:"vcpu_count"`
	MemoryMiB        int64             `json:"memory_mib"`
	RootDiskMiB      int64             `json:"root_disk_mib"`
	WorkspaceDiskMiB int64             `json:"workspace_disk_mib"`
	Labels           map[string]string `json:"labels"`
	// Run is an optional launch-attached run block. R2 validation is applied
	// per-member; a bad member is reported as a refusal, not a batch-level error.
	Run *runBlockBody `json:"run"`
}

func (s *Server) handleCreateBatch(w http.ResponseWriter, r *http.Request) {
	ident, ok := auth.IdentityFrom(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, Error{
			Code: "internal", Message: "no identity in context", Retryable: false, Cause: "no_identity",
		})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var body createBatchBody
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   fmt.Sprintf("cannot decode request body: %v", err),
			Retryable: false,
			Cause:     "body_invalid",
		})
		return
	}

	if len(body.Members) == 0 {
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   "batch must have at least one member",
			Retryable: false,
			Cause:     "members_empty",
		})
		return
	}
	if maxMembers := s.maxBatchSize(); len(body.Members) > maxMembers {
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   fmt.Sprintf("batch has %d members, maximum is %d", len(body.Members), maxMembers),
			Retryable: false,
			Cause:     "batch_too_large",
			Details:   map[string]any{"max_batch_size": maxMembers},
		})
		return
	}

	// Per-member R2 validation: stop_and_finalize is refused as a per-member
	// refusal (same shape as admission refusals), not a batch-level error.
	// Members that pass validation are forwarded to CreateBatch; refused members
	// are injected back into the result at their original positions.
	type r2Refusal struct {
		position int
		name     string
		cause    string
		message  string
	}
	var r2Refusals []r2Refusal
	members := make([]runtime.BatchMemberRequest, 0, len(body.Members))
	for i, bm := range body.Members {
		var runAttach *store.RunAttachment
		if bm.Run != nil {
			if verr := validateRunBlock(bm.Run); verr != nil {
				r2Refusals = append(r2Refusals, r2Refusal{
					position: i,
					name:     bm.Name,
					cause:    verr.Cause,
					message:  verr.Message,
				})
				continue
			}
			runAttach = &store.RunAttachment{
				Goal:           bm.Run.Goal,
				CriteriaType:   bm.Run.SuccessCriteria.Type,
				OnCompletion:   bm.Run.OnCompletion,
				ProgressEvents: bm.Run.ProgressEvents,
			}
		}
		members = append(members, runtime.BatchMemberRequest{
			Name:             bm.Name,
			TemplateID:       bm.TemplateID,
			VCPUCount:        bm.VCPUCount,
			MemoryMiB:        bm.MemoryMiB,
			RootDiskMiB:      bm.RootDiskMiB,
			WorkspaceDiskMiB: bm.WorkspaceDiskMiB,
			Labels:           bm.Labels,
			Run:              runAttach,
		})
	}

	// Batch provisioning outlives the client that asked for it, same as the
	// single-VM create path: see Manager.OperationContext.
	opCtx, cancel := s.manager.OperationContext(r.Context())
	defer cancel()
	result, err := s.manager.CreateBatch(opCtx, ident.Owner, runtime.CreateBatchRequest{
		Members:         members,
		ReservationMode: body.ReservationMode,
		OnFailure:       body.OnFailure,
		IdempotencyKey:  body.IdempotencyKey,
	})
	if err != nil {
		// Batch errors are the same class as single-VM create errors and must
		// teach identically (same codes, same remediations).
		writeVMError(w, err)
		return
	}

	// Merge R2 refusals back into the result at the original positions. We
	// re-build the member list with the refused members inserted at their
	// original offsets so position numbers are correct for the caller.
	if len(r2Refusals) > 0 {
		all := make([]*store.BatchMemberResult, 0, len(body.Members))
		ri := 0 // index into r2Refusals
		ki := 0 // index into result.Members (from CreateBatch)
		for i, bm := range body.Members {
			if ri < len(r2Refusals) && r2Refusals[ri].position == i {
				// Use this member's own cause and message, not the first member's.
				cause := r2Refusals[ri].cause
				msg := r2Refusals[ri].message
				all = append(all, &store.BatchMemberResult{
					Position:       i,
					Name:           bm.Name,
					RefusalCause:   &cause,
					RefusalMessage: &msg,
				})
				ri++
			} else {
				if ki < len(result.Members) {
					all = append(all, result.Members[ki])
					ki++
				}
			}
		}
		result.Members = all
	}

	// Replays return the same 201 as the original request (retry-transparent
	// status); is_replay in the body marks the truth of what happened.
	s.writeBatchResult(w, r, http.StatusCreated, result)
}

func (s *Server) handleGetBatch(w http.ResponseWriter, r *http.Request) {
	raw := r.PathValue("id")
	id, ok := parseBatchID(raw)
	if !ok {
		writeError(w, http.StatusNotFound, Error{
			Code:        "not_found",
			Message:     fmt.Sprintf("batch %q not found", raw),
			Retryable:   false,
			Cause:       "batch_not_found",
			Remediation: []Remediation{metaRemediation()},
		})
		return
	}
	result, err := s.store.GetVMBatch(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrBatchUnknown) {
			writeError(w, http.StatusNotFound, Error{
				Code:        "not_found",
				Message:     fmt.Sprintf("batch %s not found", raw),
				Retryable:   false,
				Cause:       "batch_not_found",
				Remediation: []Remediation{metaRemediation()},
			})
			return
		}
		writeError(w, http.StatusInternalServerError, Error{
			Code:      "internal",
			Message:   "get batch failed",
			Retryable: true,
			Cause:     "storage_failure",
		})
		return
	}

	// AT-079: cross-owner access is indistinguishable from missing.
	ident, ok := auth.IdentityFrom(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, Error{
			Code: "internal", Message: "no identity in context", Retryable: false, Cause: "no_identity",
		})
		return
	}
	if ident.Owner != result.Batch.Owner {
		writeError(w, http.StatusNotFound, Error{
			Code:        "not_found",
			Message:     fmt.Sprintf("batch %s not found", raw),
			Retryable:   false,
			Cause:       "batch_not_found",
			Remediation: []Remediation{metaRemediation()},
		})
		return
	}

	s.writeBatchResult(w, r, http.StatusOK, result)
}
