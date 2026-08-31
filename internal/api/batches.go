// ABOUTME: HTTP handlers for batch VM creation (SPEC §6.3, AT-014/AT-015).
// ABOUTME: POST /vm-batches creates, GET /vm-batches/{id} retrieves a batch.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/store"
)

// MaxBatchSize is the maximum number of members allowed in a single batch.
// It lives in the API layer because it is a protocol constraint, not a
// store or admission constraint.
const MaxBatchSize = 50

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

func renderBatchMember(m *store.BatchMemberResult) wireBatchMember {
	wm := wireBatchMember{
		Position: m.Position,
		Name:     m.Name,
	}
	if m.VM != nil {
		v := renderVM(m.VM)
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
	return wm
}

func renderBatchResult(result *store.CreateVMBatchResult) wireBatchResponse {
	members := make([]wireBatchMember, len(result.Members))
	for i, m := range result.Members {
		members[i] = renderBatchMember(m)
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
	return resp
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
}

func (s *Server) handleCreateBatch(w http.ResponseWriter, r *http.Request) {
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
	if len(body.Members) > MaxBatchSize {
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   fmt.Sprintf("batch has %d members, maximum is %d", len(body.Members), MaxBatchSize),
			Retryable: false,
			Cause:     "batch_too_large",
			Details:   map[string]any{"max_batch_size": MaxBatchSize},
		})
		return
	}

	members := make([]runtime.BatchMemberRequest, len(body.Members))
	for i, bm := range body.Members {
		members[i] = runtime.BatchMemberRequest{
			Name:             bm.Name,
			TemplateID:       bm.TemplateID,
			VCPUCount:        bm.VCPUCount,
			MemoryMiB:        bm.MemoryMiB,
			RootDiskMiB:      bm.RootDiskMiB,
			WorkspaceDiskMiB: bm.WorkspaceDiskMiB,
			Labels:           bm.Labels,
		}
	}

	result, err := s.manager.CreateBatch(r.Context(), runtime.CreateBatchRequest{
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
	// Replays return the same 201 as the original request (retry-transparent
	// status); is_replay in the body marks the truth of what happened.
	writeJSON(w, http.StatusCreated, renderBatchResult(result))
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
	writeJSON(w, http.StatusOK, renderBatchResult(result))
}
