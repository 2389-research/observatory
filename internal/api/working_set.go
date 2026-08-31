// ABOUTME: The operator working set over HTTP: GET /situation, GET/ack
// ABOUTME: /attention, POST/GET /annotations. Triggers evaluate lazily on read.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/2389-research/observatory-v2/internal/store"
)

// operatorAuthor is the identity trusted ingress assigns to annotations until
// the auth boundary lands (P5). Never taken from the request body.
const operatorAuthor = "local_operator"

// wireAttention is the attention item exactly as SPEC §12.7 shows it. Count is
// a decimal string like every counter that can grow with the event stream.
type wireAttention struct {
	AttentionID      string                  `json:"attention_id"`
	Cursor           string                  `json:"cursor"`
	Severity         string                  `json:"severity"`
	Kind             string                  `json:"kind"`
	VMID             *string                 `json:"vm_id,omitempty"`
	RunID            *string                 `json:"run_id,omitempty"`
	Summary          string                  `json:"summary"`
	SystemAction     string                  `json:"system_action"`
	Count            string                  `json:"count"`
	Acked            bool                    `json:"acked"`
	EvidenceLinks    []string                `json:"evidence_links"`
	SuggestedActions []store.SuggestedAction `json:"suggested_actions"`
}

func renderAttentionID(id int64) string { return fmt.Sprintf("att-%06d", id) }

func parseAttentionID(raw string) (int64, bool) {
	s := strings.TrimPrefix(raw, "att-")
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

// renderAttention converts a queue row to the wire shape. The ack action is
// composed at render time so its params always carry this item's current id —
// suggested actions must execute as returned (P-06).
func renderAttention(it *store.AttentionItem) wireAttention {
	w := wireAttention{
		AttentionID:      renderAttentionID(it.AttentionID),
		Cursor:           strconv.FormatInt(it.LastEventID, 10),
		Severity:         it.Severity,
		Kind:             it.TriggerClass,
		VMID:             it.VMID,
		RunID:            it.RunID,
		Summary:          it.Summary,
		SystemAction:     it.SystemAction,
		Count:            strconv.FormatInt(it.Count, 10),
		Acked:            it.Acked,
		EvidenceLinks:    it.EvidenceLinks,
		SuggestedActions: it.SuggestedActions,
	}
	if w.EvidenceLinks == nil {
		w.EvidenceLinks = []string{}
	}
	if w.SuggestedActions == nil {
		w.SuggestedActions = []store.SuggestedAction{}
	}
	if !it.Acked {
		w.SuggestedActions = append(w.SuggestedActions, store.SuggestedAction{
			Action:    "ack",
			Params:    map[string]any{"attention_id": w.AttentionID},
			Rationale: "acknowledge after acting on it; acked items leave the default queue view but stay durable",
		})
	}
	return w
}

func renderAttentionList(items []*store.AttentionItem) []wireAttention {
	out := make([]wireAttention, 0, len(items))
	for _, it := range items {
		out = append(out, renderAttention(it))
	}
	return out
}

// evaluate runs the trigger fold before a read so the working set reflects
// everything already durable. Materialization on read, not a background race.
func (s *Server) evaluate(w http.ResponseWriter, r *http.Request) bool {
	if err := s.engine.Evaluate(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, Error{
			Code:      "internal",
			Message:   "trigger evaluation failed in storage",
			Retryable: true,
			Cause:     "storage_failure",
		})
		return false
	}
	return true
}

type situationWatch struct {
	TriggerClassesActive []string `json:"trigger_classes_active"`
	SensorsDegraded      int      `json:"sensors_degraded"`
}

type situationHost struct {
	VMsRunning      int            `json:"vms_running"`
	VMsTotal        int            `json:"vms_total"`
	CapacityFreeMiB int64          `json:"capacity_free_mib"`
	Watch           situationWatch `json:"watch"`
}

type situationResponse struct {
	AsOfCursor    string          `json:"as_of_cursor"`
	SinceCursor   string          `json:"since_cursor,omitempty"`
	Quiet         bool            `json:"quiet"`
	Host          situationHost   `json:"host"`
	ChangedVMs    []wireChangedVM `json:"changed_vms"`
	AttentionHead []wireAttention `json:"attention_head"`
}

func (s *Server) handleSituation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !s.evaluate(w, r) {
		return
	}
	since := r.URL.Query().Get("since")
	snap, err := s.engine.Snapshot(ctx, since)
	if err != nil {
		writeQueryError(w, err)
		return
	}

	// VM counts from the registry (real accounting replaces the P2 zeros).
	vmCounts, err := s.store.CountVMsByObservedState(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{
			Code: "internal", Message: "vm count query failed", Retryable: true, Cause: "storage_failure",
		})
		return
	}
	vmRunning := vmCounts["running"]
	vmTotal := 0
	for state, count := range vmCounts {
		if state != "deleted" {
			vmTotal += count
		}
	}

	// Capacity from the admission policy — real accounting closes the P2 deviation.
	cap, err := s.manager.Capacity(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{
			Code: "internal", Message: "capacity query failed", Retryable: true, Cause: "storage_failure",
		})
		return
	}

	// changed_vms: populated only on since requests; a full-fleet dump belongs
	// to GET /vms. The delta is bounded to 50 entries; byte-bound sheds first
	// attention_head, then changed_vms if the response is still too large.
	changedVMs := []wireChangedVM{}
	if since != "" {
		sinceID, _ := strconv.ParseInt(since, 10, 64) // already validated by engine.Snapshot
		const changedVMsLimit = 50
		changed, err := s.store.ChangedVMs(ctx, sinceID, changedVMsLimit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, Error{
				Code: "internal", Message: "changed_vms query failed", Retryable: true, Cause: "storage_failure",
			})
			return
		}
		var openByVM map[string]int64
		if len(changed) > 0 {
			openByVM, err = s.store.CountOpenAttentionByVM(ctx)
			if err != nil {
				writeError(w, http.StatusInternalServerError, Error{
					Code: "internal", Message: "attention count query failed", Retryable: true, Cause: "storage_failure",
				})
				return
			}
		}
		for _, vm := range changed {
			changedVMs = append(changedVMs, renderChangedVM(vm, openByVM[vm.VMID]))
		}
	}

	resp := situationResponse{
		AsOfCursor:  snap.AsOfCursor,
		SinceCursor: snap.SinceCursor,
		Quiet:       snap.Quiet,
		Host: situationHost{
			VMsRunning:      vmRunning,
			VMsTotal:        vmTotal,
			CapacityFreeMiB: cap.FreeMemoryMiB,
			Watch: situationWatch{
				TriggerClassesActive: snap.ActiveClasses,
				SensorsDegraded:      snap.SensorsDegraded,
			},
		},
		ChangedVMs:    changedVMs,
		AttentionHead: renderAttentionList(snap.Head),
	}

	// Bounded by config (P-01): shed attention_head first (full queue is
	// behind GET /attention), then changed_vms (full delta behind GET /vms).
	// Never shed the watch scope — a truncated watch scope would violate P-03.
	maxBytes := s.engine.Config().SituationMaxResponseBytes
	for {
		raw, err := json.Marshal(resp)
		if err != nil {
			writeError(w, http.StatusInternalServerError, Error{
				Code: "internal", Message: "situation encoding failed",
				Retryable: true, Cause: "encoding_failure",
			})
			return
		}
		if maxBytes <= 0 || int64(len(raw)) <= maxBytes {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(raw)
			return
		}
		if len(resp.AttentionHead) > 0 {
			resp.AttentionHead = resp.AttentionHead[:len(resp.AttentionHead)/2]
		} else if len(resp.ChangedVMs) > 0 {
			resp.ChangedVMs = resp.ChangedVMs[:len(resp.ChangedVMs)/2]
		} else {
			// Nothing left to shed; emit as-is (watch scope always included).
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(raw)
			return
		}
	}
}

type attentionListResponse struct {
	Items     []wireAttention `json:"items"`
	NextAfter string          `json:"next_after"`
}

func (s *Server) handleAttention(w http.ResponseWriter, r *http.Request) {
	if !s.evaluate(w, r) {
		return
	}
	params := r.URL.Query()
	q := store.AttentionQuery{IncludeAcked: params.Get("include_acked") == "true"}
	if raw := params.Get("after"); raw != "" {
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, Error{
				Code:      "malformed_request",
				Message:   fmt.Sprintf("after %q is not a decimal attention id", raw),
				Retryable: false,
				Cause:     "query_parameter_invalid",
			})
			return
		}
		q.After = v
	}
	if raw := params.Get("limit"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, Error{
				Code:      "malformed_request",
				Message:   fmt.Sprintf("limit %q is not an integer", raw),
				Retryable: false,
				Cause:     "query_parameter_invalid",
			})
			return
		}
		q.Limit = v
	}

	items, err := s.store.ListAttention(r.Context(), q)
	if err != nil {
		writeQueryError(w, err)
		return
	}
	resp := attentionListResponse{Items: renderAttentionList(items)}
	if n := len(items); n > 0 {
		resp.NextAfter = strconv.FormatInt(items[n-1].AttentionID, 10)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAttentionAck(w http.ResponseWriter, r *http.Request) {
	id, ok := parseAttentionID(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   fmt.Sprintf("attention id %q is not the att-000123 form this API returns", r.PathValue("id")),
			Retryable: false,
			Cause:     "path_parameter_invalid",
		})
		return
	}
	item, err := s.store.AckAttention(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrAttentionUnknown):
		writeError(w, http.StatusNotFound, Error{
			Code:      "not_found",
			Message:   err.Error(),
			Retryable: false,
			Cause:     "attention_unknown",
			Remediation: []Remediation{{
				Action:    "get",
				Params:    map[string]any{"path": basePath + "/attention"},
				Rationale: "the queue lists every open item with its current id",
			}},
		})
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, Error{
			Code: "internal", Message: "acknowledgment failed in storage",
			Retryable: true, Cause: "storage_failure",
		})
		return
	}
	writeJSON(w, http.StatusOK, renderAttention(item))
}

// wireAnnotation mirrors the stored row; ids follow the same prefixed form as
// attention so agents can tell entity ids apart on sight.
type wireAnnotation struct {
	AnnotationID      string            `json:"annotation_id"`
	TargetRef         string            `json:"target_ref"`
	Author            string            `json:"author"`
	Text              string            `json:"text"`
	Tags              map[string]string `json:"tags"`
	Redacted          bool              `json:"redacted"`
	RedactionPolicyID string            `json:"redaction_policy_id,omitempty"`
	EventID           string            `json:"event_id"`
	CreatedAt         string            `json:"created_at"`
}

func renderAnnotation(a *store.Annotation) wireAnnotation {
	return wireAnnotation{
		AnnotationID:      fmt.Sprintf("ann-%06d", a.AnnotationID),
		TargetRef:         a.TargetRef,
		Author:            a.Author,
		Text:              a.Text,
		Tags:              a.Tags,
		Redacted:          a.Redacted,
		RedactionPolicyID: a.RedactionPolicyID,
		EventID:           strconv.FormatInt(a.EventID, 10),
		CreatedAt:         a.CreatedAt,
	}
}

func (s *Server) handleAnnotationsCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TargetRef string            `json:"target_ref"`
		Text      string            `json:"text"`
		Tags      map[string]string `json:"tags"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	// Unknown fields are refused, not dropped: silently discarding an
	// "author" claim would hide that identity is assigned here, not accepted.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   fmt.Sprintf("annotation body did not decode: %v", err),
			Retryable: false,
			Cause:     "body_invalid",
			Details:   map[string]any{"accepted_fields": []string{"target_ref", "text", "tags"}},
		})
		return
	}
	if body.Text == "" {
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   "annotation text is required",
			Retryable: false,
			Cause:     "body_invalid",
		})
		return
	}

	ann, err := s.store.CreateAnnotation(r.Context(), store.AnnotationInput{
		TargetRef: body.TargetRef,
		Author:    operatorAuthor,
		Text:      body.Text,
		Tags:      body.Tags,
	})
	if err != nil {
		writeAnnotationError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, renderAnnotation(ann))
}

func (s *Server) handleAnnotationsList(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	q := store.AnnotationQuery{Ref: params.Get("ref")}
	if raw := params.Get("after"); raw != "" {
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, Error{
				Code:      "malformed_request",
				Message:   fmt.Sprintf("after %q is not a decimal annotation id", raw),
				Retryable: false,
				Cause:     "query_parameter_invalid",
			})
			return
		}
		q.After = v
	}
	if raw := params.Get("limit"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, Error{
				Code:      "malformed_request",
				Message:   fmt.Sprintf("limit %q is not an integer", raw),
				Retryable: false,
				Cause:     "query_parameter_invalid",
			})
			return
		}
		q.Limit = v
	}

	anns, err := s.store.ListAnnotations(r.Context(), q)
	if err != nil {
		writeAnnotationError(w, err)
		return
	}
	out := make([]wireAnnotation, 0, len(anns))
	for _, a := range anns {
		out = append(out, renderAnnotation(a))
	}
	resp := struct {
		Annotations []wireAnnotation `json:"annotations"`
		NextAfter   string           `json:"next_after"`
	}{Annotations: out}
	if n := len(anns); n > 0 {
		resp.NextAfter = strconv.FormatInt(anns[n-1].AnnotationID, 10)
	}
	writeJSON(w, http.StatusOK, resp)
}

func writeAnnotationError(w http.ResponseWriter, err error) {
	var bound *store.AnnotationBoundError
	var pageBound *store.BoundError
	switch {
	case errors.Is(err, store.ErrInvalidTargetRef):
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   err.Error(),
			Retryable: false,
			Cause:     "target_ref_invalid",
			Remediation: []Remediation{{
				Action:    "retry_with_ref",
				Params:    map[string]any{"format": "<type>:<id>", "types": []string{"vm", "boot", "run", "event", "operation", "template", "artifact", "host"}},
				Rationale: "refs name a stored entity; the type prefix says which collection resolves the id",
			}},
		})
	case errors.As(err, &bound):
		writeError(w, http.StatusBadRequest, Error{
			Code:      "limit_exceeded",
			Message:   err.Error(),
			Retryable: false,
			Cause:     "annotation_bound_exceeded",
			Details:   map[string]any{"field": bound.Field, "got": bound.Got, "max": bound.Max},
		})
	case errors.As(err, &pageBound):
		writeError(w, http.StatusBadRequest, Error{
			Code:      "limit_exceeded",
			Message:   err.Error(),
			Retryable: false,
			Cause:     "limit_out_of_bounds",
			Details:   map[string]any{"requested": pageBound.Requested, "max": pageBound.Max},
		})
	default:
		writeError(w, http.StatusInternalServerError, Error{
			Code: "internal", Message: "annotation operation failed in storage",
			Retryable: true, Cause: "storage_failure",
		})
	}
}
