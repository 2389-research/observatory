// ABOUTME: VM, operation, template, and host-status handlers: POST/GET /vms,
// ABOUTME: POST /vms/{id}/actions, DELETE /vms/{id}, GET /operations/{id}, etc.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/2389-research/observatory-v2/internal/auth"
	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/store"
)

// --- wire types ---

type wireVMResources struct {
	VCPUCount        int   `json:"vcpu_count"`
	MemoryMiB        int64 `json:"memory_mib"`
	RootDiskMiB      int64 `json:"root_disk_mib"`
	WorkspaceDiskMiB int64 `json:"workspace_disk_mib"`
}

type wireVMFailure struct {
	Stage  string `json:"stage"`
	Reason string `json:"reason"`
}

type wireVM struct {
	VMID            string            `json:"vm_id"`
	Name            string            `json:"name"`
	Owner           string            `json:"owner"`
	TemplateID      string            `json:"template_id"`
	TemplateDigest  string            `json:"template_digest"`
	DesiredState    string            `json:"desired_state"`
	ObservedState   string            `json:"observed_state"`
	Revision        string            `json:"revision"` // decimal string; can grow with the event stream
	Resources       wireVMResources   `json:"resources"`
	NetworkProfile  string            `json:"network_profile"`
	NetworkPolicyID string            `json:"network_policy_id"`
	Labels          map[string]string `json:"labels"`
	Failure         *wireVMFailure    `json:"failure,omitempty"`
	CreatedAt       string            `json:"created_at"`
	UpdatedAt       string            `json:"updated_at"`
	// Links carry the event stream for this VM; executable as returned (P-06).
	Links map[string]string `json:"links"`
}

type wireOperationError struct {
	Cause   string `json:"cause"`
	Message string `json:"message"`
}

type wireOperation struct {
	OperationID string              `json:"operation_id"`
	Kind        string              `json:"kind"`
	VMID        *string             `json:"vm_id,omitempty"`
	Phase       string              `json:"phase"`
	State       string              `json:"state"`
	Error       *wireOperationError `json:"error,omitempty"`
	Attempt     int                 `json:"attempt"`
	CreatedAt   string              `json:"created_at"`
	UpdatedAt   string              `json:"updated_at"`
}

// wireActiveRun is the compact run summary in the per-VM changed_vms entry.
// The key is omitted entirely when no active run exists (§12.7).
type wireActiveRun struct {
	RunID string `json:"run_id"`
	Phase string `json:"phase"`
}

// wireChangedVM is the compact per-VM entry in situation's changed_vms list.
type wireChangedVM struct {
	VMID            string            `json:"vm_id"`
	Name            string            `json:"name"`
	LifecycleState  string            `json:"lifecycle_state"`
	TelemetryHealth string            `json:"telemetry_health"`
	ActiveRun       *wireActiveRun    `json:"active_run,omitempty"` // omitted when no active run
	AttentionOpen   int64             `json:"attention_open"`
	Links           map[string]string `json:"links"`
}

type wireTemplate struct {
	TemplateID             string            `json:"template_id"`
	Description            string            `json:"description"`
	Digest                 string            `json:"digest"`
	KernelImage            string            `json:"kernel_image"`
	RootImage              string            `json:"root_image"`
	GuestPrivilegeProfiles []string          `json:"guest_privilege_profiles"`
	Sensors                []string          `json:"sensors"`
	ProtocolVersions       map[string]string `json:"protocol_versions"`
}

// --- render helpers ---

func renderVM(vm *store.VM) wireVM {
	labels := vm.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	w := wireVM{
		VMID:           vm.VMID,
		Name:           vm.Name,
		Owner:          vm.Owner,
		TemplateID:     vm.TemplateID,
		TemplateDigest: vm.TemplateDigest,
		DesiredState:   vm.DesiredState,
		ObservedState:  vm.ObservedState,
		Revision:       strconv.FormatInt(vm.Revision, 10),
		Resources: wireVMResources{
			VCPUCount:        vm.VCPUCount,
			MemoryMiB:        vm.MemoryMiB,
			RootDiskMiB:      vm.RootDiskMiB,
			WorkspaceDiskMiB: vm.WorkspaceDiskMiB,
		},
		NetworkProfile:  vm.NetworkProfile,
		NetworkPolicyID: vm.NetworkPolicyID,
		Labels:          labels,
		CreatedAt:       vm.CreatedAt,
		UpdatedAt:       vm.UpdatedAt,
		Links: map[string]string{
			"events": basePath + "/events?vm_id=" + vm.VMID,
		},
	}
	if vm.FailureStage != nil || vm.FailureReason != nil {
		f := &wireVMFailure{}
		if vm.FailureStage != nil {
			f.Stage = *vm.FailureStage
		}
		if vm.FailureReason != nil {
			f.Reason = *vm.FailureReason
		}
		w.Failure = f
	}
	return w
}

func renderOperationID(id int64) string { return fmt.Sprintf("op-%06d", id) }

func parseOperationID(raw string) (int64, bool) {
	s := strings.TrimPrefix(raw, "op-")
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

func renderOperation(op *store.Operation) wireOperation {
	w := wireOperation{
		OperationID: renderOperationID(op.OperationID),
		Kind:        op.Kind,
		VMID:        op.VMID,
		Phase:       op.Phase,
		State:       op.State,
		Attempt:     op.Attempt,
		CreatedAt:   op.CreatedAt,
		UpdatedAt:   op.UpdatedAt,
	}
	if op.ErrorCause != nil {
		w.Error = &wireOperationError{Cause: *op.ErrorCause}
		if op.ErrorMessage != nil {
			w.Error.Message = *op.ErrorMessage
		}
	}
	return w
}

func renderChangedVM(vm *store.VM, attentionOpen int64, activeRun *store.Run) wireChangedVM {
	w := wireChangedVM{
		VMID:            vm.VMID,
		Name:            vm.Name,
		LifecycleState:  vm.ObservedState,
		TelemetryHealth: "unknown", // honest: no sensors exist yet
		AttentionOpen:   attentionOpen,
		Links: map[string]string{
			"vm": basePath + "/vms/" + vm.VMID,
		},
	}
	if activeRun != nil {
		w.ActiveRun = &wireActiveRun{
			RunID: activeRun.RunID,
			Phase: activeRun.Phase,
		}
	}
	return w
}

func renderTemplate(id string, tpl runtime.Template) wireTemplate {
	profiles := tpl.GuestPrivilegeProfiles
	if profiles == nil {
		profiles = []string{}
	}
	sensors := tpl.Sensors
	if sensors == nil {
		sensors = []string{}
	}
	versions := tpl.ProtocolVersions
	if versions == nil {
		versions = map[string]string{}
	}
	return wireTemplate{
		TemplateID:             id,
		Description:            tpl.Description,
		Digest:                 tpl.Digest,
		KernelImage:            tpl.KernelImage,
		RootImage:              tpl.RootImage,
		GuestPrivilegeProfiles: profiles,
		Sensors:                sensors,
		ProtocolVersions:       versions,
	}
}

// --- error mapping ---

// writeVMError maps store/runtime errors to the API error taxonomy. It uses
// the same Error/Remediation types as the rest of the API surface.
func writeVMError(w http.ResponseWriter, err error) {
	// 501: runtime unavailable — this host cannot launch VMs.
	var unavail *runtime.UnavailableError
	if errors.As(err, &unavail) {
		writeError(w, http.StatusNotImplemented, Error{
			Code:      "missing_capability",
			Message:   "runtime not available on this host: " + unavail.Reason,
			Retryable: false,
			Cause:     "runtime_unavailable",
			Details:   map[string]any{"reason": unavail.Reason},
			Remediation: []Remediation{{
				Action:    "get",
				Params:    map[string]any{"path": basePath + "/host/status"},
				Rationale: "the Linux/KVM track host (aibox03) provides the firecracker runtime; this dev host cannot launch VMs",
			}},
		})
		return
	}

	// 409: admission refused — capacity shortfall.
	var refusal *store.AdmissionRefusal
	if errors.As(err, &refusal) {
		writeError(w, http.StatusConflict, Error{
			Code:      "insufficient_capacity",
			Message:   "host cannot admit this VM: " + refusal.Message,
			Retryable: false,
			Cause:     "admission_refused",
			Details:   map[string]any{"shortfall": refusal.Message},
			Remediation: []Remediation{
				{
					Action:    "get",
					Params:    map[string]any{"path": basePath + "/host/status"},
					Rationale: "shows current reservations, usable capacity, and active VMs",
				},
				{
					Action:    "post",
					Params:    map[string]any{"path": basePath + "/vms/{id}/actions", "body": map[string]string{"action": "stop"}},
					Rationale: "stopping a running VM releases its memory and CPU reservation",
				},
			},
		})
		return
	}

	// 409: idempotency key reused with a different payload.
	if errors.Is(err, store.ErrIdempotencyConflict) {
		writeError(w, http.StatusConflict, Error{
			Code:      "idempotency_conflict",
			Message:   "the idempotency key was already used for a different request",
			Retryable: false,
			Cause:     "idempotency_key_reused",
			Remediation: []Remediation{
				{
					Action:    "get",
					Params:    map[string]any{"path": basePath + "/operations/{id}"},
					Rationale: "retrieve the original operation by its ID",
				},
			},
		})
		return
	}

	// 409: stale revision on a conflicting lifecycle change.
	var revErr *store.RevisionMismatchError
	if errors.As(err, &revErr) {
		writeError(w, http.StatusConflict, Error{
			Code:      "revision_mismatch",
			Message:   fmt.Sprintf("revision is now %s; re-read the VM and retry", strconv.FormatInt(revErr.Current, 10)),
			Retryable: true,
			Cause:     "optimistic_concurrency_failure",
			Details:   map[string]any{"current_revision": strconv.FormatInt(revErr.Current, 10)},
			Remediation: []Remediation{{
				Action:    "get",
				Params:    map[string]any{"path": basePath + "/vms/{id}"},
				Rationale: "read the current revision before retrying the action",
			}},
		})
		return
	}

	// 409: the requested transition is not in the §5.2 matrix.
	var txnErr *store.InvalidTransitionError
	if errors.As(err, &txnErr) {
		writeError(w, http.StatusConflict, Error{
			Code:      "invalid_transition",
			Message:   fmt.Sprintf("cannot transition from %q to %q", txnErr.From, txnErr.To),
			Retryable: false,
			Cause:     "lifecycle_state_machine",
			Details:   map[string]any{"from": txnErr.From, "to": txnErr.To},
		})
		return
	}

	// 409: delete attempted while VM is still live.
	if errors.Is(err, store.ErrVMLive) {
		writeError(w, http.StatusConflict, Error{
			Code:      "vm_live",
			Message:   "cannot delete a live VM without force-stop",
			Retryable: false,
			Cause:     "vm_still_running",
			Remediation: []Remediation{
				{
					Action:    "post",
					Params:    map[string]any{"path": basePath + "/vms/{id}/actions", "body": map[string]string{"action": "stop"}},
					Rationale: "stop the VM first, then delete",
				},
				{
					Action:    "delete",
					Params:    map[string]any{"path": basePath + "/vms/{id}?force=true"},
					Rationale: "force=true stops and deletes in one request",
				},
			},
		})
		return
	}

	// 400: requested template not in approved registry.
	var tplErr *runtime.ErrTemplateUnknown
	if errors.As(err, &tplErr) {
		writeError(w, http.StatusBadRequest, Error{
			Code:      "template_unknown",
			Message:   tplErr.Error(),
			Retryable: false,
			Cause:     "template_not_found",
			Details:   map[string]any{"requested": tplErr.Requested, "known": tplErr.KnownIDs},
			Remediation: []Remediation{{
				Action:    "get",
				Params:    map[string]any{"path": basePath + "/templates"},
				Rationale: "lists the approved templates available on this host",
			}},
		})
		return
	}

	// 400: invalid request body (name missing, name too long, etc.).
	var badReq *runtime.ErrInvalidRequest
	if errors.As(err, &badReq) {
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   badReq.Reason,
			Retryable: false,
			Cause:     "body_invalid",
		})
		return
	}

	// 400: unknown action name.
	var actErr *runtime.ErrUnknownAction
	if errors.As(err, &actErr) {
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   actErr.Error(),
			Retryable: false,
			Cause:     "body_invalid",
			Details:   map[string]any{"valid_actions": actErr.Known},
		})
		return
	}

	// 500: the runtime could not release a VM's resources. Retryable, and named
	// so the operator looks at the host rather than the database: the row is
	// still readable at "deleting", and whatever survived the release is still
	// on the machine.
	var relErr *runtime.ErrReleaseFailed
	if errors.As(err, &relErr) {
		writeError(w, http.StatusInternalServerError, Error{
			Code:      "internal",
			Message:   "could not release the VM's host resources: " + relErr.Reason,
			Retryable: true,
			Cause:     "resource_release_failed",
			Details:   map[string]any{"vm_id": relErr.VMID, "reason": relErr.Reason},
			Remediation: []Remediation{
				{
					Action:    "get",
					Params:    map[string]any{"path": basePath + "/vms/{id}"},
					Rationale: "the VM stays in deleting until its resources are released",
				},
				{
					Action:    "delete",
					Params:    map[string]any{"path": basePath + "/vms/{id}?force=true"},
					Rationale: "retry the delete once the cause of the release failure is cleared",
				},
			},
		})
		return
	}

	// 404: VM not found.
	if errors.Is(err, store.ErrVMUnknown) {
		writeError(w, http.StatusNotFound, Error{
			Code:      "not_found",
			Message:   "VM not found",
			Retryable: false,
			Cause:     "vm_unknown",
			Remediation: []Remediation{{
				Action:    "get",
				Params:    map[string]any{"path": basePath + "/vms"},
				Rationale: "list all VMs",
			}},
		})
		return
	}

	// 404: operation not found.
	if errors.Is(err, store.ErrOperationUnknown) {
		writeError(w, http.StatusNotFound, Error{
			Code:      "not_found",
			Message:   "operation not found",
			Retryable: false,
			Cause:     "operation_unknown",
			Remediation: []Remediation{{
				Action:    "get",
				Params:    map[string]any{"path": basePath + "/operations/{id}"},
				Rationale: "the operation ID is in the vm.create or vm.action response",
			}},
		})
		return
	}

	// 500: unexpected.
	writeError(w, http.StatusInternalServerError, Error{
		Code:      "internal",
		Message:   "unexpected error",
		Retryable: true,
		Cause:     "storage_failure",
	})
}

// resourceOwner checks that the resource's stored owner matches the caller's
// authenticated identity. When they differ it writes the standard not_found 404
// (same body as an unknown ID — no existence oracle) and returns false. The
// caller must return immediately without any further action or store write.
//
// This deliberately produces the same response as ErrVMUnknown / ErrRunNotFound
// so a cross-owner request is indistinguishable from a missing resource (AT-079).
func (s *Server) resourceOwner(w http.ResponseWriter, r *http.Request, fetchedOwner string) bool {
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
	if ident.Owner != fetchedOwner {
		// Deliberately indistinguishable from "not found": AT-079.
		writeError(w, http.StatusNotFound, Error{
			Code:      "not_found",
			Message:   "VM not found",
			Retryable: false,
			Cause:     "vm_unknown",
			Remediation: []Remediation{{
				Action:    "get",
				Params:    map[string]any{"path": basePath + "/vms"},
				Rationale: "list all VMs",
			}},
		})
		return false
	}
	return true
}

// --- handlers ---

func (s *Server) handleHostStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	cap, err := s.manager.Capacity(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{
			Code: "internal", Message: "capacity query failed", Retryable: true, Cause: "storage_failure",
		})
		return
	}

	diag, err := s.store.Diagnostics(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{
			Code: "internal", Message: "storage diagnostics failed", Retryable: true, Cause: "storage_failure",
		})
		return
	}

	counts, err := s.store.CountVMsByObservedState(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{
			Code: "internal", Message: "vm count query failed", Retryable: true, Cause: "storage_failure",
		})
		return
	}

	// runtime.available: nil error means available.
	rtAvailable := true
	rtReason := ""
	if err := s.manager.Availability(ctx); err != nil {
		rtAvailable = false
		var u *runtime.UnavailableError
		if errors.As(err, &u) {
			rtReason = u.Reason
		} else {
			rtReason = err.Error()
		}
	}

	resp := map[string]any{
		"capacity": map[string]any{
			"usable_memory_mib":   cap.UsableMemoryMiB,
			"reserved_memory_mib": cap.ReservedMemoryMiB,
			"free_memory_mib":     cap.FreeMemoryMiB,
			"usable_vcpu":         cap.UsableVCPU,
			"reserved_vcpu":       cap.ReservedVCPU,
			"free_vcpu":           cap.FreeVCPU,
			"usable_disk_mib":     cap.UsableDiskMiB,
			"reserved_disk_mib":   cap.ReservedDiskMiB,
			"free_disk_mib":       cap.FreeDiskMiB,
			"active_vms":          cap.ActiveVMs,
		},
		"runtime": map[string]any{
			"available": rtAvailable,
			"reason":    rtReason,
		},
		"storage": diag,
		"vms":     counts,
	}

	// Admission parameters: what the host charges and caps, published so the
	// launch form's reservation preview restates API-served numbers instead of
	// computing a private truth (SPEC §13).
	adm := s.manager.AdmissionParams()
	resp["admission"] = map[string]any{
		"allow_memory_overcommit":          adm.AllowMemoryOvercommit,
		"cpu_overcommit_ratio":             adm.CPUOvercommitRatio,
		"reserve_per_vm_host_overhead_mib": adm.ReservePerVMHostOverheadMiB,
		"max_parallel_provisions":          adm.MaxParallelProvisions,
		"max_batch_size":                   adm.MaxBatchSize,
	}

	// Per-VM defaults: what a create request gets for any resource it omits.
	// The launch form prefills from these and renders the fields it cannot set
	// yet at the value the host would apply anyway.
	def := s.manager.DefaultParams()
	resp["vm_defaults"] = map[string]any{
		"vcpu_count":            def.VCPUCount,
		"memory_mib":            def.MemoryMiB,
		"root_disk_mib":         def.RootDiskMiB,
		"workspace_disk_mib":    def.WorkspaceDiskMiB,
		"guest_privilege":       def.GuestPrivilege,
		"network_profile":       def.NetworkProfile,
		"network_policy_id":     def.NetworkPolicyID,
		"max_terminal_sessions": def.MaxTerminalSessions,
		"stop_grace_seconds":    def.StopGraceSeconds,
	}

	// Preflight block: present only when the hook is wired. Never an empty fake block.
	if s.preflight != nil {
		refresh := r.URL.Query().Get("refresh") == "1"
		report := s.preflight(ctx, refresh)
		resp["preflight"] = report
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleTemplates(w http.ResponseWriter, r *http.Request) {
	tpls := s.manager.Templates()
	ids := make([]string, 0, len(tpls))
	for id := range tpls {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]wireTemplate, 0, len(ids))
	for _, id := range ids {
		out = append(out, renderTemplate(id, tpls[id]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"templates": out})
}

// createVMBody is the allowed create request shape. DisallowUnknownFields at
// decode time means any extra key is a 400, preventing silent field ignorance.
type createVMBody struct {
	Name             string            `json:"name"`
	TemplateID       string            `json:"template_id"`
	IdempotencyKey   *string           `json:"idempotency_key"`
	VCPUCount        int               `json:"vcpu_count"`
	MemoryMiB        int64             `json:"memory_mib"`
	RootDiskMiB      int64             `json:"root_disk_mib"`
	WorkspaceDiskMiB int64             `json:"workspace_disk_mib"`
	Labels           map[string]string `json:"labels"`
	// Run is an optional launch-attached run block. R2 validation is applied
	// before the request reaches the store.
	Run *runBlockBody `json:"run"`
}

func (s *Server) handleCreateVM(w http.ResponseWriter, r *http.Request) {
	// Owner comes from the authenticated identity; never from the request body.
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
	var body createVMBody
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   fmt.Sprintf("cannot decode request body: %v", err),
			Retryable: false,
			Cause:     "body_invalid",
		})
		return
	}

	// R2: validate the run block before persisting anything.
	if body.Run != nil {
		if !validateRunBlockHTTP(w, body.Run) {
			return
		}
	}

	req := runtime.CreateRequest{
		Name:             body.Name,
		TemplateID:       body.TemplateID,
		IdempotencyKey:   body.IdempotencyKey,
		VCPUCount:        body.VCPUCount,
		MemoryMiB:        body.MemoryMiB,
		RootDiskMiB:      body.RootDiskMiB,
		WorkspaceDiskMiB: body.WorkspaceDiskMiB,
		Labels:           body.Labels,
	}
	if body.Run != nil {
		req.Run = &store.RunAttachment{
			Goal:           body.Run.Goal,
			CriteriaType:   body.Run.SuccessCriteria.Type,
			OnCompletion:   body.Run.OnCompletion,
			ProgressEvents: body.Run.ProgressEvents,
		}
	}
	// Provisioning outlives the client that asked for it: see Manager.OperationContext.
	opCtx, cancel := s.manager.OperationContext(r.Context())
	defer cancel()
	vm, op, replayed, err := s.manager.CreateVM(opCtx, ident.Owner, req)
	if err != nil {
		writeVMError(w, err)
		return
	}
	// Replays return the same 201 as the original request (retry-transparent
	// status) with is_replay marking the truth of what happened.
	resp := map[string]any{
		"vm":        renderVM(vm),
		"operation": renderOperation(op),
	}
	if replayed {
		resp["is_replay"] = true
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleListVMs(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	ident, ok := auth.IdentityFrom(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, Error{
			Code: "internal", Message: "no identity in context", Retryable: false, Cause: "no_identity",
		})
		return
	}
	q := store.VMQuery{Owner: ident.Owner}

	if raw := params.Get("after"); raw != "" {
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, Error{
				Code: "malformed_request", Message: "after must be a decimal row_id",
				Retryable: false, Cause: "query_parameter_invalid",
			})
			return
		}
		q.After = v
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
	// ?state= is repeatable; e.g. ?state=running&state=paused.
	q.States = params["state"]

	vms, err := s.store.ListVMs(r.Context(), q)
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
		writeError(w, http.StatusInternalServerError, Error{
			Code: "internal", Message: "list vms failed", Retryable: true, Cause: "storage_failure",
		})
		return
	}

	wireVMs := make([]wireVM, 0, len(vms))
	for _, vm := range vms {
		wireVMs = append(wireVMs, renderVM(vm))
	}
	nextAfter := ""
	if len(vms) > 0 {
		nextAfter = strconv.FormatInt(vms[len(vms)-1].RowID, 10)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"vms":        wireVMs,
		"next_after": nextAfter,
	})
}

func (s *Server) handleGetVM(w http.ResponseWriter, r *http.Request) {
	vmID := r.PathValue("id")
	vm, err := s.store.GetVM(r.Context(), vmID)
	if err != nil {
		writeVMError(w, err)
		return
	}
	if !s.resourceOwner(w, r, vm.Owner) {
		return
	}
	writeJSON(w, http.StatusOK, renderVM(vm))
}

type vmActionBody struct {
	Action           string `json:"action"`
	ExpectedRevision string `json:"expected_revision"`
}

func (s *Server) handleVMAction(w http.ResponseWriter, r *http.Request) {
	vmID := r.PathValue("id")

	// Fetch first, then check ownership — no action operation is created on the
	// denied path (AT-079: no side effects).
	vm, err := s.store.GetVM(r.Context(), vmID)
	if err != nil {
		writeVMError(w, err)
		return
	}
	if !s.resourceOwner(w, r, vm.Owner) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var body vmActionBody
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   fmt.Sprintf("cannot decode action body: %v", err),
			Retryable: false,
			Cause:     "body_invalid",
		})
		return
	}

	// expected_revision is required (SPEC §14: conflicting lifecycle changes need it).
	if body.ExpectedRevision == "" {
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   "expected_revision is required to prevent concurrent modification",
			Retryable: false,
			Cause:     "body_invalid",
			Remediation: []Remediation{{
				Action:    "get",
				Params:    map[string]any{"path": basePath + "/vms/" + vmID},
				Rationale: "read the VM to get the current revision, then submit the action",
			}},
		})
		return
	}
	rev, err := strconv.ParseInt(body.ExpectedRevision, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   "expected_revision must be a decimal integer",
			Retryable: false,
			Cause:     "body_invalid",
		})
		return
	}

	// A stop that has begun must finish even if the client hangs up mid-flight:
	// see Manager.OperationContext.
	opCtx, cancel := s.manager.OperationContext(r.Context())
	defer cancel()
	updVM, op, err := s.manager.Action(opCtx, vmID, body.Action, &rev)
	if err != nil {
		writeVMError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"vm":        renderVM(updVM),
		"operation": renderOperation(op),
	})
}

func (s *Server) handleDeleteVM(w http.ResponseWriter, r *http.Request) {
	vmID := r.PathValue("id")

	// Fetch first, then check ownership — no store mutation on the denied path.
	existingVM, err := s.store.GetVM(r.Context(), vmID)
	if err != nil {
		writeVMError(w, err)
		return
	}
	if !s.resourceOwner(w, r, existingVM.Owner) {
		return
	}

	params := r.URL.Query()
	force := params.Get("force") == "true"

	var expectedRev *int64
	if raw := params.Get("expected_revision"); raw != "" {
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, Error{
				Code:      "malformed_request",
				Message:   "expected_revision must be a decimal integer",
				Retryable: false,
				Cause:     "query_parameter_invalid",
			})
			return
		}
		expectedRev = &v
	}

	// A delete that has begun must finish even if the client hangs up mid-flight:
	// see Manager.OperationContext.
	opCtx, cancel := s.manager.OperationContext(r.Context())
	defer cancel()
	vm, err := s.manager.Delete(opCtx, vmID, force, expectedRev)
	if err != nil {
		writeVMError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"vm": renderVM(vm)})
}

func (s *Server) handleGetOperation(w http.ResponseWriter, r *http.Request) {
	raw := r.PathValue("id")
	id, ok := parseOperationID(raw)
	if !ok {
		writeError(w, http.StatusBadRequest, Error{
			Code:      "malformed_request",
			Message:   fmt.Sprintf("operation id %q is not in op-NNNNNN format", raw),
			Retryable: false,
			Cause:     "path_parameter_invalid",
		})
		return
	}
	op, err := s.store.GetOperation(r.Context(), id)
	if err != nil {
		writeVMError(w, err)
		return
	}
	// Operation ownership check post-fetch (AT-079: indistinguishable from missing).
	ident, identOK := auth.IdentityFrom(r.Context())
	if !identOK {
		writeError(w, http.StatusInternalServerError, Error{
			Code: "internal", Message: "no identity in context", Retryable: false, Cause: "no_identity",
		})
		return
	}
	if op.Owner != ident.Owner {
		writeError(w, http.StatusNotFound, Error{
			Code:      "not_found",
			Message:   "operation not found",
			Retryable: false,
			Cause:     "operation_unknown",
			Remediation: []Remediation{{
				Action:    "get",
				Params:    map[string]any{"path": basePath + "/operations/{id}"},
				Rationale: "the operation ID is in the vm.create or vm.action response",
			}},
		})
		return
	}
	writeJSON(w, http.StatusOK, renderOperation(op))
}
