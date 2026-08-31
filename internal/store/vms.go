// ABOUTME: VM registry, operations, and admission reservations (SPEC §5, §6):
// ABOUTME: transactional create/transition with durable lifecycle events.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// --- sentinel errors ---

var (
	// ErrVMUnknown: no VM has this vm_id.
	ErrVMUnknown = errors.New("vm not found")
	// ErrOperationUnknown: no operation has this id.
	ErrOperationUnknown = errors.New("operation not found")
	// ErrIdempotencyConflict: same (owner, kind, key) exists with a different request hash.
	ErrIdempotencyConflict = errors.New("idempotency key conflict: same key used for a different request; use a different key or retrieve the original result")
)

// AdmissionRefusal is the typed error an Admit callback returns when the host
// cannot accept the VM. The store persists Cause and Message on the failed
// operation as durable refusal evidence.
type AdmissionRefusal struct {
	Cause   string
	Message string
}

func (a *AdmissionRefusal) Error() string {
	return fmt.Sprintf("admission refused: %s: %s", a.Cause, a.Message)
}

// replayedRefusal reconstructs the original refusal outcome from its durable
// operation, for idempotent replays of a refused create. The operation row is
// the source of truth; only rows our own refusal path wrote reach here, so a
// missing cause is reported as the storage inconsistency it would be.
func replayedRefusal(op *Operation) error {
	if op.State != "failed" || op.ErrorCause == nil {
		return fmt.Errorf("operation %d has no vm and no recorded refusal: state %q", op.OperationID, op.State)
	}
	msg := ""
	if op.ErrorMessage != nil {
		msg = *op.ErrorMessage
	}
	return &AdmissionRefusal{Cause: *op.ErrorCause, Message: msg}
}

// RevisionMismatchError carries the revision that was current when the
// conflict was detected, so callers can retry with a fresh read.
type RevisionMismatchError struct {
	Current int64
}

func (e *RevisionMismatchError) Error() string {
	return fmt.Sprintf("revision mismatch: current revision is %d; read the VM again before retrying", e.Current)
}

func (e *RevisionMismatchError) Is(target error) bool {
	_, ok := target.(*RevisionMismatchError)
	return ok
}

// InvalidTransitionError names the rejected transition so the caller can
// surface the exact state pair in a remediation hint.
type InvalidTransitionError struct {
	From string
	To   string
}

func (e *InvalidTransitionError) Error() string {
	return fmt.Sprintf("transition %s→%s is not valid (SPEC §5.2)", e.From, e.To)
}

func (e *InvalidTransitionError) Is(target error) bool {
	_, ok := target.(*InvalidTransitionError)
	return ok
}

// ErrVMLive: deletion rejected because the VM is still live. Force-stop first.
var ErrVMLive = errors.New("vm is still live; stop or force-stop before deleting")

// validTransitions encodes the SPEC §5.2 state machine exactly.
var validTransitions = map[string][]string{
	"provisioning": {"starting", "failed", "stopping"},
	"starting":     {"running", "failed", "stopping"},
	"running":      {"paused", "stopping", "failed"},
	"paused":       {"running", "stopping", "failed"},
	"stopping":     {"stopped", "failed"},
	"stopped":      {"starting", "deleting"},
	"failed":       {"deleting"},
	"deleting":     {"deleted"},
}

func transitionAllowed(from, to string) bool {
	for _, allowed := range validTransitions[from] {
		if allowed == to {
			return true
		}
	}
	return false
}

// --- wire types ---

// VM is one row of the VM registry.
type VM struct {
	RowID            int64 // keyset cursor; never exposed as identity
	VMID             string
	Name             string
	Owner            string
	TemplateID       string
	TemplateDigest   string
	DesiredState     string
	ObservedState    string
	Revision         int64
	VCPUCount        int
	MemoryMiB        int64
	RootDiskMiB      int64
	WorkspaceDiskMiB int64
	NetworkProfile   string
	NetworkPolicyID  string
	Labels           map[string]string
	FailureStage     *string
	FailureReason    *string
	CreatedAt        string
	UpdatedAt        string
}

// Operation is one row of the operations log.
type Operation struct {
	OperationID    int64
	Owner          string
	Kind           string
	IdempotencyKey *string
	RequestHash    string
	VMID           *string
	Phase          string
	State          string
	ErrorCause     *string
	ErrorMessage   *string
	Attempt        int
	CreatedAt      string
	UpdatedAt      string
}

// Reservation is one row of the reservations table.
type Reservation struct {
	VMID            string
	MemoryTotalMiB  int64
	VCPU            int
	DiskMiB         int64
	ComputeReleased bool
	Released        bool
	CreatedAt       string
	UpdatedAt       string
}

// ReservationTotals is the aggregate admission view.
type ReservationTotals struct {
	MemoryMiB int64 // sum of memory_total_mib for non-released, non-compute-released rows
	VCPU      int64 // sum of vcpu for non-released, non-compute-released rows
	DiskMiB   int64 // sum of disk_mib for non-released rows (stopped VMs keep disk)
	ActiveVMs int   // count of non-released rows
}

// --- inputs ---

// CreateVMInput carries everything needed to atomically create a VM record,
// reserve capacity, and open an operation — all in one transaction.
type CreateVMInput struct {
	VMID             string
	Name             string
	Owner            string
	TemplateID       string
	TemplateDigest   string
	VCPUCount        int
	MemoryMiB        int64
	RootDiskMiB      int64
	WorkspaceDiskMiB int64
	MemoryTotalMiB   int64 // guest RAM + per-VM host overhead
	NetworkProfile   string
	NetworkPolicyID  string
	Labels           map[string]string
	Kind             string                        // "vm.create"
	IdempotencyKey   *string                       // nil means no idempotency tracking for this call
	RequestHash      string                        // hex sha256 of the canonical request
	Admit            func(ReservationTotals) error // evaluated inside the tx
}

// TransitionInput carries everything needed to advance a VM's lifecycle state.
type TransitionInput struct {
	VMID             string
	ExpectedRevision *int64 // nil skips the optimistic-concurrency check
	To               string
	Reason           string
	OperationID      int64
	DesiredState     *string // set when the desired state also changes
	FailureStage     *string // set when transitioning to "failed"
	FailureReason    *string
	ReleaseCompute   bool    // true on stopped: frees RAM+CPU but keeps disk
	ReleaseAll       bool    // true on deleted: frees everything
	BootID           *string // non-nil when a new boot identity is established
}

// OperationUpdate advances an operation's phase/state.
type OperationUpdate struct {
	OperationID  int64
	Phase        string
	State        string
	ErrorCause   *string
	ErrorMessage *string
}

// VMQuery pages VMs by row_id keyset with an optional state filter.
type VMQuery struct {
	After  int64    // row_id cursor; 0 = from the start
	Limit  int      // 0 = DefaultPageLimit
	States []string // nil/empty = all states
}

// --- CreateVMWithOperation ---

// CreateVMWithOperation atomically creates a VM record, checks admission, and
// records a durable operation — all in one writer transaction. On admission
// refusal it still commits a failed operation for evidence (AT-012).
func (s *Store) CreateVMWithOperation(ctx context.Context, in CreateVMInput) (*VM, *Operation, error) {
	// Idempotency check first (quick readers path before we take the writer lock).
	// We re-check inside the tx; this is an optimistic early exit.
	if in.IdempotencyKey != nil {
		vm, op, err := s.lookupByIdempotencyKey(ctx, in.Owner, in.Kind, *in.IdempotencyKey, in.RequestHash)
		if err != nil {
			return nil, nil, err
		}
		if vm != nil {
			return vm, op, nil
		}
	}

	labels := in.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	labelsJSON, err := json.Marshal(labels)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal labels: %w", err)
	}

	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("begin create-vm: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Re-check idempotency inside the tx (serialization point).
	if in.IdempotencyKey != nil {
		var existingOpID int64
		var existingHash string
		err := tx.QueryRowContext(ctx,
			`SELECT operation_id, request_hash FROM operations WHERE owner = ? AND kind = ? AND idempotency_key = ?`,
			in.Owner, in.Kind, *in.IdempotencyKey,
		).Scan(&existingOpID, &existingHash)
		switch {
		case err == nil:
			if existingHash != in.RequestHash {
				return nil, nil, ErrIdempotencyConflict
			}
			// Replay: load the existing VM and operation.
			var existingVMID sql.NullString
			if err := tx.QueryRowContext(ctx,
				`SELECT vm_id FROM operations WHERE operation_id = ?`, existingOpID,
			).Scan(&existingVMID); err != nil {
				return nil, nil, fmt.Errorf("replay vm lookup: %w", err)
			}
			if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
				return nil, nil, fmt.Errorf("rollback replay: %w", err)
			}
			op, err := s.GetOperation(ctx, existingOpID)
			if err != nil {
				return nil, nil, err
			}
			if !existingVMID.Valid {
				// The original request was refused at admission. A repeated
				// identical request returns the original outcome (SPEC §14),
				// reconstructed from the durable operation — admission is not
				// re-run; a fresh attempt needs a fresh idempotency key.
				return nil, op, replayedRefusal(op)
			}
			vm, err := s.GetVM(ctx, existingVMID.String)
			if err != nil {
				return nil, nil, err
			}
			return vm, op, nil
		case !errors.Is(err, sql.ErrNoRows):
			return nil, nil, fmt.Errorf("idempotency lookup: %w", err)
		}
	}

	// Compute admission totals inside the tx.
	totals, err := reservationTotalsInTx(ctx, tx)
	if err != nil {
		return nil, nil, fmt.Errorf("read reservations: %w", err)
	}

	admitErr := in.Admit(totals)
	if admitErr != nil {
		// Must be an *AdmissionRefusal for durable evidence; anything else is
		// an internal error that aborts without committing.
		var refusal *AdmissionRefusal
		if !errors.As(admitErr, &refusal) {
			return nil, nil, fmt.Errorf("admit callback internal error: %w", admitErr)
		}

		// Insert a failed operation as durable evidence.
		res, err := tx.ExecContext(ctx,
			`INSERT INTO operations (owner, kind, idempotency_key, request_hash, vm_id, phase, state, error_cause, error_message, created_at, updated_at)
			 VALUES (?, ?, ?, ?, NULL, 'admission', 'failed', ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
			in.Owner, in.Kind, nullable(in.IdempotencyKey), in.RequestHash, refusal.Cause, refusal.Message)
		if err != nil {
			return nil, nil, fmt.Errorf("insert failed operation: %w", err)
		}
		opID, _ := res.LastInsertId()
		if _, err := s.appendSystemInTx(ctx, tx, s.systemEnvelope("operation.state_changed", "registry", notApplicableQuality(), map[string]any{
			"operation_id": strconv.FormatInt(opID, 10),
			"kind":         in.Kind,
			"vm_id":        nil,
			"phase":        "admission",
			"state":        "failed",
			"attempt":      1,
			"error":        map[string]any{"cause": refusal.Cause, "message": refusal.Message},
		})); err != nil {
			return nil, nil, fmt.Errorf("append refusal event: %w", err)
		}

		op, err := scanOperationInTx(ctx, tx, opID)
		if err != nil {
			return nil, nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, nil, fmt.Errorf("commit failed-op: %w", err)
		}
		return nil, op, admitErr
	}

	// Admission granted — insert vm, operation, reservation rows.
	vmRes, err := tx.ExecContext(ctx,
		`INSERT INTO vms (vm_id, name, owner, template_id, template_digest, desired_state, observed_state, revision, vcpu, memory_mib, root_disk_mib, workspace_disk_mib, network_profile, network_policy_id, labels, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, 'running', 'provisioning', 1, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
		in.VMID, in.Name, in.Owner, in.TemplateID, in.TemplateDigest,
		in.VCPUCount, in.MemoryMiB, in.RootDiskMiB, in.WorkspaceDiskMiB,
		in.NetworkProfile, in.NetworkPolicyID, string(labelsJSON))
	if err != nil {
		return nil, nil, fmt.Errorf("insert vm: %w", err)
	}
	_ = vmRes // row_id not needed; vm_id is the identity

	opRes, err := tx.ExecContext(ctx,
		`INSERT INTO operations (owner, kind, idempotency_key, request_hash, vm_id, phase, state, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, 'admitted', 'running', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
		in.Owner, in.Kind, nullable(in.IdempotencyKey), in.RequestHash, in.VMID)
	if err != nil {
		return nil, nil, fmt.Errorf("insert operation: %w", err)
	}
	opID, _ := opRes.LastInsertId()

	diskMiB := in.RootDiskMiB + in.WorkspaceDiskMiB
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO reservations (vm_id, memory_total_mib, vcpu, disk_mib, created_at, updated_at)
		 VALUES (?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
		in.VMID, in.MemoryTotalMiB, in.VCPUCount, diskMiB); err != nil {
		return nil, nil, fmt.Errorf("insert reservation: %w", err)
	}

	// Durable events.
	if _, err := s.appendSystemInTx(ctx, tx, s.systemEnvelope("vm.created", "registry", notApplicableQuality(), map[string]any{
		"vm_id":           in.VMID,
		"name":            in.Name,
		"template_id":     in.TemplateID,
		"template_digest": in.TemplateDigest,
		"operation_id":    strconv.FormatInt(opID, 10),
		"owner":           in.Owner,
		"resources": map[string]any{
			"vcpu":               in.VCPUCount,
			"memory_mib":         in.MemoryMiB,
			"root_disk_mib":      in.RootDiskMiB,
			"workspace_disk_mib": in.WorkspaceDiskMiB,
		},
	})); err != nil {
		return nil, nil, err
	}
	if _, err := s.appendSystemInTx(ctx, tx, s.systemEnvelope("operation.state_changed", "registry", notApplicableQuality(), map[string]any{
		"operation_id": strconv.FormatInt(opID, 10),
		"kind":         in.Kind,
		"vm_id":        in.VMID,
		"phase":        "admitted",
		"state":        "running",
		"attempt":      1,
	})); err != nil {
		return nil, nil, err
	}

	vm, err := scanVMInTx(ctx, tx, in.VMID)
	if err != nil {
		return nil, nil, err
	}
	op, err := scanOperationInTx(ctx, tx, opID)
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("commit create-vm: %w", err)
	}
	return vm, op, nil
}

// lookupByIdempotencyKey is the optimistic readers-path check before taking the writer.
func (s *Store) lookupByIdempotencyKey(ctx context.Context, owner, kind, key, requestHash string) (*VM, *Operation, error) {
	var opID int64
	var hash string
	err := s.readers.QueryRowContext(ctx,
		`SELECT operation_id, request_hash FROM operations WHERE owner = ? AND kind = ? AND idempotency_key = ?`,
		owner, kind, key,
	).Scan(&opID, &hash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil, nil
	case err != nil:
		return nil, nil, fmt.Errorf("idempotency pre-check: %w", err)
	}
	if hash != requestHash {
		return nil, nil, ErrIdempotencyConflict
	}
	op, err := s.GetOperation(ctx, opID)
	if err != nil {
		return nil, nil, err
	}
	if op.VMID == nil {
		return nil, op, nil
	}
	vm, err := s.GetVM(ctx, *op.VMID)
	if err != nil {
		return nil, nil, err
	}
	return vm, op, nil
}

// --- TransitionVM ---

// TransitionVM advances a VM's observed_state inside one writer transaction,
// validates the transition against the SPEC §5.2 matrix, bumps the revision,
// updates reservation release flags, and emits a vm.state_changed event.
func (s *Store) TransitionVM(ctx context.Context, in TransitionInput) (*VM, error) {
	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin transition: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Load current state with an exclusive lock (single-writer conn serializes this).
	var current VM
	var labelsJSON string
	err = tx.QueryRowContext(ctx,
		`SELECT row_id, vm_id, name, owner, template_id, template_digest, desired_state, observed_state, revision,
		        vcpu, memory_mib, root_disk_mib, workspace_disk_mib, network_profile, network_policy_id, labels,
		        failure_stage, failure_reason, created_at, updated_at
		 FROM vms WHERE vm_id = ?`, in.VMID,
	).Scan(&current.RowID, &current.VMID, &current.Name, &current.Owner,
		&current.TemplateID, &current.TemplateDigest,
		&current.DesiredState, &current.ObservedState, &current.Revision,
		&current.VCPUCount, &current.MemoryMiB, &current.RootDiskMiB, &current.WorkspaceDiskMiB,
		&current.NetworkProfile, &current.NetworkPolicyID, &labelsJSON,
		&current.FailureStage, &current.FailureReason,
		&current.CreatedAt, &current.UpdatedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, ErrVMUnknown
	case err != nil:
		return nil, fmt.Errorf("load vm: %w", err)
	}
	if err := json.Unmarshal([]byte(labelsJSON), &current.Labels); err != nil {
		return nil, fmt.Errorf("decode labels: %w", err)
	}

	if in.ExpectedRevision != nil && *in.ExpectedRevision != current.Revision {
		return nil, &RevisionMismatchError{Current: current.Revision}
	}
	if !transitionAllowed(current.ObservedState, in.To) {
		return nil, &InvalidTransitionError{From: current.ObservedState, To: in.To}
	}

	newRevision := current.Revision + 1
	desired := current.DesiredState
	if in.DesiredState != nil {
		desired = *in.DesiredState
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE vms SET observed_state = ?, desired_state = ?, revision = ?,
		               failure_stage = ?, failure_reason = ?,
		               updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
		 WHERE vm_id = ?`,
		in.To, desired, newRevision, in.FailureStage, in.FailureReason, in.VMID); err != nil {
		return nil, fmt.Errorf("update vm state: %w", err)
	}

	// Update reservation flags.
	if in.ReleaseAll {
		if _, err := tx.ExecContext(ctx,
			`UPDATE reservations SET released = 1, compute_released = 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE vm_id = ?`,
			in.VMID); err != nil {
			return nil, fmt.Errorf("release reservation: %w", err)
		}
	} else if in.ReleaseCompute {
		if _, err := tx.ExecContext(ctx,
			`UPDATE reservations SET compute_released = 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE vm_id = ?`,
			in.VMID); err != nil {
			return nil, fmt.Errorf("release compute: %w", err)
		}
	}

	stateData := map[string]any{
		"vm_id":        in.VMID,
		"from":         current.ObservedState,
		"to":           in.To,
		"reason":       in.Reason,
		"operation_id": strconv.FormatInt(in.OperationID, 10),
		"revision":     strconv.FormatInt(newRevision, 10),
	}
	if in.BootID != nil {
		stateData["boot_id"] = *in.BootID
	}
	if _, err := s.appendSystemInTx(ctx, tx, s.systemEnvelope("vm.state_changed", "registry", notApplicableQuality(), stateData)); err != nil {
		return nil, err
	}
	// vm.deleted marks the terminal resource-release; history and artifacts are
	// not purged (SPEC §5.4) — the row stays in "deleted" state.
	if in.To == "deleted" {
		if _, err := s.appendSystemInTx(ctx, tx, s.systemEnvelope("vm.deleted", "registry", notApplicableQuality(), map[string]any{
			"vm_id":        in.VMID,
			"operation_id": strconv.FormatInt(in.OperationID, 10),
		})); err != nil {
			return nil, err
		}
	}

	vm, err := scanVMInTx(ctx, tx, in.VMID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit transition: %w", err)
	}
	return vm, nil
}

// --- UpdateOperation ---

// UpdateOperation advances an operation's phase and state and emits an
// operation.state_changed event.
func (s *Store) UpdateOperation(ctx context.Context, upd OperationUpdate) (*Operation, error) {
	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin update-op: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`UPDATE operations SET phase = ?, state = ?, error_cause = ?, error_message = ?,
		                       updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
		 WHERE operation_id = ?`,
		upd.Phase, upd.State, upd.ErrorCause, upd.ErrorMessage, upd.OperationID)
	if err != nil {
		return nil, fmt.Errorf("update operation: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, ErrOperationUnknown
	}

	op, err := scanOperationInTx(ctx, tx, upd.OperationID)
	if err != nil {
		return nil, err
	}

	data := map[string]any{
		"operation_id": strconv.FormatInt(op.OperationID, 10),
		"kind":         op.Kind,
		"phase":        op.Phase,
		"state":        op.State,
		"attempt":      op.Attempt,
	}
	if op.VMID != nil {
		data["vm_id"] = *op.VMID
	}
	if op.ErrorCause != nil {
		data["error"] = map[string]any{"cause": *op.ErrorCause, "message": *op.ErrorMessage}
	}
	if _, err := s.appendSystemInTx(ctx, tx, s.systemEnvelope("operation.state_changed", "registry", notApplicableQuality(), data)); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit update-op: %w", err)
	}
	return op, nil
}

// ActionOperationInput creates an operation row for a VM lifecycle action
// (pause, resume, stop, etc.) without creating a VM or reservation row.
type ActionOperationInput struct {
	Owner       string
	VMID        string
	Phase       string
	RequestHash string
}

// InsertActionOperation inserts an operation row for a lifecycle action and
// emits an operation.state_changed event. Returns the operation ID.
func (s *Store) InsertActionOperation(ctx context.Context, in ActionOperationInput) (int64, error) {
	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin action op: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`INSERT INTO operations (owner, kind, request_hash, vm_id, phase, state, created_at, updated_at)
		 VALUES (?, 'vm.action', ?, ?, ?, 'running', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
		in.Owner, in.RequestHash, in.VMID, in.Phase)
	if err != nil {
		return 0, fmt.Errorf("insert action op: %w", err)
	}
	opID, _ := res.LastInsertId()

	if _, err := s.appendSystemInTx(ctx, tx, s.systemEnvelope("operation.state_changed", "registry", notApplicableQuality(), map[string]any{
		"operation_id": strconv.FormatInt(opID, 10),
		"kind":         "vm.action",
		"vm_id":        in.VMID,
		"phase":        in.Phase,
		"state":        "running",
		"attempt":      1,
	})); err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit action op: %w", err)
	}
	return opID, nil
}

// ListOperationsByState returns all operations in a given state, used by
// Reconcile to find in-flight operations after a controller restart.
func (s *Store) ListOperationsByState(ctx context.Context, state string) ([]*Operation, error) {
	rows, err := s.readers.QueryContext(ctx,
		operationColumns+` FROM operations WHERE state = ? ORDER BY operation_id ASC`, state)
	if err != nil {
		return nil, fmt.Errorf("list operations by state: %w", err)
	}
	defer rows.Close()
	var out []*Operation
	for rows.Next() {
		op, err := scanOperation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, op)
	}
	return out, rows.Err()
}

// --- Read methods ---

// GetVM returns one VM by vm_id.
func (s *Store) GetVM(ctx context.Context, vmID string) (*VM, error) {
	row := s.readers.QueryRowContext(ctx, vmColumns+` FROM vms WHERE vm_id = ?`, vmID)
	vm, err := scanVM(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrVMUnknown
	}
	return vm, err
}

// ListVMs returns a keyset-paged slice of VMs, optionally filtered by state.
func (s *Store) ListVMs(ctx context.Context, q VMQuery) ([]*VM, error) {
	limit := q.Limit
	if limit == 0 {
		limit = DefaultPageLimit
	}
	if limit < 0 || limit > MaxPageLimit {
		return nil, &BoundError{Requested: q.Limit, Max: MaxPageLimit}
	}

	where := "row_id > ?"
	args := []any{q.After}
	if len(q.States) > 0 {
		placeholders := strings.Repeat("?,", len(q.States))
		placeholders = placeholders[:len(placeholders)-1]
		where += " AND observed_state IN (" + placeholders + ")"
		for _, s := range q.States {
			args = append(args, s)
		}
	}
	args = append(args, limit)

	rows, err := s.readers.QueryContext(ctx,
		vmColumns+` FROM vms WHERE `+where+` ORDER BY row_id ASC LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("list vms: %w", err)
	}
	defer rows.Close()

	out := []*VM{}
	for rows.Next() {
		vm, err := scanVM(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, vm)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan vms: %w", err)
	}
	return out, nil
}

// GetOperation returns one operation by its integer id.
func (s *Store) GetOperation(ctx context.Context, id int64) (*Operation, error) {
	row := s.readers.QueryRowContext(ctx, operationColumns+` FROM operations WHERE operation_id = ?`, id)
	op, err := scanOperation(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrOperationUnknown
	}
	return op, err
}

// ReservationTotals sums live reservations for the admission check.
// Memory and VCPU exclude rows where compute was released (stopped VMs).
// Disk includes stopped VMs — they still hold disk until deleted.
func (s *Store) ReservationTotals(ctx context.Context) (ReservationTotals, error) {
	var t ReservationTotals
	err := s.readers.QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(CASE WHEN compute_released = 0 THEN memory_total_mib ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN compute_released = 0 THEN vcpu ELSE 0 END), 0),
			COALESCE(SUM(disk_mib), 0),
			COUNT(*)
		FROM reservations WHERE released = 0`).Scan(&t.MemoryMiB, &t.VCPU, &t.DiskMiB, &t.ActiveVMs)
	if err != nil {
		return t, fmt.Errorf("sum reservations: %w", err)
	}
	return t, nil
}

// GetReservation returns one reservation row by vm_id.
func (s *Store) GetReservation(ctx context.Context, vmID string) (*Reservation, error) {
	var r Reservation
	var cr, rel int64
	err := s.readers.QueryRowContext(ctx,
		`SELECT vm_id, memory_total_mib, vcpu, disk_mib, compute_released, released, created_at, updated_at FROM reservations WHERE vm_id = ?`,
		vmID).Scan(&r.VMID, &r.MemoryTotalMiB, &r.VCPU, &r.DiskMiB, &cr, &rel, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrVMUnknown
	}
	if err != nil {
		return nil, fmt.Errorf("get reservation: %w", err)
	}
	r.ComputeReleased = cr != 0
	r.Released = rel != 0
	return &r, nil
}

// --- scanner helpers ---

type vmScanner interface {
	Scan(...any) error
}

const vmColumns = `SELECT row_id, vm_id, name, owner, template_id, template_digest,
	desired_state, observed_state, revision,
	vcpu, memory_mib, root_disk_mib, workspace_disk_mib,
	network_profile, network_policy_id, labels,
	failure_stage, failure_reason, created_at, updated_at`

func scanVM(sc vmScanner) (*VM, error) {
	var vm VM
	var labelsJSON string
	if err := sc.Scan(
		&vm.RowID, &vm.VMID, &vm.Name, &vm.Owner,
		&vm.TemplateID, &vm.TemplateDigest,
		&vm.DesiredState, &vm.ObservedState, &vm.Revision,
		&vm.VCPUCount, &vm.MemoryMiB, &vm.RootDiskMiB, &vm.WorkspaceDiskMiB,
		&vm.NetworkProfile, &vm.NetworkPolicyID, &labelsJSON,
		&vm.FailureStage, &vm.FailureReason,
		&vm.CreatedAt, &vm.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(labelsJSON), &vm.Labels); err != nil {
		return nil, fmt.Errorf("decode vm labels: %w", err)
	}
	return &vm, nil
}

func scanVMInTx(ctx context.Context, tx *sql.Tx, vmID string) (*VM, error) {
	row := tx.QueryRowContext(ctx, vmColumns+` FROM vms WHERE vm_id = ?`, vmID)
	vm, err := scanVM(row)
	if err != nil {
		return nil, fmt.Errorf("read vm back: %w", err)
	}
	return vm, nil
}

type operationScanner interface {
	Scan(...any) error
}

const operationColumns = `SELECT operation_id, owner, kind, idempotency_key, request_hash, vm_id, phase, state, error_cause, error_message, attempt, created_at, updated_at`

func scanOperation(sc operationScanner) (*Operation, error) {
	var op Operation
	if err := sc.Scan(
		&op.OperationID, &op.Owner, &op.Kind, &op.IdempotencyKey, &op.RequestHash,
		&op.VMID, &op.Phase, &op.State, &op.ErrorCause, &op.ErrorMessage,
		&op.Attempt, &op.CreatedAt, &op.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &op, nil
}

func scanOperationInTx(ctx context.Context, tx *sql.Tx, id int64) (*Operation, error) {
	row := tx.QueryRowContext(ctx, operationColumns+` FROM operations WHERE operation_id = ?`, id)
	op, err := scanOperation(row)
	if err != nil {
		return nil, fmt.Errorf("read operation back: %w", err)
	}
	return op, nil
}

// reservationTotalsInTx computes totals inside an open transaction so the
// Admit callback sees a consistent snapshot (AT-012: concurrent creates must
// not oversubscribe the same capacity).
func reservationTotalsInTx(ctx context.Context, tx *sql.Tx) (ReservationTotals, error) {
	var t ReservationTotals
	err := tx.QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(CASE WHEN compute_released = 0 THEN memory_total_mib ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN compute_released = 0 THEN vcpu ELSE 0 END), 0),
			COALESCE(SUM(disk_mib), 0),
			COUNT(*)
		FROM reservations WHERE released = 0`).Scan(&t.MemoryMiB, &t.VCPU, &t.DiskMiB, &t.ActiveVMs)
	if err != nil {
		return t, fmt.Errorf("sum reservations in tx: %w", err)
	}
	return t, nil
}
