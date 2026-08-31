// ABOUTME: Batch VM creation: atomic_reservation and best_effort modes, with
// ABOUTME: per-batch idempotency tracking (AT-015) and durable evidence.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// ErrBatchUnknown is returned when no batch exists with the given ID.
var ErrBatchUnknown = errors.New("batch not found")

// Batch is one row of the vm_batches table.
type Batch struct {
	BatchID         int64
	Owner           string
	IdempotencyKey  *string
	RequestHash     string
	ReservationMode string
	OnFailure       string
	BatchOpID       *int64
	CreatedAt       string
	UpdatedAt       string
}

// BatchMemberInput is one member's pre-validated spec (defaults applied, VMID assigned).
type BatchMemberInput struct {
	Name             string
	VMID             string
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
}

// BatchMemberResult is one member's outcome after CreateVMBatch.
type BatchMemberResult struct {
	Position       int
	Name           string
	VM             *VM
	Operation      *Operation
	RefusalCause   *string
	RefusalMessage *string
}

// CreateVMBatchInput carries everything needed to atomically create a batch.
type CreateVMBatchInput struct {
	Owner           string
	IdempotencyKey  *string
	RequestHash     string
	ReservationMode string // "atomic_reservation" or "best_effort"
	OnFailure       string // "keep_successful" or "stop_successful"
	Members         []BatchMemberInput

	// AdmitBatch is for atomic_reservation: called once with current totals.
	// The manager passes a closure with the total batch cost baked in.
	AdmitBatch func(totals ReservationTotals) error
	// AdmitMember is for best_effort: called per member with current totals
	// (which include previously admitted members' reservations).
	AdmitMember func(totals ReservationTotals, memTotal int64, vcpu int, diskTotal int64) error
}

// CreateVMBatchResult is the full result of CreateVMBatch.
type CreateVMBatchResult struct {
	Batch    *Batch
	BatchOp  *Operation
	Members  []*BatchMemberResult
	IsReplay bool
}

// CreateVMBatch atomically creates a batch of VM records inside one writer tx.
// For atomic_reservation, the whole batch cost is evaluated in one admission
// decision. For best_effort, each member is evaluated independently with
// cumulative totals so previously admitted members' reservations are visible.
// The batch-level operation carries durable evidence for all outcomes.
func (s *Store) CreateVMBatch(ctx context.Context, in CreateVMBatchInput) (*CreateVMBatchResult, error) {
	// Readers-path idempotency check before taking the writer lock.
	if in.IdempotencyKey != nil {
		result, err := s.lookupBatch(ctx, in.Owner, *in.IdempotencyKey, in.RequestHash)
		if err != nil {
			return nil, err
		}
		if result != nil {
			result.IsReplay = true
			return result, nil
		}
	}

	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin batch tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// In-tx idempotency re-check (serialization point).
	if in.IdempotencyKey != nil {
		var existingBatchID int64
		var existingHash string
		err := tx.QueryRowContext(ctx,
			`SELECT batch_id, request_hash FROM vm_batches WHERE owner = ? AND idempotency_key = ?`,
			in.Owner, *in.IdempotencyKey,
		).Scan(&existingBatchID, &existingHash)
		switch {
		case err == nil:
			if existingHash != in.RequestHash {
				return nil, ErrIdempotencyConflict
			}
			// Replay: rollback and read the original result outside the tx.
			if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
				return nil, fmt.Errorf("rollback replay: %w", err)
			}
			result, err := s.GetVMBatch(ctx, existingBatchID)
			if err != nil {
				return nil, err
			}
			result.IsReplay = true
			return result, nil
		case !errors.Is(err, sql.ErrNoRows):
			return nil, fmt.Errorf("batch idempotency lookup: %w", err)
		}
	}

	// Insert the batch row (batch_op_id set after op is known).
	batchRes, err := tx.ExecContext(ctx,
		`INSERT INTO vm_batches (owner, idempotency_key, request_hash, reservation_mode, on_failure, batch_op_id, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, NULL, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
		in.Owner, nullable(in.IdempotencyKey), in.RequestHash, in.ReservationMode, in.OnFailure)
	if err != nil {
		return nil, fmt.Errorf("insert batch: %w", err)
	}
	batchID, _ := batchRes.LastInsertId()

	// Process members based on reservation mode.
	var memberResults []*BatchMemberResult
	var batchOpState string
	var batchRefusal *AdmissionRefusal

	switch in.ReservationMode {
	case "atomic_reservation":
		memberResults, batchOpState, batchRefusal, err = s.processAtomicBatch(ctx, tx, batchID, in)
	case "best_effort":
		memberResults, batchOpState, batchRefusal, err = s.processBestEffortBatch(ctx, tx, batchID, in)
	default:
		return nil, fmt.Errorf("unknown reservation_mode %q", in.ReservationMode)
	}
	if err != nil {
		return nil, err
	}

	// Insert the batch-level operation.
	batchOpKind := "vm_batch.create"
	batchOpPhase := "admitted"
	if batchOpState == "failed" {
		batchOpPhase = "admission"
	}
	var errCause, errMsg *string
	if batchRefusal != nil {
		errCause = &batchRefusal.Cause
		errMsg = &batchRefusal.Message
	}

	batchOpRes, err := tx.ExecContext(ctx,
		`INSERT INTO operations (owner, kind, idempotency_key, request_hash, vm_id, phase, state, error_cause, error_message, created_at, updated_at)
		 VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
		in.Owner, batchOpKind, nullable(in.IdempotencyKey), in.RequestHash,
		batchOpPhase, batchOpState, nullable(errCause), nullable(errMsg))
	if err != nil {
		return nil, fmt.Errorf("insert batch op: %w", err)
	}
	batchOpID, _ := batchOpRes.LastInsertId()

	// Back-fill the batch row with the op id.
	if _, err := tx.ExecContext(ctx,
		`UPDATE vm_batches SET batch_op_id = ? WHERE batch_id = ?`, batchOpID, batchID); err != nil {
		return nil, fmt.Errorf("update batch op_id: %w", err)
	}

	// Durable operation.state_changed event for the batch op.
	eventData := map[string]any{
		"operation_id": strconv.FormatInt(batchOpID, 10),
		"kind":         batchOpKind,
		"vm_id":        nil,
		"phase":        batchOpPhase,
		"state":        batchOpState,
		"attempt":      1,
	}
	if batchRefusal != nil {
		eventData["error"] = map[string]any{"cause": batchRefusal.Cause, "message": batchRefusal.Message}
	}
	if _, err := s.appendSystemInTx(ctx, tx, s.systemEnvelope("operation.state_changed", "registry", notApplicableQuality(), eventData)); err != nil {
		return nil, fmt.Errorf("append batch op event: %w", err)
	}

	batchOp, err := scanOperationInTx(ctx, tx, batchOpID)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit batch: %w", err)
	}

	// Read the batch row back outside the tx.
	batch, err := s.getBatchRow(ctx, batchID)
	if err != nil {
		return nil, err
	}

	return &CreateVMBatchResult{
		Batch:   batch,
		BatchOp: batchOp,
		Members: memberResults,
	}, nil
}

// processAtomicBatch checks the whole batch cost in one admission decision.
// On refusal, all members are marked refused; no VM/op rows are created.
func (s *Store) processAtomicBatch(ctx context.Context, tx *sql.Tx, batchID int64, in CreateVMBatchInput) ([]*BatchMemberResult, string, *AdmissionRefusal, error) {
	totals, err := reservationTotalsInTx(ctx, tx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("read reservations: %w", err)
	}

	admitErr := in.AdmitBatch(totals)
	if admitErr != nil {
		var refusal *AdmissionRefusal
		if !errors.As(admitErr, &refusal) {
			return nil, "", nil, fmt.Errorf("admit callback internal error: %w", admitErr)
		}
		// Mark all members refused; insert member rows with refusal.
		members := make([]*BatchMemberResult, len(in.Members))
		for i, m := range in.Members {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO vm_batch_members (batch_id, position, name, vm_id, operation_id, refusal_cause, refusal_message)
				 VALUES (?, ?, ?, NULL, NULL, ?, ?)`,
				batchID, i, m.Name, refusal.Cause, refusal.Message); err != nil {
				return nil, "", nil, fmt.Errorf("insert refused member %d: %w", i, err)
			}
			c, msg := refusal.Cause, refusal.Message
			members[i] = &BatchMemberResult{
				Position:       i,
				Name:           m.Name,
				RefusalCause:   &c,
				RefusalMessage: &msg,
			}
		}
		return members, "failed", refusal, nil
	}

	// Admission granted — create all members.
	members, err := s.insertAdmittedMembers(ctx, tx, batchID, in.Owner, in.Members)
	if err != nil {
		return nil, "", nil, err
	}
	return members, "running", nil, nil
}

// processBestEffortBatch evaluates each member independently with cumulative
// totals visible in the tx (previously admitted members' reservations count).
func (s *Store) processBestEffortBatch(ctx context.Context, tx *sql.Tx, batchID int64, in CreateVMBatchInput) ([]*BatchMemberResult, string, *AdmissionRefusal, error) {
	members := make([]*BatchMemberResult, len(in.Members))
	anyAdmitted := false
	var lastRefusal *AdmissionRefusal

	for i, m := range in.Members {
		totals, err := reservationTotalsInTx(ctx, tx)
		if err != nil {
			return nil, "", nil, fmt.Errorf("read reservations for member %d: %w", i, err)
		}

		diskTotal := m.RootDiskMiB + m.WorkspaceDiskMiB
		admitErr := in.AdmitMember(totals, m.MemoryTotalMiB, m.VCPUCount, diskTotal)
		if admitErr != nil {
			var refusal *AdmissionRefusal
			if !errors.As(admitErr, &refusal) {
				return nil, "", nil, fmt.Errorf("admit callback internal error for member %d: %w", i, admitErr)
			}
			lastRefusal = refusal
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO vm_batch_members (batch_id, position, name, vm_id, operation_id, refusal_cause, refusal_message)
				 VALUES (?, ?, ?, NULL, NULL, ?, ?)`,
				batchID, i, m.Name, refusal.Cause, refusal.Message); err != nil {
				return nil, "", nil, fmt.Errorf("insert refused member %d: %w", i, err)
			}
			c, msg := refusal.Cause, refusal.Message
			members[i] = &BatchMemberResult{
				Position:       i,
				Name:           m.Name,
				RefusalCause:   &c,
				RefusalMessage: &msg,
			}
			continue
		}

		// Admitted: insert VM, op, reservation, events.
		admitted, err := s.insertOneMember(ctx, tx, batchID, i, in.Owner, m)
		if err != nil {
			return nil, "", nil, err
		}
		members[i] = admitted
		anyAdmitted = true
	}

	batchOpState := "running"
	var batchRefusal *AdmissionRefusal
	if !anyAdmitted {
		batchOpState = "failed"
		batchRefusal = lastRefusal
	}
	return members, batchOpState, batchRefusal, nil
}

// insertAdmittedMembers creates all VM/op/reservation/event rows for a fully
// admitted batch (atomic_reservation path). Each member is independent.
func (s *Store) insertAdmittedMembers(ctx context.Context, tx *sql.Tx, batchID int64, owner string, members []BatchMemberInput) ([]*BatchMemberResult, error) {
	results := make([]*BatchMemberResult, len(members))
	for i, m := range members {
		r, err := s.insertOneMember(ctx, tx, batchID, i, owner, m)
		if err != nil {
			return nil, err
		}
		results[i] = r
	}
	return results, nil
}

// insertOneMember creates one VM+op+reservation+events inside the batch tx.
// Mirrors the admitted path in CreateVMWithOperation but shares the batch tx.
func (s *Store) insertOneMember(ctx context.Context, tx *sql.Tx, batchID int64, pos int, owner string, m BatchMemberInput) (*BatchMemberResult, error) {
	labels := m.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	labelsJSON, err := json.Marshal(labels)
	if err != nil {
		return nil, fmt.Errorf("marshal member %d labels: %w", pos, err)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO vms (vm_id, name, owner, template_id, template_digest, desired_state, observed_state, revision,
		                  vcpu, memory_mib, root_disk_mib, workspace_disk_mib, network_profile, network_policy_id, labels,
		                  created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, 'running', 'provisioning', 1, ?, ?, ?, ?, ?, ?, ?,
		         strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
		m.VMID, m.Name, owner, m.TemplateID, m.TemplateDigest,
		m.VCPUCount, m.MemoryMiB, m.RootDiskMiB, m.WorkspaceDiskMiB,
		m.NetworkProfile, m.NetworkPolicyID, string(labelsJSON)); err != nil {
		return nil, fmt.Errorf("insert member %d vm: %w", pos, err)
	}

	opRes, err := tx.ExecContext(ctx,
		`INSERT INTO operations (owner, kind, idempotency_key, request_hash, vm_id, phase, state, created_at, updated_at)
		 VALUES (?, 'vm.create', NULL, '', ?, 'admitted', 'running',
		         strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
		owner, m.VMID)
	if err != nil {
		return nil, fmt.Errorf("insert member %d op: %w", pos, err)
	}
	opID, _ := opRes.LastInsertId()

	diskMiB := m.RootDiskMiB + m.WorkspaceDiskMiB
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO reservations (vm_id, memory_total_mib, vcpu, disk_mib, created_at, updated_at)
		 VALUES (?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
		m.VMID, m.MemoryTotalMiB, m.VCPUCount, diskMiB); err != nil {
		return nil, fmt.Errorf("insert member %d reservation: %w", pos, err)
	}

	// vm.created event.
	createdCursor, err := s.appendSystemInTx(ctx, tx, s.systemEnvelope("vm.created", "registry", notApplicableQuality(), map[string]any{
		"vm_id":           m.VMID,
		"name":            m.Name,
		"template_id":     m.TemplateID,
		"template_digest": m.TemplateDigest,
		"operation_id":    strconv.FormatInt(opID, 10),
		"owner":           owner,
		"resources": map[string]any{
			"vcpu":               m.VCPUCount,
			"memory_mib":         m.MemoryMiB,
			"root_disk_mib":      m.RootDiskMiB,
			"workspace_disk_mib": m.WorkspaceDiskMiB,
		},
	}))
	if err != nil {
		return nil, fmt.Errorf("member %d vm.created: %w", pos, err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE vms SET last_event_id = ? WHERE vm_id = ?`, createdCursor, m.VMID); err != nil {
		return nil, fmt.Errorf("member %d set last_event_id: %w", pos, err)
	}

	// operation.state_changed event.
	if _, err := s.appendSystemInTx(ctx, tx, s.systemEnvelope("operation.state_changed", "registry", notApplicableQuality(), map[string]any{
		"operation_id": strconv.FormatInt(opID, 10),
		"kind":         "vm.create",
		"vm_id":        m.VMID,
		"phase":        "admitted",
		"state":        "running",
		"attempt":      1,
	})); err != nil {
		return nil, fmt.Errorf("member %d op event: %w", pos, err)
	}

	// vm_batch_members row.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO vm_batch_members (batch_id, position, name, vm_id, operation_id)
		 VALUES (?, ?, ?, ?, ?)`,
		batchID, pos, m.Name, m.VMID, opID); err != nil {
		return nil, fmt.Errorf("insert member %d batch row: %w", pos, err)
	}

	vm, err := scanVMInTx(ctx, tx, m.VMID)
	if err != nil {
		return nil, fmt.Errorf("read back member %d vm: %w", pos, err)
	}
	op, err := scanOperationInTx(ctx, tx, opID)
	if err != nil {
		return nil, fmt.Errorf("read back member %d op: %w", pos, err)
	}

	return &BatchMemberResult{
		Position:  pos,
		Name:      m.Name,
		VM:        vm,
		Operation: op,
	}, nil
}

// GetVMBatch loads a batch and its members by batch_id.
func (s *Store) GetVMBatch(ctx context.Context, batchID int64) (*CreateVMBatchResult, error) {
	batch, err := s.getBatchRow(ctx, batchID)
	if err != nil {
		return nil, err
	}

	// Load the batch-level operation.
	var batchOp *Operation
	if batch.BatchOpID != nil {
		batchOp, err = s.GetOperation(ctx, *batch.BatchOpID)
		if err != nil {
			return nil, fmt.Errorf("load batch op: %w", err)
		}
	}

	// Load all members.
	rows, err := s.readers.QueryContext(ctx,
		`SELECT position, name, vm_id, operation_id, refusal_cause, refusal_message
		 FROM vm_batch_members WHERE batch_id = ? ORDER BY position`,
		batchID)
	if err != nil {
		return nil, fmt.Errorf("load batch members: %w", err)
	}
	defer rows.Close()

	var members []*BatchMemberResult
	for rows.Next() {
		var pos int
		var name string
		var vmID sql.NullString
		var opIDInt sql.NullInt64
		var refCause, refMsg sql.NullString
		if err := rows.Scan(&pos, &name, &vmID, &opIDInt, &refCause, &refMsg); err != nil {
			return nil, fmt.Errorf("scan member: %w", err)
		}
		m := &BatchMemberResult{Position: pos, Name: name}
		if refCause.Valid {
			c := refCause.String
			m.RefusalCause = &c
		}
		if refMsg.Valid {
			msg := refMsg.String
			m.RefusalMessage = &msg
		}
		if vmID.Valid {
			vm, err := s.GetVM(ctx, vmID.String)
			if err != nil && !errors.Is(err, ErrVMUnknown) {
				return nil, fmt.Errorf("load member %d vm: %w", pos, err)
			}
			m.VM = vm
		}
		if opIDInt.Valid {
			op, err := s.GetOperation(ctx, opIDInt.Int64)
			if err != nil && !errors.Is(err, ErrOperationUnknown) {
				return nil, fmt.Errorf("load member %d op: %w", pos, err)
			}
			m.Operation = op
		}
		members = append(members, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan members: %w", err)
	}

	return &CreateVMBatchResult{
		Batch:   batch,
		BatchOp: batchOp,
		Members: members,
	}, nil
}

// UpdateBatchOp updates the batch-level operation to reflect final state
// (called by the manager when all admitted members reach terminal state).
func (s *Store) UpdateBatchOp(ctx context.Context, batchOpID int64, state, cause, message string) error {
	var errCause, errMsg *string
	if cause != "" {
		errCause = &cause
		errMsg = &message
	}
	_, err := s.UpdateOperation(ctx, OperationUpdate{
		OperationID:  batchOpID,
		Phase:        "complete",
		State:        state,
		ErrorCause:   errCause,
		ErrorMessage: errMsg,
	})
	return err
}

// getBatchRow reads one vm_batches row.
func (s *Store) getBatchRow(ctx context.Context, batchID int64) (*Batch, error) {
	var b Batch
	var ikey sql.NullString
	var opID sql.NullInt64
	err := s.readers.QueryRowContext(ctx,
		`SELECT batch_id, owner, idempotency_key, request_hash, reservation_mode, on_failure, batch_op_id, created_at, updated_at
		 FROM vm_batches WHERE batch_id = ?`, batchID,
	).Scan(&b.BatchID, &b.Owner, &ikey, &b.RequestHash, &b.ReservationMode, &b.OnFailure, &opID, &b.CreatedAt, &b.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrBatchUnknown
	}
	if err != nil {
		return nil, fmt.Errorf("get batch: %w", err)
	}
	if ikey.Valid {
		s := ikey.String
		b.IdempotencyKey = &s
	}
	if opID.Valid {
		v := opID.Int64
		b.BatchOpID = &v
	}
	return &b, nil
}

// lookupBatch is the readers-path idempotency check for batches.
func (s *Store) lookupBatch(ctx context.Context, owner, key, requestHash string) (*CreateVMBatchResult, error) {
	var batchID int64
	var hash string
	err := s.readers.QueryRowContext(ctx,
		`SELECT batch_id, request_hash FROM vm_batches WHERE owner = ? AND idempotency_key = ?`,
		owner, key,
	).Scan(&batchID, &hash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("batch idempotency pre-check: %w", err)
	}
	if hash != requestHash {
		return nil, ErrIdempotencyConflict
	}
	return s.GetVMBatch(ctx, batchID)
}
