// ABOUTME: The two records a row makes about itself when the controller could not
// ABOUTME: finish a cleanup, or could not classify the VM the row names at all.
package store

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/2389-research/observatory/internal/redact"
)

// RecordCleanupFailure appends vm.cleanup_failed for a cleanup that did not
// complete: the VM's host resources are still owned and its row stays in the
// pre-terminal state it is retained in.
//
// SPEC §5.3 asks for cleanup failures to be recorded as well as retried. The
// retry has always existed -- Reconcile runs at every controller start -- but
// the reason lived only in the DELETE response, which nobody is holding open
// after a restart. Without this, a row parked at "deleting" is a bounded result
// with no actionable content: it says a cleanup is outstanding and not one word
// about what survived or why.
func (s *Store) RecordCleanupFailure(ctx context.Context, vmID, state, reason string) error {
	if vmID == "" || state == "" || reason == "" {
		return errors.New("cleanup failure record requires vm_id, state and reason")
	}
	reason = redacted(reason)
	if len(reason) > 2048 {
		reason = reason[:2045]
		for !utf8.ValidString(reason) {
			reason = reason[:len(reason)-1]
		}
		reason += "..."
	}
	return s.recordVMStatement(ctx, "vm.cleanup_failed", vmID, map[string]any{
		"vm_id":  vmID,
		"state":  state,
		"reason": reason,
	})
}

// RecordReconcileAmbiguity appends vm.reconcile_ambiguous for a VM the startup
// scan looked at and could not classify.
//
// §5.5 quarantines an ambiguous VM at the runtime layer: the scan touches
// nothing and says so. The row above it is quarantined the same way, which means
// Reconcile does not settle it -- and a row deliberately left alone is
// indistinguishable from one nobody got to. This is the difference. detail is
// the runtime's own account of what it could not tell, which is the only thing
// that tells an operator where to look on the host.
func (s *Store) RecordReconcileAmbiguity(ctx context.Context, vmID, state, detail string) error {
	if vmID == "" || state == "" || detail == "" {
		return errors.New("reconcile ambiguity record requires vm_id, state and detail")
	}
	return s.recordVMStatement(ctx, "vm.reconcile_ambiguous", vmID, map[string]any{
		"vm_id":  vmID,
		"state":  state,
		"detail": redacted(detail),
	})
}

// redacted applies the §15.3 policy to a host-supplied string. Both records
// above carry one, and host error text is exactly where a stray credential would
// surface -- a runner argv in a wrapped exec error, an Authorization header in a
// transport failure.
func redacted(s string) string {
	safe, _ := redact.Apply(s)
	return safe
}

// recordVMStatement appends one system event about a VM without transitioning
// it. A statement, not a transition: the row's state is unchanged and no
// revision is spent, because nothing about the VM changed -- the controller
// either failed again to change it, or declined to guess.
func (s *Store) recordVMStatement(ctx context.Context, kind, vmID string, data map[string]any) error {
	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin %s record for %s: %w", kind, vmID, err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := s.appendSystemInTx(ctx, tx,
		s.systemEnvelope(kind, "registry", notApplicableQuality(), data)); err != nil {
		return err
	}
	if kind == "vm.cleanup_failed" && data["state"] == "stopped" {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO cleanup_debt(vm_id)
  SELECT vm_id FROM vms WHERE vm_id = ? AND observed_state IN ('stopping', 'stopped')`, vmID); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit %s record for %s: %w", kind, vmID, err)
	}
	return nil
}

// ReleaseVMReservations releases failed VM debt after a full host release.
// The caller must hold the lifecycle claim and have observed release success.
func (s *Store) ReleaseVMReservations(ctx context.Context, vmID string) error {
	_, err := s.writer.ExecContext(ctx, `UPDATE reservations SET released = 1, compute_released = 1,
 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE vm_id = ?
 AND EXISTS (SELECT 1 FROM vms WHERE vm_id = ? AND observed_state = 'failed')`, vmID, vmID)
	return err
}

// ClearCleanupDebt records that a fresh force-stop finished stopped jail cleanup.
// It retains every reservation and disk needed for a later restart.
func (s *Store) ClearCleanupDebt(ctx context.Context, vmID string) error {
	_, err := s.writer.ExecContext(ctx, `DELETE FROM cleanup_debt WHERE vm_id = ?`, vmID)
	return err
}

// HasCleanupDebt rechecks a candidate's durable marker after lifecycle ownership.
func (s *Store) HasCleanupDebt(ctx context.Context, vmID string) (bool, error) {
	var pending bool
	err := s.readers.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM cleanup_debt WHERE vm_id = ?)`, vmID).Scan(&pending)
	return pending, err
}
