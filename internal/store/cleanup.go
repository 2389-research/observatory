// ABOUTME: The two records a row makes about itself when the controller could not
// ABOUTME: finish a cleanup, or could not classify the VM the row names at all.
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/2389-research/observatory-v2/internal/redact"
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
	return s.recordVMStatement(ctx, "vm.cleanup_failed", vmID, map[string]any{
		"vm_id":  vmID,
		"state":  state,
		"reason": redacted(reason),
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
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit %s record for %s: %w", kind, vmID, err)
	}
	return nil
}
