// ABOUTME: RecordCleanupFailure: the durable record of a cleanup the controller
// ABOUTME: retried and could not finish, so a retained row states its own reason.
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
//
// The record is a statement, not a transition: the row's state is unchanged and
// no revision is spent, because nothing about the VM changed -- the controller
// merely failed again to change it. reason is redacted on the same terms as an
// attention summary (SPEC §15.3); it is a host error string, and host error
// strings are exactly where a stray credential would surface.
func (s *Store) RecordCleanupFailure(ctx context.Context, vmID, state, reason string) error {
	if vmID == "" || state == "" || reason == "" {
		return errors.New("cleanup failure record requires vm_id, state and reason")
	}
	safe, _ := redact.Apply(reason)

	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin cleanup record: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := s.appendSystemInTx(ctx, tx, s.systemEnvelope("vm.cleanup_failed", "registry",
		notApplicableQuality(), map[string]any{
			"vm_id":  vmID,
			"state":  state,
			"reason": safe,
		})); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit cleanup record: %w", err)
	}
	return nil
}
