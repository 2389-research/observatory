// ABOUTME: Store methods for deterministic run-report generation (P4 Task 7):
// ABOUTME: CountEventsForReport and ListAttentionForReport keep SQL in the store package.
package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/2389-research/observatory-v2/internal/events"
)

// CountEventsForReport counts events in the run window (after < event_id <= until)
// for the given family, matching by vm_id column OR by data.vm_id / data.run_id
// in the event payload. This covers both regular VM events (vm_id column set)
// and store-synthesized run.* events (vm_id column NULL, linkage in payload).
//
// The matching reproduce_query is:
// /api/v1/events?vm_id=<vm>&family=<f>&after=<after>&until=<until>
// and the API must apply the same vm-or-data matching for counts to reproduce.
func (s *Store) CountEventsForReport(ctx context.Context, vmID, runID, family string, afterID, untilID int64) (int64, error) {
	familyKinds := events.KindsByFamily(family)
	if familyKinds == nil {
		// Unknown family — honest zero, not an error (future families return 0).
		return 0, nil
	}

	// Build IN clause for family kinds.
	placeholders := strings.Repeat("?,", len(familyKinds))
	placeholders = placeholders[:len(placeholders)-1]
	args := []any{afterID, untilID}
	for _, k := range familyKinds {
		args = append(args, k)
	}
	args = append(args, vmID, vmID, runID)

	// Match events by:
	// 1. vm_id column = vmID (regular VM events and vm.* events), OR
	// 2. payload json data.vm_id = vmID (run.* events with NULL column vm_id), OR
	// 3. payload json data.run_id = runID (run.* events linked by run_id)
	q := `SELECT COUNT(*) FROM events
		WHERE event_id > ? AND event_id <= ?
		AND kind IN (` + placeholders + `)
		AND (
			vm_id = ?
			OR json_extract(payload, '$.data.vm_id') = ?
			OR json_extract(payload, '$.data.run_id') = ?
		)`

	var count int64
	if err := s.readers.QueryRowContext(ctx, q, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count events for report (family %s): %w", family, err)
	}
	return count, nil
}

// ListAttentionForReport returns all attention items relevant to a run, ordered
// by attention_id ASC (oldest first). An item is relevant if:
// - run_id = runID, OR
// - vm_id = vmID AND raised_event_id is in the run window (after < id <= until).
// Returns up to 129 items so the caller can detect overflow at 128.
func (s *Store) ListAttentionForReport(ctx context.Context, vmID, runID string, afterID, untilID int64) ([]*AttentionItem, error) {
	// Fetch up to 129 so the report generator can detect the >128 overflow.
	const fetchLimit = 129
	rows, err := s.readers.QueryContext(ctx,
		attentionColumns+` FROM attention_items
		WHERE (run_id = ?)
		   OR (vm_id = ? AND raised_event_id > ? AND raised_event_id <= ?)
		ORDER BY attention_id ASC
		LIMIT ?`,
		runID, vmID, afterID, untilID, fetchLimit)
	if err != nil {
		return nil, fmt.Errorf("list attention for report: %w", err)
	}
	defer rows.Close()
	return scanAttentionRows(rows)
}

// InsertReportOperation creates an operation row of kind "run.report_generate"
// in state "running" for a given VM and run. Returns the operation ID.
// This is the narrow insertion path for report operations; the broader
// CreateVMWithOperation path is for VM creation.
func (s *Store) InsertReportOperation(ctx context.Context, owner, vmID, runID string) (int64, error) {
	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin report op: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`INSERT INTO operations (owner, kind, request_hash, vm_id, phase, state, created_at, updated_at)
		 VALUES (?, 'run.report_generate', ?, ?, 'generating', 'running',
		         strftime('%Y-%m-%dT%H:%M:%fZ','now'),
		         strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
		owner, runID, vmID)
	if err != nil {
		return 0, fmt.Errorf("insert report op: %w", err)
	}
	opID, _ := res.LastInsertId()

	if _, err := s.appendSystemInTx(ctx, tx, s.systemEnvelope("operation.state_changed", "registry", notApplicableQuality(), map[string]any{
		"operation_id": fmt.Sprintf("%d", opID),
		"kind":         "run.report_generate",
		"vm_id":        vmID,
		"phase":        "generating",
		"state":        "running",
		"attempt":      1,
	})); err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit report op: %w", err)
	}
	return opID, nil
}

// HasRunningReportOp returns true if there is already a "running" or "pending"
// operation of kind "run.report_generate" for the given runID (matched via
// request_hash which stores the runID). This prevents duplicate report ops
// from piling up during reconcile.
func (s *Store) HasRunningReportOp(ctx context.Context, runID string) (bool, error) {
	var count int64
	err := s.readers.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM operations
		 WHERE kind = 'run.report_generate'
		   AND request_hash = ?
		   AND state IN ('running', 'pending')`,
		runID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check running report op: %w", err)
	}
	return count > 0, nil
}
