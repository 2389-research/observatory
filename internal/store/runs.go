// ABOUTME: Runs registry: guarded phase-machine transitions, idempotent create,
// ABOUTME: and keyset-paginated reads (SPEC §12, P4).
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/2389-research/observatory-v2/internal/events"
	"github.com/google/uuid"
)

// --- sentinel errors ---

var (
	// ErrRunNotFound: no run has this run_id.
	ErrRunNotFound = errors.New("run not found")
	// ErrActiveRunExists: a non-terminal run already exists for this VM.
	ErrActiveRunExists = errors.New("a non-terminal run already exists for this VM; conclude it before creating another")
	// ErrSubmissionRejected: a guest submission was rejected (oversized, malformed, or
	// disabled). Wrapped with the specific bounded reason.
	ErrSubmissionRejected = errors.New("submission rejected")
	// ErrRunNotAcceptingSubmissions: the run is not in a phase that accepts progress
	// or result submissions (concluding or terminal).
	ErrRunNotAcceptingSubmissions = errors.New("run is not in pending or running phase; submissions are not accepted")
	// ErrReportNotFound: no report has been stored for this run_id.
	ErrReportNotFound = errors.New("run report not found")
)

// InvalidRunTransitionError names the rejected run phase transition.
type InvalidRunTransitionError struct {
	RunID string
	From  string
	To    string
}

func (e *InvalidRunTransitionError) Error() string {
	return fmt.Sprintf("run %s: transition %s→%s is not valid", e.RunID, e.From, e.To)
}

func (e *InvalidRunTransitionError) Is(target error) bool {
	_, ok := target.(*InvalidRunTransitionError)
	return ok
}

// validRunTransitions encodes the phase machine verbatim from the plan.
// Terminal phases (succeeded, failed, inconclusive, aborted) have no outgoing edges.
var validRunTransitions = map[string][]string{
	"pending":    {"running", "concluding"},
	"running":    {"concluding"},
	"concluding": {"succeeded", "failed", "inconclusive", "aborted"},
}

func runTransitionAllowed(from, to string) bool {
	for _, allowed := range validRunTransitions[from] {
		if allowed == to {
			return true
		}
	}
	return false
}

// terminalRunPhases is the set of phases from which no further transitions exist.
var terminalRunPhases = map[string]bool{
	"succeeded":    true,
	"failed":       true,
	"inconclusive": true,
	"aborted":      true,
}

// --- wire types ---

// Run is one row of the runs table.
type Run struct {
	RowID            int64
	RunID            string // uuid
	VMID             string
	Owner            string
	Goal             string
	CriteriaType     string // exec_exit_zero | guest_result | operator_verdict
	OnCompletion     string // keep_running | stop
	ProgressEvents   bool
	Phase            string
	EvaluatedBy      string // "", or exec_exit|guest_result|operator|system on terminal
	Reason           string // outcome/interruption reason, "" until set
	ResultJSON       string // "" until a result is recorded
	ResultStatus     string // "" | succeeded | failed
	ProgressSeq      int64  // monotonic counter of accepted progress submissions
	IdempotencyKey   *string
	RequestHash      string
	CreatedEventID   int64 // event_id of run.created — report window start
	ConcludedEventID int64 // event_id of terminal run.state_changed, 0 until terminal
	CreatedAt        string
	StartedAt        string // "" until started
	ConcludedAt      string // "" until concluded
	UpdatedAt        string
}

// --- inputs ---

// CreateRunInput carries everything needed to atomically create a run.
type CreateRunInput struct {
	VMID, Owner, Goal, CriteriaType, OnCompletion string
	ProgressEvents                                bool
	IdempotencyKey                                *string
	RequestHash                                   string
	InitialPhase                                  string // "pending" (launch-attach) or "running" (standalone on a running VM)
}

// RunTransitionInput carries everything needed to advance a run's phase.
type RunTransitionInput struct {
	RunID, From, To     string
	Reason, EvaluatedBy string // recorded on terminal transitions
}

// RunQuery pages runs by row_id keyset with optional VMID and Phase filters.
type RunQuery struct {
	VMID  string // "" means no filter
	Phase string // "" means no filter
	After string // decimal row_id cursor, exclusive; "" means from the start
	Limit int    // 0 = DefaultPageLimit
}

// SubmitProgressInput carries a guest progress payload for one run.
type SubmitProgressInput struct {
	RunID    string
	Payload  json.RawMessage
	MaxBytes int64
}

// SubmitResultInput carries a guest final result for one run.
type SubmitResultInput struct {
	RunID    string
	Result   json.RawMessage
	MaxBytes int64
}

// RunReport is one row of the run_reports table.
type RunReport struct {
	RunID       string
	ReportJSON  string
	Digest      string
	GeneratedAt string
	OperationID int64
}

// --- CreateRun ---

// CreateRun atomically creates a run record and emits run.created, with
// optional idempotency. Returns (run, isReplay, error).
func (s *Store) CreateRun(ctx context.Context, in CreateRunInput) (*Run, bool, error) {
	// Readers-path idempotency check before taking the writer lock.
	if in.IdempotencyKey != nil {
		run, isReplay, err := s.lookupRunByIdempotencyKey(ctx, in.Owner, *in.IdempotencyKey, in.RequestHash)
		if err != nil {
			return nil, false, err
		}
		if isReplay {
			return run, true, nil
		}
	}

	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("begin create-run: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// In-tx idempotency re-check (serialization point).
	if in.IdempotencyKey != nil {
		var existingRunID, existingHash string
		err := tx.QueryRowContext(ctx,
			`SELECT run_id, request_hash FROM runs WHERE owner = ? AND idempotency_key = ?`,
			in.Owner, *in.IdempotencyKey,
		).Scan(&existingRunID, &existingHash)
		switch {
		case err == nil:
			if existingHash != in.RequestHash {
				return nil, false, ErrIdempotencyConflict
			}
			// Replay: rollback and read outside tx.
			if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
				return nil, false, fmt.Errorf("rollback replay: %w", err)
			}
			run, err := s.GetRun(ctx, existingRunID)
			if err != nil {
				return nil, false, err
			}
			return run, true, nil
		case !errors.Is(err, sql.ErrNoRows):
			return nil, false, fmt.Errorf("idempotency lookup: %w", err)
		}
	}

	runID := uuid.NewString()

	// We need to emit run.created first to capture the event_id for created_event_id.
	// However, the run row references created_event_id, so we must emit the event,
	// then insert the run row with that cursor. The event carries run_id even though
	// the run row doesn't exist yet — that is fine, events are the primary evidence.
	progressEventsInt := 0
	if in.ProgressEvents {
		progressEventsInt = 1
	}

	createdEventID, err := s.appendSystemInTx(ctx, tx, s.systemEnvelope("run.created", "registry", notApplicableQuality(), map[string]any{
		"run_id":           runID,
		"vm_id":            in.VMID,
		"owner":            in.Owner,
		"goal":             in.Goal,
		"success_criteria": in.CriteriaType,
		"on_completion":    in.OnCompletion,
		"progress_events":  progressEventsInt,
		"phase":            in.InitialPhase,
	}))
	if err != nil {
		return nil, false, fmt.Errorf("emit run.created: %w", err)
	}

	// Insert the run row. started_at is conditionally set.
	var insertSQL string
	var insertArgs []any
	if in.InitialPhase == "running" {
		insertSQL = `INSERT INTO runs
			(run_id, vm_id, owner, goal, criteria_type, on_completion, progress_events,
			 phase, idempotency_key, request_hash, created_event_id,
			 created_at, started_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?,
			        ?, ?, ?, ?,
			        strftime('%Y-%m-%dT%H:%M:%fZ','now'),
			        strftime('%Y-%m-%dT%H:%M:%fZ','now'),
			        strftime('%Y-%m-%dT%H:%M:%fZ','now'))`
		insertArgs = []any{
			runID, in.VMID, in.Owner, in.Goal, in.CriteriaType, in.OnCompletion, progressEventsInt,
			in.InitialPhase, nullable(in.IdempotencyKey), in.RequestHash, createdEventID,
		}
	} else {
		insertSQL = `INSERT INTO runs
			(run_id, vm_id, owner, goal, criteria_type, on_completion, progress_events,
			 phase, idempotency_key, request_hash, created_event_id,
			 created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?,
			        ?, ?, ?, ?,
			        strftime('%Y-%m-%dT%H:%M:%fZ','now'),
			        strftime('%Y-%m-%dT%H:%M:%fZ','now'))`
		insertArgs = []any{
			runID, in.VMID, in.Owner, in.Goal, in.CriteriaType, in.OnCompletion, progressEventsInt,
			in.InitialPhase, nullable(in.IdempotencyKey), in.RequestHash, createdEventID,
		}
	}

	res, err := tx.ExecContext(ctx, insertSQL, insertArgs...)
	if err != nil {
		// Map the partial unique index violation (one active run per VM) to the sentinel error.
		// The modernc SQLite driver reports the column path (runs.vm_id) not the index name.
		if isActiveRunConstraintError(err) {
			return nil, false, ErrActiveRunExists
		}
		return nil, false, fmt.Errorf("insert run: %w", err)
	}
	_ = res

	// Bump the VM's last_event_id so the situation delta notices the new run.
	if _, err := tx.ExecContext(ctx,
		`UPDATE vms SET last_event_id = ? WHERE vm_id = ?`, createdEventID, in.VMID); err != nil {
		return nil, false, fmt.Errorf("update vm last_event_id: %w", err)
	}

	run, err := scanRunInTx(ctx, tx, runID)
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit create-run: %w", err)
	}
	return run, false, nil
}

// lookupRunByIdempotencyKey is the readers-path idempotency check.
func (s *Store) lookupRunByIdempotencyKey(ctx context.Context, owner, key, requestHash string) (*Run, bool, error) {
	var existingRunID, existingHash string
	err := s.readers.QueryRowContext(ctx,
		`SELECT run_id, request_hash FROM runs WHERE owner = ? AND idempotency_key = ?`,
		owner, key,
	).Scan(&existingRunID, &existingHash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, false, nil
	case err != nil:
		return nil, false, fmt.Errorf("idempotency pre-check: %w", err)
	}
	if existingHash != requestHash {
		return nil, false, ErrIdempotencyConflict
	}
	run, err := s.GetRun(ctx, existingRunID)
	if err != nil {
		return nil, false, err
	}
	return run, true, nil
}

// --- TransitionRun ---

// TransitionRun advances a run's phase inside one writer transaction, validates
// the transition against the phase machine, and emits run.state_changed. It pins
// on in.From before checking edge legality — a stale caller walks away.
func (s *Store) TransitionRun(ctx context.Context, in RunTransitionInput) (*Run, error) {
	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin transition-run: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var current Run
	var progressEventsInt int
	err = tx.QueryRowContext(ctx,
		runColumns+` FROM runs WHERE run_id = ?`, in.RunID,
	).Scan(runScanDest(&current, &progressEventsInt)...)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, ErrRunNotFound
	case err != nil:
		return nil, fmt.Errorf("load run: %w", err)
	}
	current.ProgressEvents = progressEventsInt != 0

	// From pin: refuse even legal edges if the run has moved (stale caller).
	if in.From != "" && in.From != current.Phase {
		return nil, &InvalidRunTransitionError{RunID: in.RunID, From: current.Phase, To: in.To}
	}
	if !runTransitionAllowed(current.Phase, in.To) {
		return nil, &InvalidRunTransitionError{RunID: in.RunID, From: current.Phase, To: in.To}
	}

	isTerminal := terminalRunPhases[in.To]

	// Build the UPDATE statement.
	setClauses := []string{
		"phase = ?",
		"updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
	}
	args := []any{in.To}

	if in.To == "running" && current.Phase == "pending" {
		// pending→running: set started_at.
		setClauses = append(setClauses, "started_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')")
	}
	if isTerminal {
		setClauses = append(setClauses,
			"evaluated_by = ?",
			"reason = ?",
			"concluded_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
		)
		args = append(args, in.EvaluatedBy, in.Reason)
	}

	// Emit run.state_changed before the UPDATE so we capture the cursor.
	eventData := map[string]any{
		"run_id": in.RunID,
		"vm_id":  current.VMID,
		"from":   current.Phase,
		"to":     in.To,
	}
	if isTerminal {
		eventData["evaluated_by"] = in.EvaluatedBy
		eventData["reason"] = in.Reason
	}
	changedEventID, err := s.appendSystemInTx(ctx, tx, s.systemEnvelope("run.state_changed", "registry", notApplicableQuality(), eventData))
	if err != nil {
		return nil, fmt.Errorf("emit run.state_changed: %w", err)
	}

	if isTerminal {
		setClauses = append(setClauses, "concluded_event_id = ?")
		args = append(args, changedEventID)
	}

	args = append(args, in.RunID) // WHERE clause
	updateSQL := `UPDATE runs SET ` + strings.Join(setClauses, ", ") + ` WHERE run_id = ?`
	if _, err := tx.ExecContext(ctx, updateSQL, args...); err != nil {
		return nil, fmt.Errorf("update run phase: %w", err)
	}

	// Bump the VM's last_event_id on every transition so ?since delta notices phase changes.
	if _, err := tx.ExecContext(ctx,
		`UPDATE vms SET last_event_id = ? WHERE vm_id = ?`, changedEventID, current.VMID); err != nil {
		return nil, fmt.Errorf("update vm last_event_id: %w", err)
	}

	run, err := scanRunInTx(ctx, tx, in.RunID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit transition-run: %w", err)
	}
	return run, nil
}

// --- Read methods ---

// GetRun returns one run by run_id.
func (s *Store) GetRun(ctx context.Context, runID string) (*Run, error) {
	var run Run
	var progressEventsInt int
	err := s.readers.QueryRowContext(ctx,
		runColumns+` FROM runs WHERE run_id = ?`, runID,
	).Scan(runScanDest(&run, &progressEventsInt)...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrRunNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get run: %w", err)
	}
	run.ProgressEvents = progressEventsInt != 0
	return &run, nil
}

// ListRuns returns a keyset-paged slice of runs, optionally filtered by VMID
// and Phase. The After cursor is a decimal row_id (exclusive).
func (s *Store) ListRuns(ctx context.Context, q RunQuery) ([]*Run, string, error) {
	limit := q.Limit
	if limit == 0 {
		limit = DefaultPageLimit
	}
	if limit < 0 || limit > MaxPageLimit {
		return nil, "", &BoundError{Requested: q.Limit, Max: MaxPageLimit}
	}

	after := int64(0)
	if q.After != "" {
		if _, err := fmt.Sscanf(q.After, "%d", &after); err != nil || after <= 0 {
			return nil, "", ErrInvalidCursor
		}
	}

	where := "row_id > ?"
	args := []any{after}
	if q.VMID != "" {
		where += " AND vm_id = ?"
		args = append(args, q.VMID)
	}
	if q.Phase != "" {
		where += " AND phase = ?"
		args = append(args, q.Phase)
	}
	args = append(args, limit)

	rows, err := s.readers.QueryContext(ctx,
		runColumns+` FROM runs WHERE `+where+` ORDER BY row_id ASC LIMIT ?`, args...)
	if err != nil {
		return nil, "", fmt.Errorf("list runs: %w", err)
	}
	defer rows.Close()

	var out []*Run
	var lastRowID int64
	for rows.Next() {
		var run Run
		var progressEventsInt int
		if err := rows.Scan(runScanDest(&run, &progressEventsInt)...); err != nil {
			return nil, "", fmt.Errorf("scan run: %w", err)
		}
		run.ProgressEvents = progressEventsInt != 0
		out = append(out, &run)
		lastRowID = run.RowID
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("iterate runs: %w", err)
	}

	// Empty page returns the caller's input cursor unchanged — same semantics as
	// events pagination (QueryResult.NextAfter when the page is empty).
	nextAfter := q.After
	if len(out) > 0 {
		nextAfter = fmt.Sprintf("%d", lastRowID)
	}
	return out, nextAfter, nil
}

// ActiveRunForVM returns the single non-terminal run for vmID, or nil if none.
func (s *Store) ActiveRunForVM(ctx context.Context, vmID string) (*Run, error) {
	var run Run
	var progressEventsInt int
	err := s.readers.QueryRowContext(ctx,
		runColumns+` FROM runs WHERE vm_id = ? AND phase IN ('pending','running','concluding')`, vmID,
	).Scan(runScanDest(&run, &progressEventsInt)...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("active run for vm: %w", err)
	}
	run.ProgressEvents = progressEventsInt != 0
	return &run, nil
}

// ListRunsInPhases returns all runs currently in any of the listed phases.
// Used by the manager for reconciliation; not bounded by page limits because
// active runs are inherently bounded (one per VM).
func (s *Store) ListRunsInPhases(ctx context.Context, phases ...string) ([]*Run, error) {
	if len(phases) == 0 {
		return nil, nil
	}
	placeholders := strings.Repeat("?,", len(phases))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, len(phases))
	for i, p := range phases {
		args[i] = p
	}

	rows, err := s.readers.QueryContext(ctx,
		runColumns+` FROM runs WHERE phase IN (`+placeholders+`) ORDER BY row_id ASC`, args...)
	if err != nil {
		return nil, fmt.Errorf("list runs in phases: %w", err)
	}
	defer rows.Close()

	var out []*Run
	for rows.Next() {
		var run Run
		var progressEventsInt int
		if err := rows.Scan(runScanDest(&run, &progressEventsInt)...); err != nil {
			return nil, fmt.Errorf("scan run: %w", err)
		}
		run.ProgressEvents = progressEventsInt != 0
		out = append(out, &run)
	}
	return out, rows.Err()
}

// --- scanner helpers ---

const runColumns = `SELECT row_id, run_id, vm_id, owner, goal, criteria_type, on_completion,
	progress_events, phase, evaluated_by, reason, result_json, result_status, progress_seq,
	idempotency_key, request_hash, created_event_id, concluded_event_id,
	created_at, started_at, concluded_at, updated_at`

// runScanDest returns the ordered destination list for runColumns.
// progressEventsInt is a separate int because SQLite stores booleans as INTEGER.
func runScanDest(r *Run, progressEventsInt *int) []any {
	return []any{
		&r.RowID, &r.RunID, &r.VMID, &r.Owner, &r.Goal, &r.CriteriaType, &r.OnCompletion,
		progressEventsInt, &r.Phase, &r.EvaluatedBy, &r.Reason, &r.ResultJSON, &r.ResultStatus,
		&r.ProgressSeq,
		&r.IdempotencyKey, &r.RequestHash, &r.CreatedEventID, &r.ConcludedEventID,
		&r.CreatedAt, &r.StartedAt, &r.ConcludedAt, &r.UpdatedAt,
	}
}

func scanRunInTx(ctx context.Context, tx *sql.Tx, runID string) (*Run, error) {
	var run Run
	var progressEventsInt int
	err := tx.QueryRowContext(ctx,
		runColumns+` FROM runs WHERE run_id = ?`, runID,
	).Scan(runScanDest(&run, &progressEventsInt)...)
	if err != nil {
		return nil, fmt.Errorf("read run back: %w", err)
	}
	run.ProgressEvents = progressEventsInt != 0
	return &run, nil
}

// isActiveRunConstraintError reports whether err is the partial unique index
// violation for idx_runs_active (one active run per VM). The modernc SQLite
// driver reports "UNIQUE constraint failed: runs.vm_id" for this index.
func isActiveRunConstraintError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") &&
		strings.Contains(msg, "runs.vm_id")
}

// --- createRunInTx ---

// createRunInTx creates a run row inside an existing transaction (used by
// CreateVMWithOperation and insertOneMember for launch-attached runs). It
// emits run.created and bumps the VM's last_event_id in the same tx.
// No idempotency: the VM create's key covers the whole submission.
func (s *Store) createRunInTx(ctx context.Context, tx *sql.Tx, in CreateRunInput) error {
	runID := uuid.NewString()
	progressEventsInt := 0
	if in.ProgressEvents {
		progressEventsInt = 1
	}

	createdEventID, err := s.appendSystemInTx(ctx, tx, s.systemEnvelope("run.created", "registry", notApplicableQuality(), map[string]any{
		"run_id":           runID,
		"vm_id":            in.VMID,
		"owner":            in.Owner,
		"goal":             in.Goal,
		"success_criteria": in.CriteriaType,
		"on_completion":    in.OnCompletion,
		"progress_events":  progressEventsInt,
		"phase":            in.InitialPhase,
	}))
	if err != nil {
		return fmt.Errorf("emit run.created: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO runs
			(run_id, vm_id, owner, goal, criteria_type, on_completion, progress_events,
			 phase, idempotency_key, request_hash, created_event_id,
			 created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?,
			        ?, NULL, '', ?,
			        strftime('%Y-%m-%dT%H:%M:%fZ','now'),
			        strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
		runID, in.VMID, in.Owner, in.Goal, in.CriteriaType, in.OnCompletion, progressEventsInt,
		in.InitialPhase, createdEventID)
	if err != nil {
		if isActiveRunConstraintError(err) {
			return ErrActiveRunExists
		}
		return fmt.Errorf("insert run: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE vms SET last_event_id = ? WHERE vm_id = ?`, createdEventID, in.VMID); err != nil {
		return fmt.Errorf("update vm last_event_id: %w", err)
	}
	return nil
}

// --- RunForVM ---

// RunForVM returns the most recent run for vmID ordered by row_id DESC. Returns
// ErrRunNotFound when no run exists for the VM.
func (s *Store) RunForVM(ctx context.Context, vmID string) (*Run, error) {
	var run Run
	var progressEventsInt int
	err := s.readers.QueryRowContext(ctx,
		runColumns+` FROM runs WHERE vm_id = ? ORDER BY row_id DESC LIMIT 1`, vmID,
	).Scan(runScanDest(&run, &progressEventsInt)...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrRunNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("run for vm: %w", err)
	}
	run.ProgressEvents = progressEventsInt != 0
	return &run, nil
}

// --- SubmitRunProgress ---

// SubmitRunProgress records a bounded guest progress submission and emits
// run.progress (GuestReported). The seq counter is stored on the run row for
// O(1) increment. Returns ErrSubmissionRejected for malformed/oversized/disabled
// submissions; ErrRunNotAcceptingSubmissions for concluding/terminal runs.
func (s *Store) SubmitRunProgress(ctx context.Context, in SubmitProgressInput) (seq int64, err error) {
	// Fast-path phase and settings check before taking the writer lock.
	run, err := s.GetRun(ctx, in.RunID)
	if err != nil {
		return 0, err
	}

	if run.Phase != "pending" && run.Phase != "running" {
		return 0, ErrRunNotAcceptingSubmissions
	}

	// Validate payload before opening the writer tx.
	payloadBytes := int64(len(in.Payload))
	if payloadBytes > in.MaxBytes {
		return 0, s.recordSubmissionRejected(ctx, run, "progress",
			fmt.Sprintf("payload exceeds max_bytes limit (%d > %d)", payloadBytes, in.MaxBytes),
			payloadBytes)
	}
	if !json.Valid(in.Payload) {
		return 0, s.recordSubmissionRejected(ctx, run, "progress",
			"payload is not valid JSON", payloadBytes)
	}
	if !run.ProgressEvents {
		return 0, s.recordSubmissionRejected(ctx, run, "progress",
			"progress_events disabled for this run", payloadBytes)
	}

	// Open writer tx: increment progress_seq and emit run.progress.
	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin submit-progress: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Re-read run inside tx to pin the current seq value (single-writer serializes this).
	var currentSeq int64
	var phase string
	var progressEventsEnabled int
	if err := tx.QueryRowContext(ctx,
		`SELECT progress_seq, phase, progress_events FROM runs WHERE run_id = ?`, in.RunID,
	).Scan(&currentSeq, &phase, &progressEventsEnabled); err != nil {
		return 0, fmt.Errorf("read run for progress: %w", err)
	}
	if phase != "pending" && phase != "running" {
		return 0, ErrRunNotAcceptingSubmissions
	}

	nextSeq := currentSeq + 1

	// Emit run.progress (GuestReported) before updating the row.
	progressEnv := &events.Envelope{
		SchemaVersion:    1,
		SourceInstanceID: s.instanceID,
		SourceSeq:        fmt.Sprintf("%d", s.systemSeq.Add(1)),
		Kind:             "run.progress",
		Provenance:       events.GuestReported,
		Sensor:           "registry",
		HostReceivedAt:   events.Timestamp{Time: time.Now().UTC()},
		Quality: events.Quality{
			PathResolution: events.PathNotApplicable,
			Attribution:    events.AttributionNotApplicable,
		},
		Data: map[string]any{
			"run_id": in.RunID,
			"vm_id":  run.VMID,
			"seq":    nextSeq,
		},
	}
	eventID, err := s.appendSystemInTx(ctx, tx, progressEnv)
	if err != nil {
		return 0, fmt.Errorf("emit run.progress: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE runs SET progress_seq = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE run_id = ?`,
		nextSeq, in.RunID); err != nil {
		return 0, fmt.Errorf("update progress_seq: %w", err)
	}
	// Bump VM's last_event_id so ?since delta sees progress.
	if _, err := tx.ExecContext(ctx,
		`UPDATE vms SET last_event_id = ? WHERE vm_id = ?`, eventID, run.VMID); err != nil {
		return 0, fmt.Errorf("update vm last_event_id: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit submit-progress: %w", err)
	}
	return nextSeq, nil
}

// recordSubmissionRejected emits run.submission_rejected and returns
// ErrSubmissionRejected wrapped with the reason.
func (s *Store) recordSubmissionRejected(ctx context.Context, run *Run, submission, reason string, sizeBytes int64) error {
	env := s.systemEnvelope("run.submission_rejected", "registry", notApplicableQuality(), map[string]any{
		"run_id":     run.RunID,
		"vm_id":      run.VMID,
		"submission": submission,
		"reason":     reason,
		"size_bytes": sizeBytes,
	})
	// Best-effort: if the event fails to record, still return the rejection.
	_, _ = s.append(ctx, env, false)
	return fmt.Errorf("%w: %s", ErrSubmissionRejected, reason)
}

// --- SubmitRunResult ---

// SubmitRunResult records a bounded guest final result on the run row and emits
// run.result_recorded (HostObserved). Returns ErrSubmissionRejected for
// malformed/oversized/duplicate results; ErrRunNotAcceptingSubmissions for
// concluding/terminal runs. Phase is NOT changed — conclusion is the Manager's job.
func (s *Store) SubmitRunResult(ctx context.Context, in SubmitResultInput) (*Run, error) {
	run, err := s.GetRun(ctx, in.RunID)
	if err != nil {
		return nil, err
	}
	if run.Phase != "pending" && run.Phase != "running" {
		return nil, ErrRunNotAcceptingSubmissions
	}

	resultBytes := int64(len(in.Result))
	if resultBytes > in.MaxBytes {
		return nil, s.recordSubmissionRejected(ctx, run, "result",
			fmt.Sprintf("payload exceeds max_bytes limit (%d > %d)", resultBytes, in.MaxBytes),
			resultBytes)
	}

	// Parse and validate the result envelope before opening the writer tx.
	var resultMap map[string]any
	if err := json.Unmarshal(in.Result, &resultMap); err != nil {
		return nil, s.recordSubmissionRejected(ctx, run, "result",
			"result is not valid JSON", resultBytes)
	}
	statusRaw, ok := resultMap["status"]
	if !ok {
		return nil, s.recordSubmissionRejected(ctx, run, "result",
			"result missing required field: status", resultBytes)
	}
	status, isStr := statusRaw.(string)
	if !isStr || (status != "succeeded" && status != "failed") {
		return nil, s.recordSubmissionRejected(ctx, run, "result",
			fmt.Sprintf("status must be 'succeeded' or 'failed', got %q", statusRaw),
			resultBytes)
	}
	// detail size bound (1024 bytes).
	if detailRaw, has := resultMap["detail"]; has {
		if detail, isStr := detailRaw.(string); isStr && len(detail) > 1024 {
			return nil, s.recordSubmissionRejected(ctx, run, "result",
				fmt.Sprintf("detail exceeds 1024 bytes (%d)", len(detail)), resultBytes)
		}
	}

	// Open writer tx for the serialization point checks and the store.
	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin submit-result: %w", err)
	}
	txDone := false
	defer func() {
		if !txDone {
			_ = tx.Rollback()
		}
	}()

	// In-tx checks: phase and existing result (serialization point).
	var currentPhase, currentResultStatus string
	if err := tx.QueryRowContext(ctx,
		`SELECT phase, result_status FROM runs WHERE run_id = ?`, in.RunID,
	).Scan(&currentPhase, &currentResultStatus); err != nil {
		return nil, fmt.Errorf("read run for result: %w", err)
	}
	if currentPhase != "pending" && currentPhase != "running" {
		return nil, ErrRunNotAcceptingSubmissions
	}
	if currentResultStatus != "" {
		// Roll back the writer tx before calling recordSubmissionRejected
		// (which opens its own tx to emit the rejection event).
		txDone = true
		_ = tx.Rollback()
		return nil, s.recordSubmissionRejected(ctx, run, "result",
			"result already recorded", resultBytes)
	}

	// Emit run.result_recorded (HostObserved) before updating the row.
	eventID, err := s.appendSystemInTx(ctx, tx, s.systemEnvelope("run.result_recorded", "registry", notApplicableQuality(), map[string]any{
		"run_id":     in.RunID,
		"vm_id":      run.VMID,
		"status":     status,
		"size_bytes": resultBytes,
	}))
	if err != nil {
		return nil, fmt.Errorf("emit run.result_recorded: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE runs SET result_json = ?, result_status = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE run_id = ?`,
		string(in.Result), status, in.RunID); err != nil {
		return nil, fmt.Errorf("store result: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE vms SET last_event_id = ? WHERE vm_id = ?`, eventID, run.VMID); err != nil {
		return nil, fmt.Errorf("update vm last_event_id: %w", err)
	}

	updated, err := scanRunInTx(ctx, tx, in.RunID)
	if err != nil {
		return nil, err
	}
	txDone = true
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit submit-result: %w", err)
	}
	return updated, nil
}

// --- PutRunReport / GetRunReport ---

// PutRunReport stores a generated report row. Reports are immutable: a second
// call for the same run_id is rejected with an error naming the existing digest.
func (s *Store) PutRunReport(ctx context.Context, runID, reportJSON, digest string, operationID int64) error {
	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin put-report: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Check for existing report inside the tx.
	var existingDigest string
	err = tx.QueryRowContext(ctx,
		`SELECT digest FROM run_reports WHERE run_id = ?`, runID,
	).Scan(&existingDigest)
	if err == nil {
		// Report already exists — return error naming the existing digest.
		return fmt.Errorf("report already stored for run %s (digest: %s); reports are immutable", runID, existingDigest)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check existing report: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO run_reports (run_id, report_json, digest, operation_id, generated_at)
		 VALUES (?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
		runID, reportJSON, digest, operationID); err != nil {
		return fmt.Errorf("insert report: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit put-report: %w", err)
	}
	return nil
}

// GetRunReport returns the stored report for runID, or ErrReportNotFound.
func (s *Store) GetRunReport(ctx context.Context, runID string) (*RunReport, error) {
	var r RunReport
	err := s.readers.QueryRowContext(ctx,
		`SELECT run_id, report_json, digest, operation_id, generated_at FROM run_reports WHERE run_id = ?`,
		runID,
	).Scan(&r.RunID, &r.ReportJSON, &r.Digest, &r.OperationID, &r.GeneratedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrReportNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get run report: %w", err)
	}
	return &r, nil
}
