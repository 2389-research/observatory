// ABOUTME: The durable attention queue (SPEC §12.7): raises land atomically as
// ABOUTME: attention.raised events plus queue rows; ack state survives restart.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/2389-research/observatory-v2/internal/redact"
)

// Severity has three levels only (SPEC §12.7): grade by whether and when the
// operator must act.
const (
	SeverityInfo          = "info"
	SeverityNeedsDecision = "needs_decision"
	SeverityCritical      = "critical"
)

// ErrAttentionUnknown: no attention item has this id.
var ErrAttentionUnknown = errors.New("attention item not found; list open items via GET /api/v1/attention")

// SuggestedAction is a typed action executable as returned (P-06). It shares
// the shape of error remediations deliberately.
type SuggestedAction struct {
	Action    string         `json:"action"`
	Params    map[string]any `json:"params,omitempty"`
	Rationale string         `json:"rationale"`
}

// RaiseInput describes one trigger firing. Only the in-process trigger engine
// calls RaiseAttention; the API never exposes it.
type RaiseInput struct {
	TriggerClass     string
	Severity         string
	VMID             *string
	RunID            *string
	Summary          string
	SystemAction     string
	EvidenceLinks    []string
	SuggestedActions []SuggestedAction
	// Collapse folds a duplicate of an open (trigger_class, vm) item into its
	// count instead of raising a new item.
	Collapse bool
	// QueueMax bounds open items; at the bound, non-critical raises are refused
	// and recorded as attention.queue_overflow. <=0 means unbounded.
	QueueMax int
	// CursorName/CursorTo advance an engine cursor in the same transaction, so
	// a crash never re-raises an already-processed trigger event.
	CursorName string
	CursorTo   int64
}

// AttentionItem is one row of the queue view.
type AttentionItem struct {
	AttentionID      int64
	RaisedEventID    int64
	LastEventID      int64
	VMID             *string
	RunID            *string
	TriggerClass     string
	Severity         string
	Summary          string
	SystemAction     string
	EvidenceLinks    []string
	SuggestedActions []SuggestedAction
	Count            int64
	Acked            bool
	AckedAt          *string
	CreatedAt        string
	UpdatedAt        string
}

// AttentionQuery pages the queue by attention_id keyset.
type AttentionQuery struct {
	IncludeAcked bool
	After        int64
	Limit        int
}

func validSeverity(s string) bool {
	return s == SeverityInfo || s == SeverityNeedsDecision || s == SeverityCritical
}

// RaiseAttention records one trigger firing: the attention.raised event, the
// queue upsert (new item or collapse), and the engine-cursor advance land in
// one writer transaction. A refused (overflowed) raise returns (nil, nil) and
// records attention.queue_overflow instead.
func (s *Store) RaiseAttention(ctx context.Context, in RaiseInput) (*AttentionItem, error) {
	if in.TriggerClass == "" || in.Summary == "" {
		return nil, errors.New("attention raise requires trigger class and summary")
	}
	if !validSeverity(in.Severity) {
		return nil, fmt.Errorf("severity %q is not one of info, needs_decision, critical", in.Severity)
	}
	// Attention summaries pass the same redaction policy as annotations before
	// persistence (SPEC §15.3).
	summary, _ := redact.Apply(in.Summary)

	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin raise: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	item, err := s.raiseInTx(ctx, tx, in, summary)
	if err != nil {
		return nil, err
	}
	if in.CursorName != "" {
		if err := advanceCursorInTx(ctx, tx, in.CursorName, in.CursorTo); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit raise: %w", err)
	}
	return item, nil
}

func (s *Store) raiseInTx(ctx context.Context, tx *sql.Tx, in RaiseInput, summary string) (*AttentionItem, error) {
	eventData := map[string]any{
		"trigger_class": in.TriggerClass,
		"severity":      in.Severity,
		"summary":       summary,
		"system_action": in.SystemAction,
	}
	if in.VMID != nil {
		eventData["vm_id"] = *in.VMID
	}
	if in.RunID != nil {
		eventData["run_id"] = *in.RunID
	}

	if in.Collapse {
		var existing int64
		err := tx.QueryRowContext(ctx,
			`SELECT attention_id FROM attention_items
			 WHERE acked = 0 AND trigger_class = ? AND vm_id IS ?`,
			in.TriggerClass, nullable(in.VMID)).Scan(&existing)
		switch {
		case err == nil:
			eventData["attention_id"] = strconv.FormatInt(existing, 10)
			eventData["collapsed"] = true
			eid, err := s.appendSystemInTx(ctx, tx,
				s.systemEnvelope("attention.raised", "situation", notApplicableQuality(), eventData))
			if err != nil {
				return nil, err
			}
			if _, err := tx.ExecContext(ctx,
				`UPDATE attention_items SET count = count + 1, last_event_id = ?,
				 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE attention_id = ?`,
				eid, existing); err != nil {
				return nil, fmt.Errorf("collapse item: %w", err)
			}
			return readAttentionInTx(ctx, tx, existing)
		case !errors.Is(err, sql.ErrNoRows):
			return nil, fmt.Errorf("look up open item: %w", err)
		}
	}

	// Bounded queue: refuse non-critical raises at the cap, and make the
	// refusal itself evidence. Critical items are never refused.
	if in.QueueMax > 0 && in.Severity != SeverityCritical {
		var open int64
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM attention_items WHERE acked = 0`).Scan(&open); err != nil {
			return nil, fmt.Errorf("count open items: %w", err)
		}
		if open >= int64(in.QueueMax) {
			overflow := map[string]any{
				"trigger_class": in.TriggerClass,
				"open_count":    strconv.FormatInt(open, 10),
				"queue_max":     strconv.Itoa(in.QueueMax),
			}
			if in.VMID != nil {
				overflow["vm_id"] = *in.VMID
			}
			if _, err := s.appendSystemInTx(ctx, tx,
				s.systemEnvelope("attention.queue_overflow", "situation", notApplicableQuality(), overflow)); err != nil {
				return nil, err
			}
			return nil, nil
		}
	}

	links, err := json.Marshal(orEmpty(in.EvidenceLinks))
	if err != nil {
		return nil, fmt.Errorf("marshal evidence links: %w", err)
	}
	actions, err := json.Marshal(orEmptyActions(in.SuggestedActions))
	if err != nil {
		return nil, fmt.Errorf("marshal suggested actions: %w", err)
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO attention_items
		 (raised_event_id, last_event_id, vm_id, run_id, trigger_class, severity,
		  summary, system_action, evidence_links, suggested_actions, created_at, updated_at)
		 VALUES (0, 0, ?, ?, ?, ?, ?, ?, ?, ?,
		  strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
		nullable(in.VMID), nullable(in.RunID), in.TriggerClass, in.Severity,
		summary, in.SystemAction, string(links), string(actions))
	if err != nil {
		return nil, fmt.Errorf("insert item: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("read attention id: %w", err)
	}

	eventData["attention_id"] = strconv.FormatInt(id, 10)
	eid, err := s.appendSystemInTx(ctx, tx,
		s.systemEnvelope("attention.raised", "situation", notApplicableQuality(), eventData))
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE attention_items SET raised_event_id = ?, last_event_id = ? WHERE attention_id = ?`,
		eid, eid, id); err != nil {
		return nil, fmt.Errorf("link raised event: %w", err)
	}
	return readAttentionInTx(ctx, tx, id)
}

// AckAttention durably acknowledges an item. Acking an already-acked item is
// idempotent success: the suggested action stays executable as returned.
func (s *Store) AckAttention(ctx context.Context, id int64) (*AttentionItem, error) {
	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin ack: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := readAttentionInTx(ctx, tx, id); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE attention_items SET acked = 1, acked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
		 WHERE attention_id = ? AND acked = 0`, id); err != nil {
		return nil, fmt.Errorf("ack item: %w", err)
	}
	item, err := readAttentionInTx(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit ack: %w", err)
	}
	return item, nil
}

// ListAttention pages the queue by attention_id. The default view is open
// items; IncludeAcked returns history too.
func (s *Store) ListAttention(ctx context.Context, q AttentionQuery) ([]*AttentionItem, error) {
	limit := q.Limit
	if limit == 0 {
		limit = DefaultPageLimit
	}
	if limit < 0 || limit > MaxPageLimit {
		return nil, &BoundError{Requested: q.Limit, Max: MaxPageLimit}
	}
	where := "attention_id > ?"
	if !q.IncludeAcked {
		where += " AND acked = 0"
	}
	rows, err := s.readers.QueryContext(ctx,
		attentionColumns+` FROM attention_items WHERE `+where+` ORDER BY attention_id ASC LIMIT ?`,
		q.After, limit)
	if err != nil {
		return nil, fmt.Errorf("list attention: %w", err)
	}
	defer rows.Close()
	return scanAttentionRows(rows)
}

// OpenAttentionHead returns the top of the open queue: severity first, newest
// within a severity.
func (s *Store) OpenAttentionHead(ctx context.Context, n int) ([]*AttentionItem, error) {
	rows, err := s.readers.QueryContext(ctx,
		attentionColumns+` FROM attention_items WHERE acked = 0
		 ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'needs_decision' THEN 1 ELSE 2 END,
		          attention_id DESC
		 LIMIT ?`, n)
	if err != nil {
		return nil, fmt.Errorf("attention head: %w", err)
	}
	defer rows.Close()
	return scanAttentionRows(rows)
}

// CountOpenAttention reports how many items await acknowledgment.
func (s *Store) CountOpenAttention(ctx context.Context) (int64, error) {
	var n int64
	err := s.readers.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM attention_items WHERE acked = 0`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count open attention: %w", err)
	}
	return n, nil
}

// CountOpenAttentionByVM reports how many unacknowledged items reference each
// VM. Host-scoped items (no vm_id) are not in the map.
func (s *Store) CountOpenAttentionByVM(ctx context.Context) (map[string]int64, error) {
	rows, err := s.readers.QueryContext(ctx,
		`SELECT vm_id, COUNT(*) FROM attention_items WHERE acked = 0 AND vm_id IS NOT NULL GROUP BY vm_id`)
	if err != nil {
		return nil, fmt.Errorf("count open attention by vm: %w", err)
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var vmID string
		var n int64
		if err := rows.Scan(&vmID, &n); err != nil {
			return nil, fmt.Errorf("scan attention count: %w", err)
		}
		out[vmID] = n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("count open attention by vm: %w", err)
	}
	return out, nil
}

// ReadEngineCursor returns the persisted cursor for name, 0 if never advanced.
func (s *Store) ReadEngineCursor(ctx context.Context, name string) (int64, error) {
	var c int64
	err := s.readers.QueryRowContext(ctx,
		`SELECT cursor FROM engine_cursors WHERE name = ?`, name).Scan(&c)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read cursor %s: %w", name, err)
	}
	return c, nil
}

// AdvanceEngineCursor persists the cursor for name outside a raise, covering
// spans of events that matched no trigger.
func (s *Store) AdvanceEngineCursor(ctx context.Context, name string, to int64) error {
	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin cursor advance: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := advanceCursorInTx(ctx, tx, name, to); err != nil {
		return err
	}
	return tx.Commit()
}

func advanceCursorInTx(ctx context.Context, tx *sql.Tx, name string, to int64) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO engine_cursors (name, cursor) VALUES (?, ?)
		 ON CONFLICT(name) DO UPDATE SET cursor = excluded.cursor`, name, to)
	if err != nil {
		return fmt.Errorf("advance cursor %s: %w", name, err)
	}
	return nil
}

const attentionColumns = `SELECT attention_id, raised_event_id, last_event_id, vm_id, run_id,
	trigger_class, severity, summary, system_action, evidence_links, suggested_actions,
	count, acked, acked_at, created_at, updated_at`

type attentionScanner interface {
	Scan(dest ...any) error
}

func scanAttention(sc attentionScanner) (*AttentionItem, error) {
	var it AttentionItem
	var vm, run, ackedAt sql.NullString
	var acked int64
	var links, actions string
	if err := sc.Scan(&it.AttentionID, &it.RaisedEventID, &it.LastEventID, &vm, &run,
		&it.TriggerClass, &it.Severity, &it.Summary, &it.SystemAction, &links, &actions,
		&it.Count, &acked, &ackedAt, &it.CreatedAt, &it.UpdatedAt); err != nil {
		return nil, err
	}
	if vm.Valid {
		it.VMID = &vm.String
	}
	if run.Valid {
		it.RunID = &run.String
	}
	if ackedAt.Valid {
		it.AckedAt = &ackedAt.String
	}
	it.Acked = acked != 0
	if err := json.Unmarshal([]byte(links), &it.EvidenceLinks); err != nil {
		return nil, fmt.Errorf("decode evidence links: %w", err)
	}
	if err := json.Unmarshal([]byte(actions), &it.SuggestedActions); err != nil {
		return nil, fmt.Errorf("decode suggested actions: %w", err)
	}
	return &it, nil
}

func readAttentionInTx(ctx context.Context, tx *sql.Tx, id int64) (*AttentionItem, error) {
	row := tx.QueryRowContext(ctx, attentionColumns+` FROM attention_items WHERE attention_id = ?`, id)
	item, err := scanAttention(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("attention id %d: %w", id, ErrAttentionUnknown)
	}
	if err != nil {
		return nil, fmt.Errorf("read attention item: %w", err)
	}
	return item, nil
}

func scanAttentionRows(rows *sql.Rows) ([]*AttentionItem, error) {
	items := []*AttentionItem{}
	for rows.Next() {
		it, err := scanAttention(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan attention items: %w", err)
	}
	return items, nil
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func orEmptyActions(a []SuggestedAction) []SuggestedAction {
	if a == nil {
		return []SuggestedAction{}
	}
	return a
}
