// ABOUTME: Bounded keyset queries over the ingestion cursor: default and maximum
// ABOUTME: page sizes are the single source of truth for every read surface.
package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/2389-research/observatory-v2/internal/events"
)

const (
	// DefaultPageLimit applies when a query does not name a limit (P-01:
	// bounded by default).
	DefaultPageLimit = 200
	// MaxPageLimit is the hard ceiling; asking for more is an error that
	// teaches, not a silent clamp.
	MaxPageLimit = 1000
)

// ErrInvalidCursor: the After or Until cursor is not a decimal event id.
var ErrInvalidCursor = errors.New("cursor must be a decimal event_id as returned in next_after")

// ErrUnknownFamily: the Family has no registered kinds.
var ErrUnknownFamily = errors.New("family has no registered event kinds; check /meta/event-kinds")

// ErrConflictingFilters: Kind and Family were both set; only one axis at a time.
var ErrConflictingFilters = errors.New("kind and family are mutually exclusive; set one axis at a time for unambiguous reproduce queries")

// BoundError reports a limit outside 1..MaxPageLimit.
type BoundError struct {
	Requested int
	Max       int
}

func (e *BoundError) Error() string {
	return fmt.Sprintf("limit %d outside 1..%d; request at most %d and page with after", e.Requested, e.Max, e.Max)
}

// Query selects events in ingestion order, strictly after the After cursor.
type Query struct {
	VMID   *string // nil: no vm filter
	Kind   string  // "": no kind filter
	Family string  // "": no family filter; mutually exclusive with Kind
	After  string  // "": from the start
	Until  string  // "": no upper bound (inclusive); decimal event_id
	Limit  int     // 0: DefaultPageLimit
}

// QueryResult always states how far the store goes (LatestEventID) so an empty
// page is evidence of quiet, not absence of coverage (P-03).
type QueryResult struct {
	Events        []*events.Envelope
	NextAfter     string // resume cursor; equals After when the page is empty
	LatestEventID string // highest cursor in the store, "" when empty
}

func (s *Store) Query(ctx context.Context, q Query) (QueryResult, error) {
	var zero QueryResult

	// Conflict guard: Kind and Family are mutually exclusive.
	if q.Kind != "" && q.Family != "" {
		return zero, ErrConflictingFilters
	}

	limit := q.Limit
	if limit == 0 {
		limit = DefaultPageLimit
	}
	if limit < 1 || limit > MaxPageLimit {
		return zero, &BoundError{Requested: q.Limit, Max: MaxPageLimit}
	}
	after := int64(0)
	if q.After != "" {
		if !events.DecimalString(q.After) {
			return zero, fmt.Errorf("after %q: %w", q.After, ErrInvalidCursor)
		}
		var err error
		if after, err = strconv.ParseInt(q.After, 10, 64); err != nil {
			return zero, fmt.Errorf("after %q: %w", q.After, ErrInvalidCursor)
		}
	}
	until := int64(-1) // -1 means no upper bound
	if q.Until != "" {
		if !events.DecimalString(q.Until) {
			return zero, fmt.Errorf("until %q: %w", q.Until, ErrInvalidCursor)
		}
		var err error
		if until, err = strconv.ParseInt(q.Until, 10, 64); err != nil {
			return zero, fmt.Errorf("until %q: %w", q.Until, ErrInvalidCursor)
		}
	}

	// Resolve family to a set of kind strings.
	var familyKinds []string
	if q.Family != "" {
		familyKinds = events.KindsByFamily(q.Family)
		if familyKinds == nil {
			return zero, fmt.Errorf("family %q: %w", q.Family, ErrUnknownFamily)
		}
	}

	where := "event_id > ?"
	args := []any{after}
	if until >= 0 {
		where += " AND event_id <= ?"
		args = append(args, until)
	}
	if q.VMID != nil {
		// vm_id= has one meaning everywhere: events linked to this VM, whether
		// by the envelope column (regular ingested events) or by data.vm_id in
		// the payload (store-synthesized events — vm.*, run.* — that ride the
		// host-wide stream with a NULL vm_id column). No knob; always both arms.
		where += " AND (vm_id = ? OR json_extract(payload, '$.data.vm_id') = ?)"
		args = append(args, *q.VMID, *q.VMID)
	}
	if q.Kind != "" {
		where += " AND kind = ?"
		args = append(args, q.Kind)
	}
	if len(familyKinds) > 0 {
		placeholders := strings.Repeat("?,", len(familyKinds))
		placeholders = placeholders[:len(placeholders)-1] // trim trailing comma
		where += " AND kind IN (" + placeholders + ")"
		for _, k := range familyKinds {
			args = append(args, k)
		}
	}
	args = append(args, limit)

	rows, err := s.readers.QueryContext(ctx,
		`SELECT event_id, payload FROM events WHERE `+where+` ORDER BY event_id ASC LIMIT ?`, args...)
	if err != nil {
		return zero, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	result := QueryResult{NextAfter: q.After}
	for rows.Next() {
		var id int64
		var payload []byte
		if err := rows.Scan(&id, &payload); err != nil {
			return zero, fmt.Errorf("scan event: %w", err)
		}
		env, err := events.Parse(payload)
		if err != nil {
			return zero, fmt.Errorf("stored payload for event %d does not parse: %w", id, err)
		}
		cursor := strconv.FormatInt(id, 10)
		env.EventID = &cursor
		result.Events = append(result.Events, env)
		result.NextAfter = cursor
	}
	if err := rows.Err(); err != nil {
		return zero, fmt.Errorf("iterate events: %w", err)
	}

	var latest int64
	if err := s.readers.QueryRowContext(ctx, `SELECT COALESCE(MAX(event_id), 0) FROM events`).Scan(&latest); err != nil {
		return zero, fmt.Errorf("read latest cursor: %w", err)
	}
	if latest > 0 {
		result.LatestEventID = strconv.FormatInt(latest, 10)
	}
	return result, nil
}
