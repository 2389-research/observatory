// ABOUTME: Immutable operator annotations on entity refs (AT-100): redacted
// ABOUTME: before persistence, recorded as annotation.created events, queryable by ref.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/2389-research/observatory/internal/redact"
)

// Annotation bounds. The spec requires bounded text without naming a number;
// these are the numbers, served through /meta limits.
const (
	AnnotationTextMaxBytes     = 4096
	AnnotationMaxTags          = 16
	AnnotationTagKeyMaxBytes   = 64
	AnnotationTagValueMaxBytes = 256
	AnnotationRefMaxBytes      = 256
)

// ErrInvalidTargetRef: refs are "<type>:<id>" with a known type.
var ErrInvalidTargetRef = errors.New(
	`target_ref must be "<type>:<id>" with type one of vm, boot, run, event, operation, template, artifact, host and a printable id`)

var refTypes = map[string]bool{
	"vm": true, "boot": true, "run": true, "event": true,
	"operation": true, "template": true, "artifact": true, "host": true,
}

// AnnotationBoundError teaches the violated bound instead of truncating:
// silent truncation would misquote the operator.
type AnnotationBoundError struct {
	Field string
	Got   int
	Max   int
}

func (e *AnnotationBoundError) Error() string {
	return fmt.Sprintf("annotation %s is %d bytes/items, max %d; shorten it — truncating operator text would misquote it", e.Field, e.Got, e.Max)
}

// AnnotationInput is what trusted ingress accepts. Author is assigned by the
// caller from its authentication context, never from client payload.
type AnnotationInput struct {
	TargetRef string
	Author    string
	Text      string
	Tags      map[string]string
}

// Annotation is one immutable recorded note.
type Annotation struct {
	AnnotationID      int64
	TargetRef         string
	Author            string
	Text              string
	Tags              map[string]string
	Redacted          bool
	RedactionPolicyID string
	EventID           int64
	CreatedAt         string
}

// AnnotationQuery pages annotations by id keyset, optionally filtered to one ref.
type AnnotationQuery struct {
	Ref   string
	After int64
	Limit int
}

func validateRef(ref string) error {
	typ, id, ok := strings.Cut(ref, ":")
	if !ok || len(ref) > AnnotationRefMaxBytes || !refTypes[typ] || id == "" {
		return fmt.Errorf("ref %q: %w", ref, ErrInvalidTargetRef)
	}
	for _, r := range id {
		if r <= ' ' || r > '~' {
			return fmt.Errorf("ref %q: %w", ref, ErrInvalidTargetRef)
		}
	}
	return nil
}

func validateAnnotation(in AnnotationInput) error {
	if err := validateRef(in.TargetRef); err != nil {
		return err
	}
	if in.Author == "" {
		return errors.New("annotation author is required; ingress assigns it from the authenticated identity")
	}
	if in.Text == "" {
		return errors.New("annotation text is required")
	}
	if n := len(in.Text); n > AnnotationTextMaxBytes {
		return &AnnotationBoundError{Field: "text", Got: n, Max: AnnotationTextMaxBytes}
	}
	if n := len(in.Tags); n > AnnotationMaxTags {
		return &AnnotationBoundError{Field: "tags", Got: n, Max: AnnotationMaxTags}
	}
	for k, v := range in.Tags {
		if k == "" || len(k) > AnnotationTagKeyMaxBytes {
			return &AnnotationBoundError{Field: "tag key", Got: len(k), Max: AnnotationTagKeyMaxBytes}
		}
		if len(v) > AnnotationTagValueMaxBytes {
			return &AnnotationBoundError{Field: "tag value", Got: len(v), Max: AnnotationTagValueMaxBytes}
		}
	}
	return nil
}

// CreateAnnotation records one immutable annotation: the row and its
// annotation.created event land in one transaction, text redacted first
// (SPEC §15.3). There is no update or delete path by design.
func (s *Store) CreateAnnotation(ctx context.Context, in AnnotationInput) (*Annotation, error) {
	if err := validateAnnotation(in); err != nil {
		return nil, err
	}
	text, redacted := redact.Apply(in.Text)
	policy := ""
	if redacted {
		policy = redact.PolicyID
	}
	tags := in.Tags
	if tags == nil {
		tags = map[string]string{}
	}
	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		return nil, fmt.Errorf("marshal tags: %w", err)
	}

	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin annotation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`INSERT INTO annotations (target_ref, author, text, tags, redacted, redaction_policy_id, event_id, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, 0, strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
		in.TargetRef, in.Author, text, string(tagsJSON), boolInt(redacted), policy)
	if err != nil {
		return nil, fmt.Errorf("insert annotation: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("read annotation id: %w", err)
	}

	quality := notApplicableQuality()
	quality.Redacted = redacted
	quality.RedactionPolicyID = policy
	data := map[string]any{
		"annotation_id": strconv.FormatInt(id, 10),
		"target_ref":    in.TargetRef,
		"author":        in.Author,
		"text":          text,
		"tags":          tags,
	}
	eid, err := s.appendSystemInTx(ctx, tx,
		s.systemEnvelope("annotation.created", "annotations", quality, data))
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE annotations SET event_id = ? WHERE annotation_id = ?`, eid, id); err != nil {
		return nil, fmt.Errorf("link annotation event: %w", err)
	}

	row := tx.QueryRowContext(ctx, annotationColumns+` FROM annotations WHERE annotation_id = ?`, id)
	ann, err := scanAnnotation(row)
	if err != nil {
		return nil, fmt.Errorf("read annotation back: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit annotation: %w", err)
	}
	return ann, nil
}

// ListAnnotations pages annotations by id, optionally filtered by target ref.
func (s *Store) ListAnnotations(ctx context.Context, q AnnotationQuery) ([]*Annotation, error) {
	limit := q.Limit
	if limit == 0 {
		limit = DefaultPageLimit
	}
	if limit < 0 || limit > MaxPageLimit {
		return nil, &BoundError{Requested: q.Limit, Max: MaxPageLimit}
	}
	where := "annotation_id > ?"
	args := []any{q.After}
	if q.Ref != "" {
		if err := validateRef(q.Ref); err != nil {
			return nil, err
		}
		where += " AND target_ref = ?"
		args = append(args, q.Ref)
	}
	args = append(args, limit)
	rows, err := s.readers.QueryContext(ctx,
		annotationColumns+` FROM annotations WHERE `+where+` ORDER BY annotation_id ASC LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("list annotations: %w", err)
	}
	defer rows.Close()

	out := []*Annotation{}
	for rows.Next() {
		ann, err := scanAnnotation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ann)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan annotations: %w", err)
	}
	return out, nil
}

const annotationColumns = `SELECT annotation_id, target_ref, author, text, tags, redacted, redaction_policy_id, event_id, created_at`

func scanAnnotation(sc attentionScanner) (*Annotation, error) {
	var a Annotation
	var redacted int64
	var tags string
	if err := sc.Scan(&a.AnnotationID, &a.TargetRef, &a.Author, &a.Text, &tags,
		&redacted, &a.RedactionPolicyID, &a.EventID, &a.CreatedAt); err != nil {
		return nil, err
	}
	a.Redacted = redacted != 0
	if err := json.Unmarshal([]byte(tags), &a.Tags); err != nil {
		return nil, fmt.Errorf("decode tags: %w", err)
	}
	return &a, nil
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
