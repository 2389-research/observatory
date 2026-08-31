// ABOUTME: Trusted-ingress append: validation, kind-registry enforcement, stream
// ABOUTME: scope binding, dedup by (source, seq), integrity failures as health events.
package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/2389-research/observatory-v2/internal/events"
)

var (
	// ErrEventIDPreset: producers never assign the ingestion cursor.
	ErrEventIDPreset = errors.New("event_id is assigned by the store at ingest; remove it from the envelope")
	// ErrUnregisteredKind: the kind is absent from the in-code registry.
	ErrUnregisteredKind = errors.New("event kind is not registered; register the kind alongside the code that emits it")
	// ErrProvenanceMismatch: the envelope claims a provenance the registry does
	// not assign to its kind. Provenance is an ingress decision, not a producer claim.
	ErrProvenanceMismatch = errors.New("provenance does not match the registered provenance for this kind")
	// ErrIntegrityFailure: a (source_instance_id, source_seq) key was resent
	// with different payload bytes. The original stands; the conflict is recorded.
	ErrIntegrityFailure = errors.New("stream integrity failure: same source and seq resent with different payload")
	// ErrStreamScopeMismatch: a source instance tried to emit for a different
	// VM than its stream is bound to.
	ErrStreamScopeMismatch = errors.New("stream is bound to a different vm scope; a producer instance serves exactly one vm")
)

// AppendResult reports where an envelope landed in the ingestion order.
type AppendResult struct {
	EventID string
	Deduped bool
}

// Append persists one envelope. Identical resends dedupe silently to the
// original cursor; protocol violations are rejected and recorded as
// host_observed telemetry health events so they show up as evidence, not logs.
func (s *Store) Append(ctx context.Context, env *events.Envelope) (AppendResult, error) {
	return s.append(ctx, env, true)
}

func (s *Store) append(ctx context.Context, env *events.Envelope, emitHealth bool) (AppendResult, error) {
	var zero AppendResult
	if env.EventID != nil {
		return zero, ErrEventIDPreset
	}
	if err := env.Validate(); err != nil {
		return zero, err
	}
	info, ok := events.LookupKind(env.Kind)
	if !ok {
		err := fmt.Errorf("kind %q: %w", env.Kind, ErrUnregisteredKind)
		if emitHealth {
			return zero, s.withHealth(ctx, err, "telemetry.unregistered_kind", map[string]any{
				"kind":               env.Kind,
				"source_instance_id": env.SourceInstanceID,
				"source_seq":         env.SourceSeq,
			})
		}
		return zero, err
	}
	if env.Provenance != info.Provenance {
		return zero, fmt.Errorf("kind %q is %s, envelope claims %s: %w",
			env.Kind, info.Provenance, env.Provenance, ErrProvenanceMismatch)
	}

	payload, err := json.Marshal(env)
	if err != nil {
		return zero, fmt.Errorf("marshal envelope: %w", err)
	}
	hash := sha256.Sum256(payload)

	res, verr := s.appendTx(ctx, env, payload, hash[:])
	if verr == nil || !emitHealth {
		return res, verr
	}
	switch {
	case errors.Is(verr, ErrIntegrityFailure):
		return res, s.withHealth(ctx, verr, "telemetry.integrity_failure", map[string]any{
			"failure":            "seq_payload_conflict",
			"source_instance_id": env.SourceInstanceID,
			"source_seq":         env.SourceSeq,
			"existing_event_id":  res.EventID,
		})
	case errors.Is(verr, ErrStreamScopeMismatch):
		return res, s.withHealth(ctx, verr, "telemetry.integrity_failure", map[string]any{
			"failure":            "stream_scope_rebind",
			"source_instance_id": env.SourceInstanceID,
			"source_seq":         env.SourceSeq,
		})
	}
	return res, verr
}

// appendTx runs the bind/dedup/insert protocol in one writer transaction.
// On ErrIntegrityFailure the returned result carries the existing cursor.
func (s *Store) appendTx(ctx context.Context, env *events.Envelope, payload, hash []byte) (AppendResult, error) {
	var zero AppendResult
	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return zero, fmt.Errorf("begin append: %w", err)
	}
	// Rollback after a successful Commit returns ErrTxDone; nothing to act on.
	defer func() { _ = tx.Rollback() }()

	var boundVM sql.NullString
	streamKnown := true
	err = tx.QueryRowContext(ctx,
		`SELECT vm_id FROM streams WHERE source_instance_id = ?`, env.SourceInstanceID,
	).Scan(&boundVM)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		streamKnown = false
	case err != nil:
		return zero, fmt.Errorf("look up stream: %w", err)
	}
	if streamKnown && !sameScope(boundVM, env.VMID) {
		return zero, fmt.Errorf("source %s: %w", env.SourceInstanceID, ErrStreamScopeMismatch)
	}

	var existingID int64
	var existingHash []byte
	err = tx.QueryRowContext(ctx,
		`SELECT event_id, payload_hash FROM events WHERE source_instance_id = ? AND source_seq = ?`,
		env.SourceInstanceID, env.SourceSeq,
	).Scan(&existingID, &existingHash)
	switch {
	case err == nil:
		existing := AppendResult{EventID: strconv.FormatInt(existingID, 10)}
		if bytes.Equal(hash, existingHash) {
			existing.Deduped = true
			return existing, nil
		}
		return existing, fmt.Errorf("source %s seq %s: %w", env.SourceInstanceID, env.SourceSeq, ErrIntegrityFailure)
	case !errors.Is(err, sql.ErrNoRows):
		return zero, fmt.Errorf("look up dedup key: %w", err)
	}

	if !streamKnown {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO streams (source_instance_id, vm_id, created_at)
			 VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
			env.SourceInstanceID, nullable(env.VMID)); err != nil {
			return zero, fmt.Errorf("bind stream: %w", err)
		}
	}

	received, err := env.HostReceivedAt.MarshalJSON()
	if err != nil {
		return zero, fmt.Errorf("format received time: %w", err)
	}
	insert, err := tx.ExecContext(ctx,
		`INSERT INTO events (source_instance_id, source_seq, vm_id, boot_id, kind, host_received_at, payload, payload_hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		env.SourceInstanceID, env.SourceSeq, nullable(env.VMID), nullable(env.BootID),
		env.Kind, string(bytes.Trim(received, `"`)), string(payload), hash)
	if err != nil {
		return zero, fmt.Errorf("insert event: %w", err)
	}
	id, err := insert.LastInsertId()
	if err != nil {
		return zero, fmt.Errorf("read cursor: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return zero, fmt.Errorf("commit append: %w", err)
	}
	return AppendResult{EventID: strconv.FormatInt(id, 10)}, nil
}

// withHealth records a host-wide health event about cause and returns cause,
// joined with the recording error if that fails too. Health events use the
// store's own stream (host-wide scope) and reference the offender in data.
func (s *Store) withHealth(ctx context.Context, cause error, kind string, data map[string]any) error {
	env := &events.Envelope{
		SchemaVersion:    1,
		SourceInstanceID: s.instanceID,
		SourceSeq:        strconv.FormatInt(s.healthSeq.Add(1), 10),
		Kind:             kind,
		Provenance:       events.HostObserved,
		Sensor:           "store",
		HostReceivedAt:   events.Timestamp{Time: time.Now().UTC()},
		Quality: events.Quality{
			PathResolution: events.PathNotApplicable,
			Attribution:    events.AttributionNotApplicable,
		},
		Data: data,
	}
	if _, err := s.append(ctx, env, false); err != nil {
		return errors.Join(cause, fmt.Errorf("record health event %s: %w", kind, err))
	}
	return cause
}

func sameScope(bound sql.NullString, vm *string) bool {
	if !bound.Valid {
		return vm == nil
	}
	return vm != nil && bound.String == *vm
}

func nullable(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}
