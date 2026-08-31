// ABOUTME: SQLite-backed event store: WAL, synchronous=FULL, one logical writer
// ABOUTME: connection plus a small read-only pool, with in-code migrations.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"sync/atomic"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// migrations run in order inside one writer transaction each; version = index+1.
// event_id is INTEGER PRIMARY KEY AUTOINCREMENT: the ingestion cursor must
// never be reused, even after future retention deletes rows.
var migrations = []string{
	`CREATE TABLE events (
		event_id INTEGER PRIMARY KEY AUTOINCREMENT,
		source_instance_id TEXT NOT NULL,
		source_seq TEXT NOT NULL,
		vm_id TEXT,
		boot_id TEXT,
		kind TEXT NOT NULL,
		host_received_at TEXT NOT NULL,
		payload TEXT NOT NULL,
		payload_hash BLOB NOT NULL,
		UNIQUE (source_instance_id, source_seq)
	);
	CREATE INDEX idx_events_vm ON events (vm_id, event_id);
	CREATE INDEX idx_events_kind ON events (kind, event_id);
	CREATE TABLE streams (
		source_instance_id TEXT PRIMARY KEY,
		vm_id TEXT,
		created_at TEXT NOT NULL
	);`,
	// v2: the attention queue (a materialized view over attention.* events plus
	// ack state, SPEC §12.7), annotations, and trigger-engine cursors.
	`CREATE TABLE attention_items (
		attention_id INTEGER PRIMARY KEY AUTOINCREMENT,
		raised_event_id INTEGER NOT NULL,
		last_event_id INTEGER NOT NULL,
		vm_id TEXT,
		run_id TEXT,
		trigger_class TEXT NOT NULL,
		severity TEXT NOT NULL,
		summary TEXT NOT NULL,
		system_action TEXT NOT NULL,
		evidence_links TEXT NOT NULL,
		suggested_actions TEXT NOT NULL,
		count INTEGER NOT NULL DEFAULT 1,
		acked INTEGER NOT NULL DEFAULT 0,
		acked_at TEXT,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);
	CREATE INDEX idx_attention_open ON attention_items (acked, attention_id);
	CREATE INDEX idx_attention_collapse ON attention_items (trigger_class, vm_id) WHERE acked = 0;
	CREATE TABLE annotations (
		annotation_id INTEGER PRIMARY KEY AUTOINCREMENT,
		target_ref TEXT NOT NULL,
		author TEXT NOT NULL,
		text TEXT NOT NULL,
		tags TEXT NOT NULL,
		redacted INTEGER NOT NULL DEFAULT 0,
		redaction_policy_id TEXT,
		event_id INTEGER NOT NULL,
		created_at TEXT NOT NULL
	);
	CREATE INDEX idx_annotations_ref ON annotations (target_ref, annotation_id);
	CREATE TABLE engine_cursors (
		name TEXT PRIMARY KEY,
		cursor INTEGER NOT NULL
	);`,
}

// Store owns one SQLite database. All writes go through the writer pool, which
// holds exactly one connection: SQLite has a single writer anyway, and a
// one-connection pool turns lock contention into queueing.
type Store struct {
	path    string
	writer  *sql.DB
	readers *sql.DB
	// instanceID and systemSeq form the stream identity for events this store
	// synthesizes (health records, attention raises, annotations). A fresh
	// instance per Open is correct: dedup keys never collide across restarts.
	instanceID string
	systemSeq  atomic.Int64
}

func dsn(path string, params url.Values) string {
	u := url.URL{Scheme: "file", Path: path, RawQuery: params.Encode()}
	return u.String()
}

// Open opens (creating if needed) the database at path and applies migrations.
func Open(path string) (*Store, error) {
	writer, err := sql.Open("sqlite", dsn(path, url.Values{
		"_journal_mode": {"WAL"},
		"_synchronous":  {"FULL"},
		"_busy_timeout": {"5000"},
		"_foreign_keys": {"1"},
	}))
	if err != nil {
		return nil, fmt.Errorf("open writer: %w", err)
	}
	writer.SetMaxOpenConns(1)
	writer.SetMaxIdleConns(1)

	if err := migrate(writer); err != nil {
		writer.Close()
		return nil, err
	}

	// Readers open after the writer has created the file and set WAL (a file
	// property). _query_only makes reads incapable of writing by construction.
	readers, err := sql.Open("sqlite", dsn(path, url.Values{
		"_busy_timeout": {"5000"},
		"_query_only":   {"1"},
	}))
	if err != nil {
		writer.Close()
		return nil, fmt.Errorf("open readers: %w", err)
	}
	readers.SetMaxOpenConns(4)
	readers.SetMaxIdleConns(4)

	return &Store{
		path:       path,
		writer:     writer,
		readers:    readers,
		instanceID: uuid.NewString(),
	}, nil
}

func migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("create migrations table: %w", err)
	}
	var current int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	for i := current; i < len(migrations); i++ {
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version, applied_at)
			VALUES (?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))`, i+1); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %d: %w", i+1, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", i+1, err)
		}
	}
	return nil
}

func (s *Store) Close() error {
	rerr := s.readers.Close()
	werr := s.writer.Close()
	if werr != nil {
		return werr
	}
	return rerr
}

// Diagnostics reports the writer connection's actual durability settings, for
// honest self-description (a /meta that claims WAL should have checked).
type Diagnostics struct {
	Path        string `json:"path"`
	JournalMode string `json:"journal_mode"`
	Synchronous string `json:"synchronous"`
}

var synchronousNames = map[int]string{0: "off", 1: "normal", 2: "full", 3: "extra"}

func (s *Store) Diagnostics(ctx context.Context) (Diagnostics, error) {
	d := Diagnostics{Path: s.path}
	if err := s.writer.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&d.JournalMode); err != nil {
		return d, fmt.Errorf("read journal_mode: %w", err)
	}
	var sync int
	if err := s.writer.QueryRowContext(ctx, `PRAGMA synchronous`).Scan(&sync); err != nil {
		return d, fmt.Errorf("read synchronous: %w", err)
	}
	name, ok := synchronousNames[sync]
	if !ok {
		name = fmt.Sprintf("unknown(%d)", sync)
	}
	d.Synchronous = name
	return d, nil
}
