// ABOUTME: Host-side spool importer: walks per-VM spool dirs, imports envelopes
// ABOUTME: into the store with commit-then-cursor-then-prune ordering (SPEC §12.4).
package spool

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/2389-research/observatory/internal/events"
	"github.com/2389-research/observatory/internal/store"
)

// ImportStats reports what one ImportOnce cycle did.
type ImportStats struct {
	Appended int // envelopes newly written to the store
	Deduped  int // envelopes already present (at-least-once idempotence)
	Pruned   int // segment files removed after full commit + cursor advancement
}

// cursor is the on-disk cursor.json structure.
// segment is the base filename (e.g. "seg-0000000000000000.vmsp").
// record is the zero-based index of the last fully-committed record in that segment.
type cursor struct {
	Segment string `json:"segment"`
	Record  int    `json:"record"`
}

// Importer walks per-VM spool dirs under root and imports envelopes into st.
type Importer struct {
	mu            sync.RWMutex // protects health snapshots read by HTTP handlers
	cycleMu       sync.Mutex   // serializes manual and background cycles
	health        map[string]importHealth
	reportFailure func(context.Context, string, ImportStatus) error
	st            *store.Store
	root          string
	interval      time.Duration
	onImported    func(*events.Envelope) // called per newly-appended envelope; may be nil
}

// NewImporter constructs an Importer that polls root every interval.
// onImported is called for each envelope that is newly appended to the store
// (not deduped). Pass nil to omit the callback. The callback fires synchronously
// in the import loop and must not block for long.
func NewImporter(st *store.Store, root string, interval time.Duration, onImported func(*events.Envelope)) *Importer {
	if interval <= 0 {
		interval = time.Second
	}
	return &Importer{health: make(map[string]importHealth), st: st, root: root, interval: interval, onImported: onImported}
}

// Run calls ImportOnce every interval until ctx is done.
// Per-cycle failures are recorded in health and coalesced attention; one VM
// never delays another VM by sleeping during its retry backoff.
// Run returns ctx.Err() when the context is cancelled or expired.
func (imp *Importer) Run(ctx context.Context) error {
	ticker := time.NewTicker(imp.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// Health retains failures even if the store cannot record attention.
			_, _ = imp.importOnce(ctx, true)
		}
	}
}

// ImportOnce runs one full import cycle across all VM dirs under root.
// For each VM dir it:
//  1. Calls spool.Recover to repair truncated tails and detect gaps.
//  2. Iterates Recover's reported segments in order.
//  3. Appends the GapEmitted envelope (if any) to the store.
//  4. Imports records from each segment, skipping those already past the cursor.
//  5. Writes cursor.json atomically after each segment's batch commits.
//  6. Prunes fully-committed closed segments.
func (imp *Importer) ImportOnce(ctx context.Context) (ImportStats, error) {
	return imp.importOnce(ctx, false)
}

// Explicit cycles always attempt work; Run alone observes the retry schedule.
func (imp *Importer) importOnce(ctx context.Context, backoff bool) (ImportStats, error) {
	imp.cycleMu.Lock()
	defer imp.cycleMu.Unlock()
	var total ImportStats
	if err := ctx.Err(); err != nil {
		return total, err
	}
	if backoff && !imp.due("") {
		return total, nil
	}
	entries, err := os.ReadDir(imp.root)
	if err != nil {
		err = fmt.Errorf("importer: readdir %s: %w", imp.root, err)
		imp.record(ctx, "", err)
		return total, err
	}
	imp.record(ctx, "", nil)
	var firstErr error
	failed := 0
	present := map[string]bool{"": true}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		present[id] = true
		if err := ctx.Err(); err != nil {
			return total, err
		}
		if backoff && !imp.due(id) {
			continue
		}
		stats, err := imp.importVM(ctx, filepath.Join(imp.root, id))
		total.Appended += stats.Appended
		total.Deduped += stats.Deduped
		total.Pruned += stats.Pruned
		if ctx.Err() != nil {
			return total, ctx.Err()
		}
		imp.record(ctx, id, err)
		if err != nil {
			failed++
			if firstErr == nil {
				firstErr = fmt.Errorf("VM %s: %w", id, err)
			}
		}
	}
	imp.mu.Lock()
	for id := range imp.health {
		if !present[id] {
			delete(imp.health, id)
		}
	}
	imp.mu.Unlock()
	if failed > 0 {
		return total, fmt.Errorf("importer: %d VM imports failed; first: %w", failed, firstErr)
	}
	return total, nil
}

// importVM runs one cycle for a single VM spool directory.
func (imp *Importer) importVM(ctx context.Context, vmDir string) (ImportStats, error) {
	var stats ImportStats

	// Step 1: recover — repairs truncated tails, detects interior corruption.
	report, err := Recover(vmDir)
	if err != nil {
		return stats, fmt.Errorf("importer: recover %s: %w", vmDir, err)
	}
	if len(report.Segments) == 0 {
		return stats, nil
	}

	// Step 2: load cursor (absent = start of everything).
	cur, err := imp.loadCursor(vmDir)
	if err != nil {
		return stats, fmt.Errorf("importer: read cursor: %w", err)
	}

	// Step 3: if recovery detected corrupt segments, append one gap envelope per
	// segment to the store. Each envelope carries its own stable
	// (source_instance_id, source_seq) identity built by buildGapEnvelope in
	// reader.go, so distinct corruptions cannot dedup away each other.
	for _, gapEnv := range report.Gaps {
		ar, err := imp.st.Append(ctx, gapEnv)
		if err != nil {
			// ErrIntegrityFailure here means the store already holds a gap
			// envelope for this (source_instance_id, source_seq), but the
			// payload hash drifted — most likely the corrupt segment's mtime
			// changed (backup tool, rsync). The original gap is already
			// faithfully recorded; treating this as Deduped and continuing
			// prevents a permanent wedge that would block all real-event import
			// (Step 4) over a segment that is already accounted for.
			// Every other Append error still aborts the VM cycle.
			if errors.Is(err, store.ErrIntegrityFailure) {
				stats.Deduped++
				continue
			}
			return stats, fmt.Errorf("importer: append gap envelope: %w", err)
		}
		if ar.Deduped {
			stats.Deduped++
		} else {
			stats.Appended++
		}
	}

	// Step 4: iterate segments in order (Recover already sorts them).
	for _, segPath := range report.Segments {
		segName := filepath.Base(segPath)

		// Classify this segment relative to the cursor:
		//
		//   PAST:    segName < cur.Segment   → all records committed; count as Deduped + maybe prune.
		//   CURRENT: segName == cur.Segment  → records 0..cur.Record committed; resume at cur.Record+1.
		//   FUTURE:  segName > cur.Segment   → no records committed yet; start at 0.

		if cur.Segment != "" && segName < cur.Segment {
			// PAST segment: all records already committed.
			// Count readable records as Deduped; prune only when the segment is
			// readable end-to-end (countSegmentRecords >= 0) AND has the end
			// marker. A corrupt segment (countSegmentRecords == -1) is never
			// pruned — it is evidence whose last records never committed, and
			// the prune rule requires the store batch containing its last record
			// to have committed. Corrupt evidence survives on disk permanently.
			n, err := countSegmentRecords(segPath)
			if err != nil && !errors.Is(err, ErrCorruptRecord) {
				return stats, fmt.Errorf("importer: count segment %s: %w", segPath, err)
			}
			if n > 0 {
				stats.Deduped += n
			}
			closed, err := segmentHasEndMarker(segPath)
			if err != nil {
				return stats, fmt.Errorf("importer: read end marker %s: %w", segPath, err)
			}
			if n >= 0 && closed {
				if rerr := os.Remove(segPath); rerr != nil {
					return stats, fmt.Errorf("importer: prune %s: %w", segPath, rerr)
				}
				stats.Pruned++
			}
			continue
		}

		// CURRENT or FUTURE: open the iterator.
		iter, err := ReadSegment(segPath)
		if err != nil {
			return stats, fmt.Errorf("importer: read segment: %w", err)
		}

		// Records 0..resumeFrom-1 are already committed (CURRENT case).
		resumeFrom := 0
		if cur.Segment == segName {
			resumeFrom = cur.Record + 1
		}

		recIdx := 0
		reachedEOF := false // true when iter exhausted this segment (end-marker or tail)
		var importErr error

		for {
			env, nextErr := iter.Next()
			if errors.Is(nextErr, io.EOF) {
				reachedEOF = true
				break
			}
			if errors.Is(nextErr, ErrCorruptRecord) {
				// Stop at interior corruption; do not advance cursor past it.
				break
			}
			if nextErr != nil {
				importErr = nextErr
				break
			}

			if recIdx < resumeFrom {
				// Already committed: count as Deduped.
				stats.Deduped++
				recIdx++
				continue
			}

			// Append this record to the store.
			ar, appendErr := imp.st.Append(ctx, env)
			if appendErr != nil {
				importErr = appendErr
				break
			}
			if ar.Deduped {
				stats.Deduped++
			} else {
				stats.Appended++
				if imp.onImported != nil {
					imp.onImported(env)
				}
			}

			// §12.4 ordering: store committed → write cursor → then continue.
			newCur := cursor{Segment: segName, Record: recIdx}
			if writeErr := writeCursor(vmDir, newCur); writeErr != nil {
				importErr = fmt.Errorf("write cursor: %w", writeErr)
				break
			}
			cur = newCur
			recIdx++
		}
		closeErr := iter.Close()
		if importErr != nil || closeErr != nil {
			return stats, fmt.Errorf("importer: segment %s: %w", segPath, errors.Join(importErr, closeErr))
		}

		// Prune: remove segment if it had a clean end-marker and we reached EOF
		// (meaning we processed all records and cur is at the last one).
		closed, err := segmentHasEndMarker(segPath)
		if err != nil {
			return stats, fmt.Errorf("importer: read end marker %s: %w", segPath, err)
		}
		if reachedEOF && closed {
			if rerr := os.Remove(segPath); rerr != nil {
				return stats, fmt.Errorf("importer: prune %s: %w", segPath, rerr)
			}
			stats.Pruned++
		}
	}

	return stats, nil
}

// segmentHasEndMarker reads the last 4 bytes of segPath and returns true if
// they are the end-marker (0xFFFFFFFF).
func segmentHasEndMarker(segPath string) (bool, error) {
	f, err := os.Open(segPath)
	if err != nil {
		return false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	if info.Size() < 4 {
		return false, io.ErrUnexpectedEOF
	}
	var tail [4]byte
	if _, err := f.ReadAt(tail[:], info.Size()-4); err != nil {
		return false, err
	}
	return binary.BigEndian.Uint32(tail[:]) == endMarker, nil
}

// loadCursor reads durable progress. Only an absent cursor means start at zero.
func (imp *Importer) loadCursor(vmDir string) (cursor, error) {
	data, err := os.ReadFile(filepath.Join(vmDir, "cursor.json"))
	if os.IsNotExist(err) {
		return cursor{}, nil
	}
	if err != nil {
		return cursor{}, err
	}
	var c cursor
	if err := json.Unmarshal(data, &c); err != nil {
		return cursor{}, err
	}
	if c.Segment == "" || filepath.Base(c.Segment) != c.Segment || c.Record < 0 {
		return cursor{}, fmt.Errorf("invalid cursor")
	}
	return c, nil
}

// writeCursor writes cur to cursor.json in vmDir using tempfile+rename (atomic).
// The temp file is fsync'd before rename so the data is durable on-disk before
// the rename makes it visible — matching the spool writer's durability discipline.
func writeCursor(vmDir string, cur cursor) error {
	data, err := json.Marshal(cur)
	if err != nil {
		return fmt.Errorf("marshal cursor: %w", err)
	}

	tmp, err := os.CreateTemp(vmDir, "cursor-*.tmp")
	if err != nil {
		return fmt.Errorf("create cursor temp: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write cursor temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("fsync cursor temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close cursor temp: %w", err)
	}

	dest := filepath.Join(vmDir, "cursor.json")
	if err := os.Rename(tmpPath, dest); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename cursor: %w", err)
	}
	return nil
}

// countSegmentRecords counts records in a segment to know if cursor is at the end.
// Returns -1 on error.
//
// Any iterator error that is not a clean io.EOF (including ErrCorruptRecord)
// returns -1, making the PAST-branch prune guard (n >= 0 && hasEndMarker)
// false. This preserves corrupt segments as evidence on disk across all cycles
// (controller ruling R8). Accepted consequence: a corrupt PAST segment
// contributes nothing to the per-cycle Deduped stat — stats are observability,
// not evidence; retention is what matters.
func countSegmentRecords(segPath string) (int, error) {
	iter, err := ReadSegment(segPath)
	if err != nil {
		return -1, err
	}
	defer iter.Close()
	count := 0
	for {
		_, err := iter.Next()
		if errors.Is(err, io.EOF) {
			return count, nil
		}
		if err != nil {
			// Non-EOF error (including ErrCorruptRecord): signal error to caller.
			return -1, err
		}
		count++
	}
}

// Sensor is the sensor name used by this package for all emitted events.
// Exported so tests and callers can reference it.
const Sensor = "runner"
