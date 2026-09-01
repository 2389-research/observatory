// ABOUTME: Tests for the spool importer: at-least-once delivery, dedup, cursor
// ABOUTME: durability, prune protocol, and recovery-gap ingress. TDD — all RED first.
package spool_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/events"
	"github.com/2389-research/observatory-v2/internal/spool"
	"github.com/2389-research/observatory-v2/internal/store"
)

// openTestStore creates a real SQLite store in a temp file, returning it and a
// cleanup function. The store is backed by a fresh database every call.
func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// makeSpoolEnvelope builds a minimal valid envelope for spool tests.
// Unlike makeEnvelope, it uses host_observed provenance so it can be
// appended through the trusted importer path without a kind mismatch.
// The kind "vm.state_changed" is pre-registered, host_observed.
func makeSpoolEnvelope(vmID, instanceID, seq string) *events.Envelope {
	vid := vmID
	return &events.Envelope{
		SchemaVersion:    1,
		VMID:             &vid,
		SourceInstanceID: instanceID,
		SourceSeq:        seq,
		Kind:             "vm.state_changed",
		Provenance:       events.HostObserved,
		Sensor:           "runner",
		HostReceivedAt:   events.Timestamp{Time: time.Now().UTC()},
		Quality: events.Quality{
			PathResolution: events.PathNotApplicable,
			Attribution:    events.AttributionNotApplicable,
		},
		Data: map[string]any{
			"vm_id": vmID,
			"from":  "stopped",
			"to":    "starting",
		},
	}
}

// writeSegment writes a slice of envelopes into a new spool dir under root/<vmID>/,
// returning the spool dir path.
func writeSegment(t *testing.T, root, vmID string, envs []*events.Envelope, closed bool) string {
	t.Helper()
	spoolDir := filepath.Join(root, vmID)
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatalf("mkdir spool dir: %v", err)
	}
	w, err := spool.OpenWriter(spoolDir, spool.WriterCfg{
		VMID:            vmID,
		InstanceID:      "inst-1",
		MaxSegmentBytes: 4 * 1024 * 1024,
		MaxSpoolBytes:   64 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("OpenWriter: %v", err)
	}
	for _, env := range envs {
		if err := w.Append(env); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if closed {
		if err := w.Close(); err != nil {
			t.Fatalf("Writer.Close: %v", err)
		}
	}
	return spoolDir
}

// countEvents returns the number of events in the store matching a given
// source_instance_id by fetching from the store's query API.
func countEvents(t *testing.T, st *store.Store, instanceID string) int {
	t.Helper()
	ctx := context.Background()
	result, err := st.Query(ctx, store.Query{
		Limit: 1000,
	})
	if err != nil {
		t.Fatalf("store.Query: %v", err)
	}
	count := 0
	for _, env := range result.Events {
		if env.SourceInstanceID == instanceID {
			count++
		}
	}
	return count
}

// TestImportTwoSegments — §12.4 at-least-once transport, deduplicated storage.
// Write 2 segments with 3 envelopes each, import once, assert all 6 land.
func TestImportTwoSegments(t *testing.T) {
	st := openTestStore(t)
	root := t.TempDir()

	vmID := "11111111-1111-1111-1111-111111111111"
	instanceID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

	spoolDir := filepath.Join(root, vmID)
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Write segment 0: 3 envelopes, closed.
	w0, err := spool.OpenWriter(spoolDir, spool.WriterCfg{
		VMID: vmID, InstanceID: instanceID,
		MaxSegmentBytes: 512, MaxSpoolBytes: 64 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("OpenWriter seg0: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := w0.Append(makeSpoolEnvelope(vmID, instanceID, fmt.Sprintf("%d", i))); err != nil {
			t.Fatalf("Append seg0[%d]: %v", i, err)
		}
	}
	if err := w0.Close(); err != nil {
		t.Fatalf("Close seg0: %v", err)
	}

	// Write segment 1: 3 more envelopes, closed.
	w1, err := spool.OpenWriter(spoolDir, spool.WriterCfg{
		VMID: vmID, InstanceID: instanceID,
		MaxSegmentBytes: 512, MaxSpoolBytes: 64 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("OpenWriter seg1: %v", err)
	}
	for i := 3; i < 6; i++ {
		if err := w1.Append(makeSpoolEnvelope(vmID, instanceID, fmt.Sprintf("%d", i))); err != nil {
			t.Fatalf("Append seg1[%d]: %v", i, err)
		}
	}
	if err := w1.Close(); err != nil {
		t.Fatalf("Close seg1: %v", err)
	}

	imp := spool.NewImporter(st, root, time.Second)
	stats, err := imp.ImportOnce(context.Background())
	if err != nil {
		t.Fatalf("ImportOnce: %v", err)
	}
	if stats.Appended != 6 {
		t.Errorf("Appended: want 6, got %d", stats.Appended)
	}
	if stats.Deduped != 0 {
		t.Errorf("Deduped: want 0, got %d", stats.Deduped)
	}
	if countEvents(t, st, instanceID) != 6 {
		t.Errorf("store: want 6 events from instanceID, got %d", countEvents(t, st, instanceID))
	}
}

// TestImportDedup — §12.4 at-least-once transport, deduplicated storage.
// Re-run ImportOnce on an already-imported spool; Deduped should equal Appended
// from the first run, Appended should be 0.
// We use an open (non-closed) segment so the segment is not pruned after the first
// import, allowing the second import to see the same records and deduplicate them.
func TestImportDedup(t *testing.T) {
	st := openTestStore(t)
	root := t.TempDir()

	vmID := "22222222-2222-2222-2222-222222222222"
	instanceID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	envs := make([]*events.Envelope, 4)
	for i := range envs {
		envs[i] = makeSpoolEnvelope(vmID, instanceID, fmt.Sprintf("%d", i))
	}
	// open=false would prune the segment after first import; use open=true (no end-marker)
	// so the segment persists for the second import to iterate and deduplicate.
	writeSegment(t, root, vmID, envs, false /* open — no end-marker, not prunable */)

	imp := spool.NewImporter(st, root, time.Second)

	// First import.
	stats1, err := imp.ImportOnce(context.Background())
	if err != nil {
		t.Fatalf("ImportOnce (first): %v", err)
	}
	if stats1.Appended != 4 {
		t.Errorf("first import Appended: want 4, got %d", stats1.Appended)
	}
	if stats1.Pruned != 0 {
		t.Errorf("first import Pruned: want 0 (open segment), got %d", stats1.Pruned)
	}

	// Second import: must be all dedup, zero new appended.
	// The cursor points to record 3 (0-based); re-reading the same 4 records
	// counts them as Deduped (cursor-skipped = already committed).
	stats2, err := imp.ImportOnce(context.Background())
	if err != nil {
		t.Fatalf("ImportOnce (second): %v", err)
	}
	if stats2.Appended != 0 {
		t.Errorf("second import Appended: want 0, got %d", stats2.Appended)
	}
	if stats2.Deduped != 4 {
		t.Errorf("second import Deduped: want 4, got %d", stats2.Deduped)
	}
}

// TestCrashBetweenBatchAndCursor — kill between batch commit and cursor write.
// The test deletes cursor.json after a completed import, simulating a crash
// between the store commit and the cursor fsync. Re-importing must deduplicate
// all records without double-counting.
// We use an open segment (no end-marker) so the segment file persists after the
// first import and is available for re-import when cursor.json is removed.
func TestCrashBetweenBatchAndCursor(t *testing.T) {
	st := openTestStore(t)
	root := t.TempDir()

	vmID := "33333333-3333-3333-3333-333333333333"
	instanceID := "cccccccc-cccc-cccc-cccc-cccccccccccc"

	envs := make([]*events.Envelope, 5)
	for i := range envs {
		envs[i] = makeSpoolEnvelope(vmID, instanceID, fmt.Sprintf("%d", i))
	}
	// Open (no end-marker) so the segment is not pruned after the first import.
	writeSegment(t, root, vmID, envs, false)

	imp := spool.NewImporter(st, root, time.Second)

	// First import: succeeds; all 5 records land in the store.
	stats1, err := imp.ImportOnce(context.Background())
	if err != nil {
		t.Fatalf("ImportOnce (first): %v", err)
	}
	if stats1.Appended != 5 {
		t.Errorf("first import Appended: want 5, got %d", stats1.Appended)
	}
	if stats1.Pruned != 0 {
		t.Errorf("first import Pruned: want 0, got %d", stats1.Pruned)
	}

	// Simulate crash: delete cursor.json. Store still has all 5 events.
	cursorPath := filepath.Join(root, vmID, "cursor.json")
	if err := os.Remove(cursorPath); err != nil {
		t.Fatalf("remove cursor.json: %v", err)
	}

	// Re-import without cursor: the store's dedup keyed on (source_instance_id,
	// source_seq) absorbs all 5 re-appended records. Nothing new is added.
	stats2, err := imp.ImportOnce(context.Background())
	if err != nil {
		t.Fatalf("ImportOnce (after cursor delete): %v", err)
	}
	if stats2.Appended != 0 {
		t.Errorf("replay Appended: want 0, got %d", stats2.Appended)
	}
	if stats2.Deduped != 5 {
		t.Errorf("replay Deduped: want 5, got %d", stats2.Deduped)
	}
	// Total events in store must remain 5 (no duplicates).
	if countEvents(t, st, instanceID) != 5 {
		t.Errorf("store: want 5 events, got %d", countEvents(t, st, instanceID))
	}
}

// TestPruneAfterEndMarkerAndCursor — prune only after end marker + cursor past.
// Write a closed segment, import it, assert it is pruned.
// Write an open (no end-marker) segment; it must NOT be pruned even when cursor-past.
func TestPruneAfterEndMarkerAndCursor(t *testing.T) {
	st := openTestStore(t)
	root := t.TempDir()

	vmID := "44444444-4444-4444-4444-444444444444"
	instanceID := "dddddddd-dddd-dddd-dddd-dddddddddddd"

	// Closed segment: should be pruned after import.
	envs := make([]*events.Envelope, 3)
	for i := range envs {
		envs[i] = makeSpoolEnvelope(vmID, instanceID, fmt.Sprintf("%d", i))
	}
	writeSegment(t, root, vmID, envs, true)

	imp := spool.NewImporter(st, root, time.Second)
	stats, err := imp.ImportOnce(context.Background())
	if err != nil {
		t.Fatalf("ImportOnce: %v", err)
	}
	if stats.Pruned != 1 {
		t.Errorf("Pruned: want 1, got %d", stats.Pruned)
	}

	// The closed segment file must be gone.
	segs, _ := filepath.Glob(filepath.Join(root, vmID, "seg-*.vmsp"))
	if len(segs) != 0 {
		t.Errorf("expected 0 segments after prune, found %d: %v", len(segs), segs)
	}

	// Now write an open segment (crash simulation — no end marker).
	instanceID2 := "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
	vmID2 := "55555555-5555-5555-5555-555555555555"
	envs2 := []*events.Envelope{makeSpoolEnvelope(vmID2, instanceID2, "0")}
	writeSegment(t, root, vmID2, envs2, false /* not closed */)

	imp2 := spool.NewImporter(st, root, time.Second)
	stats2, err := imp2.ImportOnce(context.Background())
	if err != nil {
		t.Fatalf("ImportOnce (open seg): %v", err)
	}
	// Open segment: Recover truncates the tail if needed, but no end-marker → not prunable.
	if stats2.Pruned != 0 {
		t.Errorf("open segment: Pruned want 0, got %d", stats2.Pruned)
	}
	segs2, _ := filepath.Glob(filepath.Join(root, vmID2, "seg-*.vmsp"))
	if len(segs2) == 0 {
		t.Error("open segment was pruned but should not have been")
	}
}

// TestRegistryKinds — all four new kinds are in the registry with correct
// provenance, family, sensor, and schema_version.
func TestRegistryKinds(t *testing.T) {
	cases := []struct {
		kind       string
		family     string
		provenance events.Provenance
	}{
		{"guest.channel_established", "guest", events.HostObserved},
		{"guest.channel_lost", "guest", events.HostObserved},
		{"vm.vmm_exited", "vm", events.HostObserved},
		{"spool.recovery_gap", "spool", events.HostObserved},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			info, ok := events.LookupKind(tc.kind)
			if !ok {
				t.Fatalf("kind %q not registered", tc.kind)
			}
			if info.Family != tc.family {
				t.Errorf("family: want %q, got %q", tc.family, info.Family)
			}
			if info.Provenance != tc.provenance {
				t.Errorf("provenance: want %q, got %q", tc.provenance, info.Provenance)
			}
			if info.SchemaVersion != 1 {
				t.Errorf("schema_version: want 1, got %d", info.SchemaVersion)
			}
			if info.Semantics == "" {
				t.Error("semantics must not be empty")
			}
		})
	}
}

// TestEmptyRoot — ImportOnce on a root with no VM dirs returns zero stats without error.
func TestEmptyRoot(t *testing.T) {
	st := openTestStore(t)
	root := t.TempDir()

	imp := spool.NewImporter(st, root, time.Second)
	stats, err := imp.ImportOnce(context.Background())
	if err != nil {
		t.Fatalf("ImportOnce on empty root: %v", err)
	}
	if stats.Appended != 0 || stats.Deduped != 0 || stats.Pruned != 0 {
		t.Errorf("want zero stats on empty root, got %+v", stats)
	}
}

// TestRunLoopCancellation — Run(ctx) returns when context is cancelled,
// and the return value satisfies errors.Is(err, context.Canceled).
func TestRunLoopCancellation(t *testing.T) {
	st := openTestStore(t)
	root := t.TempDir()

	imp := spool.NewImporter(st, root, 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- imp.Run(ctx) }()

	cancel()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned non-cancel error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Run did not return after ctx cancel")
	}
}

// TestGapEnvelopeIngress — when Recover emits a GapEmitted envelope (interior
// corruption), the importer appends it to the store as a spool.recovery_gap event.
func TestGapEnvelopeIngress(t *testing.T) {
	st := openTestStore(t)
	root := t.TempDir()

	vmID := "66666666-6666-6666-6666-666666666666"

	// Build a segment with interior corruption: write header + valid record +
	// corrupt bytes to simulate an interior bad record.
	spoolDir := filepath.Join(root, vmID)
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Write one valid record so the segment is non-empty.
	instanceID := "ffffffff-ffff-ffff-ffff-ffffffffffff"
	w, err := spool.OpenWriter(spoolDir, spool.WriterCfg{
		VMID: vmID, InstanceID: instanceID,
		MaxSegmentBytes: 4 * 1024 * 1024, MaxSpoolBytes: 64 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("OpenWriter: %v", err)
	}
	_ = w.Append(makeSpoolEnvelope(vmID, instanceID, "0"))
	// Do NOT call Close — leave open (Recover will handle the tail).

	// Manually inject a bad record to simulate interior corruption.
	// Find the segment file and flip bytes to create a corrupt interior record.
	segs, _ := filepath.Glob(filepath.Join(spoolDir, "seg-*.vmsp"))
	if len(segs) == 0 {
		t.Fatal("no segment found")
	}

	// Read raw, find first record body, flip it to corrupt the CRC.
	raw, err := os.ReadFile(segs[0])
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// Find header end.
	headerEnd := -1
	for i, b := range raw {
		if b == '\n' {
			headerEnd = i
			break
		}
	}
	if headerEnd < 0 {
		t.Fatal("no newline in segment")
	}
	// Flip a byte inside the body (past len+crc = 8 bytes).
	flipAt := headerEnd + 1 + 8
	if flipAt < len(raw) {
		raw[flipAt] ^= 0xFF
		if err := os.WriteFile(segs[0], raw, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	imp := spool.NewImporter(st, root, time.Second)
	stats, err := imp.ImportOnce(context.Background())
	if err != nil {
		t.Fatalf("ImportOnce with corrupt segment: %v", err)
	}
	// The gap envelope must have been appended.
	_ = stats

	// Query all events and find a spool.recovery_gap.
	ctx := context.Background()
	result, err := st.Query(ctx, store.Query{Limit: 100})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	found := false
	for _, env := range result.Events {
		if env.Kind == "spool.recovery_gap" {
			found = true
			break
		}
	}
	if !found {
		// Unmarshal each envelope's raw JSON to confirm the kind.
		var kinds []string
		for _, env := range result.Events {
			kinds = append(kinds, env.Kind)
		}
		t.Errorf("spool.recovery_gap not found in store; found kinds: %v", kinds)
	}
}

// corruptSegment flips a byte inside the first record body of segPath,
// turning the record into an interior corrupt record (CRC mismatch).
// The segment must have at least one written record.
func corruptSegment(t *testing.T, segPath string) {
	t.Helper()
	raw, err := os.ReadFile(segPath)
	if err != nil {
		t.Fatalf("corruptSegment ReadFile %s: %v", segPath, err)
	}
	// Find header end (first '\n').
	headerEnd := -1
	for i, b := range raw {
		if b == '\n' {
			headerEnd = i
			break
		}
	}
	if headerEnd < 0 {
		t.Fatalf("corruptSegment: no newline in %s", segPath)
	}
	// Flip a byte at offset 8 past header end (inside record body, past len+crc).
	flipAt := headerEnd + 1 + 8
	if flipAt >= len(raw) {
		t.Fatalf("corruptSegment: segment too short to flip: len=%d flipAt=%d", len(raw), flipAt)
	}
	raw[flipAt] ^= 0xFF
	if err := os.WriteFile(segPath, raw, 0o600); err != nil {
		t.Fatalf("corruptSegment WriteFile %s: %v", segPath, err)
	}
}

// TestTwoCorruptSegmentsTwoGaps — two corrupt segments produce two Gaps with
// distinct (source_instance_id, source_seq); second ImportOnce dedups both.
func TestTwoCorruptSegmentsTwoGaps(t *testing.T) {
	st := openTestStore(t)
	root := t.TempDir()

	vmID := "88888888-8888-8888-8888-888888888888"
	spoolDir := filepath.Join(root, vmID)
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	instanceID := "aaaaaaaa-aaaa-4444-bbbb-aaaaaaaaaaaa"

	// Write two separate segments. Use large MaxSegmentBytes so no rotation
	// occurs inside a single writer session — each Open/Close pair produces
	// exactly one segment file with one record.
	w0, err := spool.OpenWriter(spoolDir, spool.WriterCfg{
		VMID: vmID, InstanceID: instanceID,
		MaxSegmentBytes: 4 * 1024 * 1024, MaxSpoolBytes: 64 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("OpenWriter seg0: %v", err)
	}
	if err := w0.Append(makeSpoolEnvelope(vmID, instanceID, "100")); err != nil {
		t.Fatalf("Append seg0: %v", err)
	}
	if err := w0.Close(); err != nil {
		t.Fatalf("Close seg0: %v", err)
	}

	// seg0 now has header + 1 record + end-marker.
	segsAfterFirst, _ := filepath.Glob(filepath.Join(spoolDir, "seg-*.vmsp"))
	if len(segsAfterFirst) != 1 {
		t.Fatalf("expected 1 segment after first write, got %d: %v", len(segsAfterFirst), segsAfterFirst)
	}
	seg0Path := segsAfterFirst[0]
	corruptSegment(t, seg0Path)

	// Open a second writer — nextSegmentIndex advances to idx 1.
	w1, err := spool.OpenWriter(spoolDir, spool.WriterCfg{
		VMID: vmID, InstanceID: instanceID,
		MaxSegmentBytes: 4 * 1024 * 1024, MaxSpoolBytes: 64 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("OpenWriter seg1: %v", err)
	}
	if err := w1.Append(makeSpoolEnvelope(vmID, instanceID, "200")); err != nil {
		t.Fatalf("Append seg1: %v", err)
	}
	if err := w1.Close(); err != nil {
		t.Fatalf("Close seg1: %v", err)
	}

	// Find seg1 (the new one).
	allSegs, _ := filepath.Glob(filepath.Join(spoolDir, "seg-*.vmsp"))
	if len(allSegs) != 2 {
		t.Fatalf("expected 2 segments, got %d: %v", len(allSegs), allSegs)
	}
	var seg1Path string
	for _, s := range allSegs {
		if s != seg0Path {
			seg1Path = s
			break
		}
	}
	if seg1Path == "" {
		t.Fatal("could not identify seg1")
	}
	corruptSegment(t, seg1Path)

	// Verify Recover returns two Gaps.
	report, err := spool.Recover(spoolDir)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if len(report.Gaps) != 2 {
		t.Fatalf("Recover: want 2 Gaps, got %d", len(report.Gaps))
	}

	// The two Gaps must have distinct (source_instance_id, source_seq) pairs.
	key0 := report.Gaps[0].SourceInstanceID + "/" + report.Gaps[0].SourceSeq
	key1 := report.Gaps[1].SourceInstanceID + "/" + report.Gaps[1].SourceSeq
	if key0 == key1 {
		t.Errorf("gaps have same dedup key %q — identity collapses", key0)
	}

	// Both gaps must have non-empty UUIDs in SourceInstanceID.
	for i, g := range report.Gaps {
		if len(g.SourceInstanceID) != 36 {
			t.Errorf("gap[%d].SourceInstanceID not UUID-shaped: %q", i, g.SourceInstanceID)
		}
		if g.SourceSeq == "" {
			t.Errorf("gap[%d].SourceSeq is empty", i)
		}
	}

	// First ImportOnce: both gap records land.
	imp := spool.NewImporter(st, root, time.Second)
	stats1, err := imp.ImportOnce(context.Background())
	if err != nil {
		t.Fatalf("ImportOnce (first): %v", err)
	}

	// Count gap records in store.
	ctx := context.Background()
	res, err := st.Query(ctx, store.Query{Limit: 100})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	var gapEnvs []*events.Envelope
	for _, ev := range res.Events {
		if ev.Kind == "spool.recovery_gap" {
			gapEnvs = append(gapEnvs, ev)
		}
	}
	if len(gapEnvs) != 2 {
		t.Fatalf("store: want 2 gap records, got %d (Appended=%d, Deduped=%d)",
			len(gapEnvs), stats1.Appended, stats1.Deduped)
	}

	// The two store-side gaps must also have distinct (source_instance_id, source_seq).
	storeKey0 := gapEnvs[0].SourceInstanceID + "/" + gapEnvs[0].SourceSeq
	storeKey1 := gapEnvs[1].SourceInstanceID + "/" + gapEnvs[1].SourceSeq
	if storeKey0 == storeKey1 {
		t.Errorf("store gap records share dedup key %q", storeKey0)
	}

	// Second ImportOnce: both must dedup, no new appended.
	stats2, err := imp.ImportOnce(context.Background())
	if err != nil {
		t.Fatalf("ImportOnce (second): %v", err)
	}
	if stats2.Appended != 0 {
		t.Errorf("second import: want 0 Appended, got %d", stats2.Appended)
	}
	// At least the two gaps must be deduped.
	if stats2.Deduped < 2 {
		t.Errorf("second import: want >=2 Deduped (the two gaps), got %d", stats2.Deduped)
	}
}

// TestCorruptSegmentWithEndMarkerNotPruned — a corrupt interior segment that
// carries a clean end marker must NOT be pruned by ImportOnce when the cursor
// is past it. Evidence must survive on disk across multiple import cycles.
//
// The key RED: with the old countSegmentRecords bug (returns partial count
// instead of -1 on iterator error), the PAST-branch prune guard
// (n >= 0 && segmentHasEndMarker) fires on the SECOND cycle — destroying the
// corrupt segment. After the fix (return -1 on any non-EOF iterator error),
// n == -1 makes the guard false and the segment survives.
func TestCorruptSegmentWithEndMarkerNotPruned(t *testing.T) {
	st := openTestStore(t)
	root := t.TempDir()

	vmID := "99999999-9999-9999-9999-999999999999"
	spoolDir := filepath.Join(root, vmID)
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	instanceID := "cccccccc-dddd-4444-eeee-cccccccccccc"

	// Write segment 0 with one valid record and a clean close (end marker).
	// Large MaxSegmentBytes avoids rotation — one record lands in seg0.
	w0, err := spool.OpenWriter(spoolDir, spool.WriterCfg{
		VMID: vmID, InstanceID: instanceID,
		MaxSegmentBytes: 4 * 1024 * 1024, MaxSpoolBytes: 64 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("OpenWriter seg0: %v", err)
	}
	if err := w0.Append(makeSpoolEnvelope(vmID, instanceID, "0")); err != nil {
		t.Fatalf("Append seg0: %v", err)
	}
	if err := w0.Close(); err != nil {
		t.Fatalf("Close seg0: %v", err)
	}

	// Locate and corrupt seg0 AFTER close (so the end marker is in place).
	segs0, _ := filepath.Glob(filepath.Join(spoolDir, "seg-*.vmsp"))
	if len(segs0) != 1 {
		t.Fatalf("expected 1 segment after close, got %d: %v", len(segs0), segs0)
	}
	seg0Path := segs0[0]
	corruptSegment(t, seg0Path)

	// Write segment 1 with one valid record and import it cleanly so the cursor
	// advances past seg0.
	w1, err := spool.OpenWriter(spoolDir, spool.WriterCfg{
		VMID: vmID, InstanceID: instanceID,
		MaxSegmentBytes: 4 * 1024 * 1024, MaxSpoolBytes: 64 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("OpenWriter seg1: %v", err)
	}
	if err := w1.Append(makeSpoolEnvelope(vmID, instanceID, "1")); err != nil {
		t.Fatalf("Append seg1: %v", err)
	}
	if err := w1.Close(); err != nil {
		t.Fatalf("Close seg1: %v", err)
	}

	imp := spool.NewImporter(st, root, time.Second)

	// Cycle 1: cursor advances past seg1. seg0 is FUTURE (cursor empty) here —
	// the bug does not fire yet.
	_, err = imp.ImportOnce(context.Background())
	if err != nil {
		t.Fatalf("ImportOnce cycle 1: %v", err)
	}

	// seg0 must survive cycle 1.
	if _, err := os.Stat(seg0Path); os.IsNotExist(err) {
		t.Error("corrupt segment with end marker was pruned on cycle 1 — must survive as evidence")
	}

	// Cycle 2: seg0 is now PAST (cursor points into seg1). This is where the
	// prune bug fires — countSegmentRecords returns n>=0 (partial count before
	// error) instead of -1, so the n>=0 && hasEndMarker guard is satisfied and
	// the segment gets deleted. After fix, n==-1, guard is false, file survives.
	_, err = imp.ImportOnce(context.Background())
	if err != nil {
		t.Fatalf("ImportOnce cycle 2: %v", err)
	}

	// seg0 must survive cycle 2 — corrupt evidence is never pruned (R8).
	if _, err := os.Stat(seg0Path); os.IsNotExist(err) {
		t.Error("corrupt segment with end marker was pruned on cycle 2 — violates R8 evidence-retention invariant")
	}
}

// TestImportOnceSwallowsPerVMErrors — ImportOnce returns nil when one VM dir
// is broken and another is healthy. Healthy records must land in the store;
// stats must reflect only the healthy dir.
//
// We make one dir unreadable by planting a cursor.json that is itself a
// directory (not a file): loadCursor handles the read error gracefully, but
// any subsequent segment open fails because the dir itself is chmod 000.
// Using a 000-mode dir is portable and deterministic across Linux/macOS.
func TestImportOnceSwallowsPerVMErrors(t *testing.T) {
	st := openTestStore(t)
	root := t.TempDir()

	// Healthy VM: one closed segment with two records.
	healthyVMID := "aaaabbbb-cccc-dddd-eeee-ffffffff0001"
	healthyInstance := "11112222-3333-4444-5555-666677778888"
	envs := []*events.Envelope{
		makeSpoolEnvelope(healthyVMID, healthyInstance, "0"),
		makeSpoolEnvelope(healthyVMID, healthyInstance, "1"),
	}
	writeSegment(t, root, healthyVMID, envs, true /* closed */)

	// Broken VM: a directory that is chmod 000 so Recover / ReadDir fail.
	brokenVMID := "bbbbcccc-dddd-eeee-ffff-000011112222"
	brokenDir := filepath.Join(root, brokenVMID)
	if err := os.MkdirAll(brokenDir, 0o700); err != nil {
		t.Fatalf("mkdir broken dir: %v", err)
	}
	// Plant a segment file first so there's something to fail on, then lock the dir.
	// Actually, chmod 000 on the dir itself makes ReadDir inside Recover fail,
	// which causes importVM to return an error — exactly the swallow path.
	if err := os.Chmod(brokenDir, 0o000); err != nil {
		t.Fatalf("chmod broken dir: %v", err)
	}
	// Restore permissions at test end so t.TempDir cleanup works.
	t.Cleanup(func() { _ = os.Chmod(brokenDir, 0o700) })

	imp := spool.NewImporter(st, root, time.Second)
	stats, err := imp.ImportOnce(context.Background())

	// Must return nil — per-VM errors are swallowed.
	if err != nil {
		t.Fatalf("ImportOnce: want nil error, got: %v", err)
	}

	// Healthy records must have landed.
	if stats.Appended != 2 {
		t.Errorf("Appended: want 2 (from healthy dir), got %d", stats.Appended)
	}
	if stats.Deduped != 0 {
		t.Errorf("Deduped: want 0, got %d", stats.Deduped)
	}

	// Store must contain exactly the two healthy records.
	if got := countEvents(t, st, healthyInstance); got != 2 {
		t.Errorf("store: want 2 events from healthy instance, got %d", got)
	}
}

// TestDriftedGapMtimeDoesNotWedge — a gap envelope already in the store whose
// payload hash drifts (because the corrupt segment's mtime changed) must not
// block Step 4 real-event import. The second ImportOnce must succeed, count
// the gap as Deduped, and still import any healthy later segments.
//
// Scenario:
//  1. Write a corrupt segment (seg0) + a clean closed segment (seg1, one record).
//  2. ImportOnce — gap recorded, seg1's record lands (Appended ≥ 1).
//  3. Touch seg0's mtime — simulates backup/rsync metadata drift.
//  4. ImportOnce again — must return nil, gap counted Deduped, Appended == 0
//     (seg1 was pruned after step 2; its record is already in the store, so
//     nothing new arrives, but the import must not error).
func TestDriftedGapMtimeDoesNotWedge(t *testing.T) {
	st := openTestStore(t)
	root := t.TempDir()

	vmID := "aaaaaaaa-bbbb-4444-cccc-dddddddddddd"
	spoolDir := filepath.Join(root, vmID)
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	instanceID := "11111111-2222-4444-3333-444444444444"

	// Write seg0: one record, then corrupt its interior so Recover emits a gap.
	w0, err := spool.OpenWriter(spoolDir, spool.WriterCfg{
		VMID: vmID, InstanceID: instanceID,
		MaxSegmentBytes: 4 * 1024 * 1024, MaxSpoolBytes: 64 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("OpenWriter seg0: %v", err)
	}
	if err := w0.Append(makeSpoolEnvelope(vmID, instanceID, "0")); err != nil {
		t.Fatalf("Append seg0: %v", err)
	}
	if err := w0.Close(); err != nil {
		t.Fatalf("Close seg0: %v", err)
	}
	segs0, _ := filepath.Glob(filepath.Join(spoolDir, "seg-*.vmsp"))
	if len(segs0) != 1 {
		t.Fatalf("expected 1 segment, got %d", len(segs0))
	}
	seg0Path := segs0[0]
	corruptSegment(t, seg0Path)

	// Write seg1: one clean record, closed — so it is prunable after import.
	instanceID2 := "55555555-6666-4444-7777-888888888888"
	w1, err := spool.OpenWriter(spoolDir, spool.WriterCfg{
		VMID: vmID, InstanceID: instanceID2,
		MaxSegmentBytes: 4 * 1024 * 1024, MaxSpoolBytes: 64 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("OpenWriter seg1: %v", err)
	}
	if err := w1.Append(makeSpoolEnvelope(vmID, instanceID2, "0")); err != nil {
		t.Fatalf("Append seg1: %v", err)
	}
	if err := w1.Close(); err != nil {
		t.Fatalf("Close seg1: %v", err)
	}

	imp := spool.NewImporter(st, root, time.Second)

	// First import: gap recorded, seg1's record lands.
	stats1, err := imp.ImportOnce(context.Background())
	if err != nil {
		t.Fatalf("ImportOnce (first): %v", err)
	}
	// seg1 has a clean record that must have landed.
	if stats1.Appended == 0 {
		t.Fatalf("first import: Appended want >0, got 0 (seg1 record must land)")
	}

	// Drift the corrupt segment's mtime — simulates backup/rsync touching metadata.
	driftTime := time.Now().Add(-72 * time.Hour)
	if err := os.Chtimes(seg0Path, driftTime, driftTime); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	// Second import: must not error. The gap's stored payload now has a different
	// mtime-derived hash, but ErrIntegrityFailure must be treated as Deduped, not fatal.
	stats2, err := imp.ImportOnce(context.Background())
	if err != nil {
		t.Fatalf("ImportOnce (second, after mtime drift): %v", err)
	}
	// The gap collision must register as Deduped, not ignored silently.
	if stats2.Deduped == 0 {
		t.Errorf("second import: Deduped want >0 (drifted gap must count), got 0")
	}
	// No new appended records — everything is already in the store.
	if stats2.Appended != 0 {
		t.Errorf("second import: Appended want 0, got %d", stats2.Appended)
	}
}

// TestCursorIsWrittenAtomically — cursor.json must be a valid JSON file
// after ImportOnce returns (tempfile+rename guarantees this).
func TestCursorIsWrittenAtomically(t *testing.T) {
	st := openTestStore(t)
	root := t.TempDir()

	vmID := "77777777-7777-7777-7777-777777777777"
	instanceID := "aaaabbbb-cccc-dddd-eeee-ffffffffffff"

	envs := []*events.Envelope{makeSpoolEnvelope(vmID, instanceID, "0")}
	writeSegment(t, root, vmID, envs, true)

	imp := spool.NewImporter(st, root, time.Second)
	if _, err := imp.ImportOnce(context.Background()); err != nil {
		t.Fatalf("ImportOnce: %v", err)
	}

	cursorPath := filepath.Join(root, vmID, "cursor.json")
	data, err := os.ReadFile(cursorPath)
	if err != nil {
		t.Fatalf("read cursor.json: %v", err)
	}

	var cursor struct {
		Segment string `json:"segment"`
		Record  int    `json:"record"`
	}
	if err := json.Unmarshal(data, &cursor); err != nil {
		t.Fatalf("cursor.json is not valid JSON: %v\ncontent: %s", err, data)
	}
	if cursor.Segment == "" {
		t.Error("cursor.json segment field is empty")
	}
	if cursor.Record < 0 {
		t.Errorf("cursor.json record field is negative: %d", cursor.Record)
	}
}
