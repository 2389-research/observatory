// ABOUTME: Tests for Recover's newest-segment rule: the segment a live writer
// ABOUTME: may still be appending to is never opened read-write or rejected.
package spool_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/events"
	"github.com/2389-research/observatory/internal/spool"
)

// TestRecoverLeavesEmptyNewestSegmentForNextCycle covers the moment a second
// writer has just created its segment file but has not yet written the
// header line: a 0-byte file at the newest index. This is not corruption —
// the creation may still be under way — so Recover must leave the file on
// disk and exclude it from the report, while the closed segment below it
// still imports normally.
func TestRecoverLeavesEmptyNewestSegmentForNextCycle(t *testing.T) {
	st := openTestStore(t)
	root := t.TempDir()
	vmID := "33333333-3333-3333-3333-333333333333"
	instanceID := "cccccccc-cccc-cccc-cccc-cccccccccccc"

	envs := []*events.Envelope{
		makeSpoolEnvelope(vmID, instanceID, "0"),
		makeSpoolEnvelope(vmID, instanceID, "1"),
	}
	vmDir := writeSegment(t, root, vmID, envs, true /* closed */)
	seg0 := filepath.Join(vmDir, "seg-0000000000000000.vmsp")

	seg1 := filepath.Join(vmDir, "seg-0000000000000001.vmsp")
	if err := os.WriteFile(seg1, nil, 0o600); err != nil {
		t.Fatalf("create empty seg1: %v", err)
	}

	report, err := spool.Recover(vmDir)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if want := []string{seg0}; !slices.Equal(report.Segments, want) {
		t.Errorf("Segments = %v, want %v", report.Segments, want)
	}
	if _, statErr := os.Stat(seg1); statErr != nil {
		t.Errorf("empty newest segment must still exist: %v", statErr)
	}

	imp := spool.NewImporter(st, root, time.Second, nil)
	stats, err := imp.ImportOnce(context.Background())
	if err != nil {
		t.Fatalf("ImportOnce: %v", err)
	}
	if stats.Appended != 2 {
		t.Errorf("Appended = %d, want 2", stats.Appended)
	}
}

// TestRecoverRemovesTornCreationBelowNewest covers a segment below the
// newest whose header was never finished: no writer will ever come back to
// it, because a writer only ever appends to the segment it just created and
// moves on to a new one after any failure. Recover must remove it and report
// the other, valid segments.
func TestRecoverRemovesTornCreationBelowNewest(t *testing.T) {
	root := t.TempDir()
	vmID := "44444444-4444-4444-4444-444444444444"
	instanceID := "dddddddd-dddd-dddd-dddd-dddddddddddd"

	vmDir := writeSegment(t, root, vmID, []*events.Envelope{makeSpoolEnvelope(vmID, instanceID, "0")}, true /* closed */)
	seg0 := filepath.Join(vmDir, "seg-0000000000000000.vmsp")

	// seg1: a torn creation — some header bytes landed, but the terminating
	// newline never arrived.
	seg1 := filepath.Join(vmDir, "seg-0000000000000001.vmsp")
	if err := os.WriteFile(seg1, []byte(`{"magic":"vmsp","vers`), 0o600); err != nil {
		t.Fatalf("create torn seg1: %v", err)
	}

	// seg2: the next writer, now the newest and fully valid.
	w2, err := spool.OpenWriter(vmDir, spool.WriterCfg{
		VMID:            vmID,
		InstanceID:      instanceID,
		MaxSegmentBytes: 4 * 1024 * 1024,
		MaxSpoolBytes:   64 * 1024 * 1024,
		LossRecord:      lossRecordFor(vmID),
	})
	if err != nil {
		t.Fatalf("OpenWriter seg2: %v", err)
	}
	if err := w2.Append(makeSpoolEnvelope(vmID, instanceID, "1")); err != nil {
		t.Fatalf("Append seg2: %v", err)
	}
	if err := w2.Close(); err != nil {
		t.Fatalf("Close seg2: %v", err)
	}
	seg2 := filepath.Join(vmDir, "seg-0000000000000002.vmsp")
	if _, err := os.Stat(seg2); err != nil {
		t.Fatalf("expected seg2 at index 2: %v", err)
	}

	report, err := spool.Recover(vmDir)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if want := []string{seg0, seg2}; !slices.Equal(report.Segments, want) {
		t.Errorf("Segments = %v, want %v", report.Segments, want)
	}
	if _, statErr := os.Stat(seg1); !os.IsNotExist(statErr) {
		t.Errorf("torn creation below newest must be removed, stat err = %v", statErr)
	}
}

// TestRecoverIgnoresNonPatternFiles covers .vmsp files the writer never
// makes (a quota-filling ballast file, for instance). Recover must never
// read, truncate, remove, or treat them as the newest segment — they are
// simply not in the naming scheme parseSegmentName accepts.
func TestRecoverIgnoresNonPatternFiles(t *testing.T) {
	st := openTestStore(t)
	root := t.TempDir()
	vmID := "55555555-5555-5555-5555-555555555555"
	instanceID := "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"

	vmDir := writeSegment(t, root, vmID, []*events.Envelope{makeSpoolEnvelope(vmID, instanceID, "0")}, true /* closed */)
	seg0 := filepath.Join(vmDir, "seg-0000000000000000.vmsp")

	bad := filepath.Join(vmDir, "bad.vmsp")
	zz := filepath.Join(vmDir, "zz.vmsp")
	for _, p := range []string{bad, zz} {
		if err := os.WriteFile(p, []byte("garbage"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	report, err := spool.Recover(vmDir)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if want := []string{seg0}; !slices.Equal(report.Segments, want) {
		t.Errorf("Segments = %v, want %v", report.Segments, want)
	}
	for _, p := range []string{bad, zz} {
		if _, statErr := os.Stat(p); statErr != nil {
			t.Errorf("non-pattern file must remain on disk: %s: %v", p, statErr)
		}
	}

	imp := spool.NewImporter(st, root, time.Second, nil)
	stats, err := imp.ImportOnce(context.Background())
	if err != nil {
		t.Fatalf("ImportOnce: %v", err)
	}
	if stats.Appended != 1 {
		t.Errorf("Appended = %d, want 1", stats.Appended)
	}
}

// TestRecoverNewestUnparseableHeaderIsHardError covers a segment whose header
// line is complete (terminated by a newline) but not valid — real corruption,
// not a creation in progress. This must stay a hard error even when the
// segment is the newest.
func TestRecoverNewestUnparseableHeaderIsHardError(t *testing.T) {
	dir := t.TempDir()
	seg := filepath.Join(dir, "seg-0000000000000000.vmsp")
	if err := os.WriteFile(seg, []byte("not json at all\n"), 0o600); err != nil {
		t.Fatalf("write seg: %v", err)
	}

	if _, err := spool.Recover(dir); err == nil {
		t.Fatal("expected error for newest segment with unparseable header, got nil")
	}
}
