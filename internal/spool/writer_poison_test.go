// ABOUTME: White-box tests for Writer poison (sticky write-failure) semantics.
// ABOUTME: Uses package spool (not spool_test) to access unexported fields directly.
package spool

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/events"
)

// makeEnvelopeInternal builds a minimal valid Envelope for white-box tests.
func makeEnvelopeInternal(kind string, seq int) *events.Envelope {
	vmID := "wb-vm-1"
	bootID := "wb-boot-1"
	return &events.Envelope{
		SchemaVersion:    1,
		VMID:             &vmID,
		BootID:           &bootID,
		SourceInstanceID: "wb-inst-1",
		SourceSeq:        "1",
		Kind:             kind,
		Provenance:       events.GuestReported,
		Sensor:           "test",
		HostReceivedAt:   events.Timestamp{Time: time.Now().UTC()},
		Quality: events.Quality{
			PathResolution: events.PathNotApplicable,
			Attribution:    events.AttributionNotApplicable,
		},
		Data: map[string]any{"seq": seq},
	}
}

// TestPoisonAfterWriteFailure verifies sticky write-failure (poison) semantics:
// once any Append fails at write or fsync of record bytes, every subsequent
// Append returns the same error immediately, and Close does NOT write an end
// marker (the segment is crashed, not clean).
func TestPoisonAfterWriteFailure(t *testing.T) {
	dir := t.TempDir()
	w, err := OpenWriter(dir, WriterCfg{
		VMID:            "wb-vm-1",
		InstanceID:      "wb-inst-1",
		MaxSegmentBytes: 4 * 1024 * 1024,
		MaxSpoolBytes:   64 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("OpenWriter: %v", err)
	}

	// Append one good record so the segment has content.
	if err := w.Append(makeEnvelopeInternal("fs.modify", 0)); err != nil {
		t.Fatalf("first Append (good): %v", err)
	}

	// Force a real failure by closing the underlying file descriptor directly.
	// The next Append will attempt a Write to a closed fd and get an OS error.
	if err := w.f.Close(); err != nil {
		t.Fatalf("close underlying fd: %v", err)
	}

	// This Append must fail because the fd is closed.
	err1 := w.Append(makeEnvelopeInternal("fs.modify", 1))
	if err1 == nil {
		t.Fatal("second Append (closed fd): expected error, got nil")
	}

	// A subsequent Append must return the same poison error without further writes.
	err2 := w.Append(makeEnvelopeInternal("fs.modify", 2))
	if !errors.Is(err2, err1) {
		t.Errorf("third Append: expected same poison error %v, got %v", err1, err2)
	}

	// Close must NOT write an end marker — the segment is poisoned.
	// Capture the segment path before Close (Close on a poisoned writer just closes the fd).
	segs, _ := filepath.Glob(filepath.Join(dir, "seg-*.vmsp"))
	if len(segs) == 0 {
		t.Fatal("no segment file found")
	}
	segPath := segs[0]

	// Read raw bytes BEFORE close so we know the file's current tail.
	rawBefore, err := os.ReadFile(segPath)
	if err != nil {
		t.Fatalf("ReadFile before Close: %v", err)
	}

	// Close on a poisoned writer. It may return the poison error or the fd-close
	// error (fd is already closed — expect an error here).
	_ = w.Close()

	// Read raw bytes AFTER close.
	rawAfter, err := os.ReadFile(segPath)
	if err != nil {
		t.Fatalf("ReadFile after Close: %v", err)
	}

	// The file must not have grown (no end marker appended).
	if len(rawAfter) != len(rawBefore) {
		t.Errorf("Close on poisoned writer wrote %d bytes (file grew from %d to %d); end marker must not be written",
			len(rawAfter)-len(rawBefore), len(rawBefore), len(rawAfter))
	}

	// Confirm the tail is NOT the end marker (0xFFFFFFFF).
	if len(rawAfter) >= 4 {
		last4 := uint32(rawAfter[len(rawAfter)-4])<<24 |
			uint32(rawAfter[len(rawAfter)-3])<<16 |
			uint32(rawAfter[len(rawAfter)-2])<<8 |
			uint32(rawAfter[len(rawAfter)-1])
		if last4 == endMarker {
			t.Error("poisoned Close wrote end marker; must not — segment is not cleanly closed")
		}
	}

	// The segment must still be readable up to the one good record.
	iter, err := ReadSegment(segPath)
	if err != nil {
		t.Fatalf("ReadSegment after poison Close: %v", err)
	}
	defer iter.Close()
	_, err = iter.Next()
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("Next (good record): %v", err)
	}
}
