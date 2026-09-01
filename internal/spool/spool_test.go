// ABOUTME: Tests for the spool segment format: writer, reader, and recovery.
// ABOUTME: All tests use real files and real fsync — no mocking.
package spool_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/events"
	"github.com/2389-research/observatory-v2/internal/spool"
)

// makeEnvelope constructs a minimal valid Envelope for testing.
func makeEnvelope(kind string, seq int) *events.Envelope {
	vmID := "test-vm-1"
	bootID := "test-boot-1"
	return &events.Envelope{
		SchemaVersion:    1,
		VMID:             &vmID,
		BootID:           &bootID,
		SourceInstanceID: "test-instance-1",
		SourceSeq:        fmt.Sprintf("%d", seq),
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

// TestRoundTrip writes 3 envelopes and reads them back verbatim.
func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	w, err := spool.OpenWriter(dir, spool.WriterCfg{
		VMID:            "vm-1",
		InstanceID:      "inst-1",
		MaxSegmentBytes: 4 * 1024 * 1024, // 4 MiB — well over our small payloads
		MaxSpoolBytes:   64 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("OpenWriter: %v", err)
	}

	envs := make([]*events.Envelope, 3)
	for i := range envs {
		envs[i] = makeEnvelope("fs.modify", i)
		if err := w.Append(envs[i]); err != nil {
			t.Fatalf("Append(%d): %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Find the segment file.
	segs, err := filepath.Glob(filepath.Join(dir, "seg-*.vmsp"))
	if err != nil || len(segs) == 0 {
		t.Fatalf("no segment files found: %v", err)
	}

	iter, err := spool.ReadSegment(segs[0])
	if err != nil {
		t.Fatalf("ReadSegment: %v", err)
	}
	defer iter.Close()

	for i, want := range envs {
		got, err := iter.Next()
		if err != nil {
			t.Fatalf("Next(%d): %v", i, err)
		}
		wantJSON, _ := json.Marshal(want)
		gotJSON, _ := json.Marshal(got)
		if !bytes.Equal(wantJSON, gotJSON) {
			t.Errorf("record %d mismatch:\n want %s\n  got %s", i, wantJSON, gotJSON)
		}
	}

	// Next call after last record must return io.EOF.
	_, err = iter.Next()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF after last record, got %v", err)
	}
}

// TestCrashSimulation writes 2 records, appends garbage, then calls Recover.
// Recovery should report TruncatedTail=true and the iterator yields exactly 2.
func TestCrashSimulation(t *testing.T) {
	dir := t.TempDir()
	w, err := spool.OpenWriter(dir, spool.WriterCfg{
		VMID:            "vm-1",
		InstanceID:      "inst-1",
		MaxSegmentBytes: 4 * 1024 * 1024,
		MaxSpoolBytes:   64 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("OpenWriter: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := w.Append(makeEnvelope("fs.modify", i)); err != nil {
			t.Fatalf("Append(%d): %v", i, err)
		}
	}
	// Simulate crash: do not call Close (no end-marker), instead append garbage.
	segs, _ := filepath.Glob(filepath.Join(dir, "seg-*.vmsp"))
	if len(segs) == 0 {
		t.Fatal("no segment file found before appending garbage")
	}
	f, err := os.OpenFile(segs[0], os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open seg for garbage append: %v", err)
	}
	_, _ = f.Write([]byte{0x00, 0x00, 0x00, 0x05, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}) // 10 garbage bytes — not a valid record
	_ = f.Sync()
	_ = f.Close()
	// Also skip w.Close() to leave file "crashed".

	report, err := spool.Recover(dir)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if !report.TruncatedTail {
		t.Error("expected TruncatedTail=true, got false")
	}
	if len(report.Segments) == 0 {
		t.Error("expected at least one segment in report")
	}

	// Now read the recovered segment — should yield exactly 2 records.
	iter, err := spool.ReadSegment(segs[0])
	if err != nil {
		t.Fatalf("ReadSegment after Recover: %v", err)
	}
	defer iter.Close()
	count := 0
	for {
		_, err := iter.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Next(): unexpected error: %v", err)
		}
		count++
	}
	if count != 2 {
		t.Errorf("expected 2 records after recovery, got %d", count)
	}
}

// TestInteriorCorruption flips a byte inside record 1 of 3 and expects
// ErrCorruptRecord after reading 0 records.
func TestInteriorCorruption(t *testing.T) {
	dir := t.TempDir()
	w, err := spool.OpenWriter(dir, spool.WriterCfg{
		VMID:            "vm-1",
		InstanceID:      "inst-1",
		MaxSegmentBytes: 4 * 1024 * 1024,
		MaxSpoolBytes:   64 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("OpenWriter: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := w.Append(makeEnvelope("fs.modify", i)); err != nil {
			t.Fatalf("Append(%d): %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	segs, _ := filepath.Glob(filepath.Join(dir, "seg-*.vmsp"))
	if len(segs) == 0 {
		t.Fatal("no segment file")
	}

	// Read the raw file, find the first record body (after the header line),
	// and flip a byte inside the JSON body of record 0.
	raw, err := os.ReadFile(segs[0])
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// The header is the first line (\n-terminated JSON).
	// Record 0 starts right after: [4-byte len][4-byte crc][body].
	headerEnd := bytes.IndexByte(raw, '\n')
	if headerEnd < 0 {
		t.Fatal("no newline in segment file (header not found)")
	}
	recStart := headerEnd + 1
	// Flip a byte inside the body (offset 8 into the record — past len+crc headers).
	flipAt := recStart + 8
	if flipAt >= len(raw) {
		t.Fatalf("segment too short to flip: len=%d flipAt=%d", len(raw), flipAt)
	}
	raw[flipAt] ^= 0xFF
	if err := os.WriteFile(segs[0], raw, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	iter, err := spool.ReadSegment(segs[0])
	if err != nil {
		t.Fatalf("ReadSegment: %v", err)
	}
	defer iter.Close()
	// First Next() must return ErrCorruptRecord (record 0 is corrupt).
	_, err = iter.Next()
	if !errors.Is(err, spool.ErrCorruptRecord) {
		t.Errorf("expected ErrCorruptRecord, got %v", err)
	}
}

// TestErrSpoolFull ensures Append returns ErrSpoolFull once the spool exceeds
// the configured MaxSpoolBytes.
func TestErrSpoolFull(t *testing.T) {
	dir := t.TempDir()
	// Give a very small spool limit — less than one envelope's JSON size.
	w, err := spool.OpenWriter(dir, spool.WriterCfg{
		VMID:            "vm-1",
		InstanceID:      "inst-1",
		MaxSegmentBytes: 4 * 1024 * 1024,
		MaxSpoolBytes:   64, // 64 bytes — will be exceeded by first envelope
	})
	if err != nil {
		t.Fatalf("OpenWriter: %v", err)
	}
	defer w.Close()

	err = w.Append(makeEnvelope("fs.modify", 0))
	if !errors.Is(err, spool.ErrSpoolFull) {
		t.Errorf("expected ErrSpoolFull, got %v", err)
	}
}

// TestSegmentRotation verifies that a new segment is created when MaxSegmentBytes
// is exceeded, and that both segments contain readable records.
func TestSegmentRotation(t *testing.T) {
	dir := t.TempDir()
	// Craft a segment limit small enough to force rotation after ~2 records.
	// A typical envelope marshal is ~300 bytes; set limit at 600 bytes.
	w, err := spool.OpenWriter(dir, spool.WriterCfg{
		VMID:            "vm-1",
		InstanceID:      "inst-1",
		MaxSegmentBytes: 600,
		MaxSpoolBytes:   64 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("OpenWriter: %v", err)
	}

	// Write enough envelopes to guarantee rotation.
	total := 6
	for i := 0; i < total; i++ {
		if err := w.Append(makeEnvelope("fs.modify", i)); err != nil {
			t.Fatalf("Append(%d): %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	segs, _ := filepath.Glob(filepath.Join(dir, "seg-*.vmsp"))
	if len(segs) < 2 {
		t.Fatalf("expected at least 2 segments after rotation, got %d", len(segs))
	}

	// All segments must be readable and yield at least one record.
	for _, seg := range segs {
		iter, err := spool.ReadSegment(seg)
		if err != nil {
			t.Fatalf("ReadSegment(%s): %v", seg, err)
		}
		_, err = iter.Next()
		_ = iter.Close()
		if errors.Is(err, io.EOF) {
			t.Errorf("segment %s has zero records (expected at least one)", seg)
		} else if err != nil {
			t.Errorf("segment %s Next(): %v", seg, err)
		}
	}
}

// TestEndMarkerPresence verifies that a cleanly closed segment has an end marker
// (len==0xFFFFFFFF), and a simulated-crash segment does not.
func TestEndMarkerPresence(t *testing.T) {
	dir := t.TempDir()
	w, err := spool.OpenWriter(dir, spool.WriterCfg{
		VMID:            "vm-1",
		InstanceID:      "inst-1",
		MaxSegmentBytes: 4 * 1024 * 1024,
		MaxSpoolBytes:   64 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("OpenWriter: %v", err)
	}
	if err := w.Append(makeEnvelope("fs.modify", 0)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	// Record the path before Close (rotation could in theory produce a new one,
	// but with large limits that won't happen here).
	segs, _ := filepath.Glob(filepath.Join(dir, "seg-*.vmsp"))
	if len(segs) == 0 {
		t.Fatal("no segment found")
	}
	segPath := segs[0]

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The last 4 bytes of a cleanly closed segment must be 0xFFFFFFFF.
	raw, err := os.ReadFile(segPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(raw) < 4 {
		t.Fatalf("segment too short: %d bytes", len(raw))
	}
	last4 := binary.BigEndian.Uint32(raw[len(raw)-4:])
	if last4 != 0xFFFFFFFF {
		t.Errorf("clean close: last 4 bytes = %08X, want FFFFFFFF", last4)
	}

	// Crash simulation: write a second segment, do NOT close.
	dir2 := t.TempDir()
	w2, err := spool.OpenWriter(dir2, spool.WriterCfg{
		VMID:            "vm-1",
		InstanceID:      "inst-1",
		MaxSegmentBytes: 4 * 1024 * 1024,
		MaxSpoolBytes:   64 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("OpenWriter2: %v", err)
	}
	if err := w2.Append(makeEnvelope("fs.modify", 0)); err != nil {
		t.Fatalf("Append2: %v", err)
	}
	// Drop w2 without Close — simulated crash.
	segs2, _ := filepath.Glob(filepath.Join(dir2, "seg-*.vmsp"))
	if len(segs2) == 0 {
		t.Fatal("no segment in crash dir")
	}
	raw2, err := os.ReadFile(segs2[0])
	if err != nil {
		t.Fatalf("ReadFile2: %v", err)
	}
	if len(raw2) >= 4 {
		last4crash := binary.BigEndian.Uint32(raw2[len(raw2)-4:])
		if last4crash == 0xFFFFFFFF {
			t.Error("crash segment unexpectedly has end marker")
		}
	}
}

// TestRecoverEmptyDir verifies Recover on an empty directory returns a zero
// report without error.
func TestRecoverEmptyDir(t *testing.T) {
	dir := t.TempDir()
	report, err := spool.Recover(dir)
	if err != nil {
		t.Fatalf("Recover on empty dir: %v", err)
	}
	if len(report.Segments) != 0 {
		t.Errorf("expected 0 segments, got %d", len(report.Segments))
	}
	if report.TruncatedTail {
		t.Error("expected TruncatedTail=false on empty dir")
	}
	if report.GapEmitted != nil {
		t.Error("expected GapEmitted=nil on empty dir")
	}
}

// TestZeroRecordSegment verifies that ReadSegment on a segment with 0 records
// (only header + end marker) returns io.EOF immediately on the first Next().
func TestZeroRecordSegment(t *testing.T) {
	dir := t.TempDir()
	w, err := spool.OpenWriter(dir, spool.WriterCfg{
		VMID:            "vm-1",
		InstanceID:      "inst-1",
		MaxSegmentBytes: 4 * 1024 * 1024,
		MaxSpoolBytes:   64 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("OpenWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	segs, _ := filepath.Glob(filepath.Join(dir, "seg-*.vmsp"))
	if len(segs) == 0 {
		t.Fatal("no segment file created")
	}

	iter, err := spool.ReadSegment(segs[0])
	if err != nil {
		t.Fatalf("ReadSegment: %v", err)
	}
	defer iter.Close()
	_, err = iter.Next()
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected EOF from empty segment, got %v", err)
	}
}

// TestMaxRecordSize verifies that a record exactly at the 256 KiB limit succeeds,
// and that a record just over the limit is rejected.
func TestMaxRecordSize(t *testing.T) {
	dir := t.TempDir()
	w, err := spool.OpenWriter(dir, spool.WriterCfg{
		VMID:            "vm-1",
		InstanceID:      "inst-1",
		MaxSegmentBytes: 4 * 1024 * 1024,
		MaxSpoolBytes:   64 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("OpenWriter: %v", err)
	}
	defer w.Close()

	// Build an envelope whose JSON marshals to exactly 256 KiB by padding the
	// Data field. First measure a base envelope, then pad to hit the limit.
	base := makeEnvelope("fs.modify", 0)
	baseJSON, _ := json.Marshal(base)
	target := 256 * 1024
	padding := target - len(baseJSON) - len(`,"pad":"`) - 1 // -1 for closing "
	if padding < 0 {
		t.Skip("base envelope already exceeds 256 KiB — test environment issue")
	}
	padStr := make([]byte, padding)
	for i := range padStr {
		padStr[i] = 'A'
	}
	base.Data["pad"] = string(padStr)
	atLimit, _ := json.Marshal(base)
	if len(atLimit) > target {
		// Trim pad to land exactly at target.
		excess := len(atLimit) - target
		base.Data["pad"] = string(padStr[:padding-excess])
		atLimit, _ = json.Marshal(base)
	}

	// A record at exactly (or under) 256 KiB must succeed.
	if len(atLimit) <= target {
		envAtLimit := &events.Envelope{}
		_ = json.Unmarshal(atLimit, envAtLimit)
		if err := w.Append(envAtLimit); err != nil {
			t.Errorf("Append at %d bytes (≤256 KiB): %v", len(atLimit), err)
		}
	}

	// A record just over 256 KiB must be rejected.
	over := makeEnvelope("fs.modify", 99)
	overPad := make([]byte, target+1)
	for i := range overPad {
		overPad[i] = 'B'
	}
	over.Data["pad"] = string(overPad)
	if err := w.Append(over); err == nil {
		t.Error("expected error for record exceeding 256 KiB, got nil")
	}
}

// TestMaxSegmentBytesZeroError verifies that MaxSegmentBytes <= 0 returns an error.
func TestMaxSegmentBytesZeroError(t *testing.T) {
	dir := t.TempDir()
	_, err := spool.OpenWriter(dir, spool.WriterCfg{
		VMID:            "vm-1",
		InstanceID:      "inst-1",
		MaxSegmentBytes: 0,
		MaxSpoolBytes:   64 * 1024 * 1024,
	})
	if err == nil {
		t.Error("expected error for MaxSegmentBytes=0, got nil")
	}
}
