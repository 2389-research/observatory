// ABOUTME: Tests that a new writer never reuses a segment name the import
// ABOUTME: cursor has already passed, across plain, rotated and stray-name boots.
package spool_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/spool"
)

// oneRecordSegmentBytes calibrates the exact segment size (header + one
// makeSpoolEnvelope record) for vmID/instanceID, so a caller can force
// exactly one record per segment without hand-computing JSON marshal sizes.
// It writes into its own throwaway directory and never touches the caller's.
func oneRecordSegmentBytes(t *testing.T, vmID, instanceID string) int64 {
	t.Helper()
	calDir := t.TempDir()
	w, err := spool.OpenWriter(calDir, spool.WriterCfg{
		VMID:            vmID,
		InstanceID:      instanceID,
		MaxSegmentBytes: 1 << 20,
		MaxSpoolBytes:   64 * 1024 * 1024,
		LossRecord:      lossRecordFor(vmID),
	})
	if err != nil {
		t.Fatalf("OpenWriter (calibration): %v", err)
	}
	if err := w.Append(makeSpoolEnvelope(vmID, instanceID, "0")); err != nil {
		t.Fatalf("Append (calibration): %v", err)
	}
	segs, err := filepath.Glob(filepath.Join(calDir, "*.vmsp"))
	if err != nil || len(segs) != 1 {
		t.Fatalf("calibration segment glob: %v, err=%v", segs, err)
	}
	info, err := os.Stat(segs[0])
	if err != nil {
		t.Fatalf("stat calibration segment: %v", err)
	}
	return info.Size()
}

// vmspNames globs dir for *.vmsp files and returns their sorted base names.
func vmspNames(t *testing.T, dir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "*.vmsp"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	names := make([]string, len(matches))
	for i, m := range matches {
		names[i] = filepath.Base(m)
	}
	return names
}

// TestNewBootAfterPruneImportsEveryRecord is the plain repro from the task
// brief: boot A's single segment is fully imported and pruned, then boot B
// must not reissue seg-0000000000000000.vmsp — the cursor still names it as
// CURRENT with all of boot A's records committed, so a reused name would
// make the importer skip boot B's first records as already-seen.
func TestNewBootAfterPruneImportsEveryRecord(t *testing.T) {
	st := openTestStore(t)
	root := t.TempDir()
	vm := "7a7a7a7a-0001-4000-8000-000000000001"
	instanceA := "7a7a7a7a-0001-4000-8000-0000000000aa"
	instanceB := "7a7a7a7a-0001-4000-8000-0000000000bb"
	spoolDir := filepath.Join(root, vm)
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	wA, err := spool.OpenWriter(spoolDir, spool.WriterCfg{
		VMID: vm, InstanceID: instanceA,
		MaxSegmentBytes: 4 * 1024 * 1024, MaxSpoolBytes: 64 * 1024 * 1024,
		LossRecord: lossRecordFor(vm),
	})
	if err != nil {
		t.Fatalf("OpenWriter boot A: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := wA.Append(makeSpoolEnvelope(vm, instanceA, fmt.Sprintf("%d", i))); err != nil {
			t.Fatalf("Append boot A[%d]: %v", i, err)
		}
	}
	if err := wA.Close(); err != nil {
		t.Fatalf("Close boot A: %v", err)
	}

	imp := spool.NewImporter(st, root, time.Second, nil)
	if _, err := imp.ImportOnce(context.Background()); err != nil {
		t.Fatalf("ImportOnce (boot A): %v", err)
	}
	if segs := vmspNames(t, spoolDir); len(segs) != 0 {
		t.Fatalf("boot A segment not pruned: %v", segs)
	}

	wB, err := spool.OpenWriter(spoolDir, spool.WriterCfg{
		VMID: vm, InstanceID: instanceB,
		MaxSegmentBytes: 4 * 1024 * 1024, MaxSpoolBytes: 64 * 1024 * 1024,
		LossRecord: lossRecordFor(vm),
	})
	if err != nil {
		t.Fatalf("OpenWriter boot B: %v", err)
	}
	want := []string{"seg-0000000000000001.vmsp"}
	if segs := vmspNames(t, spoolDir); !slices.Equal(segs, want) {
		t.Fatalf("boot B segment = %v, want %v", segs, want)
	}
	for i := 0; i < 4; i++ {
		if err := wB.Append(makeSpoolEnvelope(vm, instanceB, fmt.Sprintf("%d", i))); err != nil {
			t.Fatalf("Append boot B[%d]: %v", i, err)
		}
	}
	if err := wB.Close(); err != nil {
		t.Fatalf("Close boot B: %v", err)
	}

	if _, err := imp.ImportOnce(context.Background()); err != nil {
		t.Fatalf("ImportOnce (boot B): %v", err)
	}
	if got := countEvents(t, st, instanceB); got != 4 {
		t.Fatalf("countEvents(instanceB) = %d, want 4", got)
	}
}

// TestNewBootAfterRotatedPruneImportsEveryRecord covers the second repro from
// the brief: boot A rotates across three segments before every one of them is
// imported and pruned. Boot B must start past the highest name boot A ever
// used, not just past whatever the (now-empty) directory shows.
func TestNewBootAfterRotatedPruneImportsEveryRecord(t *testing.T) {
	st := openTestStore(t)
	root := t.TempDir()
	vm := "7a7a7a7a-0002-4000-8000-000000000002"
	instanceA := "7a7a7a7a-0002-4000-8000-0000000000aa"
	instanceB := "7a7a7a7a-0002-4000-8000-0000000000bb"
	spoolDir := filepath.Join(root, vm)
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Cap each segment at exactly one record's worth of bytes so 3 records
	// force 2 rotations — verified below by listing, not assumed.
	segCap := oneRecordSegmentBytes(t, vm, instanceA)
	wA, err := spool.OpenWriter(spoolDir, spool.WriterCfg{
		VMID: vm, InstanceID: instanceA,
		MaxSegmentBytes: segCap, MaxSpoolBytes: 64 * 1024 * 1024,
		LossRecord: lossRecordFor(vm),
	})
	if err != nil {
		t.Fatalf("OpenWriter boot A: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := wA.Append(makeSpoolEnvelope(vm, instanceA, fmt.Sprintf("%d", i))); err != nil {
			t.Fatalf("Append boot A[%d]: %v", i, err)
		}
	}
	if err := wA.Close(); err != nil {
		t.Fatalf("Close boot A: %v", err)
	}

	wantA := []string{"seg-0000000000000000.vmsp", "seg-0000000000000001.vmsp", "seg-0000000000000002.vmsp"}
	if segs := vmspNames(t, spoolDir); !slices.Equal(segs, wantA) {
		t.Fatalf("boot A segments = %v, want %v", segs, wantA)
	}

	imp := spool.NewImporter(st, root, time.Second, nil)
	if _, err := imp.ImportOnce(context.Background()); err != nil {
		t.Fatalf("ImportOnce (boot A): %v", err)
	}
	if segs := vmspNames(t, spoolDir); len(segs) != 0 {
		t.Fatalf("boot A segments not all pruned: %v", segs)
	}

	wB, err := spool.OpenWriter(spoolDir, spool.WriterCfg{
		VMID: vm, InstanceID: instanceB,
		MaxSegmentBytes: 4 * 1024 * 1024, MaxSpoolBytes: 64 * 1024 * 1024,
		LossRecord: lossRecordFor(vm),
	})
	if err != nil {
		t.Fatalf("OpenWriter boot B: %v", err)
	}
	wantB := []string{"seg-0000000000000003.vmsp"}
	if segs := vmspNames(t, spoolDir); !slices.Equal(segs, wantB) {
		t.Fatalf("boot B segment = %v, want %v", segs, wantB)
	}
	for i := 0; i < 4; i++ {
		if err := wB.Append(makeSpoolEnvelope(vm, instanceB, fmt.Sprintf("%d", i))); err != nil {
			t.Fatalf("Append boot B[%d]: %v", i, err)
		}
	}
	if err := wB.Close(); err != nil {
		t.Fatalf("Close boot B: %v", err)
	}

	if _, err := imp.ImportOnce(context.Background()); err != nil {
		t.Fatalf("ImportOnce (boot B): %v", err)
	}
	if got := countEvents(t, st, instanceB); got != 4 {
		t.Fatalf("countEvents(instanceB) = %d, want 4", got)
	}
}

// TestStraySpoolFileDoesNotResetSegmentIndex plants a name that sorts after
// every real segment name. The old scan sorted all *.vmsp names as strings
// and Sscanf'd only the lexical maximum, so a trailing stray name made
// parsing fail and silently reset the index to 0.
func TestStraySpoolFileDoesNotResetSegmentIndex(t *testing.T) {
	root := t.TempDir()
	vm := "7a7a7a7a-0003-4000-8000-000000000003"
	spoolDir := filepath.Join(root, vm)
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, name := range []string{"seg-0000000000000004.vmsp", "zz-stray.vmsp"} {
		if err := os.WriteFile(filepath.Join(spoolDir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("plant %s: %v", name, err)
		}
	}

	w, err := spool.OpenWriter(spoolDir, spool.WriterCfg{
		VMID: vm, InstanceID: "7a7a7a7a-0003-4000-8000-0000000000aa",
		MaxSegmentBytes: 4 * 1024 * 1024, MaxSpoolBytes: 64 * 1024 * 1024,
		LossRecord: lossRecordFor(vm),
	})
	if err != nil {
		t.Fatalf("OpenWriter: %v", err)
	}
	defer w.Close()

	want := []string{"seg-0000000000000004.vmsp", "seg-0000000000000005.vmsp", "zz-stray.vmsp"}
	if segs := vmspNames(t, spoolDir); !slices.Equal(segs, want) {
		t.Fatalf("segments = %v, want %v", segs, want)
	}
}

// TestInvalidCursorFailsOpenWriter: a cursor.json that fails to parse must
// fail OpenWriter rather than silently reusing index 0.
func TestInvalidCursorFailsOpenWriter(t *testing.T) {
	root := t.TempDir()
	vm := "7a7a7a7a-0004-4000-8000-000000000004"
	spoolDir := filepath.Join(root, vm)
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(spoolDir, "cursor.json"), []byte("not json"), 0o600); err != nil {
		t.Fatalf("write cursor.json: %v", err)
	}

	_, err := spool.OpenWriter(spoolDir, spool.WriterCfg{
		VMID: vm, InstanceID: "7a7a7a7a-0004-4000-8000-0000000000aa",
		MaxSegmentBytes: 4 * 1024 * 1024, MaxSpoolBytes: 64 * 1024 * 1024,
		LossRecord: lossRecordFor(vm),
	})
	if err == nil {
		t.Fatal("OpenWriter succeeded on an unparsable cursor")
	}
	if !strings.Contains(err.Error(), "read import cursor") {
		t.Fatalf("error = %q, want it to contain %q", err.Error(), "read import cursor")
	}
	if segs := vmspNames(t, spoolDir); len(segs) != 0 {
		t.Fatalf("segments created despite OpenWriter failure: %v", segs)
	}
}

// TestCursorNamingANonSegmentFailsOpenWriter: a well-formed cursor.json whose
// segment field is not a segment name must fail OpenWriter with a message
// naming the offending value, and must create nothing.
func TestCursorNamingANonSegmentFailsOpenWriter(t *testing.T) {
	root := t.TempDir()
	vm := "7a7a7a7a-0005-4000-8000-000000000005"
	spoolDir := filepath.Join(root, vm)
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(spoolDir, "cursor.json"), []byte(`{"segment":"notes.txt","record":0}`), 0o600); err != nil {
		t.Fatalf("write cursor.json: %v", err)
	}

	_, err := spool.OpenWriter(spoolDir, spool.WriterCfg{
		VMID: vm, InstanceID: "7a7a7a7a-0005-4000-8000-0000000000aa",
		MaxSegmentBytes: 4 * 1024 * 1024, MaxSpoolBytes: 64 * 1024 * 1024,
		LossRecord: lossRecordFor(vm),
	})
	if err == nil {
		t.Fatal("OpenWriter succeeded with a cursor naming a non-segment file")
	}
	if !strings.Contains(err.Error(), `import cursor names "notes.txt"`) {
		t.Fatalf("error = %q, want it to contain %q", err.Error(), `import cursor names "notes.txt"`)
	}
	if segs := vmspNames(t, spoolDir); len(segs) != 0 {
		t.Fatalf("segments created despite OpenWriter failure: %v", segs)
	}
}

// TestSegmentIndexCeiling: the highest expressible 16-digit index must refuse
// to grow further — a 17-digit name would sort before every 16-digit name
// and be pruned as PAST on sight.
func TestSegmentIndexCeiling(t *testing.T) {
	root := t.TempDir()
	vm := "7a7a7a7a-0006-4000-8000-000000000006"
	spoolDir := filepath.Join(root, vm)
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(spoolDir, "seg-9999999999999999.vmsp"), []byte("x"), 0o600); err != nil {
		t.Fatalf("plant ceiling segment: %v", err)
	}

	_, err := spool.OpenWriter(spoolDir, spool.WriterCfg{
		VMID: vm, InstanceID: "7a7a7a7a-0006-4000-8000-0000000000aa",
		MaxSegmentBytes: 4 * 1024 * 1024, MaxSpoolBytes: 64 * 1024 * 1024,
		LossRecord: lossRecordFor(vm),
	})
	if err == nil {
		t.Fatal("OpenWriter succeeded past the 16-digit segment name space")
	}
	if !strings.Contains(err.Error(), "exceeds the 16-digit name space") {
		t.Fatalf("error = %q, want it to contain %q", err.Error(), "exceeds the 16-digit name space")
	}
	want := []string{"seg-9999999999999999.vmsp"}
	if segs := vmspNames(t, spoolDir); !slices.Equal(segs, want) {
		t.Fatalf("segments = %v, want only the planted ceiling segment %v", segs, want)
	}
}
