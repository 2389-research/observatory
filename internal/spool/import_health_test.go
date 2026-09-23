// ABOUTME: Exercises import failure reporting and retry recovery with real disk and SQLite.
// ABOUTME: Keeps healthy VM progress independent from broken spool directories.
package spool_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/events"
	"github.com/2389-research/observatory/internal/situation"
	"github.com/2389-research/observatory/internal/spool"
	"github.com/2389-research/observatory/internal/store"
)

func TestImportFailureStatusAndRecovery(t *testing.T) {
	st := openTestStore(t)
	root := t.TempDir()
	bad := "aaaabbbb-cccc-dddd-eeee-ffffffff0001"
	good := "bbbbcccc-dddd-eeee-ffff-000011112222"
	badDir := writeSegment(t, root, bad, []*events.Envelope{makeSpoolEnvelope(bad, "11112222-3333-4444-5555-666677778888", "0")}, true)
	if err := os.Mkdir(filepath.Join(badDir, "cursor.json"), 0700); err != nil {
		t.Fatal(err)
	}
	writeSegment(t, root, good, []*events.Envelope{makeSpoolEnvelope(good, "22223333-4444-5555-6666-777788889999", "0")}, true)
	imp := spool.NewImporter(st, root, time.Millisecond, nil)
	situation.New(st, situation.Config{Triggers: map[string]bool{"telemetry_degraded": true}, QueueMaxItems: 10, CollapseDuplicates: true}).SetImporter(imp)
	stats, err := imp.ImportOnce(t.Context())
	if err == nil {
		t.Fatal("mixed import hid cursor failure")
	}
	if stats.Appended != 1 {
		t.Fatalf("healthy progress = %+v", stats)
	}
	state := imp.Status(bad)
	if state.ConsecutiveFailures != "1" || !strings.Contains(state.LastError, "cursor") || state.LastSuccessAt != "" {
		t.Fatalf("failure status = %+v", state)
	}
	for range 2 {
		if _, err := imp.ImportOnce(t.Context()); err == nil {
			t.Fatal("all remaining VM failure hidden")
		}
	}
	if state = imp.Status(bad); state.ConsecutiveFailures != "3" {
		t.Fatalf("retries = %+v", state)
	}
	items, err := st.ListAttention(t.Context(), store.AttentionQuery{Limit: 10})
	if err != nil || len(items) != 1 || items[0].Count != 1 {
		t.Fatalf("attention must coalesce episode: %+v, %v", items, err)
	}
	if err := os.Remove(filepath.Join(badDir, "cursor.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := imp.ImportOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	state = imp.Status(bad)
	if state.ConsecutiveFailures != "0" || state.LastError != "" || state.LastSuccessAt == "" {
		t.Fatalf("recovery = %+v", state)
	}
	before := state.LastSuccessAt
	if _, err := imp.ImportOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if imp.Status(bad).LastSuccessAt < before {
		t.Fatal("empty success lost last success")
	}
}

func TestImportRootFailureAndCancellation(t *testing.T) {
	st := openTestStore(t)
	root := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(root, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	imp := spool.NewImporter(st, root, time.Second, nil)
	if _, err := imp.ImportOnce(t.Context()); err == nil {
		t.Fatal("root failure hidden")
	}
	if imp.Status("").ConsecutiveFailures != "1" {
		t.Fatal("root failure absent")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := imp.ImportOnce(ctx); err != context.Canceled {
		t.Fatalf("cancel = %v", err)
	}
	if imp.Status("").ConsecutiveFailures != "1" {
		t.Fatal("shutdown counted as incident")
	}
}

func TestRunBackoffLeavesHealthyVMProgress(t *testing.T) {
	st := openTestStore(t)
	root := t.TempDir()
	bad := "aaaabbbb-cccc-dddd-eeee-ffffffff0001"
	dir := writeSegment(t, root, bad, []*events.Envelope{makeSpoolEnvelope(bad, "11112222-3333-4444-5555-666677778888", "0")}, true)
	if err := os.Mkdir(filepath.Join(dir, "cursor.json"), 0700); err != nil {
		t.Fatal(err)
	}
	imp := spool.NewImporter(st, root, 10*time.Millisecond, nil)
	// Repeated real failures reach the cap without waiting a minute in a test.
	for range 15 {
		if _, err := imp.ImportOnce(t.Context()); err == nil {
			t.Fatal("failure missing")
		}
	}
	status := imp.Status(bad)
	next, err := time.Parse(events.TimestampLayout, status.NextRetryAt)
	if err != nil {
		t.Fatal(err)
	}
	if delay := time.Until(next); delay < 59*time.Second || delay > time.Minute {
		t.Fatalf("retry cap = %s", delay)
	}
	good := "bbbbcccc-dddd-eeee-ffff-000011112222"
	instance := "22223333-4444-5555-6666-777788889999"
	writeSegment(t, root, good, []*events.Envelope{makeSpoolEnvelope(good, instance, "0")}, true)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- imp.Run(ctx) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(3 * time.Second)
	for countEvents(t, st, instance) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("healthy VM blocked by bad VM backoff")
		}
		time.Sleep(time.Millisecond)
	}
	if imp.Status(bad).ConsecutiveFailures != "15" {
		t.Fatal("background loop ignored backoff")
	}
}

func TestStoreFailureRetainsSegmentsAndReportsProgress(t *testing.T) {
	st := openTestStore(t)
	root := t.TempDir()
	vm := "aaaabbbb-cccc-dddd-eeee-ffffffff0001"
	dir := writeSegment(t, root, vm, []*events.Envelope{makeSpoolEnvelope(vm, "11112222-3333-4444-5555-666677778888", "0")}, true)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	imp := spool.NewImporter(st, root, time.Second, nil)
	stats, err := imp.ImportOnce(t.Context())
	if err == nil || stats.Appended != 0 || stats.Pruned != 0 {
		t.Fatalf("closed store = %+v, %v", stats, err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.vmsp"))
	if len(files) != 1 {
		t.Fatal("uncommitted segment lost")
	}
	if _, err := os.Stat(filepath.Join(dir, "cursor.json")); !os.IsNotExist(err) {
		t.Fatalf("cursor advanced before commit: %v", err)
	}
	if imp.Status(vm).LastError == "" {
		t.Fatal("store failure invisible when attention cannot be written")
	}
}

func TestCursorWriteFailureStopsBeforeLaterSegments(t *testing.T) {
	st := openTestStore(t)
	root := t.TempDir()
	vm := "aaaabbbb-cccc-dddd-eeee-ffffffff0001"
	instance := "11112222-3333-4444-5555-666677778888"
	dir := writeSegment(t, root, vm, []*events.Envelope{makeSpoolEnvelope(vm, instance, "0")}, true)
	writeSegment(t, root, vm, []*events.Envelope{makeSpoolEnvelope(vm, instance, "1")}, true)
	blocked := false
	imp := spool.NewImporter(st, root, time.Second, func(*events.Envelope) {
		if !blocked {
			blocked = true
			if err := os.Mkdir(filepath.Join(dir, "cursor.json"), 0700); err != nil {
				t.Fatal(err)
			}
		}
	})
	stats, err := imp.ImportOnce(t.Context())
	if err == nil || stats.Appended != 1 || stats.Pruned != 0 {
		t.Fatalf("cursor write = %+v, %v", stats, err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.vmsp"))
	if len(files) != 2 {
		t.Fatal("cursor failure pruned evidence")
	}
	if err := os.Remove(filepath.Join(dir, "cursor.json")); err != nil {
		t.Fatal(err)
	}
	stats, err = imp.ImportOnce(t.Context())
	if err != nil || stats.Deduped != 1 || stats.Appended != 1 || stats.Pruned != 2 {
		t.Fatalf("replay = %+v, %v", stats, err)
	}
}

func TestSegmentDisappearsDuringImportIsReported(t *testing.T) {
	st := openTestStore(t)
	root := t.TempDir()
	vm := "aaaabbbb-cccc-dddd-eeee-ffffffff0001"
	dir := writeSegment(t, root, vm, []*events.Envelope{makeSpoolEnvelope(vm, "11112222-3333-4444-5555-666677778888", "0")}, true)
	files, _ := filepath.Glob(filepath.Join(dir, "*.vmsp"))
	imp := spool.NewImporter(st, root, time.Second, func(*events.Envelope) {
		if err := os.Remove(files[0]); err != nil {
			t.Fatal(err)
		}
	})
	stats, err := imp.ImportOnce(t.Context())
	if err == nil || stats.Appended != 1 || stats.Pruned != 0 {
		t.Fatalf("segment read failure hidden: %+v, %v", stats, err)
	}
}

// statusInstance is the runner instance the writer-status tests open writers
// under.
const statusInstance = "33334444-5555-6666-7777-888899990000"

// openStatusWriter opens a writer on root/<vmID> with the given quota and
// closes it when the test ends.
func openStatusWriter(t *testing.T, root, vmID string, quota int64) *spool.Writer {
	t.Helper()
	dir := filepath.Join(root, vmID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir spool dir: %v", err)
	}
	w, err := spool.OpenWriter(dir, spool.WriterCfg{
		VMID:            vmID,
		InstanceID:      statusInstance,
		MaxSegmentBytes: 4 << 20,
		MaxSpoolBytes:   quota,
		LossRecord:      lossRecordFor(vmID),
	})
	if err != nil {
		t.Fatalf("OpenWriter: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

// fillSpoolQuota creates a sparse ballast.vmsp in dir as large as quota. The
// writer counts every *.vmsp file toward its quota, so the spool is then full
// while the disk is not; the importer reads only segment names and ignores
// it. It returns the ballast's path.
func fillSpoolQuota(t *testing.T, dir string, quota int64) string {
	t.Helper()
	ballast := filepath.Join(dir, "ballast.vmsp")
	if err := os.WriteFile(ballast, nil, 0o600); err != nil {
		t.Fatalf("create ballast: %v", err)
	}
	if err := os.Truncate(ballast, quota); err != nil {
		t.Fatalf("size ballast: %v", err)
	}
	return ballast
}

// refuseAppend appends a record the full spool must refuse.
func refuseAppend(t *testing.T, w *spool.Writer, vmID, seq string) {
	t.Helper()
	if err := w.Append(makeSpoolEnvelope(vmID, statusInstance, seq)); !errors.Is(err, spool.ErrSpoolFull) {
		t.Fatalf("append to a full spool: %v, want ErrSpoolFull", err)
	}
}

// importCycle runs one import cycle, which must succeed.
func importCycle(t *testing.T, imp *spool.Importer) {
	t.Helper()
	if _, err := imp.ImportOnce(t.Context()); err != nil {
		t.Fatalf("ImportOnce: %v", err)
	}
}

// writerStatus returns the writer health on vmID's import status, failing the
// test when there is none.
func writerStatus(t *testing.T, imp *spool.Importer, vmID string) spool.WriterHealth {
	t.Helper()
	w := imp.Status(vmID).Writer
	if w == nil {
		t.Fatalf("the import status of %s has no writer", vmID)
	}
	return *w
}

// A VM's import status carries its writer's health as the status file said
// at the last cycle: unknown before any cycle read it, then healthy, failing
// and healthy again as an outage opens and its loss lands. The root status
// has no writer, and a VM dir that vanishes takes its entry with it.
func TestWriterStatusFollowsTheFileEachCycle(t *testing.T) {
	st := openTestStore(t)
	root := t.TempDir()
	vm := "aaaabbbb-cccc-dddd-eeee-ffffffff0001"
	const quota = 64 << 10
	w := openStatusWriter(t, root, vm, quota)
	imp := spool.NewImporter(st, root, time.Second, nil)
	if got := writerStatus(t, imp, vm); got != (spool.WriterHealth{State: "unknown"}) {
		t.Errorf("before any cycle the writer is %+v, want unknown", got)
	}
	importCycle(t, imp)
	if got := imp.Status("").Writer; got != nil {
		t.Errorf("the root status has a writer: %+v", *got)
	}
	opened := writerStatus(t, imp, vm)
	if opened.State != "healthy" || opened.Since == "" || opened.InstanceID != statusInstance || opened.RunnerRecordsRefused != "0" || opened.GuestPushesRefused != "0" {
		t.Fatalf("after a cycle the writer is %+v, want healthy since its open", opened)
	}

	ballast := fillSpoolQuota(t, filepath.Join(root, vm), quota)
	refuseAppend(t, w, vm, "0")
	if got := writerStatus(t, imp, vm); got != opened {
		t.Errorf("between cycles the writer is %+v, want the last cycle's %+v", got, opened)
	}
	importCycle(t, imp)
	failing := writerStatus(t, imp, vm)
	if failing.State != "failing" || failing.Since == opened.Since || failing.Cause != spool.ErrSpoolFull.Error() || failing.LastError != spool.ErrSpoolFull.Error() || failing.RunnerRecordsRefused != "1" || failing.GuestPushesRefused != "0" {
		t.Errorf("after a refusal the writer is %+v, want failing since the refusal with one runner record refused", failing)
	}

	if err := os.Remove(ballast); err != nil {
		t.Fatalf("remove the ballast: %v", err)
	}
	if err := w.Append(makeSpoolEnvelope(vm, statusInstance, "1")); err != nil {
		t.Fatalf("append after the quota freed: %v", err)
	}
	importCycle(t, imp)
	recovered := writerStatus(t, imp, vm)
	if recovered.State != "healthy" || recovered.Since <= failing.Since || recovered.Cause != "" || recovered.RunnerRecordsRefused != "0" {
		t.Errorf("after the loss landed the writer is %+v, want healthy since the landing", recovered)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := os.RemoveAll(filepath.Join(root, vm)); err != nil {
		t.Fatalf("remove the VM's spool dir: %v", err)
	}
	importCycle(t, imp)
	if got := writerStatus(t, imp, vm); got != (spool.WriterHealth{State: "unknown"}) {
		t.Errorf("after the VM's dir vanished the writer is %+v, want unknown", got)
	}
}

// A VM whose import is backing off still has its writer's status read every
// cycle of Run, so a failing writer shows while the import waits a minute.
func TestWriterStatusReadWhileImportBacksOff(t *testing.T) {
	st := openTestStore(t)
	root := t.TempDir()
	vm := "aaaabbbb-cccc-dddd-eeee-ffffffff0001"
	const quota = 64 << 10
	w := openStatusWriter(t, root, vm, quota)
	dir := filepath.Join(root, vm)
	if err := os.Mkdir(filepath.Join(dir, "cursor.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	imp := spool.NewImporter(st, root, 10*time.Millisecond, nil)
	// Repeated real failures reach the one-minute cap.
	for range 15 {
		if _, err := imp.ImportOnce(t.Context()); err == nil {
			t.Fatal("a cursor that is a directory did not fail the import")
		}
	}
	fillSpoolQuota(t, dir, quota)
	refuseAppend(t, w, vm, "0")
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- imp.Run(ctx) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(3 * time.Second)
	for writerStatus(t, imp, vm).State != "failing" {
		if time.Now().After(deadline) {
			t.Fatalf("the writer still reads %+v under Run, want failing", writerStatus(t, imp, vm))
		}
		time.Sleep(time.Millisecond)
	}
	if got := imp.Status(vm).ConsecutiveFailures; got != "15" {
		t.Errorf("consecutive failures %s, want 15: Run imported a VM that was backing off", got)
	}
}

// The importer reports a failing writer once per outage: on the first cycle
// that reads it failing, again on later cycles while the report fails, and
// not again until an outage with another Since. An unknown read is not a
// recovery, so an outage that reads unknown for a cycle is not reported
// twice.
func TestWriterFailureReportedOncePerOutage(t *testing.T) {
	st := openTestStore(t)
	root := t.TempDir()
	vm := "aaaabbbb-cccc-dddd-eeee-ffffffff0001"
	dir := filepath.Join(root, vm)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	imp := spool.NewImporter(st, root, time.Second, nil)
	var reports []spool.WriterHealth
	refuseReport := true
	imp.SetWriterFailureReporter(func(_ context.Context, id string, h spool.WriterHealth) error {
		if id != vm {
			t.Errorf("reported VM %q, want %q", id, vm)
		}
		reports = append(reports, h)
		if refuseReport {
			refuseReport = false
			return errors.New("attention store unavailable")
		}
		return nil
	})
	expect := func(when string, n int) {
		t.Helper()
		if len(reports) != n {
			t.Fatalf("%s: %d reports, want %d", when, len(reports), n)
		}
	}

	importCycle(t, imp)
	expect("with no status file", 0)
	const quota = 64 << 10
	w := openStatusWriter(t, root, vm, quota)
	importCycle(t, imp)
	expect("while healthy", 0)

	ballast := fillSpoolQuota(t, dir, quota)
	refuseAppend(t, w, vm, "0")
	importCycle(t, imp)
	expect("on the first failing read, whose report fails", 1)
	importCycle(t, imp)
	expect("on the next cycle, whose report succeeds", 2)
	first := writerStatus(t, imp, vm)
	if reports[1] != first || first.State != "failing" || first.Cause != spool.ErrSpoolFull.Error() {
		t.Errorf("reported %+v, want the failing status %+v", reports[1], first)
	}
	refuseAppend(t, w, vm, "1")
	importCycle(t, imp)
	importCycle(t, imp)
	expect("after more refusals in the same outage", 2)

	if err := os.WriteFile(filepath.Join(dir, "writer.status"), make([]byte, 4096), 0o600); err != nil {
		t.Fatalf("zero the status file: %v", err)
	}
	importCycle(t, imp)
	if got := writerStatus(t, imp, vm); got.State != "unknown" {
		t.Fatalf("a zeroed status file reads %+v, want unknown", got)
	}
	refuseAppend(t, w, vm, "2")
	importCycle(t, imp)
	if got := writerStatus(t, imp, vm); got.State != "failing" || got.Since != first.Since {
		t.Fatalf("after the next refusal the writer is %+v, want failing since %s", got, first.Since)
	}
	expect("when the same outage reads failing after an unknown read", 2)

	if err := os.Remove(ballast); err != nil {
		t.Fatalf("remove the ballast: %v", err)
	}
	if err := w.Append(makeSpoolEnvelope(vm, statusInstance, "3")); err != nil {
		t.Fatalf("append after the quota freed: %v", err)
	}
	importCycle(t, imp)
	expect("after the loss landed", 2)

	fillSpoolQuota(t, dir, quota)
	refuseAppend(t, w, vm, "4")
	importCycle(t, imp)
	expect("on a new outage", 3)
	if reports[2].Since == first.Since {
		t.Errorf("the new outage was reported with the old Since %s", first.Since)
	}
}
