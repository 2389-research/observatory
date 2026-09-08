// ABOUTME: Exercises import failure reporting and retry recovery with real disk and SQLite.
// ABOUTME: Keeps healthy VM progress independent from broken spool directories.
package spool_test

import (
	"context"
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
