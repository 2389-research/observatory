// ABOUTME: Tests the event store against real SQLite files: WAL/FULL settings,
// ABOUTME: cursor assignment, dedup, integrity failures, stream binding, keyset queries.
package store_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/events"
	"github.com/2389-research/observatory-v2/internal/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "events.sqlite"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func testUUID(n int) string {
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", n)
}

// fsModify builds a valid guest_reported fs.modify envelope for the given
// stream and scope.
func fsModify(source string, seq string, vm, boot *string) *events.Envelope {
	return &events.Envelope{
		SchemaVersion:    1,
		VMID:             vm,
		BootID:           boot,
		SourceInstanceID: source,
		SourceSeq:        seq,
		Kind:             "fs.modify",
		Provenance:       events.GuestReported,
		Sensor:           "fanotify",
		HostReceivedAt:   events.Timestamp{Time: time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)},
		Quality: events.Quality{
			PathResolution: events.PathExactAtCapture,
			Attribution:    events.AttributionExact,
		},
		Data: map[string]any{"path_display": "/workspace/app.py"},
	}
}

func mustAppend(t *testing.T, s *store.Store, env *events.Envelope) store.AppendResult {
	t.Helper()
	res, err := s.Append(context.Background(), env)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	return res
}

func queryAll(t *testing.T, s *store.Store, q store.Query) store.QueryResult {
	t.Helper()
	res, err := s.Query(context.Background(), q)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	return res
}

func TestOpenSetsWALFullAndStartsEmpty(t *testing.T) {
	s := openStore(t)
	diag, err := s.Diagnostics(context.Background())
	if err != nil {
		t.Fatalf("diagnostics: %v", err)
	}
	if diag.JournalMode != "wal" {
		t.Errorf("journal_mode = %q, want wal", diag.JournalMode)
	}
	if diag.Synchronous != "full" {
		t.Errorf("synchronous = %q, want full", diag.Synchronous)
	}
	res := queryAll(t, s, store.Query{})
	if len(res.Events) != 0 || res.LatestEventID != "" {
		t.Errorf("fresh store not empty: %d events, latest %q", len(res.Events), res.LatestEventID)
	}
}

func TestAppendAssignsSequentialCursor(t *testing.T) {
	s := openStore(t)
	vm, boot := testUUID(1), testUUID(2)
	for i := 1; i <= 3; i++ {
		res := mustAppend(t, s, fsModify(testUUID(9), strconv.Itoa(i), &vm, &boot))
		if res.EventID != strconv.Itoa(i) {
			t.Errorf("event %d assigned id %q", i, res.EventID)
		}
		if res.Deduped {
			t.Errorf("fresh event %d marked deduped", i)
		}
	}
}

func TestAppendRejectsPresetEventID(t *testing.T) {
	s := openStore(t)
	vm, boot := testUUID(1), testUUID(2)
	env := fsModify(testUUID(9), "1", &vm, &boot)
	preset := "77"
	env.EventID = &preset
	if _, err := s.Append(context.Background(), env); !errors.Is(err, store.ErrEventIDPreset) {
		t.Errorf("preset event_id: err = %v", err)
	}
}

func TestAppendRejectsInvalidEnvelope(t *testing.T) {
	s := openStore(t)
	vm, boot := testUUID(1), testUUID(2)
	env := fsModify(testUUID(9), "007", &vm, &boot) // leading-zero seq
	if _, err := s.Append(context.Background(), env); err == nil {
		t.Error("invalid envelope accepted")
	}
}

func TestAppendRejectsUnregisteredKindAndRecordsHealth(t *testing.T) {
	s := openStore(t)
	vm, boot := testUUID(1), testUUID(2)
	env := fsModify(testUUID(9), "1", &vm, &boot)
	env.Kind = "no.such_thing"
	_, err := s.Append(context.Background(), env)
	if !errors.Is(err, store.ErrUnregisteredKind) {
		t.Fatalf("unregistered kind: err = %v", err)
	}
	if got := queryAll(t, s, store.Query{Kind: "no.such_thing"}); len(got.Events) != 0 {
		t.Error("unregistered event was persisted")
	}
	health := queryAll(t, s, store.Query{Kind: "telemetry.unregistered_kind"})
	if len(health.Events) != 1 {
		t.Fatalf("want 1 health event, got %d", len(health.Events))
	}
	h := health.Events[0]
	if h.VMID != nil || h.BootID != nil {
		t.Error("health event should be host-wide")
	}
	if h.Provenance != events.HostObserved {
		t.Errorf("health provenance = %q", h.Provenance)
	}
	if h.Data["kind"] != "no.such_thing" || h.Data["source_instance_id"] != testUUID(9) {
		t.Errorf("health data = %v", h.Data)
	}
}

func TestAppendRejectsProvenanceMismatch(t *testing.T) {
	s := openStore(t)
	vm, boot := testUUID(1), testUUID(2)
	env := fsModify(testUUID(9), "1", &vm, &boot)
	env.Provenance = events.HostObserved // registry says fs.modify is guest_reported
	if _, err := s.Append(context.Background(), env); !errors.Is(err, store.ErrProvenanceMismatch) {
		t.Errorf("provenance mismatch: err = %v", err)
	}
}

func TestDedupIdenticalResendIsSilent(t *testing.T) {
	s := openStore(t)
	vm, boot := testUUID(1), testUUID(2)
	first := mustAppend(t, s, fsModify(testUUID(9), "5", &vm, &boot))
	second := mustAppend(t, s, fsModify(testUUID(9), "5", &vm, &boot))
	if second.EventID != first.EventID {
		t.Errorf("dedup returned %q, want %q", second.EventID, first.EventID)
	}
	if !second.Deduped {
		t.Error("identical resend not marked deduped")
	}
	all := queryAll(t, s, store.Query{})
	if len(all.Events) != 1 {
		t.Errorf("store has %d events after dedup, want 1", len(all.Events))
	}
}

func TestConflictingResendRecordsIntegrityFailure(t *testing.T) {
	s := openStore(t)
	vm, boot := testUUID(1), testUUID(2)
	original := fsModify(testUUID(9), "5", &vm, &boot)
	res := mustAppend(t, s, original)

	conflict := fsModify(testUUID(9), "5", &vm, &boot)
	conflict.Data = map[string]any{"path_display": "/workspace/OTHER.py"}
	_, err := s.Append(context.Background(), conflict)
	if !errors.Is(err, store.ErrIntegrityFailure) {
		t.Fatalf("conflicting resend: err = %v", err)
	}

	stored := queryAll(t, s, store.Query{Kind: "fs.modify"})
	if len(stored.Events) != 1 {
		t.Fatalf("want original untouched, got %d fs.modify events", len(stored.Events))
	}
	if stored.Events[0].Data["path_display"] != "/workspace/app.py" {
		t.Errorf("original payload mutated: %v", stored.Events[0].Data)
	}

	health := queryAll(t, s, store.Query{Kind: "telemetry.integrity_failure"})
	if len(health.Events) != 1 {
		t.Fatalf("want 1 integrity health event, got %d", len(health.Events))
	}
	d := health.Events[0].Data
	if d["failure"] != "seq_payload_conflict" || d["source_instance_id"] != testUUID(9) ||
		d["source_seq"] != "5" || d["existing_event_id"] != res.EventID {
		t.Errorf("integrity data = %v", d)
	}
}

func TestStreamBindsVMScopeNotBoot(t *testing.T) {
	s := openStore(t)
	vmA, vmB := testUUID(1), testUUID(3)
	boot1, boot2 := testUUID(2), testUUID(4)
	source := testUUID(9)

	mustAppend(t, s, fsModify(source, "1", &vmA, &boot1))
	// Same VM, different boot: a per-VM producer outlives reboots.
	mustAppend(t, s, fsModify(source, "2", &vmA, &boot2))
	// Same VM, no boot yet.
	mustAppend(t, s, fsModify(source, "3", &vmA, nil))

	// Different VM: stream scope rebind, rejected and recorded.
	_, err := s.Append(context.Background(), fsModify(source, "4", &vmB, &boot1))
	if !errors.Is(err, store.ErrStreamScopeMismatch) {
		t.Fatalf("vm rebind: err = %v", err)
	}
	health := queryAll(t, s, store.Query{Kind: "telemetry.integrity_failure"})
	if len(health.Events) != 1 || health.Events[0].Data["failure"] != "stream_scope_rebind" {
		t.Errorf("rebind health record wrong: %+v", health.Events)
	}
}

func TestQueryKeysetPagination(t *testing.T) {
	s := openStore(t)
	vm, boot := testUUID(1), testUUID(2)
	for i := 1; i <= 250; i++ {
		mustAppend(t, s, fsModify(testUUID(9), strconv.Itoa(i), &vm, &boot))
	}

	page1 := queryAll(t, s, store.Query{})
	if len(page1.Events) != store.DefaultPageLimit {
		t.Fatalf("default page = %d events, want %d", len(page1.Events), store.DefaultPageLimit)
	}
	if page1.NextAfter != "200" || page1.LatestEventID != "250" {
		t.Errorf("page1 cursors: next %q latest %q", page1.NextAfter, page1.LatestEventID)
	}

	page2 := queryAll(t, s, store.Query{After: page1.NextAfter})
	if len(page2.Events) != 50 || page2.NextAfter != "250" {
		t.Errorf("page2: %d events, next %q", len(page2.Events), page2.NextAfter)
	}

	// Caught up: empty page still states how far the store goes (silence is evidence).
	page3 := queryAll(t, s, store.Query{After: "250"})
	if len(page3.Events) != 0 || page3.NextAfter != "250" || page3.LatestEventID != "250" {
		t.Errorf("page3: %d events, next %q, latest %q", len(page3.Events), page3.NextAfter, page3.LatestEventID)
	}
}

func TestQueryLimitAndCursorBounds(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	var bound *store.BoundError
	if _, err := s.Query(ctx, store.Query{Limit: store.MaxPageLimit + 1}); !errors.As(err, &bound) {
		t.Errorf("limit beyond max: err = %v", err)
	}
	if _, err := s.Query(ctx, store.Query{Limit: -1}); !errors.As(err, &bound) {
		t.Errorf("negative limit: err = %v", err)
	}
	if _, err := s.Query(ctx, store.Query{Limit: store.MaxPageLimit}); err != nil {
		t.Errorf("max limit rejected: %v", err)
	}
	if _, err := s.Query(ctx, store.Query{After: "not-a-cursor"}); !errors.Is(err, store.ErrInvalidCursor) {
		t.Errorf("bad cursor: err = %v", err)
	}
}

func TestQueryFiltersAndEnvelopeFidelity(t *testing.T) {
	s := openStore(t)
	vmA, vmB, boot := testUUID(1), testUUID(3), testUUID(2)
	mustAppend(t, s, fsModify(testUUID(9), "1", &vmA, &boot))
	mustAppend(t, s, fsModify(testUUID(8), "1", &vmB, &boot))
	mustAppend(t, s, fsModify(testUUID(9), "2", &vmA, &boot))

	res := queryAll(t, s, store.Query{VMID: &vmA})
	if len(res.Events) != 2 {
		t.Fatalf("vm filter returned %d events", len(res.Events))
	}
	prev := int64(0)
	for _, e := range res.Events {
		if e.EventID == nil {
			t.Fatal("queried event missing event_id")
		}
		id, err := strconv.ParseInt(*e.EventID, 10, 64)
		if err != nil || id <= prev {
			t.Errorf("cursor order broken at %v", e.EventID)
		}
		prev = id
		if e.VMID == nil || *e.VMID != vmA {
			t.Errorf("vm filter leaked event for %v", e.VMID)
		}
		if err := e.Validate(); err != nil {
			t.Errorf("stored envelope invalid: %v", err)
		}
		if e.Data["path_display"] != "/workspace/app.py" {
			t.Errorf("data did not round-trip: %v", e.Data)
		}
	}

	byKind := queryAll(t, s, store.Query{Kind: "telemetry.loss"})
	if len(byKind.Events) != 0 {
		t.Errorf("kind filter leaked %d events", len(byKind.Events))
	}
}

func TestReopenContinuesCursorAndStreamBindings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.sqlite")
	vm, vmB, boot := testUUID(1), testUUID(3), testUUID(2)

	s, err := store.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	mustAppend(t, s, fsModify(testUUID(9), "1", &vm, &boot))
	mustAppend(t, s, fsModify(testUUID(9), "2", &vm, &boot))
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2, err := store.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	res := mustAppend(t, s2, fsModify(testUUID(9), "3", &vm, &boot))
	if res.EventID != "3" {
		t.Errorf("cursor after reopen = %q, want 3", res.EventID)
	}
	if got := queryAll(t, s2, store.Query{}); len(got.Events) != 3 {
		t.Errorf("reopened store has %d events", len(got.Events))
	}
	// The stream binding must survive reopen too.
	if _, err := s2.Append(context.Background(), fsModify(testUUID(9), "4", &vmB, &boot)); !errors.Is(err, store.ErrStreamScopeMismatch) {
		t.Errorf("rebind after reopen: err = %v", err)
	}
}

func TestParallelAppendsSerialize(t *testing.T) {
	s := openStore(t)
	vm, boot := testUUID(1), testUUID(2)
	const producers, perProducer = 8, 10

	var wg sync.WaitGroup
	errs := make(chan error, producers*perProducer)
	ids := make(chan string, producers*perProducer)
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			source := testUUID(100 + p)
			for i := 1; i <= perProducer; i++ {
				res, err := s.Append(context.Background(), fsModify(source, strconv.Itoa(i), &vm, &boot))
				if err != nil {
					errs <- err
					return
				}
				ids <- res.EventID
			}
		}(p)
	}
	wg.Wait()
	close(errs)
	close(ids)
	for err := range errs {
		t.Errorf("parallel append: %v", err)
	}
	seen := map[string]bool{}
	for id := range ids {
		if seen[id] {
			t.Errorf("cursor %q assigned twice", id)
		}
		seen[id] = true
	}
	if len(seen) != producers*perProducer {
		t.Errorf("%d events stored, want %d", len(seen), producers*perProducer)
	}
	if latest := queryAll(t, s, store.Query{}).LatestEventID; latest != strconv.Itoa(producers*perProducer) {
		t.Errorf("latest cursor = %q", latest)
	}
}
