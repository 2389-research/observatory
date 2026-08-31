// ABOUTME: Tests the durable attention queue: raise-with-event atomicity,
// ABOUTME: collapse, overflow refusal, durable ack, and the trigger cursor.
package store_test

import (
	"errors"
	"strconv"
	"testing"

	"github.com/2389-research/observatory-v2/internal/store"
)

func raiseInput(class string, vm *string) store.RaiseInput {
	return store.RaiseInput{
		TriggerClass:  class,
		Severity:      store.SeverityNeedsDecision,
		VMID:          vm,
		Summary:       "telemetry loss recorded",
		SystemAction:  "loss recorded as evidence; ingestion continuing",
		EvidenceLinks: []string{"/api/v1/events?kind=telemetry.loss"},
		Collapse:      true,
		QueueMax:      500,
	}
}

func TestRaiseCreatesItemAndEvent(t *testing.T) {
	s := openStore(t)
	ctx := t.Context()
	vm := testUUID(1)

	item, err := s.RaiseAttention(ctx, raiseInput("telemetry_degraded", &vm))
	if err != nil {
		t.Fatalf("raise: %v", err)
	}
	if item == nil {
		t.Fatal("raise refused without cause")
	}
	if item.AttentionID == 0 || item.Count != 1 || item.Acked {
		t.Errorf("item = %+v", item)
	}
	if item.VMID == nil || *item.VMID != vm {
		t.Errorf("vm scope lost: %+v", item.VMID)
	}

	// The raise is also a durable attention.raised event (P-08: the queue is a
	// view over attention.* events plus ack state).
	res, err := s.Query(ctx, store.Query{Kind: "attention.raised"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("attention.raised events = %d, want 1", len(res.Events))
	}
	ev := res.Events[0]
	if ev.VMID != nil {
		t.Error("attention events are host-wide; vm linkage lives in data")
	}
	if got := ev.Data["attention_id"]; got != strconv.FormatInt(item.AttentionID, 10) {
		t.Errorf("event data attention_id = %v", got)
	}
	if got, _ := ev.Data["vm_id"].(string); got != vm {
		t.Errorf("event data vm_id = %v", ev.Data["vm_id"])
	}
	if raised := strconv.FormatInt(item.RaisedEventID, 10); *ev.EventID != raised {
		t.Errorf("item raised_event_id %s != event id %s", raised, *ev.EventID)
	}
}

func TestRaiseCollapsesDuplicates(t *testing.T) {
	s := openStore(t)
	ctx := t.Context()
	vm := testUUID(1)

	first, err := s.RaiseAttention(ctx, raiseInput("telemetry_degraded", &vm))
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.RaiseAttention(ctx, raiseInput("telemetry_degraded", &vm))
	if err != nil {
		t.Fatal(err)
	}
	if second.AttentionID != first.AttentionID {
		t.Fatalf("duplicate raised new item %d, want collapse into %d", second.AttentionID, first.AttentionID)
	}
	if second.Count != 2 {
		t.Errorf("count = %d, want 2", second.Count)
	}
	if second.LastEventID <= first.LastEventID {
		t.Errorf("last_event_id did not advance: %d -> %d", first.LastEventID, second.LastEventID)
	}

	// Different vm scope: a separate condition, no collapse.
	otherVM := testUUID(2)
	other, err := s.RaiseAttention(ctx, raiseInput("telemetry_degraded", &otherVM))
	if err != nil {
		t.Fatal(err)
	}
	if other.AttentionID == first.AttentionID {
		t.Error("different vm collapsed into same item")
	}

	// Acked items stop collapsing: a recurrence is a fresh condition.
	if _, err := s.AckAttention(ctx, first.AttentionID); err != nil {
		t.Fatal(err)
	}
	fresh, err := s.RaiseAttention(ctx, raiseInput("telemetry_degraded", &vm))
	if err != nil {
		t.Fatal(err)
	}
	if fresh.AttentionID == first.AttentionID {
		t.Error("raise collapsed into an acked item")
	}

	// Collapse disabled: every raise is its own item.
	in := raiseInput("telemetry_degraded", &otherVM)
	in.Collapse = false
	uncollapsed, err := s.RaiseAttention(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if uncollapsed.AttentionID == other.AttentionID {
		t.Error("collapse=false still collapsed")
	}
}

func TestQueueOverflowRefusesNonCriticalRecordsHealth(t *testing.T) {
	s := openStore(t)
	ctx := t.Context()

	in := raiseInput("telemetry_degraded", nil)
	in.Collapse = false
	in.QueueMax = 2
	for i := 0; i < 2; i++ {
		if item, err := s.RaiseAttention(ctx, in); err != nil || item == nil {
			t.Fatalf("raise %d: item=%v err=%v", i, item, err)
		}
	}

	// Third non-critical raise: refused, and the refusal is itself evidence.
	item, err := s.RaiseAttention(ctx, in)
	if err != nil {
		t.Fatalf("overflow refusal must not error: %v", err)
	}
	if item != nil {
		t.Fatalf("queue over max accepted non-critical item %+v", item)
	}
	res, err := s.Query(ctx, store.Query{Kind: "attention.queue_overflow"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("overflow health events = %d, want 1", len(res.Events))
	}
	if got, _ := res.Events[0].Data["trigger_class"].(string); got != "telemetry_degraded" {
		t.Errorf("overflow event data = %+v", res.Events[0].Data)
	}

	// Critical items are never refused (SPEC §12.7 / failure table).
	crit := in
	crit.Severity = store.SeverityCritical
	critItem, err := s.RaiseAttention(ctx, crit)
	if err != nil || critItem == nil {
		t.Fatalf("critical raise past cap: item=%v err=%v", critItem, err)
	}
}

func TestAckDurableAndIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/events.sqlite"
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()

	item, err := s.RaiseAttention(ctx, raiseInput("telemetry_degraded", nil))
	if err != nil {
		t.Fatal(err)
	}

	acked, err := s.AckAttention(ctx, item.AttentionID)
	if err != nil {
		t.Fatalf("ack: %v", err)
	}
	if !acked.Acked || acked.AckedAt == nil {
		t.Errorf("acked item = %+v", acked)
	}

	// Idempotent: acking twice succeeds and stays acked.
	again, err := s.AckAttention(ctx, item.AttentionID)
	if err != nil || !again.Acked {
		t.Errorf("second ack: %+v, %v", again, err)
	}

	if _, err := s.AckAttention(ctx, 99999); !errors.Is(err, store.ErrAttentionUnknown) {
		t.Errorf("unknown id error = %v", err)
	}

	// Ack survives restart (AT-090).
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	items, err := s2.ListAttention(ctx, store.AttentionQuery{IncludeAcked: true, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || !items[0].Acked {
		t.Fatalf("after reopen: %+v", items)
	}
	open, err := s2.ListAttention(ctx, store.AttentionQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 0 {
		t.Errorf("acked item still in default view: %+v", open)
	}
}

func TestAttentionListKeysetAndHead(t *testing.T) {
	s := openStore(t)
	ctx := t.Context()

	in := raiseInput("telemetry_degraded", nil)
	in.Collapse = false
	for i := 0; i < 3; i++ {
		if _, err := s.RaiseAttention(ctx, in); err != nil {
			t.Fatal(err)
		}
	}
	crit := in
	crit.Severity = store.SeverityCritical
	critItem, err := s.RaiseAttention(ctx, crit)
	if err != nil {
		t.Fatal(err)
	}

	// Keyset: two pages of two.
	page1, err := s.ListAttention(ctx, store.AttentionQuery{Limit: 2})
	if err != nil || len(page1) != 2 {
		t.Fatalf("page1: %v %v", page1, err)
	}
	page2, err := s.ListAttention(ctx, store.AttentionQuery{After: page1[1].AttentionID, Limit: 2})
	if err != nil || len(page2) != 2 {
		t.Fatalf("page2: %v %v", page2, err)
	}
	if page2[0].AttentionID <= page1[1].AttentionID {
		t.Error("keyset order broken")
	}

	// Head orders severity first: the critical item leads despite being newest.
	head, err := s.OpenAttentionHead(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(head) != 2 || head[0].AttentionID != critItem.AttentionID {
		t.Errorf("head = %+v", head)
	}

	n, err := s.CountOpenAttention(ctx)
	if err != nil || n != 4 {
		t.Errorf("open count = %d, %v", n, err)
	}
}

func TestEngineCursorAdvancesWithRaise(t *testing.T) {
	s := openStore(t)
	ctx := t.Context()

	c, err := s.ReadEngineCursor(ctx, "attention_triggers")
	if err != nil || c != 0 {
		t.Fatalf("fresh cursor = %d, %v", c, err)
	}

	in := raiseInput("telemetry_degraded", nil)
	in.CursorName = "attention_triggers"
	in.CursorTo = 41
	if _, err := s.RaiseAttention(ctx, in); err != nil {
		t.Fatal(err)
	}
	c, err = s.ReadEngineCursor(ctx, "attention_triggers")
	if err != nil || c != 41 {
		t.Errorf("cursor after raise = %d, %v", c, err)
	}

	if err := s.AdvanceEngineCursor(ctx, "attention_triggers", 55); err != nil {
		t.Fatal(err)
	}
	c, _ = s.ReadEngineCursor(ctx, "attention_triggers")
	if c != 55 {
		t.Errorf("cursor after advance = %d", c)
	}
}

func TestCountOpenAttentionByVM(t *testing.T) {
	s := openStore(t)
	ctx := t.Context()
	vmA, vmB := testUUID(1), testUUID(2)

	// Two classes on A (collapse is per class+vm), one on B, one host-scoped.
	itemA, err := s.RaiseAttention(ctx, raiseInput("telemetry_degraded", &vmA))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RaiseAttention(ctx, raiseInput("lifecycle_failed", &vmA)); err != nil {
		t.Fatal(err)
	}
	itemB, err := s.RaiseAttention(ctx, raiseInput("telemetry_degraded", &vmB))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RaiseAttention(ctx, raiseInput("capacity_exhausted", nil)); err != nil {
		t.Fatal(err)
	}

	counts, err := s.CountOpenAttentionByVM(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counts[vmA] != 2 || counts[vmB] != 1 {
		t.Errorf("counts = %v, want %s:2 %s:1", counts, vmA, vmB)
	}
	if len(counts) != 2 {
		t.Errorf("host-scoped item leaked into per-VM counts: %v", counts)
	}

	// Acked items leave the count; a fully acked VM leaves the map.
	if _, err := s.AckAttention(ctx, itemA.AttentionID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AckAttention(ctx, itemB.AttentionID); err != nil {
		t.Fatal(err)
	}
	counts, err = s.CountOpenAttentionByVM(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counts[vmA] != 1 {
		t.Errorf("count for %s after ack = %d, want 1", vmA, counts[vmA])
	}
	if _, present := counts[vmB]; present {
		t.Errorf("%s still in counts after its only item was acked: %v", vmB, counts)
	}
}
