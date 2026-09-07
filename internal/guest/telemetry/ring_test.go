// ABOUTME: Tests the guest's bounded telemetry ring: seq assigned at enqueue,
// ABOUTME: drop-oldest under pressure, ack-driven removal, and a drop count that never lies.
package telemetry_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/2389-research/observatory/internal/guest/telemetry"
)

func TestRingAssignsSeqAtEnqueue(t *testing.T) {
	r := telemetry.NewRing(4)
	for i := 0; i < 3; i++ {
		r.Push("guest.sensor_health", json.RawMessage(`{}`))
	}
	got := drainSeqs(t, r, 3)
	want := []string{"1", "2", "3"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("seqs = %v, want %v", got, want)
		}
	}
}

// Seq is assigned when the event happens, not when it is sent, because a
// re-send after a broken connection must carry the same seq for the store's
// dedup to recognise it. A seq assigned at send time would make every re-send
// a new event.
func TestRingKeepsSeqStableAcrossAFailedSend(t *testing.T) {
	r := telemetry.NewRing(4)
	r.Push("guest.sensor_health", json.RawMessage(`{"n":1}`))
	first, ok := r.Next()
	if !ok {
		t.Fatal("Next on a non-empty ring returned nothing")
	}
	r.Advance() // the write returned, but no ack came back

	// The connection broke. A new one rewinds and re-sends the same event.
	r.Rewind()
	again, ok := r.Next()
	if !ok {
		t.Fatal("an unacknowledged event vanished when the connection broke")
	}
	if again.Seq != first.Seq {
		t.Fatalf("seq changed across a re-send: %q then %q", first.Seq, again.Seq)
	}
}

// A write that returned proves the bytes reached a kernel buffer, not that the
// host kept them. Only the ack releases the item; §507 forbids loss nobody
// counted, and an item dropped at write time is exactly that.
func TestRingHoldsWhatItSentUntilTheHostAcknowledges(t *testing.T) {
	r := telemetry.NewRing(4)
	r.Push("guest.sensor_health", json.RawMessage(`{}`))
	r.Push("guest.sensor_health", json.RawMessage(`{}`))
	it, _ := r.Next()
	r.Advance()
	it2, _ := r.Next()
	r.Advance()

	if got := r.Stats().Queued; got != 2 {
		t.Fatalf("queued = %d after writing both, want 2 — a written event is not a delivered one", got)
	}
	r.AckThrough(it.Seq)
	if got := r.Stats().Queued; got != 1 {
		t.Fatalf("queued = %d after acking %s, want 1", got, it.Seq)
	}
	r.AckThrough(it2.Seq)
	if got := r.Stats().Queued; got != 0 {
		t.Fatalf("queued = %d after acking both, want 0", got)
	}
	// The cursor survived the acks: nothing is left to send.
	if _, ok := r.Next(); ok {
		t.Fatal("Next returned an item after every event was acknowledged")
	}
}

// A cumulative ack releases everything up to it, which is what lets the host
// ack once per batch rather than once per event.
func TestRingAckIsCumulative(t *testing.T) {
	r := telemetry.NewRing(8)
	for i := 0; i < 5; i++ {
		r.Push("guest.sensor_health", json.RawMessage(`{}`))
	}
	r.AckThrough("3")
	if got := r.Stats().Queued; got != 2 {
		t.Fatalf("queued = %d after acking through 3 of 5, want 2", got)
	}
	next, ok := r.Next()
	if !ok || next.Seq != "4" {
		t.Fatalf("next = %+v ok=%v, want seq 4", next, ok)
	}
}

// Garbage from the wire must not empty the ring. The host is trusted ingress,
// not a trusted correctness oracle.
func TestRingIgnoresAnUnparseableAck(t *testing.T) {
	r := telemetry.NewRing(4)
	r.Push("guest.sensor_health", json.RawMessage(`{}`))
	r.AckThrough("not-a-number")
	if got := r.Stats().Queued; got != 1 {
		t.Fatalf("queued = %d after a junk ack, want 1", got)
	}
}

func TestRingDropsOldestAndCounts(t *testing.T) {
	r := telemetry.NewRing(3)
	for i := 0; i < 5; i++ {
		r.Push("guest.sensor_health", json.RawMessage(`{}`))
	}
	st := r.Stats()
	if st.Queued != 3 {
		t.Errorf("queued = %d, want 3 (capacity)", st.Queued)
	}
	if st.Dropped != "2" {
		t.Errorf("dropped = %q, want \"2\"", st.Dropped)
	}
	// The survivors are the newest three: 3, 4, 5.
	got := drainSeqs(t, r, 3)
	for i, want := range []string{"3", "4", "5"} {
		if got[i] != want {
			t.Fatalf("survivors = %v, want [3 4 5] — the ring must drop the oldest", got)
		}
	}
}

// The count never resets while the agent lives: a reader comparing two
// heartbeats subtracts, and a counter that restarts makes that subtraction lie.
func TestRingDropCountDoesNotResetOnDrain(t *testing.T) {
	r := telemetry.NewRing(1)
	r.Push("guest.sensor_health", json.RawMessage(`{}`))
	r.Push("guest.sensor_health", json.RawMessage(`{}`))
	r.AckThrough("2")
	if got := r.Stats().Dropped; got != "1" {
		t.Fatalf("dropped = %q after draining, want \"1\"", got)
	}
}

func TestRingStatsCounterIsADecimalString(t *testing.T) {
	b, err := json.Marshal(telemetry.RingStats{Capacity: 4, Queued: 0, Dropped: "9007199254740993"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"dropped":"9007199254740993"`) {
		t.Fatalf("dropped rendered as %s; a count past 2^53 must be a decimal string", b)
	}
}

func drainSeqs(t *testing.T, r *telemetry.Ring, n int) []string {
	t.Helper()
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		it, ok := r.Next()
		if !ok {
			t.Fatalf("ring emptied after %d of %d items", i, n)
		}
		out = append(out, it.Seq)
		r.Advance()
		r.AckThrough(it.Seq)
	}
	return out
}
