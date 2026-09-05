// ABOUTME: The guest's bounded telemetry ring: fixed capacity, drop-oldest,
// ABOUTME: an explicit drop count, and a sequence assigned when the event happens.
package telemetry

import (
	"encoding/json"
	"strconv"
	"sync"
	"time"
)

// Item is one queued event waiting for the host. Seq is assigned at Push, not
// at send: a re-send after a broken connection must carry the same seq for the
// store's (source_instance_id, source_seq) dedup to recognise it as the event
// it already holds. A seq assigned at send time would turn every re-send into
// a new event.
type Item struct {
	Seq  string
	Kind string
	Data json.RawMessage
	// GuestWallAt and GuestMonotonicNS are stamped when the event was queued,
	// not when it is sent. The monotonic epoch is this ring's creation — the
	// agent's start, in practice — which is enough to order events within one
	// agent lifetime, and an agent restart is a new stream identity anyway.
	GuestWallAt      string
	GuestMonotonicNS string
}

// RingStats is the ring's self-report, rendered into every heartbeat.
type RingStats struct {
	Capacity int `json:"capacity"`
	Queued   int `json:"queued"`
	// Dropped is a decimal string: a long-lived agent under a stalled host can
	// exceed what a JSON number safely carries.
	Dropped string `json:"dropped"`
}

// Ring is a bounded FIFO of events the guest has observed and the host has not
// yet acknowledged. Bounded because §8.3 requires it: a host that stops reading
// must not stop the guest. Under pressure it drops the oldest — a stale event
// is worth less than the one that replaced it — and counts every drop, because
// §507 wants loss measured rather than inferred from a quiet stream.
//
// An item leaves the ring when the host acknowledges it, never when a write to
// the socket returned. A successful write means the bytes reached a kernel
// buffer, which is not evidence the host kept them; popping there would lose
// every in-flight event on a broken connection and count nothing. So the ring
// holds what it has sent, re-sends it on the next connection, and lets the
// bound do the forgetting where the drop is counted.
//
// Safe for concurrent use: sensors push while the sender drains.
type Ring struct {
	mu    sync.Mutex
	items []Item
	// sent is how many of items have been written on the current connection.
	// Rewind resets it, so a reconnect re-sends everything still unacknowledged.
	sent    int
	cap     int
	seq     uint64
	dropped uint64
	created time.Time
	// notify carries one pending wakeup for a waiting sender. Buffered at one
	// and written without blocking: a sender that is already awake needs no
	// second nudge, and a Push must never wait on a reader.
	notify chan struct{}
}

// NewRing returns a ring holding at most capacity items. A capacity below one
// is raised to one: a ring that drops everything reports honestly but observes
// nothing, and no caller means that.
func NewRing(capacity int) *Ring {
	if capacity < 1 {
		capacity = 1
	}
	return &Ring{
		cap:     capacity,
		items:   make([]Item, 0, capacity),
		created: time.Now(),
		notify:  make(chan struct{}, 1),
	}
}

// Push queues one event, assigning it the next sequence. When the ring is full
// the oldest item is dropped and counted.
func (r *Ring) Push(kind string, data json.RawMessage) {
	now := time.Now()
	r.mu.Lock()
	r.seq++
	if len(r.items) == r.cap {
		r.items = r.items[1:]
		r.dropped++
		if r.sent > 0 {
			// The dropped item may already have been written on this
			// connection; the send cursor counts items, so it moves with them.
			r.sent--
		}
	}
	r.items = append(r.items, Item{
		Seq:              strconv.FormatUint(r.seq, 10),
		Kind:             kind,
		Data:             data,
		GuestWallAt:      now.UTC().Format(time.RFC3339Nano),
		GuestMonotonicNS: strconv.FormatInt(now.Sub(r.created).Nanoseconds(), 10),
	})
	r.mu.Unlock()

	select {
	case r.notify <- struct{}{}:
	default:
	}
}

// Waiting returns the channel a sender blocks on while it has nothing to send.
// A receive means "something may be queued", never "exactly one item is
// queued": the sender calls Next again and loops.
func (r *Ring) Waiting() <-chan struct{} { return r.notify }

// Next returns the oldest item this connection has not written yet. It does not
// remove anything — only AckThrough does that.
func (r *Ring) Next() (Item, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sent >= len(r.items) {
		return Item{}, false
	}
	return r.items[r.sent], true
}

// Advance moves the send cursor past the item Next returned. Call it after a
// write returned, which says the item was offered to the host — not that the
// host has it.
func (r *Ring) Advance() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sent < len(r.items) {
		r.sent++
	}
}

// Rewind puts the send cursor back to the oldest unacknowledged item. A new
// connection calls it: whatever the previous connection wrote but never got
// acknowledged goes out again, and the host's dedup absorbs any duplicate.
func (r *Ring) Rewind() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = 0
	// A rewound cursor means there is something to send; wake the sender in
	// case it is blocked on an empty ring.
	select {
	case r.notify <- struct{}{}:
	default:
	}
}

// AckThrough forgets every item up to and including seq, which the host has
// reported it holds durably. An ack the ring cannot parse, or one naming an
// item already forgotten, changes nothing.
func (r *Ring) AckThrough(seq string) {
	n, err := strconv.ParseUint(seq, 10, 64)
	if err != nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	kept := 0
	for kept < len(r.items) {
		itemSeq, err := strconv.ParseUint(r.items[kept].Seq, 10, 64)
		if err != nil || itemSeq > n {
			break
		}
		kept++
	}
	if kept == 0 {
		return
	}
	r.items = r.items[kept:]
	r.sent -= kept
	if r.sent < 0 {
		r.sent = 0
	}
}

// Stats reports capacity, depth and the lifetime drop count. Queued counts
// what the host has not acknowledged, so it stays above zero while a send is in
// flight. The drop count never resets while the agent lives: a reader comparing
// two heartbeats subtracts them, and a counter that restarts makes that
// subtraction lie.
func (r *Ring) Stats() RingStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return RingStats{
		Capacity: r.cap,
		Queued:   len(r.items),
		Dropped:  strconv.FormatUint(r.dropped, 10),
	}
}
