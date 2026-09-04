// ABOUTME: The host's in-flight window (§8.3): bytes handed to a browser but
// ABOUTME: not yet acknowledged, bounded so a slow tab cannot grow the host.
package terminal

import "sync"

// Window bounds the bytes sent toward one browser and not yet acknowledged.
// At the limit the relay stops reading from the runner, which stops the runner
// reading vsock, which leaves the guest's ring to absorb the backlog and report
// what it drops. Every step of that chain is bounded and none of it is silent.
type Window struct {
	mu    sync.Mutex
	max   int64
	sent  uint64
	acked uint64
}

// NewWindow bounds unacknowledged bytes at max, starting from startOffset — a
// reattachment resumes at the guest ring's offset, not at zero, and the
// arithmetic has to start there or the first ack looks stale.
func NewWindow(max int64, startOffset uint64) *Window {
	if max <= 0 {
		max = 1
	}
	return &Window{max: max, sent: startOffset, acked: startOffset}
}

// Reserve claims room for n more bytes, reporting whether the window has it.
// A refusal is backpressure, not an error: the caller waits for an Ack.
func (w *Window) Reserve(n int) bool {
	if n <= 0 {
		return true
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if int64(w.sent-w.acked)+int64(n) > w.max {
		return false
	}
	w.sent += uint64(n)
	return true
}

// Ack records the browser's consumed offset. An offset behind the current one
// is not news — a stale ack would otherwise open the window on bytes nobody
// has read. An offset past everything sent is clamped: a browser cannot have
// consumed bytes it was never handed.
func (w *Window) Ack(offset uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if offset <= w.acked {
		return
	}
	if offset > w.sent {
		offset = w.sent
	}
	w.acked = offset
}

// InFlight is the number of sent-but-unacknowledged bytes.
func (w *Window) InFlight() int64 { return int64(w.sentMinusAcked()) }

// Available is the room left before Reserve starts refusing.
func (w *Window) Available() int64 { return w.max - int64(w.sentMinusAcked()) }

func (w *Window) sentMinusAcked() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.sent - w.acked
}
