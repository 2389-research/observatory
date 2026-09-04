// ABOUTME: The per-session replay ring: a fixed window of the newest PTY output.
// ABOUTME: It never blocks the shell, and it never loses bytes without naming the range it lost.
package pty

// Range is a half-open span of stream offsets, [From, To).
type Range struct {
	From uint64
	To   uint64
}

// Ring holds the newest bytes of one PTY's output stream in a fixed buffer.
//
// Offsets are absolute positions in the stream, not indexes into the buffer, so
// a reader that reconnects can say exactly where it stopped. They are uint64
// because a busy shell passes 2^53 bytes in days, not years.
//
// A Ring has no reader and never waits for one: §8.1 requires that a detached
// session keeps running, so the shell writes into the ring whether or not any
// browser is attached. Overwriting old bytes is the declared behaviour at the
// limit, and Append reports the exact range it lost so the loss reaches the
// operator as terminal.dropped rather than as a silent hole.
//
// A Ring is not safe for concurrent use; the session that owns it serializes
// access.
type Ring struct {
	buf   []byte
	start int    // index in buf of the oldest byte held
	count int    // bytes held, at most len(buf)
	head  uint64 // stream offset one past the newest byte
}

// NewRing returns a ring holding the newest size bytes. A size below one byte
// is clamped rather than refused: the broker is responsible for applying the
// configured floor, and this is the last line of defence against a zero.
func NewRing(size int) *Ring {
	if size < 1 {
		size = 1
	}
	return &Ring{buf: make([]byte, size)}
}

// Head is the stream offset one past the newest byte held.
// Size is the ring's capacity in bytes: what the broker actually allocated,
// which is not always what the host asked for.
func (r *Ring) Size() int { return len(r.buf) }

func (r *Ring) Head() uint64 { return r.head }

// Tail is the stream offset of the oldest byte still held.
func (r *Ring) Tail() uint64 { return r.head - uint64(r.count) }

// seek places an empty ring at an absolute stream offset. Only tests use it,
// to reach magnitudes a test cannot write its way to.
func (r *Ring) seek(offset uint64) {
	r.head, r.start, r.count = offset, 0, 0
}

// Append writes p to the ring. When p pushes older bytes out, dropped names the
// exact range that is gone and lost is true; otherwise dropped is the zero
// Range and lost is false.
func (r *Ring) Append(p []byte) (dropped Range, lost bool) {
	if len(p) == 0 {
		return Range{}, false
	}
	before := r.Tail()

	if len(p) >= len(r.buf) {
		// Only the newest len(buf) bytes survive; the rest never enter the ring.
		copy(r.buf, p[len(p)-len(r.buf):])
		r.start, r.count = 0, len(r.buf)
	} else {
		end := (r.start + r.count) % len(r.buf)
		n := copy(r.buf[end:], p)
		copy(r.buf, p[n:])
		if over := r.count + len(p) - len(r.buf); over > 0 {
			r.start = (r.start + over) % len(r.buf)
			r.count = len(r.buf)
		} else {
			r.count += len(p)
		}
	}
	r.head += uint64(len(p))

	if after := r.Tail(); after > before {
		return Range{From: before, To: after}, true
	}
	return Range{}, false
}

// ReadFrom returns every byte held from offset onward, the offset to pass to
// the next call, and whether bytes between offset and the returned window were
// dropped.
//
// When offset is older than the tail the read resumes at the tail and gap is
// true; the caller learns where it resumed from next minus the length. An
// offset at or beyond the head returns no bytes and is not a gap: that reader
// is simply caught up.
func (r *Ring) ReadFrom(offset uint64) (b []byte, next uint64, gap bool) {
	tail := r.Tail()
	if offset < tail {
		offset, gap = tail, true
	}
	if offset >= r.head {
		return nil, r.head, gap
	}
	out := make([]byte, r.head-offset)
	from := (r.start + int(offset-tail)) % len(r.buf)
	n := copy(out, r.buf[from:])
	copy(out[n:], r.buf)
	return out, r.head, gap
}
