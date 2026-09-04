// ABOUTME: The reconnect ring's contract: exact offsets, exact drop ranges, no silent loss.
// ABOUTME: Portable — no PTY here, so this runs on every platform the repo builds on.
package pty

import (
	"bytes"
	"strings"
	"testing"
)

func TestRingKeepsEverythingUnderCapacity(t *testing.T) {
	r := NewRing(16)
	dropped, lost := r.Append([]byte("hello"))
	if lost {
		t.Fatalf("Append under capacity dropped %v", dropped)
	}
	if r.Tail() != 0 || r.Head() != 5 {
		t.Fatalf("tail/head = %d/%d, want 0/5", r.Tail(), r.Head())
	}

	b, next, gap := r.ReadFrom(0)
	if gap {
		t.Error("ReadFrom(0) reported a gap on a ring that has dropped nothing")
	}
	if string(b) != "hello" {
		t.Errorf("bytes = %q, want %q", b, "hello")
	}
	if next != 5 {
		t.Errorf("next = %d, want 5", next)
	}
}

func TestRingAppendPastCapacityNamesTheExactLostRange(t *testing.T) {
	r := NewRing(8)
	r.Append([]byte("abcdefgh")) // exactly full: nothing lost yet
	if r.Tail() != 0 {
		t.Fatalf("an exactly-full ring moved its tail to %d", r.Tail())
	}

	dropped, lost := r.Append([]byte("ijk"))
	if !lost {
		t.Fatal("Append past capacity reported no loss")
	}
	if dropped.From != 0 || dropped.To != 3 {
		t.Errorf("dropped = [%d,%d), want [0,3)", dropped.From, dropped.To)
	}
	if r.Tail() != 3 || r.Head() != 11 {
		t.Errorf("tail/head = %d/%d, want 3/11", r.Tail(), r.Head())
	}

	b, next, gap := r.ReadFrom(3)
	if gap {
		t.Error("ReadFrom(tail) reported a gap; the tail is still readable")
	}
	if string(b) != "defghijk" {
		t.Errorf("window = %q, want %q", b, "defghijk")
	}
	if next != 11 {
		t.Errorf("next = %d, want 11", next)
	}
}

func TestRingAppendLargerThanItselfKeepsTheNewestBytes(t *testing.T) {
	r := NewRing(4)
	dropped, lost := r.Append([]byte("abcdefghij"))
	if !lost {
		t.Fatal("an append longer than the ring reported no loss")
	}
	// Ten bytes arrived into four bytes of room: everything before offset 6 is gone.
	if dropped.From != 0 || dropped.To != 6 {
		t.Errorf("dropped = [%d,%d), want [0,6)", dropped.From, dropped.To)
	}
	b, next, gap := r.ReadFrom(0)
	if !gap {
		t.Error("ReadFrom(0) after a drop must report the gap")
	}
	if string(b) != "ghij" {
		t.Errorf("window = %q, want %q", b, "ghij")
	}
	if next != 10 {
		t.Errorf("next = %d, want 10", next)
	}
	if next-uint64(len(b)) != r.Tail() {
		t.Errorf("the returned bytes start at %d, not at the tail %d", next-uint64(len(b)), r.Tail())
	}
}

func TestRingReadFromOlderThanTailResumesAtTheTail(t *testing.T) {
	r := NewRing(8)
	r.Append([]byte("abcdefghijkl")) // tail is now 4

	b, next, gap := r.ReadFrom(1)
	if !gap {
		t.Fatal("ReadFrom(1) with a tail of 4 must report a gap, not silently skip")
	}
	if next-uint64(len(b)) != r.Tail() {
		t.Errorf("resumed at %d, want the tail %d", next-uint64(len(b)), r.Tail())
	}
	if string(b) != "efghijkl" {
		t.Errorf("window = %q, want %q", b, "efghijkl")
	}
}

func TestRingReadFromHeadIsEmptyAndNotAGap(t *testing.T) {
	r := NewRing(8)
	r.Append([]byte("abc"))

	b, next, gap := r.ReadFrom(3)
	if gap {
		t.Error("reading at the head is caught up, not a gap")
	}
	if len(b) != 0 {
		t.Errorf("bytes = %q, want none", b)
	}
	if next != 3 {
		t.Errorf("next = %d, want 3", next)
	}
}

func TestRingWrapsWithoutReorderingBytes(t *testing.T) {
	r := NewRing(5)
	for _, s := range []string{"ab", "cd", "ef", "gh"} {
		r.Append([]byte(s))
	}
	b, _, _ := r.ReadFrom(r.Tail())
	if string(b) != "defgh" {
		t.Errorf("window = %q, want %q — a wrapped read reassembled out of order", b, "defgh")
	}
}

func TestRingOffsetsStayExactPastTheJSSafeInteger(t *testing.T) {
	r := NewRing(8)
	// A busy shell passes 2^53 bytes in days, not years, so the ring is placed
	// there directly rather than pretending a test can write that much.
	const start = uint64(1) << 53
	r.seek(start)

	r.Append([]byte("abcdefgh"))
	dropped, lost := r.Append([]byte("ij"))
	if !lost {
		t.Fatal("Append past capacity reported no loss")
	}
	if dropped.From != start || dropped.To != start+2 {
		t.Errorf("dropped = [%d,%d), want [%d,%d)", dropped.From, dropped.To, start, start+2)
	}
	if r.Head() != start+10 {
		t.Errorf("head = %d, want %d", r.Head(), start+10)
	}
	b, next, gap := r.ReadFrom(start)
	if !gap {
		t.Error("an offset below the tail must report a gap at any magnitude")
	}
	if next != start+10 {
		t.Errorf("next = %d, want %d", next, start+10)
	}
	if string(b) != "cdefghij" {
		t.Errorf("window = %q, want %q", b, "cdefghij")
	}
}

func TestRingHoldsBinaryOutputUnchanged(t *testing.T) {
	// Terminal output is bytes, not text: escape sequences and NULs ride through.
	raw := []byte{0x1b, '[', '3', '1', 'm', 0x00, 0xff, '\n'}
	r := NewRing(64)
	r.Append(raw)
	b, _, _ := r.ReadFrom(0)
	if !bytes.Equal(b, raw) {
		t.Errorf("bytes = %v, want %v", b, raw)
	}
}

func TestRingAppendOfNothingChangesNothing(t *testing.T) {
	r := NewRing(8)
	r.Append([]byte("abc"))
	dropped, lost := r.Append(nil)
	if lost {
		t.Errorf("an empty append dropped %v", dropped)
	}
	if r.Head() != 3 {
		t.Errorf("head = %d, want 3", r.Head())
	}
}

func TestNewRingClampsAnUnusableSize(t *testing.T) {
	// The broker clamps what arrives on the wire; this is the last line of
	// defence, so a zero cannot divide by zero deeper in.
	r := NewRing(0)
	dropped, lost := r.Append([]byte(strings.Repeat("x", 100)))
	if !lost || dropped.From != 0 || dropped.To != 99 {
		t.Errorf("dropped = [%d,%d) lost=%v, want [0,99) lost=true", dropped.From, dropped.To, lost)
	}
	if r.Head() != 100 || r.Tail() != 99 {
		t.Errorf("tail/head = %d/%d, want 99/100 — a zero size holds one byte, not none", r.Tail(), r.Head())
	}
	b, next, gap := r.ReadFrom(99)
	if string(b) != "x" || next != 100 || gap {
		t.Errorf("ReadFrom(99) = %q, %d, %v; want \"x\", 100, false", b, next, gap)
	}
}
