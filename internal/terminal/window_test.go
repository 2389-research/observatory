// ABOUTME: Window tests: the host stops reading from the runner at the in-flight
// ABOUTME: bound, resumes on an ack, and never lets an ack run backwards.
package terminal_test

import (
	"testing"

	"github.com/2389-research/observatory-v2/internal/terminal"
)

func TestWindowRefusesPastTheInflightBound(t *testing.T) {
	w := terminal.NewWindow(1024, 0)

	if !w.Reserve(1024) {
		t.Fatal("a reserve of exactly the bound was refused")
	}
	if w.Reserve(1) {
		t.Fatal("the window admitted a byte past its bound; a slow browser can now grow the host without limit")
	}
	if got := w.InFlight(); got != 1024 {
		t.Errorf("in flight = %d, want 1024", got)
	}
}

func TestAnAckReopensTheWindow(t *testing.T) {
	w := terminal.NewWindow(1024, 0)
	w.Reserve(1024)

	w.Ack(512)
	if got := w.InFlight(); got != 512 {
		t.Errorf("in flight = %d after acking half, want 512", got)
	}
	if !w.Reserve(512) {
		t.Error("the window stayed shut after an ack freed room")
	}
	if w.Reserve(1) {
		t.Error("the window admitted a byte past its bound again")
	}
}

// An ack is a consumed-offset report from a browser, and a browser can send a
// stale one. Honouring it would open the window on bytes nobody has read.
func TestAnOldAckDoesNotMoveTheWindowBackwards(t *testing.T) {
	w := terminal.NewWindow(1024, 0)
	w.Reserve(1024)
	w.Ack(800)

	w.Ack(100)
	if got := w.InFlight(); got != 224 {
		t.Errorf("in flight = %d after a stale ack, want 224: an ack behind the current one is not news", got)
	}
}

// An ack past everything sent is a browser claiming to have consumed bytes that
// were never handed to it. Clamp rather than let in-flight go negative.
func TestAnAckPastTheSentOffsetIsClamped(t *testing.T) {
	w := terminal.NewWindow(1024, 0)
	w.Reserve(100)

	w.Ack(9999)
	if got := w.InFlight(); got != 0 {
		t.Errorf("in flight = %d after an impossible ack, want 0", got)
	}
	if !w.Reserve(1024) {
		t.Error("the window did not reopen after the clamped ack")
	}
}

// A reattachment resumes at the guest ring's offset, not at zero: the window's
// arithmetic has to start there or the first ack looks like a stale one.
func TestAWindowResumesAtAnOffset(t *testing.T) {
	w := terminal.NewWindow(1024, 9007199254740993)
	if !w.Reserve(64) {
		t.Fatal("a fresh window refused its first reserve")
	}
	w.Ack(9007199254741057)
	if got := w.InFlight(); got != 0 {
		t.Errorf("in flight = %d, want 0: the ack matched exactly what was sent", got)
	}
}
