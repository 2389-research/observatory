// ABOUTME: Lease tests: one writer at a time, a grace window that survives a
// ABOUTME: reload, and a steal that takes the shell back immediately.
package terminal_test

import (
	"sync"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/terminal"
)

// testClock is a hand-wound clock. The lease's grace window is 30 seconds in
// production; a test that slept through it would be a test nobody runs.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *testClock {
	return &testClock{now: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)}
}
func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}
func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestFirstAcquireWins(t *testing.T) {
	clk := newClock()
	l := terminal.NewLease(30*time.Second, clk.Now)

	ok, holder := l.Acquire("conn-a")
	if !ok {
		t.Fatalf("the first acquire was refused; holder = %q", holder)
	}
	if holder != "conn-a" {
		t.Errorf("holder = %q, want conn-a", holder)
	}
	if !l.IsWriter("conn-a") {
		t.Error("the holder is not the writer")
	}
}

func TestSecondAttachIsReadOnlyAndSaysWhy(t *testing.T) {
	clk := newClock()
	l := terminal.NewLease(30*time.Second, clk.Now)
	l.Acquire("conn-a")

	ok, holder := l.Acquire("conn-b")
	if ok {
		t.Fatal("two writers on one shell; the lease admitted a second holder")
	}
	if holder != "conn-a" {
		t.Errorf("a refused acquire returned holder %q; a read-only viewer must be told who has the shell", holder)
	}
	if l.IsWriter("conn-b") {
		t.Error("the second connection reports itself a writer")
	}
}

func TestStealTakesTheShellImmediately(t *testing.T) {
	clk := newClock()
	l := terminal.NewLease(30*time.Second, clk.Now)
	l.Acquire("conn-a")

	prev := l.Steal("conn-b")
	if prev != "conn-a" {
		t.Errorf("Steal reported previous holder %q, want conn-a", prev)
	}
	if !l.IsWriter("conn-b") {
		t.Error("the thief is not the writer")
	}
	// §8.2: the old writer's input is refused from that instant, not on its
	// next reconnect.
	if l.IsWriter("conn-a") {
		t.Error("the old holder still reports itself a writer after a steal")
	}
}

func TestReleaseKeepsTheLeaseForTheGraceWindow(t *testing.T) {
	clk := newClock()
	l := terminal.NewLease(30*time.Second, clk.Now)
	l.Acquire("conn-a")

	l.Release("conn-a")
	if got := l.Holder(); got != "conn-a" {
		t.Errorf("holder = %q right after release; the grace window exists so a reload does not lose the shell", got)
	}
	clk.advance(29 * time.Second)
	if ok, holder := l.Acquire("conn-b"); ok {
		t.Errorf("a bystander took the shell %v into a 30s grace window (holder was %q)", 29*time.Second, holder)
	}

	clk.advance(2 * time.Second)
	if ok, _ := l.Acquire("conn-b"); !ok {
		t.Error("the lease never expired; a departed writer holds the shell forever")
	}
}

func TestReconnectInsideTheGraceWindowKeepsTheLease(t *testing.T) {
	clk := newClock()
	l := terminal.NewLease(30*time.Second, clk.Now)
	l.Acquire("conn-a")
	l.Release("conn-a")

	clk.advance(10 * time.Second)
	if ok, holder := l.Acquire("conn-a"); !ok {
		t.Fatalf("the same connection could not reclaim its own lease; holder = %q", holder)
	}
	clk.advance(60 * time.Second)
	if !l.IsWriter("conn-a") {
		t.Error("reclaiming did not cancel the pending release; the lease expired anyway")
	}
}

func TestStealBeatsTheGraceWindow(t *testing.T) {
	clk := newClock()
	l := terminal.NewLease(30*time.Second, clk.Now)
	l.Acquire("conn-a")
	l.Release("conn-a")

	clk.advance(time.Second)
	if prev := l.Steal("conn-b"); prev != "conn-a" {
		t.Errorf("Steal inside the grace window reported %q", prev)
	}
	if !l.IsWriter("conn-b") {
		t.Error("a steal inside the grace window did not transfer the lease")
	}
}

func TestReleaseByANonHolderDoesNothing(t *testing.T) {
	clk := newClock()
	l := terminal.NewLease(30*time.Second, clk.Now)
	l.Acquire("conn-a")

	l.Release("conn-b")
	clk.advance(time.Hour)
	if !l.IsWriter("conn-a") {
		t.Error("a stranger's Release dropped the holder's lease")
	}
}
