// ABOUTME: Tests recoveryContext's budget arithmetic: one recovery budget per mutation tail, not one per derivation.
// ABOUTME: Internal test package — recoveryContext is unexported and its deadline is the whole claim.
package runtime

import (
	"context"
	"testing"
	"time"
)

type recoveryTestKey struct{}

// TestRecoveryContextIsIdempotent: a mutation's tail gets one recovery budget,
// however many times the code on that tail asks for one.
//
// The tails that matter derive twice. doAction's shared tail runs on
// recoveryContext(ctx) and then hands that context to failAction, which derives
// again; the start path's success branch does the same with okCtx. Two
// derivations meant two fresh recoveryBudgets stacked end to end, so a stop's
// worst case was 150 + 75 + 75 and a start's was 240 + 75 + 75 — 390s against a
// gate client priced at 330s, and against recoveryBudget's own sizing comment,
// which sizes one tail and not two.
//
// The sleep is here only so a re-derivation is unmistakable: under the bug the
// second deadline moves by however long elapsed between the two calls, and
// exact equality is what correct code returns, with no tolerance needed.
func TestRecoveryContextIsIdempotent(t *testing.T) {
	m := &Manager{}

	parent, parentCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer parentCancel()

	first, firstCancel := m.recoveryContext(parent)
	defer firstCancel()
	firstDeadline, ok := first.Deadline()
	if !ok {
		t.Fatal("recoveryContext returned a context with no deadline: unbounded, not budgeted")
	}

	time.Sleep(5 * time.Millisecond)

	second, secondCancel := m.recoveryContext(first)
	secondDeadline, ok := second.Deadline()
	if !ok {
		t.Fatal("re-derived recovery context has no deadline")
	}
	if !secondDeadline.Equal(firstDeadline) {
		t.Errorf("re-deriving moved the deadline by %v; the tail must get one recoveryBudget, not one per derivation",
			secondDeadline.Sub(firstDeadline))
	}

	// The cancel handed back on the idempotent path must be a no-op. failAction
	// defers it and returns, and the caller that owns the tail keeps using its
	// own context afterwards; a cancel that reached through would kill a budget
	// it does not own.
	secondCancel()
	if err := first.Err(); err != nil {
		t.Errorf("the re-derived cancel killed the caller's tail: %v", err)
	}
}

// TestRecoveryContextFreshFromOrdinaryParent is the other half: idempotency
// must not swallow the first derivation. A mutation context — the operation
// budget, or a start's launch budget — is not a recovery tail, so deriving from
// one buys a full recoveryBudget, detached from the parent's own deadline
// because that deadline is usually what just expired.
func TestRecoveryContextFreshFromOrdinaryParent(t *testing.T) {
	m := &Manager{}

	// A parent already past its own deadline: the ordinary case, since a failed
	// mutation is most often one whose budget ran out.
	parent, parentCancel := context.WithTimeout(
		context.WithValue(context.Background(), recoveryTestKey{}, "caller-identity"),
		time.Nanosecond)
	defer parentCancel()
	<-parent.Done()

	before := time.Now()
	rec, cancel := m.recoveryContext(parent)
	defer cancel()

	if err := rec.Err(); err != nil {
		t.Fatalf("recovery context inherited the parent's expiry: %v", err)
	}
	deadline, ok := rec.Deadline()
	if !ok {
		t.Fatal("recoveryContext returned a context with no deadline: unbounded, not budgeted")
	}
	// A second's slack either way: the point is which budget was granted, and
	// the only other candidate — two of them, or none — is 75s away.
	if got := deadline.Sub(before); got > recoveryBudget+time.Second || got < recoveryBudget-time.Second {
		t.Errorf("recovery budget = %v, want ~%v", got, recoveryBudget)
	}
	// The caller's values ride along — the authenticated identity and tracing
	// travel this way into every write the tail makes.
	if got := rec.Value(recoveryTestKey{}); got != "caller-identity" {
		t.Errorf("caller value = %v, want %q", got, "caller-identity")
	}
}
