// ABOUTME: Tests for the in-memory session store: lifecycle, expiry, and
// ABOUTME: uniqueness guarantees verified with -race.
package auth

import (
	"testing"
	"time"
)

func TestSessionLifecycle(t *testing.T) {
	sm := NewSessions(time.Hour)
	sess := sm.Create("local_operator")
	if sess.ID == "" || sess.CSRFToken == "" || sess.ID == sess.CSRFToken {
		t.Fatalf("weak session material: %+v", sess)
	}
	got, ok := sm.Get(sess.ID)
	if !ok || got.Owner != "local_operator" {
		t.Fatalf("Get = %+v, %v", got, ok)
	}
	if !sm.Revoke(sess.ID) {
		t.Fatal("Revoke returned false for a live session")
	}
	if _, ok := sm.Get(sess.ID); ok {
		t.Fatal("session survived revoke")
	}
}

func TestSessionExpiry(t *testing.T) {
	sm := NewSessions(10 * time.Millisecond)
	sess := sm.Create("op")
	time.Sleep(30 * time.Millisecond)
	if _, ok := sm.Get(sess.ID); ok {
		t.Fatal("expired session still valid")
	}
}

func TestSessionIDsUnique(t *testing.T) {
	sm := NewSessions(time.Hour)
	seen := map[string]bool{}
	for range 100 {
		s := sm.Create("op")
		if seen[s.ID] {
			t.Fatal("duplicate session ID")
		}
		seen[s.ID] = true
	}
}

func TestNewSessionsZeroTTLPanics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for ttl=0, got none")
		}
	}()
	NewSessions(0)
}

func TestNewSessionsNegativeTTLPanics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for negative ttl, got none")
		}
	}()
	NewSessions(-time.Second)
}

// TestExpiredSweepOnGet verifies that expired entries are purged when Get is
// called — even for a nonexistent id — not only when Create runs.
func TestExpiredSweepOnGet(t *testing.T) {
	sm := NewSessions(10 * time.Millisecond)
	sm.Create("victim1")
	sm.Create("victim2")

	time.Sleep(30 * time.Millisecond)

	if len(sm.entries) != 2 {
		t.Fatalf("expected 2 entries before sweep, got %d", len(sm.entries))
	}

	// Calling Get with a nonexistent id should still sweep all expired entries.
	sm.Get("does-not-exist")

	if len(sm.entries) != 0 {
		t.Fatalf("expected 0 entries after sweep via Get, got %d", len(sm.entries))
	}
}

// TestExpiredSweepOnRevoke verifies that expired entries are purged when
// Revoke is called for a *different* id.
func TestExpiredSweepOnRevoke(t *testing.T) {
	sm := NewSessions(10 * time.Millisecond)
	sm.Create("victim1")
	sm.Create("victim2")

	time.Sleep(30 * time.Millisecond)

	if len(sm.entries) != 2 {
		t.Fatalf("expected 2 entries before sweep, got %d", len(sm.entries))
	}

	// Revoke a nonexistent id — only the sweep path should run.
	sm.Revoke("does-not-exist")

	if len(sm.entries) != 0 {
		t.Fatalf("expected 0 entries after sweep via Revoke, got %d", len(sm.entries))
	}
}
