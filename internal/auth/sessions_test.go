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
