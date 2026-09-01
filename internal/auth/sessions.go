// ABOUTME: In-memory browser sessions with absolute TTL and per-session CSRF tokens;
// ABOUTME: restart logs the operator out by design (no file persistence).
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// Session is a single authenticated browser session.
type Session struct {
	ID        string
	Owner     string
	CSRFToken string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Sessions is a concurrency-safe in-memory session store.
type Sessions struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]Session
}

// NewSessions returns a Sessions store that grants sessions with the given TTL.
// Panics if ttl is zero or negative — a non-positive TTL is programmer error.
func NewSessions(ttl time.Duration) *Sessions {
	if ttl <= 0 {
		panic("auth: session ttl must be positive")
	}
	return &Sessions{
		ttl:     ttl,
		entries: make(map[string]Session),
	}
}

// randToken returns 32 random bytes encoded with base64.RawURLEncoding.
func randToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("auth: crypto/rand unavailable: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// sweepExpiredLocked deletes all entries whose ExpiresAt is before now.
// The caller must hold s.mu.
func (s *Sessions) sweepExpiredLocked(now time.Time) {
	for id, sess := range s.entries {
		if now.After(sess.ExpiresAt) {
			delete(s.entries, id)
		}
	}
}

// Create mints a new session for owner, sweeps expired entries opportunistically,
// and stores the session. The session ID and CSRF token are independent 32-byte
// random values (base64url); they are guaranteed to differ.
func (s *Sessions) Create(owner string) Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	s.sweepExpiredLocked(now)

	id := randToken()
	csrf := randToken()
	// Extremely unlikely to collide with 32 bytes each, but enforce the
	// brief's invariant (sess.ID != sess.CSRFToken) explicitly.
	for csrf == id {
		csrf = randToken()
	}

	sess := Session{
		ID:        id,
		Owner:     owner,
		CSRFToken: csrf,
		CreatedAt: now,
		ExpiresAt: now.Add(s.ttl),
	}
	s.entries[id] = sess
	return sess
}

// Get returns the session for id, or (zero, false) for unknown or expired
// sessions. Sweeps all expired entries on every call.
func (s *Sessions) Get(id string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	s.sweepExpiredLocked(now)

	sess, ok := s.entries[id]
	if !ok {
		return Session{}, false
	}
	return sess, true
}

// Revoke removes the session for id. Returns true if the session existed and
// was not expired at call time; false if unknown or already expired. Sweeps all
// expired entries on every call.
func (s *Sessions) Revoke(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	s.sweepExpiredLocked(now)

	if _, ok := s.entries[id]; !ok {
		return false
	}
	delete(s.entries, id)
	return true
}
