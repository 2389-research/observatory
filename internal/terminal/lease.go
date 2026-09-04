// ABOUTME: The writer lease (§8.2, D6): one connection types, every other one
// ABOUTME: watches, and a disconnect keeps the shell for a grace window.
package terminal

import (
	"sync"
	"time"
)

// Lease decides which attachment may type. Exactly one connection holds it;
// every other attachment on the same session is read-only and is told who has
// it, so a viewer sees a name rather than a shell that ignores the keyboard.
//
// A disconnect does not hand the shell straight to a bystander: the holder
// keeps it for a grace window, long enough to survive a page reload on a flaky
// link. A Steal overrides that window at once — §8.2's writer transfer is a
// deliberate act, not a race with a timer.
type Lease struct {
	mu    sync.Mutex
	grace time.Duration
	now   func() time.Time

	holder string
	// releasedAt is when the holder disconnected. Zero while it is attached,
	// which is what makes an idle holder's lease permanent and a departed
	// one's expire.
	releasedAt time.Time

	// changed is closed and replaced whenever the holder changes. A demoted
	// writer has to hear about it without polling: §8.2 takes the shell at the
	// instant of the steal, and a browser still showing a writer badge lies.
	changed chan struct{}
}

// NewLease builds a lease with the given grace window. A nil clock uses
// time.Now; tests wind their own rather than sleeping out a 30-second window.
func NewLease(grace time.Duration, now func() time.Time) *Lease {
	if now == nil {
		now = time.Now
	}
	if grace < 0 {
		grace = 0
	}
	return &Lease{grace: grace, now: now, changed: make(chan struct{})}
}

// Acquire takes the lease for connID. It reports whether connID may now type
// and, either way, who holds it — a refusal has to name the holder or the
// viewer has nothing to display.
func (l *Lease) Acquire(connID string) (bool, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expireLocked()
	if l.holder == "" || l.holder == connID {
		if l.holder != connID {
			l.notifyLocked()
		}
		l.holder = connID
		l.releasedAt = time.Time{}
		return true, connID
	}
	return false, l.holder
}

// Release gives up the lease after the grace window. A Release from anyone but
// the holder is ignored: a read-only viewer closing its tab must not drop the
// writer's shell.
func (l *Lease) Release(connID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expireLocked()
	if l.holder != connID || !l.releasedAt.IsZero() {
		return
	}
	l.releasedAt = l.now()
}

// Steal transfers the lease to connID immediately and returns whoever held it,
// empty if nobody did. The previous holder stops being the writer at this
// instant, not on its next reconnect (§8.2).
func (l *Lease) Steal(connID string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expireLocked()
	previous := l.holder
	l.holder = connID
	l.releasedAt = time.Time{}
	if previous == connID {
		return ""
	}
	l.notifyLocked()
	return previous
}

// Holder is the connection that may type, empty if none.
func (l *Lease) Holder() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expireLocked()
	return l.holder
}

// IsWriter reports whether connID may type right now.
func (l *Lease) IsWriter(connID string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expireLocked()
	return l.holder != "" && l.holder == connID
}

// expireLocked drops a released lease once its grace window has passed. It runs
// on every operation rather than on a timer: the lease only matters when
// somebody asks, and a timer would keep a closed session alive to fire.
func (l *Lease) expireLocked() {
	if l.holder == "" || l.releasedAt.IsZero() {
		return
	}
	if l.now().Sub(l.releasedAt) >= l.grace {
		l.holder = ""
		l.releasedAt = time.Time{}
		l.notifyLocked()
	}
}

// Changed returns a channel closed the next time the holder changes. Callers
// re-read it after each wake: the channel is replaced, not reused, so a stale
// one never fires twice.
func (l *Lease) Changed() <-chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.changed
}

// notifyLocked wakes everyone watching and arms the next wait.
func (l *Lease) notifyLocked() {
	close(l.changed)
	l.changed = make(chan struct{})
}
