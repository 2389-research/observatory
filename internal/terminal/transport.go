// ABOUTME: Attachments: the registry hands out one runner connection per
// ABOUTME: attached session, bounded by a window and gated by the writer lease.
package terminal

import (
	"context"
	"io"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/2389-research/observatory-v2/internal/runner"
)

// runnerSocket is where the jailer puts a VM's runner control socket. The
// layout is decided in internal/jailer/launch.go; this rebuilds it rather than
// depending on that package for one path join. Options.Dial is the seam for a
// host that arranges its sockets differently.
func runnerSocket(stateDir, vmID string) string {
	return filepath.Join(stateDir, "vms", vmID, "runner.sock")
}

// AttachRequest is one attach. It carries the VM's current boot id because the
// staleness check is the point: §8.2 says a reboot invalidates a session rather
// than silently reattaching, and a two-argument attach cannot ask that question.
type AttachRequest struct {
	SessionID string
	// AfterOffset is where this attachment resumes; 0 means from the ring's tail.
	AfterOffset uint64
	// BootID is the VM's boot right now, not the session's.
	BootID string
	// ConnID identifies this attachment to the writer lease.
	ConnID string
	// Steal takes the writer lease from its current holder (§8.2).
	Steal bool
}

// Attachment is one caller's view of a session's byte stream. It is an opaque
// pipe: it counts bytes and checks the lease, and it never looks at a PTY byte.
type Attachment struct {
	SessionID string
	// ResumeOffset is the stream position the guest will send from.
	ResumeOffset uint64
	// Gap is true when the requested offset had already fallen out of the
	// guest's ring, so output between the two is gone.
	Gap bool

	connID   string
	lease    *Lease
	window   *Window
	stream   io.ReadWriteCloser
	registry *Registry
	once     sync.Once
}

// Attach opens a session's byte stream through its runner. The caller owns the
// returned attachment and must Close it.
func (r *Registry) Attach(ctx context.Context, req AttachRequest) (*Attachment, error) {
	r.mu.Lock()
	st, ok := r.sessions[req.SessionID]
	if !ok {
		r.mu.Unlock()
		return nil, newError("session_not_found", "no terminal session %q is registered on this host", req.SessionID)
	}
	s := st.session
	r.mu.Unlock()

	if s.State == StateClosed {
		return nil, newError("session_closed",
			"terminal session %s ended (%s); create a new session rather than reattaching", s.ID, closedReason(s))
	}
	if req.BootID != "" && s.BootID != req.BootID {
		return nil, newError("session_stale",
			"terminal session %s belongs to boot %s and VM %s is now on boot %s; the reboot ended that shell",
			s.ID, s.BootID, s.VMID, req.BootID)
	}

	conn, err := r.opts.Dial(ctx, s.VMID)
	if err != nil {
		return nil, wrapError("runner_unreachable", err,
			"the runner supervising VM %s is not answering its control socket", s.VMID)
	}
	reply, stream, err := runner.NewCtlClient(conn).Attach(ctx, runner.TerminalCtlRequest{
		SessionID:   s.ID,
		AfterOffset: strconv.FormatUint(req.AfterOffset, 10),
	})
	if err != nil {
		return nil, wrapError("attach_refused", err, "the runner refused an attach to session %s", s.ID)
	}

	att := &Attachment{
		SessionID: s.ID,
		connID:    req.ConnID,
		lease:     st.lease,
		stream:    stream,
		registry:  r,
	}
	if reply.Terminal != nil {
		att.Gap = reply.Terminal.Gap
		off, perr := parseOffset(reply.Terminal.ResumeOffset)
		if perr != nil {
			stream.Close()
			return nil, wrapError("attach_refused", perr,
				"the runner reported resume offset %q for session %s, which is not a decimal offset",
				reply.Terminal.ResumeOffset, s.ID)
		}
		att.ResumeOffset = off
	}
	att.window = NewWindow(r.opts.MaxInflightBrowserBytes, att.ResumeOffset)

	if req.Steal {
		st.lease.Steal(req.ConnID)
	} else {
		st.lease.Acquire(req.ConnID)
	}

	// The session can have been closed while the runner round trip was in
	// flight. Registering into a closed session would leak this stream past the
	// close that was supposed to end it.
	r.mu.Lock()
	if st.session.State == StateClosed {
		r.mu.Unlock()
		stream.Close()
		return nil, newError("session_closed",
			"terminal session %s ended while this attach was opening", s.ID)
	}
	st.live[att] = struct{}{}
	r.mu.Unlock()
	return att, nil
}

// Read returns frames from the guest.
func (a *Attachment) Read(p []byte) (int, error) { return a.stream.Read(p) }

// Write sends frames to the guest, and refuses when this attachment does not
// hold the writer lease. The refusal is an error rather than a silent drop:
// input that vanishes is indistinguishable from a hung shell.
func (a *Attachment) Write(p []byte) (int, error) {
	if !a.lease.IsWriter(a.connID) {
		return 0, ErrReadOnly
	}
	return a.stream.Write(p)
}

// Close releases the writer lease — after its grace window, so a reload does
// not hand the shell to a bystander — and drops the runner connection.
func (a *Attachment) Close() error {
	a.lease.Release(a.connID)
	a.registry.forget(a.SessionID, a)
	return a.closeStream()
}

// closeStream drops the runner connection without touching the lease. The
// registry uses it when a session closes: the shell is gone, so there is no
// grace window worth honouring.
func (a *Attachment) closeStream() error {
	var err error
	a.once.Do(func() { err = a.stream.Close() })
	return err
}

// IsWriter reports whether this attachment may type right now.
func (a *Attachment) IsWriter() bool { return a.lease.IsWriter(a.connID) }

// Holder names the attachment that may type, so a read-only viewer can say who.
func (a *Attachment) Holder() string { return a.lease.Holder() }

// Reserve claims in-flight room for n bytes bound for the browser.
func (a *Attachment) Reserve(n int) bool { return a.window.Reserve(n) }

// Ack records the browser's consumed offset, reopening the window.
func (a *Attachment) Ack(offset uint64) { a.window.Ack(offset) }

// InFlight is the bytes sent to the browser and not yet acknowledged.
func (a *Attachment) InFlight() int64 { return a.window.InFlight() }

// forget drops an attachment from its session's live set.
func (r *Registry) forget(sessionID string, a *Attachment) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if st, ok := r.sessions[sessionID]; ok {
		delete(st.live, a)
	}
}

// LeaseMode is what a lease request asks for.
type LeaseMode string

const (
	LeaseAcquire LeaseMode = "acquire"
	LeaseSteal   LeaseMode = "steal"
	LeaseRelease LeaseMode = "release"
)

// LeaseResult reports who may type after a lease request, and why.
type LeaseResult struct {
	Writer bool
	Holder string
	Reason string
}

// RequestLease applies a lease change to a session on behalf of connID. It is
// the API's entry point to the rules in lease.go; the rules themselves stay in
// one place.
func (r *Registry) RequestLease(sessionID, connID string, mode LeaseMode) (LeaseResult, error) {
	r.mu.Lock()
	st, ok := r.sessions[sessionID]
	r.mu.Unlock()
	if !ok {
		return LeaseResult{}, newError("session_not_found",
			"no terminal session %q is registered on this host", sessionID)
	}
	if st.session.State == StateClosed {
		return LeaseResult{}, newError("session_closed",
			"terminal session %s ended (%s)", sessionID, closedReason(st.session))
	}

	switch mode {
	case LeaseAcquire:
		ok, holder := st.lease.Acquire(connID)
		reason := "acquired the writer lease"
		if !ok {
			reason = "another connection holds the writer lease; steal it to take the shell"
		}
		return LeaseResult{Writer: ok, Holder: holder, Reason: reason}, nil
	case LeaseSteal:
		previous := st.lease.Steal(connID)
		reason := "took the writer lease"
		if previous != "" {
			reason = "took the writer lease from " + previous
		}
		return LeaseResult{Writer: true, Holder: connID, Reason: reason}, nil
	case LeaseRelease:
		st.lease.Release(connID)
		return LeaseResult{Writer: false, Holder: st.lease.Holder(),
			Reason: "released; the lease is held for its grace window in case you come back"}, nil
	default:
		return LeaseResult{}, newError("invalid_lease_mode",
			"lease mode %q is not one of acquire, steal or release", string(mode))
	}
}

// closedReason renders why a session ended, for an error a person reads.
func closedReason(s Session) string {
	switch {
	case s.ExitCode != nil:
		return "exit code " + strconv.Itoa(*s.ExitCode)
	case s.Signal != "":
		return "signal " + s.Signal
	case s.Reason != "":
		return s.Reason
	default:
		return "reason unrecorded"
	}
}
