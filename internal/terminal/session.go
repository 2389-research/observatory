// ABOUTME: The terminal session registry: the one thing in the host that talks
// ABOUTME: to a runner about terminals, and the rules it enforces (§8.2, §18).
package terminal

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/2389-research/observatory/internal/runner"
)

// State is a session's lifecycle position as the host knows it.
type State string

const (
	StateOpen   State = "open"
	StateClosed State = "closed"
)

// Error is a terminal rule violation carrying the machine-readable cause the
// API turns into a typed HTTP error (§17). The cause is the contract; the
// message is what an operator reads.
type Error struct {
	Cause   string
	Message string
	err     error
}

func (e *Error) Error() string {
	if e.err != nil {
		return e.Cause + ": " + e.Message + ": " + e.err.Error()
	}
	return e.Cause + ": " + e.Message
}

func (e *Error) Unwrap() error { return e.err }

func newError(cause, format string, args ...any) *Error {
	return &Error{Cause: cause, Message: fmt.Sprintf(format, args...)}
}

func wrapError(cause string, err error, format string, args ...any) *Error {
	return &Error{Cause: cause, Message: fmt.Sprintf(format, args...), err: err}
}

// ErrReadOnly is what a non-holder's input gets. It is returned rather than
// dropped: a keystroke that vanishes with no error is indistinguishable from a
// hung shell.
var ErrReadOnly = errors.New("this attachment is read-only: another connection holds the writer lease")

// Spec is what the host asks the guest to start.
type Spec struct {
	Owner string
	User  string
	Cwd   string
	Argv  []string
	Term  string
	Rows  uint16
	Cols  uint16
}

// Session is the host's record of one terminal. It is a snapshot: the registry
// hands out copies so a caller cannot mutate the live state behind its back.
type Session struct {
	ID        string
	VMID      string
	BootID    string
	Owner     string
	CreatedAt time.Time
	State     State
	Rows      uint16
	Cols      uint16
	Argv      []string
	PID       int

	// OutputBytes and InputBytes are what this session has carried, counted at
	// the attachment. They exceed 2^53 on a busy shell, so every wire rendering
	// of them is a decimal string.
	OutputBytes uint64
	InputBytes  uint64

	// WriterHolder is the connection that may type right now, empty when the
	// lease is free. §8.2 requires read-only viewers to be told who holds it.
	WriterHolder string

	ClosedAt time.Time
	Reason   string
	ExitCode *int
	Signal   string
}

// Options configure a Registry. The byte bounds arrive already resolved:
// internal/config owns what a zero means, and a package that re-resolved them
// would be a second answer to the same question.
type Options struct {
	MaxReplayBytesPerSession int64
	MaxInflightBrowserBytes  int64
	WriterLease              time.Duration

	// Dial opens the control socket of the runner supervising vmID.
	Dial func(ctx context.Context, vmID string) (net.Conn, error)

	// NewID mints session ids; nil uses a UUID.
	NewID func() string
	// Now is the clock; nil uses time.Now.
	Now func() time.Time
}

// UnixDialer dials the runner control socket the jailer creates per VM.
func UnixDialer(stateDir string) func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, vmID string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", runnerSocket(stateDir, vmID))
	}
}

// Registry is the only thing in the host that talks to a runner about
// terminals. Handlers get their streams from here and never dial a runner
// themselves, so a leaked attachment has exactly one place to be found.
type Registry struct {
	mu       sync.Mutex
	opts     Options
	sessions map[string]*sessionState
	nextSeq  uint64
}

// sessionState is the live record behind a Session snapshot.
type sessionState struct {
	session Session
	seq     uint64
	lease   *Lease
	// live is every attachment currently holding a runner connection for this
	// session, so closing the session closes them too.
	live map[*Attachment]struct{}

	// Byte counts are atomics rather than fields under the registry lock: every
	// Read and Write on every attachment touches them, and a session's traffic
	// must not serialize against the registry's map.
	outputBytes atomic.Uint64
	inputBytes  atomic.Uint64

	// inputSeq numbers keystrokes for the whole session, not per attachment.
	// The guest drops any sequence it has already seen, so a second attachment
	// starting its own count would have everything it typed silently ignored.
	inputSeq atomic.Uint64
}

// snapshot copies a session's record with its live byte counts folded in.
func (st *sessionState) snapshot() Session {
	s := st.session
	s.OutputBytes = st.outputBytes.Load()
	s.InputBytes = st.inputBytes.Load()
	s.WriterHolder = st.lease.Holder()
	return s
}

// NewRegistry builds a registry over the given runner dialer.
func NewRegistry(opts Options) *Registry {
	if opts.NewID == nil {
		opts.NewID = uuid.NewString
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.MaxReplayBytesPerSession <= 0 {
		opts.MaxReplayBytesPerSession = 256 << 10
	}
	if opts.MaxInflightBrowserBytes <= 0 {
		opts.MaxInflightBrowserBytes = 1 << 20
	}
	if opts.WriterLease <= 0 {
		opts.WriterLease = 30 * time.Second
	}
	return &Registry{opts: opts, sessions: map[string]*sessionState{}}
}

// Create asks the VM's runner for a new PTY and records the session against the
// boot it was created under. The host mints the id: an id the guest chose could
// not be handed out by the API that has to address it.
func (r *Registry) Create(ctx context.Context, vmID string, spec Spec) (Session, error) {
	id := r.opts.NewID()
	reply, err := r.do(ctx, vmID, runner.CtlRequest{
		Cmd: "terminal-create",
		Terminal: &runner.TerminalCtlRequest{
			SessionID: id,
			User:      spec.User,
			Cwd:       spec.Cwd,
			Argv:      spec.Argv,
			Term:      spec.Term,
			Rows:      spec.Rows,
			Cols:      spec.Cols,
			RingBytes: int(r.opts.MaxReplayBytesPerSession),
		},
	})
	if err != nil {
		return Session{}, err
	}

	s := Session{
		ID:        id,
		VMID:      vmID,
		Owner:     spec.Owner,
		CreatedAt: r.opts.Now().UTC(),
		State:     StateOpen,
		Rows:      spec.Rows,
		Cols:      spec.Cols,
		Argv:      append([]string(nil), spec.Argv...),
	}
	// The boot identity comes from the runner, not from the caller: the runner
	// is the process supervising this boot, and a host record can be stale.
	if reply.Terminal != nil {
		s.PID = reply.Terminal.PID
		s.BootID = reply.Terminal.BootID
	}

	r.mu.Lock()
	r.nextSeq++
	r.sessions[id] = &sessionState{
		session: s,
		seq:     r.nextSeq,
		lease:   NewLease(r.opts.WriterLease, r.opts.Now),
		live:    map[*Attachment]struct{}{},
	}
	r.mu.Unlock()
	return s, nil
}

// Get returns a snapshot of one session.
func (r *Registry) Get(id string) (Session, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, ok := r.sessions[id]
	if !ok {
		return Session{}, false
	}
	return st.snapshot(), true
}

// ListForVM returns that VM's sessions oldest first, so a cursor over the list
// stays stable as new ones are created.
func (r *Registry) ListForVM(vmID string) []Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	var states []*sessionState
	for _, st := range r.sessions {
		if st.session.VMID == vmID {
			states = append(states, st)
		}
	}
	sort.Slice(states, func(i, j int) bool { return states[i].seq < states[j].seq })
	out := make([]Session, 0, len(states))
	for _, st := range states {
		out = append(out, st.snapshot())
	}
	return out
}

// Close ends a session and every attachment on it. It is idempotent: an
// unknown or already-closed session is the caller's intent already satisfied,
// not an error, which is what lets DELETE answer 204 twice.
func (r *Registry) Close(ctx context.Context, id string) error {
	r.mu.Lock()
	st, ok := r.sessions[id]
	if !ok || st.session.State == StateClosed {
		r.mu.Unlock()
		return nil
	}
	vmID := st.session.VMID
	r.mu.Unlock()

	reply, err := r.do(ctx, vmID, runner.CtlRequest{
		Cmd:      "terminal-close",
		Terminal: &runner.TerminalCtlRequest{SessionID: id},
	})
	if err != nil {
		return err
	}

	r.mu.Lock()
	st.session.State = StateClosed
	st.session.ClosedAt = r.opts.Now().UTC()
	if reply.Terminal != nil {
		st.session.Reason = reply.Terminal.Reason
		st.session.ExitCode = reply.Terminal.ExitCode
		st.session.Signal = reply.Terminal.Signal
	}
	attachments := make([]*Attachment, 0, len(st.live))
	for a := range st.live {
		attachments = append(attachments, a)
	}
	st.live = map[*Attachment]struct{}{}
	r.mu.Unlock()

	// Outside the lock: closing a stream can block on a peer, and the registry
	// is not a place to wait.
	for _, a := range attachments {
		_ = a.closeStream()
	}
	return nil
}

// do runs one control verb against a VM's runner and returns its reply.
func (r *Registry) do(ctx context.Context, vmID string, req runner.CtlRequest) (runner.CtlReply, error) {
	conn, err := r.opts.Dial(ctx, vmID)
	if err != nil {
		return runner.CtlReply{}, wrapError("runner_unreachable", err,
			"the runner supervising VM %s is not answering its control socket", vmID)
	}
	reply, err := runner.NewCtlClient(conn).Do(ctx, req)
	if err != nil {
		return runner.CtlReply{}, wrapError("runner_refused", err, "the runner refused %s", req.Cmd)
	}
	return reply, nil
}

// parseOffset reads a decimal-string offset. Offsets cross the wire as strings
// because a busy shell passes 2^53 bytes in days (P-06).
func parseOffset(s string) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	return strconv.ParseUint(s, 10, 64)
}
