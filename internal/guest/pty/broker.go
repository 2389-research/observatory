// ABOUTME: The guest PTY broker: it owns each terminal session and its child shell.
// ABOUTME: A session outlives every attachment, so closing a browser tab never kills a shell.
package pty

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Ring size bounds. ring_bytes arrives off the wire in terminal.create, so it
// is clamped here rather than trusted: DefaultRingBytes is SPEC §8.3's
// terminal.max_replay_bytes_per_session default.
const (
	MinRingBytes     = 4 << 10
	DefaultRingBytes = 256 << 10
	MaxRingBytes     = 4 << 20
)

const (
	// readChunk matches §8.3's default terminal.max_wire_chunk_bytes, so one
	// drain read fills at most one wire frame.
	readChunk = 32 << 10
	// closeGrace is how long a hung-up session has to die before it is killed.
	closeGrace = 2 * time.Second
	// guestPath is the session's PATH. The broker builds the child's whole
	// environment rather than leaking guestd's.
	guestPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

var (
	ErrArgvInvalid    = errors.New("session argv is not an executable argument array")
	ErrSessionExists  = errors.New("session id already exists")
	ErrUnknownSession = errors.New("no such session")
	ErrSessionExited  = errors.New("session has exited")
	ErrUserUnknown    = errors.New("no such guest user")
	ErrOffsetAhead    = errors.New("resume offset is ahead of the stream")
)

// SessionSpec is one terminal.create request: SPEC §8.1's "server-generated
// UUID, approved guest user, cwd, shell argv, terminal type, rows and
// columns", plus the replay window the host asked for.
type SessionSpec struct {
	SessionID string
	User      string
	Cwd       string
	Argv      []string
	Term      string
	Rows      uint16
	Cols      uint16
	RingBytes int
}

// ExitStatus is how a session ended. Exactly one of Code and Signal is set:
// a process either returns a status or is killed, never both.
type ExitStatus struct {
	Code   *int
	Signal string
	Reason string // "exited" or "signaled"
}

func (e ExitStatus) String() string {
	switch {
	case e.Signal != "":
		return "signaled " + e.Signal
	case e.Code != nil:
		return "exited " + strconv.Itoa(*e.Code)
	default:
		return "unknown"
	}
}

// SessionInfo is a snapshot of one session, the shape terminal.sessions
// renders. Head and Tail are byte offsets in the session's output stream;
// the wire renders them as decimal strings.
type SessionInfo struct {
	SessionID string
	PID       int
	Rows      uint16
	Cols      uint16
	Head      uint64
	Tail      uint64
	RingBytes int
	StartedAt time.Time
	Exited    bool
	Exit      ExitStatus
}

// BrokerConfig configures a Broker.
type BrokerConfig struct {
	// OnExit is called once per session, from the reaper, after the child is
	// gone. The control loop is strictly request/response, so this is how an
	// attached connection learns to send terminal.closed.
	OnExit func(SessionInfo)
}

// Broker owns every live session in the guest.
type Broker struct {
	cfg BrokerConfig

	mu       sync.Mutex
	sessions map[string]*Session
}

func NewBroker(cfg BrokerConfig) *Broker {
	return &Broker{cfg: cfg, sessions: make(map[string]*Session)}
}

// clampRing bounds a wire-supplied ring size. The effective size is reported
// in SessionInfo.RingBytes, so a clamped request is visible rather than
// silently honoured.
func clampRing(n int) int {
	switch {
	case n <= 0:
		return DefaultRingBytes
	case n < MinRingBytes:
		return MinRingBytes
	case n > MaxRingBytes:
		return MaxRingBytes
	default:
		return n
	}
}

// validateArgv enforces SPEC §8.1: "Use an argument array. No host shell
// participates in this chain." argv[0] is a program, not a command line, and
// a -c anywhere would make the shell an interpreter wrapped around a string —
// one quoting bug away from executing whatever reached it.
func validateArgv(argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("%w: argv is empty", ErrArgvInvalid)
	}
	if !filepath.IsAbs(argv[0]) {
		return fmt.Errorf("%w: argv[0] %q is not an absolute path", ErrArgvInvalid, argv[0])
	}
	for _, a := range argv[1:] {
		if a == "-c" {
			return fmt.Errorf("%w: argv carries -c; the shell is a member of argv, not an interpreter wrapped around it", ErrArgvInvalid)
		}
	}
	return nil
}

// childUser resolves the approved guest user. An empty name means the user
// guestd already runs as. A name that does not resolve is refused: running as
// root instead would be a silent privilege upgrade.
func childUser(name string) (*user.User, *syscall.Credential, error) {
	self, err := user.Current()
	if err != nil {
		return nil, nil, fmt.Errorf("current user: %w", err)
	}
	if name == "" || name == self.Username {
		return self, nil, nil
	}
	u, err := user.Lookup(name)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s", ErrUserUnknown, name)
	}
	if u.Uid == self.Uid {
		return u, nil, nil
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s has a non-numeric uid %q", ErrUserUnknown, name, u.Uid)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s has a non-numeric gid %q", ErrUserUnknown, name, u.Gid)
	}
	cred := &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	if ids, err := u.GroupIds(); err == nil {
		for _, raw := range ids {
			g, err := strconv.ParseUint(raw, 10, 32)
			if err != nil {
				continue
			}
			cred.Groups = append(cred.Groups, uint32(g))
		}
	}
	return u, cred, nil
}

// Create allocates a PTY, starts the session's program on it with a
// controlling terminal, and begins draining its output into the replay ring.
func (b *Broker) Create(spec SessionSpec) (*Session, error) {
	if spec.SessionID == "" {
		return nil, fmt.Errorf("%w: session id is empty", ErrArgvInvalid)
	}
	if err := validateArgv(spec.Argv); err != nil {
		return nil, err
	}
	if spec.Cwd != "" && !filepath.IsAbs(spec.Cwd) {
		return nil, fmt.Errorf("%w: cwd %q is not an absolute path", ErrArgvInvalid, spec.Cwd)
	}
	if spec.Rows == 0 || spec.Cols == 0 {
		return nil, fmt.Errorf("%w: rows and cols must both be non-zero", ErrArgvInvalid)
	}
	u, cred, err := childUser(spec.User)
	if err != nil {
		return nil, err
	}

	b.mu.Lock()
	if _, dup := b.sessions[spec.SessionID]; dup {
		b.mu.Unlock()
		return nil, fmt.Errorf("%w: %s", ErrSessionExists, spec.SessionID)
	}
	b.mu.Unlock()

	master, slaveName, err := Open(spec.Rows, spec.Cols)
	if err != nil {
		return nil, err
	}
	slave, err := os.OpenFile(slaveName, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		_ = master.Close()
		return nil, fmt.Errorf("open %s: %w", slaveName, err)
	}

	cwd := spec.Cwd
	if cwd == "" {
		cwd = u.HomeDir
	}
	if cwd == "" {
		cwd = "/"
	}
	term := spec.Term
	if term == "" {
		term = "xterm-256color"
	}

	cmd := exec.Command(spec.Argv[0], spec.Argv[1:]...) //nolint:gosec // §8.1: the argv is the contract; no shell interprets it
	cmd.Dir = cwd
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	// A built environment, not an inherited one: guestd's own variables have
	// no business in an operator's shell. LANG is UTF-8 because §8.2 requires
	// UTF-8 to work.
	cmd.Env = []string{
		"TERM=" + term,
		"PATH=" + guestPath,
		"HOME=" + cwd,
		"USER=" + u.Username,
		"LOGNAME=" + u.Username,
		"SHELL=" + spec.Argv[0],
		"LANG=C.UTF-8",
	}
	// Setsid makes the child a session leader; Setctty with Ctty 0 makes the
	// pts on its fd 0 the controlling terminal. Together they are what make
	// job control and SIGWINCH real (SPEC §8.1).
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:     true,
		Setctty:    true,
		Ctty:       0,
		Credential: cred,
	}
	if err := cmd.Start(); err != nil {
		_ = slave.Close()
		_ = master.Close()
		return nil, fmt.Errorf("start session %s: %w", spec.SessionID, err)
	}
	// The parent's copy of the slave has to go, or the master never sees EOF
	// when the child dies and the session would hang forever.
	_ = slave.Close()

	s := &Session{
		id:        spec.SessionID,
		cmd:       cmd,
		master:    master,
		slaveName: slaveName,
		startedAt: time.Now().UTC(),
		ring:      NewRing(clampRing(spec.RingBytes)),
		rows:      spec.Rows,
		cols:      spec.Cols,
		done:      make(chan struct{}),
		onExit:    b.cfg.OnExit,
	}
	s.cond = sync.NewCond(&s.mu)

	b.mu.Lock()
	if _, dup := b.sessions[spec.SessionID]; dup {
		b.mu.Unlock()
		s.terminate()
		return nil, fmt.Errorf("%w: %s", ErrSessionExists, spec.SessionID)
	}
	b.sessions[spec.SessionID] = s
	b.mu.Unlock()

	go s.drain()
	return s, nil
}

// Get returns a live or exited session by id. A session stays here after its
// child dies so terminal.list can report the exit; Close removes it.
func (b *Broker) Get(id string) (*Session, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.sessions[id]
	return s, ok
}

// Close ends a session and reaps its child. It is the only thing that
// removes a session from the broker.
func (b *Broker) Close(id string) error {
	b.mu.Lock()
	s, ok := b.sessions[id]
	if !ok {
		b.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrUnknownSession, id)
	}
	delete(b.sessions, id)
	b.mu.Unlock()

	s.terminate()
	return nil
}

// List snapshots every session the broker holds, ordered by id so two calls
// with the same state return the same page.
func (b *Broker) List() []SessionInfo {
	b.mu.Lock()
	all := make([]*Session, 0, len(b.sessions))
	for _, s := range b.sessions {
		all = append(all, s)
	}
	b.mu.Unlock()

	out := make([]SessionInfo, 0, len(all))
	for _, s := range all {
		out = append(out, s.Info())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SessionID < out[j].SessionID })
	return out
}

// Session is one PTY, one child process group, and one replay ring.
type Session struct {
	id        string
	cmd       *exec.Cmd
	master    *os.File
	slaveName string
	startedAt time.Time
	onExit    func(SessionInfo)

	mu     sync.Mutex
	cond   *sync.Cond
	ring   *Ring
	rows   uint16
	cols   uint16
	eof    bool // the master will produce no more output
	exited bool
	status ExitStatus

	done chan struct{}

	// inputMu guards the write path alone. The drain goroutine never takes
	// it, so a child that has stopped reading its input can never stall the
	// goroutine that keeps the ring filling.
	inputMu sync.Mutex
	lastSeq uint64
}

func (s *Session) ID() string  { return s.id }
func (s *Session) PID() int    { return s.cmd.Process.Pid }
func (s *Session) TTY() string { return s.slaveName }

// Done closes when the child has been reaped and its status recorded.
func (s *Session) Done() <-chan struct{} { return s.done }

// Exit returns how the session ended, and false while it is still running.
func (s *Session) Exit() (ExitStatus, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status, s.exited
}

func (s *Session) Info() SessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return SessionInfo{
		SessionID: s.id,
		PID:       s.cmd.Process.Pid,
		Rows:      s.rows,
		Cols:      s.cols,
		Head:      s.ring.Head(),
		Tail:      s.ring.Tail(),
		RingBytes: s.ring.Size(),
		StartedAt: s.startedAt,
		Exited:    s.exited,
		Exit:      s.status,
	}
}

// drain copies the terminal's output into the ring forever, then reaps the
// child. It runs whether or not anyone is attached: §8.1's session owns its
// shell, so output has somewhere to go even with every tab closed.
func (s *Session) drain() {
	buf := make([]byte, readChunk)
	for {
		n, err := s.master.Read(buf)
		if n > 0 {
			s.mu.Lock()
			s.ring.Append(buf[:n])
			s.mu.Unlock()
			s.cond.Broadcast()
		}
		if err != nil {
			break
		}
	}

	waitErr := s.cmd.Wait()
	status := exitStatus(s.cmd.ProcessState, waitErr)

	s.mu.Lock()
	s.eof = true
	s.exited = true
	s.status = status
	s.mu.Unlock()
	s.cond.Broadcast()
	close(s.done)

	if s.onExit != nil {
		s.onExit(s.Info())
	}
}

// exitStatus reads the wait status. A signalled child has no exit code, and
// reporting 255 for one would invent a number the kernel never produced.
func exitStatus(ps *os.ProcessState, waitErr error) ExitStatus {
	if ps == nil {
		msg := "unknown"
		if waitErr != nil {
			msg = waitErr.Error()
		}
		return ExitStatus{Reason: msg}
	}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return ExitStatus{Signal: signalName(ws.Signal()), Reason: "signaled"}
	}
	code := ps.ExitCode()
	return ExitStatus{Code: &code, Reason: "exited"}
}

// signalName renders a signal as its kernel name. syscall.Signal.String()
// gives a description ("killed"), and the wire wants the name ("SIGKILL").
func signalName(sig syscall.Signal) string {
	if name := unix.SignalName(sig); name != "" {
		return name
	}
	return "signal " + strconv.Itoa(int(sig))
}

// terminate hangs up the terminal and reaps the child. Closing the master is
// what sends SIGHUP to the session's foreground process group — the kernel's
// own disconnect path, so nothing here signals a pid that may already have
// been recycled.
func (s *Session) terminate() {
	_ = s.master.Close()
	select {
	case <-s.done:
		return
	case <-time.After(closeGrace):
	}
	_ = s.cmd.Process.Kill()
	<-s.done
}

// Input applies one host input frame. SPEC §8.2: "A retransmitted accepted
// frame must not type the same text twice", so a sequence at or below the
// last applied one is dropped. A failed write leaves the sequence untouched,
// so a retry can still land.
func (s *Session) Input(seq uint64, b []byte) bool {
	s.inputMu.Lock()
	defer s.inputMu.Unlock()
	if seq <= s.lastSeq {
		return false
	}
	if _, err := s.master.Write(b); err != nil {
		return false
	}
	s.lastSeq = seq
	return true
}

// Resize changes the terminal's size, which signals SIGWINCH to the
// foreground process group.
func (s *Session) Resize(rows, cols uint16) error {
	if rows == 0 || cols == 0 {
		return fmt.Errorf("resize %s: rows and cols must both be non-zero", s.id)
	}
	if err := setWinsize(s.master, rows, cols); err != nil {
		return fmt.Errorf("resize %s: %w", s.id, err)
	}
	s.mu.Lock()
	s.rows, s.cols = rows, cols
	s.mu.Unlock()
	return nil
}

// DropReporter names output an attachment skipped because the ring overwrote
// it before the reader got there. The reader Attach returns implements it, so
// the connection above can emit terminal.dropped with the exact lost range.
type DropReporter interface {
	Dropped() (Range, bool)
}

// Attach opens a reader over the session's output starting at the first byte
// after the given offset. It returns the offset the stream actually resumes
// from and whether replay was lost getting there.
func (s *Session) Attach(after uint64) (io.ReadCloser, uint64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.exited {
		return nil, 0, false, fmt.Errorf("%w: %s %s", ErrSessionExited, s.id, s.status)
	}
	if after > s.ring.Head() {
		return nil, 0, false, fmt.Errorf("%w: asked for %d, stream head is %d", ErrOffsetAhead, after, s.ring.Head())
	}
	resume, gap := after, false
	if tail := s.ring.Tail(); resume < tail {
		resume, gap = tail, true
	}
	return &attachment{s: s, off: resume, closed: make(chan struct{})}, resume, gap, nil
}

// attachment is one reader over a session's output. It holds only an offset:
// the ring is the single source of the bytes, so a slow reader falls behind
// the stream rather than growing a queue of its own.
type attachment struct {
	s   *Session
	off uint64

	closed    chan struct{}
	closeOnce sync.Once

	dropMu  sync.Mutex
	drop    Range
	dropped bool
}

func (a *attachment) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s := a.s
	s.mu.Lock()
	for {
		select {
		case <-a.closed:
			s.mu.Unlock()
			return 0, io.EOF
		default:
		}
		if tail := s.ring.Tail(); a.off < tail {
			a.recordDrop(Range{From: a.off, To: tail})
			a.off = tail
		}
		if a.off < s.ring.Head() {
			break
		}
		if s.eof {
			s.mu.Unlock()
			return 0, io.EOF
		}
		s.cond.Wait()
	}
	b, _, _ := s.ring.ReadFrom(a.off)
	s.mu.Unlock()

	n := copy(p, b)
	a.off += uint64(n)
	return n, nil
}

func (a *attachment) Close() error {
	a.closeOnce.Do(func() {
		close(a.closed)
		// A parked Read is waiting on the session's condition, so waking every
		// waiter is how this one gets to see its own closed channel.
		a.s.cond.Broadcast()
	})
	return nil
}

func (a *attachment) recordDrop(r Range) {
	a.dropMu.Lock()
	defer a.dropMu.Unlock()
	if !a.dropped {
		a.drop = r
		a.dropped = true
		return
	}
	// Consecutive drops merge: the reader lost everything between the first
	// From and the latest To.
	a.drop.To = r.To
}

// Dropped returns and clears the range lost since the last call.
func (a *attachment) Dropped() (Range, bool) {
	a.dropMu.Lock()
	defer a.dropMu.Unlock()
	r, ok := a.drop, a.dropped
	a.drop, a.dropped = Range{}, false
	return r, ok
}
