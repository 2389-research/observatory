// ABOUTME: Linux-only broker tests: a real /dev/ptmx, a real child shell, real signals.
// ABOUTME: Nothing here is faked — a controlling terminal is either allocated or it is not.
//go:build linux

package pty_test

import (
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/guest/pty"
)

// shell is the session program every test drives. §8.2 requires job control
// and a real prompt, so this is an interactive shell, not a script runner.
const shell = "/bin/bash"

func requireShell(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(shell); err != nil {
		t.Skipf("%s is not installed on this host: %v", shell, err)
	}
}

// sink collects a session's output from a background reader. Every assertion
// reads through String, so the test goroutine never races the copier.
type sink struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (s *sink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *sink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// attach starts a background reader at the given offset and returns what it
// has collected so far, plus the reader so a test can detach it.
func attach(t *testing.T, s *pty.Session, after uint64) (*sink, io.ReadCloser) {
	t.Helper()
	r, resume, _, err := s.Attach(after)
	if err != nil {
		t.Fatalf("attach(%d): %v", after, err)
	}
	if resume < after {
		t.Fatalf("attach(%d) resumed at %d, behind the requested offset", after, resume)
	}
	out := &sink{}
	go func() { _, _ = io.Copy(out, r) }()
	t.Cleanup(func() { _ = r.Close() })
	return out, r
}

// waitForText polls until the shell has produced want. Every wait here is on
// a real child process, so the deadline is generous and the failure prints
// everything seen — a timeout with no output is a different bug from a
// timeout with the wrong output.
func waitForText(t *testing.T, out *sink, want string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(out.String(), want) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q; output so far:\n%s", want, out.String())
}

func waitDone(t *testing.T, s *pty.Session) {
	t.Helper()
	select {
	case <-s.Done():
	case <-time.After(15 * time.Second):
		t.Fatal("session never reported an exit")
	}
}

// typer sends input with a strictly increasing sequence, the way an attached
// writer does.
type typer struct{ seq uint64 }

func (tp *typer) send(t *testing.T, s *pty.Session, line string) {
	t.Helper()
	tp.seq++
	if !s.Input(tp.seq, []byte(line)) {
		t.Fatalf("input seq %d was not applied: %q", tp.seq, line)
	}
}

func newSession(t *testing.T, spec pty.SessionSpec) (*pty.Broker, *pty.Session) {
	t.Helper()
	requireShell(t)
	b := pty.NewBroker(pty.BrokerConfig{})
	if spec.SessionID == "" {
		spec.SessionID = "sess-" + strconv.Itoa(os.Getpid())
	}
	if len(spec.Argv) == 0 {
		spec.Argv = []string{shell, "-i"}
	}
	if spec.Rows == 0 || spec.Cols == 0 {
		spec.Rows, spec.Cols = 24, 80
	}
	if spec.Term == "" {
		spec.Term = "xterm-256color"
	}
	s, err := b.Create(spec)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = b.Close(spec.SessionID) })
	return b, s
}

// SPEC §8.1: "Use an argument array. No host shell participates in this
// chain." A broker that accepts `-c` is an interpreter with extra steps, and
// every later layer would then be one string-quoting bug from arbitrary
// execution.
func TestCreateRefusesAnInterpretedCommand(t *testing.T) {
	requireShell(t)
	cases := []struct {
		name string
		argv []string
	}{
		{"shell -c", []string{"/bin/sh", "-c", "echo hi"}},
		{"bash -c", []string{shell, "-c", "id"}},
		{"relative program", []string{"bash", "-i"}},
		{"empty argv", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := pty.NewBroker(pty.BrokerConfig{})
			s, err := b.Create(pty.SessionSpec{SessionID: "s1", Argv: tc.argv, Rows: 24, Cols: 80})
			if err == nil {
				_ = b.Close("s1")
				t.Fatalf("Create(%q) was accepted; want a refusal", tc.argv)
			}
			if !errors.Is(err, pty.ErrArgvInvalid) {
				t.Errorf("error = %v; want ErrArgvInvalid", err)
			}
			if s != nil {
				t.Error("refused Create returned a session")
			}
			if got := b.List(); len(got) != 0 {
				t.Errorf("refused Create registered %d sessions", len(got))
			}
		})
	}
}

// procStat returns the session id and tty_nr fields of /proc/<pid>/stat.
// comm can contain spaces and parentheses, so the fixed fields are read after
// the last ')'.
func procStat(t *testing.T, pid int) (sid, ttyNr int) {
	t.Helper()
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		t.Fatalf("read stat: %v", err)
	}
	rest := string(raw[strings.LastIndex(string(raw), ")")+1:])
	f := strings.Fields(rest)
	if len(f) < 5 {
		t.Fatalf("stat has %d fields after comm: %q", len(f), rest)
	}
	// f[0]=state f[1]=ppid f[2]=pgrp f[3]=session f[4]=tty_nr
	sid, err = strconv.Atoi(f[3])
	if err != nil {
		t.Fatalf("session field %q: %v", f[3], err)
	}
	ttyNr, err = strconv.Atoi(f[4])
	if err != nil {
		t.Fatalf("tty_nr field %q: %v", f[4], err)
	}
	return sid, ttyNr
}

// newEncodeDev mirrors the kernel's new_encode_dev, which is how tty_nr is
// written into /proc/<pid>/stat.
func newEncodeDev(major, minor int) int {
	return (major << 8) | (minor & 0xff) | ((minor &^ 0xff) << 12)
}

// SPEC §8.1: "A PTY provides terminal-device behavior and an associated
// controlling terminal for the guest process." Session-id == pid proves
// setsid ran; a non-zero tty_nr matching the child's own fd 0 proves the pts
// became its controlling terminal rather than merely its stdin.
func TestChildGetsAControllingTerminal(t *testing.T) {
	_, s := newSession(t, pty.SessionSpec{})

	pid := s.PID()
	if pid <= 0 {
		t.Fatalf("PID = %d", pid)
	}

	var slave string
	for _, fd := range []string{"0", "1", "2"} {
		link, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/fd/" + fd)
		if err != nil {
			t.Fatalf("readlink fd %s: %v", fd, err)
		}
		if !strings.HasPrefix(link, "/dev/pts/") {
			t.Fatalf("child fd %s is %q, want a /dev/pts device", fd, link)
		}
		if slave != "" && link != slave {
			t.Fatalf("child fd %s is %q, but fd 0 is %q", fd, link, slave)
		}
		slave = link
	}

	ptsNum, err := strconv.Atoi(strings.TrimPrefix(slave, "/dev/pts/"))
	if err != nil {
		t.Fatalf("pts number in %q: %v", slave, err)
	}

	sid, ttyNr := procStat(t, pid)
	if sid != pid {
		t.Errorf("session id = %d, pid = %d; setsid did not run", sid, pid)
	}
	// 136 is UNIX98_PTY_SLAVE_MAJOR; ptys past 256 spill into the next major.
	want := newEncodeDev(136+ptsNum/256, ptsNum%256)
	if ttyNr != want {
		t.Errorf("tty_nr = %d, want %d for %s; the pts is not the controlling terminal", ttyNr, want, slave)
	}
}

// The size a session is created with is the size the child sees. A terminal
// that lies about its dimensions renders every full-screen program wrong.
func TestSttyReportsTheCreatedSize(t *testing.T) {
	_, s := newSession(t, pty.SessionSpec{Rows: 24, Cols: 80})
	out, _ := attach(t, s, 0)

	var tp typer
	tp.send(t, s, "stty size\n")
	waitForText(t, out, "24 80")
}

// SPEC §8.2: "Support resize/SIGWINCH propagation". Both halves are asserted:
// the child is signalled, and the new size is what the tty reports afterwards.
// The trap body and the marker are built by shell string concatenation so the
// marker text can never appear in the terminal's echo of the typed line —
// otherwise this test would pass on echo alone.
func TestResizeSignalsTheChildAndChangesTheSize(t *testing.T) {
	_, s := newSession(t, pty.SessionSpec{Rows: 24, Cols: 80})
	out, _ := attach(t, s, 0)

	var tp typer
	tp.send(t, s, `trap 'printf "WIN""CHSEEN\n"' WINCH; printf "TRAP""READY\n"`+"\n")
	waitForText(t, out, "TRAPREADY")

	if err := s.Resize(40, 100); err != nil {
		t.Fatalf("resize: %v", err)
	}
	// An empty line returns the shell from readline, so a pending trap runs
	// promptly instead of at the mercy of the prompt's redisplay timing.
	tp.send(t, s, "\n")
	waitForText(t, out, "WINCHSEEN")

	tp.send(t, s, "stty size\n")
	waitForText(t, out, "40 100")

	if info := s.Info(); info.Rows != 40 || info.Cols != 100 {
		t.Errorf("Info reports %dx%d after resize, want 40x100", info.Rows, info.Cols)
	}
}

// SPEC §8.2: "A retransmitted accepted frame must not type the same text
// twice." The counter makes a second application visible even though the
// text repeats: MARK=2 can only appear if the line ran twice.
func TestRepeatedInputSequenceTypesOnce(t *testing.T) {
	_, s := newSession(t, pty.SessionSpec{})
	out, _ := attach(t, s, 0)

	const line = `i=$((i+1)); printf "MARK""=$i\n"` + "\n"

	if !s.Input(7, []byte(line)) {
		t.Fatal("first input at seq 7 was not applied")
	}
	waitForText(t, out, "MARK=1")

	if s.Input(7, []byte(line)) {
		t.Error("a retransmit of seq 7 was applied a second time")
	}
	if s.Input(3, []byte(line)) {
		t.Error("an older seq 3 was applied")
	}

	// The next real frame proves the counter is still at 1: MARK=2 here means
	// nothing ran in between.
	if !s.Input(8, []byte(line)) {
		t.Fatal("input at seq 8 was not applied")
	}
	waitForText(t, out, "MARK=2")

	if n := strings.Count(out.String(), "MARK="); n != 2 {
		t.Errorf("output carries %d MARK= lines, want 2:\n%s", n, out.String())
	}
}

// SPEC §8.1: "Disconnecting a tab detaches it, not the underlying shell."
func TestDetachLeavesTheShellRunningAndTheRingFilling(t *testing.T) {
	b, s := newSession(t, pty.SessionSpec{})
	out, reader := attach(t, s, 0)

	var tp typer
	tp.send(t, s, `printf "BEFORE""DETACH\n"`+"\n")
	waitForText(t, out, "BEFOREDETACH")

	if err := reader.Close(); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if err := syscall.Kill(s.PID(), 0); err != nil {
		t.Fatalf("child %d is gone after a detach: %v", s.PID(), err)
	}

	head := s.Info().Head
	tp.send(t, s, `printf "AFTER""DETACH\n"`+"\n")

	deadline := time.Now().Add(15 * time.Second)
	for s.Info().Head == head && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if s.Info().Head == head {
		t.Fatalf("ring head stayed at %d with nobody attached", head)
	}
	if _, ok := b.Get(s.ID()); !ok {
		t.Error("broker dropped the session when its reader detached")
	}

	// A new tab replays from the start and sees both halves.
	replay, _ := attach(t, s, 0)
	waitForText(t, replay, "BEFOREDETACH")
	waitForText(t, replay, "AFTERDETACH")
}

// Attaching behind the ring's tail is a replay gap, not a silent skip: §8.2
// requires the UI to be told so it can resynchronize the screen.
func TestAttachBehindTheTailReportsAGap(t *testing.T) {
	_, s := newSession(t, pty.SessionSpec{RingBytes: pty.MinRingBytes})

	var tp typer
	// yes(1) would outrun the assertion; a bounded loop overruns the small
	// ring by a known margin and then stops.
	tp.send(t, s, `i=0; while [ $i -lt 400 ]; do printf "0123456789012345678901234567890123456789\n"; i=$((i+1)); done; printf "FLOOD""DONE\n"`+"\n")

	out, _ := attach(t, s, 0)
	waitForText(t, out, "FLOODDONE")

	tail := s.Info().Tail
	if tail == 0 {
		t.Fatalf("ring tail is still 0 after flooding a %d byte ring", pty.MinRingBytes)
	}

	r, resume, gap, err := s.Attach(0)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer func() { _ = r.Close() }()
	if !gap {
		t.Error("attach at offset 0 reported no gap after the ring wrapped")
	}
	if resume < tail {
		t.Errorf("resume offset %d is behind the tail %d", resume, tail)
	}
}

// An offset the guest never produced is a host bug or a stale session, and
// answering it with a plausible-looking stream would invent evidence.
func TestAttachAheadOfTheHeadIsRefused(t *testing.T) {
	_, s := newSession(t, pty.SessionSpec{})
	if _, _, _, err := s.Attach(1 << 40); err == nil {
		t.Fatal("attach past the head was accepted")
	}
}

func TestCloseReapsAndReportsTheExitCode(t *testing.T) {
	b, s := newSession(t, pty.SessionSpec{SessionID: "exit-code"})
	out, _ := attach(t, s, 0)

	var tp typer
	tp.send(t, s, "exit 7\n")
	waitDone(t, s)
	_ = out

	if err := b.Close("exit-code"); err != nil {
		t.Fatalf("close: %v", err)
	}
	st, ok := s.Exit()
	if !ok {
		t.Fatal("Exit reports the session is still running after Close")
	}
	if st.Code == nil || *st.Code != 7 {
		t.Errorf("exit code = %v, want 7", st.Code)
	}
	if st.Signal != "" {
		t.Errorf("signal = %q, want none", st.Signal)
	}
	if st.Reason != "exited" {
		t.Errorf("reason = %q, want exited", st.Reason)
	}
	if _, found := b.Get("exit-code"); found {
		t.Error("closed session is still in the broker")
	}
	if got := b.List(); len(got) != 0 {
		t.Errorf("List has %d sessions after Close", len(got))
	}
	if err := b.Close("exit-code"); !errors.Is(err, pty.ErrUnknownSession) {
		t.Errorf("second close error = %v, want ErrUnknownSession", err)
	}
}

func TestKilledChildReportsTheSignal(t *testing.T) {
	_, s := newSession(t, pty.SessionSpec{})

	if err := syscall.Kill(s.PID(), syscall.SIGKILL); err != nil {
		t.Fatalf("kill: %v", err)
	}
	waitDone(t, s)

	st, ok := s.Exit()
	if !ok {
		t.Fatal("Exit reports the session is still running after SIGKILL")
	}
	if st.Signal != "SIGKILL" {
		t.Errorf("signal = %q, want SIGKILL", st.Signal)
	}
	if st.Code != nil {
		t.Errorf("exit code = %v, want none for a signalled child", *st.Code)
	}
	if st.Reason != "signaled" {
		t.Errorf("reason = %q, want signaled", st.Reason)
	}
}

// A dead session has an exit status; handing back an empty stream instead
// would leave the UI waiting on output that can never come.
func TestAttachToAnExitedSessionFails(t *testing.T) {
	_, s := newSession(t, pty.SessionSpec{})
	if err := syscall.Kill(s.PID(), syscall.SIGKILL); err != nil {
		t.Fatalf("kill: %v", err)
	}
	waitDone(t, s)

	_, _, _, err := s.Attach(0)
	if !errors.Is(err, pty.ErrSessionExited) {
		t.Fatalf("attach error = %v, want ErrSessionExited", err)
	}
	if !strings.Contains(err.Error(), "SIGKILL") {
		t.Errorf("attach error %q does not carry the exit status", err)
	}
}

// The broker notifies its owner when a child dies, so the attached
// connection can send terminal.closed without the control loop growing a
// push channel.
func TestExitNotifiesTheBrokerOwner(t *testing.T) {
	requireShell(t)
	exits := make(chan pty.SessionInfo, 1)
	b := pty.NewBroker(pty.BrokerConfig{OnExit: func(i pty.SessionInfo) { exits <- i }})
	s, err := b.Create(pty.SessionSpec{SessionID: "notify", Argv: []string{shell, "-i"}, Rows: 24, Cols: 80})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = b.Close("notify") })

	if err := syscall.Kill(s.PID(), syscall.SIGTERM); err != nil {
		t.Fatalf("kill: %v", err)
	}
	select {
	case info := <-exits:
		if info.SessionID != "notify" {
			t.Errorf("OnExit reported session %q", info.SessionID)
		}
		if !info.Exited || info.Exit.Signal != "SIGTERM" {
			t.Errorf("OnExit status = %+v, want a SIGTERM exit", info.Exit)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("OnExit never fired")
	}
}

// ring_bytes arrives off the wire, so the broker clamps it and reports what
// it actually allocated rather than echoing the number it was handed.
func TestRingSizeIsClampedAndReported(t *testing.T) {
	requireShell(t)
	cases := []struct {
		name string
		ask  int
		want int
	}{
		{"below the floor", 10, pty.MinRingBytes},
		{"unset", 0, pty.DefaultRingBytes},
		{"above the ceiling", 1 << 30, pty.MaxRingBytes},
		{"in range", 64 << 10, 64 << 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := pty.NewBroker(pty.BrokerConfig{})
			s, err := b.Create(pty.SessionSpec{SessionID: "ring", Argv: []string{shell, "-i"}, Rows: 24, Cols: 80, RingBytes: tc.ask})
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			defer func() { _ = b.Close("ring") }()
			if got := s.Info().RingBytes; got != tc.want {
				t.Errorf("ring_bytes %d became %d, want %d", tc.ask, got, tc.want)
			}
		})
	}
}

// SPEC §8.1: the session runs as an "approved guest user". A name the guest
// cannot resolve is refused rather than quietly downgraded to whoever guestd
// happens to be running as.
func TestCreateRefusesAnUnknownUser(t *testing.T) {
	requireShell(t)
	b := pty.NewBroker(pty.BrokerConfig{})
	_, err := b.Create(pty.SessionSpec{
		SessionID: "unknown-user",
		User:      "no-such-user-9f3a1c",
		Argv:      []string{shell, "-i"},
		Rows:      24, Cols: 80,
	})
	if err == nil {
		_ = b.Close("unknown-user")
		t.Fatal("Create with an unknown user was accepted")
	}
	if !errors.Is(err, pty.ErrUserUnknown) {
		t.Errorf("error = %v, want ErrUserUnknown", err)
	}
}

func TestDuplicateSessionIDIsRefused(t *testing.T) {
	b, _ := newSession(t, pty.SessionSpec{SessionID: "dup"})
	if _, err := b.Create(pty.SessionSpec{SessionID: "dup", Argv: []string{shell, "-i"}, Rows: 24, Cols: 80}); !errors.Is(err, pty.ErrSessionExists) {
		t.Fatalf("second Create with the same id: %v, want ErrSessionExists", err)
	}
}

func TestListReportsLiveSessions(t *testing.T) {
	b, s := newSession(t, pty.SessionSpec{SessionID: "listed", Rows: 30, Cols: 120})
	out, _ := attach(t, s, 0)

	var tp typer
	tp.send(t, s, `printf "LIST""MARK\n"`+"\n")
	waitForText(t, out, "LISTMARK")

	list := b.List()
	if len(list) != 1 {
		t.Fatalf("List has %d sessions, want 1", len(list))
	}
	got := list[0]
	if got.SessionID != "listed" || got.PID != s.PID() {
		t.Errorf("List entry = %+v, want session listed at pid %d", got, s.PID())
	}
	if got.Rows != 30 || got.Cols != 120 {
		t.Errorf("List reports %dx%d, want 30x120", got.Rows, got.Cols)
	}
	if got.Head == 0 {
		t.Error("List reports head 0 after the shell produced output")
	}
	if got.StartedAt.IsZero() {
		t.Error("List entry has no start time")
	}
}
