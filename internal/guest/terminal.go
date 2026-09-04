// ABOUTME: Guest terminal service: the terminal.* control verbs, and one byte
// ABOUTME: stream per attached session on its own vsock port (SPEC §8.1-§8.3).
package guest

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/2389-research/observatory-v2/internal/guest/proto"
	"github.com/2389-research/observatory-v2/internal/guest/pty"
)

const (
	// streamChunk is §8.3's terminal.max_wire_chunk_bytes default, so one read
	// of the replay ring fills at most one wire frame.
	streamChunk = 32 << 10
	// exitStatusWait bounds how long a stream waits for the reaper to record
	// an exit status before reporting the close without one. An unknown status
	// is reported as unknown; it is never guessed.
	exitStatusWait = 3 * time.Second
)

// ServeStreams accepts session byte streams from ln until ctx is cancelled or
// ln is closed. Each connection carries exactly one session's output and input;
// the listener is NOT closed by ServeStreams.
func (a *Agent) ServeStreams(ctx context.Context, ln net.Listener) error {
	return a.accept(ctx, ln, a.handleStream)
}

// serveTerminal answers one terminal control verb. The returned error is a
// transport failure and ends the connection; a verb the guest refuses is
// answered with terminal.error and is not an error here.
func (a *Agent) serveTerminal(conn net.Conn, env proto.Envelope) error {
	switch env.Kind {
	case proto.KindTerminalCreate:
		var req proto.TerminalCreate
		if err := json.Unmarshal(env.Data, &req); err != nil {
			return a.terminalError(conn, "malformed_request", "terminal.create payload is not valid JSON")
		}
		sess, err := a.broker.Create(pty.SessionSpec{
			SessionID: req.SessionID,
			User:      req.User,
			Cwd:       req.Cwd,
			Argv:      req.Argv,
			Term:      req.Term,
			Rows:      req.Rows,
			Cols:      req.Cols,
			RingBytes: req.RingBytes,
		})
		if err != nil {
			return a.terminalError(conn, terminalCause(err), err.Error())
		}
		return a.writeControl(conn, proto.KindTerminalCreated, proto.TerminalCreated{
			SessionID: sess.ID(),
			PID:       sess.PID(),
			StartedAt: sess.Info().StartedAt.UTC().Format(time.RFC3339Nano),
		})

	case proto.KindTerminalClose:
		var req proto.TerminalClose
		if err := json.Unmarshal(env.Data, &req); err != nil {
			return a.terminalError(conn, "malformed_request", "terminal.close payload is not valid JSON")
		}
		// The session handle is taken before Close removes it from the broker,
		// so the reply can carry the real exit status rather than "gone".
		sess, ok := a.broker.Get(req.SessionID)
		if !ok {
			return a.terminalError(conn, "session_unknown", fmt.Sprintf("no such session: %s", req.SessionID))
		}
		if err := a.broker.Close(req.SessionID); err != nil {
			return a.terminalError(conn, terminalCause(err), err.Error())
		}
		return a.writeControl(conn, proto.KindTerminalClosed, closedFrom(sess))

	case proto.KindTerminalList:
		infos := a.broker.List()
		out := make([]proto.TerminalSession, 0, len(infos))
		for _, in := range infos {
			out = append(out, proto.TerminalSession{
				SessionID:  in.SessionID,
				PID:        in.PID,
				Rows:       in.Rows,
				Cols:       in.Cols,
				HeadOffset: strconv.FormatUint(in.Head, 10),
				TailOffset: strconv.FormatUint(in.Tail, 10),
			})
		}
		return a.writeControl(conn, proto.KindTerminalSessions, proto.TerminalSessions{Sessions: out})
	}
	return a.terminalError(conn, "unsupported", fmt.Sprintf("unsupported terminal verb %q", env.Kind))
}

// closedFrom renders how a session ended. Broker.Close returns only after the
// child is reaped, so the status is already recorded by the time this runs.
func closedFrom(sess *pty.Session) proto.TerminalClosed {
	closed := proto.TerminalClosed{SessionID: sess.ID(), Reason: "closed"}
	if status, exited := sess.Exit(); exited {
		closed.ExitCode = status.Code
		closed.Signal = status.Signal
		if status.Reason != "" {
			closed.Reason = status.Reason
		}
	}
	return closed
}

func (a *Agent) terminalError(conn net.Conn, cause, message string) error {
	return a.writeControl(conn, proto.KindTerminalError, proto.TerminalError{Cause: cause, Message: message})
}

// terminalCause maps a broker failure to a stable cause string. The host turns
// a cause into remediation; the guest knows what went wrong, not what an
// operator should do about it.
func terminalCause(err error) string {
	switch {
	case errors.Is(err, pty.ErrArgvInvalid):
		return "argv_invalid"
	case errors.Is(err, pty.ErrSessionExists):
		return "session_exists"
	case errors.Is(err, pty.ErrUnknownSession):
		return "session_unknown"
	case errors.Is(err, pty.ErrSessionExited):
		return "session_exited"
	case errors.Is(err, pty.ErrUserUnknown):
		return "user_unknown"
	case errors.Is(err, pty.ErrOffsetAhead):
		return "offset_ahead"
	default:
		return "session_failed"
	}
}

// handleStream runs one session's byte stream: the same authenticated hello as
// the control channel, extended with the session to attach and where to resume,
// then frames in both directions until either end goes away.
func (a *Agent) handleStream(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	defer closeOnCancel(ctx, conn)()

	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return
	}
	env, err := proto.ReadControl(conn)
	if err != nil {
		a.sendError(conn, "read stream hello")
		return
	}
	if env.Kind != proto.KindHello {
		a.sendError(conn, "expected hello")
		return
	}
	var hello proto.Hello
	if err := json.Unmarshal(env.Data, &hello); err != nil {
		a.sendError(conn, "malformed hello")
		return
	}
	if reason := a.authHello(hello); reason != "" {
		_ = a.writeControl(conn, proto.KindHelloAck, proto.HelloAck{Accepted: false, Reason: reason})
		return
	}

	sess, ok := a.broker.Get(hello.SessionID)
	if !ok {
		_ = a.writeControl(conn, proto.KindHelloAck, proto.HelloAck{
			Accepted: false,
			Reason:   fmt.Sprintf("no such session: %s", hello.SessionID),
		})
		return
	}
	var after uint64
	if hello.AfterOffset != "" {
		v, err := strconv.ParseUint(hello.AfterOffset, 10, 64)
		if err != nil {
			_ = a.writeControl(conn, proto.KindHelloAck, proto.HelloAck{
				Accepted: false,
				Reason:   "after_offset must be a decimal string",
			})
			return
		}
		after = v
	}
	rd, resume, gap, err := sess.Attach(after)
	if err != nil {
		_ = a.writeControl(conn, proto.KindHelloAck, proto.HelloAck{Accepted: false, Reason: err.Error()})
		return
	}
	defer rd.Close()

	if err := a.writeControl(conn, proto.KindHelloAck, proto.HelloAck{
		Accepted:     true,
		ResumeOffset: strconv.FormatUint(resume, 10),
		Gap:          gap,
	}); err != nil {
		return
	}

	// A terminal idles for hours between keystrokes, and a stalled reader is
	// backpressure rather than a fault (§8.3). Neither side gets a deadline
	// past the handshake; the connection closing is what ends this.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return
	}

	sc := &streamConn{c: conn}
	var detached atomic.Bool
	inDone := make(chan struct{})
	go func() {
		defer close(inDone)
		a.streamIn(sc, sess)
		// The caller hung up. Closing the attachment wakes the output pump,
		// which must then keep quiet: this is a detach, not a session exit.
		detached.Store(true)
		rd.Close()
	}()

	a.streamOut(sc, sess, rd, resume, &detached)
	conn.Close() // unblock the input pump if it is still parked on a read
	<-inDone
}

// streamOut copies the session's output to the caller as PTY frames, each
// stamped with the absolute stream offset of its first byte.
//
// The offset is derived rather than asked for: the attachment advances by
// exactly the number of bytes each Read returns, and a drop resets it to the
// range's end. So a drop sets cur to the reported To, and every read advances
// cur by n. That stays exact across drops without the attachment having to
// publish its cursor.
func (a *Agent) streamOut(sc *streamConn, sess *pty.Session, rd io.Reader, resume uint64, detached *atomic.Bool) {
	reporter, _ := rd.(pty.DropReporter)
	cur := resume
	buf := make([]byte, streamChunk)
	frame := make([]byte, 8+streamChunk)
	for {
		n, err := rd.Read(buf)
		if reporter != nil {
			if r, ok := reporter.Dropped(); ok {
				if werr := sc.control(proto.KindTerminalDropped, proto.TerminalDropped{
					FromOffset: strconv.FormatUint(r.From, 10),
					ToOffset:   strconv.FormatUint(r.To, 10),
				}); werr != nil {
					return
				}
				cur = r.To
			}
		}
		if n > 0 {
			binary.BigEndian.PutUint64(frame[:8], cur)
			copy(frame[8:], buf[:n])
			if werr := sc.frame(proto.FramePTY, frame[:8+n]); werr != nil {
				return
			}
			cur += uint64(n)
		}
		if err != nil {
			if detached.Load() {
				return
			}
			// The output ended because the child did. The control loop is
			// request/response, so this stream is the only place that can tell
			// an attached caller how the session ended.
			select {
			case <-sess.Done():
			case <-time.After(exitStatusWait):
			}
			_ = sc.control(proto.KindTerminalClosed, closedFrom(sess))
			return
		}
	}
}

// streamIn applies the caller's keystrokes and resizes to the session.
func (a *Agent) streamIn(sc *streamConn, sess *pty.Session) {
	for {
		typ, payload, err := proto.ReadFrame(sc.c)
		if err != nil {
			return
		}
		switch typ {
		case proto.FramePTY:
			if len(payload) < 8 {
				// A PTY frame without its sequence number is not decodable;
				// guessing which bytes are input would type garbage at a shell.
				return
			}
			sess.Input(binary.BigEndian.Uint64(payload[:8]), payload[8:])
		case proto.FrameControl:
			var env proto.Envelope
			if json.Unmarshal(payload, &env) != nil || env.Kind != proto.KindTerminalResize {
				continue
			}
			var rz proto.TerminalResize
			if json.Unmarshal(env.Data, &rz) != nil {
				continue
			}
			if err := sess.Resize(rz.Rows, rz.Cols); err != nil {
				if werr := sc.control(proto.KindTerminalError, proto.TerminalError{
					Cause:   "resize_failed",
					Message: err.Error(),
				}); werr != nil {
					return
				}
			}
		}
	}
}

// streamConn serializes the two writers on a session stream: the output pump
// and the input pump's error replies share one connection.
type streamConn struct {
	c  net.Conn
	mu sync.Mutex
}

func (s *streamConn) frame(typ byte, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return proto.WriteFrame(s.c, typ, payload)
}

func (s *streamConn) control(kind string, data any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return proto.WriteControl(s.c, kind, data)
}
