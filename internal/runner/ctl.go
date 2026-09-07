// ABOUTME: Control socket for the runner: newline-delimited JSON over unix socket.
// ABOUTME: One command per connection, except terminal-attach, which becomes a stream.
package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/2389-research/observatory/internal/guest/proto"
)

// CtlRequest is one command on the runner control socket. It is exported
// because both ends of this wire live outside this file: the server below
// decodes it, and two encoders send it — CtlClient, used by the host's terminal
// registry, and the jailer's dialCtl, which stops a guest before teardown. Two
// definitions of one wire is a protocol that drifts.
type CtlRequest struct {
	Cmd    string `json:"cmd"`
	GraceS int    `json:"grace_s,omitempty"`
	// Terminal carries the arguments of a terminal-* command. It is a nested
	// block rather than more top-level fields so the two command families
	// cannot collide as either grows.
	Terminal *TerminalCtlRequest `json:"terminal,omitempty"`
}

// CtlReply is the answer to one CtlRequest.
type CtlReply struct {
	OK       bool              `json:"ok"`
	Error    string            `json:"error,omitempty"`
	Terminal *TerminalCtlReply `json:"terminal,omitempty"`
}

// CtlHandlers are the commands a ctl server can serve. A nil handler answers
// "not available" rather than failing the connection.
type CtlHandlers struct {
	Shutdown func(graceS int) error
	Finalize func() error

	TerminalCreate func(context.Context, TerminalCtlRequest) (TerminalCtlReply, error)
	TerminalClose  func(context.Context, TerminalCtlRequest) (TerminalCtlReply, error)
	TerminalList   func(context.Context) (TerminalCtlReply, error)
	// TerminalAttach returns a relay that owns the guest side of a session
	// stream. The caller's connection becomes the other side of it.
	TerminalAttach func(context.Context, TerminalCtlRequest) (*Relay, TerminalCtlReply, error)
}

// CtlServer listens on a unix socket and dispatches commands to registered handlers.
type CtlServer struct {
	ln net.Listener
	h  CtlHandlers
}

// ListenCtl creates a unix socket at sockPath (mode 0600) and starts serving
// ctl connections. Any handler in h may be nil, in which case that command
// returns a "not available" error. Connections are handled one-at-a-time per
// goroutine; the listener stays open until Close is called.
func ListenCtl(ctx context.Context, sockPath string, h CtlHandlers) (*CtlServer, error) {
	// Remove stale socket if it exists.
	_ = os.Remove(sockPath)

	// Set umask so the socket is created 0600.
	old := applyUmask(0o177)
	ln, lnErr := net.Listen("unix", sockPath)
	applyUmask(old)
	if lnErr != nil {
		return nil, fmt.Errorf("runner ctl: listen %s: %w", sockPath, lnErr)
	}

	srv := &CtlServer{ln: ln, h: h}
	go srv.serve(ctx)
	return srv, nil
}

// Close closes the listener, stopping the serve loop.
func (s *CtlServer) Close() {
	_ = s.ln.Close()
}

// serve accepts connections until the context is done or the listener is closed.
func (s *CtlServer) serve(ctx context.Context) {
	go func() {
		<-ctx.Done()
		_ = s.ln.Close()
	}()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(ctx, conn)
	}
}

// handle reads one command from conn, dispatches it, and writes the reply.
// terminal-attach is the exception: its reply is followed by a frame stream,
// so it keeps the connection for as long as the session is attached.
func (s *CtlServer) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	var req CtlRequest
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&req); err != nil {
		// Malformed command — write error and close.
		reply := CtlReply{OK: false, Error: "malformed command"}
		_ = json.NewEncoder(conn).Encode(reply)
		return
	}

	if req.Cmd == "terminal-attach" {
		s.attach(ctx, conn, dec, req)
		return
	}

	var reply CtlReply
	switch req.Cmd {
	case "shutdown_guest":
		if s.h.Shutdown == nil {
			reply = CtlReply{OK: false, Error: "shutdown not available"}
		} else if err := s.h.Shutdown(req.GraceS); err != nil {
			reply = CtlReply{OK: false, Error: err.Error()}
		} else {
			reply = CtlReply{OK: true}
		}
	case "finalize":
		if s.h.Finalize == nil {
			reply = CtlReply{OK: false, Error: "finalize not available"}
		} else if err := s.h.Finalize(); err != nil {
			reply = CtlReply{OK: false, Error: err.Error()}
		} else {
			reply = CtlReply{OK: true}
		}
	case "terminal-create":
		reply = terminalReply(func() (TerminalCtlReply, error) {
			if s.h.TerminalCreate == nil {
				return TerminalCtlReply{}, errNotAvailable("terminal-create")
			}
			if req.Terminal == nil {
				return TerminalCtlReply{}, errNeedsTerminalBlock("terminal-create")
			}
			return s.h.TerminalCreate(ctx, *req.Terminal)
		})
	case "terminal-close":
		reply = terminalReply(func() (TerminalCtlReply, error) {
			if s.h.TerminalClose == nil {
				return TerminalCtlReply{}, errNotAvailable("terminal-close")
			}
			if req.Terminal == nil {
				return TerminalCtlReply{}, errNeedsTerminalBlock("terminal-close")
			}
			return s.h.TerminalClose(ctx, *req.Terminal)
		})
	case "terminal-list":
		reply = terminalReply(func() (TerminalCtlReply, error) {
			if s.h.TerminalList == nil {
				return TerminalCtlReply{}, errNotAvailable("terminal-list")
			}
			return s.h.TerminalList(ctx)
		})
	default:
		reply = CtlReply{OK: false, Error: fmt.Sprintf("unknown cmd %q", req.Cmd)}
	}

	_ = json.NewEncoder(conn).Encode(reply)
}

func errNotAvailable(cmd string) error { return fmt.Errorf("%s not available", cmd) }
func errNeedsTerminalBlock(c string) error {
	return fmt.Errorf("%s needs a terminal block", c)
}

// terminalReply runs one terminal command and renders its outcome.
func terminalReply(run func() (TerminalCtlReply, error)) CtlReply {
	out, err := run()
	if err != nil {
		return CtlReply{OK: false, Error: err.Error()}
	}
	return CtlReply{OK: true, Terminal: &out}
}

// attach answers a terminal-attach and then hands the connection to the relay.
// The reply goes first because it carries the offset the caller's first frame
// will be stamped with; frames follow it on the same connection.
func (s *CtlServer) attach(ctx context.Context, conn net.Conn, dec *json.Decoder, req CtlRequest) {
	enc := json.NewEncoder(conn)
	if s.h.TerminalAttach == nil {
		_ = enc.Encode(CtlReply{OK: false, Error: errNotAvailable("terminal-attach").Error()})
		return
	}
	if req.Terminal == nil {
		_ = enc.Encode(CtlReply{OK: false, Error: errNeedsTerminalBlock("terminal-attach").Error()})
		return
	}
	relay, out, err := s.h.TerminalAttach(ctx, *req.Terminal)
	if err != nil {
		_ = enc.Encode(CtlReply{OK: false, Error: err.Error()})
		return
	}
	defer relay.Close()
	if err := enc.Encode(CtlReply{OK: true, Terminal: &out}); err != nil {
		return
	}

	_ = relay.Run(FrameStream(dec, conn), conn)
}

// terminalReplyError renders a guest answer that is not the one asked for.
func terminalReplyError(env proto.Envelope) error {
	if env.Kind == proto.KindTerminalError {
		var te proto.TerminalError
		if json.Unmarshal(env.Data, &te) == nil {
			return fmt.Errorf("%s: %s", te.Cause, te.Message)
		}
	}
	return fmt.Errorf("the guest answered %q", env.Kind)
}

// --- the client side ------------------------------------------------------

// CtlClient sends one command on a runner control socket. The server handles
// one command per connection, so a client owns its connection for exactly one
// command: Do closes it, and Attach hands it on to the caller.
type CtlClient struct {
	conn net.Conn
}

// NewCtlClient wraps an already-dialled control socket connection.
func NewCtlClient(conn net.Conn) *CtlClient { return &CtlClient{conn: conn} }

// DialCtl connects to a runner's control socket.
func DialCtl(ctx context.Context, sockPath string) (*CtlClient, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("dial runner ctl %s: %w", sockPath, err)
	}
	return NewCtlClient(conn), nil
}

// Do sends one command, reads its reply, and closes the connection. A reply
// carrying OK: false is returned as an error naming what the runner said.
func (c *CtlClient) Do(ctx context.Context, req CtlRequest) (CtlReply, error) {
	defer c.conn.Close()
	reply, _, err := c.send(ctx, req)
	if err != nil {
		return CtlReply{}, err
	}
	if !reply.OK {
		return reply, fmt.Errorf("runner refused %s: %s", req.Cmd, reply.Error)
	}
	return reply, nil
}

// Attach sends terminal-attach and, on success, hands back the connection as
// the session's frame stream. The caller owns it and must Close it; on any
// error Attach has already closed it.
//
// Deadlines are cleared before the stream is returned: an attached terminal may
// idle for hours, and a quiet shell is not a stalled one.
func (c *CtlClient) Attach(ctx context.Context, req TerminalCtlRequest) (CtlReply, io.ReadWriteCloser, error) {
	reply, dec, err := c.send(ctx, CtlRequest{Cmd: "terminal-attach", Terminal: &req})
	if err != nil {
		c.conn.Close()
		return CtlReply{}, nil, err
	}
	if !reply.OK {
		c.conn.Close()
		return reply, nil, fmt.Errorf("runner refused terminal-attach: %s", reply.Error)
	}
	if err := c.conn.SetDeadline(time.Time{}); err != nil {
		c.conn.Close()
		return CtlReply{}, nil, fmt.Errorf("clear ctl deadline: %w", err)
	}
	return reply, &attachStream{r: FrameStream(dec, c.conn), conn: c.conn}, nil
}

// send writes one command and decodes one reply, leaving the connection open
// and returning the decoder so an attach can splice its frame phase on.
func (c *CtlClient) send(ctx context.Context, req CtlRequest) (CtlReply, *json.Decoder, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(terminalRequestTimeout)
	}
	if err := c.conn.SetDeadline(deadline); err != nil {
		return CtlReply{}, nil, fmt.Errorf("set ctl deadline: %w", err)
	}
	if err := json.NewEncoder(c.conn).Encode(req); err != nil {
		return CtlReply{}, nil, fmt.Errorf("encode %s: %w", req.Cmd, err)
	}
	dec := json.NewDecoder(c.conn)
	var reply CtlReply
	if err := dec.Decode(&reply); err != nil {
		return CtlReply{}, nil, fmt.Errorf("decode %s reply: %w", req.Cmd, err)
	}
	return reply, dec, nil
}

// attachStream is an attached connection with the frame bytes the JSON decoder
// read ahead put back in front of it.
type attachStream struct {
	r    io.Reader
	conn net.Conn
}

func (s *attachStream) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *attachStream) Write(p []byte) (int, error) { return s.conn.Write(p) }
func (s *attachStream) Close() error                { return s.conn.Close() }
