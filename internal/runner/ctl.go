// ABOUTME: Control socket for the runner: newline-delimited JSON over unix socket.
// ABOUTME: One command per connection; supports shutdown_guest and finalize commands.
package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
)

// ctlRequest is decoded from the incoming command connection.
type ctlRequest struct {
	Cmd    string `json:"cmd"`
	GraceS int    `json:"grace_s"`
}

// ctlReply is encoded back to the caller.
type ctlReply struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// CtlServer listens on a unix socket and dispatches commands to registered handlers.
type CtlServer struct {
	ln       net.Listener
	shutdown func(grace int) error
	finalize func() error
}

// ListenCtl creates a unix socket at sockPath (mode 0600) and starts serving
// ctl connections. shutdown and finalize may be nil if those commands should
// return a "not supported" error. Connections are handled one-at-a-time per
// goroutine; the listener stays open until Close is called.
func ListenCtl(ctx context.Context, sockPath string, shutdown func(int) error, finalize func() error) (*CtlServer, error) {
	// Remove stale socket if it exists.
	_ = os.Remove(sockPath)

	// Set umask so the socket is created 0600.
	old := applyUmask(0o177)
	ln, lnErr := net.Listen("unix", sockPath)
	applyUmask(old)
	if lnErr != nil {
		return nil, fmt.Errorf("runner ctl: listen %s: %w", sockPath, lnErr)
	}

	srv := &CtlServer{
		ln:       ln,
		shutdown: shutdown,
		finalize: finalize,
	}
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
		go s.handle(conn)
	}
}

// handle reads one command from conn, dispatches it, and writes the reply.
func (s *CtlServer) handle(conn net.Conn) {
	defer conn.Close()
	var req ctlRequest
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&req); err != nil {
		// Malformed command — write error and close.
		reply := ctlReply{OK: false, Error: "malformed command"}
		_ = json.NewEncoder(conn).Encode(reply)
		return
	}

	var reply ctlReply
	switch req.Cmd {
	case "shutdown_guest":
		if s.shutdown == nil {
			reply = ctlReply{OK: false, Error: "shutdown not available"}
		} else if err := s.shutdown(req.GraceS); err != nil {
			reply = ctlReply{OK: false, Error: err.Error()}
		} else {
			reply = ctlReply{OK: true}
		}
	case "finalize":
		if s.finalize == nil {
			reply = ctlReply{OK: false, Error: "finalize not available"}
		} else if err := s.finalize(); err != nil {
			reply = ctlReply{OK: false, Error: err.Error()}
		} else {
			reply = ctlReply{OK: true}
		}
	default:
		reply = ctlReply{OK: false, Error: fmt.Sprintf("unknown cmd %q", req.Cmd)}
	}

	_ = json.NewEncoder(conn).Encode(reply)
}
