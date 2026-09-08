// ABOUTME: The browser's terminal WebSocket: every gate answers as plain HTTP
// ABOUTME: before the upgrade, and the relay stays bounded and honest (§8.2-8.4).
package api

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"

	"github.com/2389-research/observatory/internal/guest/proto"
	"github.com/2389-research/observatory/internal/terminal"
)

// ptyOffsetBytes is the big-endian prefix on every PTY message: the absolute
// stream offset going out, the browser's sequence number coming in.
const ptyOffsetBytes = 8

// wireStreamMsg is one host-to-browser control message. Writer carries no
// omitempty: "you may not type" is the message a demoted writer needs, and an
// omitted field reads as no news at all.
type wireStreamMsg struct {
	Type             string `json:"type"`
	SessionID        string `json:"session_id,omitempty"`
	ConnID           string `json:"conn_id,omitempty"`
	ResumeOffset     string `json:"resume_offset,omitempty"`
	Gap              bool   `json:"gap,omitempty"`
	Writer           bool   `json:"writer"`
	Holder           string `json:"holder,omitempty"`
	MaxInflightBytes string `json:"max_inflight_bytes,omitempty"`
	Reason           string `json:"reason,omitempty"`
	FromOffset       string `json:"from_offset,omitempty"`
	ToOffset         string `json:"to_offset,omitempty"`
	Cause            string `json:"cause,omitempty"`
	Message          string `json:"message,omitempty"`
	ExitCode         *int   `json:"exit_code,omitempty"`
	Signal           string `json:"signal,omitempty"`
}

// browserStreamMsg is one browser-to-host control message.
type browserStreamMsg struct {
	Type   string `json:"type"`
	Offset string `json:"offset"`
	Rows   uint16 `json:"rows"`
	Cols   uint16 `json:"cols"`
	Mode   string `json:"mode"`
}

// handleTerminalStream attaches a browser to a session's byte stream.
//
// Every refusal happens before the upgrade, so it is an ordinary HTTP response
// with a typed body rather than a socket that opens and immediately closes. The
// origin gate runs earlier still, in withAuth: a cross-origin page must not
// learn even that the route exists.
func (s *Server) handleTerminalStream(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	sess, ok := s.terminals.Get(sessionID)
	if !ok {
		writeTerminalNotFound(w, sessionID)
		return
	}
	if !s.terminalOwner(w, r, sess) {
		return
	}

	att, err := s.terminals.Attach(r.Context(), terminal.AttachRequest{
		SessionID: sessionID,
		ConnID:    uuid.NewString(),
	})
	if err != nil {
		writeTerminalError(w, sessionID, err)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// §7.4: never compress a stream that mixes attacker-influenced output
		// with whatever the operator types into it.
		CompressionMode: websocket.CompressionDisabled,
		// The origin gate in withAuth already ran and is stricter than this
		// library's, which treats an absent Origin as same-origin.
		InsecureSkipVerify: true,
	})
	if err != nil {
		_ = att.Close()
		return
	}
	// A paste arrives as one message and the guest's own frame cap is the
	// honest ceiling for it.
	conn.SetReadLimit(proto.MaxBinaryFrame)

	rl := &streamRelay{
		conn:      conn,
		att:       att,
		registry:  s.terminals,
		sessionID: sessionID,
		acked:     make(chan struct{}, 1),
	}
	rl.run(r.Context())
}

// streamRelay moves bytes between one browser and one session. It parses just
// enough of each frame to count, bound and gate it; the PTY payload passes
// through untouched, and no shell is ever started here.
type streamRelay struct {
	conn      *websocket.Conn
	att       *terminal.Attachment
	registry  *terminal.Registry
	sessionID string

	// acked wakes the guest pump when the browser reports progress. It is
	// buffered so an ack that lands between a failed reserve and the wait is
	// not lost.
	acked chan struct{}

	// lastClientSeq is the highest sequence this browser has sent. Only the
	// browser pump touches it.
	lastClientSeq uint64
}

func (rl *streamRelay) run(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := rl.send(ctx, wireStreamMsg{
		Type:             "attached",
		SessionID:        rl.sessionID,
		ConnID:           rl.att.ConnID(),
		ResumeOffset:     strconv.FormatUint(rl.att.ResumeOffset, 10),
		Gap:              rl.att.Gap,
		Writer:           rl.att.IsWriter(),
		Holder:           rl.att.Holder(),
		MaxInflightBytes: strconv.FormatInt(rl.att.MaxInflight(), 10),
	}); err != nil {
		_ = rl.att.Close()
		_ = rl.conn.CloseNow()
		return
	}

	// Whichever side ends first cancels; this unblocks the other, which is
	// parked on a read that no context can interrupt.
	go func() {
		<-ctx.Done()
		_ = rl.att.Close()
		_ = rl.conn.CloseNow()
	}()
	go rl.watchLease(ctx)
	go func() { defer cancel(); _ = terminalHeartbeat(ctx, rl.conn, 30*time.Second, 10*time.Second) }()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); defer cancel(); rl.pumpGuest(ctx) }()
	go func() { defer wg.Done(); defer cancel(); rl.pumpBrowser(ctx) }()
	wg.Wait()
}

// pumpGuest carries output to the browser, bounded by the in-flight window.
func (rl *streamRelay) pumpGuest(ctx context.Context) {
	for {
		typ, payload, err := rl.att.ReadFrame()
		if err != nil {
			if ctx.Err() == nil {
				_ = rl.send(ctx, wireStreamMsg{
					Type:   "closed",
					Reason: "the session's byte stream ended",
					Writer: rl.att.IsWriter(),
				})
			}
			return
		}
		switch typ {
		case proto.FramePTY:
			if len(payload) < ptyOffsetBytes {
				continue
			}
			offset := binary.BigEndian.Uint64(payload[:ptyOffsetBytes])
			if err := rl.sendOutput(ctx, offset, payload[ptyOffsetBytes:]); err != nil {
				return
			}
		case proto.FrameControl:
			if err := rl.forwardGuestControl(ctx, payload); err != nil {
				return
			}
		}
	}
}

// sendOutput hands the browser one run of shell output, split so each piece
// fits the window. The offset travels with every piece: a browser that has to
// count bytes to know where it is cannot report a gap.
func (rl *streamRelay) sendOutput(ctx context.Context, offset uint64, b []byte) error {
	limit := int(rl.att.MaxInflight())
	for len(b) > 0 {
		n := len(b)
		if n > limit {
			n = limit
		}
		if err := rl.reserve(ctx, n); err != nil {
			return err
		}
		msg := make([]byte, ptyOffsetBytes+n)
		binary.BigEndian.PutUint64(msg[:ptyOffsetBytes], offset)
		copy(msg[ptyOffsetBytes:], b[:n])
		if err := rl.conn.Write(ctx, websocket.MessageBinary, msg); err != nil {
			return err
		}
		offset += uint64(n)
		b = b[n:]
	}
	return nil
}

// reserve waits for window room. Waiting rather than dropping is the point:
// the host never discards output it was handed, so the only gap a browser ever
// sees is one the guest reported (§8.3).
func (rl *streamRelay) reserve(ctx context.Context, n int) error {
	for !rl.att.Reserve(n) {
		select {
		case <-rl.acked:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// forwardGuestControl translates the guest's session-scoped control messages.
// A frame this host cannot parse is reported rather than swallowed, and does
// not end the shell.
func (rl *streamRelay) forwardGuestControl(ctx context.Context, payload []byte) error {
	var env proto.Envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return rl.sendError(ctx, "guest_protocol_error",
			"the guest sent a control frame this host could not decode")
	}
	switch env.Kind {
	case proto.KindTerminalDropped:
		var d proto.TerminalDropped
		if err := json.Unmarshal(env.Data, &d); err != nil {
			return rl.sendError(ctx, "guest_protocol_error",
				"the guest reported dropped output in a form this host could not decode")
		}
		return rl.send(ctx, wireStreamMsg{
			Type:       "dropped",
			FromOffset: d.FromOffset,
			ToOffset:   d.ToOffset,
			Writer:     rl.att.IsWriter(),
		})
	case proto.KindTerminalError:
		var e proto.TerminalError
		if err := json.Unmarshal(env.Data, &e); err != nil {
			return rl.sendError(ctx, "guest_protocol_error",
				"the guest reported an error in a form this host could not decode")
		}
		return rl.sendError(ctx, e.Cause, e.Message)
	case proto.KindTerminalClosed:
		var c proto.TerminalClosed
		if err := json.Unmarshal(env.Data, &c); err != nil {
			return rl.sendError(ctx, "guest_protocol_error",
				"the guest reported a close in a form this host could not decode")
		}
		return rl.send(ctx, wireStreamMsg{
			Type:     "closed",
			Reason:   c.Reason,
			ExitCode: c.ExitCode,
			Signal:   c.Signal,
			Writer:   rl.att.IsWriter(),
		})
	}
	return nil
}

// pumpBrowser carries keystrokes and control messages toward the guest.
func (rl *streamRelay) pumpBrowser(ctx context.Context) {
	for {
		typ, data, err := rl.conn.Read(ctx)
		if err != nil {
			return
		}
		switch typ {
		case websocket.MessageBinary:
			if err := rl.handleInput(ctx, data); err != nil {
				return
			}
		case websocket.MessageText:
			if err := rl.handleBrowserControl(ctx, data); err != nil {
				return
			}
		}
	}
}

// handleInput delivers one keystroke message. A repeated sequence number is a
// resend after a hiccup and is delivered once; input from a read-only
// connection is refused out loud, because a keystroke that vanishes silently
// looks exactly like a hung shell (§8.2).
func (rl *streamRelay) handleInput(ctx context.Context, data []byte) error {
	if len(data) < ptyOffsetBytes {
		return rl.sendError(ctx, "malformed_input",
			"an input message starts with an 8-byte big-endian sequence number")
	}
	seq := binary.BigEndian.Uint64(data[:ptyOffsetBytes])
	if seq <= rl.lastClientSeq {
		return nil
	}
	rl.lastClientSeq = seq

	if err := rl.att.WriteInput(data[ptyOffsetBytes:]); err != nil {
		if errors.Is(err, terminal.ErrReadOnly) {
			return rl.sendLease(ctx,
				"this connection is read-only, so those keystrokes were not delivered; steal the writer lease to type")
		}
		return err
	}
	return nil
}

// handleBrowserControl applies one browser control message.
func (rl *streamRelay) handleBrowserControl(ctx context.Context, data []byte) error {
	var m browserStreamMsg
	if err := json.Unmarshal(data, &m); err != nil {
		return rl.sendError(ctx, "malformed_message",
			"a control message must be a JSON object with a type field")
	}
	switch m.Type {
	case "ack":
		offset, err := strconv.ParseUint(m.Offset, 10, 64)
		if err != nil {
			return rl.sendError(ctx, "malformed_message",
				"an ack carries the consumed stream offset as a decimal string")
		}
		rl.att.Ack(offset)
		select {
		case rl.acked <- struct{}{}:
		default:
		}
		return nil
	case "resize":
		err := rl.att.WriteControl(proto.KindTerminalResize, proto.TerminalResize{Rows: m.Rows, Cols: m.Cols})
		if errors.Is(err, terminal.ErrReadOnly) {
			return rl.sendLease(ctx,
				"this connection is read-only, so the shell was not resized; steal the writer lease first")
		}
		return err
	case "lease":
		return rl.applyLease(ctx, terminal.LeaseMode(m.Mode))
	default:
		return rl.sendError(ctx, "malformed_message",
			"a control message type is one of ack, resize or lease")
	}
}

// applyLease runs a lease request through the registry, which owns the rules.
func (rl *streamRelay) applyLease(ctx context.Context, mode terminal.LeaseMode) error {
	before := rl.att.IsWriter()
	res, err := rl.registry.RequestLease(rl.sessionID, rl.att.ConnID(), mode)
	if err != nil {
		var te *terminal.Error
		if errors.As(err, &te) {
			return rl.sendError(ctx, te.Cause, te.Message)
		}
		return err
	}
	// A change reaches every connection through the lease watcher, this one
	// included. Answering here as well would send the same news twice, so the
	// direct reply is for requests that moved nothing.
	if rl.att.IsWriter() == before {
		return rl.send(ctx, wireStreamMsg{
			Type:   "lease",
			Writer: res.Writer,
			Holder: res.Holder,
			Reason: res.Reason,
		})
	}
	return nil
}

// watchLease tells this browser whenever the writer changes. §8.2 takes the
// shell at the instant of a steal, and a page still showing a writer badge is
// telling its operator something untrue.
func (rl *streamRelay) watchLease(ctx context.Context) {
	for {
		changed := rl.att.LeaseChanged()
		select {
		case <-ctx.Done():
			return
		case <-changed:
			if err := rl.sendLease(ctx, "the writer lease moved"); err != nil {
				return
			}
		}
	}
}

func (rl *streamRelay) sendLease(ctx context.Context, reason string) error {
	return rl.send(ctx, wireStreamMsg{
		Type:   "lease",
		Writer: rl.att.IsWriter(),
		Holder: rl.att.Holder(),
		Reason: reason,
	})
}

func (rl *streamRelay) sendError(ctx context.Context, cause, message string) error {
	return rl.send(ctx, wireStreamMsg{
		Type:    "error",
		Cause:   cause,
		Message: message,
		Writer:  rl.att.IsWriter(),
	})
}

func (rl *streamRelay) send(ctx context.Context, m wireStreamMsg) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return rl.conn.Write(ctx, websocket.MessageText, raw)
}

// terminalHeartbeat permits quiet sessions while bounding an unresponsive peer.
func terminalHeartbeat(ctx context.Context, conn *websocket.Conn, interval, pongWait time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			pingCtx, cancel := context.WithTimeout(ctx, pongWait)
			err := conn.Ping(pingCtx)
			cancel()
			if err != nil {
				return err
			}
		}
	}
}
