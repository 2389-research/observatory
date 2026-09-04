// ABOUTME: Runner-side terminal support: the four ctl verbs, and a bounded relay
// ABOUTME: between a caller's connection and one guest session stream (§8.2, §8.3).
package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/2389-research/observatory-v2/internal/guest/proto"
)

// streamPort is the guest vsock port carrying session byte streams. Control
// verbs stay on vsockPort: that channel is strictly request/response, and a
// terminal's bytes would starve the ping cycle sharing it.
const streamPort = 10002

const (
	// DefaultMaxWireChunkBytes is §8.3's terminal.max_wire_chunk_bytes default.
	DefaultMaxWireChunkBytes = 32 << 10
	// relayQueueChunks is §8.3's runner relay queue bound, in wire chunks.
	relayQueueChunks = 8
	// terminalRequestTimeout bounds one control verb's round trip to the guest.
	terminalRequestTimeout = 15 * time.Second
)

// FrameStream splices a ctl connection's frame phase onto the decoder that read
// its JSON phase. A json.Decoder reads ahead, so the bytes it buffered past the
// object are the head of the frame stream and must be put back — all except the
// newline that terminated the JSON line, which belongs to the JSON phase. That
// newline would otherwise be read as a frame header and swallow the first real
// frame. Leading whitespace can never begin a frame: every frame type byte is
// 0x01..0x03, so trimming it is unambiguous.
//
// Both ends of a terminal-attach need this rule, and a rule applied at one end
// only is a protocol that drifts.
func FrameStream(dec *json.Decoder, conn io.Reader) io.Reader {
	rest, err := io.ReadAll(dec.Buffered())
	if err != nil {
		return conn
	}
	rest = bytes.TrimLeft(rest, " \t\r\n")
	if len(rest) == 0 {
		return conn
	}
	return io.MultiReader(bytes.NewReader(rest), conn)
}

// TerminalCtlRequest is the argument block of every terminal-* ctl command.
// Fields not meaningful to a given command are ignored by it.
type TerminalCtlRequest struct {
	SessionID string   `json:"session_id,omitempty"`
	User      string   `json:"user,omitempty"`
	Cwd       string   `json:"cwd,omitempty"`
	Argv      []string `json:"argv,omitempty"`
	Term      string   `json:"term,omitempty"`
	Rows      uint16   `json:"rows,omitempty"`
	Cols      uint16   `json:"cols,omitempty"`
	RingBytes int      `json:"ring_bytes,omitempty"`
	// AfterOffset is where an attach resumes, as a decimal string.
	AfterOffset string `json:"after_offset,omitempty"`
}

// TerminalCtlReply is the answer block. Offsets are decimal strings: a busy
// shell passes 2^53 bytes in days, and JSON numbers stop being exact there.
type TerminalCtlReply struct {
	SessionID string `json:"session_id,omitempty"`
	PID       int    `json:"pid,omitempty"`
	StartedAt string `json:"started_at,omitempty"`

	Sessions []proto.TerminalSession `json:"sessions,omitempty"`

	ResumeOffset string `json:"resume_offset,omitempty"`
	Gap          bool   `json:"gap,omitempty"`

	ExitCode *int   `json:"exit_code,omitempty"`
	Signal   string `json:"signal,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// terminalRequest queues one control verb to the supervision loop, which owns
// the single guest control connection.
type terminalRequest struct {
	kind    string
	payload any
	result  chan terminalResult // buffered, exactly one send
}

type terminalResult struct {
	env proto.Envelope
	err error
}

// terminalCall sends one control verb over the guest channel and waits for the
// matching answer. The supervision loop serializes these: the channel carries
// one outstanding request at a time, so answers cannot be mismatched.
func (r *runner) terminalCall(ctx context.Context, kind string, payload any) (proto.Envelope, error) {
	result := make(chan terminalResult, 1)
	select {
	case r.terminalCh <- terminalRequest{kind: kind, payload: payload, result: result}:
	case <-ctx.Done():
		return proto.Envelope{}, ctx.Err()
	case <-time.After(terminalRequestTimeout):
		return proto.Envelope{}, fmt.Errorf("the guest control channel is not accepting %s", kind)
	}
	select {
	case res := <-result:
		return res.env, res.err
	case <-ctx.Done():
		return proto.Envelope{}, ctx.Err()
	}
}

// terminalCreate asks the guest for a new session. Argv, user and window size
// pass through untouched: the host decides policy, the runner carries it.
func (r *runner) terminalCreate(ctx context.Context, req TerminalCtlRequest) (TerminalCtlReply, error) {
	env, err := r.terminalCall(ctx, proto.KindTerminalCreate, proto.TerminalCreate{
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
		return TerminalCtlReply{}, err
	}
	if env.Kind != proto.KindTerminalCreated {
		return TerminalCtlReply{}, terminalReplyError(env)
	}
	var got proto.TerminalCreated
	if err := json.Unmarshal(env.Data, &got); err != nil {
		return TerminalCtlReply{}, fmt.Errorf("unmarshal terminal.created: %w", err)
	}
	return TerminalCtlReply{SessionID: got.SessionID, PID: got.PID, StartedAt: got.StartedAt}, nil
}

func (r *runner) terminalClose(ctx context.Context, req TerminalCtlRequest) (TerminalCtlReply, error) {
	env, err := r.terminalCall(ctx, proto.KindTerminalClose, proto.TerminalClose{SessionID: req.SessionID})
	if err != nil {
		return TerminalCtlReply{}, err
	}
	if env.Kind != proto.KindTerminalClosed {
		return TerminalCtlReply{}, terminalReplyError(env)
	}
	var got proto.TerminalClosed
	if err := json.Unmarshal(env.Data, &got); err != nil {
		return TerminalCtlReply{}, fmt.Errorf("unmarshal terminal.closed: %w", err)
	}
	return TerminalCtlReply{
		SessionID: got.SessionID,
		ExitCode:  got.ExitCode,
		Signal:    got.Signal,
		Reason:    got.Reason,
	}, nil
}

func (r *runner) terminalList(ctx context.Context) (TerminalCtlReply, error) {
	env, err := r.terminalCall(ctx, proto.KindTerminalList, proto.TerminalList{})
	if err != nil {
		return TerminalCtlReply{}, err
	}
	if env.Kind != proto.KindTerminalSessions {
		return TerminalCtlReply{}, terminalReplyError(env)
	}
	var got proto.TerminalSessions
	if err := json.Unmarshal(env.Data, &got); err != nil {
		return TerminalCtlReply{}, fmt.Errorf("unmarshal terminal.sessions: %w", err)
	}
	sessions := got.Sessions
	if sessions == nil {
		sessions = []proto.TerminalSession{}
	}
	return TerminalCtlReply{Sessions: sessions}, nil
}

// terminalAttach opens a session's own stream. It never touches the control
// channel: a session's bytes get their own vsock connection, authenticated by
// the same hello, so a busy terminal cannot delay a ping.
func (r *runner) terminalAttach(ctx context.Context, req TerminalCtlRequest) (*Relay, TerminalCtlReply, error) {
	dialCtx, cancel := context.WithTimeout(ctx, terminalRequestTimeout)
	defer cancel()
	conn, err := proto.DialHostVsock(dialCtx, r.cfg.UDSPath, streamPort)
	if err != nil {
		return nil, TerminalCtlReply{}, fmt.Errorf("dial guest session stream: %w", err)
	}

	after := req.AfterOffset
	if after == "" {
		after = "0"
	}
	ack, err := r.streamHandshake(conn, req.SessionID, after)
	if err != nil {
		conn.Close()
		return nil, TerminalCtlReply{}, err
	}
	return newRelay(conn, DefaultMaxWireChunkBytes), TerminalCtlReply{
		SessionID:    req.SessionID,
		ResumeOffset: ack.ResumeOffset,
		Gap:          ack.Gap,
	}, nil
}

// streamHandshake performs the session stream's hello/hello_ack, then clears
// the connection's deadlines: an attached terminal may idle for hours, and a
// stalled reader is backpressure rather than a fault.
func (r *runner) streamHandshake(conn net.Conn, sessionID, afterOffset string) (proto.HelloAck, error) {
	if err := conn.SetDeadline(time.Now().Add(terminalRequestTimeout)); err != nil {
		return proto.HelloAck{}, fmt.Errorf("set stream deadline: %w", err)
	}
	hello := proto.Hello{
		ProtocolVersion: proto.ProtocolVersion,
		VMID:            r.cfg.VMID,
		BootID:          r.cfg.BootID,
		SourceInstance:  r.cfg.InstanceID,
		ResumeCursor:    "0",
		AuthProof:       r.token,
		SessionID:       sessionID,
		AfterOffset:     afterOffset,
	}
	if err := proto.WriteControl(conn, proto.KindHello, hello); err != nil {
		return proto.HelloAck{}, fmt.Errorf("write stream hello: %w", err)
	}
	env, err := proto.ReadControl(conn)
	if err != nil {
		return proto.HelloAck{}, fmt.Errorf("read stream hello_ack: %w", err)
	}
	if env.Kind != proto.KindHelloAck {
		return proto.HelloAck{}, fmt.Errorf("expected hello_ack on the session stream, got %q", env.Kind)
	}
	var ack proto.HelloAck
	if err := json.Unmarshal(env.Data, &ack); err != nil {
		return proto.HelloAck{}, fmt.Errorf("unmarshal stream hello_ack: %w", err)
	}
	if !ack.Accepted {
		return proto.HelloAck{}, fmt.Errorf("the guest refused the attach: %s", ack.Reason)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return proto.HelloAck{}, fmt.Errorf("clear stream deadline: %w", err)
	}
	return ack, nil
}

// --- the relay ------------------------------------------------------------

// wireFrame is one framed message in transit, held whole so the relay never
// has to re-split a partially copied frame.
type wireFrame struct {
	typ     byte
	payload []byte
}

var errQueueClosed = errors.New("relay queue closed")

// frameQueue is the relay's bounded buffer. It is bounded in bytes rather than
// frames because §8.3's limit is a byte budget, and one frame's size varies.
type frameQueue struct {
	mu       sync.Mutex
	notEmpty *sync.Cond
	notFull  *sync.Cond
	items    []wireFrame
	bytes    int
	maxBytes int
	closed   bool
}

func newFrameQueue(maxBytes int) *frameQueue {
	q := &frameQueue{maxBytes: maxBytes}
	q.notEmpty = sync.NewCond(&q.mu)
	q.notFull = sync.NewCond(&q.mu)
	return q
}

// push blocks while the queue is over its byte bound, which is what stops the
// relay reading vsock and lets the backpressure reach the guest. A frame
// larger than the whole bound still goes through an empty queue: refusing it
// would strand the stream, and the frame codec already caps a payload.
func (q *frameQueue) push(f wireFrame) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	for !q.closed && len(q.items) > 0 && q.bytes+len(f.payload) > q.maxBytes {
		q.notFull.Wait()
	}
	if q.closed {
		return errQueueClosed
	}
	q.items = append(q.items, f)
	q.bytes += len(f.payload)
	q.notEmpty.Signal()
	return nil
}

// pop returns the oldest frame, draining what is already queued even after
// close: a session's last output is not thrown away because the guest hung up.
func (q *frameQueue) pop() (wireFrame, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.items) == 0 {
		if q.closed {
			return wireFrame{}, errQueueClosed
		}
		q.notEmpty.Wait()
	}
	f := q.items[0]
	q.items[0] = wireFrame{}
	q.items = q.items[1:]
	q.bytes -= len(f.payload)
	q.notFull.Broadcast()
	return f, nil
}

func (q *frameQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	q.notEmpty.Broadcast()
	q.notFull.Broadcast()
}

func (q *frameQueue) queued() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.bytes
}

// Relay copies frames between one guest session stream and one caller, with a
// bounded queue in the guest-to-caller direction. It copies; it never parses a
// payload, and it never runs anything.
type Relay struct {
	guest   net.Conn
	q       *frameQueue
	closing atomic.Bool
	once    sync.Once

	errMu sync.Mutex
	err   error
}

func newRelay(guest net.Conn, maxChunkBytes int) *Relay {
	if maxChunkBytes <= 0 {
		maxChunkBytes = DefaultMaxWireChunkBytes
	}
	return &Relay{guest: guest, q: newFrameQueue(maxChunkBytes * relayQueueChunks)}
}

// Run pumps frames until either end goes away. It returns the guest-side
// failure if there was one; a caller that detaches is not a failure.
func (r *Relay) Run(callerR io.Reader, callerW io.Writer) error {
	var wg sync.WaitGroup
	wg.Add(3)

	// Guest to queue. Ending here means the guest stream is done, so the queue
	// closes and the writer below drains what is left.
	go func() {
		defer wg.Done()
		defer r.q.close()
		for {
			typ, payload, err := proto.ReadFrame(r.guest)
			if err != nil {
				r.record(err)
				return
			}
			if err := r.q.push(wireFrame{typ: typ, payload: payload}); err != nil {
				return
			}
		}
	}()

	// Queue to caller. Ending here means the caller is gone or the queue is
	// drained and closed; either way the guest side has no reader left.
	go func() {
		defer wg.Done()
		defer r.closeGuest()
		for {
			f, err := r.q.pop()
			if err != nil {
				return
			}
			if err := proto.WriteFrame(callerW, f.typ, f.payload); err != nil {
				return
			}
		}
	}()

	// Caller to guest. Ending here is the detach path: closing the guest
	// connection lets the guest drop the attachment and wakes the reader above.
	go func() {
		defer wg.Done()
		defer r.closeGuest()
		for {
			typ, payload, err := proto.ReadFrame(callerR)
			if err != nil {
				return
			}
			if err := proto.WriteFrame(r.guest, typ, payload); err != nil {
				r.record(err)
				return
			}
		}
	}()

	wg.Wait()
	r.errMu.Lock()
	defer r.errMu.Unlock()
	return r.err
}

// Close tears the relay down from the outside. Run returns once its pumps see it.
func (r *Relay) Close() {
	r.closeGuest()
	r.q.close()
}

func (r *Relay) closeGuest() {
	r.once.Do(func() {
		r.closing.Store(true)
		_ = r.guest.Close()
	})
}

// record keeps the first guest-side failure. Errors caused by the relay's own
// teardown are not failures and are dropped.
func (r *Relay) record(err error) {
	if r.closing.Load() {
		return
	}
	r.errMu.Lock()
	defer r.errMu.Unlock()
	if r.err == nil {
		r.err = err
	}
}
