// ABOUTME: Runs a bounded per-VM DNS forwarder over explicitly supplied sockets.
// ABOUTME: Keeps evidence delivery nonblocking and joins socket owners on shutdown.
package manageddns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Config has no implicit upstream or zero-value defaults. Use DefaultConfig.
type Config struct {
	Upstream                                                  netip.AddrPort
	MaxConcurrent, MaxTCPConnections, MaxQueriesPerConnection int
	MaxMessageBytes, MaxRecords, ObservationCapacity          int
	QueriesPerSecond, Burst                                   int
	QueryTimeout, IdleTimeout                                 time.Duration
}

func DefaultConfig(upstream netip.AddrPort) Config {
	return Config{Upstream: upstream, MaxConcurrent: 16, MaxTCPConnections: 16, MaxQueriesPerConnection: 32, MaxMessageBytes: 65535, MaxRecords: 32, ObservationCapacity: 128, QueriesPerSecond: 100, Burst: 100, QueryTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second}
}

// Sockets belong to the worker after Run starts. Adapters must contact only
// Config.Upstream, honor context deadlines/cancellation, bound returned messages
// to Config.MaxMessageBytes, and support at most Config.MaxConcurrent callers.
// ExchangeUDP owns and closes any sockets it creates; DialTCP transfers ownership.
// Neither callback may use an ambient resolver or alternate upstream.
type Sockets struct {
	UDP         net.PacketConn
	TCP         net.Listener
	ExchangeUDP func(context.Context, []byte) ([]byte, error)
	DialTCP     func(context.Context) (net.Conn, error)
}

// Record retains typed answer evidence, never arbitrary RDATA or raw packets.
// Name/Target use decimal escapes for bytes outside ordinary name characters.
// Unrepresented resource bodies are explicitly marked DataOmitted.
type Record struct {
	Name                               string
	Type, Class                        uint16
	TTL                                uint32
	Address, Target                    string
	Preference, Priority, Weight, Port *uint16
	DataOmitted                        bool
}
type Observation struct {
	Transport, Name                   string
	Type, Class                       uint16
	Outcome, Decision, DecisionSource string
	RCode                             *uint16
	Answers                           []Record
	RecordsTruncated                  bool
	Duration                          time.Duration
	TCPFallback                       bool
	ResponseTruncated                 bool
	DeliveryError                     string
}
type Status struct {
	Ready, Running                            bool
	ActiveQueries, TCPConnections, QueueDepth int
	Received, Completed, Rejected, Dropped    uint64
}

type Worker struct {
	cfg          Config
	sockets      Sockets
	ready        chan struct{}
	observations chan Observation
	mu           sync.Mutex
	status       Status
	started      bool
	tokens       float64
	lastToken    time.Time
	queries      chan struct{}
	connections  map[net.Conn]struct{}
	udpWrite     sync.Mutex
	wg           sync.WaitGroup
}

func New(cfg Config, s Sockets) (*Worker, error) {
	if !cfg.Upstream.IsValid() || !cfg.Upstream.Addr().Is4() || cfg.Upstream.Addr().Is4In6() || cfg.Upstream.Addr().IsUnspecified() || cfg.Upstream.Addr().IsMulticast() || cfg.Upstream.Port() == 0 {
		return nil, fmt.Errorf("manageddns: explicit native IPv4 upstream required")
	}
	for _, v := range []struct {
		name            string
		value, min, max int
	}{{"concurrency", cfg.MaxConcurrent, 1, 64}, {"TCP connections", cfg.MaxTCPConnections, 1, 64}, {"queries per connection", cfg.MaxQueriesPerConnection, 1, 128}, {"message bytes", cfg.MaxMessageBytes, 512, 65535}, {"records", cfg.MaxRecords, 1, 128}, {"observation capacity", cfg.ObservationCapacity, 1, 1024}, {"queries per second", cfg.QueriesPerSecond, 1, 1000}, {"burst", cfg.Burst, 1, 1000}} {
		if v.value < v.min || v.value > v.max {
			return nil, fmt.Errorf("manageddns: %s must be %d..%d", v.name, v.min, v.max)
		}
	}
	if cfg.QueryTimeout <= 0 || cfg.QueryTimeout > 30*time.Second || cfg.IdleTimeout <= 0 || cfg.IdleTimeout > 30*time.Second {
		return nil, fmt.Errorf("manageddns: query and idle timeouts must be positive and at most 30s")
	}
	if s.UDP == nil || s.TCP == nil || s.ExchangeUDP == nil || s.DialTCP == nil {
		return nil, fmt.Errorf("manageddns: listeners and upstream adapters required")
	}
	return &Worker{cfg: cfg, sockets: s, ready: make(chan struct{}), observations: make(chan Observation, cfg.ObservationCapacity), queries: make(chan struct{}, cfg.MaxConcurrent), connections: make(map[net.Conn]struct{}), tokens: float64(cfg.Burst), lastToken: time.Now()}, nil
}
func (w *Worker) Ready() <-chan struct{}           { return w.ready }
func (w *Worker) Observations() <-chan Observation { return w.observations }
func (w *Worker) Status() Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.status
	s.QueueDepth = len(w.observations)
	return s
}

// Run is one-shot. Cancellation is a clean shutdown; unexpected listener errors
// are returned. Observations closes only after every producer has joined.
func (w *Worker) Run(parent context.Context) error {
	w.mu.Lock()
	if w.started {
		w.mu.Unlock()
		return fmt.Errorf("manageddns: worker already started")
	}
	w.started = true
	w.status.Running = true
	w.mu.Unlock()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	shutdownDone := make(chan struct{})
	context.AfterFunc(ctx, func() {
		_ = w.sockets.UDP.Close()
		_ = w.sockets.TCP.Close()
		w.mu.Lock()
		for c := range w.connections {
			_ = c.Close()
		}
		w.mu.Unlock()
		close(shutdownDone)
	})
	failures := make(chan error, 2)
	w.wg.Add(2)
	go func() { defer w.wg.Done(); failures <- w.serveUDP(ctx) }()
	go func() { defer w.wg.Done(); failures <- w.serveTCP(ctx) }()
	w.mu.Lock()
	w.status.Ready = true
	w.mu.Unlock()
	close(w.ready)
	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-failures:
	}
	cancel()
	<-shutdownDone
	w.wg.Wait()
	w.mu.Lock()
	w.status.Running = false
	w.status.Ready = false
	w.mu.Unlock()
	close(w.observations)
	if parent.Err() != nil {
		return nil
	}
	return runErr
}
func (w *Worker) emit(o Observation) {
	w.mu.Lock()
	w.status.Completed++
	if o.Decision == "refused" {
		w.status.Rejected++
	}
	select {
	case w.observations <- o:
	default:
		w.status.Dropped++
	}
	w.mu.Unlock()
}
func (w *Worker) admit() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status.Received++
	now := time.Now()
	w.tokens += now.Sub(w.lastToken).Seconds() * float64(w.cfg.QueriesPerSecond)
	w.lastToken = now
	if w.tokens > float64(w.cfg.Burst) {
		w.tokens = float64(w.cfg.Burst)
	}
	if w.tokens < 1 {
		return "rate_limited"
	}
	w.tokens--
	select {
	case w.queries <- struct{}{}:
		w.status.ActiveQueries++
		return ""
	default:
		return "overloaded"
	}
}
func (w *Worker) release() { <-w.queries; w.mu.Lock(); w.status.ActiveQueries--; w.mu.Unlock() }
func (w *Worker) writeUDP(b []byte, a net.Addr) error {
	if len(b) == 0 {
		return nil
	}
	w.udpWrite.Lock()
	defer w.udpWrite.Unlock()
	if err := w.sockets.UDP.SetWriteDeadline(time.Now().Add(w.cfg.QueryTimeout)); err != nil {
		return err
	}
	_, err := w.sockets.UDP.WriteTo(b, a)
	return err
}
func (w *Worker) serveUDP(ctx context.Context) error {
	b := make([]byte, w.cfg.MaxMessageBytes+1)
	for {
		n, a, err := w.sockets.UDP.ReadFrom(b)
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
		raw := append([]byte(nil), b[:n]...)
		if reason := w.admit(); reason != "" {
			out, o := w.reject(raw, "udp", reason)
			if w.writeUDP(out, a) != nil {
				o.DeliveryError = "write_failed"
			}
			w.emit(o)
			continue
		}
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			defer w.release()
			out, o := w.resolve(ctx, raw, "udp")
			if w.writeUDP(out, a) != nil {
				o.DeliveryError = "write_failed"
			}
			w.emit(o)
		}()
	}
}
func (w *Worker) serveTCP(ctx context.Context) error {
	for {
		c, err := w.sockets.TCP.Accept()
		if err != nil {
			return err
		}
		w.mu.Lock()
		if ctx.Err() != nil || len(w.connections) >= w.cfg.MaxTCPConnections {
			w.mu.Unlock()
			_ = c.Close()
			if ctx.Err() == nil {
				w.emit(Observation{Transport: "tcp", Outcome: "connection_limit", Decision: "refused", DecisionSource: "local"})
			}
			continue
		}
		w.connections[c] = struct{}{}
		w.status.TCPConnections++
		w.mu.Unlock()
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			defer func() { _ = c.Close(); w.mu.Lock(); delete(w.connections, c); w.status.TCPConnections--; w.mu.Unlock() }()
			w.serveTCPConnection(ctx, c)
		}()
	}
}
func (w *Worker) serveTCPConnection(ctx context.Context, c net.Conn) {
	for i := 0; i < w.cfg.MaxQueriesPerConnection; i++ {
		if ctx.Err() != nil {
			return
		}
		if c.SetReadDeadline(time.Now().Add(w.cfg.IdleTimeout)) != nil {
			return
		}
		raw, err := readFrame(c, w.cfg.MaxMessageBytes)
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, io.EOF) {
				w.emit(Observation{Transport: "tcp", Outcome: "invalid_frame", Decision: "refused", DecisionSource: "local"})
			}
			return
		}
		reason := w.admit()
		var out []byte
		var o Observation
		if reason != "" {
			out, o = w.reject(raw, "tcp", reason)
		} else {
			out, o = w.resolve(ctx, raw, "tcp")
			w.release()
		}
		if len(out) == 0 {
			w.emit(o)
			return
		}
		if c.SetWriteDeadline(time.Now().Add(w.cfg.QueryTimeout)) != nil {
			o.DeliveryError = "write_failed"
			w.emit(o)
			return
		}
		if writeFrame(c, out) != nil {
			o.DeliveryError = "write_failed"
			w.emit(o)
			return
		}
		w.emit(o)
	}
}
