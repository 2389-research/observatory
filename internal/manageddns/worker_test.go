// ABOUTME: Exercises managed DNS against real loopback upstreams and clients.
// ABOUTME: Checks forwarded evidence, wire failures, resource bounds and shutdown.
package manageddns

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type upstreamFixture struct {
	udp     net.PacketConn
	tcp     net.Listener
	wg      sync.WaitGroup
	address netip.AddrPort
}

func upstream(t *testing.T, respond func([]byte, bool) []byte) *upstreamFixture {
	t.Helper()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		tcp.Close()
		t.Fatal(err)
	}
	u := &upstreamFixture{udp: udp, tcp: tcp, address: netip.MustParseAddrPort(tcp.Addr().String())}
	u.wg.Add(2)
	go func() {
		defer u.wg.Done()
		b := make([]byte, 65536)
		for {
			n, a, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			out := respond(append([]byte(nil), b[:n]...), false)
			if out != nil {
				_, _ = udp.WriteTo(out, a)
			}
		}
	}()
	go func() {
		defer u.wg.Done()
		for {
			c, e := tcp.Accept()
			if e != nil {
				return
			}
			u.wg.Add(1)
			go func() {
				defer u.wg.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				var h [2]byte
				if _, e := io.ReadFull(c, h[:]); e != nil {
					return
				}
				b := make([]byte, binary.BigEndian.Uint16(h[:]))
				if _, e := io.ReadFull(c, b); e != nil {
					return
				}
				if out := respond(b, true); out != nil {
					binary.BigEndian.PutUint16(h[:], uint16(len(out)))
					_, _ = c.Write(append(h[:], out...))
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = udp.Close(); _ = tcp.Close(); u.wg.Wait() })
	return u
}
func (u *upstreamFixture) sockets(t *testing.T) Sockets {
	t.Helper()
	udp, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	tcp, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		udp.Close()
		t.Fatal(e)
	}
	return Sockets{UDP: udp, TCP: tcp, ExchangeUDP: func(ctx context.Context, b []byte) ([]byte, error) {
		c, e := (&net.Dialer{}).DialContext(ctx, "udp4", u.address.String())
		if e != nil {
			return nil, e
		}
		defer c.Close()
		deadline, _ := ctx.Deadline()
		_ = c.SetDeadline(deadline)
		stop := context.AfterFunc(ctx, func() { _ = c.Close() })
		defer stop()
		if _, e = c.Write(b); e != nil {
			return nil, e
		}
		out := make([]byte, 65536)
		n, e := c.Read(out)
		return out[:n], e
	}, DialTCP: func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp4", u.address.String())
	}}
}
func runWorker(t *testing.T, u *upstreamFixture, change func(*Config)) (*Worker, Sockets) {
	t.Helper()
	cfg := DefaultConfig(u.address)
	if change != nil {
		change(&cfg)
	}
	s := u.sockets(t)
	w, e := New(cfg, s)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	select {
	case <-w.Ready():
	case <-time.After(time.Second):
		t.Fatal("not ready")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case e := <-done:
			if e != nil {
				t.Errorf("Run: %v", e)
			}
		case <-time.After(2 * time.Second):
			t.Error("worker did not join")
		}
	})
	return w, s
}
func query(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: 73, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}}}
	b, e := m.Pack()
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func answer(b []byte, tcp bool) []byte {
	var m dnsmessage.Message
	if m.Unpack(b) != nil {
		return nil
	}
	m.Response = true
	m.RecursionAvailable = true
	if len(m.Questions) == 1 {
		q := m.Questions[0]
		h := dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: q.Class, TTL: 60}
		switch q.Type {
		case dnsmessage.TypeA:
			m.Answers = []dnsmessage.Resource{{Header: h, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 8}}}}
		case dnsmessage.TypeAAAA:
			m.Answers = []dnsmessage.Resource{{Header: h, Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::8").As16()}}}
		case dnsmessage.TypeCNAME:
			m.Answers = []dnsmessage.Resource{{Header: h, Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("alias.example.")}}}
		}
	}
	out, _ := m.Pack()
	return out
}
func exchange(t *testing.T, s Sockets, b []byte, tcp bool) []byte {
	t.Helper()
	network, address := "udp4", s.UDP.LocalAddr().String()
	if tcp {
		network, address = "tcp4", s.TCP.Addr().String()
	}
	c, e := net.DialTimeout(network, address, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if tcp {
		var h [2]byte
		binary.BigEndian.PutUint16(h[:], uint16(len(b)))
		if _, e = c.Write(append(h[:], b...)); e != nil {
			t.Fatal(e)
		}
		if _, e = io.ReadFull(c, h[:]); e != nil {
			t.Fatal(e)
		}
		out := make([]byte, binary.BigEndian.Uint16(h[:]))
		if _, e = io.ReadFull(c, out); e != nil {
			t.Fatal(e)
		}
		return out
	}
	if _, e = c.Write(b); e != nil {
		t.Fatal(e)
	}
	out := make([]byte, 65536)
	n, e := c.Read(out)
	if e != nil {
		t.Fatal(e)
	}
	return out[:n]
}
func observation(t *testing.T, w *Worker) Observation {
	t.Helper()
	select {
	case o := <-w.Observations():
		return o
	case <-time.After(time.Second):
		t.Fatal("missing observation")
		return Observation{}
	}
}
func responseCode(t *testing.T, b []byte) dnsmessage.RCode {
	t.Helper()
	var m dnsmessage.Message
	if e := m.Unpack(b); e != nil {
		t.Fatal(e)
	}
	return m.RCode
}
func TestForwardRealUDPAndTCP(t *testing.T) {
	u := upstream(t, answer)
	w, s := runWorker(t, u, nil)
	for _, tcp := range []bool{false, true} {
		for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypeCNAME} {
			b := exchange(t, s, query(t, "example.", typ), tcp)
			if got := responseCode(t, b); got != dnsmessage.RCodeSuccess {
				t.Fatal(got)
			}
			o := observation(t, w)
			if o.Name != "example." || o.Type != uint16(typ) || o.Outcome != "answer" || o.Decision != "forwarded" || o.DecisionSource != "upstream" || len(o.Answers) != 1 || o.Duration <= 0 {
				t.Fatalf("observation: %+v", o)
			}
		}
	}
}
func TestUpstreamOutcomesAndMatching(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*dnsmessage.Message)
		outcome string
		code    dnsmessage.RCode
	}{{"nxdomain", func(m *dnsmessage.Message) { m.RCode = dnsmessage.RCodeNameError; m.Answers = nil }, "nxdomain", dnsmessage.RCodeNameError}, {"refused", func(m *dnsmessage.Message) { m.RCode = dnsmessage.RCodeRefused; m.Answers = nil }, "refused", dnsmessage.RCodeRefused}, {"wrong_id", func(m *dnsmessage.Message) { m.ID++ }, "mismatched_response", dnsmessage.RCodeServerFailure}, {"wrong_question", func(m *dnsmessage.Message) { m.Questions[0].Type = dnsmessage.TypeAAAA }, "mismatched_response", dnsmessage.RCodeServerFailure}, {"wrong_opcode", func(m *dnsmessage.Message) { m.OpCode = 1 }, "mismatched_response", dnsmessage.RCodeServerFailure}, {"not_response", func(m *dnsmessage.Message) { m.Response = false }, "mismatched_response", dnsmessage.RCodeServerFailure}} {
		t.Run(tc.name, func(t *testing.T) {
			u := upstream(t, func(b []byte, tcp bool) []byte {
				var m dnsmessage.Message
				_ = m.Unpack(answer(b, tcp))
				tc.mutate(&m)
				out, _ := m.Pack()
				return out
			})
			w, s := runWorker(t, u, nil)
			if c := responseCode(t, exchange(t, s, query(t, "example.", dnsmessage.TypeA), false)); c != tc.code {
				t.Fatal(c)
			}
			o := observation(t, w)
			if o.Outcome != tc.outcome {
				t.Fatalf("%+v", o)
			}
			if tc.name == "refused" && o.Decision != "forwarded" {
				t.Fatalf("upstream refusal mislabeled: %+v", o)
			}
		})
	}
}
func TestTruncatedUDPUsesRealTCP(t *testing.T) {
	u := upstream(t, func(b []byte, tcp bool) []byte {
		out := answer(b, tcp)
		if !tcp {
			var m dnsmessage.Message
			_ = m.Unpack(out)
			m.Truncated = true
			m.Answers = nil
			out, _ = m.Pack()
		}
		return out
	})
	w, s := runWorker(t, u, nil)
	out := exchange(t, s, query(t, "example.", dnsmessage.TypeA), false)
	var m dnsmessage.Message
	_ = m.Unpack(out)
	o := observation(t, w)
	if len(m.Answers) != 1 || !o.TCPFallback || o.Outcome != "answer" {
		t.Fatalf("fallback: %+v %+v", m, o)
	}
}
func TestTimeoutDoesNotCreateFallback(t *testing.T) {
	u := upstream(t, func([]byte, bool) []byte { return nil })
	w, s := runWorker(t, u, func(c *Config) { c.QueryTimeout = 30 * time.Millisecond })
	if c := responseCode(t, exchange(t, s, query(t, "example.", dnsmessage.TypeA), false)); c != dnsmessage.RCodeServerFailure {
		t.Fatal(c)
	}
	o := observation(t, w)
	if o.Outcome != "timeout" || o.TCPFallback {
		t.Fatalf("%+v", o)
	}
}
func TestLocalRejectionAndSafeName(t *testing.T) {
	for _, tc := range []struct {
		name    string
		wire    func(*testing.T) []byte
		outcome string
		code    dnsmessage.RCode
	}{{"bad_wire", func(t *testing.T) []byte { return []byte{0, 73, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12} }, "malformed_query", dnsmessage.RCodeFormatError}, {"transfer", func(t *testing.T) []byte { return query(t, "example.", dnsmessage.Type(252)) }, "unsupported_query", dnsmessage.RCodeNotImplemented}, {"two_questions", func(t *testing.T) []byte {
		var m dnsmessage.Message
		_ = m.Unpack(query(t, "example.", dnsmessage.TypeA))
		m.Questions = append(m.Questions, m.Questions[0])
		b, _ := m.Pack()
		return b
	}, "unsupported_query", dnsmessage.RCodeNotImplemented}} {
		t.Run(tc.name, func(t *testing.T) {
			u := upstream(t, answer)
			w, s := runWorker(t, u, nil)
			if c := responseCode(t, exchange(t, s, tc.wire(t), false)); c != tc.code {
				t.Fatalf("code %v", c)
			}
			o := observation(t, w)
			if o.Outcome != tc.outcome || o.Decision != "refused" || o.DecisionSource != "local" {
				t.Fatalf("%+v", o)
			}
		})
	}
	t.Run("safe_name", func(t *testing.T) {
		u := upstream(t, answer)
		w, s := runWorker(t, u, nil)
		exchange(t, s, query(t, "bad\xff\\\n.example.", dnsmessage.TypeA), false)
		o := observation(t, w)
		if o.Name != "bad\\255\\092\\010.example." {
			t.Fatalf("unsafe evidence %q", o.Name)
		}
	})
}
func TestRateLimitAndObservationDrop(t *testing.T) {
	u := upstream(t, answer)
	w, s := runWorker(t, u, func(c *Config) { c.QueriesPerSecond = 1; c.Burst = 1; c.ObservationCapacity = 1 })
	q := query(t, "example.", dnsmessage.TypeA)
	if c := responseCode(t, exchange(t, s, q, false)); c != 0 {
		t.Fatal(c)
	}
	if c := responseCode(t, exchange(t, s, q, true)); c != dnsmessage.RCodeRefused {
		t.Fatal(c)
	}
	deadline := time.Now().Add(time.Second)
	for w.Status().Dropped != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	st := w.Status()
	if st.Dropped != 1 || st.Rejected != 1 || st.QueueDepth != 1 {
		t.Fatalf("%+v", st)
	}
}
func TestTCPIdleLimitAndShutdown(t *testing.T) {
	u := upstream(t, answer)
	w, s := runWorker(t, u, func(c *Config) { c.MaxTCPConnections = 1; c.IdleTimeout = 30 * time.Millisecond })
	conn, e := net.Dial("tcp4", s.TCP.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, e = conn.Read(b[:]); e == nil {
		t.Fatal("idle client left open")
	}
	deadline := time.Now().Add(time.Second)
	for w.Status().TCPConnections != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if st := w.Status(); st.TCPConnections != 0 {
		t.Fatalf("%+v", st)
	}
}
func TestConfigRejectsUnboundedAndMissingUpstream(t *testing.T) {
	u := upstream(t, answer)
	for _, change := range []func(*Config){func(c *Config) { c.Upstream = netip.AddrPort{} }, func(c *Config) { c.Upstream = netip.MustParseAddrPort("[::1]:53") }, func(c *Config) { c.MaxConcurrent = 65 }, func(c *Config) { c.MaxMessageBytes = 65536 }, func(c *Config) { c.QueryTimeout = 0 }, func(c *Config) { c.MaxTCPConnections = 0 }, func(c *Config) { c.MaxRecords = 0 }, func(c *Config) { c.QueriesPerSecond = 0 }, func(c *Config) { c.ObservationCapacity = 0 }} {
		cfg := DefaultConfig(u.address)
		change(&cfg)
		s := u.sockets(t)
		w, e := New(cfg, s)
		_ = s.UDP.Close()
		_ = s.TCP.Close()
		if e == nil {
			t.Fatalf("accepted config %+v worker %v", cfg, w)
		}
	}
}
func TestEDNSAndBoundedUDPResponse(t *testing.T) {
	u := upstream(t, func(b []byte, tcp bool) []byte {
		var m dnsmessage.Message
		_ = m.Unpack(answer(b, tcp))
		for len(m.Answers) < 60 {
			m.Answers = append(m.Answers, m.Answers[0])
		}
		out, _ := m.Pack()
		return out
	})
	w, s := runWorker(t, u, nil)
	q := query(t, "example.", dnsmessage.TypeA)
	out := exchange(t, s, q, false)
	var m dnsmessage.Message
	_ = m.Unpack(out)
	if len(out) > 512 || !m.Truncated {
		t.Fatalf("UDP not bounded: %d TC=%v", len(out), m.Truncated)
	}
	observation(t, w)
	var request dnsmessage.Message
	_ = request.Unpack(q)
	request.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 4096}, Body: &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 65001, Data: []byte{1, 2}}}}}}
	q, _ = request.Pack()
	out = exchange(t, s, q, false)
	_ = m.Unpack(out)
	if m.Truncated || len(m.Answers) != 60 {
		t.Fatalf("EDNS lost: %+v", m.Header)
	}
	o := observation(t, w)
	if !o.RecordsTruncated || len(o.Answers) != 32 {
		t.Fatalf("record cap %+v", o)
	}
}

func TestConcurrentSaturationRejectsWithoutExtraUpstream(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	u := upstream(t, func(b []byte, tcp bool) []byte {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return answer(b, tcp)
	})
	w, s := runWorker(t, u, func(c *Config) { c.MaxConcurrent = 1 })
	firstDone := make(chan []byte, 1)
	c, e := net.Dial("udp4", s.UDP.LocalAddr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	_, _ = c.Write(query(t, "example.", dnsmessage.TypeA))
	go func() { b := make([]byte, 1024); n, _ := c.Read(b); firstDone <- b[:n] }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("upstream not reached")
	}
	out := exchange(t, s, query(t, "other.example.", dnsmessage.TypeA), true)
	o := observation(t, w)
	close(release)
	if responseCode(t, out) != dnsmessage.RCodeRefused || o.Outcome != "overloaded" || w.Status().ActiveQueries > 1 {
		t.Fatalf("bad saturation %+v", o)
	}
	select {
	case out := <-firstDone:
		if responseCode(t, out) != 0 {
			t.Fatal("first failed")
		}
	case <-time.After(time.Second):
		t.Fatal("first hung")
	}
}
func TestShutdownClosesActiveQueriesAndIdleClients(t *testing.T) {
	u := upstream(t, func([]byte, bool) []byte { return nil })
	s := u.sockets(t)
	cfg := DefaultConfig(u.address)
	cfg.QueryTimeout = 5 * time.Second
	w, e := New(cfg, s)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	<-w.Ready()
	client, e := net.Dial("udp4", s.UDP.LocalAddr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	_, _ = client.Write(query(t, "example.", dnsmessage.TypeA))
	tcp, e := net.Dial("tcp4", s.TCP.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer tcp.Close()
	_, _ = tcp.Write([]byte{0})
	deadline := time.Now().Add(time.Second)
	for w.Status().ActiveQueries != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown waited for query timeout")
	}
	for range w.Observations() {
	}
	if st := w.Status(); st.Running || st.Ready || st.ActiveQueries != 0 || st.TCPConnections != 0 {
		t.Fatalf("not joined %+v", st)
	}
	if e := w.Run(context.Background()); e == nil {
		t.Fatal("second Run succeeded")
	}
}
func TestTCPConnectionBoundAndFraming(t *testing.T) {
	u := upstream(t, answer)
	w, s := runWorker(t, u, func(c *Config) {
		c.MaxTCPConnections = 1
		c.MaxQueriesPerConnection = 1
		c.IdleTimeout = 200 * time.Millisecond
	})
	first, e := net.Dial("tcp4", s.TCP.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	deadline := time.Now().Add(time.Second)
	for w.Status().TCPConnections != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	second, e := net.Dial("tcp4", s.TCP.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, e = second.Read(b[:]); e == nil {
		t.Fatal("second connection not closed")
	}
	if o := observation(t, w); o.Outcome != "connection_limit" {
		t.Fatalf("%+v", o)
	}
	q := query(t, "example.", dnsmessage.TypeA)
	frame := make([]byte, len(q)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(q)))
	copy(frame[2:], q)
	for _, v := range frame {
		if _, e = first.Write([]byte{v}); e != nil {
			t.Fatal(e)
		}
	}
	_ = first.SetReadDeadline(time.Now().Add(time.Second))
	var h [2]byte
	if _, e = io.ReadFull(first, h[:]); e != nil {
		t.Fatal(e)
	}
	response := make([]byte, binary.BigEndian.Uint16(h[:]))
	if _, e = io.ReadFull(first, response); e != nil {
		t.Fatal(e)
	}
	if _, e = first.Read(b[:]); e == nil {
		t.Fatal("per connection query cap ignored")
	}
	if o := observation(t, w); o.Outcome != "answer" {
		t.Fatalf("%+v", o)
	}
}
func TestMalformedUpstreamAndRequestShapes(t *testing.T) {
	for _, kind := range []string{"trailing", "compression_loop", "short", "duplicate_opt"} {
		t.Run(kind, func(t *testing.T) {
			u := upstream(t, func(b []byte, tcp bool) []byte {
				out := answer(b, tcp)
				switch kind {
				case "trailing":
					return append(out, 99)
				case "compression_loop":
					out[12] = 0xc0
					out[13] = 12
					return out
				case "short":
					return out[:11]
				case "duplicate_opt":
					var m dnsmessage.Message
					_ = m.Unpack(out)
					opt := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 512}, Body: &dnsmessage.OPTResource{}}
					m.Additionals = []dnsmessage.Resource{opt, opt}
					out, _ = m.Pack()
					return out
				}
				return out
			})
			w, s := runWorker(t, u, nil)
			for _, tcp := range []bool{false, true} {
				out := exchange(t, s, query(t, "example.", dnsmessage.TypeA), tcp)
				if responseCode(t, out) != dnsmessage.RCodeServerFailure {
					t.Fatal("malformed response forwarded")
				}
				if o := observation(t, w); o.Outcome != "malformed_response" {
					t.Fatalf("tcp=%v: %+v", tcp, o)
				}
			}
		})
	}
}
func TestExtendedRCodeAndEDNSVersion(t *testing.T) {
	u := upstream(t, answer)
	w, s := runWorker(t, u, nil)
	var m dnsmessage.Message
	_ = m.Unpack(query(t, "example.", dnsmessage.TypeA))
	m.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 512, TTL: 1 << 16}, Body: &dnsmessage.OPTResource{}}}
	q, _ := m.Pack()
	out := exchange(t, s, q, false)
	if e := m.Unpack(out); e != nil {
		t.Fatal(e)
	}
	if len(m.Additionals) != 1 || m.Additionals[0].Header.ExtendedRCode(m.RCode) != 16 {
		t.Fatalf("BADVERS not encoded %+v", m)
	}
	o := observation(t, w)
	if o.Outcome != "unsupported_edns_version" || o.RCode == nil || *o.RCode != 16 {
		t.Fatalf("%+v", o)
	}
}
func TestResponseShapedQueryIsObservedWithoutReply(t *testing.T) {
	u := upstream(t, answer)
	w, s := runWorker(t, u, nil)
	q := query(t, "example.", dnsmessage.TypeA)
	q[2] |= 0x80
	c, e := net.Dial("udp4", s.UDP.LocalAddr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Millisecond))
	_, _ = c.Write(q)
	var b [512]byte
	if _, e = c.Read(b[:]); e == nil {
		t.Fatal("responded to response")
	}
	o := observation(t, w)
	if o.Outcome != "response_as_query" {
		t.Fatalf("%+v", o)
	}
}

func TestUDPProtocolMaximumAndTruncationEvidence(t *testing.T) {
	u := upstream(t, func(b []byte, tcp bool) []byte {
		var m dnsmessage.Message
		_ = m.Unpack(b)
		m.Response = true
		data := make([]byte, 65485)
		m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: 65200, Class: dnsmessage.ClassINET}, Body: &dnsmessage.UnknownResource{Type: 65200, Data: data}}}
		m.Additionals = nil
		out, _ := m.Pack()
		if tcp {
			return out
		}
		m.Answers = nil
		m.Truncated = true
		out, _ = m.Pack()
		return out
	})
	w, s := runWorker(t, u, nil)
	var m dnsmessage.Message
	_ = m.Unpack(query(t, "example.", dnsmessage.TypeA))
	m.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 65535}, Body: &dnsmessage.OPTResource{}}}
	q, _ := m.Pack()
	out := exchange(t, s, q, false)
	if len(out) > 65507 {
		t.Fatal("exceeds IPv4 UDP maximum")
	}
	o := observation(t, w)
	if !o.ResponseTruncated || o.DeliveryError != "" {
		t.Fatalf("missing truncation evidence %+v", o)
	}
}
func TestResponseShapedQueryHasNoResponseRCode(t *testing.T) {
	u := upstream(t, answer)
	w, s := runWorker(t, u, nil)
	q := query(t, "example.", dnsmessage.TypeA)
	q[2] |= 0x80
	c, e := net.Dial("udp4", s.UDP.LocalAddr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_, _ = c.Write(q)
	o := observation(t, w)
	if o.RCode != nil {
		t.Fatalf("invented response rcode %+v", o)
	}
}
