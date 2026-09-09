// ABOUTME: Validates DNS wire requests and replies before forwarding or recording.
// ABOUTME: Preserves opaque extensions on wire while retaining bounded typed evidence.
package manageddns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const maxWireRecords = 2048

var errFrame = errors.New("manageddns: invalid or oversized DNS frame")

func readFrame(r io.Reader, limit int) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n < 12 || n > limit {
		return nil, errFrame
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}
func writeFrame(w io.Writer, b []byte) error {
	if len(b) < 12 || len(b) > 65535 {
		return errFrame
	}
	out := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(out, uint16(len(b)))
	copy(out[2:], b)
	for len(out) > 0 {
		n, err := w.Write(out)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		out = out[n:]
	}
	return nil
}

// boundedMessage rejects count bombs and trailing junk as well as malformed
// compression. Wire size alone does not bound expanded resource/name allocation.
func boundedMessage(b []byte, limit int) (dnsmessage.Message, error) {
	var m dnsmessage.Message
	if len(b) < 12 || len(b) > limit {
		return m, errFrame
	}
	count := 0
	for off := 4; off < 12; off += 2 {
		count += int(binary.BigEndian.Uint16(b[off:]))
	}
	if count > maxWireRecords {
		return m, errFrame
	}
	if err := m.Unpack(b); err != nil {
		return m, err
	}
	for _, records := range [][]dnsmessage.Resource{m.Answers, m.Authorities} {
		for _, r := range records {
			if r.Header.Type == dnsmessage.TypeOPT {
				return m, errFrame
			}
		}
	}
	optCount := 0
	for _, r := range m.Additionals {
		if r.Header.Type == dnsmessage.TypeOPT {
			optCount++
			if optCount > 1 || r.Header.Name.String() != "." {
				return m, errFrame
			}
		}
	}
	// dnsmessage.Unpack permits trailing bytes. Walk encoded lengths to require
	// one exact message; Unpack above already checked pointer destinations.
	off := 12
	for section := 0; section < 4; section++ {
		n := int(binary.BigEndian.Uint16(b[4+section*2:]))
		for i := 0; i < n; i++ {
			for {
				if off >= len(b) {
					return m, errFrame
				}
				c := int(b[off])
				off++
				if c == 0 {
					break
				}
				if c&0xc0 == 0xc0 {
					off++
					break
				}
				off += c
			}
			if section == 0 {
				off += 4
			} else {
				if off+10 > len(b) {
					return m, errFrame
				}
				size := int(binary.BigEndian.Uint16(b[off+8:]))
				off += 10 + size
			}
			if off > len(b) {
				return m, errFrame
			}
		}
	}
	if off != len(b) {
		return m, errFrame
	}
	return m, nil
}
func safeName(n dnsmessage.Name) string {
	var b strings.Builder
	for _, c := range n.Data[:n.Length] {
		if c == '.' || c == '-' || c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "\\%03d", c)
		}
	}
	return b.String()
}
func questionEvidence(m dnsmessage.Message, o *Observation) {
	if len(m.Questions) == 1 {
		q := m.Questions[0]
		o.Name = safeName(q.Name)
		o.Type = uint16(q.Type)
		o.Class = uint16(q.Class)
	}
}
func sameName(a, b dnsmessage.Name) bool {
	if a.Length != b.Length {
		return false
	}
	for i := 0; i < int(a.Length); i++ {
		x, y := a.Data[i], b.Data[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
func matches(q, r dnsmessage.Message) bool {
	if !r.Response || q.ID != r.ID || q.OpCode != r.OpCode || len(r.Questions) != 1 {
		return false
	}
	a, b := q.Questions[0], r.Questions[0]
	return a.Type == b.Type && a.Class == b.Class && sameName(a.Name, b.Name)
}
func rcode(m dnsmessage.Message) uint16 {
	code := uint16(m.RCode)
	for _, r := range m.Additionals {
		if r.Header.Type == dnsmessage.TypeOPT {
			code |= uint16(r.Header.TTL>>24) << 4
		}
	}
	return code
}

func localResponse(raw []byte, q dnsmessage.Message, code uint16, tc bool) []byte {
	if len(raw) < 2 || len(raw) >= 3 && raw[2]&0x80 != 0 {
		return nil
	}
	h := dnsmessage.Header{ID: binary.BigEndian.Uint16(raw), Response: true, RCode: dnsmessage.RCode(code & 15), Truncated: tc, OpCode: q.OpCode, RecursionDesired: q.RecursionDesired, CheckingDisabled: q.CheckingDisabled}
	m := dnsmessage.Message{Header: h}
	if len(q.Questions) == 1 {
		m.Questions = q.Questions
	}
	if code > 15 {
		m.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 512, TTL: uint32(code>>4) << 24}, Body: &dnsmessage.OPTResource{}}}
	}
	out, err := m.Pack()
	if err != nil {
		return nil
	}
	return out
}
func (w *Worker) reject(raw []byte, transport, reason string) ([]byte, Observation) {
	q, _ := boundedMessage(raw, w.cfg.MaxMessageBytes)
	o := Observation{Transport: transport, Outcome: reason, Decision: "refused", DecisionSource: "local"}
	questionEvidence(q, &o)
	code := uint16(dnsmessage.RCodeRefused)
	o.RCode = &code
	out := localResponse(raw, q, code, false)
	if len(out) == 0 {
		o.RCode = nil
	}
	return out, o
}

func validateQuestion(q dnsmessage.Message) (string, uint16) {
	if q.Response {
		return "response_as_query", uint16(dnsmessage.RCodeFormatError)
	}
	if q.OpCode != 0 || len(q.Questions) != 1 || len(q.Answers) != 0 || len(q.Authorities) != 0 || len(q.Additionals) > 1 {
		return "unsupported_query", uint16(dnsmessage.RCodeNotImplemented)
	}
	if q.Questions[0].Class != dnsmessage.ClassINET || q.Questions[0].Type == 251 || q.Questions[0].Type == 252 || q.Questions[0].Type == 253 || q.Questions[0].Type == 254 {
		return "unsupported_query", uint16(dnsmessage.RCodeNotImplemented)
	}
	for _, a := range q.Additionals {
		if a.Header.Type != dnsmessage.TypeOPT || a.Header.Name.String() != "." {
			return "unsupported_query", uint16(dnsmessage.RCodeNotImplemented)
		}
		if (a.Header.TTL>>16)&255 != 0 {
			return "unsupported_edns_version", 16
		}
	}
	return "", 0
}
func udpLimit(q dnsmessage.Message, limit int) int {
	n := 512
	for _, a := range q.Additionals {
		if a.Header.Type == dnsmessage.TypeOPT {
			n = int(a.Header.Class)
			if n < 512 {
				n = 512
			}
		}
	}
	if n > limit {
		n = limit
	}
	// Native IPv4 UDP payload cannot exceed 65535 - 20 - 8 bytes.
	if n > 65507 {
		n = 65507
	}
	return n
}
func (w *Worker) exchangeTCP(ctx context.Context, raw []byte) ([]byte, error) {
	c, err := w.sockets.DialTCP(ctx)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, errors.New("manageddns: nil upstream TCP socket")
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err = c.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err = writeFrame(c, raw); err != nil {
		return nil, err
	}
	return readFrame(c, w.cfg.MaxMessageBytes)
}
func (w *Worker) resolve(parent context.Context, raw []byte, transport string) (out []byte, o Observation) {
	start := time.Now()
	o = Observation{Transport: transport, Decision: "refused", DecisionSource: "local"}
	defer func() {
		o.Duration = time.Since(start)
		if len(out) == 0 {
			o.RCode = nil
		}
		if len(out) >= 3 {
			o.ResponseTruncated = out[2]&2 != 0
		}
	}()
	q, err := boundedMessage(raw, w.cfg.MaxMessageBytes)
	if err != nil {
		code := uint16(dnsmessage.RCodeFormatError)
		o.Outcome = "malformed_query"
		o.RCode = &code
		return localResponse(raw, q, code, false), o
	}
	questionEvidence(q, &o)
	if reason, code := validateQuestion(q); reason != "" {
		o.Outcome = reason
		o.RCode = &code
		return localResponse(raw, q, code, false), o
	}
	o.Decision = "forwarded"
	o.DecisionSource = "upstream"
	ctx, cancel := context.WithTimeout(parent, w.cfg.QueryTimeout)
	defer cancel()
	if transport == "tcp" {
		out, err = w.exchangeTCP(ctx, raw)
	} else {
		out, err = w.sockets.ExchangeUDP(ctx, raw)
	}
	var response dnsmessage.Message
	if err == nil {
		response, err = boundedMessage(out, w.cfg.MaxMessageBytes)
		if err != nil {
			o.Outcome = "malformed_response"
		} else if !matches(q, response) {
			err = errFrame
			o.Outcome = "mismatched_response"
		}
	}
	if err == nil && transport == "udp" && response.Truncated {
		o.TCPFallback = true
		out, err = w.exchangeTCP(ctx, raw)
		if err == nil {
			response, err = boundedMessage(out, w.cfg.MaxMessageBytes)
			if err != nil {
				o.Outcome = "malformed_response"
			} else if !matches(q, response) {
				err = errFrame
				o.Outcome = "mismatched_response"
			}
		}
	}
	if err != nil {
		if o.Outcome == "" {
			o.Outcome = "upstream_error"
			if errors.Is(err, errFrame) {
				o.Outcome = "malformed_response"
			}
			var timeout net.Error
			if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				o.Outcome = "timeout"
			}
		}
		return localResponse(raw, q, uint16(dnsmessage.RCodeServerFailure), false), o
	}
	code := rcode(response)
	o.RCode = &code
	o.Outcome = "answer"
	switch code {
	case 3:
		o.Outcome = "nxdomain"
	case 5:
		o.Outcome = "refused"
	case 0:
	default:
		o.Outcome = "upstream_rcode"
	}
	if response.Truncated {
		o.Outcome = "truncated_response"
	}
	for i, r := range response.Answers {
		if i == w.cfg.MaxRecords {
			o.RecordsTruncated = true
			break
		}
		o.Answers = append(o.Answers, record(r))
	}
	if transport == "udp" && len(out) > udpLimit(q, w.cfg.MaxMessageBytes) {
		// Return a valid retry signal, never a cut byte slice with broken RDLENGTHs
		// or compression. Copy semantic header flags; omitted answers are not NODATA.
		response.Truncated = true
		response.Answers = nil
		response.Authorities = nil
		response.Additionals = nil
		if code > 15 {
			response.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 512, TTL: uint32(code>>4) << 24}, Body: &dnsmessage.OPTResource{}}}
		}
		out, err = response.Pack()
		if err != nil {
			o.Outcome = "malformed_response"
			return localResponse(raw, q, uint16(dnsmessage.RCodeServerFailure), false), o
		}
	}
	return out, o
}
func record(r dnsmessage.Resource) Record {
	out := Record{Name: safeName(r.Header.Name), Type: uint16(r.Header.Type), Class: uint16(r.Header.Class), TTL: r.Header.TTL}
	switch b := r.Body.(type) {
	case *dnsmessage.AResource:
		out.Address = netip.AddrFrom4(b.A).String()
	case *dnsmessage.AAAAResource:
		out.Address = netip.AddrFrom16(b.AAAA).String()
	case *dnsmessage.CNAMEResource:
		out.Target = safeName(b.CNAME)
	case *dnsmessage.NSResource:
		out.Target = safeName(b.NS)
	case *dnsmessage.PTRResource:
		out.Target = safeName(b.PTR)
	case *dnsmessage.MXResource:
		out.Target = safeName(b.MX)
		v := b.Pref
		out.Preference = &v
	case *dnsmessage.SRVResource:
		out.Target = safeName(b.Target)
		priority, weight, port := b.Priority, b.Weight, b.Port
		out.Priority = &priority
		out.Weight = &weight
		out.Port = &port
	default:
		out.DataOmitted = true
	}
	return out
}
