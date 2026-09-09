// ABOUTME: Decodes bounded IPv4 conntrack and NFLOG netlink datagrams.
// ABOUTME: Socket ownership, sender validation and MSG_TRUNC checks belong to acquisition.
package netobserve

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

// Linux UAPI identifiers come from include/uapi/linux/netfilter/{nfnetlink,
// nfnetlink_conntrack,nfnetlink_log}.h. Netlink headers are native endian;
// nfnetlink attribute scalars are network endian, even without NLA_F_NET_BYTEORDER.
const (
	nestedFlag         = 0x8000
	networkFlag        = 0x4000
	attributeMask      = 0x3fff
	conntrackSubsystem = 1
	logSubsystem       = 4
)

type KernelError struct{ Code int32 }

func (e *KernelError) Error() string { return fmt.Sprintf("netlink kernel error %d", e.Code) }

type message struct {
	kind, flags uint16
	data        []byte
}

func messages(data []byte) ([]message, error) {
	if len(data) > MaxDatagramBytes {
		return nil, fmt.Errorf("%w: datagram exceeds %d bytes", ErrMalformed, MaxDatagramBytes)
	}
	var out []message
	for len(data) > 0 {
		if len(data) < 16 {
			return nil, fmt.Errorf("%w: short message header", ErrMalformed)
		}
		n := uint64(binary.NativeEndian.Uint32(data))
		if n < 16 || n > uint64(len(data)) {
			return nil, fmt.Errorf("%w: message length", ErrMalformed)
		}
		m := message{binary.NativeEndian.Uint16(data[4:]), binary.NativeEndian.Uint16(data[6:]), data[16:n]}
		// NLM_F_DUMP_INTR may occur on any dump message, including a data record.
		if m.flags&16 != 0 {
			return nil, ErrDumpInterrupted
		}
		switch m.kind {
		case 1: // NLMSG_NOOP
		case 2: // NLMSG_ERROR: zero is an acknowledgment, never an event.
			if len(m.data) < 4 {
				return nil, fmt.Errorf("%w: short kernel error", ErrMalformed)
			}
			code := int32(binary.NativeEndian.Uint32(m.data))
			if code == -105 {
				return nil, ErrOverrun
			} // Linux ENOBUFS; independent of build OS.
			if code != 0 {
				return nil, &KernelError{Code: code}
			}
		case 3: // NLMSG_DONE can terminate a failed dump.
			out = append(out, m)
		case 4:
			return nil, ErrOverrun
		default:
			out = append(out, m)
		}
		aligned := (n + 3) &^ uint64(3)
		if aligned > uint64(len(data)) {
			if n != uint64(len(data)) {
				return nil, fmt.Errorf("%w: truncated message padding", ErrMalformed)
			}
			data = nil
		} else {
			data = data[aligned:]
		}
	}
	return out, nil
}

type attribute struct {
	flags uint16
	data  []byte
}
type decoder struct {
	attrs map[uint16]attribute
	err   error
}

func decode(data []byte, padding ...uint16) *decoder {
	d := &decoder{attrs: make(map[uint16]attribute)}
	for len(data) > 0 {
		if len(data) < 4 {
			d.fail("short attribute header")
			break
		}
		n := int(binary.NativeEndian.Uint16(data))
		kind := binary.NativeEndian.Uint16(data[2:])
		if n < 4 || n > len(data) {
			d.fail("attribute length")
			break
		}
		id := kind & attributeMask
		if kind&^uint16(attributeMask) == nestedFlag|networkFlag {
			d.fail("conflicting attribute flags")
			break
		}
		isPadding := false
		for _, pad := range padding {
			if id == pad && kind == id && n == 4 {
				isPadding = true
			}
		}
		if !isPadding {
			if _, ok := d.attrs[id]; ok {
				d.fail("duplicate attribute")
				break
			}
			d.attrs[id] = attribute{kind &^ uint16(attributeMask), data[4:n]}
		}
		aligned := (n + 3) &^ 3
		if aligned > len(data) {
			if n != len(data) {
				d.fail("truncated attribute padding")
			}
			break
		}
		data = data[aligned:]
	}
	return d
}
func (d *decoder) fail(detail string) {
	if d.err == nil {
		d.err = fmt.Errorf("%w: %s", ErrMalformed, detail)
	}
}
func (d *decoder) scalar(id uint16, n int) []byte {
	a, ok := d.attrs[id]
	if !ok {
		return nil
	}
	if a.flags&nestedFlag != 0 || (n >= 0 && len(a.data) != n) {
		d.fail(fmt.Sprintf("attribute %d scalar shape", id))
		return nil
	}
	return a.data
}
func (d *decoder) child(id uint16, padding ...uint16) *decoder {
	a, ok := d.attrs[id]
	if !ok {
		return nil
	}
	if a.flags&networkFlag != 0 {
		d.fail("nested network-byte-order flag")
		return nil
	}
	return decode(a.data, padding...)
}
func (d *decoder) u8(id uint16) *uint8 {
	b := d.scalar(id, 1)
	if b == nil {
		return nil
	}
	v := b[0]
	return &v
}
func (d *decoder) u16(id uint16) *uint16 {
	b := d.scalar(id, 2)
	if b == nil {
		return nil
	}
	v := binary.BigEndian.Uint16(b)
	return &v
}
func (d *decoder) u32(id uint16) *uint32 {
	b := d.scalar(id, 4)
	if b == nil {
		return nil
	}
	v := binary.BigEndian.Uint32(b)
	return &v
}
func (d *decoder) u64(id uint16) *uint64 {
	b := d.scalar(id, 8)
	if b == nil {
		return nil
	}
	v := binary.BigEndian.Uint64(b)
	return &v
}
func (d *decoder) finish(child *decoder) {
	if child != nil && child.err != nil && d.err == nil {
		d.err = child.err
	}
}
func (d *decoder) tuple(id uint16) *Tuple {
	t := d.child(id)
	if t == nil {
		return nil
	}
	out := &Tuple{Zone: t.u16(3)}
	if ip := t.child(1); ip != nil {
		if _, ok := ip.attrs[3]; ok {
			ip.err = ErrUnsupportedFamily
		}
		if _, ok := ip.attrs[4]; ok {
			ip.err = ErrUnsupportedFamily
		}
		if b := ip.scalar(1, 4); b != nil {
			out.Source = netip.AddrFrom4([4]byte(b))
		}
		if b := ip.scalar(2, 4); b != nil {
			out.Destination = netip.AddrFrom4([4]byte(b))
		}
		t.finish(ip)
	}
	if proto := t.child(2); proto != nil {
		out.Protocol = proto.u8(1)
		out.SourcePort = proto.u16(2)
		out.DestinationPort = proto.u16(3)
		out.ICMPID = proto.u16(4)
		out.ICMPType = proto.u8(5)
		out.ICMPCode = proto.u8(6)
		t.finish(proto)
	}
	d.finish(t)
	return out
}
func (d *decoder) counters(id uint16) Counters {
	c := d.child(id, 5)
	if c == nil {
		return Counters{}
	}
	out := Counters{Packets: c.u64(1), Bytes: c.u64(2)}
	// Legacy 32-bit counters are distinct UAPI attributes. Missing counters stay nil.
	if v := c.u32(3); out.Packets == nil && v != nil {
		n := uint64(*v)
		out.Packets = &n
	}
	if v := c.u32(4); out.Bytes == nil && v != nil {
		n := uint64(*v)
		out.Bytes = &n
	}
	d.finish(c)
	return out
}
func payload(m message, subsystem uint16) (*decoder, error) {
	if m.kind>>8 != subsystem {
		return nil, fmt.Errorf("%w: unexpected subsystem %d", ErrMalformed, m.kind>>8)
	}
	if len(m.data) < 4 {
		return nil, fmt.Errorf("%w: short nfgenmsg", ErrMalformed)
	}
	if m.data[0] != 2 {
		return nil, ErrUnsupportedFamily
	}
	if m.data[1] != 0 {
		return nil, fmt.Errorf("%w: unsupported nfnetlink version", ErrMalformed)
	}
	return decode(m.data[4:]), nil
}

// ParseConntrack accepts a complete datagram from a validated kernel socket.
// snapshot must be true only for replies to the caller's verified dump request;
// multicast UPDATE and dump replies share the same kernel message type.
func ParseConntrack(data []byte, snapshot bool) ([]Flow, error) {
	ms, err := messages(data)
	if err != nil {
		return nil, err
	}
	var out []Flow
	for _, m := range ms {
		if m.kind == 3 {
			if len(m.data) > 0 {
				if len(m.data) < 4 {
					return nil, fmt.Errorf("%w: short dump status", ErrMalformed)
				}
				if code := int32(binary.NativeEndian.Uint32(m.data)); code != 0 {
					return nil, &KernelError{Code: code}
				}
			}
			continue
		}
		d, err := payload(m, conntrackSubsystem)
		if err != nil {
			return nil, err
		}
		f := Flow{Event: "update"}
		switch m.kind & 0xff {
		case 0:
			if snapshot {
				f.Event = "snapshot"
			} else if m.flags&0x600 == 0x600 {
				f.Event = "new"
			}
		case 2:
			f.Event = "destroy"
		default:
			return nil, fmt.Errorf("%w: unexpected conntrack operation", ErrMalformed)
		}
		f.Original = d.tuple(1)
		f.Reply = d.tuple(2)
		f.Status = d.u32(3)
		f.TimeoutSeconds = d.u32(7)
		f.Mark = d.u32(8)
		f.ID = d.u32(12)
		f.Zone = d.u16(18)
		f.OriginalCounters = d.counters(9)
		f.ReplyCounters = d.counters(10)
		if p := d.child(4); p != nil {
			if tcp := p.child(1); tcp != nil {
				f.TCPState = tcp.u8(1)
				p.finish(tcp)
			}
			d.finish(p)
		}
		if ts := d.child(20, 3); ts != nil {
			f.StartNanoseconds = ts.u64(1)
			f.StopNanoseconds = ts.u64(2)
			d.finish(ts)
		}
		f.EventNanoseconds = d.u64(27)
		if d.err != nil {
			return nil, d.err
		}
		out = append(out, f)
	}
	return out, nil
}

// ParseNFLog decodes records without retaining any payload bytes. The caller
// must verify the configured group/rule is a denial boundary before labeling it.
func ParseNFLog(data []byte) ([]Denial, error) {
	ms, err := messages(data)
	if err != nil {
		return nil, err
	}
	var out []Denial
	for _, m := range ms {
		if m.kind == 3 {
			// nfnetlink_log reserves sizeof(nfgenmsg) for batched NLMSG_DONE
			// without initializing those four opaque bytes.
			if len(m.data) != 4 {
				return nil, fmt.Errorf("%w: invalid NFLOG batch terminator", ErrMalformed)
			}
			continue
		}
		if m.kind>>8 != logSubsystem {
			return nil, fmt.Errorf("%w: unexpected subsystem %d", ErrMalformed, m.kind>>8)
		}
		if len(m.data) < 4 {
			return nil, fmt.Errorf("%w: short nfgenmsg", ErrMalformed)
		}
		if m.data[1] != 0 {
			return nil, fmt.Errorf("%w: unsupported nfnetlink version", ErrMalformed)
		}
		d := decode(m.data[4:])
		if m.kind&0xff != 0 {
			return nil, fmt.Errorf("%w: unexpected NFLOG operation", ErrMalformed)
		}
		n := Denial{Family: m.data[0], Group: binary.BigEndian.Uint16(m.data[2:])}
		if p := d.scalar(1, 4); p != nil {
			proto := binary.BigEndian.Uint16(p)
			hook := p[2]
			n.HardwareProtocol = &proto
			n.Hook = &hook
		}
		n.Mark = d.u32(2)
		n.InInterface = d.u32(4)
		n.OutInterface = d.u32(5)
		n.PhysicalInInterface = d.u32(6)
		n.PhysicalOutInterface = d.u32(7)
		n.Sequence = d.u32(12)
		n.GlobalSequence = d.u32(13)
		if ts := d.scalar(3, 16); ts != nil {
			sec := binary.BigEndian.Uint64(ts)
			usec := binary.BigEndian.Uint64(ts[8:])
			n.TimestampSeconds = &sec
			n.TimestampMicroseconds = &usec
			if usec >= 1000000 {
				d.fail("NFLOG microseconds out of range")
			}
		}
		if p := d.scalar(10, -1); p != nil {
			if len(p) == 0 || len(p) > 128 || p[len(p)-1] != 0 || strings.IndexByte(string(p[:len(p)-1]), 0) >= 0 {
				d.fail("invalid NFLOG prefix")
			} else {
				n.Prefix = string(p[:len(p)-1])
			}
		}
		if p := d.scalar(9, -1); p != nil {
			n.CapturedLength = len(p)
			n.ScopeLimitation = ipv4ScopeLimitation(n.Family, n.HardwareProtocol)
			if n.ScopeLimitation == "" {
				parsePacket(p, &n)
			}
		} else {
			n.ScopeLimitation = ipv4ScopeLimitation(n.Family, n.HardwareProtocol)
		}
		if d.err != nil {
			return nil, d.err
		}
		out = append(out, n)
	}
	return out, nil
}

func ipv4ScopeLimitation(family uint8, hardwareProtocol *uint16) string {
	if family != 2 && family != 5 {
		if hardwareProtocol != nil && *hardwareProtocol == 0x0800 {
			return "family_hardware_protocol_conflict"
		}
		return "unsupported_nfgen_family"
	}
	if hardwareProtocol == nil {
		return "hardware_protocol_missing"
	}
	if *hardwareProtocol == 0x0800 {
		return ""
	}
	if family == 2 {
		return "family_hardware_protocol_conflict"
	}
	return "unsupported_hardware_protocol"
}

func parsePacket(p []byte, n *Denial) {
	if len(p) < 20 {
		n.PacketTruncated = true
		return
	}
	if p[0]>>4 != 4 {
		n.PacketMalformed = true
		return
	}
	headerLen := int(p[0]&15) * 4
	original := binary.BigEndian.Uint16(p[2:])
	n.OriginalLength = &original
	n.PacketTruncated = len(p) < int(original)
	if headerLen < 20 || int(original) < headerLen {
		n.PacketMalformed = true
		return
	}
	proto := p[9]
	offset := binary.BigEndian.Uint16(p[6:]) & 0x1fff
	n.FragmentOffset = &offset
	n.Tuple = &Tuple{Source: netip.AddrFrom4([4]byte(p[12:16])), Destination: netip.AddrFrom4([4]byte(p[16:20])), Protocol: &proto}
	if headerLen > len(p) {
		n.PacketTruncated = true
		return
	}
	available := min(len(p), int(original)) - headerLen
	if offset != 0 {
		return
	}
	// Total length proves a short unfragmented transport header is malformed.
	// A copied prefix is only truncated; a first fragment may split the header.
	if binary.BigEndian.Uint16(p[6:])&0x2000 == 0 {
		transportLength := int(original) - headerLen
		if (proto == 6 && transportLength < 20) || (proto == 17 && transportLength < 8) {
			n.PacketMalformed = true
			return
		}
	}
	if (proto == 6 || proto == 17) && available >= 4 {
		src := binary.BigEndian.Uint16(p[headerLen:])
		dst := binary.BigEndian.Uint16(p[headerLen+2:])
		n.Tuple.SourcePort = &src
		n.Tuple.DestinationPort = &dst
	}
	if proto == 1 && available >= 2 {
		typ, code := p[headerLen], p[headerLen+1]
		n.Tuple.ICMPType = &typ
		n.Tuple.ICMPCode = &code
		if (typ == 0 || typ == 8) && available >= 6 {
			id := binary.BigEndian.Uint16(p[headerLen+4:])
			n.Tuple.ICMPID = &id
		}
	}
}
