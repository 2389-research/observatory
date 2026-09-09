// ABOUTME: Exercises Linux UAPI-encoded messages through the real binary decoders.
// ABOUTME: Fixtures follow kernel nfnetlink_conntrack.h and nfnetlink_log.h, not mocked calls.
package netobserve

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

// Attribute IDs and network-byte-order values follow Linux UAPI:
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nfnetlink_conntrack.h
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nfnetlink_log.h
func attr(kind uint16, payload ...[]byte) []byte {
	p := bytes.Join(payload, nil)
	b := make([]byte, (len(p)+7)&^3)
	binary.NativeEndian.PutUint16(b, uint16(4+len(p)))
	binary.NativeEndian.PutUint16(b[2:], kind)
	copy(b[4:], p)
	return b
}
func be16(n uint16) []byte      { return binary.BigEndian.AppendUint16(nil, n) }
func be32(n uint32) []byte      { return binary.BigEndian.AppendUint32(nil, n) }
func be64(n uint64) []byte      { return binary.BigEndian.AppendUint64(nil, n) }
func testPtr[T any](value T) *T { return &value }
func msg(kind, flags uint16, attrs ...[]byte) []byte {
	return msgFamily(kind, flags, 2, attrs...)
}
func msgFamily(kind, flags uint16, family uint8, attrs ...[]byte) []byte {
	p := bytes.Join(attrs, nil)
	b := make([]byte, 20+len(p))
	binary.NativeEndian.PutUint32(b, uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], kind)
	binary.NativeEndian.PutUint16(b[6:], flags)
	b[16] = family // nfgenmsg version 0, group 0.
	copy(b[20:], p)
	return b
}
func nflogDone(payload [4]byte) []byte {
	b := make([]byte, 20)
	binary.NativeEndian.PutUint32(b, uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], 3)
	copy(b[16:], payload[:])
	return b
}
func tupleAttr(kind uint16, src, dst [4]byte, sport, dport uint16) []byte {
	return attr(kind|0x8000,
		attr(1|0x8000, attr(1, src[:]), attr(2, dst[:])),
		attr(2|0x8000, attr(1, []byte{6}), attr(2, be16(sport)), attr(3, be16(dport))))
}
func flowMessage(flags uint16) []byte {
	return msg(0x100, flags,
		tupleAttr(1, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50123, 443),
		tupleAttr(2, [4]byte{93, 184, 216, 34}, [4]byte{10, 0, 0, 2}, 443, 50123),
		attr(12, be32(42)), attr(18, be16(7)), attr(3, be32(2)), attr(8, be32(9)), attr(7, be32(120)),
		attr(4|0x8000, attr(1|0x8000, attr(1, []byte{1}))),
		attr(9|0x8000, attr(1, be64(3)), attr(2, be64(180))),
		attr(10|0x8000, attr(1, be64(0)), attr(2, be64(0))),
		attr(20|0x8000, attr(1, be64(100)), attr(2, be64(200))), attr(27, be64(300)))
}
func TestConntrackLifecycleAndCounters(t *testing.T) {
	for _, tc := range []struct {
		name     string
		flags    uint16
		snapshot bool
		kind     uint16
		event    string
	}{
		{"new", 0x600, false, 0x100, "new"}, {"update", 0, false, 0x100, "update"},
		{"destroy", 0, false, 0x102, "destroy"}, {"snapshot", 2, true, 0x100, "snapshot"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := flowMessage(tc.flags)
			binary.NativeEndian.PutUint16(b[4:], tc.kind)
			flows, err := ParseConntrack(b, tc.snapshot)
			if err != nil || len(flows) != 1 {
				t.Fatalf("flows=%+v err=%v", flows, err)
			}
			f := flows[0]
			if f.Event != tc.event || f.ID == nil || *f.ID != 42 || f.Zone == nil || *f.Zone != 7 {
				t.Fatalf("identity: %+v", f)
			}
			if f.Original == nil || f.Original.Source != netip.MustParseAddr("10.0.0.2") || *f.Original.DestinationPort != 443 || f.Reply == nil || *f.Reply.SourcePort != 443 {
				t.Fatalf("tuples: %+v", f)
			}
			if f.TCPState == nil || *f.TCPState != 1 || *f.OriginalCounters.Bytes != 180 || *f.ReplyCounters.Packets != 0 || *f.StartNanoseconds != 100 || *f.StopNanoseconds != 200 || *f.EventNanoseconds != 300 || *f.Status != 2 || *f.Mark != 9 || *f.TimeoutSeconds != 120 {
				t.Fatalf("evidence: %+v", f)
			}
		})
	}
}
func TestConntrackMissingFieldsStayUnknown(t *testing.T) {
	fs, err := ParseConntrack(msg(0x100, 0, attr(12, be32(0)), attr(400, []byte{1, 2, 3})), false)
	if err != nil || len(fs) != 1 {
		t.Fatalf("%+v %v", fs, err)
	}
	f := fs[0]
	if f.ID == nil || *f.ID != 0 || f.Original != nil || f.Zone != nil || f.TCPState != nil || f.OriginalCounters.Bytes != nil {
		t.Fatalf("invented values: %+v", f)
	}
}
func TestConntrackMalformedAndUnsupported(t *testing.T) {
	badAttr := msg(0x100, 0, attr(12, []byte{1, 2}))
	badEndian := msg(0x100, 0, attr(12|0x8000, be32(2)))
	badNested := msg(0x100, 0, attr(1|0xc000, []byte{1, 2, 3}))
	duplicate := msg(0x100, 0, attr(12, be32(1)), attr(12, be32(2)))
	ipv6 := flowMessage(0)
	ipv6[16] = 10
	for name, b := range map[string][]byte{"short": {1, 2}, "attribute": badAttr, "scalar_nested": badEndian, "nested_endian": badNested, "duplicate": duplicate, "ipv6": ipv6} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseConntrack(b, false)
			if err == nil {
				t.Fatal("accepted invalid message")
			}
		})
	}
	b := flowMessage(0)
	for n := 0; n < len(b); n++ {
		if _, err := ParseConntrack(b[:n], false); n > 0 && err == nil {
			t.Fatalf("accepted truncated prefix %d", n)
		}
	}
}
func TestNetlinkControls(t *testing.T) {
	control := func(kind, flags uint16, p []byte) []byte {
		b := make([]byte, 16+len(p))
		binary.NativeEndian.PutUint32(b, uint32(len(b)))
		binary.NativeEndian.PutUint16(b[4:], kind)
		binary.NativeEndian.PutUint16(b[6:], flags)
		copy(b[16:], p)
		return b
	}
	ack := control(2, 0, make([]byte, 4))
	for _, b := range [][]byte{ack, control(1, 0, nil), control(3, 0, nil)} {
		fs, err := ParseConntrack(b, false)
		if err != nil || len(fs) != 0 {
			t.Fatalf("control became event: %v %v", fs, err)
		}
	}
	for _, tc := range []struct {
		b    []byte
		want error
	}{{control(4, 0, nil), ErrOverrun}, {control(3, 16, nil), ErrDumpInterrupted}} {
		if _, err := ParseConntrack(tc.b, false); !errors.Is(err, tc.want) {
			t.Fatalf("got %v want %v", err, tc.want)
		}
	}
	errno := make([]byte, 4)
	binary.NativeEndian.PutUint32(errno, ^uint32(104))
	if _, err := ParseConntrack(control(2, 0, errno), false); err == nil {
		t.Fatal("ignored netlink error")
	}
}
func packet() []byte {
	b := make([]byte, 44)
	b[0] = 0x45
	b[9] = 6
	binary.BigEndian.PutUint16(b[2:], 100)
	copy(b[12:], []byte{10, 0, 0, 2})
	copy(b[16:], []byte{1, 1, 1, 1})
	binary.BigEndian.PutUint16(b[20:], 50000)
	binary.BigEndian.PutUint16(b[22:], 443)
	copy(b[24:], []byte("PRIVATE BODY CONTENT"))
	return b
}
func packetHeader(protocol uint16) []byte {
	return attr(1, be16(protocol), []byte{0, 0})
}
func TestNFLogHeaderAndNoPayloadRetention(t *testing.T) {
	b := msg(0x400, 0, attr(1, []byte{8, 0, 2, 0}), attr(4, be32(3)), attr(5, be32(4)), attr(6, be32(5)), attr(7, be32(6)),
		attr(2, be32(9)), attr(12, be32(99)), attr(13, be32(123)), attr(10, []byte("deny-public\x00")),
		attr(3, be64(1234), be64(567)), attr(9, packet()))
	binary.BigEndian.PutUint16(b[18:], 100)
	ds, err := ParseNFLog(b)
	if err != nil || len(ds) != 1 {
		t.Fatalf("%+v %v", ds, err)
	}
	d := ds[0]
	if d.Group != 100 || d.Prefix != "deny-public" || *d.InInterface != 3 || *d.PhysicalOutInterface != 6 || *d.Sequence != 99 || *d.GlobalSequence != 123 || *d.Hook != 2 || *d.Mark != 9 || *d.TimestampSeconds != 1234 || *d.TimestampMicroseconds != 567 {
		t.Fatalf("header: %+v", d)
	}
	if d.Tuple == nil || *d.Tuple.DestinationPort != 443 || *d.OriginalLength != 100 || d.CapturedLength != 44 || !d.PacketTruncated {
		t.Fatalf("packet: %+v", d)
	}
	clear(b)
	if d.Prefix != "deny-public" || d.Tuple.Source != netip.MustParseAddr("10.0.0.2") {
		t.Fatal("retained mutable input")
	}
}
func TestNFLogFragmentAndShortHeaders(t *testing.T) {
	for _, tc := range []struct {
		name     string
		p        []byte
		ports    bool
		fragment uint16
	}{
		{"full", packet(), true, 0}, {"short_transport", packet()[:22], false, 0}, {"short_ip", packet()[:12], false, 0},
		{"fragment", func() []byte { p := packet(); binary.BigEndian.PutUint16(p[6:], 1); return p }(), false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ds, err := ParseNFLog(msg(0x400, 0, packetHeader(0x0800), attr(9, tc.p)))
			if err != nil || len(ds) != 1 {
				t.Fatalf("%v %v", ds, err)
			}
			d := ds[0]
			got := d.Tuple != nil && d.Tuple.SourcePort != nil
			if got != tc.ports || (tc.fragment != 0 && (d.FragmentOffset == nil || *d.FragmentOffset != tc.fragment)) {
				t.Fatalf("invented transport: %+v", d)
			}
		})
	}
	ds, err := ParseNFLog(msg(0x400, 0))
	if err != nil || len(ds) != 1 || ds[0].Tuple != nil || ds[0].Sequence != nil {
		t.Fatalf("metadata-only: %v %v", ds, err)
	}
}

func TestNFLogRejectsMalformedMetadata(t *testing.T) {
	for name, b := range map[string][]byte{
		"prefix_unterminated": msg(0x400, 0, attr(10, []byte("deny"))),
		"prefix_embedded_nul": msg(0x400, 0, attr(10, []byte("den\x00y\x00"))),
		"prefix_oversized":    msg(0x400, 0, attr(10, append(bytes.Repeat([]byte{'a'}, 128), 0))),
		"short_header":        msg(0x400, 0, attr(1, []byte{8, 0})),
		"microseconds":        msg(0x400, 0, attr(3, be64(1), be64(1000000))),
		"scalar_nested":       msg(0x400, 0, attr(12|0x8000, be32(1))),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseNFLog(b); err == nil {
				t.Fatal("accepted malformed NFLOG metadata")
			}
		})
	}
}
func TestConntrackNetworkEndianFlagsAndLegacyCounters(t *testing.T) {
	b := msg(0x100, 0, attr(12|0x4000, be32(0x12345678)), attr(9|0x8000, attr(3, be32(90)), attr(4, be32(1024))))
	fs, err := ParseConntrack(b, false)
	if err != nil || len(fs) != 1 || *fs[0].ID != 0x12345678 || *fs[0].OriginalCounters.Bytes != 1024 || *fs[0].OriginalCounters.Packets != 90 {
		t.Fatalf("network scalar: %+v %v", fs, err)
	}
}
func TestDatagramBoundsAndMultipleMessages(t *testing.T) {
	b := append(flowMessage(0x600), flowMessage(0)...)
	fs, err := ParseConntrack(b, false)
	if err != nil || len(fs) != 2 || fs[0].Event != "new" || fs[1].Event != "update" {
		t.Fatalf("batch: %+v %v", fs, err)
	}
	if _, err := ParseConntrack(make([]byte, MaxDatagramBytes+1), false); !errors.Is(err, ErrMalformed) {
		t.Fatalf("unbounded input: %v", err)
	}
}
func TestNFLogMalformedPacketIsEvidence(t *testing.T) {
	p := packet()
	p[0] = 0x41
	ds, err := ParseNFLog(msg(0x400, 0, packetHeader(0x0800), attr(9, p)))
	if err != nil || len(ds) != 1 || !ds[0].PacketMalformed || ds[0].Tuple != nil {
		t.Fatalf("malformed packet discarded or trusted: %+v %v", ds, err)
	}
	p = packet()
	p[0] = 0x65
	ds, err = ParseNFLog(msg(0x400, 0, packetHeader(0x0800), attr(9, p)))
	if err != nil || len(ds) != 1 || !ds[0].PacketMalformed {
		t.Fatalf("mismatched family trusted: %+v %v", ds, err)
	}
}

func TestNFLogNetdevIPv4UsesPacketProtocolMetadata(t *testing.T) {
	records, err := ParseNFLog(msgFamily(0x400, 0, 5,
		packetHeader(0x0800), attr(4, be32(7)), attr(10, []byte("deny-spoof\x00")), attr(9, packet())))
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	record := records[0]
	if record.Family != 5 || record.HardwareProtocol == nil || *record.HardwareProtocol != 0x0800 ||
		record.Tuple == nil || record.Tuple.Source != netip.MustParseAddr("10.0.0.2") ||
		record.ScopeLimitation != "" || record.InInterface == nil || *record.InInterface != 7 {
		t.Fatalf("netdev IPv4 evidence: %+v", record)
	}
}

func TestNFLogUnsupportedScopesRemainEvidence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		family     uint8
		protocol   *uint16
		limitation string
	}{
		{name: "native IPv6", family: 10, protocol: testPtr(uint16(0x86dd)), limitation: "unsupported_nfgen_family"},
		{name: "netdev ARP", family: 5, protocol: testPtr(uint16(0x0806)), limitation: "unsupported_hardware_protocol"},
		{name: "netdev unknown EtherType", family: 5, protocol: testPtr(uint16(0x88b5)), limitation: "unsupported_hardware_protocol"},
		{name: "netdev missing protocol", family: 5, limitation: "hardware_protocol_missing"},
		{name: "native IPv6 missing protocol", family: 10, limitation: "unsupported_nfgen_family"},
		{name: "native family conflict", family: 2, protocol: testPtr(uint16(0x86dd)), limitation: "family_hardware_protocol_conflict"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs := [][]byte{attr(4, be32(9)), attr(10, []byte("deny-ingress\x00")), attr(12, be32(41)), attr(9, packet())}
			if tc.protocol != nil {
				attrs = append([][]byte{packetHeader(*tc.protocol)}, attrs...)
			}
			records, err := ParseNFLog(msgFamily(0x400, 0, tc.family, attrs...))
			if err != nil || len(records) != 1 {
				t.Fatalf("records=%+v err=%v", records, err)
			}
			record := records[0]
			if record.Family != tc.family || record.Tuple != nil || record.PacketMalformed ||
				record.ScopeLimitation != tc.limitation || record.Prefix != "deny-ingress" ||
				record.Sequence == nil || *record.Sequence != 41 || record.CapturedLength != len(packet()) {
				t.Fatalf("unsupported evidence: %+v", record)
			}
		})
	}
}

func TestNFLogMixedUnsupportedAndSupportedRecords(t *testing.T) {
	unsupported := msgFamily(0x400, 0, 5, packetHeader(0x0806), attr(10, []byte("deny-arp\x00")), attr(9, packet()))
	supported := msgFamily(0x400, 0, 5, packetHeader(0x0800), attr(10, []byte("deny-ipv4\x00")), attr(9, packet()))
	binary.BigEndian.PutUint16(unsupported[18:], 100)
	binary.BigEndian.PutUint16(supported[18:], 100)
	batch := append(unsupported, supported...)
	batch = append(batch, nflogDone([4]byte{0xa5, 0x5a, 0xff, 0x01})...)
	records, err := ParseNFLog(batch)
	if err != nil || len(records) != 2 {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	if records[0].Tuple != nil || records[0].ScopeLimitation != "unsupported_hardware_protocol" ||
		records[1].Tuple == nil || records[1].ScopeLimitation != "" {
		t.Fatalf("mixed evidence lost or invented: %+v", records)
	}
}
func FuzzParseDatagrams(f *testing.F) {
	f.Add(flowMessage(0x600))
	f.Add(msg(0x400, 0, attr(9, packet()), attr(12, be32(1))))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseConntrack(b, false)
		_, _ = ParseConntrack(b, true)
		ds, err := ParseNFLog(b)
		if err == nil {
			for _, d := range ds {
				if d.FragmentOffset != nil && *d.FragmentOffset != 0 && d.Tuple != nil && d.Tuple.SourcePort != nil {
					t.Fatal("fragment invented ports")
				}
			}
		}
	})
}

func TestConntrackRepeatedAlignmentPadding(t *testing.T) {
	// Linux dump_counters and ctnetlink_dump_timestamp use nla_put_be64 with
	// a padding attribute before each value on architectures requiring alignment.
	b := msg(0x102, 0,
		attr(9|0x8000, attr(5), attr(1, be64(3)), attr(5), attr(2, be64(180))),
		attr(20|0x8000, attr(3), attr(1, be64(100)), attr(3), attr(2, be64(200))))
	fs, err := ParseConntrack(b, false)
	if err != nil || len(fs) != 1 || *fs[0].OriginalCounters.Bytes != 180 || *fs[0].StopNanoseconds != 200 {
		t.Fatalf("valid alignment rejected: %+v %v", fs, err)
	}
}

func TestConntrackDirectionalZone(t *testing.T) {
	b := msg(0x100, 0, attr(1|0x8000, attr(3, be16(12))))
	fs, err := ParseConntrack(b, false)
	if err != nil || len(fs) != 1 || fs[0].Original == nil || fs[0].Original.Zone == nil || *fs[0].Original.Zone != 12 {
		t.Fatalf("directional zone lost: %+v %v", fs, err)
	}
}

func TestInterruptedDumpDataCannotBecomeSnapshot(t *testing.T) {
	// The kernel may attach NLM_F_DUMP_INTR to any dump message, not only DONE.
	if _, err := ParseConntrack(flowMessage(0x10), true); !errors.Is(err, ErrDumpInterrupted) {
		t.Fatalf("interrupted data message accepted: %v", err)
	}
}

func TestNFLogDistinguishesImpossibleTransportFromCaptureTruncation(t *testing.T) {
	for _, proto := range []byte{6, 17} {
		name := "TCP"
		if proto == 17 {
			name = "UDP"
		}
		t.Run(name, func(t *testing.T) {
			short := append([]byte(nil), packet()[:24]...)
			short[9] = proto
			binary.BigEndian.PutUint16(short[2:], uint16(len(short)))
			records, err := ParseNFLog(msg(0x400, 0, packetHeader(0x0800), attr(9, short)))
			if err != nil {
				t.Fatal(err)
			}
			if !records[0].PacketMalformed || records[0].PacketTruncated {
				t.Fatalf("impossible transport marked valid: %+v", records[0])
			}
			binary.BigEndian.PutUint16(short[2:], 100)
			records, err = ParseNFLog(msg(0x400, 0, packetHeader(0x0800), attr(9, short)))
			if err != nil {
				t.Fatal(err)
			}
			if records[0].PacketMalformed || !records[0].PacketTruncated {
				t.Fatalf("snaplen truncation marked malformed: %+v", records[0])
			}
		})
	}
	// A legal first fragment can split a TCP header; its own total length is not the datagram length.
	fragment := append([]byte(nil), packet()[:28]...)
	binary.BigEndian.PutUint16(fragment[2:], 28)
	binary.BigEndian.PutUint16(fragment[6:], 0x2000)
	records, err := ParseNFLog(msg(0x400, 0, packetHeader(0x0800), attr(9, fragment)))
	if err != nil || records[0].PacketMalformed {
		t.Fatalf("first fragment marked malformed: %+v %v", records, err)
	}
}
