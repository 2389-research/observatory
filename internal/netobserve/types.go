// ABOUTME: Defines host network observations without claiming missing kernel evidence.
// ABOUTME: Values are scoped by the collector; packet bytes never become retained state.
package netobserve

import (
	"errors"
	"net/netip"
)

const MaxDatagramBytes = 1 << 20

var ErrMalformed = errors.New("malformed netlink data")
var ErrUnsupportedFamily = errors.New("network family outside IPv4 collection scope")
var ErrOverrun = errors.New("netlink receive overrun")
var ErrDumpInterrupted = errors.New("netlink dump interrupted")

// Tuple keeps absent transport fields unknown, including noninitial fragments.
type Tuple struct {
	Zone            *uint16
	Source          netip.Addr
	Destination     netip.Addr
	Protocol        *uint8
	SourcePort      *uint16
	DestinationPort *uint16
	ICMPID          *uint16
	ICMPType        *uint8
	ICMPCode        *uint8
}

type Counters struct{ Packets, Bytes *uint64 }

// Flow is one kernel observation. New is not a completed TCP connection.
// Reply is the kernel reply tuple, not a guessed translated tuple.
type Flow struct {
	Event                                               string
	Original, Reply                                     *Tuple
	ID                                                  *uint32
	Zone                                                *uint16
	Status, Mark, TimeoutSeconds                        *uint32
	TCPState                                            *uint8
	OriginalCounters, ReplyCounters                     Counters
	StartNanoseconds, StopNanoseconds, EventNanoseconds *uint64
}

// Denial is an NFLOG record from a caller-verified denial group. NFLOG alone
// cannot prove a verdict; the caller must bind Group/Prefix to installed policy.
type Denial struct {
	Group                                                                uint16
	HardwareProtocol                                                     *uint16
	Hook                                                                 *uint8
	InInterface, OutInterface, PhysicalInInterface, PhysicalOutInterface *uint32
	Mark, Sequence, GlobalSequence                                       *uint32
	TimestampSeconds, TimestampMicroseconds                              *uint64
	Prefix                                                               string
	Tuple                                                                *Tuple
	OriginalLength                                                       *uint16
	CapturedLength                                                       int
	PacketTruncated                                                      bool
	PacketMalformed                                                      bool
	FragmentOffset                                                       *uint16
}

// Scope is host-owned acquisition identity, fixed for a tracker's lifetime.
// BootID is the guest boot. HostBootID is the host kernel boot.
type Scope struct{ VMID, BootID, HostBootID, Generation, NamespaceID, Boundary string }

type Loss struct {
	Reason string
	Count  *uint64
}
type FlowObservation struct {
	Flow          Flow
	StartObserved bool
}
type Result struct {
	Scope   Scope
	Flows   []FlowObservation
	Denials []Denial
	Losses  []Loss
}
