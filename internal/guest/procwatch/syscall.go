// ABOUTME: Decodes bounded argv and connect syscall observations with explicit capture limits.
// ABOUTME: Correlates entry/results by observed process lifetime without treating tuples as socket identity.
package procwatch

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// SocketEvidence describes a connect syscall, not a proven transport flow or socket lifetime.
type SocketEvidence struct {
	FD                  int32  `json:"fd"`
	Namespace           string `json:"network_namespace_inode"`
	Family              uint16 `json:"address_family"`
	Destination         string `json:"destination,omitempty"`
	Port                uint16 `json:"destination_port,omitempty"`
	AddressStatus       string `json:"address_status"`
	LifetimeStatus      string `json:"socket_lifetime_status"`
	HostFlowAttribution string `json:"host_flow_attribution"`
	Phase               string `json:"phase"`
}

func decodeSyscall(e Event, b []byte) (Event, error) {
	u32 := func(n int) uint32 { return binary.LittleEndian.Uint32(b[n:]) }
	if binary.LittleEndian.Uint64(b[40:]) == 0 {
		return Event{}, fmt.Errorf("missing task lifetime")
	}
	e.ExecToken = strconv.FormatUint(binary.LittleEndian.Uint64(b[48:]), 10)
	e.TaskStartNS = strconv.FormatUint(binary.LittleEndian.Uint64(b[40:]), 10)
	e.SyscallNumber = binary.LittleEndian.Uint64(b[88:])
	if e.SyscallNumber != 59 && e.SyscallNumber != 322 && e.SyscallNumber != 42 {
		return Event{}, fmt.Errorf("unsupported syscall %d", e.SyscallNumber)
	}
	socketKind := e.Kind == "socket.connect_attempt" || e.Kind == "socket.connect_result"
	if socketKind != (e.SyscallNumber == 42) {
		return Event{}, fmt.Errorf("syscall kind and operation disagree")
	}
	if e.Kind == "proc.exec_result" || e.Kind == "socket.connect_result" {
		result := int64(binary.LittleEndian.Uint64(b[96:]))
		e.SyscallResult = &result
		return e, nil
	}
	if e.Kind == "socket.connect_attempt" {
		addr := b[144:172]
		socket := &SocketEvidence{FD: int32(u32(128)), Namespace: strconv.FormatUint(uint64(u32(136)), 10), AddressStatus: "unavailable", LifetimeStatus: "unknown", HostFlowAttribution: "unknown", Phase: "attempt"}
		if u32(140) == 0 {
			socket.Family = binary.LittleEndian.Uint16(addr)
			switch {
			case socket.Family == 2 && u32(132) >= 16:
				socket.Destination = netip.AddrFrom4([4]byte(addr[4:8])).String()
				socket.Port = binary.BigEndian.Uint16(addr[2:4])
				socket.AddressStatus = "observed_syscall_argument"
			case socket.Family == 10 && u32(132) >= 28:
				ip := netip.AddrFrom16([16]byte(addr[8:24]))
				if scope := binary.LittleEndian.Uint32(addr[24:28]); scope != 0 {
					ip = ip.WithZone(strconv.FormatUint(uint64(scope), 10))
				}
				socket.Destination = ip.String()
				socket.Port = binary.BigEndian.Uint16(addr[2:4])
				socket.AddressStatus = "observed_syscall_argument"
			default:
				socket.AddressStatus = "unsupported_address_family"
			}
		}
		e.Socket = socket
		return e, nil
	}
	count, flags := u32(104), u32(108)
	if count > 4 || flags & ^uint32(3) != 0 {
		return Event{}, fmt.Errorf("invalid argv bounds")
	}
	e.ArgvStatus, e.ArgvArgumentLimit, e.ArgvByteLimit = "captured", 4, 63
	e.ArgvTruncated = flags&1 != 0
	if flags&2 != 0 {
		e.ArgvStatus = "partial_read_failure"
	}
	for i := uint32(0); i < count; i++ {
		n := u32(112 + int(i)*4)
		if n == 0 || n > 64 {
			return Event{}, fmt.Errorf("invalid argv length %d", n)
		}
		raw := b[144+int(i)*64 : 144+int(i)*64+int(n)]
		if raw[len(raw)-1] != 0 {
			return Event{}, fmt.Errorf("unterminated argv")
		}
		raw = bytes.TrimSuffix(raw, []byte{0})
		if n == 64 {
			e.ArgvTruncated = true
		}
		e.ArgvRaw = append(e.ArgvRaw, base64.StdEncoding.EncodeToString(raw))
		e.ArgvDisplay = append(e.ArgvDisplay, strings.ToValidUTF8(string(raw), "�"))
	}
	return e, nil
}

type pendingKey struct {
	Identity
	PID         uint32
	TaskStartNS string
}
type pendingCall struct {
	event    Event
	received time.Time
}
type correlator struct{ pending map[pendingKey]pendingCall }

// consume reports discarded correlation records separately from unobserved kernel events.
func (c *correlator) consume(e Event, now time.Time) ([]Event, uint64) {
	if c.pending == nil {
		c.pending = make(map[pendingKey]pendingCall)
	}
	lost := c.expire(now)
	key := pendingKey{e.Process, e.PID, e.TaskStartNS}
	switch e.Kind {
	case "proc.exec_attempt", "socket.connect_attempt":
		if _, exists := c.pending[key]; exists {
			delete(c.pending, key)
			lost++
		}
		if len(c.pending) >= 1024 {
			lost++
		} else {
			c.pending[key] = pendingCall{e, now}
		}
	case "proc.exec":
		generation, _ := strconv.ParseUint(e.Process.ExecGeneration, 10, 64)
		if generation == 0 {
			return []Event{e}, lost
		}
		key.ExecGeneration = strconv.FormatUint(generation-1, 10)
		if e.OldPID != nil {
			key.PID = *e.OldPID
		}
		e.ArgvStatus = "entry_not_observed"
		// de_thread adopts the old leader's task start time. Only the kernel token
		// may bridge that transition; PID/generation without the token cannot.
		if e.ExecToken != "" && e.ExecToken != "0" {
			for candidate, entry := range c.pending {
				if candidate.Identity == key.Identity && candidate.PID == key.PID && entry.event.Kind == "proc.exec_attempt" && entry.event.ExecToken == e.ExecToken {
					copyArgs(&e, entry.event)
					delete(c.pending, candidate)
					break
				}
			}
		}
	case "proc.exec_result", "socket.connect_result":
		entry, ok := c.pending[key]
		matched := ok && entry.event.SyscallNumber == e.SyscallNumber
		if matched {
			delete(c.pending, key)
			copyArgs(&e, entry.event)
			if entry.event.Socket != nil {
				socket := *entry.event.Socket
				e.Socket = &socket
			}
		}
		if e.Kind == "proc.exec_result" {
			if e.SyscallResult == nil || *e.SyscallResult >= 0 {
				return nil, lost
			}
			e.Kind = "proc.exec_failed"
			if !matched {
				e.ArgvStatus = "entry_not_observed"
			}
		} else {
			if e.Socket == nil {
				e.Socket = &SocketEvidence{AddressStatus: "entry_not_observed", LifetimeStatus: "unknown", HostFlowAttribution: "unknown"}
			}
			e.Socket.Phase = "result"
		}
	case "proc.exit":
		if _, ok := c.pending[key]; ok {
			delete(c.pending, key)
			lost++
		}
	}
	return []Event{e}, lost
}
func copyArgs(dst *Event, src Event) {
	dst.ArgvStatus, dst.ArgvRaw, dst.ArgvDisplay = src.ArgvStatus, src.ArgvRaw, src.ArgvDisplay
	dst.ArgvTruncated, dst.ArgvArgumentLimit, dst.ArgvByteLimit = src.ArgvTruncated, src.ArgvArgumentLimit, src.ArgvByteLimit
}
func (c *correlator) expire(now time.Time) uint64 {
	var lost uint64
	for key, entry := range c.pending {
		if now.Sub(entry.received) >= 30*time.Second {
			delete(c.pending, key)
			lost++
		}
	}
	return lost
}
