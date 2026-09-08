// ABOUTME: Decodes fixed-size BPF lifecycle evidence without consulting mutable procfs state.
// ABOUTME: Preserves raw names and kernel task start and exec identity as decimal strings.
package procwatch

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

const recordSize = 104
const syscallRecordSize = 400

// Identity is guest evidence, never authority to signal a host process.
// ExecGeneration is the kernel self_exec_id value, not a count of received events.
type Identity struct {
	BootID         string `json:"boot_id"`
	TGID           uint32 `json:"tgid"`
	StartNS        string `json:"process_start_monotonic_ns"`
	ExecGeneration string `json:"exec_generation"`
}
type Event struct {
	ExecToken         string          `json:"exec_transition_token,omitempty"`
	TaskStartNS       string          `json:"task_start_monotonic_ns"`
	Kind              string          `json:"-"`
	Sensor            string          `json:"sensor"`
	Evidence          string          `json:"evidence"`
	MonotonicNS       string          `json:"monotonic_ns"`
	PID               uint32          `json:"pid"`
	Process           Identity        `json:"process"`
	Parent            *Identity       `json:"parent,omitempty"`
	CommRaw           string          `json:"comm_raw_base64"`
	CommDisplay       string          `json:"comm_display"`
	TaskExit          bool            `json:"task_exit"`
	IsThread          bool            `json:"is_thread"`
	ExitWaitStatus    *uint32         `json:"exit_wait_status,omitempty"`
	OldPID            *uint32         `json:"old_pid,omitempty"`
	ArgvStatus        string          `json:"argv_status"`
	ArgvRaw           []string        `json:"argv_raw_base64,omitempty"`
	ArgvDisplay       []string        `json:"argv_display,omitempty"`
	ArgvTruncated     bool            `json:"argv_truncated"`
	ArgvArgumentLimit int             `json:"argv_argument_limit,omitempty"`
	ArgvByteLimit     int             `json:"argv_bytes_per_argument_limit,omitempty"`
	SyscallNumber     uint64          `json:"syscall_number,omitempty"`
	SyscallResult     *int64          `json:"syscall_result,omitempty"`
	Socket            *SocketEvidence `json:"socket,omitempty"`
}

func decode(b []byte, boot string) (Event, error) {
	if len(b) != recordSize && len(b) != syscallRecordSize {
		return Event{}, fmt.Errorf("process record size %d, want %d", len(b), recordSize)
	}
	u32 := func(n int) uint32 { return binary.LittleEndian.Uint32(b[n:]) }
	u64 := func(n int) string { return strconv.FormatUint(binary.LittleEndian.Uint64(b[n:]), 10) }
	kinds := map[uint32]string{1: "proc.fork", 2: "proc.exec", 3: "proc.exit", 4: "proc.exec_attempt", 5: "proc.exec_result", 6: "socket.connect_attempt", 7: "socket.connect_result"}
	kind, ok := kinds[u32(0)]
	if !ok {
		return Event{}, fmt.Errorf("unknown process record kind %d", u32(0))
	}
	if (u32(0) > 3) != (len(b) == syscallRecordSize) {
		return Event{}, fmt.Errorf("record kind and size disagree")
	}
	if u32(4) != 0 || u32(84) != 0 {
		return Event{}, fmt.Errorf("incomplete kernel identity read")
	}
	if boot == "" || len(boot) > 128 || u32(16) == 0 || u32(20) == 0 || binary.LittleEndian.Uint64(b[24:]) == 0 {
		return Event{}, fmt.Errorf("missing process lifetime identity")
	}
	comm := b[64:80]
	if n := bytes.IndexByte(comm, 0); n >= 0 {
		comm = comm[:n]
	}
	e := Event{Kind: kind, Sensor: "process", Evidence: "bpf_raw_tracepoint", MonotonicNS: u64(8), PID: u32(16), Process: Identity{boot, u32(20), u64(24), u64(32)}, CommRaw: base64.StdEncoding.EncodeToString(comm), CommDisplay: strings.ToValidUTF8(string(comm), "�"), IsThread: u32(16) != u32(20), ArgvStatus: "not_captured"}
	if len(b) == recordSize && u32(40) != 0 && binary.LittleEndian.Uint64(b[48:]) != 0 {
		e.Parent = &Identity{boot, u32(40), u64(48), u64(56)}
	}
	if kind == "proc.exit" {
		v := u32(44)
		e.ExitWaitStatus = &v
		e.TaskExit = true
	}
	if kind == "proc.exec" {
		v := u32(80)
		e.OldPID = &v
	}
	if len(b) == recordSize {
		e.TaskStartNS = u64(88)
		e.ExecToken = u64(96)
	}
	if len(b) == syscallRecordSize {
		return decodeSyscall(e, b)
	}
	return e, nil
}
