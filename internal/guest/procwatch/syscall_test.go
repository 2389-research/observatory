// ABOUTME: Checks syscall evidence decoding and bounded correlation across process generations.
// ABOUTME: Synthetic wire bytes exercise the parser without mocking kernel or transport behavior.
package procwatch

import (
	"encoding/binary"
	"encoding/json"
	"strconv"
	"testing"
	"time"
)

func syscallSample(kind uint32) []byte {
	b := make([]byte, 400)
	copy(b, sampleRecord())
	binary.LittleEndian.PutUint32(b, kind)
	binary.LittleEndian.PutUint64(b[88:], 59)
	binary.LittleEndian.PutUint64(b[40:], 100)
	binary.LittleEndian.PutUint64(b[48:], 19)
	binary.LittleEndian.PutUint32(b[104:], 2)
	binary.LittleEndian.PutUint32(b[112:], 8)
	copy(b[144:], "/bin/sh")
	binary.LittleEndian.PutUint32(b[116:], 3)
	copy(b[208:], "-c")
	return b
}
func TestDecodeBoundedExecArguments(t *testing.T) {
	e, err := decode(syscallSample(4), "boot")
	if err != nil {
		t.Fatalf("exec entry must decode: %v", err)
	}
	data, _ := json.Marshal(e)
	var fields map[string]any
	_ = json.Unmarshal(data, &fields)
	if fields["argv_status"] != "captured" {
		t.Fatalf("missing bounded argv: %s", data)
	}
	argv, ok := fields["argv_display"].([]any)
	if !ok || len(argv) != 2 || argv[0] != "/bin/sh" || argv[1] != "-c" {
		t.Fatalf("argv: %s", data)
	}
}

func TestExecCorrelationRequiresExactLifetimeAndGeneration(t *testing.T) {
	for _, field := range []string{"matching", "start", "generation", "boot"} {
		t.Run(field, func(t *testing.T) {
			var c correlator
			now := time.Now()
			entry, _ := decode(syscallSample(4), "boot")
			c.consume(entry, now)
			execution, _ := decode(sampleRecord(), "boot")
			execution.Process.ExecGeneration = "8"
			switch field {
			case "start":
				execution.Process.StartNS = "200"
			case "generation":
				execution.Process.ExecGeneration = "9"
			case "boot":
				execution.Process.BootID = "other"
			}
			pid := execution.PID
			execution.OldPID = &pid
			got, _ := c.consume(execution, now)
			if (len(got[0].ArgvDisplay) == 2) != (field == "matching") {
				t.Fatalf("incorrect correlation: %+v", got)
			}
		})
	}
}
func TestPendingExecCannotBecomeSuccessfulOnFailedReturn(t *testing.T) {
	var c correlator
	entry, _ := decode(syscallSample(4), "boot")
	c.consume(entry, time.Now())
	result := entry
	result.Kind = "proc.exec_result"
	ret := int64(-2)
	result.SyscallResult = &ret
	result.ArgvDisplay = nil
	got, lost := c.consume(result, time.Now())
	if len(got) != 1 || got[0].Kind != "proc.exec_failed" || len(got[0].ArgvDisplay) != 2 || lost != 0 {
		t.Fatalf("failed exec: %+v lost=%d", got, lost)
	}
	if len(c.pending) != 0 {
		t.Fatal("pending exec retained after return")
	}
}
func TestPendingCorrelationsBoundedAndExpire(t *testing.T) {
	var c correlator
	now := time.Now()
	entry, _ := decode(syscallSample(4), "boot")
	var lost uint64
	for i := 0; i < 1100; i++ {
		entry.PID = uint32(i + 1)
		_, n := c.consume(entry, now)
		lost += n
	}
	if len(c.pending) != 1024 || lost != 76 {
		t.Fatalf("unbounded state entries=%d lost=%d", len(c.pending), lost)
	}
	if n := c.expire(now.Add(30 * time.Second)); n != 1024 || len(c.pending) != 0 {
		t.Fatalf("expiry=%d pending=%d", n, len(c.pending))
	}
}

func TestSyscallResultDoesNotBorrowDifferentSyscallArguments(t *testing.T) {
	var c correlator
	entry, _ := decode(syscallSample(4), "boot")
	c.consume(entry, time.Now())
	result := entry
	result.Kind = "proc.exec_result"
	result.SyscallNumber = 322
	ret := int64(-2)
	result.SyscallResult = &ret
	result.ArgvDisplay = nil
	result.ArgvRaw = nil
	result.ArgvStatus = "not_captured"
	got, _ := c.consume(result, time.Now())
	if got[0].ArgvStatus != "entry_not_observed" || len(got[0].ArgvDisplay) != 0 {
		t.Fatalf("cross-syscall attribution: %+v", got)
	}
}
func TestConnectDecodePreservesUnknownSocketIdentity(t *testing.T) {
	b := syscallSample(6)
	binary.LittleEndian.PutUint64(b[88:], 42)
	binary.LittleEndian.PutUint32(b[128:], 7)
	binary.LittleEndian.PutUint32(b[132:], 16)
	binary.LittleEndian.PutUint32(b[136:], 4026531992)
	copy(b[144:], []byte{2, 0, 0x1f, 0x90, 192, 0, 2, 5})
	e, err := decode(b, "boot")
	if err != nil {
		t.Fatal(err)
	}
	if e.Socket == nil || e.Socket.Destination != "192.0.2.5" || e.Socket.Port != 8080 || e.Socket.LifetimeStatus != "unknown" || e.Socket.HostFlowAttribution != "unknown" {
		t.Fatalf("socket: %+v", e)
	}
}
func TestArgvTruncationAndReadFailureRemainExplicit(t *testing.T) {
	b := syscallSample(4)
	binary.LittleEndian.PutUint32(b[108:], 3)
	e, err := decode(b, "boot")
	if err != nil {
		t.Fatal(err)
	}
	if !e.ArgvTruncated || e.ArgvStatus != "partial_read_failure" {
		t.Fatalf("argv status: %+v", e)
	}
}

func TestReusedThreadIDDoesNotBorrowPendingArguments(t *testing.T) {
	var c correlator
	b := syscallSample(4)
	binary.LittleEndian.PutUint64(b[40:], 501)
	entry, _ := decode(b, "boot")
	c.consume(entry, time.Now())
	binary.LittleEndian.PutUint32(b, 5)
	binary.LittleEndian.PutUint64(b[40:], 502)
	ret := int64(-2)
	binary.LittleEndian.PutUint64(b[96:], uint64(ret))
	result, _ := decode(b, "boot")
	got, _ := c.consume(result, time.Now())
	if got[0].ArgvStatus != "entry_not_observed" || len(got[0].ArgvDisplay) != 0 {
		t.Fatalf("reused thread borrowed old argv: %+v", got)
	}
}

func TestSyscallKindMustMatchOperation(t *testing.T) {
	b := syscallSample(4)
	binary.LittleEndian.PutUint64(b[88:], 42)
	if _, err := decode(b, "boot"); err == nil {
		t.Fatal("connect decoded as an exec attempt")
	}
}
func TestMissingThreadLifetimeIsRejected(t *testing.T) {
	b := syscallSample(4)
	binary.LittleEndian.PutUint64(b[40:], 0)
	if _, err := decode(b, "boot"); err == nil {
		t.Fatal("accepted missing task lifetime")
	}
}

func TestNonleaderExecRequiresKernelTransitionToken(t *testing.T) {
	for _, token := range []uint64{0, 19, 20} {
		t.Run(strconv.FormatUint(token, 10), func(t *testing.T) {
			var c correlator
			b := syscallSample(4)
			binary.LittleEndian.PutUint32(b[16:], 43)
			binary.LittleEndian.PutUint64(b[40:], 501)
			binary.LittleEndian.PutUint64(b[48:], 19)
			entry, _ := decode(b, "boot")
			c.consume(entry, time.Now())
			b = sampleRecord()
			binary.LittleEndian.PutUint64(b[32:], 8)
			binary.LittleEndian.PutUint32(b[80:], 43)
			execution, _ := decode(b, "boot")
			// JSON sets the declared wire-derived token without changing unrelated process identity.
			data, _ := json.Marshal(execution)
			var fields map[string]any
			_ = json.Unmarshal(data, &fields)
			fields["exec_transition_token"] = strconv.FormatUint(token, 10)
			data, _ = json.Marshal(fields)
			_ = json.Unmarshal(data, &execution)
			execution.Kind = "proc.exec"
			got, _ := c.consume(execution, time.Now())
			if (len(got[0].ArgvDisplay) == 2) != (token == 19) {
				t.Fatalf("unsafe or missing nonleader match token=%d: %+v", token, got)
			}
		})
	}
}
