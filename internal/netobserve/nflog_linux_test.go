// ABOUTME: Tests bounded NFLOG setup framing, ACK validation and real namespace-local packets.
// ABOUTME: Privileged coverage runs only in an explicitly selected disposable Linux container.
//go:build linux

package netobserve

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNFLogRejectsInvalidGroup(t *testing.T) {
	file, _, err := OpenNFLog(t.Context(), 0)
	if file != nil {
		_ = file.Close()
	}
	if err == nil || file != nil {
		t.Fatalf("zero NFLOG group returned file=%v error=%v", file, err)
	}
}

func TestNFLogAcquisitionCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	file, _, err := OpenNFLog(ctx, 17)
	if file != nil {
		_ = file.Close()
	}
	if !errors.Is(err, context.Canceled) || file != nil {
		t.Fatalf("canceled NFLOG acquisition returned file=%v error=%v", file, err)
	}
}

func TestNFLogExpiredAcquisition(t *testing.T) {
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	file, _, err := OpenNFLog(ctx, 17)
	if file != nil {
		_ = file.Close()
	}
	if !errors.Is(err, context.DeadlineExceeded) || file != nil {
		t.Fatalf("expired NFLOG acquisition returned file=%v error=%v", file, err)
	}
}

func TestNFLogConfigRequests(t *testing.T) {
	request := nflogSetupRequest(42, 7, 23)
	if len(request) != 48 {
		t.Fatalf("setup request length=%d want=48: %x", len(request), request)
	}
	assertNFLogHeader(t, request, 42, 7, 23)
	assertNFLogAttribute(t, request[20:28], 1, []byte{1})
	assertNFLogAttribute(t, request[28:40], 2, []byte{0, 0, 0, nfLogCopyBytes, 2, 0})
	assertNFLogAttribute(t, request[40:48], 6, []byte{0, 1})
}

func TestValidateNFLogACK(t *testing.T) {
	request := nflogSetupRequest(42, 7, 23)
	valid := nflogTestACK(request, 0, unix.NLM_F_CAPPED)
	kernel := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := validateNFLogACK(valid, request, kernel, 0); err != nil {
		t.Fatalf("valid ACK rejected: %v", err)
	}

	tests := []struct {
		name   string
		data   []byte
		from   *unix.SockaddrNetlink
		flags  int
		mutate func([]byte)
	}{
		{name: "userspace sender", data: valid, from: &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 9}},
		{name: "multicast sender", data: valid, from: &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 1}},
		{name: "truncated", data: valid, from: kernel, flags: unix.MSG_TRUNC},
		{name: "control truncated", data: valid, from: kernel, flags: unix.MSG_CTRUNC},
		{name: "short", data: valid[:35], from: kernel},
		{name: "framing mismatch", data: valid, from: kernel, mutate: func(b []byte) { binary.NativeEndian.PutUint32(b, uint32(len(b)-4)) }},
		{name: "packet before ACK", data: valid, from: kernel, mutate: func(b []byte) { binary.NativeEndian.PutUint16(b[4:], 0x400) }},
		{name: "wrong sequence", data: valid, from: kernel, mutate: func(b []byte) { binary.NativeEndian.PutUint32(b[8:], 8) }},
		{name: "wrong response port", data: valid, from: kernel, mutate: func(b []byte) { binary.NativeEndian.PutUint32(b[12:], 24) }},
		{name: "wrong original header", data: valid, from: kernel, mutate: func(b []byte) { binary.NativeEndian.PutUint16(b[24:], 0x402) }},
		{name: "positive errno", data: valid, from: kernel, mutate: func(b []byte) { binary.NativeEndian.PutUint32(b[16:], 1) }},
		{name: "unexpected ACK flags", data: valid, from: kernel, mutate: func(b []byte) { binary.NativeEndian.PutUint16(b[6:], unix.NLM_F_CAPPED|unix.NLM_F_MULTI) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := append([]byte(nil), tc.data...)
			if tc.mutate != nil {
				tc.mutate(data)
			}
			if err := validateNFLogACK(data, request, tc.from, tc.flags); err == nil {
				t.Fatal("malformed or untrusted ACK accepted")
			}
		})
	}

	rejected := nflogTestACK(request, -int32(unix.EBUSY), unix.NLM_F_CAPPED)
	if err := validateNFLogACK(rejected, request, kernel, 0); !errors.Is(err, unix.EBUSY) {
		t.Fatalf("kernel errno not retained: %v", err)
	}
}

func TestRealNFLogAcquisition(t *testing.T) {
	if os.Getenv("VMOBS_NFLOG_ACQUISITION_TEST") != "1" {
		t.Skip("explicit disposable privileged Linux container required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("privileged acquisition requires root inside disposable container")
	}
	if os.Getenv("VMOBS_NFLOG_ACQUISITION_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRealNFLogAcquisition$", "-test.v")
		cmd.Env = append(os.Environ(), "VMOBS_NFLOG_ACQUISITION_CHILD=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated NFLOG acquisition: %v\n%s", err, out)
		} else {
			t.Logf("%s", out)
		}
		return
	}

	assertFreshLoopbackNamespace(t)
	runNFLogCommand(t, "ip", "link", "set", "lo", "up")

	const group = uint16(321)
	file, info, err := OpenNFLog(t.Context(), group)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	assertNFLogSocket(t, file, info, group)

	conflict, _, err := OpenNFLog(t.Context(), group)
	if conflict != nil {
		_ = conflict.Close()
	}
	if err == nil || conflict != nil {
		t.Fatalf("second owner acquired group %d: file=%v error=%v", group, conflict, err)
	}

	const destinationPort = 46321
	installNFLogDropRule(t, group, destinationPort)
	connection, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: destinationPort})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	sourcePort := connection.LocalAddr().(*net.UDPAddr).Port
	if _, err := connection.Write([]byte("bounded NFLOG proof")); err != nil && !errors.Is(err, unix.EPERM) {
		t.Fatal(err)
	}

	denial := readNFLogDenial(t, file, info)
	if denial.Group != group || denial.Prefix != "vmobs-denied" || denial.Sequence == nil {
		t.Fatalf("wrong NFLOG identity: %+v", denial)
	}
	if denial.Tuple == nil || denial.Tuple.Source.String() != "127.0.0.1" || denial.Tuple.Destination.String() != "127.0.0.1" || denial.Tuple.Protocol == nil || *denial.Tuple.Protocol != unix.IPPROTO_UDP || denial.Tuple.SourcePort == nil || *denial.Tuple.SourcePort != uint16(sourcePort) || denial.Tuple.DestinationPort == nil || *denial.Tuple.DestinationPort != destinationPort {
		t.Fatalf("wrong NFLOG tuple: %+v", denial.Tuple)
	}
	if denial.CapturedLength > nfLogCopyBytes {
		t.Fatalf("copied %d bytes, cap is %d", denial.CapturedLength, nfLogCopyBytes)
	}

	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	replacement, replacementInfo, err := OpenNFLog(t.Context(), group)
	if err != nil {
		t.Fatalf("group remained owned after close: %v", err)
	}
	defer replacement.Close()
	assertNFLogSocket(t, replacement, replacementInfo, group)
	t.Logf("isolated child group=%d prefix=%q seq=%d tuple=%s:%d>%s:%d copy=%d", group, denial.Prefix, *denial.Sequence, denial.Tuple.Source, *denial.Tuple.SourcePort, denial.Tuple.Destination, *denial.Tuple.DestinationPort, denial.CapturedLength)
}

func assertNFLogHeader(t *testing.T, request []byte, group uint16, sequence, port uint32) {
	t.Helper()
	if binary.NativeEndian.Uint32(request) != uint32(len(request)) || binary.NativeEndian.Uint16(request[4:]) != 0x401 || binary.NativeEndian.Uint16(request[6:]) != unix.NLM_F_REQUEST|unix.NLM_F_ACK || binary.NativeEndian.Uint32(request[8:]) != sequence || binary.NativeEndian.Uint32(request[12:]) != port || request[16] != unix.AF_UNSPEC || request[17] != 0 || binary.BigEndian.Uint16(request[18:]) != group {
		t.Fatalf("invalid NFLOG request header: %x", request)
	}
}

func assertNFLogAttribute(t *testing.T, attribute []byte, kind uint16, value []byte) {
	t.Helper()
	if len(attribute) < 4 || binary.NativeEndian.Uint16(attribute) != uint16(4+len(value)) || binary.NativeEndian.Uint16(attribute[2:]) != kind || !bytes.Equal(attribute[4:4+len(value)], value) {
		t.Fatalf("invalid NFLOG attribute kind=%d value=%x: %x", kind, value, attribute)
	}
}

func nflogTestACK(request []byte, code int32, flags uint16) []byte {
	b := make([]byte, 36)
	binary.NativeEndian.PutUint32(b, uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], unix.NLMSG_ERROR)
	binary.NativeEndian.PutUint16(b[6:], flags)
	copy(b[8:16], request[8:16])
	binary.NativeEndian.PutUint32(b[16:], uint32(code))
	copy(b[20:], request[:16])
	return b
}

func assertFreshLoopbackNamespace(t *testing.T) {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(interfaces) != 1 || interfaces[0].Name != "lo" || interfaces[0].Flags&net.FlagLoopback == 0 {
		t.Fatalf("privileged test did not start in fresh loopback-only child namespace: %+v", interfaces)
	}
}

func runNFLogCommand(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.CommandContext(t.Context(), name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

func installNFLogDropRule(t *testing.T, group uint16, port int) {
	t.Helper()
	script := fmt.Sprintf("table ip vmobs_nflog_test {\n chain output {\n  type filter hook output priority 0; policy accept;\n  ip daddr 127.0.0.1 udp dport %d log prefix \"vmobs-denied\" group %d snaplen %d queue-threshold 1 drop\n }\n}\n", port, group, nfLogCopyBytes)
	cmd := exec.CommandContext(t.Context(), "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install isolated NFLOG rule: %v\n%s\n%s", err, out, script)
	}
}

func assertNFLogSocket(t *testing.T, file *os.File, info NFLogSocketInfo, group uint16) {
	t.Helper()
	fd := int(file.Fd())
	address, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	nl, ok := address.(*unix.SockaddrNetlink)
	if !ok || nl.Groups != 0 || nl.Pid != info.PortID || info.Group != group {
		t.Fatalf("wrong NFLOG socket binding: address=%+v info=%+v", address, info)
	}
	fdFlags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	if err != nil || fdFlags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("socket leaked across exec: flags=%d err=%v", fdFlags, err)
	}
	statusFlags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil || statusFlags&unix.O_NONBLOCK == 0 {
		t.Fatalf("socket blocks: flags=%d err=%v", statusFlags, err)
	}
	receiveBuffer, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	if err != nil || receiveBuffer > 2*nfLogReceiveBufferBytes {
		t.Fatalf("unbounded receive buffer: bytes=%d err=%v", receiveBuffer, err)
	}
}

func readNFLogDenial(t *testing.T, file *os.File, info NFLogSocketInfo) Denial {
	t.Helper()
	buffer := make([]byte, 4096)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, _, flags, address, err := unix.Recvmsg(int(file.Fd()), buffer, nil, unix.MSG_DONTWAIT)
		if err == unix.EAGAIN || err == unix.EINTR {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		sender, ok := address.(*unix.SockaddrNetlink)
		if !ok || sender.Pid != 0 || sender.Groups != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			t.Fatalf("untrusted NFLOG datagram: sender=%+v flags=%d", address, flags)
		}
		records, err := ParseNFLog(buffer[:n])
		if err != nil {
			t.Fatal(err)
		}
		for _, record := range records {
			if record.Group == info.Group {
				return record
			}
		}
	}
	t.Fatal("timed out waiting for real NFLOG packet")
	return Denial{}
}
