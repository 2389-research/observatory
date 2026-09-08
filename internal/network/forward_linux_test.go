// ABOUTME: Pins rtnetlink forwarding messages, bounded ACK handling and namespace scope.
// ABOUTME: The opt-in kernel test creates an isolated child namespace before any mutation.
package network

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestForwardingRequestHasOnlyExactInterfaceSetting(t *testing.T) {
	request, err := forwardingRequest(42, 7, 123)
	if err != nil {
		t.Fatal(err)
	}
	if len(request) != 52 {
		t.Fatalf("request size=%d want 52", len(request))
	}
	if binary.NativeEndian.Uint32(request) != 52 || binary.NativeEndian.Uint16(request[4:]) != unix.RTM_NEWLINK || binary.NativeEndian.Uint16(request[6:]) != unix.NLM_F_REQUEST|unix.NLM_F_ACK || binary.NativeEndian.Uint32(request[8:]) != 7 || binary.NativeEndian.Uint32(request[12:]) != 123 {
		t.Fatalf("wrong netlink header: %x", request[:16])
	}
	if request[16] != unix.AF_UNSPEC || !bytes.Equal(request[17:20], make([]byte, 3)) || binary.NativeEndian.Uint32(request[20:]) != 42 || !bytes.Equal(request[24:32], make([]byte, 8)) {
		t.Fatalf("changed link flags or identity: %x", request[16:32])
	}
	for _, a := range []struct {
		offset, length int
		kind           uint16
	}{{32, 20, unix.IFLA_AF_SPEC | unix.NLA_F_NESTED}, {36, 16, unix.AF_INET | unix.NLA_F_NESTED}, {40, 12, unix.IFLA_INET_CONF | unix.NLA_F_NESTED}, {44, 8, 1}} {
		if binary.NativeEndian.Uint16(request[a.offset:]) != uint16(a.length) || binary.NativeEndian.Uint16(request[a.offset+2:]) != a.kind {
			t.Fatalf("wrong attribute at %d: %x", a.offset, request[a.offset:])
		}
	}
	if binary.NativeEndian.Uint32(request[48:]) != 1 {
		t.Fatal("forwarding value is not 1")
	}
}
func TestForwardingRejectsInvalidIndexAndCanceledContext(t *testing.T) {
	for _, index := range []int{-1, 0, math.MaxInt32 + 1} {
		if _, err := forwardingRequest(index, 1, 1); err == nil {
			t.Fatalf("accepted index %d", index)
		}
		if err := EnableIPv4Forwarding(t.Context(), index); err == nil {
			t.Fatalf("enabled index %d", index)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := EnableIPv4Forwarding(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled request: %v", err)
	}
}
func forwardingAck(request []byte, errno int32) []byte {
	b := make([]byte, 36)
	binary.NativeEndian.PutUint32(b, uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], unix.NLMSG_ERROR)
	binary.NativeEndian.PutUint16(b[6:], unix.NLM_F_CAPPED)
	copy(b[8:16], request[8:16])
	binary.NativeEndian.PutUint32(b[16:], uint32(errno))
	copy(b[20:], request[:16])
	return b
}
func TestForwardingAckRequiresKernelIdentityAndOriginalRequest(t *testing.T) {
	request := make([]byte, 52)
	binary.NativeEndian.PutUint32(request, 52)
	binary.NativeEndian.PutUint16(request[4:], unix.RTM_NEWLINK)
	binary.NativeEndian.PutUint16(request[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(request[8:], 7)
	binary.NativeEndian.PutUint32(request[12:], 123)
	ack := forwardingAck(request, 0)
	if err := validateForwardingAck(ack, request, 0, 0); err != nil {
		t.Fatalf("kernel ACK rejected: %v", err)
	}
	if err := validateForwardingAck(forwardingAck(request, -int32(unix.EPERM)), request, 0, 0); !errors.Is(err, unix.EPERM) {
		t.Fatalf("kernel rejection lost: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func([]byte)
		sender uint32
		flags  int
	}{
		{name: "userspace_sender", sender: 123}, {name: "truncated", flags: unix.MSG_TRUNC},
		{name: "sequence", change: func(b []byte) { binary.NativeEndian.PutUint32(b[8:], 8) }},
		{name: "recipient", change: func(b []byte) { binary.NativeEndian.PutUint32(b[12:], 0) }},
		{name: "message_type", change: func(b []byte) { binary.NativeEndian.PutUint16(b[4:], unix.RTM_NEWLINK) }},
		{name: "original_request", change: func(b []byte) { binary.NativeEndian.PutUint16(b[24:], unix.RTM_DELLINK) }},
		{name: "wrong_length", change: func(b []byte) { binary.NativeEndian.PutUint32(b, 65535) }},
		{name: "positive_errno", change: func(b []byte) { binary.NativeEndian.PutUint32(b[16:], 1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := bytes.Clone(ack)
			if tc.change != nil {
				tc.change(b)
			}
			if err := validateForwardingAck(b, request, tc.sender, tc.flags); err == nil {
				t.Fatal("accepted unverified ACK")
			}
		})
	}
	for n := 0; n < len(ack); n++ {
		if err := validateForwardingAck(ack[:n], request, 0, 0); err == nil {
			t.Fatalf("accepted short ACK %d", n)
		}
	}
}
func TestForwardingAckWaitHonorsDeadlineWithoutTraffic(t *testing.T) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = receiveForwardingAck(ctx, fd, make([]byte, 52))
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("ACK wait did not honor deadline: %v", err)
	}
}

func TestIPv4ForwardingInIsolatedNamespace(t *testing.T) {
	if os.Getenv("VMOBS_NETNS_TEST") != "1" {
		t.Skip("set VMOBS_NETNS_TEST=1 with namespace creation and NET_ADMIN capabilities")
	}
	if os.Getenv("VMOBS_FORWARD_CHILD") == "1" {
		testForwardingChild(t)
		return
	}
	parentNamespace, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	parentValue := readForwardingFile(t, "/proc/sys/net/ipv4/conf/lo/forwarding")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestIPv4ForwardingInIsolatedNamespace$", "-test.v")
	command.Env = append(os.Environ(), "VMOBS_FORWARD_CHILD=1")
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("explicit namespace gate failed (requires namespace creation and NET_ADMIN): %v\n%s", err, out)
	}
	now, err := os.Readlink("/proc/self/ns/net")
	if err != nil || now != parentNamespace {
		t.Fatalf("parent namespace changed: %q %v", now, err)
	}
	if got := readForwardingFile(t, "/proc/sys/net/ipv4/conf/lo/forwarding"); got != parentValue {
		t.Fatal("parent interface was modified")
	}
	t.Logf("isolated child: %s", out)
}
func readForwardingFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}
func testForwardingChild(t *testing.T) {
	t.Helper()
	own, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	parent, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", os.Getppid()))
	if err != nil || parent == own {
		t.Fatalf("refusing mutation without distinct child namespace: %s %s %v", own, parent, err)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatalf("refusing mutation outside empty fixture namespace: %+v", interfaces)
	}
	all := readForwardingFile(t, "/proc/sys/net/ipv4/conf/all/forwarding")
	defaults := readForwardingFile(t, "/proc/sys/net/ipv4/conf/default/forwarding")
	clearFixtureForwarding(t, interfaces[0].Index)
	if value := readForwardingFile(t, "/proc/sys/net/ipv4/conf/lo/forwarding"); value != "0" {
		t.Fatalf("fresh fixture already forwarding: %s", value)
	}
	for i := 0; i < 2; i++ {
		if err := EnableIPv4Forwarding(t.Context(), interfaces[0].Index); err != nil {
			t.Fatal(err)
		}
	}
	if value := readForwardingFile(t, "/proc/sys/net/ipv4/conf/lo/forwarding"); value != "1" {
		t.Fatalf("kernel did not enable interface forwarding: %s", value)
	}
	if readForwardingFile(t, "/proc/sys/net/ipv4/conf/all/forwarding") != all || readForwardingFile(t, "/proc/sys/net/ipv4/conf/default/forwarding") != defaults {
		t.Fatal("global/default forwarding changed")
	}
	if err := EnableIPv4Forwarding(t.Context(), math.MaxInt32); !errors.Is(err, unix.ENODEV) {
		t.Fatalf("unknown interface did not produce ENODEV: %v", err)
	}
	t.Log("enabled only ifindex " + strconv.Itoa(interfaces[0].Index) + " in " + own)
}

// Only called after proving this is an empty child namespace. New namespaces
// may inherit forwarding=1; establish the disabled precondition explicitly.
func clearFixtureForwarding(t *testing.T, index int) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	request, err := forwardingRequest(index, 1, address.(*unix.SockaddrNetlink).Pid)
	if err != nil {
		t.Fatal(err)
	}
	binary.NativeEndian.PutUint32(request[48:], 0)
	if err := unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := receiveForwardingAck(ctx, fd, request); err != nil {
		t.Fatal(err)
	}
}
