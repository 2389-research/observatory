// ABOUTME: Verifies forwarding and conntrack accounting under the shipped container boundary.
// ABOUTME: All mutations and traffic stay in an unnamed child network namespace that dies on exit.

//go:build linux

package integration_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/netobserve"
	"github.com/2389-research/observatory/internal/network"
	"golang.org/x/sys/unix"
)

// Run the compiled test as root inside the gate container, retaining the shipped
// vmobs-jailer AppArmor/seccomp profiles and capabilities. The ordinary gate UID
// cannot acquire NET_ADMIN; do not add sudo grants or run this on the host.
func TestNetworkBoundaryPrimitivesGate(t *testing.T) {
	if os.Getenv("VMOBS_NETWORK_BOUNDARY_GATE") != "1" {
		t.Skip("explicit confined root gate: VMOBS_NETWORK_BOUNDARY_GATE=1")
	}
	boundaryConfinement(t)
	if os.Getenv("VMOBS_NETWORK_BOUNDARY_CHILD") == "1" {
		boundaryChild(t)
		return
	}
	before := boundaryParentState(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNetworkBoundaryPrimitivesGate$", "-test.v")
	command.Env = append(os.Environ(), "VMOBS_NETWORK_BOUNDARY_CHILD=1")
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated network boundary gate: %v\n%s", err, output)
	}
	if after := boundaryParentState(t); after != before {
		t.Fatalf("parent namespace/settings changed: before=%q after=%q", before, after)
	}
	t.Logf("confined child result:\n%s", output)
}

func boundaryConfinement(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("explicit gate requires root inside the shipped gate container")
	}
	profile := boundaryRead(t, "/proc/self/attr/current")
	if profile != "vmobs-jailer (enforce)" {
		t.Fatalf("refusing non-shipped AppArmor profile: %q", profile)
	}
	status := boundaryRead(t, "/proc/self/status")
	if !strings.Contains(status, "Seccomp:\t2") {
		t.Fatal("refusing execution without seccomp filtering")
	}
	t.Logf("boundary: AppArmor=%s seccomp=filter uid=%d", profile, os.Geteuid())
}

func boundaryRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}
func boundaryNamespace(t *testing.T, pid string) string {
	t.Helper()
	value, err := os.Readlink("/proc/" + pid + "/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func boundaryParentState(t *testing.T) string {
	t.Helper()
	result := boundaryNamespace(t, "self")
	for _, name := range []string{"all", "default", "lo"} {
		result += "|" + name + "=" + boundaryRead(t, "/proc/sys/net/ipv4/conf/"+name+"/forwarding")
	}
	// Conntrack may not yet be loaded in the parent. Record absence as well.
	data, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_acct")
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return result + "|acct=" + string(data)
}
func boundaryCommand(t *testing.T, input, name string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = strings.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, output)
	}
	return output
}

func boundaryChild(t *testing.T) {
	t.Helper()
	own := boundaryNamespace(t, "self")
	if own == boundaryNamespace(t, strconv.Itoa(os.Getppid())) {
		t.Fatal("refusing mutation in parent's network namespace")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatalf("refusing mutation in nonempty namespace: %+v", interfaces)
	}
	all := boundaryRead(t, "/proc/sys/net/ipv4/conf/all/forwarding")
	defaults := boundaryRead(t, "/proc/sys/net/ipv4/conf/default/forwarding")
	loopback := boundaryRead(t, "/proc/sys/net/ipv4/conf/lo/forwarding")
	boundaryCommand(t, "", "ip", "link", "add", "boundary0", "type", "dummy")
	device, err := net.InterfaceByName("boundary0")
	if err != nil {
		t.Fatal(err)
	}
	boundaryDisableForwarding(t, device.Index)
	if value := boundaryRead(t, "/proc/sys/net/ipv4/conf/boundary0/forwarding"); value != "0" {
		t.Fatalf("disabled fixture forwarding=%q", value)
	}
	if err := network.EnableIPv4Forwarding(t.Context(), device.Index); err != nil {
		t.Fatal(err)
	}
	if value := boundaryRead(t, "/proc/sys/net/ipv4/conf/boundary0/forwarding"); value != "1" {
		t.Fatalf("enabled fixture forwarding=%q", value)
	}
	if boundaryRead(t, "/proc/sys/net/ipv4/conf/all/forwarding") != all || boundaryRead(t, "/proc/sys/net/ipv4/conf/default/forwarding") != defaults || boundaryRead(t, "/proc/sys/net/ipv4/conf/lo/forwarding") != loopback {
		t.Fatal("forwarding modified another interface or namespace defaults")
	}
	boundaryCommand(t, "", "ip", "link", "set", "lo", "up")
	// Initialize conntrack without requesting accounting. Existing host/default
	// policy is never consulted or altered: this table exists only in this child.
	boundaryCommand(t, `table ip vmobs_primitive {
 counter blocked {
 }
 chain output {
  type filter hook output priority 0; policy accept;
  ct state invalid counter
 }
}
`, "nft", "-f", "-")
	if value := boundaryRead(t, "/proc/sys/net/netfilter/nf_conntrack_acct"); value != "0" {
		t.Fatalf("fresh child accounting must start disabled, got %q", value)
	}
	denied, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Close()
	deniedPort := denied.LocalAddr().(*net.UDPAddr).Port
	boundaryCommand(t, fmt.Sprintf("add rule ip vmobs_primitive output udp dport %d counter name blocked drop\n", deniedPort), "nft", "-f", "-")
	boundaryDenied(t, denied)
	before := boundaryDropCount(t)
	if before == 0 {
		t.Fatal("denied fixture traffic did not hit the drop rule")
	}
	// nft_ct_get_init enables accounting in this namespace when a bytes/packets
	// expression is installed. This rule has no terminal verdict.
	boundaryCommand(t, "add rule ip vmobs_primitive output ct bytes > 0 counter\n", "nft", "-f", "-")
	if value := boundaryRead(t, "/proc/sys/net/netfilter/nf_conntrack_acct"); value != "1" {
		t.Fatalf("ct bytes expression did not enable accounting: %q", value)
	}
	tcpPort, udpPort := boundaryTraffic(t)
	flows := boundaryConntrack(t)
	for _, expected := range []struct {
		protocol uint8
		port     int
	}{{6, tcpPort}, {17, udpPort}} {
		found := false
		for _, flow := range flows {
			tuple := flow.Original
			if tuple == nil || tuple.Protocol == nil || *tuple.Protocol != expected.protocol || tuple.DestinationPort == nil || int(*tuple.DestinationPort) != expected.port {
				continue
			}
			for _, counter := range []netobserve.Counters{flow.OriginalCounters, flow.ReplyCounters} {
				if counter.Bytes == nil || counter.Packets == nil || *counter.Bytes == 0 || *counter.Packets == 0 {
					t.Fatalf("protocol %d missing real bidirectional counters: %+v", expected.protocol, flow)
				}
			}
			found = true
			t.Logf("protocol=%d original packets=%d bytes=%d reply packets=%d bytes=%d", expected.protocol, *flow.OriginalCounters.Packets, *flow.OriginalCounters.Bytes, *flow.ReplyCounters.Packets, *flow.ReplyCounters.Bytes)
		}
		if !found {
			t.Fatalf("no accounted flow for protocol=%d port=%d", expected.protocol, expected.port)
		}
	}
	boundaryDenied(t, denied)
	if after := boundaryDropCount(t); after <= before {
		t.Fatalf("accounting bypassed denial: counter before=%d after=%d", before, after)
	}
	t.Logf("namespace=%s interface=%d forwarding 0->1; accounting 0->1; TCP/UDP counters and denial before/after verified", own, device.Index)
}

// Fixture-only raw SET establishes zero even when namespace defaults enable
// forwarding. The fixed UAPI shape is independent of the production encoder.
func boundaryDisableForwarding(t *testing.T, index int) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2}); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 52)
	binary.NativeEndian.PutUint32(b, 52)
	binary.NativeEndian.PutUint16(b[4:], unix.RTM_NEWLINK)
	binary.NativeEndian.PutUint16(b[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(b[8:], 1)
	binary.NativeEndian.PutUint32(b[20:], uint32(index))
	for _, a := range []struct {
		offset, length int
		kind           uint16
	}{{32, 20, unix.IFLA_AF_SPEC | unix.NLA_F_NESTED}, {36, 16, unix.AF_INET | unix.NLA_F_NESTED}, {40, 12, unix.IFLA_INET_CONF | unix.NLA_F_NESTED}, {44, 8, 1}} {
		binary.NativeEndian.PutUint16(b[a.offset:], uint16(a.length))
		binary.NativeEndian.PutUint16(b[a.offset+2:], a.kind)
	}
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	ack := make([]byte, 4096)
	n, _, flags, from, err := unix.Recvmsg(fd, ack, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	sender, ok := from.(*unix.SockaddrNetlink)
	if !ok || sender.Pid != 0 || flags&unix.MSG_TRUNC != 0 || n < 36 || binary.NativeEndian.Uint16(ack[4:]) != unix.NLMSG_ERROR || binary.NativeEndian.Uint32(ack[8:]) != 1 || binary.NativeEndian.Uint32(ack[16:]) != 0 {
		t.Fatalf("fixture forwarding SET rejected: %x", ack[:n])
	}
}

func boundaryDenied(t *testing.T, listener *net.UDPConn) {
	t.Helper()
	connection, err := net.DialTimeout("udp4", listener.LocalAddr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// A local OUTPUT drop can return EPERM to sendmsg. The receiver timeout
	// and the owned drop counter below remain the evidence of enforcement.
	if _, err := connection.Write([]byte("must be denied")); err != nil && !errors.Is(err, unix.EPERM) {
		t.Fatal(err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	_, _, err = listener.ReadFromUDP(buffer)
	if e, ok := err.(net.Error); !ok || !e.Timeout() {
		t.Fatalf("denied datagram reached listener or failed unexpectedly: %v", err)
	}
}
func boundaryDropCount(t *testing.T) uint64 {
	t.Helper()
	data := boundaryCommand(t, "", "nft", "-j", "list", "counter", "ip", "vmobs_primitive", "blocked")
	var result struct {
		Nftables []struct {
			Counter *struct {
				Name    string
				Packets uint64
			}
		}
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	for _, entry := range result.Nftables {
		if entry.Counter != nil && entry.Counter.Name == "blocked" {
			return entry.Counter.Packets
		}
	}
	t.Fatal("nft did not return the owned denial counter")
	return 0
}

func boundaryTraffic(t *testing.T) (int, int) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() {
		connection, err := listener.AcceptTCP()
		if err != nil {
			finished <- err
			return
		}
		defer connection.Close()
		if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
			finished <- err
			return
		}
		payload := make([]byte, 4)
		_, err = io.ReadFull(connection, payload)
		if err == nil {
			_, err = connection.Write(payload)
		}
		finished <- err
	}()
	client, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, []byte("ping")) {
		t.Fatal("TCP echo mismatch")
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if err := udp.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	peer, err := net.DialTimeout("udp4", udp.LocalAddr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if err := peer.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4)
	n, address, err := udp.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := udp.WriteToUDP(buffer[:n], address); err != nil {
		t.Fatal(err)
	}
	n, err = peer.Read(reply)
	if err != nil || !bytes.Equal(reply[:n], []byte("ping")) {
		t.Fatalf("UDP echo mismatch: %q %v", reply[:n], err)
	}
	return listener.Addr().(*net.TCPAddr).Port, udp.LocalAddr().(*net.UDPAddr).Port
}

func boundaryConntrack(t *testing.T) []netobserve.Flow {
	t.Helper()
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2}); err != nil {
		t.Fatal(err)
	}
	// nfnetlink_conntrack.h: subsystem CTNETLINK=1, IPCTNL_MSG_CT_GET=1.
	request := make([]byte, 20)
	binary.NativeEndian.PutUint32(request, 20)
	binary.NativeEndian.PutUint16(request[4:], 0x101)
	binary.NativeEndian.PutUint16(request[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(request[8:], 1)
	request[16] = unix.AF_INET
	if err := unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 65536)
	flows := make([]netobserve.Flow, 0, 8)
	for page := 0; page < 64; page++ {
		n, _, flags, from, err := unix.Recvmsg(fd, buffer, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		sender, ok := from.(*unix.SockaddrNetlink)
		if !ok || sender.Pid != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			t.Fatal("untrusted/truncated conntrack dump")
		}
		parsed, err := netobserve.ParseConntrack(buffer[:n], true)
		if err != nil {
			t.Fatal(err)
		}
		flows = append(flows, parsed...)
		if len(flows) > 128 {
			t.Fatal("isolated fixture exceeded bounded conntrack count")
		}
		for offset := 0; offset < n; {
			if n-offset < 16 {
				t.Fatal("short dump header")
			}
			length := int(binary.NativeEndian.Uint32(buffer[offset:]))
			if length < 16 || length > n-offset {
				t.Fatal("invalid dump message length")
			}
			if binary.NativeEndian.Uint32(buffer[offset+8:]) != 1 {
				t.Fatal("unexpected conntrack dump sequence")
			}
			if binary.NativeEndian.Uint16(buffer[offset+4:]) == unix.NLMSG_DONE {
				return flows
			}
			offset += (length + 3) &^ 3
		}
	}
	t.Fatal("conntrack dump exceeded bounded page count")
	return nil
}
