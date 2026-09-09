// ABOUTME: Proves netdev ingress NFLOG family and tuple quality with real veth traffic.
// ABOUTME: Privileged coverage runs only in an explicitly selected disposable Linux container.
//go:build linux

package netobserve

import (
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

func TestRealNFLogNetdevFamilies(t *testing.T) {
	if os.Getenv("VMOBS_NFLOG_NETDEV_TEST") != "1" {
		t.Skip("explicit disposable privileged Linux container required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("privileged netdev NFLOG test requires root inside disposable container")
	}
	if os.Getenv("VMOBS_NFLOG_NETDEV_CHILD") != "1" {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRealNFLogNetdevFamilies$", "-test.v")
		cmd.Env = append(os.Environ(), "VMOBS_NFLOG_NETDEV_CHILD=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated netdev NFLOG test: %v\n%s", err, output)
		} else {
			t.Logf("%s", output)
		}
		return
	}

	assertFreshLoopbackNamespace(t)
	runNFLogFamilyCommand(t, "ip", "link", "add", "nf-tx", "type", "veth", "peer", "name", "nf-rx")
	runNFLogFamilyCommand(t, "ip", "link", "set", "nf-tx", "up")
	runNFLogFamilyCommand(t, "ip", "link", "set", "nf-rx", "up")

	const group = uint16(322)
	file, info, err := OpenNFLog(t.Context(), group)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	installNFLogNetdevRules(t, group)

	sendNFLogEthernetFrame(t, "nf-tx", 0x0800, netdevIPv4Packet())
	sendNFLogEthernetFrame(t, "nf-tx", 0x88b5, []byte("unsupported-scope-proof"))
	records := readNFLogFamilyRecords(t, file, info, 2)

	ipv4, ok := records["vmobs-netdev-ipv4"]
	if !ok {
		t.Fatalf("missing IPv4 denial: %+v", records)
	}
	if ipv4.Family != 5 || ipv4.HardwareProtocol == nil || *ipv4.HardwareProtocol != 0x0800 ||
		ipv4.InInterface == nil || ipv4.Tuple == nil || ipv4.Tuple.Source.String() != "192.0.2.10" ||
		ipv4.Tuple.Destination.String() != "198.51.100.20" || ipv4.Tuple.Protocol == nil || *ipv4.Tuple.Protocol != unix.IPPROTO_UDP ||
		ipv4.Tuple.SourcePort == nil || *ipv4.Tuple.SourcePort != 40000 || ipv4.Tuple.DestinationPort == nil || *ipv4.Tuple.DestinationPort != 53 ||
		ipv4.ScopeLimitation != "" || ipv4.PacketMalformed {
		t.Fatalf("wrong netdev IPv4 evidence: %+v", ipv4)
	}

	unsupported, ok := records["vmobs-netdev-unknown"]
	if !ok {
		t.Fatalf("missing unsupported denial: %+v", records)
	}
	if unsupported.Family != 5 || unsupported.HardwareProtocol == nil || *unsupported.HardwareProtocol != 0x88b5 ||
		unsupported.InInterface == nil || unsupported.Tuple != nil || unsupported.ScopeLimitation != "unsupported_hardware_protocol" ||
		unsupported.PacketMalformed || unsupported.CapturedLength != len("unsupported-scope-proof") {
		t.Fatalf("wrong unsupported netdev evidence: %+v", unsupported)
	}
	t.Logf("kernel=%s group=%d IPv4_family=%d IPv4_protocol=%#x unknown_family=%d unknown_protocol=%#x", kernelRelease(), group, ipv4.Family, *ipv4.HardwareProtocol, unsupported.Family, *unsupported.HardwareProtocol)
}

func installNFLogNetdevRules(t *testing.T, group uint16) {
	t.Helper()
	script := fmt.Sprintf(`table netdev vmobs_nflog_family {
 chain ingress {
  type filter hook ingress device "nf-rx" priority 0; policy accept;
	meta protocol ip log prefix "vmobs-netdev-ipv4" group %d snaplen %d queue-threshold 2 drop
	meta protocol 0x88b5 log prefix "vmobs-netdev-unknown" group %d snaplen %d queue-threshold 2 drop
 }
}
`, group, nfLogCopyBytes, group, nfLogCopyBytes)
	cmd := exec.CommandContext(t.Context(), "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install isolated netdev NFLOG rules: %v\n%s\n%s", err, output, script)
	}
}

func sendNFLogEthernetFrame(t *testing.T, interfaceName string, etherType uint16, payload []byte) {
	t.Helper()
	link, err := net.InterfaceByName(interfaceName)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(hostToNetwork16(unix.ETH_P_ALL)))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	frame := make([]byte, 14+len(payload))
	copy(frame[:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(frame[6:12], link.HardwareAddr)
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[14:], payload)
	if err := unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{Protocol: hostToNetwork16(etherType), Ifindex: link.Index}); err != nil {
		t.Fatal(err)
	}
}

func netdevIPv4Packet() []byte {
	packet := make([]byte, 28)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = unix.IPPROTO_UDP
	copy(packet[12:16], []byte{192, 0, 2, 10})
	copy(packet[16:20], []byte{198, 51, 100, 20})
	binary.BigEndian.PutUint16(packet[20:22], 40000)
	binary.BigEndian.PutUint16(packet[22:24], 53)
	binary.BigEndian.PutUint16(packet[24:26], 8)
	return packet
}

func readNFLogFamilyRecords(t *testing.T, file *os.File, info NFLogSocketInfo, count int) map[string]Denial {
	t.Helper()
	records := make(map[string]Denial)
	buffer := make([]byte, 4096)
	deadline := time.Now().Add(2 * time.Second)
	for len(records) < count && time.Now().Before(deadline) {
		n, _, flags, address, err := unix.Recvmsg(int(file.Fd()), buffer, nil, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
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
		decoded, err := ParseNFLog(buffer[:n])
		if err != nil {
			t.Fatalf("decode real NFLOG datagram: %v\n%x", err, buffer[:n])
		}
		for _, record := range decoded {
			if record.Group == info.Group {
				records[record.Prefix] = record
			}
		}
	}
	if len(records) != count {
		t.Fatalf("timed out waiting for %d real NFLOG records: %+v", count, records)
	}
	return records
}

func runNFLogFamilyCommand(t *testing.T, name string, args ...string) {
	t.Helper()
	if output, err := exec.CommandContext(t.Context(), name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, output)
	}
}

func hostToNetwork16(value uint16) uint16 {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	return binary.NativeEndian.Uint16(encoded[:])
}

func kernelRelease() string {
	var name unix.Utsname
	if err := unix.Uname(&name); err != nil {
		return "unknown"
	}
	bytes := make([]byte, 0, len(name.Release))
	for _, value := range name.Release {
		if value == 0 {
			break
		}
		bytes = append(bytes, byte(value))
	}
	return string(bytes)
}
