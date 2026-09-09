//go:build linux

// ABOUTME: Exercises generated gateway rules with real packets across two routed NAT boundaries.
// ABOUTME: Runs only in an explicitly disposable privileged Linux network namespace.
package network_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/network"
	"golang.org/x/sys/unix"
)

const (
	packetGatewayNS  = "vmobs-packet-gateway"
	packetGuestNS    = "vmobs-packet-guest"
	packetEndpointNS = "vmobs-packet-endpoint"
	packetVMID       = "packet-proof"
)

func TestGatewayRulesForwardRealPacketsThroughTwoNATBoundaries(t *testing.T) {
	if os.Getenv("VMOBS_REAL_GATEWAY_PACKETS") != "1" {
		t.Skip("set VMOBS_REAL_GATEWAY_PACKETS=1 inside a disposable privileged Linux network namespace")
	}
	if os.Geteuid() != 0 {
		t.Fatal("VMOBS_REAL_GATEWAY_PACKETS=1 requires root in a disposable Linux network namespace")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatalf("refusing packet mutations unless the explicitly disposable starting namespace is loopback-only: interfaces=%+v err=%v", interfaces, err)
	}
	for _, command := range []string{"ip", "nft"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Fatalf("VMOBS_REAL_GATEWAY_PACKETS=1 requires %s: %v", command, err)
		}
	}

	layout, err := network.NewLayout(packetVMID, netip.MustParsePrefix("10.190.0.0/30"))
	if err != nil {
		t.Fatalf("NewLayout: %v", err)
	}
	transport := packetPolicy(t, network.ProfileTransport)
	offline := packetPolicy(t, network.ProfileOffline)
	base := network.GatewayRuleConfig{
		VMID:             packetVMID,
		Layout:           layout,
		Policy:           transport,
		HostDenyPrefixes: []netip.Prefix{netip.MustParsePrefix("192.168.50.0/24")},
		Ready:            true,
	}

	packetTopology(t, layout)
	t.Run("nested namespace work restores the calling thread", func(t *testing.T) {
		if err := inPacketNamespace(packetGuestNS, func() error {
			before, err := os.Readlink("/proc/thread-self/ns/net")
			if err != nil {
				return err
			}
			if err := inPacketNamespace(packetEndpointNS, func() error { return nil }); err != nil {
				return err
			}
			after, err := os.Readlink("/proc/thread-self/ns/net")
			if err != nil {
				return err
			}
			if after != before {
				return fmt.Errorf("calling thread moved from %s to %s", before, after)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	servers := startPacketServers(t)
	ready := packetRules(t, base)
	installPacketRules(t, ready)

	t.Run("ready transport returns TCP 80 and 443 replies after both SNAT stages", func(t *testing.T) {
		for _, port := range []string{"80", "443"} {
			response, err := packetTCPExchange(packetGuestNS, "", net.JoinHostPort("11.0.0.80", port), []byte("web"), time.Second)
			if err != nil {
				t.Fatalf("TCP %s: %v", port, err)
			}
			if !strings.HasPrefix(string(response), "11.0.0.1:") {
				t.Fatalf("TCP %s endpoint observed source %q, want host-side masquerade 11.0.0.1", port, response)
			}
		}
	})

	t.Run("managed resolver returns UDP and TCP replies through the exact upstream", func(t *testing.T) {
		udpResponse, err := packetUDPExchange(packetGuestNS, "", "172.31.255.1:53", []byte("udp-dns"), time.Second)
		if err != nil {
			t.Fatalf("managed UDP DNS: %v", err)
		}
		if !strings.HasPrefix(string(udpResponse), "11.0.0.1:") {
			t.Fatalf("UDP upstream observed source %q, want host-side masquerade 11.0.0.1", udpResponse)
		}
		tcpResponse, err := packetTCPExchange(packetGuestNS, "", "172.31.255.1:53", []byte("tcp-dns"), time.Second)
		if err != nil {
			t.Fatalf("managed TCP DNS: %v", err)
		}
		if !strings.HasPrefix(string(tcpResponse), "11.0.0.1:") {
			t.Fatalf("TCP upstream observed source %q, want host-side masquerade 11.0.0.1", tcpResponse)
		}
	})

	t.Run("managed resolver cannot reach an alternate UDP or TCP upstream", func(t *testing.T) {
		assertPacketDenied(t, packetGatewayNS, "inet", "vmobs_gateway", func() error {
			_, err := packetUDPExchange(packetGatewayNS, "10.190.0.2:0", "11.0.0.54:53", []byte("alternate-udp-dns"), 300*time.Millisecond)
			return err
		})
		assertPacketDenied(t, packetGatewayNS, "inet", "vmobs_gateway", func() error {
			_, err := packetTCPExchange(packetGatewayNS, "10.190.0.2:0", "11.0.0.54:53", []byte("alternate-tcp-dns"), 300*time.Millisecond)
			return err
		})
	})

	t.Run("guest bypass and spoof attempts increment real deny counters", func(t *testing.T) {
		assertPacketCounterStable(t, packetGatewayNS, "netdev", "vmobs_gateway_ingress", time.Second)
		assertPacketDenied(t, packetGatewayNS, "inet", "vmobs_gateway", func() error {
			_, err := packetUDPExchange(packetGuestNS, "", "11.0.0.53:53", []byte("external-dns"), 300*time.Millisecond)
			return err
		})
		assertPacketDenied(t, packetGatewayNS, "inet", "vmobs_gateway", func() error {
			_, err := packetTCPExchange(packetGuestNS, "", "11.0.0.53:53", []byte("external-dns"), 300*time.Millisecond)
			return err
		})
		assertPacketDenied(t, packetGatewayNS, "inet", "vmobs_gateway", func() error {
			_, err := packetUDPExchange(packetGuestNS, "", "11.0.0.80:12345", []byte("external-udp"), 300*time.Millisecond)
			return err
		})
		assertPacketDenied(t, packetGatewayNS, "inet", "vmobs_gateway", func() error {
			_, err := packetTCPExchange(packetGuestNS, "", "192.168.50.2:80", []byte("private"), 300*time.Millisecond)
			return err
		})
		assertPacketDenied(t, packetGatewayNS, "netdev", "vmobs_gateway_ingress", func() error {
			_, err := packetTCPExchange(packetGuestNS, "172.31.254.2:0", "11.0.0.80:80", []byte("spoof-ip"), 300*time.Millisecond)
			return err
		})
		assertPacketCounterIncreases(t, packetGatewayNS, "netdev", "vmobs_gateway_ingress", func() {
			packetSendEthernet(t, net.HardwareAddr{0x02, 0, 0, 0, 0, 0x99}, unix.ETH_P_IP)
		})
		assertPacketCounterIncreases(t, packetGatewayNS, "netdev", "vmobs_gateway_ingress", func() {
			packetSendEthernet(t, net.HardwareAddr(layout.GuestMAC[:]), unix.ETH_P_IPV6)
		})
	})

	t.Run("host input guard rejects a public address DNATed to a local service", func(t *testing.T) {
		installPacketDNAT(t)
		assertPacketDenied(t, "", "inet", ready.HostFilterTable.Name, func() error {
			_, err := packetTCPExchange(packetGuestNS, "", "11.0.0.99:80", []byte("dnat-local"), 300*time.Millisecond)
			return err
		})
	})

	t.Run("closed transport and offline remain closed", func(t *testing.T) {
		closed := base
		closed.Ready = false
		installPacketRules(t, packetRules(t, closed))
		assertPacketDenied(t, packetGatewayNS, "inet", "vmobs_gateway", func() error {
			_, err := packetTCPExchange(packetGuestNS, "", "11.0.0.80:80", []byte("closed"), 300*time.Millisecond)
			return err
		})

		offlineConfig := base
		offlineConfig.Policy = offline
		offlineConfig.Ready = true
		installPacketRules(t, packetRules(t, offlineConfig))
		assertPacketDenied(t, packetGatewayNS, "inet", "vmobs_gateway", func() error {
			_, err := packetTCPExchange(packetGuestNS, "", "11.0.0.80:443", []byte("offline"), 300*time.Millisecond)
			return err
		})
	})

	servers.check(t)
}

func packetPolicy(t *testing.T, profile network.Profile) network.EffectivePolicy {
	t.Helper()
	file := network.PolicyFile{SchemaVersion: network.PolicySchemaVersion, ID: network.OfflinePolicyID, Profile: network.ProfileOffline}
	if profile == network.ProfileTransport {
		file = network.PolicyFile{
			SchemaVersion:   network.PolicySchemaVersion,
			ID:              network.TransportPublicWebPolicyID,
			Profile:         network.ProfileTransport,
			DNSUpstream:     "11.0.0.53",
			AllowedTCPPorts: []uint16{80, 443},
		}
	}
	policy, err := network.ValidateEffectivePolicy(file)
	if err != nil {
		t.Fatalf("ValidateEffectivePolicy: %v", err)
	}
	return policy
}

func packetRules(t *testing.T, config network.GatewayRuleConfig) network.GatewayRules {
	t.Helper()
	rules, err := network.BuildGatewayRules(config)
	if err != nil {
		t.Fatalf("BuildGatewayRules: %v", err)
	}
	return rules
}

func packetTopology(t *testing.T, layout network.Layout) {
	t.Helper()
	createdNamespaces := make([]string, 0, 3)
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "delete", network.VethName(packetVMID)).Run()
		_ = exec.Command("ip", "link", "delete", "uplink0").Run()
		for index := len(createdNamespaces) - 1; index >= 0; index-- {
			_ = exec.Command("ip", "netns", "delete", createdNamespaces[index]).Run()
		}
	})
	for _, namespace := range []string{packetGatewayNS, packetGuestNS, packetEndpointNS} {
		packetCommand(t, "", nil, "ip", "netns", "add", namespace)
		createdNamespaces = append(createdNamespaces, namespace)
	}

	veth := network.VethName(packetVMID)
	packetCommand(t, "", nil, "ip", "link", "add", veth, "type", "veth", "peer", "name", "eth-up", "netns", packetGatewayNS)
	packetCommand(t, "", nil, "ip", "address", "add", layout.TransitHost.String()+"/30", "dev", veth)
	packetCommand(t, "", nil, "ip", "link", "set", veth, "up")
	packetCommand(t, packetGatewayNS, nil, "ip", "address", "add", layout.TransitNamespace.String()+"/30", "dev", "eth-up")
	packetCommand(t, packetGatewayNS, nil, "ip", "link", "set", "eth-up", "up")
	packetCommand(t, packetGatewayNS, nil, "ip", "route", "add", "default", "via", layout.TransitHost.String(), "dev", "eth-up")

	packetCommand(t, "", nil, "ip", "link", "add", "tap0", "netns", packetGatewayNS, "type", "veth", "peer", "name", "guest0", "netns", packetGuestNS)
	packetCommand(t, packetGatewayNS, nil, "ip", "address", "add", layout.GuestGateway.String()+"/30", "dev", "tap0")
	packetCommand(t, packetGatewayNS, nil, "ip", "link", "set", "tap0", "address", "02:00:00:00:00:01")
	packetCommand(t, packetGatewayNS, nil, "ip", "link", "set", "tap0", "up")
	packetCommand(t, packetGuestNS, nil, "ip", "link", "set", "guest0", "address", layout.GuestMAC.String())
	packetCommand(t, packetGuestNS, nil, "ip", "link", "set", "guest0", "addrgenmode", "none")
	packetCommand(t, packetGuestNS, nil, "ip", "address", "add", layout.GuestAddress.String()+"/30", "dev", "guest0")
	packetCommand(t, packetGuestNS, nil, "ip", "address", "add", "172.31.254.2/32", "dev", "guest0")
	packetCommand(t, packetGuestNS, nil, "ip", "link", "set", "guest0", "up")
	if output := packetCommand(t, packetGuestNS, nil, "ip", "-o", "-6", "address", "show", "dev", "guest0"); len(bytes.TrimSpace(output)) != 0 {
		t.Fatalf("guest0 acquired an unexpected IPv6 address:\n%s", output)
	}
	packetCommand(t, packetGuestNS, nil, "ip", "route", "add", "default", "via", layout.GuestGateway.String(), "dev", "guest0")
	installPacketGuestNeighbors(t)

	packetCommand(t, "", nil, "ip", "link", "add", "uplink0", "type", "veth", "peer", "name", "endpoint0", "netns", packetEndpointNS)
	packetCommand(t, "", nil, "ip", "address", "add", "11.0.0.1/24", "dev", "uplink0")
	packetCommand(t, "", nil, "ip", "address", "add", "192.168.50.1/24", "dev", "uplink0")
	packetCommand(t, "", nil, "ip", "link", "set", "uplink0", "up")
	for _, address := range []string{"11.0.0.53/24", "11.0.0.54/24", "11.0.0.80/24", "192.168.50.2/24"} {
		packetCommand(t, packetEndpointNS, nil, "ip", "address", "add", address, "dev", "endpoint0")
	}
	packetCommand(t, packetEndpointNS, nil, "ip", "link", "set", "endpoint0", "up")
	packetCommand(t, packetEndpointNS, nil, "ip", "route", "add", "default", "via", "11.0.0.1", "dev", "endpoint0")

	for _, item := range []struct{ namespace, name string }{
		{"", veth}, {"", "uplink0"}, {packetGatewayNS, "tap0"}, {packetGatewayNS, "eth-up"},
	} {
		enablePacketForwarding(t, item.namespace, item.name)
	}
}

func installPacketGuestNeighbors(t *testing.T) {
	t.Helper()
	packetCommand(t, packetGuestNS, nil, "ip", "neighbor", "replace", "172.31.255.1", "lladdr", "02:00:00:00:00:01", "nud", "permanent", "dev", "guest0")
}

func enablePacketForwarding(t *testing.T, namespace, name string) {
	t.Helper()
	if err := inPacketNamespace(namespace, func() error {
		device, err := net.InterfaceByName(name)
		if err != nil {
			return err
		}
		return network.EnableIPv4Forwarding(t.Context(), device.Index)
	}); err != nil {
		t.Fatalf("enable IPv4 forwarding on %s/%s: %v", namespace, name, err)
	}
}

func installPacketRules(t *testing.T, rules network.GatewayRules) {
	t.Helper()
	for _, table := range []network.NFTTable{rules.NamespaceIngressTable, rules.NamespaceFilterTable, rules.NamespaceNATTable} {
		packetDeleteTable(packetGatewayNS, table)
	}
	for _, table := range []network.NFTTable{rules.HostFilterTable, rules.HostNATTable} {
		packetDeleteTable("", table)
	}
	packetCommand(t, packetGatewayNS, []byte(rules.NamespaceScript), "nft", "-f", "-")
	packetCommand(t, "", []byte(rules.HostScript), "nft", "-f", "-")
	t.Cleanup(func() {
		for _, table := range []network.NFTTable{rules.HostFilterTable, rules.HostNATTable} {
			packetDeleteTable("", table)
		}
	})
}

func packetDeleteTable(namespace string, table network.NFTTable) {
	if namespace == "" {
		_ = exec.Command("nft", "delete", "table", table.Family, table.Name).Run()
		return
	}
	_ = exec.Command("ip", "netns", "exec", namespace, "nft", "delete", "table", table.Family, table.Name).Run()
}

func installPacketDNAT(t *testing.T) {
	t.Helper()
	script := `table ip vmobs_packet_dnat {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    ip daddr 11.0.0.99 tcp dport 80 dnat to 11.0.0.1:18080
  }
}
`
	packetCommand(t, "", []byte(script), "nft", "-f", "-")
	t.Cleanup(func() { packetDeleteTable("", network.NFTTable{Family: "ip", Name: "vmobs_packet_dnat"}) })
}

type packetServers struct {
	errors chan error
	done   chan struct{}
	close  []io.Closer
	once   sync.Once
}

func startPacketServers(t *testing.T) *packetServers {
	t.Helper()
	servers := &packetServers{errors: make(chan error, 16), done: make(chan struct{})}
	for _, address := range []string{"11.0.0.80:80", "11.0.0.80:443", "192.168.50.2:80", "11.0.0.54:53"} {
		servers.serveTCP(t, packetEndpointNS, address, false)
	}
	servers.serveTCP(t, packetEndpointNS, "11.0.0.53:53", false)
	servers.serveUDP(t, packetEndpointNS, "11.0.0.53:53")
	servers.serveUDP(t, packetEndpointNS, "11.0.0.54:53")
	servers.serveTCP(t, packetGatewayNS, "172.31.255.1:53", true)
	servers.serveUDPRelay(t, packetGatewayNS, "172.31.255.1:53", "11.0.0.53:53")
	servers.serveTCP(t, "", "11.0.0.1:18080", false)
	t.Cleanup(func() {
		servers.once.Do(func() { close(servers.done) })
		for _, closer := range servers.close {
			_ = closer.Close()
		}
	})
	return servers
}

func (servers *packetServers) serveTCP(t *testing.T, namespace, address string, relay bool) {
	t.Helper()
	var listener net.Listener
	if err := inPacketNamespace(namespace, func() error {
		var err error
		listener, err = (&net.ListenConfig{}).Listen(context.Background(), "tcp", address)
		return err
	}); err != nil {
		t.Fatalf("listen TCP %s in %s: %v", address, namespace, err)
	}
	servers.close = append(servers.close, listener)
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				select {
				case <-servers.done:
					return
				default:
					servers.report(fmt.Errorf("accept TCP %s: %w", address, err))
					return
				}
			}
			go func() {
				defer connection.Close()
				payload, err := io.ReadAll(io.LimitReader(connection, 1024))
				if err != nil {
					servers.report(fmt.Errorf("read TCP %s: %w", address, err))
					return
				}
				response := []byte(connection.RemoteAddr().String())
				if relay {
					response, err = packetTCPExchange(packetGatewayNS, "10.190.0.2:0", "11.0.0.53:53", payload, time.Second)
					if err != nil {
						servers.report(fmt.Errorf("relay TCP DNS: %w", err))
						return
					}
				}
				if _, err := connection.Write(response); err != nil {
					servers.report(fmt.Errorf("write TCP %s: %w", address, err))
				}
			}()
		}
	}()
}

func (servers *packetServers) serveUDP(t *testing.T, namespace, address string) {
	t.Helper()
	connection := packetListenUDP(t, namespace, address)
	servers.close = append(servers.close, connection)
	go func() {
		buffer := make([]byte, 1024)
		for {
			_, remote, err := connection.ReadFrom(buffer)
			if err != nil {
				select {
				case <-servers.done:
					return
				default:
					servers.report(fmt.Errorf("read UDP %s: %w", address, err))
					return
				}
			}
			if _, err := connection.WriteTo([]byte(remote.String()), remote); err != nil {
				servers.report(fmt.Errorf("write UDP %s: %w", address, err))
			}
		}
	}()
}

func (servers *packetServers) serveUDPRelay(t *testing.T, namespace, address, upstream string) {
	t.Helper()
	connection := packetListenUDP(t, namespace, address)
	servers.close = append(servers.close, connection)
	go func() {
		buffer := make([]byte, 1024)
		for {
			n, remote, err := connection.ReadFrom(buffer)
			if err != nil {
				select {
				case <-servers.done:
					return
				default:
					servers.report(fmt.Errorf("read managed UDP DNS: %w", err))
					return
				}
			}
			response, err := packetUDPExchange(namespace, "10.190.0.2:0", upstream, append([]byte(nil), buffer[:n]...), time.Second)
			if err != nil {
				servers.report(fmt.Errorf("relay UDP DNS: %w", err))
				continue
			}
			if _, err := connection.WriteTo(response, remote); err != nil {
				servers.report(fmt.Errorf("reply managed UDP DNS: %w", err))
			}
		}
	}()
}

func packetListenUDP(t *testing.T, namespace, address string) net.PacketConn {
	t.Helper()
	var connection net.PacketConn
	if err := inPacketNamespace(namespace, func() error {
		var err error
		connection, err = (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", address)
		return err
	}); err != nil {
		t.Fatalf("listen UDP %s in %s: %v", address, namespace, err)
	}
	return connection
}

func (servers *packetServers) report(err error) {
	select {
	case servers.errors <- err:
	default:
	}
}

func (servers *packetServers) check(t *testing.T) {
	t.Helper()
	select {
	case err := <-servers.errors:
		t.Fatal(err)
	default:
	}
}

func packetTCPExchange(namespace, local, remote string, payload []byte, timeout time.Duration) ([]byte, error) {
	var response []byte
	err := inPacketNamespace(namespace, func() error {
		dialer := net.Dialer{Timeout: timeout}
		if local != "" {
			address, err := net.ResolveTCPAddr("tcp", local)
			if err != nil {
				return err
			}
			dialer.LocalAddr = address
		}
		connection, err := dialer.Dial("tcp", remote)
		if err != nil {
			return err
		}
		defer connection.Close()
		if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		if _, err := connection.Write(payload); err != nil {
			return err
		}
		if tcp, ok := connection.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		response, err = io.ReadAll(io.LimitReader(connection, 1024))
		return err
	})
	return response, err
}

func packetUDPExchange(namespace, local, remote string, payload []byte, timeout time.Duration) ([]byte, error) {
	var response []byte
	err := inPacketNamespace(namespace, func() error {
		dialer := net.Dialer{Timeout: timeout}
		if local != "" {
			address, err := net.ResolveUDPAddr("udp", local)
			if err != nil {
				return err
			}
			dialer.LocalAddr = address
		}
		connection, err := dialer.Dial("udp", remote)
		if err != nil {
			return err
		}
		defer connection.Close()
		if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		if _, err := connection.Write(payload); err != nil {
			return err
		}
		buffer := make([]byte, 1024)
		n, err := connection.Read(buffer)
		response = append([]byte(nil), buffer[:n]...)
		return err
	})
	return response, err
}

func assertPacketDenied(t *testing.T, namespace, family, table string, action func() error) {
	t.Helper()
	var actionErr error
	assertPacketCounterIncreases(t, namespace, family, table, func() { actionErr = action() })
	if actionErr == nil {
		t.Fatal("packet unexpectedly received a reply")
	}
}

func assertPacketCounterIncreases(t *testing.T, namespace, family, table string, action func()) {
	t.Helper()
	before := packetCounter(t, namespace, family, table)
	action()
	after := packetCounter(t, namespace, family, table)
	if after <= before {
		t.Fatalf("deny counter %s/%s did not increase: before=%d after=%d", family, table, before, after)
	}
}

func assertPacketCounterStable(t *testing.T, namespace, family, table string, duration time.Duration) {
	t.Helper()
	before := packetCounter(t, namespace, family, table)
	time.Sleep(duration)
	after := packetCounter(t, namespace, family, table)
	if after != before {
		t.Fatalf("deny counter %s/%s changed without test traffic: before=%d after=%d", family, table, before, after)
	}
}

func packetSendEthernet(t *testing.T, source net.HardwareAddr, etherType uint16) {
	t.Helper()
	if err := inPacketNamespace(packetGuestNS, func() error {
		device, err := net.InterfaceByName("guest0")
		if err != nil {
			return err
		}
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(etherType)))
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		frame := make([]byte, 14)
		copy(frame[0:6], []byte{0x02, 0, 0, 0, 0, 1})
		copy(frame[6:12], source)
		frame[12] = byte(etherType >> 8)
		frame[13] = byte(etherType)
		return unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{Protocol: htons(etherType), Ifindex: device.Index, Halen: 6})
	}); err != nil {
		t.Fatalf("send Ethernet frame: %v", err)
	}
}

func htons(value uint16) uint16 {
	return value<<8 | value>>8
}

func packetCounter(t *testing.T, namespace, family, table string) uint64 {
	t.Helper()
	output := packetCommand(t, namespace, nil, "nft", "-j", "list", "counter", family, table, "denied")
	var document struct {
		NFTables []struct {
			Counter *struct {
				Packets uint64 `json:"packets"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(output, &document); err != nil {
		t.Fatalf("decode nft counter: %v\n%s", err, output)
	}
	for _, object := range document.NFTables {
		if object.Counter != nil {
			return object.Counter.Packets
		}
	}
	t.Fatalf("nft counter %s/%s had no counter object: %s", family, table, output)
	return 0
}

func inPacketNamespace(namespace string, operation func() error) error {
	if namespace == "" {
		return operation()
	}
	runtime.LockOSThread()
	unlock := true
	defer func() {
		if unlock {
			runtime.UnlockOSThread()
		}
	}()
	current, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return err
	}
	defer current.Close()
	target, err := os.Open("/var/run/netns/" + namespace)
	if err != nil {
		return err
	}
	defer target.Close()
	if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		return err
	}
	operationErr := operation()
	if restoreErr := unix.Setns(int(current.Fd()), unix.CLONE_NEWNET); restoreErr != nil {
		// Returning this thread to the runtime would let unrelated work run in
		// the wrong namespace. A restoration failure invalidates the test process.
		unlock = false
		panic(fmt.Sprintf("restore packet-test namespace: %v", restoreErr))
	}
	return operationErr
}

func packetCommand(t *testing.T, namespace string, stdin []byte, name string, arguments ...string) []byte {
	t.Helper()
	if namespace != "" {
		arguments = append([]string{"netns", "exec", namespace, name}, arguments...)
		name = "ip"
	}
	command := exec.Command(name, arguments...)
	command.Stdin = bytes.NewReader(stdin)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(arguments, " "), err, output)
	}
	return output
}
