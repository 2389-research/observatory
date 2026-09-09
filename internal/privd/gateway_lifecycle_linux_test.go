// ABOUTME: Exercises fail-closed gateway policy binding and real kernel ownership.
// ABOUTME: The real lifecycle runs only in an explicitly opted-in isolated Linux container.
//go:build linux

package privd

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/2389-research/observatory/internal/network"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGatewayRequiresTrustedExplicitPolicy(t *testing.T) {
	ops := NewRealOps(RealOpsCfg{})
	entry := VMEntry{VMID: "gateway-policy", NetCIDR: "10.99.0.0/30"}
	req := AllocateNetworkReq{VMID: entry.VMID, CIDR: entry.NetCIDR, Profile: "offline", PolicyID: "offline", GuestBootID: "b28581fb-7b8b-499a-8671-8bf54d159839"}
	if err := ops.PrepareNetworkEntry(context.Background(), &entry, req); err == nil {
		t.Fatal("missing trusted policy directory accepted")
	}
}

func TestGatewayClosedKernelLifecycle(t *testing.T) {
	if os.Getenv("VMOBS_GATEWAY_LIFECYCLE") != "1" {
		t.Skip("requires opted-in isolated Linux container")
	}
	policyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(policyDir, "offline.json"), []byte(`{"schema_version":1,"id":"offline","profile":"offline","dns_upstream":"","allowed_tcp_ports":[],"extra_deny_prefixes":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	ops := NewRealOps(RealOpsCfg{PolicyDirectory: policyDir})
	entry := VMEntry{VMID: "gateway-kernel", NetCIDR: "10.99.0.0/30"}
	req := AllocateNetworkReq{VMID: entry.VMID, CIDR: entry.NetCIDR, Profile: "offline", PolicyID: "offline", GuestBootID: "b28581fb-7b8b-499a-8671-8bf54d159839"}
	ctx := context.Background()
	if err := ops.PrepareNetworkEntry(ctx, &entry, req); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ops.ReleaseNetwork(entry); err != nil {
			t.Error(err)
		}
	})
	if err := ops.AllocateNetworkOwnedContext(ctx, &entry, req); err != nil {
		t.Fatal(err)
	}
	previousBoot := entry
	previousBoot.NetworkHostBootID = "a28581fb-7b8b-499a-8671-8bf54d159839"
	if err := ops.proveNamespace(previousBoot); err == nil {
		t.Fatal("previous host boot authorized namespace ownership")
	}
	if entry.NetworkTopologyDigest == "" || entry.NetworkNamespaceInode == 0 {
		t.Fatal("missing durable topology identity")
	}
	if err := ops.AllocateNetworkOwnedContext(ctx, &entry, req); err != nil {
		t.Fatal("revalidate:", err)
	}
	wrong := req
	wrong.GuestBootID = "a28581fb-7b8b-499a-8671-8bf54d159839"
	if err := ops.AllocateNetworkOwnedContext(ctx, &entry, wrong); err == nil {
		t.Fatal("new boot rebound live namespace")
	}
	if err := ops.runCmd(ctx, []string{"ip", "netns", "exec", "vmobs-gateway-kernel", "ip", "address", "del", "172.31.255.1/30", "dev", "tap0"}); err != nil {
		t.Fatal(err)
	}
	if err := ops.AllocateNetworkOwnedContext(ctx, &entry, req); err == nil {
		t.Fatal("damaged topology accepted")
	}
	exists, err := ops.netnsExists(ctx, entry.VMID)
	if err != nil || !exists {
		t.Fatal("failed probe destroyed existing namespace", err)
	}
	if err := ops.ReleaseNetwork(entry); err != nil {
		t.Fatal(err)
	}
	if err := ops.ReleaseNetwork(entry); err != nil {
		t.Fatal("repeat release:", err)
	}
}

func TestGatewayTransportUnavailableBeforeMutation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned policy fixture")
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "transport-public-web.json"), []byte(`{"schema_version":1,"id":"transport-public-web","profile":"transport","dns_upstream":"1.1.1.1","allowed_tcp_ports":[80,443],"extra_deny_prefixes":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	ops := NewRealOps(RealOpsCfg{PolicyDirectory: directory})
	entry := VMEntry{VMID: "transport-unavailable", NetCIDR: "10.99.0.4/30"}
	req := AllocateNetworkReq{VMID: entry.VMID, CIDR: entry.NetCIDR, Profile: "transport", PolicyID: "transport-public-web", GuestBootID: "b28581fb-7b8b-499a-8671-8bf54d159839"}
	if err := ops.PrepareNetworkEntry(context.Background(), &entry, req); err == nil {
		t.Fatal("transport accepted without resolver/acquisition")
	}
	if entry.GatewayGeneration != "" {
		t.Fatal("unavailable transport minted mutation authority")
	}
}

func TestGatewayKernelOwnershipRefusesForeignResources(t *testing.T) {
	if os.Getenv("VMOBS_GATEWAY_LIFECYCLE") != "1" {
		t.Skip("requires opted-in isolated Linux container")
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "offline.json"), []byte(`{"schema_version":1,"id":"offline","profile":"offline","dns_upstream":"","allowed_tcp_ports":[],"extra_deny_prefixes":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	ops := NewRealOps(RealOpsCfg{PolicyDirectory: directory})
	entry := VMEntry{VMID: "gateway-ownership", NetCIDR: "10.99.0.8/30"}
	req := AllocateNetworkReq{VMID: entry.VMID, CIDR: entry.NetCIDR, Profile: "offline", PolicyID: "offline", GuestBootID: "b28581fb-7b8b-499a-8671-8bf54d159839"}
	ctx := context.Background()
	if err := ops.PrepareNetworkEntry(ctx, &entry, req); err != nil {
		t.Fatal(err)
	}
	if err := ops.AllocateNetworkOwnedContext(ctx, &entry, req); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ops.ReleaseNetwork(entry); err != nil {
			t.Error(err)
		}
	})
	rules, err := gatewayTables(entry)
	if err != nil {
		t.Fatal(err)
	}
	// The ruleset changed despite identical interface presence and addresses.
	if err := ops.runCmd(ctx, []string{"nft", "add", "rule", rules.HostFilterTable.Family, rules.HostFilterTable.Name, "forward", "counter"}); err != nil {
		t.Fatal(err)
	}
	if err := ops.AllocateNetworkOwnedContext(ctx, &entry, req); err == nil {
		t.Fatal("changed firewall accepted")
	}
	// A different generation occupying the veth name cannot be deleted by release.
	name := network.VethName(entry.VMID)
	if err := ops.runCmd(ctx, []string{"ip", "link", "set", "dev", name, "alias", "foreign"}); err != nil {
		t.Fatal(err)
	}
	if err := ops.ReleaseNetwork(entry); err == nil {
		t.Fatal("release deleted foreign veth")
	}
	if _, err := net.InterfaceByName(name); err != nil {
		t.Fatal("ownership refusal mutated foreign veth", err)
	}
	if err := ops.runCmd(ctx, []string{"ip", "link", "set", "dev", name, "alias", gatewayMarker(entry)}); err != nil {
		t.Fatal(err)
	}
	if err := ops.ReleaseNetwork(entry); err != nil {
		t.Fatal(err)
	}
}

// This backend isolates the durable server protocol, not packet behavior.
type gatewayFailureBackend struct {
	OpsBackend
	ledgerDirectory string
	sawIntent       bool
}

func (b *gatewayFailureBackend) AllocateNetwork(entry VMEntry, _ AllocateNetworkReq) error {
	_, err := os.Stat(filepath.Join(b.ledgerDirectory, entry.VMID+".json"))
	b.sawIntent = err == nil
	return errors.New("setup failure")
}
func (b *gatewayFailureBackend) ReleaseNetwork(VMEntry) error { return errors.New("unproven removal") }

func TestGatewayFailedRollbackRetainsDurableClaim(t *testing.T) {
	directory := t.TempDir()
	backend := &gatewayFailureBackend{ledgerDirectory: directory}
	server := NewServer(ServerCfg{LedgerDir: directory, Ops: backend})
	req := AllocateNetworkReq{VMID: "gateway-failure", CIDR: "10.99.0.12/30"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	response := server.handleAllocateNetwork(context.Background(), data)
	if response.OK || response.Cause != "outcome_unknown" {
		t.Fatalf("failed rollback: %+v", response)
	}
	if !backend.sawIntent {
		t.Fatal("kernel mutations preceded durable lease claim")
	}
	entry, err := server.ledger.get(req.VMID)
	if err != nil {
		t.Fatal(err)
	}
	if entry.NetCIDR != req.CIDR {
		t.Fatal("failed rollback discarded lease")
	}
}

func TestGatewayInventoryRejectsOversizedOutput(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "oversized-ip")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nhead -c 4194305 /dev/zero\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ops := NewRealOps(RealOpsCfg{IPPath: executable})
	if _, err := ops.netnsExists(context.Background(), "bounded-inventory"); err == nil {
		t.Fatal("oversized namespace inventory accepted")
	}
}

type gatewayRepeatBackend struct {
	OpsBackend
	calls int
}

func (b *gatewayRepeatBackend) AllocateNetwork(VMEntry, AllocateNetworkReq) error {
	b.calls++
	return nil
}
func TestGatewayRepeatedIncompleteIntentCannotMutate(t *testing.T) {
	backend := &gatewayRepeatBackend{}
	server := NewServer(ServerCfg{LedgerDir: t.TempDir(), Ops: backend})
	entry := VMEntry{VMID: "gateway-incomplete", NetCIDR: "10.99.0.16/30"}
	if err := server.ledger.put(entry); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(AllocateNetworkReq{VMID: entry.VMID, CIDR: entry.NetCIDR})
	if err != nil {
		t.Fatal(err)
	}
	response := server.handleAllocateNetwork(context.Background(), data)
	if response.OK {
		t.Fatal("incomplete intent completed without durable kernel identity")
	}
	if backend.calls != 0 {
		t.Fatal("revalidation mutated incomplete topology")
	}
}

func TestGatewayKernelNamespaceWithoutGenerationIsNotOwned(t *testing.T) {
	if os.Getenv("VMOBS_GATEWAY_LIFECYCLE") != "1" {
		t.Skip("requires opted-in isolated Linux container")
	}
	ops := NewRealOps(RealOpsCfg{})
	boot, _, err := hostIdentity()
	if err != nil {
		t.Fatal(err)
	}
	entry := VMEntry{VMID: "gateway-unmarked", NetCIDR: "10.99.0.20/30", GatewayGeneration: "0123456789abcdef0123456789abcdef", NetworkHostBootID: boot}
	ctx := context.Background()
	if err := ops.runCmd(ctx, []string{"ip", "netns", "add", network.NamespaceName(entry.VMID)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ops.runCmd(ctx, []string{"ip", "netns", "del", network.NamespaceName(entry.VMID)}) })
	var st unix.Stat_t
	if err := unix.Stat("/run/netns/"+network.NamespaceName(entry.VMID), &st); err != nil {
		t.Fatal(err)
	}
	entry.NetworkNamespaceDevice = uint64(st.Dev)
	entry.NetworkNamespaceInode = st.Ino
	if err := ops.ReleaseNetwork(entry); err == nil {
		t.Fatal("inode/name alone authorized deletion without generation marker")
	}
}

type gatewayProbeBackend struct {
	gatewayRepeatBackend
	probes int
}

func (b *gatewayProbeBackend) ProbeNetworkContext(context.Context, VMEntry, AllocateNetworkReq) error {
	b.probes++
	return errors.New("topology is absent")
}
func TestGatewayRepeatedCompleteClaimUsesReadOnlyProbe(t *testing.T) {
	backend := &gatewayProbeBackend{}
	server := NewServer(ServerCfg{LedgerDir: t.TempDir(), Ops: backend})
	entry := VMEntry{VMID: "gateway-probe", NetCIDR: "10.99.0.24/30", NetworkComplete: true}
	if err := server.ledger.put(entry); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(AllocateNetworkReq{VMID: entry.VMID, CIDR: entry.NetCIDR})
	if err != nil {
		t.Fatal(err)
	}
	response := server.handleAllocateNetwork(context.Background(), data)
	if response.OK || backend.probes != 1 || backend.calls != 0 {
		t.Fatalf("repeat called mutation path: response=%+v probes=%d mutations=%d", response, backend.probes, backend.calls)
	}
}

func TestGatewayHostOverlapRefusesBeforeKernelMutation(t *testing.T) {
	if os.Getenv("VMOBS_GATEWAY_LIFECYCLE") != "1" {
		t.Skip("requires opted-in isolated Linux container")
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "offline.json"), []byte(`{"schema_version":1,"id":"offline","profile":"offline","dns_upstream":"","allowed_tcp_ports":[],"extra_deny_prefixes":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	ops := NewRealOps(RealOpsCfg{PolicyDirectory: directory})
	ctx := context.Background()
	snapshot := func() string {
		t.Helper()
		var result strings.Builder
		for _, argv := range [][]string{{"ip", "-j", "-4", "address", "show"}, {"ip", "-j", "-4", "route", "show", "table", "all"}, {"ip", "netns", "list"}, {"nft", "list", "tables"}} {
			out, err := ops.commandOutput(ctx, argv, "")
			if err != nil {
				t.Fatal(err)
			}
			result.Write(out)
		}
		return result.String()
	}
	cases := []struct {
		name     string
		add, del []string
		late     bool
	}{
		{"lan", []string{"ip", "route", "add", "10.77.0.0/24", "dev", "lo"}, []string{"ip", "route", "del", "10.77.0.0/24", "dev", "lo"}, false},
		{"vpn", []string{"ip", "route", "add", "10.77.0.0/24", "dev", "lo", "table", "52"}, []string{"ip", "route", "del", "10.77.0.0/24", "dev", "lo", "table", "52"}, false},
		{"blackhole", []string{"ip", "route", "add", "blackhole", "10.77.0.0/24", "table", "52"}, []string{"ip", "route", "del", "blackhole", "10.77.0.0/24", "table", "52"}, false},
		{"late-route", []string{"ip", "route", "add", "10.77.0.0/24", "dev", "lo", "table", "52"}, []string{"ip", "route", "del", "10.77.0.0/24", "dev", "lo", "table", "52"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry := VMEntry{VMID: "gateway-overlap", NetCIDR: "10.77.0.4/30"}
			req := AllocateNetworkReq{VMID: entry.VMID, CIDR: entry.NetCIDR, Profile: "offline", PolicyID: "offline", GuestBootID: "b28581fb-7b8b-499a-8671-8bf54d159839"}
			if tc.late {
				if err := ops.PrepareNetworkEntry(ctx, &entry, req); err != nil {
					t.Fatal(err)
				}
			}
			if err := ops.runCmd(ctx, tc.add); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := ops.runCmd(ctx, tc.del); err != nil {
					t.Error(err)
				}
			})
			before := snapshot()
			var err error
			if tc.late {
				err = ops.AllocateNetworkOwnedContext(ctx, &entry, req)
			} else {
				err = ops.PrepareNetworkEntry(ctx, &entry, req)
			}
			if err == nil {
				t.Error("host-overlapping transit accepted")
			}
			after := snapshot()
			if after != before {
				t.Error("rejected overlap changed kernel state")
			}
			if entry.NetworkNamespaceInode != 0 {
				if err := ops.ReleaseNetwork(entry); err != nil {
					t.Error(err)
				}
			}
		})
	}
	t.Run("address-without-prefix-route", func(t *testing.T) {
		name := "vmobs-overlap"
		if err := ops.runCmd(ctx, []string{"ip", "link", "add", name, "type", "dummy"}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := ops.runCmd(ctx, []string{"ip", "link", "del", name}); err != nil {
				t.Error(err)
			}
		})
		if err := ops.runCmd(ctx, []string{"ip", "address", "add", "10.77.0.1/24", "dev", name, "noprefixroute"}); err != nil {
			t.Fatal(err)
		}
		entry := VMEntry{VMID: "gateway-overlap", NetCIDR: "10.77.0.4/30"}
		req := AllocateNetworkReq{VMID: entry.VMID, CIDR: entry.NetCIDR, Profile: "offline", PolicyID: "offline", GuestBootID: "b28581fb-7b8b-499a-8671-8bf54d159839"}
		before := snapshot()
		if err := ops.PrepareNetworkEntry(ctx, &entry, req); err == nil {
			t.Error("host IPv4 interface prefix overlap accepted")
		}
		if snapshot() != before {
			t.Error("address overlap refusal mutated kernel state")
		}
	})
}

type gatewaySlowRollbackBackend struct {
	OpsBackend
	deadlineSeen            bool
	cleanupStartedCancelled bool
}

func (b *gatewaySlowRollbackBackend) AllocateNetwork(VMEntry, AllocateNetworkReq) error {
	return context.DeadlineExceeded
}
func (b *gatewaySlowRollbackBackend) ReleaseNetwork(entry VMEntry) error {
	return b.ReleaseNetworkContext(context.Background(), entry)
}
func (b *gatewaySlowRollbackBackend) ReleaseNetworkContext(ctx context.Context, _ VMEntry) error {
	_, b.deadlineSeen = ctx.Deadline()
	b.cleanupStartedCancelled = ctx.Err() != nil
	return exec.CommandContext(ctx, "sleep", "2").Run()
}
func TestGatewayRollbackHasBoundedCleanupBudget(t *testing.T) {
	backend := &gatewaySlowRollbackBackend{}
	server := NewServer(ServerCfg{LedgerDir: t.TempDir(), Ops: backend, ExecutionTimeout: 50 * time.Millisecond})
	req := AllocateNetworkReq{VMID: "gateway-slow-cleanup", CIDR: "10.99.0.28/30"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	allocationCtx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	response := server.handleAllocateNetwork(allocationCtx, data)
	elapsed := time.Since(started)
	if !backend.deadlineSeen || backend.cleanupStartedCancelled || elapsed > time.Second {
		t.Errorf("rollback escaped execution budget: deadline=%v elapsed=%v", backend.deadlineSeen, elapsed)
	}
	if response.OK || response.Cause != "outcome_unknown" {
		t.Errorf("cleanup timeout outcome: %+v", response)
	}
	if _, err := server.ledger.get(req.VMID); err != nil {
		t.Errorf("cleanup timeout lost durable claim: %v", err)
	}
}

func TestGatewayHostInventoryFailsClosed(t *testing.T) {
	transit := netip.MustParsePrefix("10.77.0.4/30")
	cases := []struct {
		name, routes, addresses string
		reject                  bool
	}{
		{"default", `[{"dst":"default","gateway":"192.0.2.1","dev":"eth0"}]`, `[]`, false},
		{"null-routes", `null`, `[]`, true},
		{"null-addresses", `[]`, `null`, true},
		{"malformed-route", `[{"type":"blackhole","dst":"invalid"}]`, `[]`, true},
		{"wrong-route-type", `[{"type":7,"dst":"default"}]`, `[]`, true},
		{"unexpected-ipv6-route", `[{"dst":"2001:db8::/32"}]`, `[]`, true},
		{"unreachable", `[{"type":"unreachable","dst":"10.77.0.0/24"}]`, `[]`, true},
		{"prohibit", `[{"type":"prohibit","dst":"10.77.0.0/24"}]`, `[]`, true},
		{"throw", `[{"type":"throw","dst":"10.77.0.0/24"}]`, `[]`, true},
		{"local", `[{"type":"local","dst":"10.77.0.5"}]`, `[]`, true},
		{"broadcast", `[{"type":"broadcast","dst":"10.77.0.7"}]`, `[]`, true},
		{"blackhole-default", `[{"type":"blackhole","dst":"default"}]`, `[]`, true},
		{"invalid-address", `[]`, `[{"addr_info":[{"family":"inet","local":"bad","prefixlen":24}]}]`, true},
		{"missing-prefix-length", `[]`, `[{"addr_info":[{"family":"inet","local":"10.77.0.1"}]}]`, true},
		{"interface-prefix", `[]`, `[{"addr_info":[{"family":"inet","local":"10.77.0.1","prefixlen":24}]}]`, true},
		{"unrelated", `[{"dst":"192.0.2.0/24"}]`, `[{"addr_info":[{"family":"inet","local":"192.0.2.2","prefixlen":24}]}]`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateHostTransitInventory(transit, []byte(tc.routes), []byte(tc.addresses))
			if (err != nil) != tc.reject {
				t.Fatalf("reject=%v error=%v", tc.reject, err)
			}
		})
	}
}
