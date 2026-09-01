// ABOUTME: Linux tests for privd network operations: argv construction and root-path lifecycle.
// ABOUTME: TestNetArgvConstruction runs everywhere; TestRealOpsNetworkLifecycle needs root.

//go:build linux

package privd_test

import (
	"os"
	"strings"
	"testing"

	"github.com/2389-research/observatory-v2/internal/privd"
)

// TestRealOpsNetworkLifecycle exercises AllocateNetwork + ReleaseNetwork against real
// kernel network namespaces. Skip unless running as root — real kernel ops need it.
func TestRealOpsNetworkLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root — run under privd's own integration path")
	}

	cfg := privd.RealOpsCfg{
		JailBase:        "/tmp/vmobs-test-jail",
		StageRoot:       "/tmp/vmobs-test-stage",
		FirecrackerPath: "/usr/local/bin/firecracker",
		JailerPath:      "/usr/local/bin/jailer",
		NftPath:         "/usr/sbin/nft",
		IPPath:          "/usr/sbin/ip",
	}

	ops := privd.NewRealOps(cfg)

	entry := privd.VMEntry{
		VMID:    "test-net-001",
		NetCIDR: "10.99.0.0/30",
	}
	req := privd.AllocateNetworkReq{
		VMID: entry.VMID,
		CIDR: entry.NetCIDR,
	}

	// AllocateNetwork must succeed.
	if err := ops.AllocateNetwork(entry, req); err != nil {
		t.Fatalf("AllocateNetwork: %v", err)
	}

	// Idempotent: second call with same id must succeed (detects existing netns).
	if err := ops.AllocateNetwork(entry, req); err != nil {
		t.Errorf("AllocateNetwork idempotent: %v", err)
	}

	// ReleaseNetwork must succeed.
	if err := ops.ReleaseNetwork(entry); err != nil {
		t.Fatalf("ReleaseNetwork: %v", err)
	}

	// Idempotent: teardown of an absent netns must also succeed.
	if err := ops.ReleaseNetwork(entry); err != nil {
		t.Errorf("ReleaseNetwork idempotent: %v", err)
	}
}

// TestNetArgvConstruction verifies that netSetupCommands and netTeardownCommands
// produce the exact argv sequences the root helper uses, with no shell metacharacters.
func TestNetArgvConstruction(t *testing.T) {
	id := "vm-test-001"
	cidr := "10.0.0.0/30"
	ns := "vmobs-" + id
	veth := "veth-" + id

	setup := privd.NetSetupCommands(id, cidr)
	teardown := privd.NetTeardownCommands(id)

	// ---- Setup command sequence verification ----
	// The root helper's net-setup, command for command:
	//   ip netns add vmobs-<id>
	//   ip netns exec vmobs-<id> ip link set lo up
	//   ip netns exec vmobs-<id> ip tuntap add dev tap0 mode tap
	//   ip netns exec vmobs-<id> ip link set tap0 up
	//   ip link add veth-<id> type veth peer name eth-up netns vmobs-<id>
	//   ip link set veth-<id> up
	//   ip netns exec vmobs-<id> ip link set eth-up up
	//   nft -f - <<EOF (stdin: the nft table definition)
	//     => split into: nft with the stdin text as a separate -f /dev/stdin or via a file approach.
	//     The Go port passes the nft script as stdin to nft -f /dev/stdin.
	//
	// This test checks exact argv slices (not stdin).

	if len(setup) < 7 {
		t.Fatalf("netSetupCommands: expected ≥7 commands, got %d: %v", len(setup), setup)
	}

	// Command 0: ip netns add <ns>
	assertArgv(t, setup[0], "ip", "netns", "add", ns)

	// Command 1: ip netns exec <ns> ip link set lo up
	assertArgv(t, setup[1], "ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")

	// Command 2: ip netns exec <ns> ip tuntap add dev tap0 mode tap
	assertArgv(t, setup[2], "ip", "netns", "exec", ns, "ip", "tuntap", "add", "dev", "tap0", "mode", "tap")

	// Command 3: ip netns exec <ns> ip link set tap0 up
	assertArgv(t, setup[3], "ip", "netns", "exec", ns, "ip", "link", "set", "tap0", "up")

	// Command 4: ip link add veth-<id> type veth peer name eth-up netns <ns>
	assertArgv(t, setup[4], "ip", "link", "add", veth, "type", "veth", "peer", "name", "eth-up", "netns", ns)

	// Command 5: ip link set veth-<id> up
	assertArgv(t, setup[5], "ip", "link", "set", veth, "up")

	// Command 6: ip netns exec <ns> ip link set eth-up up
	assertArgv(t, setup[6], "ip", "netns", "exec", ns, "ip", "link", "set", "eth-up", "up")

	// Command 7 (nft): nft -f /dev/stdin  — check prefix and no shell metacharacters.
	if len(setup) < 8 {
		t.Fatalf("netSetupCommands: expected ≥8 commands (including nft), got %d", len(setup))
	}
	nftCmd := setup[7]
	if len(nftCmd) < 2 || nftCmd[0] != "nft" {
		t.Errorf("setup[7] should start with 'nft', got %v", nftCmd)
	}

	// ---- Teardown command sequence verification ----
	// ip link del veth-<id>   (best-effort; error ignored in executor)
	// ip netns del vmobs-<id> (best-effort; error ignored in executor)
	if len(teardown) != 2 {
		t.Fatalf("netTeardownCommands: expected 2 commands, got %d: %v", len(teardown), teardown)
	}
	assertArgv(t, teardown[0], "ip", "link", "del", veth)
	assertArgv(t, teardown[1], "ip", "netns", "del", ns)

	// ---- No shell metacharacters ----
	shellMeta := []string{";", "&", "|", "`", "$", "<", ">", "\\", "'", "\"", "~", "!", "{", "}"}
	allCmds := append(setup, teardown...)
	for i, cmd := range allCmds {
		for _, arg := range cmd {
			for _, meta := range shellMeta {
				if strings.Contains(arg, meta) {
					t.Errorf("command[%d] arg %q contains shell metacharacter %q", i, arg, meta)
				}
			}
		}
	}

	// ---- NFT script content check ----
	// The nft stdin script must declare: table inet vmobs, chain forward (drop policy),
	// chain output (accept), chain input (accept).
	nftStdin := privd.NetSetupNFTScript()
	for _, want := range []string{
		"table inet vmobs",
		"chain forward",
		"policy drop",
		"chain output",
		"policy accept",
		"chain input",
		"policy accept",
	} {
		if !strings.Contains(nftStdin, want) {
			t.Errorf("NFT script missing %q; script:\n%s", want, nftStdin)
		}
	}
}

// assertArgv checks that got matches the want argv exactly.
func assertArgv(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("argv len = %d, want %d\n  got:  %v\n  want: %v", len(got), len(want), got, want)
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q\n  got:  %v\n  want: %v", i, got[i], want[i], got, want)
		}
	}
}
