// ABOUTME: Linux tests for privd network operations: argv construction and root-path lifecycle.
// ABOUTME: TestNetArgvConstruction runs everywhere; TestRealOpsNetworkLifecycle needs root.

//go:build linux

package privd_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/2389-research/observatory/internal/privd"
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
	t.Cleanup(func() {
		if err := ops.ReleaseNetwork(entry); err != nil {
			t.Errorf("cleanup real network: %v", err)
		}
	})

	// AllocateNetwork must succeed.
	if err := ops.AllocateNetwork(entry, req); err != nil {
		t.Fatalf("AllocateNetwork: %v", err)
	}

	// Idempotent: second call with same id must succeed (detects existing netns).
	if err := ops.AllocateNetwork(entry, req); err != nil {
		t.Errorf("AllocateNetwork idempotent: %v", err)
	}

	// A canceled real command must retain ownership of the surviving namespace.
	contextOps, ok := any(ops).(interface {
		ReleaseNetworkContext(context.Context, privd.VMEntry) error
	})
	if !ok {
		t.Fatal("network teardown cannot receive its execution budget")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := contextOps.ReleaseNetworkContext(canceled, entry); err == nil {
		t.Fatal("canceled teardown released a live network claim")
	}
	if err := ops.AllocateNetwork(entry, req); err != nil {
		t.Fatalf("canceled release damaged surviving network: %v", err)
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

// TestNetArgvConstruction verifies that NetSetupCommands and NetTeardownCommands
// produce the exact argv sequences the root helper uses, with no shell metacharacters.
func TestNetArgvConstruction(t *testing.T) {
	id := "vm-test-001"
	cidr := "10.0.0.0/30"
	ns := "vmobs-" + id
	veth := "veth-f1d5718dac" // sha256("vm-test-001")[:10], pinned — see network.VethName

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
	//   ip netns exec vmobs-<id> nft -f -  (stdin: NetSetupNFTScript())

	if len(setup) != 8 {
		t.Fatalf("NetSetupCommands: expected exactly 8 commands, got %d: %v", len(setup), setup)
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

	// Command 7 (nft): ip netns exec <ns> nft -f -  — must run inside the namespace.
	assertArgv(t, setup[7], "ip", "netns", "exec", ns, "nft", "-f", "-")

	// ---- Teardown command sequence verification ----
	// ip link del veth-<id>   (best-effort; error ignored in executor)
	// ip netns del vmobs-<id> (best-effort; error ignored in executor)
	if len(teardown) != 2 {
		t.Fatalf("NetTeardownCommands: expected 2 commands, got %d: %v", len(teardown), teardown)
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

// TestNetProbeCommands verifies that NetProbeCommands returns the exact argv sequences
// used to check whether a netns is fully configured.
func TestNetProbeCommands(t *testing.T) {
	id := "vm-probe-001"
	ns := "vmobs-" + id
	veth := "veth-1fed5eb0b3" // sha256("vm-probe-001")[:10], pinned — see network.VethName

	probes := privd.NetProbeCommands(id)

	if len(probes) != 3 {
		t.Fatalf("NetProbeCommands: expected 3 commands, got %d: %v", len(probes), probes)
	}

	// Probe 0: tap0 inside the netns
	assertArgv(t, probes[0], "ip", "netns", "exec", ns, "ip", "link", "show", "tap0")
	// Probe 1: eth-up inside the netns
	assertArgv(t, probes[1], "ip", "netns", "exec", ns, "ip", "link", "show", "eth-up")
	// Probe 2: veth-<id> on the host
	assertArgv(t, probes[2], "ip", "link", "show", veth)
}

// fakeRunner is an injectable command runner for non-root orchestration tests.
// It records which argv sequences were attempted and returns preset answers.
type fakeRunner struct {
	ran     [][]string
	answers map[string]error // keyed by strings.Join(argv, " ")
}

func (f *fakeRunner) run(argv []string) error {
	f.ran = append(f.ran, argv)
	key := strings.Join(argv, " ")
	if err, ok := f.answers[key]; ok {
		return err
	}
	return nil // success by default
}

// newFakeRunner creates a fakeRunner with a map of argv→error answers.
func newFakeRunner(answers map[string]error) *fakeRunner {
	return &fakeRunner{answers: answers}
}

// TestNetOrchestration_AbsentNetns verifies that when the netns does not exist
// (ip netns list returns empty), full setup runs.
func TestNetOrchestration_AbsentNetns(t *testing.T) {
	id := "vm-orch-001"
	ns := "vmobs-" + id

	runner := newFakeRunner(map[string]error{
		// ip netns list returns success but empty (no ns found) — simulated by default success
		// but the list output will contain no match; we fake via a special answer key for list.
		// We use a sentinel: list command returns error so the existence check returns false.
		// Actually we need to simulate output. Use the NotFoundError sentinel approach:
		// netnsExists parses output, so we fake the list cmd to succeed with no output.
		// But fakeRunner.run() just tracks errors, not stdout. We need the seam on
		// RealOps to accept a runner that also fakes the probe behavior.
		// The injectable runner handles all exec calls; the fake answers drive probe results.
		// ip netns list → no answer override → returns nil (success), but the fake needs
		// to report "absent". We use a special error sentinel for "netns list not found".
	})

	// For the absent case: ip netns list will be called; the fakeRunner records it and returns nil.
	// Because the fakeRunner records calls and the existence check uses the runner's output
	// (we inject a listOutput field), we use the richer FakeOpsForTest type.
	// See: the injectable runner on RealOps takes (argv []string) → error, but the
	// existence probe also needs stdout. So the seam must be broader.
	//
	// Instead, we use NetnsExistsFunc and ProbeHealthyFunc as the two injectable probes,
	// keeping RunCmd for the actual setup/teardown/nft commands.
	// This matches what the implementation exposes via RealOpsTestHooks.

	hooks := privd.RealOpsTestHooks{
		NetnsExists:  func(_ string) bool { return false },
		ProbeHealthy: nil, // not called when netns absent
		RunCmd:       runner.run,
	}

	cfg := privd.RealOpsCfg{NftPath: "/usr/sbin/nft", IPPath: "/usr/sbin/ip"}
	ops := privd.NewRealOpsWithHooks(cfg, hooks)

	entry := privd.VMEntry{VMID: id, NetCIDR: "10.0.0.0/30"}
	req := privd.AllocateNetworkReq{VMID: id, CIDR: entry.NetCIDR}
	if err := ops.AllocateNetwork(entry, req); err != nil {
		t.Fatalf("AllocateNetwork (absent): %v", err)
	}

	// All 8 setup commands must have run.
	want := privd.NetSetupCommands(id, entry.NetCIDR)
	if len(runner.ran) != len(want) {
		t.Fatalf("expected %d commands ran, got %d\n  ran: %v", len(want), len(runner.ran), runner.ran)
	}
	for i, argv := range want {
		assertArgv(t, runner.ran[i], argv...)
	}

	// Check nft ran inside the netns.
	assertArgv(t, runner.ran[7], "ip", "netns", "exec", ns, "nft", "-f", "-")
}

// TestNetOrchestration_PresentHealthy verifies that when netns exists and interfaces
// are all present, no setup commands run (return success immediately).
func TestNetOrchestration_PresentHealthy(t *testing.T) {
	id := "vm-orch-002"

	runner := newFakeRunner(nil)
	hooks := privd.RealOpsTestHooks{
		NetnsExists:  func(_ string) bool { return true },
		ProbeHealthy: func(_ string) bool { return true },
		RunCmd:       runner.run,
	}

	cfg := privd.RealOpsCfg{NftPath: "/usr/sbin/nft", IPPath: "/usr/sbin/ip"}
	ops := privd.NewRealOpsWithHooks(cfg, hooks)

	entry := privd.VMEntry{VMID: id, NetCIDR: "10.0.0.0/30"}
	req := privd.AllocateNetworkReq{VMID: id, CIDR: entry.NetCIDR}
	if err := ops.AllocateNetwork(entry, req); err != nil {
		t.Fatalf("AllocateNetwork (present+healthy): %v", err)
	}

	// No commands should have run — the healthy probe short-circuits.
	if len(runner.ran) != 0 {
		t.Errorf("expected 0 commands ran (healthy probe), got %d: %v", len(runner.ran), runner.ran)
	}
}

// TestNetOrchestration_PresentUnhealthy verifies that when netns exists but interfaces
// are missing, teardown runs first, then the full setup sequence.
func TestNetOrchestration_PresentUnhealthy(t *testing.T) {
	id := "vm-orch-003"

	runner := newFakeRunner(nil)
	hooks := privd.RealOpsTestHooks{
		NetnsExists:  func(_ string) bool { return true },
		ProbeHealthy: func(_ string) bool { return false }, // half-built remnant
		RunCmd:       runner.run,
	}

	cfg := privd.RealOpsCfg{NftPath: "/usr/sbin/nft", IPPath: "/usr/sbin/ip"}
	ops := privd.NewRealOpsWithHooks(cfg, hooks)

	entry := privd.VMEntry{VMID: id, NetCIDR: "10.0.0.0/30"}
	req := privd.AllocateNetworkReq{VMID: id, CIDR: entry.NetCIDR}
	if err := ops.AllocateNetwork(entry, req); err != nil {
		t.Fatalf("AllocateNetwork (present+unhealthy): %v", err)
	}

	// Teardown (2 cmds, best-effort) then full setup (8 cmds) = 10 total.
	teardown := privd.NetTeardownCommands(id)
	setup := privd.NetSetupCommands(id, entry.NetCIDR)
	wantTotal := len(teardown) + len(setup)
	if len(runner.ran) != wantTotal {
		t.Fatalf("expected %d commands (teardown+setup), got %d\n  ran: %v", wantTotal, len(runner.ran), runner.ran)
	}

	// First two: teardown.
	for i, argv := range teardown {
		assertArgv(t, runner.ran[i], argv...)
	}
	// Next eight: setup.
	offset := len(teardown)
	for i, argv := range setup {
		assertArgv(t, runner.ran[offset+i], argv...)
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

// A failed real executable lookup is unknown host state, even when every
// teardown command also failed. No fake network backend supplies this answer.
func TestReleaseNetworkRefusesUnavailableHostProbe(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	ops := privd.NewRealOps(privd.RealOpsCfg{})
	if err := ops.ReleaseNetwork(privd.VMEntry{VMID: "probe-unavailable"}); err == nil {
		t.Fatal("network release succeeded without executable teardown or host probe")
	}
}
