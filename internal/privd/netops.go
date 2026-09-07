// ABOUTME: RealOps network half: AllocateNetwork and ReleaseNetwork as argv execs.
// ABOUTME: Ports net-setup/net-teardown from the M0 fixture's vmobs-root-helper, command for command.

//go:build linux

package privd

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/2389-research/observatory/internal/network"
)

// RealOpsCfg holds the configuration for RealOps.
type RealOpsCfg struct {
	JailBase        string // root for jailer workdirs
	StageRoot       string // approved root for VM stage directories
	FirecrackerPath string // absolute path to firecracker binary
	JailerPath      string // absolute path to jailer binary
	NftPath         string // absolute path to nft binary (e.g. /usr/sbin/nft)
	IPPath          string // absolute path to ip binary (e.g. /usr/sbin/ip)
}

// RealOpsTestHooks allows non-root tests to inject fake probes and a recording runner.
// All fields are optional; a nil field falls back to the real implementation.
type RealOpsTestHooks struct {
	// NetnsExists reports whether the named netns is present (replaces ip-netns-list probe).
	NetnsExists func(vmID string) bool
	// ProbeHealthy reports whether all expected interfaces exist inside an existing netns.
	ProbeHealthy func(vmID string) bool
	// RunCmd replaces exec.CommandContext for setup/teardown/nft commands.
	RunCmd func(argv []string) error
}

// RealOps implements OpsBackend with real host operations.
type RealOps struct {
	cfg   RealOpsCfg
	hooks RealOpsTestHooks
	log   *log.Logger
}

// Compile-time check: RealOps must satisfy OpsBackend.
var _ OpsBackend = (*RealOps)(nil)

// NewRealOps creates a RealOps using the given configuration.
func NewRealOps(cfg RealOpsCfg) *RealOps {
	return &RealOps{cfg: cfg, log: log.New(os.Stderr, "privd: ", log.LstdFlags)}
}

// NewRealOpsWithHooks creates a RealOps with injectable hooks for non-root testing.
func NewRealOpsWithHooks(cfg RealOpsCfg, hooks RealOpsTestHooks) *RealOps {
	return &RealOps{cfg: cfg, hooks: hooks, log: log.New(os.Stderr, "privd: ", log.LstdFlags)}
}

// AllocateNetwork creates the per-VM network namespace, TAP device, veth pair,
// and an nftables default-deny forward chain — porting net-setup command for command.
//
// Idempotency (controller ruling R5):
//   - netns absent: run full setup.
//   - netns present + all interfaces healthy: return success, skip setup.
//   - netns present + interfaces missing (half-built remnant): teardown then full setup.
func (r *RealOps) AllocateNetwork(entry VMEntry, req AllocateNetworkReq) error {
	ctx := context.Background()

	if r.netnsExists(ctx, entry.VMID) {
		if r.probeHealthy(ctx, entry.VMID) {
			// Already fully configured — nothing to do.
			return nil
		}
		// Half-built remnant: tear it down (best-effort) then fall through to full setup.
		tearCmds := NetTeardownCommands(entry.VMID)
		for _, argv := range tearCmds {
			_ = r.runCmd(ctx, argv) // best-effort, errors ignored
		}
	}

	cmds := NetSetupCommands(entry.VMID, req.CIDR)
	// All commands except the last (nft) run via runAll.
	// The nft command receives the table script on stdin.
	normalCmds := cmds[:len(cmds)-1]
	nftCmd := cmds[len(cmds)-1]

	if err := r.runAll(ctx, normalCmds); err != nil {
		return err
	}

	// Run nft with the table script passed on stdin (matching `ip netns exec <ns> nft -f -`).
	nftScript := NetSetupNFTScript()
	if r.hooks.RunCmd != nil {
		// Test path: pass the nft argv through the fake runner (stdin not needed for argv tests).
		if err := r.hooks.RunCmd(nftCmd); err != nil {
			return fmt.Errorf("privd: exec %v: %w", nftCmd, err)
		}
		return nil
	}
	/* #nosec G204 — nftCmd is built from NetSetupCommands, literal command elements only. */
	cmd := exec.CommandContext(ctx, nftCmd[0], nftCmd[1:]...) //nolint:gosec
	cmd.Stdin = strings.NewReader(nftScript)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		stderrStr := truncateStderr(stderr.Bytes())
		return fmt.Errorf("privd: exec %v: %w: %s", nftCmd, err, stderrStr)
	}
	return nil
}

// ReleaseNetwork tears down the veth pair and network namespace — porting net-teardown.
// Idempotent: teardown of an absent netns returns success (both commands are best-effort).
func (r *RealOps) ReleaseNetwork(entry VMEntry) error {
	ctx := context.Background()
	cmds := NetTeardownCommands(entry.VMID)
	// Best-effort: errors suppressed, matching the helper's "2>/dev/null || true" pattern.
	for _, argv := range cmds {
		_ = r.runCmd(ctx, argv)
	}
	return nil
}

// netnsExists reports whether the network namespace for vmID is present.
// Uses hooks.NetnsExists when injected (non-root tests); otherwise parses `ip netns list`.
func (r *RealOps) netnsExists(ctx context.Context, vmID string) bool {
	if r.hooks.NetnsExists != nil {
		return r.hooks.NetnsExists(vmID)
	}
	nsName := network.NamespaceName(vmID)
	/* #nosec G204 — literal "ip" command, not user input. */
	cmd := exec.CommandContext(ctx, "ip", "netns", "list") //nolint:gosec
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		// Each line: "nsname (id: N)" — the name is the first whitespace-delimited token.
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == nsName {
			return true
		}
	}
	return false
}

// probeHealthy reports whether all expected interfaces exist inside an existing netns.
// Checks: tap0 inside the netns, eth-up inside the netns, veth-<id> on the host.
// Uses hooks.ProbeHealthy when injected; otherwise runs the real exec probes.
func (r *RealOps) probeHealthy(ctx context.Context, vmID string) bool {
	if r.hooks.ProbeHealthy != nil {
		return r.hooks.ProbeHealthy(vmID)
	}
	for _, argv := range NetProbeCommands(vmID) {
		/* #nosec G204 — argv built from NetProbeCommands, literal command elements only. */
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec
		if err := cmd.Run(); err != nil {
			// "does not exist" exits non-zero — a probe failure is a NO, not an error.
			return false
		}
	}
	return true
}

// runCmd executes a single argv array. Uses hooks.RunCmd when injected.
func (r *RealOps) runCmd(ctx context.Context, argv []string) error {
	if r.hooks.RunCmd != nil {
		return r.hooks.RunCmd(argv)
	}
	/* #nosec G204 — argv arrays are assembled from literal string constants, never user input. */
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		stderrStr := truncateStderr(stderr.Bytes())
		return fmt.Errorf("privd: exec %v: %w: %s", argv, err, stderrStr)
	}
	return nil
}

// runAll executes a slice of argv arrays in order via runCmd, stopping on first failure.
func (r *RealOps) runAll(ctx context.Context, cmds [][]string) error {
	for _, argv := range cmds {
		if err := r.runCmd(ctx, argv); err != nil {
			return err
		}
	}
	return nil
}

// NetSetupCommands returns the argv slices for net-setup, in order.
// The last element is ["ip", "netns", "exec", <ns>, "nft", "-f", "-"]; its stdin
// must be NetSetupNFTScript(). Pure function — non-root tests assert the exact sequence.
func NetSetupCommands(id, _ string) [][]string {
	// CIDR parameter is accepted for future anti-spoof address assignment (M3 scope).
	// The root helper's net-setup does not pass CIDR to any ip command either.
	ns := network.NamespaceName(id)
	veth := network.VethName(id)

	return [][]string{
		// ip netns add vmobs-<id>
		{"ip", "netns", "add", ns},
		// ip netns exec vmobs-<id> ip link set lo up
		{"ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"},
		// ip netns exec vmobs-<id> ip tuntap add dev tap0 mode tap
		{"ip", "netns", "exec", ns, "ip", "tuntap", "add", "dev", "tap0", "mode", "tap"},
		// ip netns exec vmobs-<id> ip link set tap0 up
		{"ip", "netns", "exec", ns, "ip", "link", "set", "tap0", "up"},
		// ip link add veth-<id> type veth peer name eth-up netns vmobs-<id>
		{"ip", "link", "add", veth, "type", "veth", "peer", "name", "eth-up", "netns", ns},
		// ip link set veth-<id> up
		{"ip", "link", "set", veth, "up"},
		// ip netns exec vmobs-<id> ip link set eth-up up
		{"ip", "netns", "exec", ns, "ip", "link", "set", "eth-up", "up"},
		// ip netns exec vmobs-<id> nft -f -  (stdin: NetSetupNFTScript())
		// Must run INSIDE the namespace — matches root helper line 47.
		{"ip", "netns", "exec", ns, "nft", "-f", "-"},
	}
}

// NetTeardownCommands returns the argv slices for net-teardown, in order.
// Both are best-effort: the caller must ignore errors (matching "|| true" in the helper).
func NetTeardownCommands(id string) [][]string {
	return [][]string{
		// ip link del veth-<id>  (best-effort; error ignored)
		{"ip", "link", "del", network.VethName(id)},
		// ip netns del vmobs-<id>  (best-effort; error ignored)
		{"ip", "netns", "del", network.NamespaceName(id)},
	}
}

// NetProbeCommands returns argv slices that check whether a netns is fully configured.
// A probe exec failing with non-zero exit means the interface does not exist (NO answer).
// Three probes: tap0 inside netns, eth-up inside netns, veth-<id> on the host.
func NetProbeCommands(id string) [][]string {
	ns := network.NamespaceName(id)
	veth := network.VethName(id)
	return [][]string{
		// ip netns exec vmobs-<id> ip link show tap0
		{"ip", "netns", "exec", ns, "ip", "link", "show", "tap0"},
		// ip netns exec vmobs-<id> ip link show eth-up
		{"ip", "netns", "exec", ns, "ip", "link", "show", "eth-up"},
		// ip link show veth-<id>
		{"ip", "link", "show", veth},
	}
}

// NetSetupNFTScript returns the nftables ruleset passed on stdin to `nft -f -`.
// Creates a vmobs table with default-deny forward, accept output and input — matching
// the root helper's heredoc verbatim.
func NetSetupNFTScript() string {
	return `table inet vmobs {
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output  { type filter hook output  priority 0; policy accept; }
  chain input   { type filter hook input   priority 0; policy accept; }
}
`
}

// truncateStderr caps stderr to 512 bytes as required — never inhale unbounded command output.
func truncateStderr(b []byte) string {
	const max = 512
	if len(b) > max {
		b = b[:max]
	}
	return strings.TrimSpace(string(b))
}
