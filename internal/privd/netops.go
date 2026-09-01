// ABOUTME: RealOps network half: AllocateNetwork and ReleaseNetwork as argv execs.
// ABOUTME: Ports net-setup/net-teardown from scripts/aibox03/vmobs-root-helper, command for command.

//go:build linux

package privd

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
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

// RealOps implements OpsBackend with real host operations.
// AllocateNetwork and ReleaseNetwork are real in this task.
// StartVM, SignalVM, and ReleaseVM are stubbed until Task 4.
type RealOps struct {
	cfg RealOpsCfg
}

// Compile-time check: RealOps must satisfy OpsBackend.
var _ OpsBackend = (*RealOps)(nil)

// NewRealOps creates a RealOps using the given configuration.
func NewRealOps(cfg RealOpsCfg) *RealOps {
	return &RealOps{cfg: cfg}
}

// AllocateNetwork creates the per-VM network namespace, TAP device, veth pair,
// and an nftables default-deny forward chain — porting net-setup command for command.
// Idempotent: if the namespace already exists, returns success.
func (r *RealOps) AllocateNetwork(entry VMEntry, req AllocateNetworkReq) error {
	ctx := context.Background()

	// Idempotency check: if the netns already exists, treat as success.
	if r.netnsExists(ctx, entry.VMID) {
		return nil
	}

	cmds := NetSetupCommands(entry.VMID, req.CIDR)
	// All commands except the nft one run normally via runAll.
	normalCmds := cmds[:len(cmds)-1]
	nftCmd := cmds[len(cmds)-1]

	if err := runAll(ctx, normalCmds); err != nil {
		return err
	}

	// Run nft with the table script passed on stdin (matching `nft -f -` with a heredoc).
	nftScript := NetSetupNFTScript()
	/* #nosec G204 — nftCmd is built from NetSetupCommands, which uses the literal "nft" command name. */
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
		/* #nosec G204 — argv built from NetTeardownCommands, literal "ip" command. */
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec
		_ = cmd.Run()
	}
	return nil
}

// StartVM is not implemented until Task 4.
func (r *RealOps) StartVM(_ *VMEntry, _ StartVMReq) (StartVMResp, error) {
	return StartVMResp{}, fmt.Errorf("privd: StartVM not implemented until Task 4")
}

// SignalVM is not implemented until Task 4.
func (r *RealOps) SignalVM(_ VMEntry, _ string) error {
	return fmt.Errorf("privd: SignalVM not implemented until Task 4")
}

// ReleaseVM is not implemented until Task 4.
func (r *RealOps) ReleaseVM(_ VMEntry) error {
	return fmt.Errorf("privd: ReleaseVM not implemented until Task 4")
}

// netnsExists reports whether the network namespace for vmID is already present.
// Parses `ip netns list` output: each line is "<name> (id: <n>)" or just "<name>".
func (r *RealOps) netnsExists(ctx context.Context, vmID string) bool {
	nsName := namespaceName(vmID)
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

// NetSetupCommands returns the argv slices for net-setup, in order.
// The last element is ["nft", "-f", "-"]; its stdin must be NetSetupNFTScript().
// Pure function with no side effects so non-root tests can verify the exact sequence.
func NetSetupCommands(id, _ string) [][]string {
	// CIDR parameter is accepted for future anti-spoof address assignment (M3 scope).
	// The root helper's net-setup does not pass CIDR to any ip command either.
	ns := namespaceName(id)
	veth := vethName(id)

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
		// nft -f -  (stdin: NetSetupNFTScript())
		{"nft", "-f", "-"},
	}
}

// NetTeardownCommands returns the argv slices for net-teardown, in order.
// Both are best-effort: the caller must ignore errors (matching "|| true" in the helper).
func NetTeardownCommands(id string) [][]string {
	return [][]string{
		// ip link del veth-<id>  (best-effort; error ignored)
		{"ip", "link", "del", vethName(id)},
		// ip netns del vmobs-<id>  (best-effort; error ignored)
		{"ip", "netns", "del", namespaceName(id)},
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

// namespaceName is the package-local derivation of the netns name from a VM id.
// Matches network.NamespaceName: "vmobs-" + id.
func namespaceName(id string) string { return "vmobs-" + id }

// vethName is the package-local derivation of the host-side veth name from a VM id.
// Matches network.VethName: "veth-" + id.
func vethName(id string) string { return "veth-" + id }

// runAll executes a slice of argv arrays in order, stopping on the first failure.
// Each failure wraps the argv and bounded stderr (max 512 bytes) into the error.
func runAll(ctx context.Context, cmds [][]string) error {
	for _, argv := range cmds {
		/* #nosec G204 — argv arrays are assembled from literal string constants, never user input. */
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			stderrStr := truncateStderr(stderr.Bytes())
			return fmt.Errorf("privd: exec %v: %w: %s", argv, err, stderrStr)
		}
	}
	return nil
}

// truncateStderr caps stderr to 512 bytes as required — never inhale unbounded command output.
func truncateStderr(b []byte) string {
	const max = 512
	if len(b) > max {
		b = b[:max]
	}
	return strings.TrimSpace(string(b))
}
