// ABOUTME: Hosts configuration and bounded command execution for privileged VM operations.
// ABOUTME: Delegates network allocation and teardown to the bound closed gateway lifecycle.

//go:build linux

package privd

import (
	"context"
	"fmt"
	"log"
	"os"
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
	PolicyDirectory string // root-owned directory of explicit policy files
}

// RealOpsTestHooks allows non-root tests to inject fake probes and a recording runner.
// All fields are optional; a nil field falls back to the real implementation.
type RealOpsTestHooks struct {
	// NetnsExists reports whether the named netns is present (replaces ip-netns-list probe).
	NetnsExists func(vmID string) bool
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

// AllocateNetwork validates a previously prepared durable ownership record.
func (r *RealOps) AllocateNetwork(entry VMEntry, req AllocateNetworkReq) error {
	return r.AllocateNetworkContext(context.Background(), entry, req)
}

// AllocateNetworkContext does not mint ownership outside the server's durable intent.
func (r *RealOps) AllocateNetworkContext(ctx context.Context, entry VMEntry, req AllocateNetworkReq) error {
	return r.AllocateNetworkOwnedContext(ctx, &entry, req)
}

// ReleaseNetwork removes only resources whose generation and kernel identity match.
func (r *RealOps) ReleaseNetwork(entry VMEntry) error {
	return r.ReleaseNetworkContext(context.Background(), entry)
}

// netnsExists reports whether the network namespace for vmID is present.
// Uses hooks.NetnsExists when injected (non-root tests); otherwise parses `ip netns list`.
func (r *RealOps) netnsExists(ctx context.Context, vmID string) (bool, error) {
	if r.hooks.NetnsExists != nil {
		return r.hooks.NetnsExists(vmID), nil
	}
	nsName := network.NamespaceName(vmID)
	out, err := r.commandOutput(ctx, []string{r.ipPath(), "netns", "list"}, "")
	if err != nil {
		return false, fmt.Errorf("privd: probe network namespaces: %w", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		// Each line: "nsname (id: N)" — the name is the first whitespace-delimited token.
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == nsName {
			return true, nil
		}
	}
	return false, nil
}

// runCmd executes a single argv array. Uses hooks.RunCmd when injected.
func (r *RealOps) runCmd(ctx context.Context, argv []string) error {
	if r.hooks.RunCmd != nil {
		return r.hooks.RunCmd(argv)
	}
	_, err := r.commandOutput(ctx, argv, "")
	return err
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

// truncateStderr caps stderr to 512 bytes as required — never inhale unbounded command output.
func truncateStderr(b []byte) string {
	const max = 512
	if len(b) > max {
		b = b[:max]
	}
	return strings.TrimSpace(string(b))
}
