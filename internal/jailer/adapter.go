// ABOUTME: Adapter implements runtime.Runtime via the §5.3 launch transaction and lifecycle ops.
// ABOUTME: One-at-a-time launches (launch mutex); Stop/ForceStop/Release/Reconcile in stop.go.
package jailer

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/2389-research/observatory/internal/network"
	"github.com/2389-research/observatory/internal/preflight"
	"github.com/2389-research/observatory/internal/privd"
	"github.com/2389-research/observatory/internal/runtime"
)

// privdClient is the package-local interface consumed by the adapter.
// The AT-005 seam: Task 13 injects failures through this interface.
// The real *privd.Client satisfies this interface.
type privdClient interface {
	AllocateNetwork(ctx context.Context, req privd.AllocateNetworkReq) error
	ReleaseNetwork(ctx context.Context, req privd.ReleaseNetworkReq) error
	StartVM(ctx context.Context, req privd.StartVMReq) (privd.StartVMResp, error)
	SignalVM(ctx context.Context, req privd.SignalVMReq) error
	ReleaseVM(ctx context.Context, req privd.ReleaseVMReq) error
}

// Config holds all static configuration for the Adapter.
type Config struct {
	StateDir  string // <StateDir>/vms/<id>/ holds per-VM manifests, tokens, runner state
	StageRoot string // staging directories live under <StageRoot>/<id>/
	JailBase  string // jailer chroot base; vsock path is <JailBase>/firecracker/<id>/root/v.sock
	SpoolRoot string // spool directories live under <SpoolRoot>/<id>/
	RunnerBin string // absolute path to the vmobs-runner binary
	RepoRoot  string // directory the lock's artifact paths resolve against (the runtime lock file's own directory — config.Runtime.ArtifactRoot())
	LockPath  string // path to runtime.lock.json

	// PrivdSocket is the path to the vmobs-privd unix socket. Used by the
	// guest_channel preflight check (connect + close with a 1s timeout).
	PrivdSocket string

	JailUIDBase int    // UID = JailUIDBase + Slot
	JailGID     int    // shared GID for all jail processes
	MaxSlots    int    // maximum concurrent VMs
	CIDBase     uint32 // vsock CID = CIDBase + Slot

	Allocator *network.Allocator // atomic CIDR lease cache reconstructed from manifests
	Preflight func(ctx context.Context, refresh bool) preflight.Report

	// AttachTimeout overrides the default 60s attach-wait deadline. Zero means 60s.
	// Production code never sets this; tests use it to bound the wrong-token subtest.
	AttachTimeout time.Duration
}

// Adapter implements runtime.Runtime using the real Firecracker/jailer pipeline.
// Satisfies runtime.Runtime; Availability/Stop/ForceStop/Reconcile land in Task 11.
type Adapter struct {
	cfg Config
	pc  privdClient

	// launchMu serialises Launch calls — one transaction at a time.
	// Concurrent CreateVM calls queue here; the comment is the spec.
	launchMu sync.Mutex
}

// New constructs an Adapter. Returns an error if cfg is obviously invalid.
func New(cfg Config, pc privdClient) (*Adapter, error) {
	if cfg.StateDir == "" || cfg.StageRoot == "" || cfg.JailBase == "" ||
		cfg.SpoolRoot == "" || cfg.RunnerBin == "" || cfg.RepoRoot == "" ||
		cfg.LockPath == "" {
		return nil, errors.New("jailer: Config missing required path field")
	}
	if cfg.MaxSlots <= 0 {
		return nil, fmt.Errorf("jailer: MaxSlots must be > 0")
	}
	if cfg.Allocator == nil {
		return nil, errors.New("jailer: Allocator is required")
	}
	if pc == nil {
		return nil, errors.New("jailer: privd client is required")
	}
	a := &Adapter{cfg: cfg, pc: pc}
	// An unreadable inventory must not prevent reconciliation or deletion.
	// Launch and Availability report it and refuse new allocation until repaired.
	_ = a.restoreNetworkLeases()
	return a, nil
}

// Availability checks whether the host can launch a VM right now.
// AT-001: the first check with Status=="fail" becomes the UnavailableError reason,
// formatted as "<check.ID>: <check.Summary>" so the operator knows exactly what failed.
func (a *Adapter) Availability(ctx context.Context) error {
	if _, err := NetworkLeases(a.cfg.StateDir); err != nil {
		return &runtime.UnavailableError{Reason: err.Error()}
	}
	if a.cfg.Preflight == nil {
		return nil
	}
	rep := a.cfg.Preflight(ctx, false)
	if rep.Overall != preflight.StatusFail {
		return nil
	}
	for _, c := range rep.Checks {
		if c.Status == preflight.StatusFail {
			return &runtime.UnavailableError{Reason: c.ID + ": " + c.Summary}
		}
	}
	// No individual fail check found (shouldn't happen if Overall=fail) — use summary.
	return &runtime.UnavailableError{Reason: "preflight failed: " + rep.Summary()}
}

// Pause returns a typed error: VMM pause is not supported in M1a.
// Pause capability is planned for a later milestone.
func (a *Adapter) Pause(_ context.Context, _ string) error {
	return &runtime.UnavailableError{Reason: "pause not supported in M1a"}
}

// Resume returns a typed error: VMM resume is not supported in M1a.
func (a *Adapter) Resume(_ context.Context, _ string) error {
	return &runtime.UnavailableError{Reason: "resume not supported in M1a (paired with Pause)"}
}

// Note: Stop, ForceStop, Release, and Reconcile are implemented in stop.go (//go:build linux).
// Launch is in launch.go (//go:build linux). The runtime.Runtime compile-time check lives there.
// Non-linux stubs for Stop/ForceStop/Release live in stop_other.go.

// restoreNetworkLeases rebuilds occupancy from manifests and privileged claims.
// Launch holds launchMu, so a release cannot remove a manifest during the scan.
func (a *Adapter) restoreNetworkLeases() error {
	leases, err := NetworkLeases(a.cfg.StateDir)
	if err != nil {
		return err
	}
	inventory, ok := a.pc.(interface {
		NetworkLeases(context.Context) (map[string]string, error)
	})
	if !ok {
		return errors.New("jailer: privileged network lease inventory unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	claims, err := inventory.NetworkLeases(ctx)
	if err != nil {
		return fmt.Errorf("jailer: privileged network lease inventory: %w", err)
	}
	for owner, cidr := range claims {
		prefix, err := netip.ParsePrefix(cidr)
		if !privd.ValidVMID(owner) || err != nil || !prefix.Addr().Is4() || prefix.Bits() != 30 || prefix != prefix.Masked() {
			return fmt.Errorf("jailer: invalid privileged network lease %q %q", owner, cidr)
		}
		if manifest, exists := leases[owner]; exists && manifest != prefix {
			return fmt.Errorf("jailer: network lease disagreement for %s: manifest %s, privd %s", owner, manifest, prefix)
		}
		leases[owner] = prefix
	}
	for owner, p := range leases {
		if err := a.cfg.Allocator.Restore(owner, p); err != nil {
			return err
		}
	}
	return nil
}
