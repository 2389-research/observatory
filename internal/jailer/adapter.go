// ABOUTME: Adapter implements runtime.Runtime via the §5.3 launch transaction.
// ABOUTME: One-at-a-time launches (launch mutex); Task 11 adds Stop/ForceStop/Reconcile.
package jailer

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/2389-research/observatory-v2/internal/network"
	"github.com/2389-research/observatory-v2/internal/preflight"
	"github.com/2389-research/observatory-v2/internal/privd"
	"github.com/2389-research/observatory-v2/internal/runtime"
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
	StateDir      string // <StateDir>/vms/<id>/ holds per-VM manifests, tokens, runner state
	StageRoot     string // staging directories live under <StageRoot>/<id>/
	JailBase      string // jailer chroot base; vsock path is <JailBase>/firecracker/<id>/root/v.sock
	SpoolRoot     string // spool directories live under <SpoolRoot>/<id>/
	RunnerBin     string // absolute path to the vmobs-runner binary
	RepoImagesDir string // directory containing vmlinux and rootfs.ext4
	LockPath      string // path to runtime.lock.json

	JailUIDBase int    // UID = JailUIDBase + Slot
	JailGID     int    // shared GID for all jail processes
	MaxSlots    int    // maximum concurrent VMs
	CIDBase     uint32 // vsock CID = CIDBase + Slot

	Allocator *network.Allocator // CIDR allocator; caller must not use concurrently
	Preflight func(ctx context.Context, refresh bool) preflight.Report
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
		cfg.SpoolRoot == "" || cfg.RunnerBin == "" || cfg.RepoImagesDir == "" ||
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
	return &Adapter{cfg: cfg, pc: pc}, nil
}

// Availability checks whether the host can launch a VM right now.
// Delegates to the Preflight func; Task 11 adds full doctor-gated logic.
func (a *Adapter) Availability(ctx context.Context) error {
	if a.cfg.Preflight == nil {
		return nil
	}
	rep := a.cfg.Preflight(ctx, false)
	if rep.Overall == preflight.StatusFail {
		return &runtime.UnavailableError{Reason: "preflight failed: " + rep.Summary()}
	}
	return nil
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

// Stop is not implemented until Task 11.
// Returns a typed error — never a fake success.
func (a *Adapter) Stop(_ context.Context, _ string, _ time.Duration) (bool, error) {
	return false, &runtime.UnavailableError{Reason: "Stop not implemented until Task 11"}
}

// ForceStop is not implemented until Task 11.
func (a *Adapter) ForceStop(_ context.Context, _ string) error {
	return &runtime.UnavailableError{Reason: "ForceStop not implemented until Task 11"}
}

// Note: Launch is implemented in launch.go (//go:build linux).
// The runtime.Runtime compile-time check lives there.
