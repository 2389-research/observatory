// ABOUTME: Firecracker runtime builder for Linux: constructs the jailer adapter
// ABOUTME: from host config fields, resolving RunnerBin beside the daemon binary.

//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/2389-research/observatory/internal/config"
	"github.com/2389-research/observatory/internal/jailer"
	"github.com/2389-research/observatory/internal/network"
	"github.com/2389-research/observatory/internal/preflight"
	"github.com/2389-research/observatory/internal/privd"
	"github.com/2389-research/observatory/internal/runtime"
)

// maxSlotsWiring is the MaxSlots constant for the jailer adapter. The allocator
// carves sequential /30s; each slot holds one VM. 64 is consistent with aibox03's
// 32-CPU capacity doubled for headroom, and well within the /16 default pools
// (65534 /30s). No config knob per YAGNI — revisit if multi-host scale demands it.
const maxSlotsWiring = 64

// buildFirecrackerRuntime constructs the real Firecracker runtime adapter.
// Called only when cfg.Runtime.Mode == "firecracker" on Linux.
//
// Path derivations (fields with no dedicated config home):
//   - StageRoot = cfg.Paths.StageRoot()  (ephemeral staging under the runtime dir)
//   - JailBase  = cfg.Paths.JailBase()   (jailer chroot base under the runtime dir)
//   - SpoolRoot = cfg.Paths.State + "/spool"  (per-VM spool dirs under the state dir)
//   - RepoRoot  = cfg.Runtime.ArtifactRoot()  (the lock file's own directory: its artifact
//     paths, like "images/dist/vmlinux", are recorded relative to the tree the lock was
//     written from, so that tree is the only root they resolve against)
//
// The default lock_file is the relative "runtime.lock.json", so by default the
// artifacts are looked for under the daemon's working directory. An operator who
// runs the daemon from somewhere else must set an absolute lock_file pointing at
// the repo tree that holds images/dist.
//
// StageRoot and JailBase are config.Paths methods because the preflight doctor
// reads the same two paths; a second inline expression here would let the doctor
// and the adapter disagree about which host they are talking about.
//
// All derivations are recorded in task-12-report.md.
func buildFirecrackerRuntime(
	cfg *config.Config,
	pfFunc func(ctx context.Context, refresh bool) preflight.Report,
) (runtime.Runtime, error) {
	// Resolve the runner binary beside the daemon binary.
	execPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("runtime_mode firecracker: resolve daemon executable: %w", err)
	}
	runnerBin := filepath.Join(filepath.Dir(execPath), "vmobs-runner")
	if _, err := os.Stat(runnerBin); err != nil {
		return nil, fmt.Errorf("runtime_mode firecracker: runner binary not found at %s: %w", runnerBin, err)
	}

	// Build network allocator from live host routing table.
	routeJSON, err := exec.Command("ip", "-json", "route", "show", "table", "all").Output()
	if err != nil {
		return nil, fmt.Errorf("runtime_mode firecracker: get host routes (is 'ip' on PATH?): %w", err)
	}
	routes, err := network.ParseIPRoutes(routeJSON)
	if err != nil {
		return nil, fmt.Errorf("runtime_mode firecracker: parse ip routes: %w", err)
	}
	// Default pools matching the M0 fixture (boot_test.go). NewAllocator excludes
	// any pool that overlaps a host route and errors when all pools overlap.
	pools := []netip.Prefix{
		netip.MustParsePrefix("10.190.0.0/16"),
		netip.MustParsePrefix("10.191.0.0/16"),
	}
	pc := &privd.Client{SocketPath: cfg.Paths.PrivilegedSocket}
	// Exempt only exact routes whose manifest and privileged ownership agree.
	// A corrupt inventory grants no exemptions; the adapter retains its cleanup
	// and reconciliation paths, while refusing launch until ownership is known.
	if leases, leaseErr := jailer.NetworkLeases(cfg.Paths.State); leaseErr == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		claims, claimErr := pc.NetworkLeases(ctx)
		cancel()
		if claimErr == nil {
			for owner, prefix := range leases {
				if claims[owner] != prefix.String() {
					delete(leases, owner)
				}
			}
			routes = network.ExcludeOwnedRoutes(routes, leases)
		}
	}
	alloc, err := network.NewAllocator(routes, pools)
	if err != nil && !errors.Is(err, network.ErrAllPoolsOverlap) {
		return nil, fmt.Errorf("runtime_mode firecracker: build network allocator: %w", err)
	}

	// Assemble jailer Config. Paths without a dedicated config field are derived
	// from existing configured roots (see doc comment above).
	jCfg := jailer.Config{
		StateDir:    cfg.Paths.State,
		StageRoot:   cfg.Paths.StageRoot(),
		JailBase:    cfg.Paths.JailBase(),
		SpoolRoot:   filepath.Join(cfg.Paths.State, "spool"),
		RunnerBin:   runnerBin,
		RepoRoot:    cfg.Runtime.ArtifactRoot(),
		LockPath:    cfg.Runtime.LockFile,
		JailUIDBase: cfg.Runtime.JailUIDBase,
		JailGID:     cfg.Runtime.JailGID,
		MaxSlots:    maxSlotsWiring,
		CIDBase:     uint32(cfg.Runtime.CIDBase),
		Allocator:   alloc,
		Preflight:   pfFunc,
	}

	adapter, err := jailer.New(jCfg, pc)
	if err != nil {
		return nil, fmt.Errorf("runtime_mode firecracker: create jailer adapter: %w", err)
	}
	return adapter, nil
}
