// ABOUTME: Firecracker runtime builder for Linux: constructs the jailer adapter
// ABOUTME: from host config fields, resolving RunnerBin beside the daemon binary.

//go:build linux

package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/2389-research/observatory-v2/internal/config"
	"github.com/2389-research/observatory-v2/internal/jailer"
	"github.com/2389-research/observatory-v2/internal/network"
	"github.com/2389-research/observatory-v2/internal/preflight"
	"github.com/2389-research/observatory-v2/internal/privd"
	"github.com/2389-research/observatory-v2/internal/runtime"
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
//   - StageRoot     = cfg.Paths.Runtime + "/stage"       (ephemeral staging under the runtime dir)
//   - JailBase      = cfg.Paths.Runtime + "/jail"        (jailer chroot base under the runtime dir)
//   - SpoolRoot     = cfg.Paths.State   + "/spool"       (per-VM spool dirs under the state dir)
//   - RepoImagesDir = cfg.Paths.State   + "/images/dist" (where vmlinux + rootfs.ext4 live)
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
		return nil, fmt.Errorf("runtime_mode firecracker: get host routes: %w", err)
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
	alloc, err := network.NewAllocator(routes, pools)
	if err != nil {
		return nil, fmt.Errorf("runtime_mode firecracker: build network allocator: %w", err)
	}

	// Build privd client.
	pc := &privd.Client{SocketPath: cfg.Paths.PrivilegedSocket}

	// Assemble jailer Config. Paths without a dedicated config field are derived
	// from existing configured roots (see doc comment above).
	jCfg := jailer.Config{
		StateDir:      cfg.Paths.State,
		StageRoot:     filepath.Join(cfg.Paths.Runtime, "stage"),
		JailBase:      filepath.Join(cfg.Paths.Runtime, "jail"),
		SpoolRoot:     filepath.Join(cfg.Paths.State, "spool"),
		RunnerBin:     runnerBin,
		RepoImagesDir: filepath.Join(cfg.Paths.State, "images", "dist"),
		LockPath:      cfg.Runtime.LockFile,
		PrivdSocket:   cfg.Paths.PrivilegedSocket,
		JailUIDBase:   cfg.Runtime.JailUIDBase,
		JailGID:       cfg.Runtime.JailGID,
		MaxSlots:      maxSlotsWiring,
		CIDBase:       uint32(cfg.Runtime.CIDBase),
		Allocator:     alloc,
		Preflight:     pfFunc,
	}

	adapter, err := jailer.New(jCfg, pc)
	if err != nil {
		return nil, fmt.Errorf("runtime_mode firecracker: create jailer adapter: %w", err)
	}
	return adapter, nil
}
