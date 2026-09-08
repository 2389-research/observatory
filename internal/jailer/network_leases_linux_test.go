// ABOUTME: Lease lifecycle integration tests using manifests and the real privd socket/ledger.
// ABOUTME: Failing before staging avoids a VMM stand-in; filesystem faults exercise release retention.

//go:build linux

package jailer_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2389-research/observatory/internal/jailer"
	"github.com/2389-research/observatory/internal/network"
	"github.com/2389-research/observatory/internal/privd"
	"github.com/2389-research/observatory/internal/runtime"
)

func TestFailedLaunchReusesTinyNetworkPool(t *testing.T) {
	h := buildInjectHarness(t, "", "10.97.0.0/30", 4, 0)
	if err := os.Remove(h.lockPath); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_, err := h.adapter.Launch(context.Background(), runtime.VMSpec{VMID: fmt.Sprintf("failed-%d", i), BootID: "boot"})
		if err == nil || !strings.Contains(err.Error(), "load lock") {
			t.Fatalf("launch %d: want staging failure, got %v", i, err)
		}
	}
}

func TestNetworkLeaseSurvivesControllerRestart(t *testing.T) {
	h := buildInjectHarness(t, "", "10.97.1.0/29", 4, 0)
	p, err := h.pool.Acquire("survivor")
	if err != nil {
		t.Fatal(err)
	}
	if err := jailer.WriteManifestExported(h.stateDir, jailer.Manifest{VMID: "survivor", CIDR: p.String(), Slot: 0}); err != nil {
		t.Fatal(err)
	}
	pool, err := network.NewAllocator(nil, []netip.Prefix{netip.MustParsePrefix(h.poolCIDR)})
	if err != nil {
		t.Fatal(err)
	}
	cfg := jailer.Config{StateDir: h.stateDir, StageRoot: h.stageRoot, JailBase: h.jailBase, SpoolRoot: h.spoolRoot, RunnerBin: runnerBin, RepoRoot: h.repoRoot, LockPath: h.lockPath, MaxSlots: 8, Allocator: pool}
	if _, err := jailer.New(cfg, &privd.Client{SocketPath: h.privdSock}); err != nil {
		t.Fatal(err)
	}
	successor, err := pool.Acquire("successor")
	if err != nil || successor == p {
		t.Fatalf("survivor prefix handed out: %v %v", successor, err)
	}
}

func TestFailedTeardownRetainsNetworkLease(t *testing.T) {
	h := buildInjectHarness(t, "", "10.97.2.0/30", 4, 0)
	p, err := h.pool.Acquire("held")
	if err != nil {
		t.Fatal(err)
	}
	if err := jailer.WriteManifestExported(h.stateDir, jailer.Manifest{VMID: "held", CIDR: p.String()}); err != nil {
		t.Fatal(err)
	}
	// Actual filesystem debt: privd has no ownership record and cannot delete
	// this surviving chroot. The adapter must keep the manifest and lease.
	jail := filepath.Join(h.jailBase, "firecracker", "held")
	if err := os.MkdirAll(jail, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := h.adapter.Release(context.Background(), "held"); err == nil {
		t.Fatal("accepted surviving chroot")
	}
	if _, err := h.pool.Acquire("next"); !errors.Is(err, network.ErrPoolExhausted) {
		t.Fatalf("failed teardown surrendered lease: %v", err)
	}
	if err := os.RemoveAll(jail); err != nil {
		t.Fatal(err)
	}
	if err := h.adapter.Release(context.Background(), "held"); err != nil {
		t.Fatal(err)
	}
	next, err := h.pool.Acquire("next")
	if err != nil || next != p {
		t.Fatalf("successful release failed to reclaim: %v %v", next, err)
	}
}

func TestFailedRollbackRetainsNetworkManifest(t *testing.T) {
	h := buildInjectHarness(t, "", "10.97.3.0/30", 4, 0)
	if err := os.Remove(h.lockPath); err != nil {
		t.Fatal(err)
	}
	jail := filepath.Join(h.jailBase, "firecracker", "held")
	if err := os.MkdirAll(jail, 0o700); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.CreateTemp(t.TempDir(), "rollback-log")
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	originalStderr := os.Stderr
	os.Stderr = logFile
	_, launchErr := h.adapter.Launch(context.Background(), runtime.VMSpec{VMID: "held", BootID: "boot"})
	os.Stderr = originalStderr
	if launchErr == nil {
		t.Fatal("expected missing lock failure")
	}
	output, err := os.ReadFile(logFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(output), "retained") {
		t.Fatalf("missing cleanup debt diagnostic: %s", output)
	}
	if _, err := jailer.ReadManifest(h.stateDir, "held"); err != nil {
		t.Fatalf("failed rollback surrendered manifest: %v", err)
	}
	if _, err := h.pool.Acquire("next"); !errors.Is(err, network.ErrPoolExhausted) {
		t.Fatalf("failed rollback surrendered lease: %v", err)
	}
}

func TestNetworkLeaseReleaseRetriesFailedDirectoryBarrier(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires unprivileged directory read refusal")
	}
	h := buildInjectHarness(t, "", "10.97.4.0/30", 4, 0)
	p, err := h.pool.Acquire("held")
	if err != nil {
		t.Fatal(err)
	}
	if err := jailer.WriteManifestExported(h.stateDir, jailer.Manifest{VMID: "held", CIDR: p.String()}); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(h.stateDir, "vms")
	if err := os.Chmod(parent, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
	for i := 0; i < 2; i++ {
		if err := h.adapter.Release(context.Background(), "held"); err == nil {
			t.Fatalf("release %d skipped failed barrier", i)
		}
		if _, err := h.pool.Acquire("next"); !errors.Is(err, network.ErrPoolExhausted) {
			t.Fatalf("release %d surrendered lease: %v", i, err)
		}
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := h.adapter.Release(context.Background(), "held"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Acquire("next"); err != nil {
		t.Fatalf("settled teardown failed to reclaim: %v", err)
	}
}

func TestNetworkLeaseRestoresPrivdOnlyClaim(t *testing.T) {
	h := buildInjectHarness(t, "", "10.97.5.0/29", 4, 0)
	// A real persisted network-only record has no manifest or host route to
	// tell the controller which prefix remains owned after an interrupted boot.
	claim := []byte(`{"vm_id":"orphan","net_cidr":"10.97.5.0/30"}`)
	if err := os.WriteFile(filepath.Join(filepath.Dir(h.privdSock), "ledger", "orphan.json"), claim, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := jailer.Config{StateDir: h.stateDir, StageRoot: h.stageRoot, JailBase: h.jailBase, SpoolRoot: h.spoolRoot, RunnerBin: runnerBin, RepoRoot: h.repoRoot, LockPath: h.lockPath, MaxSlots: 8, Allocator: h.pool}
	if _, err := jailer.New(cfg, &privd.Client{SocketPath: h.privdSock}); err != nil {
		t.Fatal(err)
	}
	prefix, err := h.pool.Acquire("successor")
	if err != nil || prefix.String() != "10.97.5.4/30" {
		t.Fatalf("privd-only claim handed to successor: %s %v", prefix, err)
	}
}

func TestNetworkLeaseRefusesConflictingPrivdOwnership(t *testing.T) {
	h := buildInjectHarness(t, "", "10.97.6.0/29", 4, 0)
	if err := jailer.WriteManifestExported(h.stateDir, jailer.Manifest{VMID: "owner", CIDR: "10.97.6.0/30"}); err != nil {
		t.Fatal(err)
	}
	claim := []byte(`{"vm_id":"owner","net_cidr":"10.97.6.4/30"}`)
	if err := os.WriteFile(filepath.Join(filepath.Dir(h.privdSock), "ledger", "owner.json"), claim, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := jailer.Config{StateDir: h.stateDir, StageRoot: h.stageRoot, JailBase: h.jailBase, SpoolRoot: h.spoolRoot, RunnerBin: runnerBin, RepoRoot: h.repoRoot, LockPath: h.lockPath, MaxSlots: 8, Allocator: h.pool}
	a, err := jailer.New(cfg, &privd.Client{SocketPath: h.privdSock})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(h.lockPath); err != nil {
		t.Fatal(err)
	}
	_, err = a.Launch(context.Background(), runtime.VMSpec{VMID: "successor", BootID: "boot"})
	if err == nil || !strings.Contains(err.Error(), "network lease disagreement") {
		t.Fatalf("conflicting ownership reached staging: %v", err)
	}
}
