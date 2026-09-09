// ABOUTME: Proves production startup installs the jailer adapter as the host coverage source.
// ABOUTME: Fails if the installation call disappears from the served runtime construction.
//go:build linux

package main

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2389-research/observatory/internal/jailer"
	"github.com/2389-research/observatory/internal/network"
	"github.com/2389-research/observatory/internal/privd"
	"github.com/2389-research/observatory/internal/situation"
	"github.com/2389-research/observatory/internal/store"
)

// startupJailerAdapter builds the adapter the served runtime installs, with the
// same constructor buildFirecrackerRuntime uses.
func startupJailerAdapter(t *testing.T) *jailer.Adapter {
	t.Helper()
	dir := t.TempDir()
	allocator, err := network.NewAllocator(nil, []netip.Prefix{netip.MustParsePrefix("10.190.0.0/16")})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := jailer.New(jailer.Config{
		StateDir:  dir,
		StageRoot: filepath.Join(dir, "stage"),
		JailBase:  filepath.Join(dir, "jail"),
		SpoolRoot: filepath.Join(dir, "spool"),
		RunnerBin: filepath.Join(dir, "vmobs-runner"),
		RepoRoot:  dir,
		LockPath:  filepath.Join(dir, "runtime.lock.json"),
		MaxSlots:  maxSlotsWiring,
		Allocator: allocator,
	}, &privd.Client{SocketPath: filepath.Join(dir, "privd.sock")})
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func startupCoverage(t *testing.T, install bool) situation.Coverage {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "coverage.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	eng := situation.New(st, situation.Config{})
	adapter := startupJailerAdapter(t)
	var rt any = adapter
	if install {
		installed, findings, err := installFirecrackerRuntime(t.Context(), eng, adapter)
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) != 0 {
			t.Fatalf("empty state dir produced findings: %+v", findings)
		}
		rt = installed
	}
	if rt != any(adapter) {
		t.Fatal("startup installed a runtime other than the adapter it built")
	}
	coverage, err := eng.VMCoverage(t.Context(), &store.VM{
		VMID: "5f8fa8f6-2fd0-4a0a-9d0b-8f2b9cf3d2a1", CurrentBootID: "0d0a1d33-77ad-4a53-9e26-a3a2c2e9d9f0",
		ObservedState: "running", NetworkProfile: "transport",
	})
	if err != nil {
		t.Fatal(err)
	}
	return coverage
}

// TestStartupInstallsJailerAsHostCoverageSource pins the served coverage answer
// to the installation call. With the jailer installed, a VM whose runner the
// adapter cannot reach is reported unavailable by the host source; without the
// call the same VM keeps the engine's "no report" default. Deleting the
// installation from installFirecrackerRuntime makes the two answers identical.
func TestStartupInstallsJailerAsHostCoverageSource(t *testing.T) {
	installed := startupCoverage(t, true)
	bare := startupCoverage(t, false)
	for _, id := range []string{"flow", "denial"} {
		got, want := collectorReason(t, installed, id), "host coverage source unavailable: "
		// The reason now carries the source's own diagnosis, so the installed
		// source is pinned by what it says failed, not by a generic sentence.
		if !strings.HasPrefix(got, want) || !strings.Contains(got, "jailer:") {
			t.Fatalf("installed host collector %s reported %q, not a jailer source failure prefixed %q", id, got, want)
		}
		if reason := collectorReason(t, bare, id); reason != "no current collector report available" {
			t.Fatalf("uninstalled host collector %s reported %q; the engine default moved", id, reason)
		}
	}
}

func collectorReason(t *testing.T, coverage situation.Coverage, id string) string {
	t.Helper()
	for _, c := range coverage.Collectors {
		if c.ID == id {
			if c.State != situation.CoverageUnavailable {
				t.Fatalf("collector %s is %s, not unavailable", id, c.State)
			}
			return c.Reason
		}
	}
	t.Fatalf("coverage carries no %s collector", id)
	return ""
}
