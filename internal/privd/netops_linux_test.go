// ABOUTME: Linux tests for privd network operations: argv construction and root-path lifecycle.
// ABOUTME: TestNetArgvConstruction runs everywhere; TestRealOpsNetworkLifecycle needs root.

//go:build linux

package privd_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/2389-research/observatory/internal/privd"
)

// TestRealOpsNetworkLifecycle exercises AllocateNetwork + ReleaseNetwork against real
// kernel network namespaces. Skip unless running as root — real kernel ops need it.
func TestRealOpsNetworkLifecycle(t *testing.T) {
	if os.Getenv("VMOBS_GATEWAY_LIFECYCLE") != "1" {
		t.Skip("requires opted-in isolated Linux container")
	}

	policyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(policyDir, "offline.json"), []byte(`{"schema_version":1,"id":"offline","profile":"offline","dns_upstream":"","allowed_tcp_ports":[],"extra_deny_prefixes":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := privd.RealOpsCfg{
		PolicyDirectory: policyDir,
		JailBase:        "/tmp/vmobs-test-jail",
		StageRoot:       "/tmp/vmobs-test-stage",
		FirecrackerPath: "/usr/local/bin/firecracker",
		JailerPath:      "/usr/local/bin/jailer",
		NftPath:         "/usr/sbin/nft",
		IPPath:          "/usr/sbin/ip",
	}

	ops := privd.NewRealOps(cfg)

	entry := privd.VMEntry{
		NetworkHostNFLogGroup: 1024,
		VMID:                  "test-net-001",
		NetCIDR:               "10.99.0.0/30",
	}
	req := privd.AllocateNetworkReq{
		VMID:    entry.VMID,
		CIDR:    entry.NetCIDR,
		Profile: "offline", PolicyID: "offline", GuestBootID: "b28581fb-7b8b-499a-8671-8bf54d159839",
	}
	if err := ops.PrepareNetworkEntry(context.Background(), &entry, req); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ops.ReleaseNetwork(entry); err != nil {
			t.Errorf("cleanup real network: %v", err)
		}
	})

	// AllocateNetwork must succeed.
	if err := ops.AllocateNetworkOwnedContext(context.Background(), &entry, req); err != nil {
		t.Fatalf("AllocateNetwork: %v", err)
	}

	// Idempotent: second call with same id must succeed (detects existing netns).
	if err := ops.AllocateNetworkOwnedContext(context.Background(), &entry, req); err != nil {
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
	if err := ops.AllocateNetworkOwnedContext(context.Background(), &entry, req); err != nil {
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

// A failed real executable lookup is unknown host state, even when every
// teardown command also failed. No fake network backend supplies this answer.
func TestReleaseNetworkRefusesUnavailableHostProbe(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	ops := privd.NewRealOps(privd.RealOpsCfg{})
	if err := ops.ReleaseNetwork(privd.VMEntry{VMID: "probe-unavailable"}); err == nil {
		t.Fatal("network release succeeded without executable teardown or host probe")
	}
}

// An interface-presence answer cannot authorize a policy-less request.
func TestGatewayRejectsUnboundAllocation(t *testing.T) {
	calls := 0
	ops := privd.NewRealOpsWithHooks(privd.RealOpsCfg{}, privd.RealOpsTestHooks{
		NetnsExists: func(string) bool { return true },
		RunCmd:      func([]string) error { calls++; return nil },
	})
	err := ops.AllocateNetwork(privd.VMEntry{VMID: "closed-regression", NetCIDR: "10.99.0.0/30"}, privd.AllocateNetworkReq{VMID: "closed-regression", CIDR: "10.99.0.0/30"})
	if err == nil {
		t.Fatal("unbound allocation succeeded on interface presence alone")
	}
	if calls != 0 {
		t.Fatal("unbound request mutated topology")
	}
}
