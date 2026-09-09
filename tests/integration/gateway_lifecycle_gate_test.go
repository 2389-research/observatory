// ABOUTME: Exercises the closed production gateway under the shipped container confinement.
// ABOUTME: Creates all network and mount resources in an isolated child, preserving the parent.
//go:build linux

package integration_test

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/network"
	"github.com/2389-research/observatory/internal/privd"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

func TestGatewayLifecycleConfinementGate(t *testing.T) {
	if os.Getenv("VMOBS_GATEWAY_CONFINEMENT_GATE") != "1" {
		t.Skip("explicit confined root gate: VMOBS_GATEWAY_CONFINEMENT_GATE=1")
	}
	boundaryConfinement(t)
	if os.Getenv("VMOBS_GATEWAY_CONFINEMENT_CHILD") == "1" {
		gatewayLifecycleChild(t)
		return
	}
	before := boundaryParentState(t)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGatewayLifecycleConfinementGate$", "-test.v", "-test.timeout=40s")
	command.Env = append(os.Environ(), "VMOBS_GATEWAY_CONFINEMENT_CHILD=1")
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET | unix.CLONE_NEWNS}
	output, err := command.CombinedOutput()
	if after := boundaryParentState(t); after != before {
		t.Errorf("parent namespace/settings changed: before=%q after=%q", before, after)
	}
	if err != nil {
		t.Fatalf("confined gateway lifecycle: %v\n%s", err, output)
	}
	t.Logf("confined child result:\n%s", output)
}

func gatewayLifecycleChild(t *testing.T) {
	t.Helper()
	if boundaryNamespace(t, "self") == boundaryNamespace(t, strconv.Itoa(os.Getppid())) {
		t.Fatal("refusing mutation in the parent's network namespace")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatalf("refusing mutation in a nonempty child namespace: %+v, %v", interfaces, err)
	}
	policyDirectory := t.TempDir()
	if err := os.WriteFile(filepath.Join(policyDirectory, "offline.json"), []byte(`{"schema_version":1,"id":"offline","profile":"offline"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ops := privd.NewRealOps(privd.RealOpsCfg{PolicyDirectory: policyDirectory})
	entry := privd.VMEntry{NetworkHostNFLogGroup: 1024, VMID: uuid.NewString(), NetCIDR: "10.201.0.0/30"}
	req := privd.AllocateNetworkReq{VMID: entry.VMID, CIDR: entry.NetCIDR, Profile: "offline", PolicyID: "offline", GuestBootID: uuid.NewString()}
	if err := ops.PrepareNetworkEntry(t.Context(), &entry, req); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := ops.ReleaseNetworkContext(ctx, entry); err != nil {
			t.Errorf("cleanup did not prove release: %v", err)
		}
	})
	if err := ops.AllocateNetworkOwnedContext(t.Context(), &entry, req); err != nil {
		t.Fatal(err)
	}
	if err := ops.ProbeNetworkContext(t.Context(), entry, req); err != nil {
		t.Fatal("probe actual closed topology:", err)
	}
	wrongBoot := req
	wrongBoot.GuestBootID = uuid.NewString()
	if err := ops.ProbeNetworkContext(t.Context(), entry, wrongBoot); err == nil {
		t.Fatal("different guest boot accepted the live allocation")
	}
	if err := ops.ProbeNetworkContext(t.Context(), entry, req); err != nil {
		t.Fatal("refused probe changed the live allocation:", err)
	}
	if err := ops.ReleaseNetworkContext(t.Context(), entry); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/run/netns/" + network.NamespaceName(entry.VMID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("namespace remains after release: %v", err)
	}
	if _, err := net.InterfaceByName(network.VethName(entry.VMID)); err == nil {
		t.Fatal("host veth remains after release")
	}
	t.Log("actual closed gateway allocation, boot-bound probe and verified teardown passed")
}
