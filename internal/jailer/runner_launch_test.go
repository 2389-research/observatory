// ABOUTME: Checks runner launch arguments against the real runner flag contract.
// ABOUTME: The adapter acquires the observers; the runner is handed them, never a socket.
package jailer

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/2389-research/observatory/internal/network"
	"github.com/2389-research/observatory/internal/privd"
	"github.com/2389-research/observatory/internal/runner"
)

// observerBundleFixture is the metadata privd returns for one acquisition: the
// binding plus the three sockets in the order privd guarantees.
func observerBundleFixture(vmID, guestBootID string) *privd.NetworkObserverBundle {
	return &privd.NetworkObserverBundle{
		Binding: privd.NetworkObserverBinding{
			VMID: vmID, GuestBootID: guestBootID,
			HostBootID: "00000000-0000-4000-8000-000000000005", AcquisitionID: "00000000-0000-4000-8000-000000000004",
			GatewayGeneration: strings.Repeat("a", 32), PolicyDigest: strings.Repeat("b", 64),
			NamespaceDevice: "4", NamespaceInode: "4026532000", PolicyID: "transport-public-web", Profile: "transport",
		},
		Sockets: []privd.ObserverSocket{
			{Kind: "conntrack", Boundary: "namespace_gateway", PortID: 11, SnapshotSequence: 7},
			{Kind: "nflog", Boundary: "namespace_gateway", PortID: 12, Group: network.NamespaceNFLogGroup},
			{Kind: "nflog", Boundary: "host_veth", PortID: 13, Group: network.MinHostNFLogGroup},
		},
	}
}

// acquiringPrivd answers only the observer verb; the other verbs are never
// reached by the argument-building tests that use it.
type acquiringPrivd struct {
	privdClient
	bundle *privd.NetworkObserverBundle
	err    error
	reqs   []privd.AcquireNetworkObserversReq
}

func (p *acquiringPrivd) AcquireNetworkObservers(_ context.Context, req privd.AcquireNetworkObserversReq) (*privd.NetworkObserverBundle, error) {
	p.reqs = append(p.reqs, req)
	return p.bundle, p.err
}

// The runner never dials privd: it is handed the acquired binding and the
// descriptors, so no privileged socket path appears in its argv at all.
func TestRunnerArgumentsCarryAcquiredBindingAndNoPrivilegedSocket(t *testing.T) {
	a := &Adapter{cfg: Config{RunnerBin: "/opt/vmobs-runner", StateDir: "/state", JailBase: "/jails", SpoolRoot: "/spool"}}
	// privd only ever answers for the VM and boot the adapter asked about, so the
	// binding an acquisition returns always names this manifest.
	m := Manifest{VMID: "00000000-0000-4000-8000-000000000001", BootID: "00000000-0000-4000-8000-000000000002", VMMPID: 123, VMMStart: "456"}
	bundle := observerBundleFixture(m.VMID, m.BootID)

	args, err := a.runnerArguments(m, "runner-one", bundle, "")
	if err != nil {
		t.Fatal(err)
	}
	if joined := strings.Join(args, " "); strings.Contains(joined, "privd") {
		t.Fatalf("runner argv names privd: %q", joined)
	}
	cfg, err := runner.ParseFlags(args[0], args[1:])
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NetworkObservers == nil {
		t.Fatalf("runner lost the acquired observer binding: %+v", cfg)
	}
	if cfg.NetworkObservers.Binding != bundle.Binding || !slices.Equal(cfg.NetworkObservers.Sockets, bundle.Sockets) {
		t.Fatalf("observer binding = %+v, want %+v", cfg.NetworkObservers, bundle)
	}
	if cfg.NetworkUnavailableReason != "" {
		t.Fatalf("acquired runner also carries an unavailable reason: %q", cfg.NetworkUnavailableReason)
	}
	if cfg.VMID != m.VMID || cfg.BootID != m.BootID || cfg.InstanceID != "runner-one" || cfg.VMMPID != m.VMMPID || cfg.VMMStartTime != m.VMMStart {
		t.Fatalf("runner lost its process binding: %+v", cfg)
	}
	if cfg.CtlSock != filepath.Join(a.cfg.StateDir, "vms", m.VMID, "runner.sock") || cfg.SpoolDir != filepath.Join(a.cfg.SpoolRoot, m.VMID) {
		t.Fatalf("runner paths escaped the VM: %+v", cfg)
	}
}

// Acquisition failure must not block the launch. The runner starts with a
// bounded reason and publishes unavailable coverage carrying it.
func TestRunnerArgumentsCarryBoundedUnavailableReasonWithoutObservers(t *testing.T) {
	a := &Adapter{cfg: Config{RunnerBin: "/opt/vmobs-runner", StateDir: "/state", JailBase: "/jails", SpoolRoot: "/spool"}}
	m := Manifest{VMID: "vm-observed", BootID: "boot-one", VMMPID: 123, VMMStart: "456"}

	args, err := a.runnerArguments(m, "runner-one", nil, strings.Repeat("z", 4096))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := runner.ParseFlags(args[0], args[1:])
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NetworkObservers != nil {
		t.Fatalf("runner claims observers it never received: %+v", cfg.NetworkObservers)
	}
	if len(cfg.NetworkUnavailableReason) != runner.MaxNetworkReasonBytes {
		t.Fatalf("unavailable reason is %d bytes, want it bounded at %d", len(cfg.NetworkUnavailableReason), runner.MaxNetworkReasonBytes)
	}
}

// The adapter bounds the reason with the runner's own function, so a privd
// message carrying a multi-byte character across the bound never reaches the
// runner - or the coverage API - as broken UTF-8.
func TestRunnerArgumentsBoundReasonStaysValidUTF8(t *testing.T) {
	a := &Adapter{cfg: Config{RunnerBin: "/opt/vmobs-runner", StateDir: "/state", JailBase: "/jails", SpoolRoot: "/spool"}}
	m := Manifest{VMID: "vm-observed", BootID: "boot-one", VMMPID: 123, VMMStart: "456"}

	// The last rune straddles the bound: one byte inside it, one byte past.
	args, err := a.runnerArguments(m, "runner-one", nil, strings.Repeat("a", runner.MaxNetworkReasonBytes-1)+"é")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := runner.ParseFlags(args[0], args[1:])
	if err != nil {
		t.Fatal(err)
	}
	if !utf8.ValidString(cfg.NetworkUnavailableReason) {
		t.Fatalf("reason %q reached the runner as invalid UTF-8", cfg.NetworkUnavailableReason)
	}
}

// A runner launched with neither observers nor a reason would report healthy
// coverage it cannot back. The flag contract refuses that shape outright.
func TestRunnerFlagsRefuseSilentlyMissingObservers(t *testing.T) {
	a := &Adapter{cfg: Config{RunnerBin: "/opt/vmobs-runner", StateDir: "/state", JailBase: "/jails", SpoolRoot: "/spool"}}
	m := Manifest{VMID: "vm-observed", BootID: "boot-one", VMMPID: 123, VMMStart: "456"}
	args, err := a.runnerArguments(m, "runner-one", nil, "")
	if err == nil {
		if _, err = runner.ParseFlags(args[0], args[1:]); err == nil {
			t.Fatal("a runner with no observers and no reason was accepted")
		}
	}
}

// A refusing privd never blocks a launch: the adapter records the refusal as the
// runner's bounded unavailable reason and starts it anyway.
func TestAcquireRunnerObserversTurnsRefusalIntoAnUnavailableReason(t *testing.T) {
	pc := &acquiringPrivd{err: &privd.RemoteError{Cause: "unsupported", Message: "network observers require Linux"}}
	a := &Adapter{cfg: Config{RunnerBin: "/opt/vmobs-runner", StateDir: "/state", JailBase: "/jails", SpoolRoot: "/spool"}, pc: pc}
	m := Manifest{VMID: "00000000-0000-4000-8000-000000000001", BootID: "00000000-0000-4000-8000-000000000002"}

	bundle, reason := a.acquireRunnerObservers(context.Background(), m)
	if bundle != nil {
		t.Fatalf("refused acquisition produced a bundle: %+v", bundle)
	}
	if !strings.Contains(reason, "network observers require Linux") || len(reason) > runner.MaxNetworkReasonBytes {
		t.Fatalf("reason = %q, want the refusal named within %d bytes", reason, runner.MaxNetworkReasonBytes)
	}
	if len(pc.reqs) != 1 || pc.reqs[0].VMID != m.VMID || pc.reqs[0].GuestBootID != m.BootID {
		t.Fatalf("acquisition request = %+v, want this VM and boot", pc.reqs)
	}
}

// The adapter is the privd client of record for observers on every launch path,
// including the respawn that follows a runner that lost its sockets.
func TestAcquireRunnerObserversReturnsTheAcquiredBundle(t *testing.T) {
	want := observerBundleFixture("00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002")
	pc := &acquiringPrivd{bundle: want}
	a := &Adapter{cfg: Config{RunnerBin: "/opt/vmobs-runner", StateDir: "/state", JailBase: "/jails", SpoolRoot: "/spool"}, pc: pc}
	m := Manifest{VMID: want.Binding.VMID, BootID: want.Binding.GuestBootID}

	bundle, reason := a.acquireRunnerObservers(context.Background(), m)
	if bundle != want || reason != "" {
		t.Fatalf("acquire = (%+v, %q), want the acquired bundle and no reason", bundle, reason)
	}
}
