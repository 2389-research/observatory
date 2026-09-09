// ABOUTME: Exercises production network acquisition and durable ingestion after credential drop.
// ABOUTME: Sends real denied traffic inside a disposable namespace without activating transport.
//go:build linux

package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/events"
	"github.com/2389-research/observatory/internal/network"
	"github.com/2389-research/observatory/internal/privd"
	"github.com/2389-research/observatory/internal/spool"
	"github.com/2389-research/observatory/internal/store"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// kernelPipelineVMID is the VM the whole role tree observes.
const kernelPipelineVMID = "c28581fb-7b8b-499a-8671-8bf54d159830"

func TestNetworkRunnerKernelPipeline(t *testing.T) {
	if os.Getenv("VMOBS_RUNNER_NETWORK_TEST") != "1" {
		t.Skip("requires disposable privileged Linux container: VMOBS_RUNNER_NETWORK_TEST=1")
	}
	switch os.Getenv("VMOBS_RUNNER_NETWORK_ROLE") {
	case "recipient":
		networkKernelRecipient(t)
		return
	case "traffic":
		conn, err := net.Dial("udp4", "10.209.0.1:43219")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("runner-network-component"))
		return
	case "tcp":
		// A real TCP SYN toward the guest address inside the owned CIDR. The
		// offline gateway drops it, so the dial never completes; the point is
		// that the packet is emitted, denied and, for conntrack, never confirmed.
		conn, err := net.DialTimeout("tcp4", "10.209.0.2:9", 2*time.Second)
		if err == nil {
			conn.Close()
			t.Fatal("offline gateway accepted a TCP connection")
		}
		t.Logf("tcp dial denied as expected: %v", err)
		return
	case "namespace":
	default:
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestNetworkRunnerKernelPipeline$", "-test.v", "-test.timeout=45s")
		cmd.Env = append(os.Environ(), "VMOBS_RUNNER_NETWORK_ROLE=namespace")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET | unix.CLONE_NEWNS}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated component: %v\n%s", err, out)
		}
		t.Logf("%s", out)
		return
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	parent, err := os.Readlink("/proc/" + strconv.Itoa(os.Getppid()) + "/ns/net")
	if err != nil || self == parent {
		t.Fatal("refusing mutation outside isolated namespace", err)
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("refusing nonempty namespace", interfaces, err)
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("/tmp", "runner-network-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	policies, ledger, work := filepath.Join(dir, "policies"), filepath.Join(dir, "ledger"), filepath.Join(dir, "work")
	for _, p := range []string{policies, ledger, work} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chown(work, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policies, "offline.json"), []byte(`{"schema_version":1,"id":"offline","profile":"offline"}`), 0600); err != nil {
		t.Fatal(err)
	}
	ops := privd.NewRealOps(privd.RealOpsCfg{PolicyDirectory: policies})
	entry := privd.VMEntry{VMID: kernelPipelineVMID, NetCIDR: "10.209.0.0/30", NetworkHostNFLogGroup: 1024}
	req := privd.AllocateNetworkReq{VMID: entry.VMID, CIDR: entry.NetCIDR, Profile: "offline", PolicyID: "offline", GuestBootID: uuid.NewString()}
	if err := ops.PrepareNetworkEntry(t.Context(), &entry, req); err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := ops.ReleaseNetworkContext(ctx, entry); err != nil {
			t.Error(err)
		}
	}()
	if err := ops.AllocateNetworkOwnedContext(t.Context(), &entry, req); err != nil {
		t.Fatal(err)
	}
	entry.NetworkComplete = true
	// The production ledger's public VMEntry schema records the real allocated resources.
	encoded, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ledger, entry.VMID+".json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	// The acquirer is root, exactly as the jailer adapter is the privd client of
	// record in production. The runner never dials privd and never sees this path.
	srv := privd.NewServer(privd.ServerCfg{AllowedUID: os.Getuid(), LedgerDir: ledger, Ops: ops, FramingTimeout: time.Second})
	socket := filepath.Join(dir, "privd.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	serverDone := make(chan error, 1)
	go func() { serverDone <- srv.Serve(ctx, listener) }()
	defer func() {
		cancel()
		if err := <-serverDone; err != nil {
			t.Error(err)
		}
	}()
	client := &privd.Client{SocketPath: socket}
	acquireReq := privd.AcquireNetworkObserversReq{VMID: entry.VMID, GuestBootID: req.GuestBootID}
	bundle, err := client.AcquireNetworkObservers(t.Context(), acquireReq)
	if err != nil {
		t.Fatalf("acquire observers as the privd client of record: %v", err)
	}
	binding, err := privd.EncodeObserverBinding(bundle)
	if err != nil {
		bundle.Close()
		t.Fatal(err)
	}
	// The rules the real privd installed decide what a flow collector can ever
	// see. Recording them makes the offline profile's reach a measurement.
	if raw, err := exec.CommandContext(t.Context(), "ip", "netns", "exec", network.NamespaceName(entry.VMID), "nft", "-n", "list", "ruleset").CombinedOutput(); err != nil {
		t.Logf("installed ruleset unavailable: %v\n%s", err, raw)
	} else {
		t.Logf("installed namespace ruleset:\n%s", raw)
	}
	binaryPath := filepath.Join(dir, "component.test")
	src, err := os.Open(os.Args[0])
	if err != nil {
		bundle.Close()
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := os.OpenFile(binaryPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0755)
	if err != nil {
		bundle.Close()
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		bundle.Close()
		t.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		bundle.Close()
		t.Fatal(err)
	}
	childCtx, childCancel := context.WithCancel(t.Context())
	cmd := exec.CommandContext(childCtx, binaryPath, "-test.run=^TestNetworkRunnerKernelPipeline$", "-test.v", "-test.timeout=25s")
	cmd.Env = append(os.Environ(), "VMOBS_RUNNER_NETWORK_ROLE=recipient", "VMOBS_RUNNER_NETWORK_BINDING="+string(binding), "VMOBS_RUNNER_NETWORK_BOOT="+req.GuestBootID, "VMOBS_RUNNER_NETWORK_WORK="+work)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, NoSetGroups: true}}
	// The descriptors reach the credential-dropped child by inheritance, at
	// runner.FirstObserverFD and up, in the binding's socket order.
	cmd.ExtraFiles = bundle.Files
	var childOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &childOut, &childOut
	if err := cmd.Start(); err != nil {
		bundle.Close()
		t.Fatal(err)
	}
	// The child owns the sockets from here: the acquirer keeps no copy, which is
	// what lets a later acquisition succeed once the child is gone.
	if err := bundle.Close(); err != nil {
		t.Fatal(err)
	}
	childDone := make(chan struct{})
	var childErr error
	go func() { defer close(childDone); childErr = cmd.Wait() }()
	joinChild := func() {
		childCancel()
		select {
		case <-childDone:
		case <-time.After(3 * time.Second):
			t.Error("credential child did not reap after cancellation")
		}
	}
	deadline := time.Now().Add(12 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(work, "ready")); err == nil {
			break
		}
		select {
		case <-childDone:
			t.Fatalf("recipient before ready: %v\n%s", childErr, childOut.String())
		default:
		}
		if time.Now().After(deadline) {
			joinChild()
			t.Fatalf("reader readiness timeout; child output: %s", childOut.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	for i := 0; i < 3; i++ {
		traffic := exec.CommandContext(t.Context(), "ip", "netns", "exec", network.NamespaceName(entry.VMID), binaryPath, "-test.run=^TestNetworkRunnerKernelPipeline$", "-test.timeout=3s")
		traffic.Env = append(os.Environ(), "VMOBS_RUNNER_NETWORK_ROLE=traffic")
		if raw, err := traffic.CombinedOutput(); err != nil {
			joinChild()
			t.Fatalf("traffic: %v %s", err, raw)
		}
	}
	tcp := exec.CommandContext(t.Context(), "ip", "netns", "exec", network.NamespaceName(entry.VMID), binaryPath, "-test.run=^TestNetworkRunnerKernelPipeline$", "-test.v", "-test.timeout=8s")
	tcp.Env = append(os.Environ(), "VMOBS_RUNNER_NETWORK_ROLE=tcp")
	tcpOut, err := tcp.CombinedOutput()
	if err != nil {
		joinChild()
		t.Fatalf("tcp traffic: %v %s", err, tcpOut)
	}
	t.Logf("real TCP attempt across the observed boundary:\n%s", tcpOut)
	<-childDone
	if childErr != nil {
		t.Fatalf("recipient: %v\n%s", childErr, childOut.String())
	}
	t.Logf("%s", childOut.String())
	// The respawn path: the first holder's process is gone, so privd hands the
	// same boot a fresh acquisition. NFLOG admits one reader per group per
	// namespace, so this succeeds only because no descriptor outlived the child.
	second, err := client.AcquireNetworkObservers(t.Context(), acquireReq)
	if err != nil {
		t.Fatalf("second acquisition after the first holder exited: %v", err)
	}
	if second.Binding.AcquisitionID == "" || second.Binding.AcquisitionID == bundle.Binding.AcquisitionID {
		t.Fatalf("respawn acquisition reused the first acquisition identity: %+v", second.Binding)
	}
	// A reader generation owns its own descriptors: netobserve closes every file
	// it is handed, so a generation built from the masters would cost the runner
	// the acquisition on the first read failure it is supposed to survive.
	generation, err := dupNetworkObservers(second)
	if err != nil {
		second.Close()
		t.Fatalf("reader generation from the acquired masters: %v", err)
	}
	if err := generation.Close(); err != nil {
		second.Close()
		t.Fatal(err)
	}
	if err := privd.ValidateObserverDescriptors(second); err != nil {
		second.Close()
		t.Fatalf("closing a reader generation cost the runner its masters: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	t.Logf("respawn re-acquisition succeeded with acquisition id %s; reader generations are independent of the retained masters", second.Binding.AcquisitionID)
}

func networkKernelRecipient(t *testing.T) {
	if os.Geteuid() != 65534 {
		t.Fatal("recipient retained root")
	}
	var caps [2]unix.CapUserData
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	if err := unix.Capget(&header, &caps[0]); err != nil {
		t.Fatal(err)
	}
	for _, c := range caps {
		if c.Effective != 0 || c.Permitted != 0 {
			t.Fatalf("retained capability %+v", caps)
		}
	}
	work := os.Getenv("VMOBS_RUNNER_NETWORK_WORK")
	root := filepath.Join(work, "spool")
	dir := filepath.Join(root, kernelPipelineVMID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	// The runner decodes the binding it inherited; it holds no privd socket path
	// and performs no acquisition of its own.
	bundle, err := privd.DecodeObserverBinding([]byte(os.Getenv("VMOBS_RUNNER_NETWORK_BINDING")))
	if err != nil {
		t.Fatalf("inherited observer binding: %v", err)
	}
	cfg := Config{VMID: kernelPipelineVMID, BootID: os.Getenv("VMOBS_RUNNER_NETWORK_BOOT"), InstanceID: uuid.NewString(), NetworkObservers: bundle}
	sw, err := spool.OpenWriter(dir, spool.WriterCfg{VMID: cfg.VMID, InstanceID: cfg.InstanceID, MaxSegmentBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	r := &runner{cfg: cfg, sw: sw}
	r.initNetworkStatus()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); r.networkLoop(ctx) }()
	ready := false
	lastStatusLog := time.Time{}
	for ctx.Err() == nil {
		status := r.networkStatus()
		if time.Since(lastStatusLog) > time.Second {
			t.Logf("live network status: %+v", status)
			lastStatusLog = time.Now()
		}
		if !ready && len(status.Collectors) == 3 && status.Collectors[0].State == "healthy" && status.Collectors[1].State == "healthy" && status.Collectors[2].State == "healthy" {
			// A healthy reader with no measured loss maps to healthy coverage: the
			// interval before acquisition is declared, never counted as unknown.
			for _, c := range status.Collectors {
				if c.UnknownIntervals != "0" {
					t.Fatalf("healthy collector %s/%s reported %s unknown intervals with no measured loss", c.ID, c.Boundary, c.UnknownIntervals)
				}
				if !observationStartDeclared(c.ScopeLimitations) {
					t.Fatalf("collector %s/%s did not declare its observation start: %v", c.ID, c.Boundary, c.ScopeLimitations)
				}
			}
			if err := os.WriteFile(filepath.Join(work, "ready"), []byte("baseline complete"), 0600); err != nil {
				t.Fatal(err)
			}
			ready = true
		}
		if ready && status.Collectors[1].LastEventAt != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if ctx.Err() != nil {
		t.Fatalf("network readiness/traffic timed out: %+v", r.networkStatus())
	}
	final := r.networkStatus()
	for _, c := range final.Collectors {
		if c.State == "healthy" && c.UnknownIntervals != "0" {
			t.Fatalf("healthy collector %s/%s reported %s unknown intervals", c.ID, c.Boundary, c.UnknownIntervals)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("network producer failed to join")
	}
	if err := sw.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(work, "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := spool.NewImporter(st, root, time.Second, nil).ImportOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	result, err := st.Query(t.Context(), store.Query{Kind: "policy.denial", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) == 0 {
		t.Fatal("no durable actual denial traffic")
	}
	protocols := map[float64]int{}
	for _, e := range result.Events {
		if e.VMID == nil || *e.VMID != cfg.VMID || e.BootID == nil || *e.BootID != cfg.BootID || e.SourceInstanceID == cfg.InstanceID || e.Provenance != events.HostObserved || e.Data["boundary"] != "namespace_gateway" || e.Data["policy_id"] != "offline" || e.Data["acquisition_id"] == "" {
			t.Fatalf("incorrect traffic identity %+v", e)
		}
		if tuple, ok := e.Data["tuple"].(map[string]any); ok {
			if protocol, ok := tuple["protocol"].(float64); ok {
				protocols[protocol]++
			}
		}
	}
	// Both real packets crossed the observed boundary: the UDP datagrams and the
	// TCP SYN. Their denials are what the offline gateway can produce.
	if protocols[unix.IPPROTO_UDP] == 0 || protocols[unix.IPPROTO_TCP] == 0 {
		t.Fatalf("denials did not carry both real protocols: %v", protocols)
	}
	// The only profile privd installs is offline: every namespace chain is policy
	// drop and jumps to deny, and gatewayRules pins Ready false, so no packet is
	// ever accepted and conntrack never confirms an entry. A flow record here
	// would mean the gateway leaked. When privd learns to install an
	// egress-permitting profile, this assertion becomes the flow assertion.
	flows, err := st.Query(t.Context(), store.Query{Kind: "net.flow.observed", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(flows.Events) != 0 {
		t.Fatalf("offline gateway produced %d observed flows: %+v", len(flows.Events), flows.Events)
	}
	t.Logf("credential-dropped production networkLoop on inherited descriptors: baseline ready, %d real denied observations imported into SQLite by protocol %v, 0 conntrack-confirmed flows under the offline profile, cancellation joined", len(result.Events), protocols)
}

// observationStartDeclared reports whether a collector named the moment its
// observation began, which is what the pre-acquisition interval is instead of an
// unknown interval it never measured.
func observationStartDeclared(limitations []string) bool {
	for _, l := range limitations {
		if len(l) > len("observation began at ") && l[:len("observation began at ")] == "observation began at " {
			return true
		}
	}
	return false
}
