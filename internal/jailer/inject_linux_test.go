// ABOUTME: AT-005 failure injection suite: injects a failure after every provisioning side effect
// ABOUTME: and proves cleanup removes exactly the owned resources; recovery launch succeeds after each.

//go:build linux

package jailer_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/guest"
	"github.com/2389-research/observatory-v2/internal/guest/proto"
	"github.com/2389-research/observatory-v2/internal/jailer"
	"github.com/2389-research/observatory-v2/internal/network"
	"github.com/2389-research/observatory-v2/internal/preflight"
	"github.com/2389-research/observatory-v2/internal/privd"
	"github.com/2389-research/observatory-v2/internal/runtime"
)

// ---------------------------------------------------------------------------
// Decorator: failingPrivd wraps a real privdClient and fails on demand.
// ---------------------------------------------------------------------------

// failingPrivd is a jailer.PrivdClient decorator that injects errors on a named verb.
// inner wraps the REAL *privd.Client (pointed at the fake-backend server).
type failingPrivd struct {
	inner  jailer.PrivdClient
	failOn string
	calls  []string
}

func (f *failingPrivd) AllocateNetwork(ctx context.Context, req privd.AllocateNetworkReq) error {
	f.calls = append(f.calls, "allocate_network")
	if f.failOn == "allocate_network" {
		return &privd.RemoteError{Cause: "exec_failed", Message: "injected"}
	}
	return f.inner.AllocateNetwork(ctx, req)
}

func (f *failingPrivd) ReleaseNetwork(ctx context.Context, req privd.ReleaseNetworkReq) error {
	f.calls = append(f.calls, "release_network")
	return f.inner.ReleaseNetwork(ctx, req)
}

func (f *failingPrivd) StartVM(ctx context.Context, req privd.StartVMReq) (privd.StartVMResp, error) {
	f.calls = append(f.calls, "start_vm")
	if f.failOn == "start_vm" {
		return privd.StartVMResp{}, &privd.RemoteError{Cause: "exec_failed", Message: "injected"}
	}
	return f.inner.StartVM(ctx, req)
}

func (f *failingPrivd) SignalVM(ctx context.Context, req privd.SignalVMReq) error {
	f.calls = append(f.calls, "signal_vm/"+req.Kind)
	return f.inner.SignalVM(ctx, req)
}

func (f *failingPrivd) ReleaseVM(ctx context.Context, req privd.ReleaseVMReq) error {
	f.calls = append(f.calls, "release_vm")
	return f.inner.ReleaseVM(ctx, req)
}

// ---------------------------------------------------------------------------
// Injection harness builder
// ---------------------------------------------------------------------------

// injectHarness holds everything for one injection subtest.
type injectHarness struct {
	adapter *jailer.Adapter
	fp      *failingPrivd
	backend *testRecordingBackend

	stateDir  string
	stageRoot string
	spoolRoot string
	jailBase  string
	repoRoot  string
	lockPath  string
	privdSock string
	pool      *network.Allocator
	cidBase   uint32
}

// buildInjectHarness builds a full harness with the given failOn string.
// poolCIDR must be large enough for the injected launch plus the recovery launch.
// attachTimeout=0 means the default 60s; set short for the wrong-token subtest.
func buildInjectHarness(
	t *testing.T,
	failOn string,
	poolCIDR string,
	cidBase uint32,
	attachTimeout time.Duration,
) *injectHarness {
	t.Helper()
	backend := &testRecordingBackend{}
	t.Cleanup(backend.killAll)
	privdSock, stageRoot := startTestPrivdServer(t, backend)

	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	spoolRoot := filepath.Join(dir, "spool")
	jailBase := filepath.Join(dir, "jail")
	for _, d := range []string{stateDir, spoolRoot, jailBase} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	repoRoot, lockPath := makeTestImagesDir(t)

	pool, err := network.NewAllocator(nil, []netip.Prefix{netip.MustParsePrefix(poolCIDR)})
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	fp := &failingPrivd{
		inner:  &privd.Client{SocketPath: privdSock},
		failOn: failOn,
	}

	cfg := jailer.Config{
		StateDir:      stateDir,
		StageRoot:     stageRoot,
		JailBase:      jailBase,
		SpoolRoot:     spoolRoot,
		RunnerBin:     runnerBin,
		RepoRoot:      repoRoot,
		LockPath:      lockPath,
		JailUIDBase:   os.Getuid(),
		JailGID:       os.Getgid(),
		MaxSlots:      8,
		CIDBase:       cidBase,
		Allocator:     pool,
		PrivdSocket:   privdSock,
		AttachTimeout: attachTimeout,
		Preflight: func(ctx context.Context, refresh bool) preflight.Report {
			return preflight.Report{Overall: preflight.StatusPass}
		},
	}
	adapter, err := jailer.New(cfg, fp)
	if err != nil {
		t.Fatalf("jailer.New: %v", err)
	}

	return &injectHarness{
		adapter:   adapter,
		fp:        fp,
		backend:   backend,
		stateDir:  stateDir,
		stageRoot: stageRoot,
		spoolRoot: spoolRoot,
		jailBase:  jailBase,
		repoRoot:  repoRoot,
		lockPath:  lockPath,
		privdSock: privdSock,
		pool:      pool,
		cidBase:   cidBase,
	}
}

// defaultSpec returns a minimal VMSpec for vmID.
func defaultSpec(vmID string) runtime.VMSpec {
	return runtime.VMSpec{
		VMID:             vmID,
		BootID:           "boot-" + vmID,
		VCPUCount:        1,
		MemoryMiB:        512,
		WorkspaceDiskMiB: 64,
	}
}

// assertCleanup checks that the rollback left no artifacts for vmID and that the
// error names failedAt as the stage. It does not call recovery — that is the
// caller's job after any additional restore steps.
func assertCleanup(t *testing.T, h *injectHarness, vmID, failedAt string, launchErr error) {
	t.Helper()
	if launchErr == nil {
		t.Fatalf("Launch should have failed at stage %q but returned nil", failedAt)
	}
	want := "failed at stage " + failedAt
	if !strings.Contains(launchErr.Error(), want) {
		t.Errorf("error = %q; want it to contain %q", launchErr.Error(), want)
	}

	// State dir must be gone.
	vmStateDir := filepath.Join(h.stateDir, "vms", vmID)
	if _, err := os.Stat(vmStateDir); !os.IsNotExist(err) {
		t.Errorf("state dir still present after rollback (err: %v)", err)
	}

	// Manifest gone with it.
	if _, err := jailer.ReadManifest(h.stateDir, vmID); !os.IsNotExist(err) {
		t.Errorf("manifest still present after rollback (err: %v)", err)
	}

	// Stage dir must be gone.
	stageDir := filepath.Join(h.stageRoot, vmID)
	if _, err := os.Stat(stageDir); !os.IsNotExist(err) {
		t.Errorf("stage dir still present after rollback (err: %v)", err)
	}
}

// assertRecoveryLaunch clears any failure injection on h and verifies that a
// fresh Launch of vmID succeeds (the slot is free after rollback).
func assertRecoveryLaunch(t *testing.T, h *injectHarness, vmID string) {
	t.Helper()
	h.fp.failOn = ""

	// Pre-create vsock dir and start the in-process guestd for the recovery launch.
	vSockDir := filepath.Join(h.jailBase, "firecracker", vmID, "root")
	if err := os.MkdirAll(vSockDir, 0o755); err != nil {
		t.Fatalf("recovery: mkdir vsock dir: %v", err)
	}
	vSockPath := filepath.Join(vSockDir, "v.sock")
	_ = os.Remove(vSockPath) // clear any stale socket the failed launch left

	guestLn, err := listen0600(vSockPath)
	if err != nil {
		t.Fatalf("recovery: listen v.sock at %s: %v", vSockPath, err)
	}
	agentCtx, agentCancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		agentCancel()
		guestLn.Close()
	})
	tokenFile := filepath.Join(h.stateDir, "vms", vmID, "token")
	gs := &guestdServer{
		tokenFile:    tokenFile,
		vmID:         vmID,
		bootID:       "boot-" + vmID + "-recovery",
		poweroffFunc: nil,
	}
	go gs.serve(agentCtx, guestLn)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := h.adapter.Launch(ctx, defaultSpec(vmID)); err != nil {
		t.Errorf("recovery Launch for %s: %v", vmID, err)
	}
	// Kill the backend sleep child so we don't leak a process between subtests.
	h.backend.killAll()
}

// ---------------------------------------------------------------------------
// wrongTokenServer: guestd that always rejects the runner's hello because it
// uses a fixed wrong token in its BootConfig. Proves a bad token never attaches.
// §15.3: the wrong token value never appears in error strings.
// ---------------------------------------------------------------------------

// wrongTokenServer is a guestd listener that serves the vsock proxy handshake and
// then presents a wrong CapabilityToken, so every runner hello is rejected.
type wrongTokenServer struct {
	vmID       string
	bootID     string
	wrongToken string // fixed value that does NOT match what the adapter staged
}

func (w *wrongTokenServer) serve(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
			default:
			}
			return
		}
		go w.handleConn(ctx, conn)
	}
}

func (w *wrongTokenServer) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// Perform the CONNECT/OK proxy handshake (same as guestdServer).
	var line []byte
	buf := make([]byte, 1)
	for len(line) < 64 {
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return
		}
		if buf[0] == '\n' {
			break
		}
		line = append(line, buf[0])
	}
	if _, err := conn.Write([]byte("OK 12345\n")); err != nil {
		return
	}

	// Build a guest.Agent with the wrong CapabilityToken. The runner will send
	// the correct token (from the token file staged by the adapter); this agent
	// will reject it because wrongToken ≠ correct token.
	cfg := &guest.BootConfig{
		Schema:          guest.GuestContextSchema,
		VMID:            w.vmID,
		BootID:          w.bootID,
		CapabilityToken: w.wrongToken,
		ProtocolVersion: proto.ProtocolVersion,
	}
	manifest := proto.CapabilityManifest{
		Schema:        "vmobs.guest_capability.v1",
		KernelRelease: "6.1.0-test",
		Features:      []proto.Feature{{ID: "btf", Present: true}},
	}
	agent := guest.NewAgent(cfg, manifest)
	agent.PoweroffFunc = func() {} // no-op in test

	scl := &singleConnListener{conn: conn, ch: make(chan struct{})}
	_ = agent.ServeControl(ctx, scl)
}

// ---------------------------------------------------------------------------
// TestInject: one subtest per injection point (AT-005)
// ---------------------------------------------------------------------------

func TestInject(t *testing.T) {
	// ── Subtest 1: manifest write failure ─────────────────────────────────────
	// The vms/ directory is made read-only before Launch so writeManifest fails.
	// This is before any side effect — backend must see ZERO calls.
	t.Run("manifest_write_failure", func(t *testing.T) {
		h := buildInjectHarness(t, "", "10.110.0.0/24", 10, 0)
		vmID := "vm-inject-1"

		// Create vms/ then make it read-only.
		vmsDir := filepath.Join(h.stateDir, "vms")
		if err := os.MkdirAll(vmsDir, 0o700); err != nil {
			t.Fatalf("mkdir vms: %v", err)
		}
		if err := os.Chmod(vmsDir, 0o555); err != nil {
			t.Fatalf("chmod vms read-only: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(vmsDir, 0o755) })

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		launchErr := h.adapter.Launch(ctx, defaultSpec(vmID))
		if launchErr == nil {
			t.Fatal("Launch returned nil; expected failure on read-only state dir")
		}
		t.Logf("got expected error: %v", launchErr)

		// No backend calls at all — manifest write precedes every side effect.
		if len(h.fp.calls) != 0 {
			t.Errorf("expected zero backend calls; got: %v", h.fp.calls)
		}

		// Restore and run recovery.
		if err := os.Chmod(vmsDir, 0o755); err != nil {
			t.Fatalf("restore chmod: %v", err)
		}
		assertRecoveryLaunch(t, h, vmID)
	})

	// ── Subtest 2: staging digest mismatch ────────────────────────────────────
	// Tamper the vmlinux on disk so the SHA-256 check inside doStage fails.
	// Stage = "staged"; no network calls must follow.
	t.Run("staging_digest_mismatch", func(t *testing.T) {
		h := buildInjectHarness(t, "", "10.111.0.0/24", 20, 0)
		vmID := "vm-inject-2"

		// Overwrite vmlinux with wrong content to break the lock hash.
		vmlinuxPath := filepath.Join(h.repoRoot, "images", "dist", "vmlinux")
		if err := os.WriteFile(vmlinuxPath, []byte("tampered"), 0o644); err != nil {
			t.Fatalf("tamper vmlinux: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		launchErr := h.adapter.Launch(ctx, defaultSpec(vmID))
		assertCleanup(t, h, vmID, "staged", launchErr)

		for _, c := range h.fp.calls {
			if c == "allocate_network" {
				t.Errorf("allocate_network was called despite staging failure; calls=%v", h.fp.calls)
			}
		}
		t.Logf("calls after digest mismatch: %v", h.fp.calls)

		// Restore vmlinux and rewrite lock with correct SHA.
		origContent := []byte("fake-vmlinux-for-jailer-test")
		if err := os.WriteFile(vmlinuxPath, origContent, 0o644); err != nil {
			t.Fatalf("restore vmlinux: %v", err)
		}
		vmlinuxSHA := sha256Hex(origContent)
		rootfsSHA := sha256Hex([]byte("fake-rootfs-for-jailer-test"))
		lockBody := fmt.Sprintf(`{
			"schema": "vmobs.runtime_lock.v1",
			"firecracker": {"version": "v1.16.1", "sha256": "", "install_path": "/usr/local/bin/firecracker"},
			"jailer": {"sha256": "", "install_path": "/usr/local/bin/jailer"},
			"host_support": {"arch": "amd64", "min_kernel": "5.10"},
			"guest_kernel": {"version": "6.1.186", "vmlinux_sha256": %q, "vmlinux_path": "images/dist/vmlinux"},
			"root_image": {"sha256": %q, "path": "images/dist/rootfs.ext4"},
			"guestd": {"protocol_version": 1}
		}`, vmlinuxSHA, rootfsSHA)
		if err := os.WriteFile(h.lockPath, []byte(lockBody), 0o644); err != nil {
			t.Fatalf("restore lock: %v", err)
		}
		assertRecoveryLaunch(t, h, vmID)
	})

	// ── Subtest 3: allocate_network injected failure ──────────────────────────
	// Stages completed before failure: reserved, staged.
	// Rollback must: remove stage dir, remove state dir.
	// Must NOT see any release verb (network was never allocated).
	t.Run("allocate_network_failure", func(t *testing.T) {
		h := buildInjectHarness(t, "allocate_network", "10.112.0.0/24", 30, 0)
		vmID := "vm-inject-3"

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		launchErr := h.adapter.Launch(ctx, defaultSpec(vmID))
		assertCleanup(t, h, vmID, "network", launchErr)

		for _, c := range h.fp.calls {
			switch c {
			case "release_network", "release_vm", "signal_vm/term", "signal_vm/kill":
				t.Errorf("unexpected rollback verb after network failure: %q (calls=%v)", c, h.fp.calls)
			}
		}
		t.Logf("calls after allocate_network failure: %v", h.fp.calls)

		assertRecoveryLaunch(t, h, vmID)
	})

	// ── Subtest 4: start_vm injected failure ──────────────────────────────────
	// Stages completed before failure: reserved, staged, network.
	// Rollback must: remove stage dir, release_network, remove state dir.
	// Must NOT see release_vm or signal_vm (VMM never started).
	t.Run("start_vm_failure", func(t *testing.T) {
		h := buildInjectHarness(t, "start_vm", "10.113.0.0/24", 40, 0)
		vmID := "vm-inject-4"

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		launchErr := h.adapter.Launch(ctx, defaultSpec(vmID))
		assertCleanup(t, h, vmID, "vmm_started", launchErr)

		var gotRelNet bool
		for _, c := range h.fp.calls {
			switch c {
			case "release_network":
				gotRelNet = true
			case "release_vm":
				t.Errorf("release_vm called when start_vm failed (VMM never started); calls=%v", h.fp.calls)
			case "signal_vm/term", "signal_vm/kill":
				t.Errorf("signal_vm called when start_vm failed (VMM never started); calls=%v", h.fp.calls)
			}
		}
		if !gotRelNet {
			t.Errorf("expected release_network in rollback; calls=%v", h.fp.calls)
		}
		t.Logf("calls after start_vm failure: %v", h.fp.calls)

		assertRecoveryLaunch(t, h, vmID)
	})

	// ── Subtest 5: runner spawn failure ───────────────────────────────────────
	// RunnerBin → missing path so exec.Command.Start() fails.
	// Stages completed before failure: reserved, staged, network, vmm_started.
	// Rollback must: signal_vm/kill + release_vm + release_network + remove stage dir + remove state dir.
	t.Run("runner_spawn_failure", func(t *testing.T) {
		h := buildInjectHarness(t, "", "10.114.0.0/24", 50, 0)
		vmID := "vm-inject-5"

		// Build a separate adapter with a broken runner; use the same pool and fp.
		brokenCfg := jailer.Config{
			StateDir:    h.stateDir,
			StageRoot:   h.stageRoot,
			JailBase:    h.jailBase,
			SpoolRoot:   h.spoolRoot,
			RunnerBin:   "/nonexistent/vmobs-runner",
			RepoRoot:    h.repoRoot,
			LockPath:    h.lockPath,
			JailUIDBase: os.Getuid(),
			JailGID:     os.Getgid(),
			MaxSlots:    8,
			CIDBase:     h.cidBase,
			Allocator:   h.pool,
			PrivdSocket: h.privdSock,
			Preflight: func(ctx context.Context, refresh bool) preflight.Report {
				return preflight.Report{Overall: preflight.StatusPass}
			},
		}
		brokenAdapter, err := jailer.New(brokenCfg, h.fp)
		if err != nil {
			t.Fatalf("jailer.New (broken runner): %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		launchErr := brokenAdapter.Launch(ctx, defaultSpec(vmID))
		assertCleanup(t, h, vmID, "runner_spawned", launchErr)

		var gotKill, gotRelVM, gotRelNet bool
		for _, c := range h.fp.calls {
			switch c {
			case "signal_vm/kill":
				gotKill = true
			case "release_vm":
				gotRelVM = true
			case "release_network":
				gotRelNet = true
			}
		}
		if !gotKill {
			t.Errorf("expected signal_vm/kill in rollback; calls=%v", h.fp.calls)
		}
		if !gotRelVM {
			t.Errorf("expected release_vm in rollback; calls=%v", h.fp.calls)
		}
		if !gotRelNet {
			t.Errorf("expected release_network in rollback; calls=%v", h.fp.calls)
		}
		t.Logf("calls after runner spawn failure: %v", h.fp.calls)

		// Restore h.adapter to the good runner for recovery.
		goodCfg := brokenCfg
		goodCfg.RunnerBin = runnerBin
		goodAdapter, err := jailer.New(goodCfg, h.fp)
		if err != nil {
			t.Fatalf("jailer.New (recovery runner): %v", err)
		}
		h.adapter = goodAdapter
		assertRecoveryLaunch(t, h, vmID)
	})

	// ── Subtest 6: wrong token → attach timeout ───────────────────────────────
	// The guestd uses a different fixed CapabilityToken than what the adapter staged.
	// The runner redials on hello refusal; attach wait burns its full budget (short here).
	// §15.3: the wrong token value must not appear in any error string.
	t.Run("wrong_token_attach_timeout", func(t *testing.T) {
		const shortAttach = 4 * time.Second
		h := buildInjectHarness(t, "", "10.115.0.0/24", 60, shortAttach)
		vmID := "vm-inject-6"

		// Pre-create vsock dir and start the wrong-token guestd.
		vSockDir := filepath.Join(h.jailBase, "firecracker", vmID, "root")
		if err := os.MkdirAll(vSockDir, 0o755); err != nil {
			t.Fatalf("mkdir vsock dir: %v", err)
		}
		vSockPath := filepath.Join(vSockDir, "v.sock")

		guestLn, err := listen0600(vSockPath)
		if err != nil {
			t.Fatalf("listen v.sock: %v", err)
		}
		agentCtx, agentCancel := context.WithCancel(context.Background())
		t.Cleanup(func() {
			agentCancel()
			guestLn.Close()
		})

		// Fixed wrong token — all-zero hex; never matches the random adapter token.
		// §15.3: this value must not leak into error strings.
		const wrongToken = "0000000000000000000000000000000000000000000000000000000000000000"
		wts := &wrongTokenServer{vmID: vmID, bootID: "boot-" + vmID, wrongToken: wrongToken}
		go wts.serve(agentCtx, guestLn)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		launchErr := h.adapter.Launch(ctx, defaultSpec(vmID))
		assertCleanup(t, h, vmID, "attached", launchErr)

		// §15.3: token value must not appear in the error string.
		if strings.Contains(launchErr.Error(), wrongToken) {
			t.Errorf("§15.3 violation: wrong token leaked into error: %q", launchErr.Error())
		}
		t.Logf("got expected timeout error: %v", launchErr)

		// Shut down the wrong-token guestd before recovery.
		agentCancel()
		guestLn.Close()

		assertRecoveryLaunch(t, h, vmID)
	})
}
