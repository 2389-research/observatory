// ABOUTME: Linux integration tests for Stop, ForceStop, Release, and Reconcile.
// ABOUTME: Uses the same fake-privd harness as launch_linux_test.go (real runner binary, in-process guestd).

//go:build linux

package jailer_test

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/jailer"
	"github.com/2389-research/observatory/internal/network"
	"github.com/2389-research/observatory/internal/preflight"
	"github.com/2389-research/observatory/internal/privd"
	"github.com/2389-research/observatory/internal/runner"
	"github.com/2389-research/observatory/internal/runtime"
)

// ---------------------------------------------------------------------------
// Helpers shared with this file
// ---------------------------------------------------------------------------

// makeStopAdapter builds a test Adapter+backend+state ready for a launched VM.
// The caller must clean up backend.killAll() on test cleanup.
// Returns (adapter, backend, privdSock, stateDir, spoolRoot, jailBase).
func makeStopHarness(t *testing.T) (
	*jailer.Adapter,
	*testRecordingBackend,
	string, // stateDir
	string, // spoolRoot
	string, // jailBase
) {
	t.Helper()
	return makeStopHarnessWrapped(t, nil)
}

// makeStopHarnessWrapped is makeStopHarness with a hook to decorate the privd
// client the adapter talks to. wrap==nil uses the real *privd.Client unchanged;
// a non-nil wrap receives that client and returns whatever the adapter should
// call instead, which is how the release-retry tests inject privd's refusals.
func makeStopHarnessWrapped(t *testing.T, wrap func(jailer.PrivdClient) jailer.PrivdClient) (
	*jailer.Adapter,
	*testRecordingBackend,
	string, // stateDir
	string, // spoolRoot
	string, // jailBase
) {
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
	// Real ReleaseVM removal from here on, so Release's jail-chroot assertions
	// have teeth instead of passing against a backend that never modeled it.
	backend.jailBase = jailBase

	repoRoot, lockPath := makeTestImagesDir(t)

	pool, err := network.NewAllocator(nil, []netip.Prefix{netip.MustParsePrefix("10.91.0.0/24")})
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	_ = stageRoot // used by privd server internally

	cfg := jailer.Config{
		StateDir:    stateDir,
		StageRoot:   stageRoot,
		JailBase:    jailBase,
		SpoolRoot:   spoolRoot,
		RunnerBin:   runnerBin,
		RepoRoot:    repoRoot,
		LockPath:    lockPath,
		JailUIDBase: os.Getuid(),
		JailGID:     os.Getgid(),
		MaxSlots:    8,
		CIDBase:     4,
		Allocator:   pool,
		PrivdSocket: privdSock,
		Preflight: func(ctx context.Context, refresh bool) preflight.Report {
			return preflight.Report{Overall: preflight.StatusPass}
		},
	}

	var pc jailer.PrivdClient = &privd.Client{SocketPath: privdSock}
	if wrap != nil {
		pc = wrap(pc)
	}
	adapter, err := jailer.New(cfg, pc)
	if err != nil {
		t.Fatalf("jailer.New: %v", err)
	}
	return adapter, backend, stateDir, spoolRoot, jailBase
}

// launchTestVM launches a VM into state stateDir and returns the vmID.
// The guestd in-process server is started here with the given poweroffFunc.
// poweroffFunc is called when the runner sends a shutdown_guest ctl to the guest.
func launchTestVM(t *testing.T, adapter *jailer.Adapter, stateDir, jailBase string, poweroffFunc func()) string {
	t.Helper()
	vmID := "vm-stop-test-" + newRandomUUID()[:8]
	bootID := "boot-" + newRandomUUID()

	// Pre-create vsock dir and listen.
	vSockDir := filepath.Join(jailBase, "firecracker", vmID, "root")
	if err := os.MkdirAll(vSockDir, 0o755); err != nil {
		t.Fatalf("mkdir vsock dir: %v", err)
	}
	vSockPath := filepath.Join(vSockDir, "v.sock")
	tokenFile := filepath.Join(stateDir, "vms", vmID, "token")

	guestLn, err := listen0600(vSockPath)
	if err != nil {
		t.Fatalf("listen v.sock: %v", err)
	}

	agentCtx, agentCancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		agentCancel()
		guestLn.Close()
	})

	gs := &guestdServer{
		tokenFile:    tokenFile,
		vmID:         vmID,
		bootID:       bootID,
		poweroffFunc: poweroffFunc,
	}
	go gs.serve(agentCtx, guestLn)

	spec := runtime.VMSpec{
		VMID:             vmID,
		BootID:           bootID,
		VCPUCount:        1,
		MemoryMiB:        512,
		WorkspaceDiskMiB: 64,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if _, err := adapter.Launch(ctx, spec); err != nil {
		t.Fatalf("Launch %s: %v", vmID, err)
	}
	return vmID
}

// ---------------------------------------------------------------------------
// Stop tests
// ---------------------------------------------------------------------------

// TestStopGraceful: guestd that responds to shutdown → forced=false, no signal_vm calls.
func TestStopGraceful(t *testing.T) {
	adapter, backend, stateDir, _, jailBase := makeStopHarness(t)

	// poweroffFunc kills the fake-VMM sleep child — simulates "guest actually powers off".
	poweroffCalled := make(chan struct{})
	poweroffFunc := func() {
		close(poweroffCalled)
		// Kill the fake sleep VMM so runner sees vmm_exited.
		backend.killAll()
	}

	vmID := launchTestVM(t, adapter, stateDir, jailBase, poweroffFunc)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	forced, err := adapter.Stop(ctx, vmID, 10*time.Second)
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if forced {
		t.Error("Stop: forced=true, want false (graceful shutdown)")
	}

	// Runner must reach finalized.
	stateFile := filepath.Join(stateDir, "vms", vmID, "runner-state.json")
	pollCtx, pollCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer pollCancel()
	s, _ := jailer.PollRunnerPhase(pollCtx, stateFile, runner.PhaseFinalized)
	if s.Phase != runner.PhaseFinalized {
		t.Errorf("runner phase = %q, want finalized", s.Phase)
	}

	// No signal_vm should have been called (guest powered off gracefully).
	if kinds := signalsFor(backend, vmID); len(kinds) != 0 {
		t.Errorf("unexpected signal_vm calls: %v", kinds)
	}

	// Slot+network+manifest must be KEPT (stopped VM can restart).
	if _, err := jailer.ReadManifest(stateDir, vmID); err != nil {
		t.Errorf("manifest removed after Stop — must be kept: %v", err)
	}
}

// TestStopForcedOnIgnoredShutdown: guestd that never acks → forced=true, and a
// SIGTERM the VMM actually dies from ends the stop there.
//
// The SIGKILL used to go out unconditionally, five seconds after the SIGTERM,
// on the reasoning that a second signal costs nothing. It does: the pid is
// reaped by then, so the only thing that signal can reach is whatever the
// kernel handed the number to next. privd re-checks the identity before
// signalling, so nothing was ever hurt — but a stop cannot both know the VMM is
// gone and go on signalling it, and every escalated stop paid the five seconds.
func TestStopForcedOnIgnoredShutdown(t *testing.T) {
	adapter, backend, stateDir, _, jailBase := makeStopHarness(t)

	// poweroffFunc does nothing — simulates guest ignoring shutdown.
	poweroffFunc := func() {}

	vmID := launchTestVM(t, adapter, stateDir, jailBase, poweroffFunc)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Short grace so test completes quickly.
	forced, err := adapter.Stop(ctx, vmID, 1*time.Second)
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !forced {
		t.Error("Stop: forced=false, want true (guest ignored shutdown)")
	}

	kinds := signalsFor(backend, vmID)
	if len(kinds) != 1 || kinds[0] != "term" {
		t.Errorf("signals = %v, want [term] only: this backend's VMM dies from the "+
			"SIGTERM, and a VMM observed gone gets no second signal", kinds)
	}
}

// TestStopEscalatesWhenTermIgnored is the other side of the same gate.
// Firecracker exits on SIGTERM, but a VMM wedged in the kernel does not, and
// that is the case the escalation exists for: the SIGTERM is not evidence, the
// process leaving /proc is.
//
// The name is short on purpose. This harness puts a vsock socket under
// t.TempDir(), which contains the test's name, and a unix socket path is capped
// at 108 bytes -- a longer name fails the launch with "bind: invalid argument"
// long before anything here is exercised.
func TestStopEscalatesWhenTermIgnored(t *testing.T) {
	adapter, backend, stateDir, _, jailBase := makeStopHarness(t)
	// The backend accepts the SIGTERM and does nothing about it, so the
	// stand-in VMM is still there when the proof gate looks.
	backend.ignoredSignals = map[string]bool{"term": true}

	vmID := launchTestVM(t, adapter, stateDir, jailBase, func() {})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	forced, err := adapter.Stop(ctx, vmID, 1*time.Second)
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !forced {
		t.Error("Stop: forced=false, want true")
	}

	kinds := signalsFor(backend, vmID)
	if len(kinds) != 2 || kinds[0] != "term" || kinds[1] != "kill" {
		t.Errorf("signals = %v, want [term kill]: a VMM that survived the SIGTERM "+
			"must be escalated, not reported stopped", kinds)
	}
}

// signalsFor returns the signal kinds the backend recorded for vmID, in order.
func signalsFor(backend *testRecordingBackend, vmID string) []string {
	var kinds []string
	for _, call := range backend.signalCalls {
		id, kind, ok := strings.Cut(call, "/")
		if ok && id == vmID {
			kinds = append(kinds, kind)
		}
	}
	return kinds
}

// TestForceStopSendsKill: ForceStop → kill signal, no graceful attempt.
func TestForceStopSendsKill(t *testing.T) {
	adapter, backend, stateDir, _, jailBase := makeStopHarness(t)

	poweroffFunc := func() {}
	vmID := launchTestVM(t, adapter, stateDir, jailBase, poweroffFunc)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := adapter.ForceStop(ctx, vmID); err != nil {
		t.Fatalf("ForceStop: %v", err)
	}

	// Must have seen a kill signal and must NOT have seen a term signal.
	if kinds := signalsFor(backend, vmID); len(kinds) != 1 || kinds[0] != "kill" {
		t.Errorf("signals = %v, want [kill]: ForceStop skips the graceful path entirely", kinds)
	}
}

// ---------------------------------------------------------------------------
// release_vm retry (the SIGKILL race that leaked a 1.7 GB chroot on aibox03)
// ---------------------------------------------------------------------------

// refusingReleasePrivd decorates a real privd client and answers release_vm with a
// chosen refusal for the first refusals calls, then delegates. Every other verb is
// promoted from the embedded client untouched.
type refusingReleasePrivd struct {
	jailer.PrivdClient
	refusal  error // what the refused calls return
	refusals int   // refusals left to serve
	calls    int   // release_vm calls seen, refused and delegated alike
}

func (p *refusingReleasePrivd) ReleaseVM(ctx context.Context, req privd.ReleaseVMReq) error {
	p.calls++
	if p.refusals > 0 {
		p.refusals--
		return p.refusal
	}
	return p.PrivdClient.ReleaseVM(ctx, req)
}

func (p *refusingReleasePrivd) NetworkLeases(ctx context.Context) (map[string]string, error) {
	return p.PrivdClient.(interface {
		NetworkLeases(context.Context) (map[string]string, error)
	}).NetworkLeases(ctx)
}

// aliveRefusal is privd's verbatim answer when the ledger still shows the VM process
// alive (internal/privd/server.go:357-360). SIGKILL is asynchronous, so a release
// issued the instant after the signal legitimately gets this.
func aliveRefusal() error {
	return &privd.RemoteError{Cause: "invalid_state", Message: "vm process is still alive; signal first"}
}

// TestForceStopRetriesRelease: privd refuses release_vm with its typed
// "signal first" invalid_state while it can still see the VMM process. The adapter
// must keep asking until privd accepts. Dropping that refusal is what left a 1.7 GB
// jail chroot and an immortal ledger entry on the host in live gate run 4, while the
// VM row read "deleted".
func TestForceStopRetriesRelease(t *testing.T) {
	var refuser *refusingReleasePrivd
	adapter, backend, stateDir, _, jailBase := makeStopHarnessWrapped(t,
		func(inner jailer.PrivdClient) jailer.PrivdClient {
			refuser = &refusingReleasePrivd{PrivdClient: inner, refusal: aliveRefusal(), refusals: 2}
			return refuser
		})

	vmID := launchTestVM(t, adapter, stateDir, jailBase, func() {})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := adapter.ForceStop(ctx, vmID); err != nil {
		t.Fatalf("ForceStop: %v", err)
	}

	// Two refusals then an accepted call: anything less means the adapter took the
	// first refusal as an answer.
	if refuser.calls < 3 {
		t.Errorf("release_vm attempts = %d, want >= 3 (two refusals then an accepted call): "+
			"the adapter discarded privd's invalid_state refusal instead of retrying", refuser.calls)
	}

	// A retry that never lands is the same leak — privd's backend must have run it.
	released := false
	for _, id := range backend.releaseVMCalls {
		if id == vmID {
			released = true
		}
	}
	if !released {
		t.Errorf("privd backend never ran release_vm for %s — the jail chroot leaked "+
			"(backend release_vm calls: %v)", vmID, backend.releaseVMCalls)
	}
}

// TestForceStopReleaseErrNoRetry: only "invalid_state" means "signal
// first, then ask again". Every other cause is a real failure and must be taken as
// the answer, so the retry cannot spin out the whole release deadline on, say, a
// broken jail directory.
func TestForceStopReleaseErrNoRetry(t *testing.T) {
	var refuser *refusingReleasePrivd
	adapter, _, stateDir, _, jailBase := makeStopHarnessWrapped(t,
		func(inner jailer.PrivdClient) jailer.PrivdClient {
			refuser = &refusingReleasePrivd{
				PrivdClient: inner,
				refusal:     &privd.RemoteError{Cause: "exec_failed", Message: "rm -rf jail dir: permission denied"},
				refusals:    100, // effectively "always"
			}
			return refuser
		})

	vmID := launchTestVM(t, adapter, stateDir, jailBase, func() {})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The VMM is proven gone and its chroot is not: that is a stop with a debt,
	// not a failed stop, and the two have to be told apart by the caller.
	err := adapter.ForceStop(ctx, vmID)
	var pending *runtime.ErrCleanupPending
	if !errors.As(err, &pending) {
		t.Fatalf("ForceStop = %v, want *runtime.ErrCleanupPending", err)
	}
	if !strings.Contains(pending.Reason, "permission denied") {
		t.Errorf("reason = %q, want privd's own refusal", pending.Reason)
	}

	if refuser.calls != 1 {
		t.Errorf("release_vm attempts = %d, want 1: exec_failed is a real failure, not "+
			"privd asking to be signalled first", refuser.calls)
	}
}

// ---------------------------------------------------------------------------
// Release tests (R1: full resource release for delete path)
// ---------------------------------------------------------------------------

// TestReleaseFreesAllResources: Release → ReleaseNetwork + removes manifest + state dir + stage dir.
// Spool dir must remain.
func TestReleaseFreesAllResources(t *testing.T) {
	adapter, _, stateDir, spoolRoot, jailBase := makeStopHarness(t)

	poweroffFunc := func() {}
	vmID := launchTestVM(t, adapter, stateDir, jailBase, poweroffFunc)

	// Verify manifest exists before release.
	if _, err := jailer.ReadManifest(stateDir, vmID); err != nil {
		t.Fatalf("manifest missing before Release: %v", err)
	}

	// Stop first (to get to a stable state), then Release.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_ = adapter.ForceStop(ctx, vmID) // best-effort; may fail if already dead

	if err := adapter.Release(ctx, vmID); err != nil {
		t.Fatalf("Release: %v", err)
	}

	// Manifest must be gone.
	if _, err := jailer.ReadManifest(stateDir, vmID); !os.IsNotExist(err) {
		t.Errorf("manifest still present after Release (err: %v)", err)
	}

	// State dir must be gone.
	vmStateDir := filepath.Join(stateDir, "vms", vmID)
	if _, err := os.Stat(vmStateDir); !os.IsNotExist(err) {
		t.Errorf("state dir still present after Release: %v", err)
	}

	// Jail chroot must be gone. ForceStop above already calls release_vm on its
	// own, so this alone would pass even with doRelease's manifest-present leak
	// still in place — TestReleaseWithManifestReclaimsTheJailChroot is what
	// actually pins that fix; this assertion is here because the silence that
	// let the leak ship was here too.
	jailDir := filepath.Join(jailBase, "firecracker", vmID)
	if _, err := os.Stat(jailDir); !os.IsNotExist(err) {
		t.Errorf("jail chroot %s still present after Release: %v", jailDir, err)
	}

	// Spool dir must remain (importer reads it).
	vmSpoolDir := filepath.Join(spoolRoot, vmID)
	if _, err := os.Stat(vmSpoolDir); err != nil {
		t.Errorf("spool dir removed after Release (must be kept): %v", err)
	}
}

// TestReleaseUnknownVMIDReturnsNil: Release on unknown vmID → nil (idempotent).
func TestReleaseUnknownVMIDReturnsNil(t *testing.T) {
	adapter, _, _, _, _ := makeStopHarness(t)

	ctx := context.Background()
	if err := adapter.Release(ctx, "vm-never-existed"); err != nil {
		t.Errorf("Release of unknown vmID should return nil, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Reconcile tests
// ---------------------------------------------------------------------------

// TestReconcileAdoptsHealthyVM: manifest with runner alive + VMM identity matches → adopted.
func TestReconcileAdoptsHealthyVM(t *testing.T) {
	adapter, backend, stateDir, spoolRoot, jailBase := makeStopHarness(t)

	poweroffFunc := func() {}
	vmID := launchTestVM(t, adapter, stateDir, jailBase, poweroffFunc)
	_ = spoolRoot

	// The VM is running; Reconcile should adopt it.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	findings, err := adapter.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var found *jailer.Finding
	for i := range findings {
		if findings[i].VMID == vmID {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("Reconcile: no Finding for %s (findings: %v)", vmID, findings)
	}
	if found.Outcome != "adopted" {
		t.Errorf("Reconcile outcome = %q, want adopted (detail: %s)", found.Outcome, found.Detail)
	}

	// Cleanup — stop the VM so the sleep process dies.
	_ = backend.killAll
	backend.killAll()
}

// TestReconcileVMMGone: manifest present but VMM process gone → vmm_gone.
func TestReconcileVMMGone(t *testing.T) {
	// Manually create a manifest pointing at a now-dead process.
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(filepath.Join(stateDir, "vms", "vm-gone"), 0o700); err != nil {
		t.Fatal(err)
	}

	// Spawn and kill a sleep to get a known-dead PID.
	cmd := exec.Command("sleep", "300")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	// Read starttime while alive.
	statData, err := os.ReadFile(privd.ProcStatPath(pid))
	if err != nil {
		t.Fatal(err)
	}
	starttime := privd.ParseStartTime(string(statData))
	_ = cmd.Process.Kill()
	_ = cmd.Wait()

	m := jailer.Manifest{
		VMID:     "vm-gone",
		Slot:     0,
		UID:      os.Getuid(),
		GID:      os.Getgid(),
		CID:      5,
		CIDR:     "10.91.0.0/30",
		VMMPID:   pid,
		VMMStart: starttime,
		Stages:   []string{"reserved", "staged", "network", "vmm_started", "runner_spawned", "attached"},
	}
	if err := jailer.WriteManifestExported(stateDir, m); err != nil {
		t.Fatal(err)
	}

	// Build a minimal adapter with this stateDir.
	pool, err := network.NewAllocator(nil, []netip.Prefix{netip.MustParsePrefix("10.91.0.0/24")})
	if err != nil {
		t.Fatal(err)
	}

	cfg := jailer.Config{
		StateDir:    stateDir,
		StageRoot:   filepath.Join(dir, "stage"),
		JailBase:    filepath.Join(dir, "jail"),
		SpoolRoot:   filepath.Join(dir, "spool"),
		RunnerBin:   runnerBin,
		RepoRoot:    filepath.Join(dir, "images"), // won't be used in Reconcile
		LockPath:    filepath.Join(dir, "lock.json"),
		PrivdSocket: filepath.Join(dir, "privd.sock"), // non-existent — reconcile shouldn't call privd
		JailUIDBase: os.Getuid(),
		JailGID:     os.Getgid(),
		MaxSlots:    8,
		CIDBase:     5,
		Allocator:   pool,
		Preflight: func(ctx context.Context, refresh bool) preflight.Report {
			return preflight.Report{Overall: preflight.StatusPass}
		},
	}

	fakePc := &privd.Client{SocketPath: cfg.PrivdSocket}
	adapter, err := jailer.New(cfg, fakePc)
	if err != nil {
		t.Fatalf("jailer.New: %v", err)
	}

	ctx := context.Background()
	findings, err := adapter.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var found *jailer.Finding
	for i := range findings {
		if findings[i].VMID == "vm-gone" {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no Finding for vm-gone (findings: %v)", findings)
	}
	if found.Outcome != "vmm_gone" {
		t.Errorf("outcome = %q, want vmm_gone", found.Outcome)
	}
}

// TestReconcileAmbiguousUnreadableManifest: unreadable manifest → ambiguous, nothing touched.
func TestReconcileAmbiguousUnreadableManifest(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	vmStateDir := filepath.Join(stateDir, "vms", "vm-ambig")
	if err := os.MkdirAll(vmStateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Write a corrupt manifest.
	manifestPath := filepath.Join(vmStateDir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte("{invalid json}"), 0o644); err != nil {
		t.Fatal(err)
	}
	sentinelFile := filepath.Join(vmStateDir, "sentinel.txt")
	if err := os.WriteFile(sentinelFile, []byte("do not touch"), 0o644); err != nil {
		t.Fatal(err)
	}

	pool, err := network.NewAllocator(nil, []netip.Prefix{netip.MustParsePrefix("10.91.1.0/24")})
	if err != nil {
		t.Fatal(err)
	}

	cfg := jailer.Config{
		StateDir:    stateDir,
		StageRoot:   filepath.Join(dir, "stage"),
		JailBase:    filepath.Join(dir, "jail"),
		SpoolRoot:   filepath.Join(dir, "spool"),
		RunnerBin:   runnerBin,
		RepoRoot:    filepath.Join(dir, "images"),
		LockPath:    filepath.Join(dir, "lock.json"),
		PrivdSocket: filepath.Join(dir, "privd.sock"),
		JailUIDBase: os.Getuid(),
		JailGID:     os.Getgid(),
		MaxSlots:    8,
		CIDBase:     6,
		Allocator:   pool,
		Preflight: func(ctx context.Context, refresh bool) preflight.Report {
			return preflight.Report{Overall: preflight.StatusPass}
		},
	}

	fakePc := &privd.Client{SocketPath: cfg.PrivdSocket}
	adapter, err := jailer.New(cfg, fakePc)
	if err != nil {
		t.Fatalf("jailer.New: %v", err)
	}

	ctx := context.Background()
	findings, err := adapter.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var found *jailer.Finding
	for i := range findings {
		if findings[i].VMID == "vm-ambig" {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no Finding for vm-ambig (findings: %v)", findings)
	}
	if found.Outcome != "ambiguous" {
		t.Errorf("outcome = %q, want ambiguous", found.Outcome)
	}

	// Sentinel file must be intact — nothing was touched.
	if _, err := os.Stat(sentinelFile); err != nil {
		t.Errorf("sentinel file touched by ambiguous reconcile: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Availability tests (AT-001: first failing check in error)
// ---------------------------------------------------------------------------

func TestAvailabilityPassWhenPreflightPasses(t *testing.T) {
	pool, _ := network.NewAllocator(nil, []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")})
	cfg := jailer.Config{
		StateDir: t.TempDir(), StageRoot: t.TempDir(), JailBase: t.TempDir(),
		SpoolRoot: t.TempDir(), RunnerBin: runnerBin, RepoRoot: t.TempDir(),
		LockPath: filepath.Join(t.TempDir(), "lock.json"), MaxSlots: 1,
		PrivdSocket: filepath.Join(t.TempDir(), "p.sock"),
		Allocator:   pool,
		Preflight: func(ctx context.Context, _ bool) preflight.Report {
			return preflight.Report{Overall: preflight.StatusPass}
		},
	}
	pc := &privd.Client{SocketPath: cfg.PrivdSocket}
	a, err := jailer.New(cfg, pc)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Availability(context.Background()); err != nil {
		t.Errorf("Availability on pass report = %v, want nil", err)
	}
}

func TestAvailabilityFailSurfacesFirstFailingCheck(t *testing.T) {
	pool, _ := network.NewAllocator(nil, []netip.Prefix{netip.MustParsePrefix("10.99.1.0/24")})
	cfg := jailer.Config{
		StateDir: t.TempDir(), StageRoot: t.TempDir(), JailBase: t.TempDir(),
		SpoolRoot: t.TempDir(), RunnerBin: runnerBin, RepoRoot: t.TempDir(),
		LockPath: filepath.Join(t.TempDir(), "lock.json"), MaxSlots: 1,
		PrivdSocket: filepath.Join(t.TempDir(), "p.sock"),
		Allocator:   pool,
		Preflight: func(ctx context.Context, _ bool) preflight.Report {
			return preflight.Report{
				Overall: preflight.StatusFail,
				Checks: []preflight.Check{
					{ID: "arch_kvm", Status: preflight.StatusPass, Summary: "ok"},
					{ID: "fc_binaries", Status: preflight.StatusFail, Summary: "binaries missing"},
				},
			}
		},
	}
	pc := &privd.Client{SocketPath: cfg.PrivdSocket}
	a, err := jailer.New(cfg, pc)
	if err != nil {
		t.Fatal(err)
	}
	avErr := a.Availability(context.Background())
	if avErr == nil {
		t.Fatal("Availability on fail report should return error")
	}
	var ue *runtime.UnavailableError
	if !isUnavailableError(avErr, &ue) {
		t.Fatalf("error is not *UnavailableError: %T %v", avErr, avErr)
	}
	if ue.Reason != "fc_binaries: binaries missing" {
		t.Errorf("UnavailableError.Reason = %q, want %q", ue.Reason, "fc_binaries: binaries missing")
	}
}

func isUnavailableError(err error, out **runtime.UnavailableError) bool {
	if err == nil {
		return false
	}
	var ue *runtime.UnavailableError
	if errors.As(err, &ue) {
		if out != nil {
			*out = ue
		}
		return true
	}
	return false
}
