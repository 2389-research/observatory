// ABOUTME: AT-005 failure injection suite: injects a failure after every provisioning side effect
// ABOUTME: and proves cleanup removes exactly the owned resources; recovery launch succeeds after each.

//go:build linux

package jailer_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/guest"
	"github.com/2389-research/observatory/internal/guest/proto"
	"github.com/2389-research/observatory/internal/jailer"
	"github.com/2389-research/observatory/internal/network"
	"github.com/2389-research/observatory/internal/preflight"
	"github.com/2389-research/observatory/internal/privd"
	"github.com/2389-research/observatory/internal/runtime"
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

func (f *failingPrivd) NetworkLeases(ctx context.Context) (map[string]string, error) {
	return f.inner.(interface {
		NetworkLeases(context.Context) (map[string]string, error)
	}).NetworkLeases(ctx)
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
	poolCIDR  string
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
	backend.jailBase = jailBase
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
		poolCIDR:  poolCIDR,
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

	// Whatever else the rollback did, an archive it names has to be there and
	// has to hold something. An error that points at an empty or missing
	// directory is worse than one that points nowhere.
	if archive := rescuedArchive(launchErr); archive != "" {
		assertRescuedArchive(t, archive)
	}
}

// rescueMarker is what the launch error puts before the archive path. Kept in
// one place so the tests break loudly if launch.go stops saying it.
const rescueMarker = "runner output rescued to "

// rescuedArchive returns the archive path a launch error names, or "" if it
// names none.
func rescuedArchive(launchErr error) string {
	if launchErr == nil {
		return ""
	}
	msg := launchErr.Error()
	i := strings.Index(msg, rescueMarker)
	if i < 0 {
		return ""
	}
	return msg[i+len(rescueMarker):]
}

// assertRescuedArchive checks the one thing the archive exists to provide: the
// runner's own output, with the capability token nowhere near it (§15.3).
func assertRescuedArchive(t *testing.T, archive string) {
	t.Helper()
	entries, err := os.ReadDir(archive)
	if err != nil {
		t.Errorf("launch error names rescue archive %s, which cannot be read: %v", archive, err)
		return
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "token") {
			t.Errorf("§15.3 violation: rescue archive %s holds %q", archive, e.Name())
		}
	}
	body, err := os.ReadFile(filepath.Join(archive, "runner.log"))
	if err != nil {
		t.Errorf("rescue archive %s has no readable runner.log: %v", archive, err)
		return
	}
	if len(body) == 0 {
		t.Errorf("rescue archive %s holds an empty runner.log, which explains nothing", archive)
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
	if _, err := h.adapter.Launch(ctx, defaultSpec(vmID)); err != nil {
		t.Errorf("recovery Launch for %s: %v", vmID, err)
		// No wait here, and nothing recorded to wait with. A failed Launch has
		// already run doRollback, which SIGKILLs the runner and then removes the
		// manifest along with the whole VM state dir (launch.go:479-522) -- so the
		// pid is gone from the record, and the kill happened synchronously inside
		// the Launch call that just returned. One failure escapes that: if
		// writeManifest fails at launch.go:226 the runner is already started, but
		// the on-disk manifest doRollback re-reads records neither the pid nor
		// stageRunnerSpawned, so the kill is skipped and this path returns with
		// that runner still alive. The window this helper exists to close is the
		// other one: a runner that was never signalled, shutting itself down a
		// tick at a time after its VMM dies -- which is what a successful launch
		// leaves behind.
		h.backend.killAll()
		return
	}

	// Kill the stand-in VMM so the runner shuts down, then wait for it to be
	// gone before returning. Both halves matter: killing it alone only starts
	// the shutdown, and the runner keeps writing until it finishes.
	m, err := jailer.ReadManifest(h.stateDir, vmID)
	if err != nil {
		t.Fatalf("recovery: read manifest for %s: %v", vmID, err)
	}
	h.backend.killAll()
	waitRunnerExit(t, m.RunnerPID)
}

// waitRunnerExit blocks until pid is gone, with a deadline.
//
// A successful launch leaves a real vmobs-runner writing runner-state.json and
// spool segments under the harness's t.TempDir() tree. Killing the stand-in VMM
// only starts its shutdown: watchVMM notices within a tick, and the exit path
// writes the state file twice more and closes the spool. Returning during that
// window leaves a live writer in a tree t.TempDir is about to delete, and
// RemoveAll then fails the test with "unlinkat <stateDir>/vms/<vmID>: directory
// not empty".
//
// Polling is the available synchronization: the runner is not this test's child
// to wait on -- Launch's own cmd.Wait goroutine owns it, which is also why the
// pid really does disappear rather than lingering as a zombie.
func waitRunnerExit(t *testing.T, pid int) {
	t.Helper()
	if pid <= 0 {
		t.Fatalf("waitRunnerExit: no runner pid to wait on (got %d); a successful "+
			"launch always records one in the manifest, so waiting on this would "+
			"return green without observing anything", pid)
	}
	const timeout = 30 * time.Second
	deadline := time.Now().Add(timeout)
	for {
		// Signal 0 checks liveness without delivering anything; ESRCH means the
		// process is gone and reaped.
		if err := syscall.Kill(pid, 0); err != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("runner pid %d still alive %s after its VMM was killed", pid, timeout)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
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

// assertCallsEqual checks that fp.calls is exactly equal to want (same length, same order).
// On mismatch it logs both slices to aid diagnosis.
func assertCallsEqual(t *testing.T, want, got []string) {
	t.Helper()
	match := len(want) == len(got)
	if match {
		for i := range want {
			if want[i] != got[i] {
				match = false
				break
			}
		}
	}
	if !match {
		t.Errorf("call sequence mismatch:\n  want: %v\n   got: %v", want, got)
	}
}

// assertRunnerGone scans /proc/*/cmdline for entries carrying vmID in the runner argv and
// asserts zero matches. The runner passes --vm-id=<vmID> on its command line; this scan
// is scoped to this vmID so concurrent tests with different IDs do not interfere.
func assertRunnerGone(t *testing.T, vmID string) {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Errorf("assertRunnerGone: readdir /proc: %v", err)
		return
	}
	var found []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Only numeric entries (PIDs).
		name := e.Name()
		isPID := len(name) > 0
		for _, c := range name {
			if c < '0' || c > '9' {
				isPID = false
				break
			}
		}
		if !isPID {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", name, "cmdline"))
		if err != nil {
			// Process may have exited; skip.
			continue
		}
		// cmdline is NUL-separated; replace NULs with spaces for substring search.
		cmdline := strings.ReplaceAll(string(data), "\x00", " ")
		if strings.Contains(cmdline, vmID) {
			found = append(found, fmt.Sprintf("pid=%s cmdline=%q", name, cmdline))
		}
	}
	if len(found) != 0 {
		t.Errorf("assertRunnerGone: runner process still alive for vm_id=%q after rollback:\n%s",
			vmID, strings.Join(found, "\n"))
	}
}

// ---------------------------------------------------------------------------
// Child launch under RLIMIT_FSIZE=0: the manifest-write injection
// ---------------------------------------------------------------------------

// helperEnv selects the role of a re-executed test binary (dispatched at the
// top of TestMain). Its only value is helperLaunchWriteFail.
const helperEnv = "VMOBS_INJECT_HELPER"

// helperLaunchWriteFail names the child that runs one Launch with RLIMIT_FSIZE=0.
const helperLaunchWriteFail = "launch-write-fail"

// launchWriteFailHelper is the body of the re-executed test binary for the
// manifest-write subtests. It lowers RLIMIT_FSIZE to zero so the first write
// that extends a regular file fails with EFBIG (Go ignores SIGXFSZ) -- the
// ENOSPC/EIO class of failure writeManifest meets in production, and unlike a
// chmod it leaves the state dir writable, so what Launch leaves behind is what
// it chose to leave rather than what it could not remove. It then runs one
// Launch against the harness the parent describes in VMOBS_INJECT_* variables
// and prints the error. A child holds the limit because it is process-wide: in
// the parent, the testing package flushes its own log file whenever its buffer
// fills, and that write would fail too.
//
// Exit status: 1 when Launch failed (its error on stdout), 0 when it succeeded,
// 2 on a setup problem (details on stderr).
func launchWriteFailHelper() int {
	get := func(key string) string {
		v := os.Getenv("VMOBS_INJECT_" + key)
		if v == "" {
			fmt.Fprintf(os.Stderr, "helper: VMOBS_INJECT_%s unset\n", key)
			os.Exit(2)
		}
		return v
	}
	pool, err := network.NewAllocator(nil, []netip.Prefix{netip.MustParsePrefix(get("POOL"))})
	if err != nil {
		fmt.Fprintf(os.Stderr, "helper: NewAllocator: %v\n", err)
		return 2
	}
	var cidBase uint32
	if _, err := fmt.Sscan(get("CID_BASE"), &cidBase); err != nil {
		fmt.Fprintf(os.Stderr, "helper: CID_BASE: %v\n", err)
		return 2
	}
	cfg := jailer.Config{
		StateDir:    get("STATE_DIR"),
		StageRoot:   get("STAGE_ROOT"),
		JailBase:    get("JAIL_BASE"),
		SpoolRoot:   get("SPOOL_ROOT"),
		RunnerBin:   get("RUNNER_BIN"),
		RepoRoot:    get("REPO_ROOT"),
		LockPath:    get("LOCK_PATH"),
		JailUIDBase: os.Getuid(),
		JailGID:     os.Getgid(),
		MaxSlots:    8,
		CIDBase:     cidBase,
		Allocator:   pool,
		PrivdSocket: get("PRIVD_SOCK"),
		Preflight: func(ctx context.Context, refresh bool) preflight.Report {
			return preflight.Report{Overall: preflight.StatusPass}
		},
	}
	adapter, err := jailer.New(cfg, &privd.Client{SocketPath: cfg.PrivdSocket})
	if err != nil {
		fmt.Fprintf(os.Stderr, "helper: jailer.New: %v\n", err)
		return 2
	}
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &lim); err != nil {
		fmt.Fprintf(os.Stderr, "helper: getrlimit RLIMIT_FSIZE: %v\n", err)
		return 2
	}
	lim.Cur = 0
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &lim); err != nil {
		fmt.Fprintf(os.Stderr, "helper: setrlimit RLIMIT_FSIZE=0: %v\n", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := adapter.Launch(ctx, defaultSpec(get("VM_ID"))); err != nil {
		fmt.Println(err.Error())
		return 1
	}
	return 0
}

// launchWithWriteFail runs one Launch of vmID against h in a re-executed test
// binary whose RLIMIT_FSIZE is zero (launchWriteFailHelper), so writeManifest
// fails on its first write, and returns the error text the child printed. The
// child talks to the same in-process privd server, so its privd verbs land on
// h.backend, not on h.fp. Fails the test when the child's Launch does not fail.
func launchWithWriteFail(t *testing.T, h *injectHarness, vmID string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(),
		helperEnv+"="+helperLaunchWriteFail,
		"VMOBS_INJECT_STATE_DIR="+h.stateDir,
		"VMOBS_INJECT_STAGE_ROOT="+h.stageRoot,
		"VMOBS_INJECT_JAIL_BASE="+h.jailBase,
		"VMOBS_INJECT_SPOOL_ROOT="+h.spoolRoot,
		"VMOBS_INJECT_RUNNER_BIN="+runnerBin,
		"VMOBS_INJECT_REPO_ROOT="+h.repoRoot,
		"VMOBS_INJECT_LOCK_PATH="+h.lockPath,
		"VMOBS_INJECT_PRIVD_SOCK="+h.privdSock,
		"VMOBS_INJECT_POOL="+h.poolCIDR,
		"VMOBS_INJECT_CID_BASE="+fmt.Sprint(h.cidBase),
		"VMOBS_INJECT_VM_ID="+vmID,
	)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		// The child has launched a whole VM under the limit; stop its stand-in
		// VMM so the runner it left behind shuts down.
		h.backend.killAll()
		t.Fatalf("child Launch of %s succeeded; the manifest write should have failed", vmID)
	case errors.As(err, &exitErr) && exitErr.ExitCode() == 1:
		// Launch failed, as injected.
	default:
		t.Fatalf("child Launch of %s: %v\nstdout: %s\nstderr: %s", vmID, err, stdout.String(), stderr.String())
	}
	return strings.TrimSpace(stdout.String())
}

// backendCallCount is the number of privd verbs the in-process server's backend
// recorded, across every verb. It is the zero-calls check for a launch that ran
// in a child process, where h.fp saw nothing.
func backendCallCount(h *injectHarness) int {
	b := h.backend
	return len(b.allocateCalls) + len(b.releaseCalls) + len(b.startCalls) +
		len(b.signalCalls) + len(b.releaseVMCalls)
}

// ---------------------------------------------------------------------------
// TestInject: one subtest per injection point (AT-005)
// ---------------------------------------------------------------------------

func TestInject(t *testing.T) {
	// ── Subtest 1: state dir mkdir failure ────────────────────────────────────
	// vms/ is made read-only before Launch so os.MkdirAll(vms/<id>) at launch.go
	// step 2 fails. Nothing exists on disk yet and no side effect has run —
	// backend must see ZERO calls. (writeManifest never runs here; subtests 2
	// and 3 inject at that write.)
	t.Run("state_dir_mkdir_failure", func(t *testing.T) {
		// chmod 0555 cannot block root's MkdirAll — this subtest requires non-root.
		if os.Getuid() == 0 {
			t.Fatal("this subtest requires non-root: chmod 0555 cannot block root's MkdirAll")
		}

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

		_, launchErr := h.adapter.Launch(ctx, defaultSpec(vmID))

		// assertCleanup verifies error contains the failed stage and all artifacts are gone.
		// Stage is "reserved": the state dir mkdir is the first filesystem step after
		// allocating the slot.
		if err := os.Chmod(vmsDir, 0o755); err != nil {
			t.Fatalf("restore chmod before assertCleanup: %v", err)
		}
		assertCleanup(t, h, vmID, "reserved", launchErr)
		// Pin the injection point: the mkdir failed, not the manifest write after it.
		if !strings.Contains(launchErr.Error(), "mkdir state dir") {
			t.Errorf("error = %q; want it to contain %q", launchErr.Error(), "mkdir state dir")
		}
		t.Logf("got expected error: %v", launchErr)

		// No backend calls at all — the state dir mkdir precedes every side effect.
		if len(h.fp.calls) != 0 {
			t.Errorf("expected zero backend calls; got: %v", h.fp.calls)
		}

		assertRecoveryLaunch(t, h, vmID)
	})

	// ── Subtest 2: manifest write failure, fresh VM ───────────────────────────
	// The [reserved] manifest write is the first file write of a launch. A child
	// runs it under RLIMIT_FSIZE=0 (launchWithWriteFail) so writeManifest fails
	// with the state dir already made and still writable. No manifest means
	// doRollback has nothing to read: Launch must reclaim that dir itself. The
	// backend must see ZERO calls.
	t.Run("manifest_write_fresh_vm", func(t *testing.T) {
		h := buildInjectHarness(t, "", "10.116.0.0/24", 70, 0)
		vmID := "vm-inject-7"

		errText := launchWithWriteFail(t, h, vmID)
		launchErr := errors.New(errText)
		assertCleanup(t, h, vmID, "reserved", launchErr)
		// Pin the injection point: the mkdir succeeded, the manifest write failed.
		if !strings.Contains(errText, "write manifest") {
			t.Errorf("error = %q; want it to contain %q", errText, "write manifest")
		}
		t.Logf("got expected error: %v", launchErr)

		// No backend calls at all — the manifest write precedes every side effect.
		if n := backendCallCount(h); n != 0 {
			t.Errorf("expected zero backend calls; got %d (allocate: %v)", n, h.backend.allocateCalls)
		}

		assertRecoveryLaunch(t, h, vmID)
	})

	// ── Subtest 3: manifest write failure, restart ────────────────────────────
	// A stopped VM keeps its manifest, network and slot (doStop), and a restart
	// reuses them. When the [reserved] write of that restart fails, the state dir
	// must survive: the previous manifest in it is the only record of the network
	// Release still has to free. Same child injection as subtest 2; the backend
	// must see ZERO calls.
	t.Run("manifest_write_restart", func(t *testing.T) {
		h := buildInjectHarness(t, "", "10.117.0.0/24", 80, 0)
		vmID := "vm-inject-8"

		// The manifest a stopped VM leaves behind. Its CIDR lies outside the
		// harness pool, so a fresh allocation can never pass for a reuse.
		seed := jailer.Manifest{
			VMID:   vmID,
			BootID: "boot-" + vmID + "-previous",
			Slot:   0,
			UID:    os.Getuid(),
			GID:    os.Getgid(),
			CID:    h.cidBase,
			CIDR:   "192.0.2.0/30",
			Stages: []string{"reserved", "staged", "network"},
		}
		if err := jailer.WriteManifestExported(h.stateDir, seed); err != nil {
			t.Fatalf("seed manifest: %v", err)
		}

		errText := launchWithWriteFail(t, h, vmID)
		for _, want := range []string{"failed at stage reserved", "write manifest"} {
			if !strings.Contains(errText, want) {
				t.Errorf("error = %q; want it to contain %q", errText, want)
			}
		}
		t.Logf("got expected error: %s", errText)

		// The stopped VM's record must survive the failed restart unchanged.
		got, err := jailer.ReadManifest(h.stateDir, vmID)
		switch {
		case err != nil:
			t.Errorf("previous manifest gone after the failed restart: %v", err)
		case got.CIDR != seed.CIDR || got.Slot != seed.Slot || got.BootID != seed.BootID ||
			strings.Join(got.Stages, ",") != strings.Join(seed.Stages, ","):
			t.Errorf("previous manifest rewritten by the failed restart:\n got %+v\nwant %+v", got, seed)
		}

		if n := backendCallCount(h); n != 0 {
			t.Errorf("expected zero backend calls; got %d (allocate: %v)", n, h.backend.allocateCalls)
		}

		// Recovery: the restart goes through on the slot and CIDR the surviving
		// manifest names, not on a fresh allocation from the pool.
		assertRecoveryLaunch(t, h, vmID)
		recovered, err := jailer.ReadManifest(h.stateDir, vmID)
		if err != nil {
			t.Fatalf("read manifest after recovery: %v", err)
		}
		if recovered.Slot != seed.Slot || recovered.CIDR != seed.CIDR {
			t.Errorf("recovery did not reuse the stopped VM's identity: slot %d cidr %q; want slot %d cidr %q",
				recovered.Slot, recovered.CIDR, seed.Slot, seed.CIDR)
		}
	})

	// ── Subtest 4: staging digest mismatch ────────────────────────────────────
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

		_, launchErr := h.adapter.Launch(ctx, defaultSpec(vmID))
		assertCleanup(t, h, vmID, "staged", launchErr)

		// Rollback verifies both privileged resource halves even when staging
		// failed before a successful host mutation was recorded.
		wantCalls4 := []string{"release_vm", "release_network"}
		assertCallsEqual(t, wantCalls4, h.fp.calls)
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

	// ── Subtest 5: stage copy failure ─────────────────────────────────────────
	// A directory planted at <stage>/<id>/rootfs.ext4 makes doStage fail inside
	// its copy loop: after it created the stage dir and copied vmlinux, before
	// stageStaged is recorded. Rollback must remove that half-built stage dir
	// along with the state dir; no privd verb has run, so ZERO calls.
	t.Run("stage_copy_failure", func(t *testing.T) {
		h := buildInjectHarness(t, "", "10.118.0.0/24", 90, 0)
		vmID := "vm-inject-9"

		// copyVerified opens its destination O_WRONLY|O_CREATE|O_TRUNC; a directory
		// there fails it with EISDIR. vmlinux copies first, so the stage dir holds
		// a real partial copy when the failure lands.
		planted := filepath.Join(h.stageRoot, vmID, "rootfs.ext4")
		if err := os.MkdirAll(planted, 0o755); err != nil {
			t.Fatalf("plant directory at the rootfs destination: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		_, launchErr := h.adapter.Launch(ctx, defaultSpec(vmID))
		assertCleanup(t, h, vmID, "staged", launchErr)
		// Pin the injection point: the rootfs copy, not artifact verification.
		if !strings.Contains(launchErr.Error(), "copy rootfs") {
			t.Errorf("error = %q; want it to contain %q", launchErr.Error(), "copy rootfs")
		}
		t.Logf("got expected error: %v", launchErr)

		assertCallsEqual(t, []string{"release_vm", "release_network"}, h.fp.calls)

		assertRecoveryLaunch(t, h, vmID)
	})

	// ── Subtest 6: allocate_network injected failure ──────────────────────────
	// Stages completed before failure: reserved, staged.
	// Rollback must: remove stage dir, remove state dir.
	// Must NOT see any release verb (network was never allocated).
	t.Run("allocate_network_failure", func(t *testing.T) {
		h := buildInjectHarness(t, "allocate_network", "10.112.0.0/24", 30, 0)
		vmID := "vm-inject-3"

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		_, launchErr := h.adapter.Launch(ctx, defaultSpec(vmID))
		assertCleanup(t, h, vmID, "network", launchErr)

		// A failed reply cannot prove absence; rollback asks privd to release
		// both halves before surrendering the manifest and lease.
		wantCalls6 := []string{"allocate_network", "release_vm", "release_network"}
		assertCallsEqual(t, wantCalls6, h.fp.calls)
		t.Logf("calls after allocate_network failure: %v", h.fp.calls)

		assertRecoveryLaunch(t, h, vmID)
	})

	// ── Subtest 7: start_vm injected failure ──────────────────────────────────
	// Stages completed before failure: reserved, staged, network.
	// Rollback must verify both host resource halves, then remove local state.
	// There is no recorded process to signal.
	t.Run("start_vm_failure", func(t *testing.T) {
		h := buildInjectHarness(t, "start_vm", "10.113.0.0/24", 40, 0)
		vmID := "vm-inject-4"

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		_, launchErr := h.adapter.Launch(ctx, defaultSpec(vmID))
		assertCleanup(t, h, vmID, "vmm_started", launchErr)

		// Start failure has no process identity to signal, but release still
		// verifies absence through the privileged ownership authority.
		wantCalls7 := []string{"allocate_network", "start_vm", "release_vm", "release_network"}
		assertCallsEqual(t, wantCalls7, h.fp.calls)
		t.Logf("calls after start_vm failure: %v", h.fp.calls)

		assertRecoveryLaunch(t, h, vmID)
	})

	// ── Subtest 8: runner spawn failure ───────────────────────────────────────
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

		_, launchErr := brokenAdapter.Launch(ctx, defaultSpec(vmID))
		assertCleanup(t, h, vmID, "runner_spawned", launchErr)

		// Exact call sequence: allocate_network+start_vm succeed; runner exec.Start() fails.
		// doRollback sees stageSet[runner_spawned]=false (manifest never updated, exec.Start failed),
		// stageSet[vmm_started]=true → signal_vm/term, 2s sleep, signal_vm/kill, release_vm.
		// stageSet[network]=true → release_network.
		// killRunnerByPID is NOT called (stageSet[runner_spawned]=false).
		// Source: launch.go doRollback — runner block guarded by stageSet[stageRunnerSpawned];
		// VMM block: SignalVM("term") + sleep + SignalVM("kill") + ReleaseVM (in that order).
		wantCalls8 := []string{
			"allocate_network",
			"start_vm",
			"signal_vm/term",
			"signal_vm/kill",
			"release_vm",
			"release_network",
		}
		assertCallsEqual(t, wantCalls8, h.fp.calls)
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

	// ── Subtest 9: wrong token → attach timeout ───────────────────────────────
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

		_, launchErr := h.adapter.Launch(ctx, defaultSpec(vmID))

		// Assert runner process is actually gone BEFORE recovery — doRollback's killRunnerByPID
		// is synchronous inside rollback (called with launchMu held), so by the time Launch
		// returns the kill path has completed. Scan /proc/*/cmdline for this vm_id.
		assertRunnerGone(t, vmID)

		assertCleanup(t, h, vmID, "attached", launchErr)

		// b2t2: this is the failure that started the issue — the runner exited
		// before attaching and doRollback removed the state dir holding the only
		// account of why. The error has to hand the reader that account.
		archive := rescuedArchive(launchErr)
		if archive == "" {
			t.Fatalf("launch failed at stage attached but the error names no rescued runner log: %v", launchErr)
		}
		assertRescuedArchive(t, archive)

		// §15.3: no 64-char lowercase-hex substring may appear in the error string —
		// catches any leaked capability token, not just the planted wrongToken value.
		if hexToken64 := regexp.MustCompile(`[0-9a-f]{64}`); hexToken64.MatchString(launchErr.Error()) {
			t.Errorf("§15.3 violation: 64-char hex token leaked into error: %q", launchErr.Error())
		}
		// Belt-and-suspenders: the specific planted wrong token must not appear either.
		if strings.Contains(launchErr.Error(), wrongToken) {
			t.Errorf("§15.3 violation: wrong token leaked into error: %q", launchErr.Error())
		}
		t.Logf("got expected timeout error: %v", launchErr)

		// Exact call sequence: allocate_network+start_vm succeed; runner spawns and attaches timeout.
		// doRollback sees stageSet[runner_spawned]=true → killRunnerByPID (OS signal, not a privd call).
		// stageSet[vmm_started]=true → signal_vm/term + signal_vm/kill + release_vm.
		// stageSet[network]=true → release_network.
		// Source: launch.go doRollback — runner block first (killRunnerByPID), then VMM block, then net.
		wantCalls9 := []string{
			"allocate_network",
			"start_vm",
			"signal_vm/term",
			"signal_vm/kill",
			"release_vm",
			"release_network",
		}
		assertCallsEqual(t, wantCalls9, h.fp.calls)

		// Shut down the wrong-token guestd before recovery.
		agentCancel()
		guestLn.Close()

		assertRecoveryLaunch(t, h, vmID)
	})
}

// ---------------------------------------------------------------------------
// F1: the rollback's release_vm must survive privd's invalid_state refusal
// ---------------------------------------------------------------------------

// TestRollbackRetriesReleaseVM: doRollback SIGKILLs the VMM and immediately asks
// privd to release the jail chroot. SIGKILL is asynchronous, so privd legitimately
// answers that first release with invalid_state "vm process is still alive"
// (gotchas #51). The rollback used to call ReleaseVM bare and discard the error, so
// one well-timed refusal left the chroot on disk and the ledger entry pinned — and a
// pinned entry makes the release_network that follows write the entry back instead
// of deleting it. ForceStop already retries (TestForceStopRetriesRelease); this pins
// the same discipline on the launch-failure path.
//
// Shape: a broken runner binary fails the launch after stage vmm_started, which is
// the rollback branch that owns the release. The decorator refuses twice, then
// delegates to the real privd server, so "the retry landed" is observable at the
// server's own backend rather than at the decorator.
func TestRollbackRetriesReleaseVM(t *testing.T) {
	h := buildInjectHarness(t, "", "10.118.0.0/24", 90, 0)
	vmID := "vm-rollback-release"

	refuser := &refusingReleasePrivd{PrivdClient: h.fp, refusal: aliveRefusal(), refusals: 2}

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
	brokenAdapter, err := jailer.New(brokenCfg, refuser)
	if err != nil {
		t.Fatalf("jailer.New (broken runner): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, launchErr := brokenAdapter.Launch(ctx, defaultSpec(vmID))
	assertCleanup(t, h, vmID, "runner_spawned", launchErr)

	// Two refusals then an accepted call: fewer means the rollback took the first
	// invalid_state as an answer.
	if refuser.calls < 3 {
		t.Errorf("rollback release_vm attempts = %d, want >= 3 (two refusals then an accepted call): "+
			"doRollback discarded privd's invalid_state refusal instead of retrying", refuser.calls)
	}

	// A retry that never reaches privd is the same leak — the server's backend must
	// have run release_vm for this VM.
	released := false
	for _, id := range h.backend.releaseVMCalls {
		if id == vmID {
			released = true
		}
	}
	if !released {
		t.Errorf("privd backend never ran release_vm for %s during rollback — the jail chroot leaked "+
			"(backend release_vm calls: %v)", vmID, h.backend.releaseVMCalls)
	}

	// The release must not have eaten the network release that follows it.
	releasedNet := false
	for _, id := range h.backend.releaseCalls {
		if id == vmID {
			releasedNet = true
		}
	}
	if !releasedNet {
		t.Errorf("rollback never released the network for %s (backend release_network calls: %v)",
			vmID, h.backend.releaseCalls)
	}

	// The slot and the CIDR must both be reusable afterwards.
	goodCfg := brokenCfg
	goodCfg.RunnerBin = runnerBin
	goodAdapter, err := jailer.New(goodCfg, h.fp)
	if err != nil {
		t.Fatalf("jailer.New (recovery runner): %v", err)
	}
	h.adapter = goodAdapter
	assertRecoveryLaunch(t, h, vmID)
}
