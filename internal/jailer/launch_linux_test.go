// ABOUTME: Linux integration test for the launch transaction: real privd server, real runner binary,
// ABOUTME: real guestd agent on a UDS — verifies the full §5.3 launch sequence end to end.

//go:build linux

package jailer_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/guest"
	"github.com/2389-research/observatory-v2/internal/guest/proto"
	"github.com/2389-research/observatory-v2/internal/jailer"
	"github.com/2389-research/observatory-v2/internal/lock"
	"github.com/2389-research/observatory-v2/internal/network"
	"github.com/2389-research/observatory-v2/internal/preflight"
	"github.com/2389-research/observatory-v2/internal/privd"
	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/spool"
)

// runnerBin is built once by TestMain and shared across all tests.
var runnerBin string

// TestMain builds the runner binary before running tests.
func TestMain(m *testing.M) {
	// Re-executed as a child of the manifest-write injection subtests: run one
	// Launch under RLIMIT_FSIZE=0 and exit (see launchWriteFailHelper).
	if os.Getenv(helperEnv) == helperLaunchWriteFail {
		os.Exit(launchWriteFailHelper())
	}
	tmp, err := os.MkdirTemp("", "jailer-test-runner-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "TestMain: mkdir runner temp: %v\n", err)
		os.Exit(1)
	}
	bin := filepath.Join(tmp, "vmobs-runner")
	cmd := exec.Command("go", "build", "-o", bin,
		"github.com/2389-research/observatory-v2/cmd/vmobs-runner")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "TestMain: build runner: %v\n", err)
		os.RemoveAll(tmp)
		os.Exit(1)
	}
	runnerBin = bin
	code := m.Run()
	os.RemoveAll(tmp)
	os.Exit(code)
}

// testRecordingBackend implements privd.OpsBackend for tests.
// StartVM spawns a real "sleep 300" as the fake VMM and records its real PID+starttime.
type testRecordingBackend struct {
	allocateCalls  []string
	releaseCalls   []string
	startCalls     []string
	abortCalls     []string
	signalCalls    []string
	releaseVMCalls []string

	// jailBase, when set, makes ReleaseVM remove the jail chroot the way
	// privd's RealOps.ReleaseVM does (internal/privd/vmops.go). Left empty,
	// ReleaseVM only records the call, which is every caller's behavior
	// before this field existed.
	jailBase string

	// ignoredSignals names the signal kinds this backend accepts and then does
	// nothing about, which is how a test builds a VMM that survives SIGTERM.
	// Empty means every signal kills the stand-in process. Set it before the
	// stop under test; SignalVM reads it on the privd server's goroutine.
	ignoredSignals map[string]bool

	// sleepProcs tracks spawned sleep processes so tests can kill them.
	sleepProcs []*sleepProc
}

// sleepProc is one spawned stand-in VMM process together with the channel its
// reaper closes. Exactly one goroutine ever calls Wait on the command; killAll
// waits on done instead of calling Wait a second time, because two concurrent
// Wait calls on the same exec.Cmd race on the command's internal state.
type sleepProc struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func (b *testRecordingBackend) AllocateNetwork(entry privd.VMEntry, req privd.AllocateNetworkReq) error {
	b.allocateCalls = append(b.allocateCalls, req.VMID)
	return nil
}

func (b *testRecordingBackend) ReleaseNetwork(entry privd.VMEntry) error {
	b.releaseCalls = append(b.releaseCalls, entry.VMID)
	return nil
}

func (b *testRecordingBackend) StartVM(entry *privd.VMEntry, req privd.StartVMReq) (privd.StartVMResp, error) {
	b.startCalls = append(b.startCalls, req.VMID)

	cmd := exec.Command("sleep", "300")
	if err := cmd.Start(); err != nil {
		return privd.StartVMResp{}, fmt.Errorf("spawn sleep: %w", err)
	}
	proc := &sleepProc{cmd: cmd, done: make(chan struct{})}
	go func() {
		defer close(proc.done)
		_ = cmd.Wait()
	}()
	b.sleepProcs = append(b.sleepProcs, proc)

	pid := cmd.Process.Pid
	statData, err := os.ReadFile(privd.ProcStatPath(pid))
	if err != nil {
		_ = cmd.Process.Kill()
		return privd.StartVMResp{}, fmt.Errorf("read proc stat: %w", err)
	}
	starttime := privd.ParseStartTime(string(statData))
	if starttime == "" {
		_ = cmd.Process.Kill()
		return privd.StartVMResp{}, fmt.Errorf("parse starttime")
	}

	// Update the entry with process identity so the server ledger stays consistent.
	entry.PID = pid
	entry.StartTime = starttime

	return privd.StartVMResp{PID: pid, StartTime: starttime}, nil
}

// AbortStartVM records the undo privd runs when StartVM fails. This backend's
// StartVM builds no jail tree, so there is nothing here to remove.
func (b *testRecordingBackend) AbortStartVM(entry privd.VMEntry) error {
	b.abortCalls = append(b.abortCalls, entry.VMID)
	return nil
}

func (b *testRecordingBackend) SignalVM(entry privd.VMEntry, kind string) error {
	b.signalCalls = append(b.signalCalls, fmt.Sprintf("%s/%s", entry.VMID, kind))
	if b.ignoredSignals[kind] {
		return nil
	}
	if entry.PID > 0 {
		if p, err := os.FindProcess(entry.PID); err == nil {
			_ = p.Kill()
		}
	}
	return nil
}

func (b *testRecordingBackend) ReleaseVM(entry privd.VMEntry) error {
	b.releaseVMCalls = append(b.releaseVMCalls, entry.VMID)
	if b.jailBase == "" {
		return nil
	}
	jailDir := filepath.Join(b.jailBase, "firecracker", entry.VMID)
	if err := os.RemoveAll(jailDir); err != nil {
		return fmt.Errorf("test backend: remove jail dir %q: %w", jailDir, err)
	}
	return nil
}

func (b *testRecordingBackend) killAll() {
	for _, p := range b.sleepProcs {
		_ = p.cmd.Process.Kill()
		<-p.done
	}
}

// startTestPrivdServer starts a privd.Server with the given backend.
// Returns the socket path. The server is cancelled on t.Cleanup.
func startTestPrivdServer(t *testing.T, backend privd.OpsBackend) (sockPath, stageRoot string) {
	t.Helper()
	dir := t.TempDir()
	sockPath = filepath.Join(dir, "privd.sock")
	stageRoot = filepath.Join(dir, "stage")
	ledgerDir := filepath.Join(dir, "ledger")
	for _, d := range []string{stageRoot, ledgerDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	cfg := privd.ServerCfg{
		AllowedUID: os.Getuid(),
		LedgerDir:  ledgerDir,
		StageRoot:  stageRoot,
		JailBase:   filepath.Join(dir, "jail"),
		UIDMin:     os.Getuid(),
		UIDMax:     os.Getuid() + 1000,
		Ops:        backend,
		Log:        testLogger(t),
	}
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen privd: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := privd.NewServer(cfg)
	go func() {
		if err := srv.Serve(ctx, ln); err != nil && ctx.Err() == nil {
			t.Logf("privd server exited: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
	})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("unix", sockPath)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("privd socket never became ready")
	return
}

// testLogger redirects server logs to t.Logf.
func testLogger(t *testing.T) *log.Logger {
	t.Helper()
	return log.New(&testLogWriter{t}, "privd: ", 0)
}

type testLogWriter struct{ t *testing.T }

func (w *testLogWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// sha256Hex computes the SHA-256 hex of a byte slice.
func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// listen0600 creates a unix socket listener with mode 0600.
func listen0600(path string) (net.Listener, error) {
	old := syscall.Umask(0o177)
	defer syscall.Umask(old)
	return net.Listen("unix", path)
}

// spoolContainsKind reports whether any segment in spoolDir contains an envelope with kind.
func spoolContainsKind(t *testing.T, spoolDir, kind string) bool {
	t.Helper()
	segs, _ := filepath.Glob(filepath.Join(spoolDir, "seg-*.vmsp"))
	for _, seg := range segs {
		iter, err := spool.ReadSegment(seg)
		if err != nil {
			continue
		}
		for {
			env, err := iter.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			if env.Kind == kind {
				iter.Close()
				return true
			}
		}
		iter.Close()
	}
	return false
}

// newRandomUUID returns a random v4 UUID string.
func newRandomUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// makeTestImagesDir creates a minimal images directory with fake vmlinux + rootfs files,
// writes a lock.json with repo-relative paths, and returns (repoRoot, lockPath).
// repoRoot is the directory the lock's artifact paths resolve against.
// Lock paths mirror the real runtime.lock.json layout: "images/dist/vmlinux" etc.
func makeTestImagesDir(t *testing.T) (repoRoot, lockPath string) {
	t.Helper()
	dir := t.TempDir()
	repoRoot = dir
	imagesDir := filepath.Join(dir, "images", "dist")
	if err := os.MkdirAll(imagesDir, 0o755); err != nil {
		t.Fatalf("mkdir images/dist: %v", err)
	}

	vmlinuxContent := []byte("fake-vmlinux-for-jailer-test")
	rootfsContent := []byte("fake-rootfs-for-jailer-test")
	if err := os.WriteFile(filepath.Join(imagesDir, "vmlinux"), vmlinuxContent, 0o644); err != nil {
		t.Fatalf("write vmlinux: %v", err)
	}
	if err := os.WriteFile(filepath.Join(imagesDir, "rootfs.ext4"), rootfsContent, 0o644); err != nil {
		t.Fatalf("write rootfs.ext4: %v", err)
	}

	vmlinuxSHA := sha256Hex(vmlinuxContent)
	rootfsSHA := sha256Hex(rootfsContent)

	// Lock paths are relative to repoRoot (dir). Mirror the real lock layout.
	lockPath = filepath.Join(dir, "runtime.lock.json")
	lockBody := fmt.Sprintf(`{
		"schema": "vmobs.runtime_lock.v1",
		"firecracker": {"version": "v1.16.1", "sha256": "", "install_path": "/usr/local/bin/firecracker"},
		"jailer": {"sha256": "", "install_path": "/usr/local/bin/jailer"},
		"host_support": {"arch": "amd64", "min_kernel": "5.10"},
		"guest_kernel": {"version": "6.1.186", "vmlinux_sha256": %q, "vmlinux_path": "images/dist/vmlinux"},
		"root_image": {"sha256": %q, "path": "images/dist/rootfs.ext4"},
		"guestd": {"protocol_version": 1}
	}`, vmlinuxSHA, rootfsSHA)
	if err := os.WriteFile(lockPath, []byte(lockBody), 0o644); err != nil {
		t.Fatalf("write lock: %v", err)
	}
	// RepoRoot (dir) is the base the lock's "images/dist/..." paths resolve against.
	// Under the old broken arithmetic (filepath.Dir(RepoImagesDir) where
	// RepoImagesDir = dir/images/dist), repoRoot was dir/images — causing
	// VerifyArtifacts to look for dir/images/images/dist/vmlinux (absent).
	// With RepoRoot = dir, VerifyArtifacts resolves dir/images/dist/vmlinux correctly.
	return repoRoot, lockPath
}

// guestdServer serves a guestd-style handshake on a UDS path, reading the capability token
// from tokenFile before accepting each connection so it matches the adapter-generated token.
// If poweroffFunc is non-nil it is called when the agent receives a shutdown command (simulating
// the guest powering off). Nil → default no-op (test guestd never shuts down).
type guestdServer struct {
	tokenFile    string
	vmID         string
	bootID       string
	poweroffFunc func() // nil = no-op
}

func (g *guestdServer) serve(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
			default:
				// listener closed or error
			}
			return
		}
		go g.handleConn(ctx, conn)
	}
}

func (g *guestdServer) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// Perform the CONNECT/OK vsock proxy handshake.
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

	// Read the token from the token file (adapter writes it before spawning the runner).
	var token string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(g.tokenFile)
		if err == nil {
			token = strings.TrimRight(string(b), "\n")
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if token == "" {
		return
	}

	cfg := &guest.BootConfig{
		Schema:          guest.GuestContextSchema,
		VMID:            g.vmID,
		BootID:          g.bootID,
		CapabilityToken: token,
		ProtocolVersion: proto.ProtocolVersion,
	}
	manifest := proto.CapabilityManifest{
		Schema:        "vmobs.guest_capability.v1",
		KernelRelease: "6.1.0-test",
		Features:      []proto.Feature{{ID: "btf", Present: true}},
	}
	agent := guest.NewAgent(cfg, manifest)
	// Use the caller's poweroff func if provided; default to no-op so the test guestd
	// never actually powers off the test machine.
	if g.poweroffFunc != nil {
		agent.PoweroffFunc = g.poweroffFunc
	} else {
		agent.PoweroffFunc = func() {} // no-op in test
	}

	// Wrap the already-connected conn as a single-connection listener.
	scl := &singleConnListener{conn: conn, ch: make(chan struct{})}
	_ = agent.ServeControl(ctx, scl)
}

// singleConnListener adapts a single conn into a net.Listener.
// Accept() returns the conn once, then blocks until Close().
type singleConnListener struct {
	conn net.Conn
	ch   chan struct{}
	used bool
}

func (s *singleConnListener) Accept() (net.Conn, error) {
	if !s.used {
		s.used = true
		return s.conn, nil
	}
	<-s.ch
	return nil, fmt.Errorf("singleConnListener: closed")
}
func (s *singleConnListener) Close() error {
	select {
	case <-s.ch:
	default:
		close(s.ch)
	}
	return nil
}
func (s *singleConnListener) Addr() net.Addr { return s.conn.LocalAddr() }

// TestLaunchTransactionAgainstFakePrivd drives Adapter.Launch with:
//   - A real privd.Server backed by testRecordingBackend (StartVM returns real sleep 300 PID)
//   - A real guestdServer on the VM's vsock UDS path
//   - The real vmobs-runner binary built by TestMain
//
// Asserts: manifest stages complete in order; allocate_network was called;
// runner reaches "attached"; spool contains guest.channel_established.
func TestLaunchTransactionAgainstFakePrivd(t *testing.T) {
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

	vmID := "vm-launch-test"
	bootID := "boot-" + newRandomUUID()
	spec := runtime.VMSpec{
		VMID:             vmID,
		BootID:           bootID,
		VCPUCount:        1,
		MemoryMiB:        512,
		WorkspaceDiskMiB: 64,
	}

	// Pre-create the vsock UDS dir so we know its path before the adapter runs.
	vSockDir := filepath.Join(jailBase, "firecracker", vmID, "root")
	if err := os.MkdirAll(vSockDir, 0o755); err != nil {
		t.Fatalf("mkdir vsock dir: %v", err)
	}
	vSockPath := filepath.Join(vSockDir, "v.sock")

	// Token file path (adapter writes it during staging).
	tokenFile := filepath.Join(stateDir, "vms", vmID, "token")

	// Start guestd listener at the vsock path before the adapter spawns the runner.
	guestLn, err := listen0600(vSockPath)
	if err != nil {
		t.Fatalf("listen v.sock at %s: %v", vSockPath, err)
	}
	agentCtx, agentCancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		agentCancel()
		guestLn.Close()
	})

	gs := &guestdServer{tokenFile: tokenFile, vmID: vmID, bootID: bootID, poweroffFunc: nil}
	go gs.serve(agentCtx, guestLn)

	// Build a simple network allocator (no host routes to exclude in the test).
	pool, err := network.NewAllocator(nil, []netip.Prefix{netip.MustParsePrefix("10.88.0.0/24")})
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

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
		CIDBase:     3,
		Allocator:   pool,
		Preflight: func(ctx context.Context, refresh bool) preflight.Report {
			return preflight.Report{Overall: preflight.StatusPass}
		},
	}

	pc := &privd.Client{SocketPath: privdSock}
	adapter, err := jailer.New(cfg, pc)
	if err != nil {
		t.Fatalf("jailer.New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	staged, err := adapter.Launch(ctx, spec)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}

	// The launch reports the images it staged, and this is the only report of
	// them: doStage reads runtime.lock.json itself, on every launch, while the
	// daemon serves the copy it loaded at startup. Compare against a fresh read
	// of the same file — what the stage verified the bytes against is what the
	// VM row must end up saying it booted.
	if staged == nil {
		t.Fatal("Launch reported no staged images although it staged and verified two artifacts")
	}
	lk, err := lock.Load(lockPath)
	if err != nil {
		t.Fatalf("load lock: %v", err)
	}
	if *staged != lk.Images() {
		t.Errorf("Launch reported %+v, want the entries from the lock it staged from %+v", *staged, lk.Images())
	}

	// Assert manifest has all six stages in order.
	m, err := jailer.ReadManifest(stateDir, vmID)
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	wantStages := []string{"reserved", "staged", "network", "vmm_started", "runner_spawned", "attached"}
	if len(m.Stages) != len(wantStages) {
		t.Errorf("stages = %v, want %v", m.Stages, wantStages)
	} else {
		for i, want := range wantStages {
			if m.Stages[i] != want {
				t.Errorf("stages[%d] = %q, want %q", i, m.Stages[i], want)
			}
		}
	}

	// Assert the manifest recorded the runner's identity, not just its pid. The VM
	// is attached, so the runner is alive and /proc must agree with what the spawn
	// wrote — a pid without a start time is the recycled-pid hole (SPEC §9.1).
	if m.RunnerPID <= 0 {
		t.Errorf("manifest runner_pid = %d after a successful launch", m.RunnerPID)
	} else {
		if m.RunnerStart == "" {
			t.Error("manifest runner_starttime is empty after a successful launch: " +
				"the runner has no identity, only a pid")
		}
		statData, err := os.ReadFile(privd.ProcStatPath(m.RunnerPID))
		if err != nil {
			t.Errorf("read runner proc stat: %v", err)
		} else if want := privd.ParseStartTime(string(statData)); m.RunnerStart != want {
			t.Errorf("manifest runner_starttime = %q, live runner pid %d started at %q",
				m.RunnerStart, m.RunnerPID, want)
		}
	}

	// Assert network was allocated.
	if len(backend.allocateCalls) == 0 {
		t.Error("allocate_network was never called")
	}

	// Assert spool contains guest.channel_established.
	vmSpoolDir := filepath.Join(spoolRoot, vmID)
	if !spoolContainsKind(t, vmSpoolDir, "guest.channel_established") {
		t.Error("spool: missing guest.channel_established")
	}
}

// TestLaunchDigestTamperingBlocksNetwork verifies that a digest mismatch in the staging
// step causes a failure BEFORE allocate_network is called (network is step 4; digest
// check is inside step 3/staging).
func TestLaunchDigestTamperingBlocksNetwork(t *testing.T) {
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

	imagesDir := filepath.Join(dir, "images", "dist")
	if err := os.MkdirAll(imagesDir, 0o755); err != nil {
		t.Fatalf("mkdir images/dist: %v", err)
	}

	// Write real files.
	realContent := []byte("real content for tamper test")
	if err := os.WriteFile(filepath.Join(imagesDir, "vmlinux"), realContent, 0o644); err != nil {
		t.Fatalf("write vmlinux: %v", err)
	}
	if err := os.WriteFile(filepath.Join(imagesDir, "rootfs.ext4"), realContent, 0o644); err != nil {
		t.Fatalf("write rootfs: %v", err)
	}

	// Lock has WRONG hashes — staging will fail on digest mismatch.
	wrongSHA := sha256Hex([]byte("this is not the real content"))
	lockPath := filepath.Join(dir, "runtime.lock.json")
	lockBody := fmt.Sprintf(`{
		"schema": "vmobs.runtime_lock.v1",
		"firecracker": {"version": "v1.16.1", "sha256": "", "install_path": "/usr/local/bin/firecracker"},
		"jailer": {"sha256": "", "install_path": "/usr/local/bin/jailer"},
		"host_support": {"arch": "amd64", "min_kernel": "5.10"},
		"guest_kernel": {"version": "6.1.186", "vmlinux_sha256": %q, "vmlinux_path": "images/dist/vmlinux"},
		"root_image": {"sha256": %q, "path": "images/dist/rootfs.ext4"},
		"guestd": {"protocol_version": 1}
	}`, wrongSHA, wrongSHA)
	if err := os.WriteFile(lockPath, []byte(lockBody), 0o644); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	pool, err := network.NewAllocator(nil, []netip.Prefix{netip.MustParsePrefix("10.89.0.0/24")})
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	cfg := jailer.Config{
		StateDir:    stateDir,
		StageRoot:   stageRoot,
		JailBase:    jailBase,
		SpoolRoot:   spoolRoot,
		RunnerBin:   runnerBin,
		RepoRoot:    dir,
		LockPath:    lockPath,
		JailUIDBase: os.Getuid(),
		JailGID:     os.Getgid(),
		MaxSlots:    8,
		CIDBase:     3,
		Allocator:   pool,
		Preflight: func(ctx context.Context, refresh bool) preflight.Report {
			return preflight.Report{Overall: preflight.StatusPass}
		},
	}

	pc := &privd.Client{SocketPath: privdSock}
	adapter, err := jailer.New(cfg, pc)
	if err != nil {
		t.Fatalf("jailer.New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, launchErr := adapter.Launch(ctx, runtime.VMSpec{
		VMID:             "vm-tamper",
		BootID:           "boot-tamper",
		VCPUCount:        1,
		MemoryMiB:        512,
		WorkspaceDiskMiB: 64,
	})
	if launchErr == nil {
		t.Fatal("expected Launch to fail on digest tamper, got nil")
	}
	t.Logf("launch failed as expected: %v", launchErr)

	// network must NOT have been allocated — staging fails in step 3, network is step 4.
	if len(backend.allocateCalls) > 0 {
		t.Errorf("allocate_network was called despite digest mismatch (got calls: %v)", backend.allocateCalls)
	}
}
