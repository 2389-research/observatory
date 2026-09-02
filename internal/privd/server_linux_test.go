// ABOUTME: Linux integration tests for the privd server: peer-cred auth, dispatch, ledger.
// ABOUTME: Uses a recording backend and real unix sockets with real peer credentials.

//go:build linux

package privd_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/privd"
)

// recordingBackend implements OpsBackend, capturing every call made by the server.
type recordingBackend struct {
	allocateCalls  []recordedAllocate
	releaseCalls   []string // vm_ids
	startCalls     []recordedStart
	signalCalls    []recordedSignal
	releaseVMCalls []string // vm_ids

	// Injected responses.
	allocateErr error
	startResp   privd.StartVMResp
	startErr    error
	signalErr   error
}

type recordedAllocate struct {
	entry privd.VMEntry
	req   privd.AllocateNetworkReq
}

type recordedStart struct {
	entry privd.VMEntry
	req   privd.StartVMReq
}

type recordedSignal struct {
	entry  privd.VMEntry
	signal string
}

func (b *recordingBackend) AllocateNetwork(entry privd.VMEntry, req privd.AllocateNetworkReq) error {
	b.allocateCalls = append(b.allocateCalls, recordedAllocate{entry, req})
	return b.allocateErr
}

func (b *recordingBackend) ReleaseNetwork(entry privd.VMEntry) error {
	b.releaseCalls = append(b.releaseCalls, entry.VMID)
	return nil
}

func (b *recordingBackend) StartVM(entry *privd.VMEntry, req privd.StartVMReq) (privd.StartVMResp, error) {
	b.startCalls = append(b.startCalls, recordedStart{*entry, req})
	return b.startResp, b.startErr
}

func (b *recordingBackend) SignalVM(entry privd.VMEntry, signal string) error {
	b.signalCalls = append(b.signalCalls, recordedSignal{entry, signal})
	return b.signalErr
}

func (b *recordingBackend) ReleaseVM(entry privd.VMEntry) error {
	b.releaseVMCalls = append(b.releaseVMCalls, entry.VMID)
	return nil
}

// dialPrivd connects to the server via a unix socket.
func dialPrivd(t *testing.T, sockPath string) *net.UnixConn {
	t.Helper()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		t.Fatalf("dial privd: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// sendRecv sends a request and reads a response over a unix connection.
func sendRecv(t *testing.T, conn net.Conn, req privd.Request) privd.Response {
	t.Helper()
	if err := privd.WriteMsg(conn, req); err != nil {
		t.Fatalf("WriteMsg: %v", err)
	}
	var resp privd.Response
	if err := privd.ReadMsg(conn, &resp); err != nil {
		t.Fatalf("ReadMsg: %v", err)
	}
	return resp
}

// makeReq builds a Request envelope for a verb + payload struct.
func makeReq(t *testing.T, verb string, payload any) privd.Request {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return privd.Request{V: privd.ProtoVersion, Verb: verb, Payload: json.RawMessage(raw)}
}

// testLogger returns a *log.Logger that writes via t.Logf, so server output only
// appears when the test fails or is run with -v.
func testLogger(t *testing.T) *log.Logger {
	t.Helper()
	return log.New(testLogWriter{t}, "privd: ", 0)
}

// testLogWriter adapts t.Logf to io.Writer.
type testLogWriter struct{ t *testing.T }

func (w testLogWriter) Write(p []byte) (int, error) {
	w.t.Helper()
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// startServer launches a Server and waits until the socket is ready.
// Returns the socket path. The server is cancelled when t.Cleanup runs.
func startServer(t *testing.T, sockPath string, cfg privd.ServerCfg) {
	t.Helper()
	if cfg.Log == nil {
		cfg.Log = testLogger(t)
	}
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := privd.NewServer(cfg)
	go func() {
		if err := srv.Serve(ctx, ln); err != nil && ctx.Err() == nil {
			t.Logf("server exited: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		ln.Close()
	})
	// Brief wait for socket readiness.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("unix", sockPath)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("server socket never ready")
}

// spawnShortProcess starts a process and waits for it to exit; returns its pid and
// the starttime string from /proc/<pid>/stat. The process is dead when this returns.
func spawnShortProcess(t *testing.T) (pid int, starttime string) {
	t.Helper()
	cmd := exec.Command("true") // exits immediately
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn process: %v", err)
	}
	// Read starttime while the process still exists (before Wait).
	statPath := privd.ProcStatPath(cmd.Process.Pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		t.Fatalf("read /proc stat: %v", err)
	}
	starttime = privd.ParseStartTime(string(data))
	if starttime == "" {
		t.Fatalf("could not parse starttime from %q", string(data))
	}
	// Wait for the process to die.
	if err := cmd.Wait(); err != nil {
		// "true" exits 0, but accept any exit here.
	}
	return cmd.Process.Pid, starttime
}

// TestHappyPath exercises the full sequence: allocate → start → signal → release_vm → release_network
// over a real unix socket with the caller's own UID as the allowed UID.
//
// R4 semantics: release_vm clears the VM half only (UID/GID/CID/PID/StartTime); the ledger
// entry survives with NetCIDR intact. release_network then clears NetCIDR and deletes the file.
func TestHappyPath(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "privd.sock")
	stageRoot := filepath.Join(dir, "stage")
	if err := os.MkdirAll(stageRoot, 0o755); err != nil {
		t.Fatalf("mkdir stageroot: %v", err)
	}
	stageDir := filepath.Join(stageRoot, "vm-test-001")
	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		t.Fatalf("mkdir stagedir: %v", err)
	}
	ledgerDir := filepath.Join(dir, "ledger")
	if err := os.MkdirAll(ledgerDir, 0o755); err != nil {
		t.Fatalf("mkdir ledger: %v", err)
	}

	pid, starttime := spawnShortProcess(t)

	backend := &recordingBackend{
		startResp: privd.StartVMResp{PID: pid, StartTime: starttime},
	}

	cfg := privd.ServerCfg{
		AllowedUID: os.Getuid(),
		LedgerDir:  ledgerDir,
		StageRoot:  stageRoot,
		JailBase:   filepath.Join(dir, "jail"),
		UIDMin:     os.Getuid(),
		UIDMax:     os.Getuid() + 100,
		Ops:        backend,
	}
	startServer(t, sockPath, cfg)

	vmID := "vm-test-001"
	cidr := "192.168.100.0/30"

	// Step 1: allocate_network.
	conn := dialPrivd(t, sockPath)
	resp := sendRecv(t, conn, makeReq(t, "allocate_network", privd.AllocateNetworkReq{VMID: vmID, CIDR: cidr}))
	if !resp.OK {
		t.Fatalf("allocate_network: %+v", resp)
	}
	conn.Close()

	// Ledger file should exist now.
	ledgerFile := filepath.Join(ledgerDir, vmID+".json")
	if _, err := os.Stat(ledgerFile); err != nil {
		t.Fatalf("ledger file not created: %v", err)
	}

	// Step 2: start_vm.
	conn2 := dialPrivd(t, sockPath)
	resp2 := sendRecv(t, conn2, makeReq(t, "start_vm", privd.StartVMReq{
		VMID:     vmID,
		UID:      os.Getuid(),
		GID:      os.Getgid(),
		CID:      3,
		StageDir: stageDir,
	}))
	if !resp2.OK {
		t.Fatalf("start_vm: %+v", resp2)
	}
	conn2.Close()

	// Verify StartVMResp payload was returned.
	var startResp privd.StartVMResp
	if err := json.Unmarshal(resp2.Payload, &startResp); err != nil {
		t.Fatalf("decode start_vm payload: %v", err)
	}
	if startResp.PID != pid {
		t.Errorf("start_vm PID = %d, want %d", startResp.PID, pid)
	}

	// Step 3: signal_vm.
	conn3 := dialPrivd(t, sockPath)
	resp3 := sendRecv(t, conn3, makeReq(t, "signal_vm", privd.SignalVMReq{VMID: vmID, Kind: "term"}))
	if !resp3.OK {
		t.Fatalf("signal_vm: %+v", resp3)
	}
	conn3.Close()

	// Step 4: release_vm — pid is dead; should succeed.
	conn4 := dialPrivd(t, sockPath)
	resp4 := sendRecv(t, conn4, makeReq(t, "release_vm", privd.ReleaseVMReq{VMID: vmID}))
	if !resp4.OK {
		t.Fatalf("release_vm: %+v", resp4)
	}
	conn4.Close()

	// R4: after release_vm the ledger file MUST STILL EXIST — NetCIDR is still set,
	// but the VM half (UID/GID/CID/PID/StartTime) must be zeroed.
	rawEntry, err := os.ReadFile(ledgerFile)
	if err != nil {
		t.Fatalf("ledger file missing after release_vm (want: still exists): %v", err)
	}
	var afterReleaseVM privd.VMEntry
	if err := json.Unmarshal(rawEntry, &afterReleaseVM); err != nil {
		t.Fatalf("unmarshal ledger after release_vm: %v", err)
	}
	if afterReleaseVM.NetCIDR != cidr {
		t.Errorf("after release_vm: NetCIDR = %q, want %q", afterReleaseVM.NetCIDR, cidr)
	}
	if afterReleaseVM.PID != 0 {
		t.Errorf("after release_vm: PID = %d, want 0", afterReleaseVM.PID)
	}
	if afterReleaseVM.StartTime != "" {
		t.Errorf("after release_vm: StartTime = %q, want empty", afterReleaseVM.StartTime)
	}
	if afterReleaseVM.UID != 0 {
		t.Errorf("after release_vm: UID = %d, want 0", afterReleaseVM.UID)
	}
	if afterReleaseVM.GID != 0 {
		t.Errorf("after release_vm: GID = %d, want 0", afterReleaseVM.GID)
	}
	if afterReleaseVM.CID != 0 {
		t.Errorf("after release_vm: CID = %d, want 0", afterReleaseVM.CID)
	}

	// release_vm must NOT have called ReleaseNetwork.
	if len(backend.releaseCalls) != 0 {
		t.Errorf("ReleaseNetwork called by release_vm (want: 0 calls so far), got %d", len(backend.releaseCalls))
	}

	// Step 5: release_network — clears NetCIDR and deletes the entry file.
	conn5 := dialPrivd(t, sockPath)
	resp5 := sendRecv(t, conn5, makeReq(t, "release_network", privd.ReleaseNetworkReq{VMID: vmID}))
	if !resp5.OK {
		t.Fatalf("release_network: %+v", resp5)
	}
	conn5.Close()

	// Ledger file must be gone now (both halves released).
	if _, err := os.Stat(ledgerFile); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("ledger file still exists after release_network")
	}

	// Backend call log: exactly one of each, in order, no extra ReleaseNetwork.
	if len(backend.allocateCalls) != 1 {
		t.Errorf("allocateCalls = %d, want 1", len(backend.allocateCalls))
	}
	if len(backend.startCalls) != 1 {
		t.Errorf("startCalls = %d, want 1", len(backend.startCalls))
	}
	if len(backend.signalCalls) != 1 {
		t.Errorf("signalCalls = %d, want 1", len(backend.signalCalls))
	}
	if len(backend.releaseVMCalls) != 1 {
		t.Errorf("releaseVMCalls = %d, want 1", len(backend.releaseVMCalls))
	}
	// Exactly one ReleaseNetwork, triggered by release_network (not release_vm).
	if len(backend.releaseCalls) != 1 {
		t.Errorf("releaseNetworkCalls = %d, want 1 (from release_network step only)", len(backend.releaseCalls))
	}

	// Verify ledger entry carried the right CIDR to the start call.
	if backend.startCalls[0].entry.NetCIDR != cidr {
		t.Errorf("start entry NetCIDR = %q, want %q", backend.startCalls[0].entry.NetCIDR, cidr)
	}
}

// TestWrongUIDRejection verifies that a connection from the wrong UID is closed without
// sending any response bytes.
func TestWrongUIDRejection(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "privd.sock")
	ledgerDir := filepath.Join(dir, "ledger")
	if err := os.MkdirAll(ledgerDir, 0o755); err != nil {
		t.Fatalf("mkdir ledger: %v", err)
	}

	cfg := privd.ServerCfg{
		AllowedUID: os.Getuid() + 9999, // never matches
		LedgerDir:  ledgerDir,
		StageRoot:  dir,
		JailBase:   filepath.Join(dir, "jail"),
		UIDMin:     1000,
		UIDMax:     2000,
		Ops:        &recordingBackend{},
	}
	startServer(t, sockPath, cfg)

	conn := dialPrivd(t, sockPath)

	// Send a request — server should close without responding.
	if err := privd.WriteMsg(conn, makeReq(t, "allocate_network", privd.AllocateNetworkReq{VMID: "vm-x", CIDR: "10.0.0.0/30"})); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// ReadMsg should get a connection-closed error (no response bytes written).
	// Linux closes with RST when the server returns without writing; that surfaces as
	// "connection reset by peer" rather than EOF. Both are acceptable evidence that
	// no response was sent.
	var resp privd.Response
	err := privd.ReadMsg(conn, &resp)
	if err == nil {
		t.Fatal("expected error from wrong-uid connection, got nil")
	}
	msg := err.Error()
	closed := errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "broken pipe")
	if !closed {
		t.Errorf("expected closed-connection error, got: %v", err)
	}
}

// TestStageDirEscape verifies that a start_vm with a StageDir that escapes StageRoot
// via a symlink returns bad_request and never calls the backend.
func TestStageDirEscape(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "privd.sock")
	stageRoot := filepath.Join(dir, "stage")
	if err := os.MkdirAll(stageRoot, 0o755); err != nil {
		t.Fatalf("mkdir stageroot: %v", err)
	}
	ledgerDir := filepath.Join(dir, "ledger")
	if err := os.MkdirAll(ledgerDir, 0o755); err != nil {
		t.Fatalf("mkdir ledger: %v", err)
	}

	// Create a symlink inside stageRoot pointing outside of it.
	escapedTarget := filepath.Join(dir, "outside")
	if err := os.MkdirAll(escapedTarget, 0o755); err != nil {
		t.Fatalf("mkdir escaped target: %v", err)
	}
	symlinkPath := filepath.Join(stageRoot, "escape-link")
	if err := os.Symlink(escapedTarget, symlinkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	backend := &recordingBackend{}
	cfg := privd.ServerCfg{
		AllowedUID: os.Getuid(),
		LedgerDir:  ledgerDir,
		StageRoot:  stageRoot,
		JailBase:   filepath.Join(dir, "jail"),
		UIDMin:     os.Getuid(),
		UIDMax:     os.Getuid() + 100,
		Ops:        backend,
	}
	startServer(t, sockPath, cfg)

	vmID := "vm-escape"
	cidr := "10.0.0.0/30"

	// First allocate network so the ledger entry exists (required for start_vm).
	conn := dialPrivd(t, sockPath)
	resp := sendRecv(t, conn, makeReq(t, "allocate_network", privd.AllocateNetworkReq{VMID: vmID, CIDR: cidr}))
	if !resp.OK {
		t.Fatalf("allocate_network: %+v", resp)
	}
	conn.Close()

	// Now start_vm with the escaping symlink as StageDir.
	conn2 := dialPrivd(t, sockPath)
	resp2 := sendRecv(t, conn2, makeReq(t, "start_vm", privd.StartVMReq{
		VMID:     vmID,
		UID:      os.Getuid(),
		GID:      os.Getgid(),
		CID:      4,
		StageDir: symlinkPath,
	}))
	conn2.Close()

	if resp2.OK {
		t.Fatal("expected bad_request from escaping StageDir, got OK")
	}
	if resp2.Cause != "bad_request" {
		t.Errorf("cause = %q, want bad_request", resp2.Cause)
	}
	if len(backend.startCalls) != 0 {
		t.Errorf("backend.StartVM was called despite bad StageDir (%d calls)", len(backend.startCalls))
	}
}

// TestDuplicateAllocate tests idempotent same-CIDR and conflicting different-CIDR.
func TestDuplicateAllocate(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "privd.sock")
	ledgerDir := filepath.Join(dir, "ledger")
	if err := os.MkdirAll(ledgerDir, 0o755); err != nil {
		t.Fatalf("mkdir ledger: %v", err)
	}

	backend := &recordingBackend{}
	cfg := privd.ServerCfg{
		AllowedUID: os.Getuid(),
		LedgerDir:  ledgerDir,
		StageRoot:  dir,
		JailBase:   filepath.Join(dir, "jail"),
		UIDMin:     1000,
		UIDMax:     2000,
		Ops:        backend,
	}
	startServer(t, sockPath, cfg)

	vmID := "vm-dup"
	cidr := "10.1.0.0/30"

	// First allocate — should succeed.
	conn := dialPrivd(t, sockPath)
	resp := sendRecv(t, conn, makeReq(t, "allocate_network", privd.AllocateNetworkReq{VMID: vmID, CIDR: cidr}))
	conn.Close()
	if !resp.OK {
		t.Fatalf("first allocate: %+v", resp)
	}

	// Second allocate with same CIDR — idempotent OK, backend not called again.
	conn2 := dialPrivd(t, sockPath)
	resp2 := sendRecv(t, conn2, makeReq(t, "allocate_network", privd.AllocateNetworkReq{VMID: vmID, CIDR: cidr}))
	conn2.Close()
	if !resp2.OK {
		t.Fatalf("idempotent allocate: %+v", resp2)
	}
	if len(backend.allocateCalls) != 1 {
		t.Errorf("allocateCalls after idempotent = %d, want 1", len(backend.allocateCalls))
	}

	// Third allocate with a different CIDR — invalid_state.
	conn3 := dialPrivd(t, sockPath)
	resp3 := sendRecv(t, conn3, makeReq(t, "allocate_network", privd.AllocateNetworkReq{VMID: vmID, CIDR: "10.2.0.0/30"}))
	conn3.Close()
	if resp3.OK {
		t.Fatal("expected invalid_state for conflicting CIDR, got OK")
	}
	if resp3.Cause != "invalid_state" {
		t.Errorf("cause = %q, want invalid_state", resp3.Cause)
	}
}

// TestLedgerSurvivesRestart verifies that a new server instance with the same LedgerDir
// can read back entries written by the previous server.
func TestLedgerSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	ledgerDir := filepath.Join(dir, "ledger")
	if err := os.MkdirAll(ledgerDir, 0o755); err != nil {
		t.Fatalf("mkdir ledger: %v", err)
	}

	sock1 := filepath.Join(dir, "privd1.sock")
	cfg := privd.ServerCfg{
		AllowedUID: os.Getuid(),
		LedgerDir:  ledgerDir,
		StageRoot:  dir,
		JailBase:   filepath.Join(dir, "jail"),
		UIDMin:     1000,
		UIDMax:     2000,
		Ops:        &recordingBackend{},
	}
	startServer(t, sock1, cfg)

	vmID := "vm-restart"
	cidr := "10.3.0.0/30"

	// Write via server 1.
	conn := dialPrivd(t, sock1)
	resp := sendRecv(t, conn, makeReq(t, "allocate_network", privd.AllocateNetworkReq{VMID: vmID, CIDR: cidr}))
	conn.Close()
	if !resp.OK {
		t.Fatalf("allocate: %+v", resp)
	}

	// Start a second server with the same ledger dir (simulates restart).
	sock2 := filepath.Join(dir, "privd2.sock")
	backend2 := &recordingBackend{}
	cfg2 := privd.ServerCfg{
		AllowedUID: os.Getuid(),
		LedgerDir:  ledgerDir,
		StageRoot:  dir,
		JailBase:   filepath.Join(dir, "jail"),
		UIDMin:     1000,
		UIDMax:     2000,
		Ops:        backend2,
	}
	startServer(t, sock2, cfg2)

	// Try allocating a conflicting CIDR via server 2 — it should see the existing entry.
	conn2 := dialPrivd(t, sock2)
	resp2 := sendRecv(t, conn2, makeReq(t, "allocate_network", privd.AllocateNetworkReq{VMID: vmID, CIDR: "10.9.0.0/30"}))
	conn2.Close()
	if resp2.OK {
		t.Fatal("expected invalid_state from reloaded ledger, got OK")
	}
	if resp2.Cause != "invalid_state" {
		t.Errorf("cause = %q, want invalid_state", resp2.Cause)
	}
	// Backend should not have been called since the conflict was caught pre-backend.
	if len(backend2.allocateCalls) != 0 {
		t.Errorf("backend2.allocateCalls = %d, want 0", len(backend2.allocateCalls))
	}
}

// TestStageRootSymlink verifies that a configured StageRoot that is itself a symlink to a
// real directory does not cause a false containment failure for stage dirs under it.
// This is a regression test for Finding 1: StageRoot must be EvalSymlinks-resolved, not
// just Abs-resolved, before the prefix containment check.
func TestStageRootSymlink(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "privd.sock")

	// Real stage root directory.
	realStageRoot := filepath.Join(dir, "real-stage")
	if err := os.MkdirAll(realStageRoot, 0o755); err != nil {
		t.Fatalf("mkdir real stage root: %v", err)
	}
	// Symlink pointing at the real root — this is what the server is configured with.
	symlinkRoot := filepath.Join(dir, "stage-link")
	if err := os.Symlink(realStageRoot, symlinkRoot); err != nil {
		t.Fatalf("symlink stage root: %v", err)
	}
	// Stage dir lives under the real root (and therefore under the symlink too).
	stageDir := filepath.Join(realStageRoot, "vm-sym-001")
	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		t.Fatalf("mkdir stage dir: %v", err)
	}
	ledgerDir := filepath.Join(dir, "ledger")
	if err := os.MkdirAll(ledgerDir, 0o755); err != nil {
		t.Fatalf("mkdir ledger: %v", err)
	}

	pid, starttime := spawnShortProcess(t)
	backend := &recordingBackend{
		startResp: privd.StartVMResp{PID: pid, StartTime: starttime},
	}
	cfg := privd.ServerCfg{
		AllowedUID: os.Getuid(),
		LedgerDir:  ledgerDir,
		StageRoot:  symlinkRoot, // configured with the symlink path
		JailBase:   filepath.Join(dir, "jail"),
		UIDMin:     os.Getuid(),
		UIDMax:     os.Getuid() + 100,
		Ops:        backend,
	}
	startServer(t, sockPath, cfg)

	vmID := "vm-sym-001"
	cidr := "10.20.0.0/30"

	conn := dialPrivd(t, sockPath)
	resp := sendRecv(t, conn, makeReq(t, "allocate_network", privd.AllocateNetworkReq{VMID: vmID, CIDR: cidr}))
	conn.Close()
	if !resp.OK {
		t.Fatalf("allocate_network: %+v", resp)
	}

	conn2 := dialPrivd(t, sockPath)
	resp2 := sendRecv(t, conn2, makeReq(t, "start_vm", privd.StartVMReq{
		VMID:     vmID,
		UID:      os.Getuid(),
		GID:      os.Getgid(),
		CID:      5,
		StageDir: stageDir, // real path — should still be accepted
	}))
	conn2.Close()

	if !resp2.OK {
		t.Fatalf("start_vm with symlink StageRoot: %+v (want OK; containment must not fail when StageRoot is a symlink)", resp2)
	}
	if len(backend.startCalls) != 1 {
		t.Errorf("startCalls = %d, want 1", len(backend.startCalls))
	}
}

// TestReleaseVMAliveProcess verifies that release_vm returns invalid_state when the recorded
// process is still alive, and succeeds once the process is dead.
// This covers the aliveness gate in handleReleaseVM (Finding 2 — previously untested).
func TestReleaseVMAliveProcess(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "privd.sock")
	stageRoot := filepath.Join(dir, "stage")
	if err := os.MkdirAll(stageRoot, 0o755); err != nil {
		t.Fatalf("mkdir stageroot: %v", err)
	}
	stageDir := filepath.Join(stageRoot, "vm-alive-001")
	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		t.Fatalf("mkdir stagedir: %v", err)
	}
	ledgerDir := filepath.Join(dir, "ledger")
	if err := os.MkdirAll(ledgerDir, 0o755); err != nil {
		t.Fatalf("mkdir ledger: %v", err)
	}

	// Spawn a long-lived process we control.
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn sleep: %v", err)
	}
	// Ensure the process is cleaned up on all exit paths.
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	// Read starttime while the process is definitely alive.
	statPath := privd.ProcStatPath(cmd.Process.Pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		t.Fatalf("read /proc stat: %v", err)
	}
	starttime := privd.ParseStartTime(string(data))
	if starttime == "" {
		t.Fatalf("could not parse starttime from %q", string(data))
	}
	livePID := cmd.Process.Pid

	backend := &recordingBackend{
		startResp: privd.StartVMResp{PID: livePID, StartTime: starttime},
	}
	cfg := privd.ServerCfg{
		AllowedUID: os.Getuid(),
		LedgerDir:  ledgerDir,
		StageRoot:  stageRoot,
		JailBase:   filepath.Join(dir, "jail"),
		UIDMin:     os.Getuid(),
		UIDMax:     os.Getuid() + 100,
		Ops:        backend,
	}
	startServer(t, sockPath, cfg)

	vmID := "vm-alive-001"
	cidr := "10.30.0.0/30"

	// allocate_network → start_vm to get the VM into the ledger with the live PID.
	conn := dialPrivd(t, sockPath)
	resp := sendRecv(t, conn, makeReq(t, "allocate_network", privd.AllocateNetworkReq{VMID: vmID, CIDR: cidr}))
	conn.Close()
	if !resp.OK {
		t.Fatalf("allocate_network: %+v", resp)
	}

	conn2 := dialPrivd(t, sockPath)
	resp2 := sendRecv(t, conn2, makeReq(t, "start_vm", privd.StartVMReq{
		VMID:     vmID,
		UID:      os.Getuid(),
		GID:      os.Getgid(),
		CID:      6,
		StageDir: stageDir,
	}))
	conn2.Close()
	if !resp2.OK {
		t.Fatalf("start_vm: %+v", resp2)
	}

	// release_vm while process is still alive → must return invalid_state.
	conn3 := dialPrivd(t, sockPath)
	resp3 := sendRecv(t, conn3, makeReq(t, "release_vm", privd.ReleaseVMReq{VMID: vmID}))
	conn3.Close()
	if resp3.OK {
		t.Fatal("release_vm on live process: expected invalid_state, got OK")
	}
	if resp3.Cause != "invalid_state" {
		t.Errorf("release_vm cause = %q, want invalid_state", resp3.Cause)
	}

	// Kill the process and wait for it to be reaped.
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("kill sleep: %v", err)
	}
	_ = cmd.Wait() // reap the child; after this /proc/<pid> is gone

	// release_vm after process is dead → must succeed.
	conn4 := dialPrivd(t, sockPath)
	resp4 := sendRecv(t, conn4, makeReq(t, "release_vm", privd.ReleaseVMReq{VMID: vmID}))
	conn4.Close()
	if !resp4.OK {
		t.Fatalf("release_vm after kill: %+v", resp4)
	}
	if len(backend.releaseVMCalls) != 1 {
		t.Errorf("releaseVMCalls = %d, want 1", len(backend.releaseVMCalls))
	}
}

// TestAllocateNetworkRollsBackOnFailure verifies that when the backend's AllocateNetwork
// call fails partway through setup, the server issues a best-effort ReleaseNetwork to
// undo any partial host state, writes no ledger entry, and returns the original setup
// error unchanged — so a subsequent release_network correctly reports not_found rather
// than the orphan being invisible to privd forever.
func TestAllocateNetworkRollsBackOnFailure(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "privd.sock")
	ledgerDir := filepath.Join(dir, "ledger")
	if err := os.MkdirAll(ledgerDir, 0o755); err != nil {
		t.Fatalf("mkdir ledger: %v", err)
	}

	setupErr := errors.New("exec [ip link add veth-x type veth peer name eth-up netns vmobs-x]: exit status 2")
	backend := &recordingBackend{allocateErr: setupErr}
	cfg := privd.ServerCfg{
		AllowedUID: os.Getuid(),
		LedgerDir:  ledgerDir,
		StageRoot:  dir,
		JailBase:   filepath.Join(dir, "jail"),
		UIDMin:     1000,
		UIDMax:     2000,
		Ops:        backend,
	}
	startServer(t, sockPath, cfg)

	vmID := "vm-rollback-001"
	cidr := "10.3.0.0/30"

	conn := dialPrivd(t, sockPath)
	resp := sendRecv(t, conn, makeReq(t, "allocate_network", privd.AllocateNetworkReq{VMID: vmID, CIDR: cidr}))
	conn.Close()

	if resp.OK {
		t.Fatal("expected allocate_network to fail, got OK")
	}
	if resp.Cause != "exec_failed" {
		t.Errorf("cause = %q, want exec_failed", resp.Cause)
	}
	if resp.Message != setupErr.Error() {
		t.Errorf("message = %q, want original setup error %q", resp.Message, setupErr.Error())
	}

	// Teardown must have been issued exactly once, for this vmID.
	if len(backend.releaseCalls) != 1 {
		t.Fatalf("releaseCalls = %d, want 1 (rollback teardown)\n  calls: %v", len(backend.releaseCalls), backend.releaseCalls)
	}
	if backend.releaseCalls[0] != vmID {
		t.Errorf("releaseCalls[0] = %q, want %q", backend.releaseCalls[0], vmID)
	}

	// No ledger entry must have been written.
	ledgerFile := filepath.Join(ledgerDir, vmID+".json")
	if _, err := os.Stat(ledgerFile); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("ledger file exists after failed allocate (want: absent): err=%v", err)
	}

	// A subsequent release_network for the same vmID must report not_found — the
	// server has no record of it, so there is nothing left to release.
	conn2 := dialPrivd(t, sockPath)
	resp2 := sendRecv(t, conn2, makeReq(t, "release_network", privd.ReleaseNetworkReq{VMID: vmID}))
	conn2.Close()
	if resp2.OK {
		t.Fatal("expected release_network on unledgered vm to fail, got OK")
	}
	if resp2.Cause != "not_found" {
		t.Errorf("release_network cause = %q, want not_found", resp2.Cause)
	}
}

// TestAllocateNetworkHappyPathNoTeardown verifies that a successful allocate_network
// issues no teardown call — rollback must never run on the success path.
func TestAllocateNetworkHappyPathNoTeardown(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "privd.sock")
	ledgerDir := filepath.Join(dir, "ledger")
	if err := os.MkdirAll(ledgerDir, 0o755); err != nil {
		t.Fatalf("mkdir ledger: %v", err)
	}

	backend := &recordingBackend{}
	cfg := privd.ServerCfg{
		AllowedUID: os.Getuid(),
		LedgerDir:  ledgerDir,
		StageRoot:  dir,
		JailBase:   filepath.Join(dir, "jail"),
		UIDMin:     1000,
		UIDMax:     2000,
		Ops:        backend,
	}
	startServer(t, sockPath, cfg)

	vmID := "vm-happy-001"
	cidr := "10.4.0.0/30"

	conn := dialPrivd(t, sockPath)
	resp := sendRecv(t, conn, makeReq(t, "allocate_network", privd.AllocateNetworkReq{VMID: vmID, CIDR: cidr}))
	conn.Close()
	if !resp.OK {
		t.Fatalf("allocate_network: %+v", resp)
	}

	ledgerFile := filepath.Join(ledgerDir, vmID+".json")
	if _, err := os.Stat(ledgerFile); err != nil {
		t.Fatalf("ledger file not created: %v", err)
	}
	if len(backend.releaseCalls) != 0 {
		t.Errorf("releaseCalls = %d, want 0 (no teardown on success)\n  calls: %v", len(backend.releaseCalls), backend.releaseCalls)
	}
}
