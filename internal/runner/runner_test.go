// ABOUTME: Portable tests for the runner package: state roundtrip and ctl protocol.
// ABOUTME: These build on any OS; no /proc, no vsock, no real child processes.
package runner_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/runner"
)

// shortSockDir creates a temp dir with a short path (avoids macOS sun_path limit).
// The returned dir is cleaned up when the test ends.
func shortSockDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "rv")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// TestStateRoundTrip verifies that State can be written and read back, and
// that concurrent writes produce no invalid JSON for a looping reader.
func TestStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "runner-state.json")

	s := runner.State{
		VMID:          "vm-abc",
		BootID:        "boot-xyz",
		InstanceID:    "inst-123",
		RunnerPID:     12345,
		VMMPID:        99999,
		VMMStartTime:  "4321098",
		Phase:         "starting",
		UpdatedAtUnix: time.Now().Unix(),
	}
	if err := runner.WriteState(stateFile, s); err != nil {
		t.Fatalf("WriteState: %v", err)
	}

	got, err := runner.ReadState(stateFile)
	if err != nil {
		t.Fatalf("ReadState: %v", err)
	}
	if got.VMID != s.VMID {
		t.Errorf("VMID: got %q, want %q", got.VMID, s.VMID)
	}
	if got.Phase != s.Phase {
		t.Errorf("Phase: got %q, want %q", got.Phase, s.Phase)
	}
	if got.RunnerPID != s.RunnerPID {
		t.Errorf("RunnerPID: got %d, want %d", got.RunnerPID, s.RunnerPID)
	}
	if got.VMMStartTime != s.VMMStartTime {
		t.Errorf("VMMStartTime: got %q, want %q", got.VMMStartTime, s.VMMStartTime)
	}
}

// TestStateAtomicWrite verifies that a reader looping during 100 concurrent
// writes never sees invalid (truncated/partial) JSON.
func TestStateAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "runner-state.json")

	// Write an initial state so the reader has something valid to start with.
	initial := runner.State{VMID: "vm-x", Phase: "starting", UpdatedAtUnix: time.Now().Unix()}
	if err := runner.WriteState(stateFile, initial); err != nil {
		t.Fatalf("WriteState initial: %v", err)
	}

	const writes = 100
	var wg sync.WaitGroup
	var invalidJSON atomic.Int32

	// Reader goroutine: loops for the duration of the writes.
	wg.Add(1)
	done := make(chan struct{})
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			data, err := os.ReadFile(stateFile)
			if err != nil {
				// File may temporarily vanish during rename — skip.
				continue
			}
			var s runner.State
			if err := json.Unmarshal(data, &s); err != nil {
				invalidJSON.Add(1)
			}
		}
	}()

	// Writer: 100 sequential writes.
	for i := 0; i < writes; i++ {
		s := runner.State{
			VMID:          "vm-x",
			Phase:         "attached",
			UpdatedAtUnix: time.Now().Unix(),
		}
		if err := runner.WriteState(stateFile, s); err != nil {
			t.Errorf("WriteState(%d): %v", i, err)
		}
	}
	close(done)
	wg.Wait()

	if n := invalidJSON.Load(); n > 0 {
		t.Errorf("reader saw %d invalid JSON snapshots during 100 writes", n)
	}
}

// TestCtlProtocolShutdownGuest verifies the ctl socket protocol for shutdown_guest:
// the injected shutdown func is called with the right grace, reply is {"ok":true}.
func TestCtlProtocolShutdownGuest(t *testing.T) {
	dir := shortSockDir(t)
	sockPath := filepath.Join(dir, "r.sock")

	var calledGrace int
	var calledMu sync.Mutex
	shutdownFn := func(grace int) error {
		calledMu.Lock()
		calledGrace = grace
		calledMu.Unlock()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv, err := runner.ListenCtl(ctx, sockPath, runner.CtlHandlers{Shutdown: shutdownFn})
	if err != nil {
		t.Fatalf("ListenCtl: %v", err)
	}
	defer srv.Close()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// Send shutdown_guest command.
	cmd := map[string]any{"cmd": "shutdown_guest", "grace_s": 20}
	if err := json.NewEncoder(conn).Encode(cmd); err != nil {
		t.Fatalf("Encode cmd: %v", err)
	}

	var reply map[string]any
	if err := json.NewDecoder(conn).Decode(&reply); err != nil {
		t.Fatalf("Decode reply: %v", err)
	}
	ok, _ := reply["ok"].(bool)
	if !ok {
		t.Errorf("shutdown_guest reply: want ok=true, got %v", reply)
	}

	calledMu.Lock()
	grace := calledGrace
	calledMu.Unlock()
	if grace != 20 {
		t.Errorf("shutdown grace: got %d, want 20", grace)
	}
}

// TestCtlProtocolShutdownGuestError verifies that a shutdown func returning an
// error causes the reply to carry ok=false.
func TestCtlProtocolShutdownGuestError(t *testing.T) {
	dir := shortSockDir(t)
	sockPath := filepath.Join(dir, "r.sock")

	shutdownFn := func(_ int) error {
		return errors.New("channel dropped")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv, err := runner.ListenCtl(ctx, sockPath, runner.CtlHandlers{Shutdown: shutdownFn})
	if err != nil {
		t.Fatalf("ListenCtl: %v", err)
	}
	defer srv.Close()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	cmd := map[string]any{"cmd": "shutdown_guest", "grace_s": 10}
	if err := json.NewEncoder(conn).Encode(cmd); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var reply map[string]any
	if err := json.NewDecoder(conn).Decode(&reply); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	ok, _ := reply["ok"].(bool)
	if ok {
		t.Errorf("want ok=false on error, got ok=true")
	}
	if _, has := reply["error"]; !has {
		t.Errorf("want error field in reply, got %v", reply)
	}
}

// TestCtlProtocolFinalize verifies the finalize command calls the finalize func
// and replies ok=true.
func TestCtlProtocolFinalize(t *testing.T) {
	dir := shortSockDir(t)
	sockPath := filepath.Join(dir, "r.sock")

	var finalized atomic.Bool
	finalizeFn := func() error {
		finalized.Store(true)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv, err := runner.ListenCtl(ctx, sockPath, runner.CtlHandlers{Finalize: finalizeFn})
	if err != nil {
		t.Fatalf("ListenCtl: %v", err)
	}
	defer srv.Close()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	cmd := map[string]any{"cmd": "finalize"}
	if err := json.NewEncoder(conn).Encode(cmd); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var reply map[string]any
	if err := json.NewDecoder(conn).Decode(&reply); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	ok, _ := reply["ok"].(bool)
	if !ok {
		t.Errorf("finalize reply: want ok=true, got %v", reply)
	}
	if !finalized.Load() {
		t.Error("finalize func was not called")
	}
}

// TestCtlProtocolUnknownCmd verifies that an unknown command returns ok=false.
func TestCtlProtocolUnknownCmd(t *testing.T) {
	dir := shortSockDir(t)
	sockPath := filepath.Join(dir, "r.sock")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv, err := runner.ListenCtl(ctx, sockPath, runner.CtlHandlers{})
	if err != nil {
		t.Fatalf("ListenCtl: %v", err)
	}
	defer srv.Close()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	cmd := map[string]any{"cmd": "dance"}
	if err := json.NewEncoder(conn).Encode(cmd); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var reply map[string]any
	if err := json.NewDecoder(conn).Decode(&reply); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	ok, _ := reply["ok"].(bool)
	if ok {
		t.Errorf("unknown cmd: want ok=false, got ok=true")
	}
}

// TestParseFlagsValid verifies that parseFlags accepts valid flag sets.
func TestParseFlagsValid(t *testing.T) {
	args := []string{
		"--vm-id", "vm-abc",
		"--boot-id", "boot-xyz",
		"--instance-id", "inst-123",
		"--uds", "/tmp/v.sock",
		"--token-file", "/tmp/token",
		"--spool-dir", "/tmp/spool",
		"--state-file", "/tmp/state.json",
		"--ctl-sock", "/tmp/runner.sock",
		"--vmm-pid", "12345",
		"--vmm-starttime", "9876543",
		"--ping-interval", "5s",
	}
	cfg, err := runner.ParseFlags("vmobs-runner", args)
	if err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if cfg.VMID != "vm-abc" {
		t.Errorf("VMID: got %q, want %q", cfg.VMID, "vm-abc")
	}
	if cfg.VMMStartTime != "9876543" {
		t.Errorf("VMMStartTime: got %q, want %q", cfg.VMMStartTime, "9876543")
	}
}

// TestParseFlagsNonDecimalStarttime verifies that non-decimal --vmm-starttime is rejected.
func TestParseFlagsNonDecimalStarttime(t *testing.T) {
	args := []string{
		"--vm-id", "vm-abc",
		"--boot-id", "boot-xyz",
		"--instance-id", "inst-123",
		"--uds", "/tmp/v.sock",
		"--token-file", "/tmp/token",
		"--spool-dir", "/tmp/spool",
		"--state-file", "/tmp/state.json",
		"--ctl-sock", "/tmp/runner.sock",
		"--vmm-pid", "12345",
		"--vmm-starttime", "0xdeadbeef",
		"--ping-interval", "5s",
	}
	_, err := runner.ParseFlags("vmobs-runner", args)
	if err == nil {
		t.Fatal("expected error for non-decimal --vmm-starttime, got nil")
	}
}

// TestParseFlagsMissingRequired verifies that missing required flags cause an error.
func TestParseFlagsMissingRequired(t *testing.T) {
	// Missing --boot-id and several others.
	args := []string{
		"--vm-id", "vm-abc",
		"--vmm-pid", "12345",
		"--vmm-starttime", "9876543",
	}
	_, err := runner.ParseFlags("vmobs-runner", args)
	if err == nil {
		t.Fatal("expected error for missing required flags, got nil")
	}
}

// TestCtlSocketMode0600 verifies the socket is created with mode 0600.
func TestCtlSocketMode0600(t *testing.T) {
	dir := shortSockDir(t)
	sockPath := filepath.Join(dir, "r.sock")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv, err := runner.ListenCtl(ctx, sockPath, runner.CtlHandlers{})
	if err != nil {
		t.Fatalf("ListenCtl: %v", err)
	}
	defer srv.Close()

	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	mode := info.Mode().Perm()
	if mode != 0o600 {
		t.Errorf("socket mode: got %04o, want 0600", mode)
	}
}

// TestPhaseValues verifies that the Phase constants have the exact string values
// the brief mandates.
func TestPhaseValues(t *testing.T) {
	cases := []struct {
		got  string
		want string
	}{
		{runner.PhaseStarting, "starting"},
		{runner.PhaseAttached, "attached"},
		{runner.PhaseDegraded, "degraded"},
		{runner.PhaseVMMExited, "vmm_exited"},
		{runner.PhaseFinalized, "finalized"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("phase constant: got %q, want %q", c.got, c.want)
		}
	}
}

// TestMultipleCtlConnections verifies the ctl socket handles multiple sequential
// connections independently.
func TestMultipleCtlConnections(t *testing.T) {
	dir := shortSockDir(t)
	sockPath := filepath.Join(dir, "r.sock")

	var count atomic.Int32
	finalizeFn := func() error {
		count.Add(1)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv, err := runner.ListenCtl(ctx, sockPath, runner.CtlHandlers{Finalize: finalizeFn})
	if err != nil {
		t.Fatalf("ListenCtl: %v", err)
	}
	defer srv.Close()

	for i := 0; i < 3; i++ {
		conn, err := net.Dial("unix", sockPath)
		if err != nil {
			t.Fatalf("Dial[%d]: %v", i, err)
		}
		cmd := map[string]any{"cmd": "finalize"}
		if err := json.NewEncoder(conn).Encode(cmd); err != nil {
			conn.Close()
			t.Fatalf("Encode[%d]: %v", i, err)
		}
		var reply map[string]any
		if err := json.NewDecoder(conn).Decode(&reply); err != nil {
			conn.Close()
			t.Fatalf("Decode[%d]: %v", i, err)
		}
		conn.Close()

		if ok, _ := reply["ok"].(bool); !ok {
			t.Errorf("connection %d: want ok=true, got %v", i, reply)
		}

		_ = fmt.Sprintf("conn %d done", i) // prevent lint unused
	}

	if n := count.Load(); n != 3 {
		t.Errorf("finalize called %d times, want 3", n)
	}
}
