// ABOUTME: Linux integration test for the runner: real guestd, real child process as VMM.
// ABOUTME: Verifies state transitions, spool contents, and clean Run exit on VMM death.

//go:build linux

package runner_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/guest"
	"github.com/2389-research/observatory-v2/internal/guest/proto"
	"github.com/2389-research/observatory-v2/internal/privd"
	"github.com/2389-research/observatory-v2/internal/runner"
	"github.com/2389-research/observatory-v2/internal/spool"
)

// TestRunnerAgainstRealGuestd runs runner.Run against:
//   - a REAL guest.Agent + ServeControl on a unix socket (mimicking guestd)
//   - a real "sleep 300" child process as the VMM stand-in
//
// Asserts:
//  1. State reaches "attached"
//  2. Spool contains guest.channel_established
//  3. Killing the sleep child → state reaches "finalized"
//  4. Spool ends with vm.vmm_exited + end marker
//  5. Run returns nil
func TestRunnerAgainstRealGuestd(t *testing.T) {
	if os.Getenv("VMOBS_RUNNER_TEST") == "" {
		// Require explicit opt-in on linux: real guestd + child proc
		// Use VMOBS_RUNNER_TEST=1 to enable.
		// Skip cleanly so scripts/linux without the env still runs green.
		t.Skip("set VMOBS_RUNNER_TEST=1 to run the linux integration test")
	}

	dir := t.TempDir()
	spoolDir := filepath.Join(dir, "spool")
	stateFile := filepath.Join(dir, "runner-state.json")
	ctlSock := filepath.Join(dir, "runner.sock")
	// UDS for guestd — simulates the VM's v.sock
	vSock := filepath.Join(dir, "v.sock")

	const token = "test-capability-token-12345"

	// Write the token file (runner reads from file, never from argv — §15.3).
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte(token), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	// Create spool dir.
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatalf("mkdir spool: %v", err)
	}

	// Start a real guest.Agent on the UDS that proto.DialHostVsock will CONNECT to.
	// proto.DialHostVsock speaks "CONNECT <port>\n" → "OK <hostport>\n" then hands
	// the conn to the application. We implement that accept-side CONNECT/OK protocol
	// in the listener below.
	guestLn, err := listen0600(vSock)
	if err != nil {
		t.Fatalf("listen v.sock: %v", err)
	}
	defer guestLn.Close()

	cfg := &guest.BootConfig{
		Schema:          "vmobs.guest_context.v1",
		VMID:            "vm-test-runner",
		BootID:          "boot-test-runner",
		CapabilityToken: token,
		ProtocolVersion: proto.ProtocolVersion,
	}
	manifest := proto.CapabilityManifest{
		Schema:        "vmobs.guest_capability.v1",
		KernelRelease: "6.1.0-test",
		Features:      []proto.Feature{{ID: "btf", Present: true}},
	}
	agent := guest.NewAgent(cfg, manifest)

	// Wrap the raw UDS listener so it speaks CONNECT/OK before handing the conn
	// to the guest agent. This matches what Firecracker's vsock proxy does.
	connectLn := &connectOKListener{Listener: guestLn}

	agentCtx, agentCancel := context.WithCancel(context.Background())
	defer agentCancel()

	agentDone := make(chan error, 1)
	go func() {
		agentDone <- agent.ServeControl(agentCtx, connectLn)
	}()

	// Spawn a real "sleep 300" as the fake VMM.
	cmd := exec.Command("sleep", "300")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	vmmPID := cmd.Process.Pid

	// Read the actual starttime from /proc/<pid>/stat.
	statData, err := os.ReadFile(privd.ProcStatPath(vmmPID))
	if err != nil {
		t.Fatalf("read proc stat: %v", err)
	}
	vmmStartTime := privd.ParseStartTime(string(statData))
	if vmmStartTime == "" {
		t.Fatal("could not parse starttime from proc stat")
	}

	// Build runner Config.
	rcfg := runner.Config{
		VMID:         "vm-test-runner",
		BootID:       "boot-test-runner",
		InstanceID:   "inst-test-runner-1",
		UDSPath:      vSock,
		TokenFile:    tokenFile,
		SpoolDir:     spoolDir,
		StateFile:    stateFile,
		CtlSock:      ctlSock,
		VMMPID:       vmmPID,
		VMMStartTime: vmmStartTime,
		PingInterval: 500 * time.Millisecond,
	}

	// Run runner.Run in a goroutine.
	runCtx, runCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer runCancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runner.Run(runCtx, rcfg)
	}()

	// Wait for state to reach "attached".
	if !waitForPhase(t, stateFile, runner.PhaseAttached, 10*time.Second) {
		t.Fatal("state never reached 'attached'")
	}

	// Assert spool contains guest.channel_established.
	if !spoolContainsKind(t, spoolDir, "guest.channel_established") {
		t.Error("spool missing guest.channel_established")
	}

	// Kill the fake VMM — this should trigger vm.vmm_exited → finalized.
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill sleep: %v", err)
	}
	_ = cmd.Wait()

	// Wait for state to reach "finalized".
	if !waitForPhase(t, stateFile, runner.PhaseFinalized, 10*time.Second) {
		t.Fatal("state never reached 'finalized'")
	}

	// Run should return nil.
	select {
	case err := <-runDone:
		if err != nil {
			t.Errorf("Run returned non-nil error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Run did not return within 5s of finalized state")
		runCancel()
	}

	// Assert spool contains vm.vmm_exited with graceful=false.
	if !spoolContainsKind(t, spoolDir, "vm.vmm_exited") {
		t.Error("spool missing vm.vmm_exited")
	}

	// Assert at least one segment has an end marker (clean close).
	if !spoolHasEndMarker(t, spoolDir) {
		t.Error("spool has no segment with end marker (Close was not clean)")
	}

	// Cleanup.
	agentCancel()
	select {
	case <-agentDone:
	case <-time.After(2 * time.Second):
	}
}

// connectOKListener wraps a net.Listener and performs the Firecracker-style
// CONNECT <port>\n → OK <port>\n handshake on each accepted connection before
// returning the conn. This mimics what the jailer's vsock proxy does.
type connectOKListener struct {
	net.Listener
}

func (l *connectOKListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	// Read the CONNECT line (byte at a time, up to 64 bytes).
	var line []byte
	buf := make([]byte, 1)
	for len(line) < 64 {
		if _, err := conn.Read(buf); err != nil {
			conn.Close()
			return nil, fmt.Errorf("connectOK: read CONNECT: %w", err)
		}
		if buf[0] == '\n' {
			break
		}
		line = append(line, buf[0])
	}
	// Write OK response.
	if _, err := conn.Write([]byte("OK 12345\n")); err != nil {
		conn.Close()
		return nil, fmt.Errorf("connectOK: write OK: %w", err)
	}
	return conn, nil
}

// listen0600 creates a unix socket with mode 0600.
func listen0600(path string) (net.Listener, error) {
	old := umask(0o177)
	defer umask(old)
	return net.Listen("unix", path)
}

// waitForPhase polls stateFile until phase matches or timeout.
func waitForPhase(t *testing.T, stateFile, phase string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s, err := runner.ReadState(stateFile)
		if err == nil && s.Phase == phase {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Read final state for the error message.
	s, err := runner.ReadState(stateFile)
	t.Logf("waitForPhase(%q): timeout; last state=%+v err=%v", phase, s, err)
	return false
}

// spoolContainsKind checks whether any spool segment in dir contains an envelope
// with the given kind.
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
			if errors.Is(err, io.EOF) {
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

// spoolHasEndMarker returns true when any segment has a clean end marker.
func spoolHasEndMarker(t *testing.T, spoolDir string) bool {
	t.Helper()
	segs, _ := filepath.Glob(filepath.Join(spoolDir, "seg-*.vmsp"))
	for _, seg := range segs {
		// End marker is the last 4 bytes == 0xFFFFFFFF.
		f, err := os.Open(seg)
		if err != nil {
			continue
		}
		info, err := f.Stat()
		f.Close()
		if err != nil || info.Size() < 4 {
			continue
		}
		raw, err := os.ReadFile(seg)
		if err != nil || len(raw) < 4 {
			continue
		}
		if raw[len(raw)-4] == 0xFF && raw[len(raw)-3] == 0xFF &&
			raw[len(raw)-2] == 0xFF && raw[len(raw)-1] == 0xFF {
			return true
		}
	}
	return false
}
