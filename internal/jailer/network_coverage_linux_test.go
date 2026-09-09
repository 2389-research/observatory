// ABOUTME: Exercises network coverage through a real runner control server process.
// ABOUTME: Proves manifest, state, process, and Unix peer identities must all agree.

//go:build linux

package jailer

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/privd"
	"github.com/2389-research/observatory/internal/runner"
	"github.com/2389-research/observatory/internal/situation"
	"github.com/2389-research/observatory/internal/store"
)

const coverageHelperEnv = "VMOBS_NETWORK_COVERAGE_HELPER"

func TestNetworkCoverageCtlHelper(t *testing.T) {
	if os.Getenv(coverageHelperEnv) == "" {
		return
	}
	var status runner.NetworkStatus
	if err := json.Unmarshal([]byte(os.Getenv("VMOBS_NETWORK_STATUS")), &status); err != nil {
		t.Fatal(err)
	}
	// A live runner re-stamps its published status for its whole life and moves
	// nothing but the timestamp (runner.keepNetworkStatusLive). This helper does
	// the same at serve time: the status it was handed is fresh when it is read,
	// however long the parent waited for this socket to appear.
	srv, err := runner.ListenCtl(context.Background(), os.Getenv("VMOBS_NETWORK_SOCKET"), runner.CtlHandlers{
		NetworkStatus: func() runner.NetworkStatus {
			live := status
			live.UpdatedAt = time.Now().UTC()
			return live
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	select {}
}

func TestAdapterCoverageAuthenticatesRealRunnerCtlProcess(t *testing.T) {
	now := time.Now().UTC()
	status := validNetworkStatus(now)
	a, vm, child := liveCoverageFixture(t, status)

	got, err := a.Coverage(t.Context(), vm)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].State != situation.CoverageHealthy || got[1].State != situation.CoverageHealthy {
		t.Fatalf("coverage = %+v, want two healthy live collectors", got)
	}
	if child.ProcessState != nil {
		t.Fatal("runner helper exited before coverage returned")
	}
}

func TestAdapterCoverageRejectsRunnerInstanceMismatch(t *testing.T) {
	status := validNetworkStatus(time.Now().UTC())
	a, vm, _ := liveCoverageFixture(t, status)
	statePath := filepath.Join(a.cfg.StateDir, "vms", vm.VMID, "runner-state.json")
	state, err := runner.ReadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	state.InstanceID = "00000000-0000-4000-8000-000000000099"
	if err := runner.WriteState(statePath, state); err != nil {
		t.Fatal(err)
	}
	// Any error would satisfy "was refused", including one raised long before the
	// instance comparison. Name the refusal this test exists to prove.
	if _, err := a.Coverage(t.Context(), vm); err == nil || !strings.Contains(err.Error(), "jailer: network status names another runner instance") {
		t.Fatalf("err = %v, want the status refused for naming another runner instance", err)
	}
}

func TestAdapterCoverageRejectsWrongUnixPeerPID(t *testing.T) {
	status := validNetworkStatus(time.Now().UTC())
	a, vm, _ := liveCoverageFixture(t, status)
	otherPID := spawnRunnerLookalike(t, "--vm-id", vm.VMID)
	m, err := readManifest(a.cfg.StateDir, vm.VMID)
	if err != nil {
		t.Fatal(err)
	}
	m.RunnerPID, m.RunnerStart = otherPID, readRunnerStart(otherPID)
	if err := writeManifest(a.cfg.StateDir, m); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(a.cfg.StateDir, "vms", vm.VMID, "runner-state.json")
	state, err := runner.ReadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	state.RunnerPID = otherPID
	if err := runner.WriteState(statePath, state); err != nil {
		t.Fatal(err)
	}
	// Same reason: a dial or manifest failure is not proof that the peer check ran.
	if _, err := a.Coverage(t.Context(), vm); err == nil || !strings.Contains(err.Error(), "jailer: runner control peer does not match live runner identity") {
		t.Fatalf("err = %v, want the control peer refused for not matching the live runner", err)
	}
}

func liveCoverageFixture(t *testing.T, status runner.NetworkStatus) (*Adapter, *store.VM, *exec.Cmd) {
	t.Helper()
	stateDir, err := os.MkdirTemp("/tmp", "vmobs-nc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })
	socketPath := filepath.Join(stateDir, "vms", status.VMID, "runner.sock")
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestNetworkCoverageCtlHelper$", "--", "--vm-id", status.VMID)
	cmd.Env = append(os.Environ(), coverageHelperEnv+"=1", "VMOBS_NETWORK_SOCKET="+socketPath, "VMOBS_NETWORK_STATUS="+string(encoded))
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	// The package TestMain builds vmobs-runner before selecting this helper test.
	// A cold Linux container may need to compile that dependency graph first.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(socketPath); err != nil {
		t.Fatalf("runner helper did not create control socket: %v", err)
	}
	runnerStart := readRunnerStart(cmd.Process.Pid)
	vmmStart := readRunnerStart(os.Getpid())
	m := Manifest{VMID: status.VMID, BootID: status.BootID, RunnerPID: cmd.Process.Pid, RunnerStart: runnerStart, VMMPID: os.Getpid(), VMMStart: vmmStart}
	if err := writeManifest(stateDir, m); err != nil {
		t.Fatal(err)
	}
	if err := runner.WriteState(filepath.Join(stateDir, "vms", status.VMID, "runner-state.json"), runner.State{
		VMID: status.VMID, BootID: status.BootID, InstanceID: status.InstanceID, RunnerPID: cmd.Process.Pid,
		VMMPID: os.Getpid(), VMMStartTime: vmmStart, Phase: runner.PhaseAttached, UpdatedAtUnix: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	if !privd.PIDAlive(cmd.Process.Pid, runnerStart) {
		t.Fatal("runner helper process is not live under its recorded identity")
	}
	return &Adapter{cfg: Config{StateDir: stateDir}}, &store.VM{
		VMID: status.VMID, CurrentBootID: status.BootID, NetworkProfile: status.Profile, NetworkPolicyID: status.PolicyID,
	}, cmd
}

// The never-acquired shape has to survive the adapter's own gates too: the
// runner it names is live and authenticated, it just owns no observers, and
// the VM's profile is not evidence the runner ever bound to it.
func TestAdapterCoverageCarriesNeverAcquiredRunnerReason(t *testing.T) {
	status := neverAcquiredStatus(time.Now().UTC())
	a, vm, _ := liveCoverageFixture(t, status)
	vm.NetworkProfile, vm.NetworkPolicyID = "transport", "transport-public-web"

	got, err := a.Coverage(t.Context(), vm)
	if err != nil {
		t.Fatalf("never-acquired runner status refused by the adapter: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("coverage = %+v, want flow and denial", got)
	}
	for _, collector := range got {
		if collector.State != situation.CoverageUnavailable || !strings.Contains(collector.Reason, "network observer acquisition refused: privd said no") {
			t.Fatalf("%s = %+v, want unavailable carrying the runner's own reason", collector.ID, collector)
		}
	}
}
