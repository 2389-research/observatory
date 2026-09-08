// ABOUTME: Exercises importer recovery and terminal liveness against a real guest.
// ABOUTME: Runs inside the Docker acceptance gate with actual spool permission faults.

//go:build linux

package integration_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/jailer"
	"github.com/2389-research/observatory/internal/runtime"
)

func TestKataImportAndTerminalGate(t *testing.T) {
	if os.Getenv("VMOBS_FIXTURE") != "1" {
		t.Skip("set VMOBS_FIXTURE=1 inside scripts/vmobs-gate")
	}
	gateSkipChecks(t)
	m1aSkipChecks(t)
	if os.Getuid() == 0 {
		t.Fatal("run the gate as its configured non-root operator")
	}
	d := startDaemon(t, findRepoRoot(t),
		buildBinary(t, "github.com/2389-research/observatory/cmd/vmobsd"),
		buildBinary(t, "github.com/2389-research/observatory/cmd/vmobs-runner"),
		"kata-import-terminal", withRequiredAuth(m1bOperator, m1bPassword))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	id := d.createVM(t, "kata-import-terminal")
	d.waitVMState(ctx, t, id, "running")
	d.waitHeartbeats(t, id, 2, 90*time.Second)
	term := d.openTerm(t, d.createTerminal(t, id).ID, "kata-terminal")
	term.takeWriter()
	attached := time.Now()

	waitStatus := func(state string, minimumFailures uint64) map[string]any {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		var status map[string]any
		for time.Now().Before(deadline) {
			status = d.apiGet(t, "/vms/"+id+"/telemetry/import")
			failures, err := strconv.ParseUint(stringField(status, "consecutive_failures"), 10, 64)
			if err == nil && stringField(status, "state") == state && failures >= minimumFailures {
				return status
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("import status did not reach %s with >=%d failures: %v", state, minimumFailures, status)
		return nil
	}
	before := waitStatus("healthy", 0)
	spoolDir := filepath.Join(d.stateDir, "spool", id)
	info, err := os.Stat(spoolDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(spoolDir, info.Mode().Perm()); err != nil && !os.IsNotExist(err) {
			t.Errorf("restore spool permissions: %v", err)
		}
	})
	if err := os.Chmod(spoolDir, 0); err != nil {
		t.Fatal(err)
	}
	failed := waitStatus("degraded", 2)
	if stringField(failed, "last_error") == "" || stringField(failed, "next_retry_at") == "" || stringField(failed, "last_success_at") == "" {
		t.Fatalf("fault diagnostics missing: %v", failed)
	}
	if _, state := d.waitTelemetryHealth(t, id, "degraded", 10*time.Second); state != "running" {
		t.Fatalf("import fault changed VM lifecycle to %s", state)
	}
	if err := os.Chmod(spoolDir, info.Mode().Perm()); err != nil {
		t.Fatal(err)
	}
	after := waitStatus("healthy", 0)
	if stringField(after, "last_success_at") <= stringField(before, "last_success_at") || stringField(after, "last_error") != "" || stringField(after, "consecutive_failures") != "0" {
		t.Fatalf("recovery did not clear the fault and advance success: before=%v after=%v", before, after)
	}
	d.waitTelemetryHealth(t, id, "healthy", 90*time.Second)
	// Exercise the production 30s HTTP and ping budgets, including the 10s
	// pong deadline. The browser reader stays active while this terminal is idle.
	if remaining := 45*time.Second - time.Since(attached); remaining > 0 {
		time.Sleep(remaining)
	}
	if output := term.runGuest("printf 'kata_terminal_alive\\n'", m1bCommandTimeout); !strings.Contains(output, "kata_terminal_alive") {
		t.Fatalf("terminal failed after idle heartbeat and import recovery: %s", tailOf(output, 400))
	}
	if status, body := d.apiDelete(t, "/vms/"+id+"?force=true"); status != 200 {
		t.Fatalf("force delete: status=%d body=%v", status, body)
	}
	t.Logf("real guest import fault retried and recovered; terminal remained usable after %s", time.Since(attached).Round(time.Second))
}

func TestKataRestartDiskAndNetworkGate(t *testing.T) {
	if os.Getenv("VMOBS_FIXTURE") != "1" {
		t.Skip("set VMOBS_FIXTURE=1 inside scripts/vmobs-gate")
	}
	gateSkipChecks(t)
	m1aSkipChecks(t)
	repo := findRepoRoot(t)
	// Build both controller generations before measuring free space, so the
	// test's own binaries cannot consume the headroom being tested.
	firstBin := buildBinary(t, "github.com/2389-research/observatory/cmd/vmobsd")
	firstRunner := buildBinary(t, "github.com/2389-research/observatory/cmd/vmobs-runner")
	secondBin := buildBinary(t, "github.com/2389-research/observatory/cmd/vmobsd")
	secondRunner := buildBinary(t, "github.com/2389-research/observatory/cmd/vmobs-runner")
	stateDir := t.TempDir()
	host, err := runtime.ProbeHost(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	const requestedDisk = gateRootDiskMiB + gateWorkspaceDiskMiB
	scratch := host.StateDiskFreeMiB - requestedDisk - 512
	if scratch < 20480 {
		t.Fatalf("need enough free disk to preserve the 20480 MiB inspection reserve: free=%d", host.StateDiskFreeMiB)
	}
	reserve := func(o *daemonOptions) { o.scratchMiB = scratch }
	first := startDaemon(t, repo, firstBin, firstRunner, "kata-before-restart", withStateDir(stateDir), reserve)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	baseline := first.reservedTotals(t)
	id := first.createVM(t, "kata-survivor")
	first.waitVMState(ctx, t, id, "running")
	charged := first.reservedTotals(t)
	manifest, err := jailer.ReadManifest(stateDir, id)
	if err != nil {
		t.Fatal(err)
	}
	first.cancel()
	waitControllerGone(t, first, 30*time.Second)
	second := startDaemon(t, repo, secondBin, secondRunner, "kata-after-restart", withStateDir(stateDir), reserve)
	second.adoptVMsFrom(first)
	second.waitVMState(ctx, t, id, "running")
	if got := second.reservedTotals(t); got != charged {
		t.Fatalf("restart changed reservations: before=%s after=%s", charged, got)
	}
	allocated, err := runtime.ProbeHost(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	// The old startup-only calculation must refuse a successor at this point,
	// even after releasing its reservation. This proves the regression setup.
	if available := allocated.StateDiskFreeMiB - scratch; available >= requestedDisk {
		t.Fatalf("headroom is too large to reproduce stale admission: %d >= %d", available, requestedDisk)
	}
	if status, body := second.apiDelete(t, "/vms/"+id+"?force=true"); status != 200 {
		t.Fatalf("delete survivor: status=%d body=%v", status, body)
	}
	for _, removed := range []string{
		filepath.Join(stateDir, "vms", id),
		filepath.Join(m1aStageBaseDir, id),
		filepath.Join(m1aJailBase, "firecracker", id),
	} {
		if _, err := os.Lstat(removed); !os.IsNotExist(err) {
			t.Fatalf("release left %s: %v", removed, err)
		}
	}
	if got := second.reservedTotals(t); got != baseline {
		t.Fatalf("delete retained reservations: baseline=%s got=%s", baseline, got)
	}
	next := second.createVM(t, "kata-reclaimed-successor")
	second.waitVMState(ctx, t, next, "running")
	if got := second.reservedTotals(t); got != charged {
		t.Fatalf("equal successor changed reservations: before=%s after=%s", charged, got)
	}
	nextManifest, err := jailer.ReadManifest(stateDir, next)
	if err != nil {
		t.Fatal(err)
	}
	if nextManifest.CIDR != manifest.CIDR {
		t.Fatalf("released network not reused: old=%s new=%s", manifest.CIDR, nextManifest.CIDR)
	}
	if status, body := second.apiDelete(t, "/vms/"+next+"?force=true"); status != 200 {
		t.Fatalf("delete successor: status=%d body=%v", status, body)
	}
	t.Logf("restart free=%d MiB scratch=%d MiB request=%d MiB; delete admitted equal successor and reused %s without restart", allocated.StateDiskFreeMiB, scratch, requestedDisk, manifest.CIDR)
}
