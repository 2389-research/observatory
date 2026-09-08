// ABOUTME: Interrupts the real helper transport while a live VM is being deleted.
// ABOUTME: Proves timer-driven cleanup retains ownership and recovers without restart.

//go:build linux

package integration_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/privd"
	"github.com/2389-research/observatory/internal/store"
)

func TestKataAutomaticCleanupGate(t *testing.T) {
	if os.Getenv("VMOBS_FIXTURE") != "1" {
		t.Skip("set VMOBS_FIXTURE=1 inside scripts/vmobs-gate")
	}
	gateSkipChecks(t)
	m1aSkipChecks(t)
	socket := filepath.Join(t.TempDir(), "helper.sock")
	if err := os.Symlink(m1aPrivdSock, socket); err != nil {
		t.Fatal(err)
	}
	d := startDaemon(t, findRepoRoot(t), buildBinary(t, "github.com/2389-research/observatory/cmd/vmobsd"),
		buildBinary(t, "github.com/2389-research/observatory/cmd/vmobs-runner"), "kata-auto-cleanup", func(o *daemonOptions) { o.privdSocket = socket })
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	id := d.createVM(t, "kata-auto-cleanup")
	d.waitVMState(ctx, t, id, "running")
	st, err := store.Open(filepath.Join(d.stateDir, "vmobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	client := &privd.Client{SocketPath: m1aPrivdSock}
	leases, err := client.NetworkLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := leases[id]; !ok {
		t.Fatal("running guest has no real lease")
	}
	if err := os.Remove(socket); err != nil {
		t.Fatal(err)
	}
	// Restore even on assertion failure, before the daemon helper tears down guests.
	restored := false
	defer func() {
		if !restored {
			if err := os.Symlink(m1aPrivdSock, socket); err != nil {
				t.Error(err)
			}
		}
	}()
	status, body := d.apiDelete(t, "/vms/"+id+"?force=true")
	if status < 400 {
		t.Fatalf("unavailable helper cleanup reported success: %d %v", status, body)
	}
	// Leave the failure in place across a production 30-second retry interval.
	time.Sleep(35 * time.Second)
	vm, err := st.GetVM(ctx, id)
	if err != nil || vm.ObservedState != "stopping" {
		t.Fatalf("unproved cleanup changed VM: %+v %v", vm, err)
	}
	held, err := st.GetReservation(ctx, id)
	if err != nil || held.Released || held.ComputeReleased {
		t.Fatalf("unproved cleanup released reservation: %+v %v", held, err)
	}
	leases, err = client.NetworkLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := leases[id]; !ok {
		t.Fatal("failed cleanup lost real network lease")
	}
	if err := os.Symlink(m1aPrivdSock, socket); err != nil {
		t.Fatal(err)
	}
	restored = true
	// No second DELETE or restart: only the production timer may finish this row.
	d.waitVMState(ctx, t, id, "deleted")
	held, err = st.GetReservation(ctx, id)
	if err != nil || !held.Released {
		t.Fatalf("proved cleanup retained reservation: %+v %v", held, err)
	}
	leases, err = client.NetworkLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := leases[id]; ok {
		t.Fatal("automatic cleanup retained network lease")
	}
	if _, err := os.Lstat(filepath.Join(m1aJailBase, "firecracker", id)); !os.IsNotExist(err) {
		t.Fatalf("automatic cleanup retained jail: %v", err)
	}
	t.Log("real helper outage retained compute and network; restoring transport let the timer finish deletion without restart")
}
