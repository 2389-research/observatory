// ABOUTME: Drops a real privileged start response after Firecracker has launched.
// ABOUTME: Verifies queryable outcome, exact replay and full cleanup through the API.

//go:build linux

package integration_test

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/privd"
	"github.com/2389-research/observatory/internal/store"
)

type droppedStartReply struct {
	request  privd.Request
	response privd.Response
}

func dropFirstStartReply(t *testing.T, hold <-chan struct{}) (string, <-chan droppedStartReply) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "kata-privd-")
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "s")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var dropped atomic.Bool
	var workers sync.WaitGroup
	replies := make(chan droppedStartReply, 1)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer client.Close()
				_ = client.SetDeadline(time.Now().Add(2 * time.Minute))
				upstream, err := net.DialTimeout("unix", m1aPrivdSock, 5*time.Second)
				if err != nil {
					t.Errorf("privd proxy dial: %v", err)
					return
				}
				defer upstream.Close()
				_ = upstream.SetDeadline(time.Now().Add(2 * time.Minute))
				var request privd.Request
				if err := privd.ReadMsg(client, &request); err != nil {
					return
				}
				if err := privd.WriteMsg(upstream, request); err != nil {
					t.Errorf("privd proxy request: %v", err)
					return
				}
				var response privd.Response
				if err := privd.ReadMsg(upstream, &response); err != nil {
					t.Errorf("privd proxy response: %v", err)
					return
				}
				if request.Verb == "start_vm" && dropped.CompareAndSwap(false, true) {
					replies <- droppedStartReply{request, response}
					if hold != nil {
						<-hold
					}
					return
				}
				_ = privd.WriteMsg(client, response)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-stopped
		workers.Wait()
		_ = os.RemoveAll(dir)
	})
	return socket, replies
}

func TestKataLostStartReplyGate(t *testing.T) {
	if os.Getenv("VMOBS_FIXTURE") != "1" {
		t.Skip("set VMOBS_FIXTURE=1 inside scripts/vmobs-gate")
	}
	gateSkipChecks(t)
	m1aSkipChecks(t)
	socket, replies := dropFirstStartReply(t, nil)
	d := startDaemon(t, findRepoRoot(t),
		buildBinary(t, "github.com/2389-research/observatory/cmd/vmobsd"),
		buildBinary(t, "github.com/2389-research/observatory/cmd/vmobs-runner"),
		"kata-lost-start-reply", func(o *daemonOptions) { o.privdSocket = socket })
	id := d.createVM(t, "kata-lost-reply")
	var dropped droppedStartReply
	select {
	case dropped = <-replies:
	case <-time.After(2 * time.Minute):
		t.Fatal("no real start response reached proxy")
	}
	if !dropped.response.OK || dropped.request.OpID == "" {
		t.Fatalf("fault did not lose a successful identified start: %+v", dropped.response)
	}
	client := &privd.Client{SocketPath: m1aPrivdSock}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	outcome, err := client.QueryOperation(ctx, dropped.request.OpID)
	if err != nil || outcome.State != "succeeded" {
		t.Fatalf("lost successful response not queryable: %+v %v", outcome, err)
	}
	// The launch attempt reports its lost response; cleanup must still resolve
	// the actual committed start before releasing compute and disk ownership.
	d.waitVMState(ctx, t, id, "failed")
	if status, body := d.apiDelete(t, "/vms/"+id+"?force=true"); status != 200 {
		t.Fatalf("delete after lost response: status=%d body=%v", status, body)
	}
	var request privd.StartVMReq
	if err := json.Unmarshal(dropped.request.Payload, &request); err != nil {
		t.Fatal(err)
	}
	if _, err := client.StartVM(privd.WithOperationID(ctx, dropped.request.OpID), request); err != nil {
		t.Fatalf("exact replay lost historical result: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(m1aJailBase, "firecracker", id)); !os.IsNotExist(err) {
		t.Fatalf("replay recreated released jail: %v", err)
	}
	leases, err := client.NetworkLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, held := leases[id]; held {
		t.Fatal("cleanup retained privileged network claim")
	}
	next := d.createVM(t, "kata-after-lost-reply")
	d.waitVMState(ctx, t, next, "running")
	if status, body := d.apiDelete(t, "/vms/"+next+"?force=true"); status != 200 {
		t.Fatalf("delete successor: status=%d body=%v", status, body)
	}
	t.Log("real start reply lost; outcome queried, cleanup proved, replay caused no new launch, successor ran")
}

func TestKataShutdownDuringBatchLaunchGate(t *testing.T) {
	if os.Getenv("VMOBS_FIXTURE") != "1" {
		t.Skip("set VMOBS_FIXTURE=1 inside scripts/vmobs-gate")
	}
	gateSkipChecks(t)
	m1aSkipChecks(t)
	hold := make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(hold) })
	socket, replies := dropFirstStartReply(t, hold)
	repo := findRepoRoot(t)
	d := startDaemon(t, repo,
		buildBinary(t, "github.com/2389-research/observatory/cmd/vmobsd"),
		buildBinary(t, "github.com/2389-research/observatory/cmd/vmobs-runner"),
		"kata-shutdown-batch", func(o *daemonOptions) { o.privdSocket = socket; o.parallelProvisions = 1 })
	member := func(name string) map[string]any {
		return map[string]any{"name": name, "template_id": "standard", "root_disk_mib": gateRootDiskMiB,
			"workspace_disk_mib": gateWorkspaceDiskMiB, "memory_mib": 512, "vcpu_count": 1,
			"run": map[string]any{"goal": "observe shutdown", "success_criteria": map[string]any{"type": "operator_verdict"}, "on_completion": "keep_running"}}
	}
	status, batch := d.apiPost(t, "/vm-batches", map[string]any{"reservation_mode": "atomic_reservation", "on_failure": "keep_successful", "members": []any{member("active"), member("queued")}})
	if status != 201 {
		t.Fatalf("batch: status=%d body=%v", status, batch)
	}
	var ids []string
	for _, raw := range batch["members"].([]any) {
		vm, ok := raw.(map[string]any)["vm"].(map[string]any)
		if !ok {
			t.Fatalf("batch member not admitted: %v", raw)
		}
		id := stringField(vm, "vm_id")
		ids = append(ids, id)
		d.trackVMID(id)
	}
	var reply droppedStartReply
	select {
	case reply = <-replies:
	case <-time.After(2 * time.Minute):
		t.Fatal("no actual KVM start completed")
	}
	if !reply.response.OK {
		t.Fatalf("start did not succeed before shutdown: %+v", reply.response)
	}
	shutdownStarted := time.Now()
	daemonStart := procStartTime(t, d.cmd.Process.Pid)
	if err := d.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	for privd.PIDAlive(d.cmd.Process.Pid, daemonStart) {
		if time.Since(shutdownStarted) > 90*time.Second {
			t.Fatal("daemon process exceeded shutdown budget")
		}
		time.Sleep(20 * time.Millisecond)
	}
	drainElapsed := time.Since(shutdownStarted)
	release.Do(func() { close(hold) })
	st, err := store.Open(filepath.Join(d.stateDir, "vmobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for _, state := range []string{"pending", "running"} {
		ops, err := st.ListOperationsByState(ctx, state)
		if err != nil || len(ops) != 0 {
			t.Fatalf("shutdown left %s operations: %v %v", state, ops, err)
		}
	}
	for _, id := range ids {
		run, err := st.RunForVM(ctx, id)
		if err != nil || run == nil {
			t.Fatalf("run missing: %v %v", run, err)
		}
		if run.Phase == "pending" || run.Phase == "running" || run.Phase == "concluding" {
			t.Fatalf("run not concluded: %+v", run)
		}
	}
	var startReq privd.StartVMReq
	var started privd.StartVMResp
	if err := json.Unmarshal(reply.request.Payload, &startReq); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(reply.response.Payload, &started); err != nil {
		t.Fatal(err)
	}
	if privd.PIDAlive(started.PID, started.StartTime) {
		reservation, err := st.GetReservation(ctx, startReq.VMID)
		if err != nil || reservation == nil || reservation.MemoryTotalMiB == 0 || reservation.ComputeReleased || reservation.Released || reservation.DiskMiB == 0 {
			t.Fatalf("possible live VMM lost reservation: %+v %v", reservation, err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	successor := startDaemon(t, repo,
		buildBinary(t, "github.com/2389-research/observatory/cmd/vmobsd"),
		buildBinary(t, "github.com/2389-research/observatory/cmd/vmobs-runner"),
		"kata-after-shutdown", withStateDir(d.stateDir))
	successor.adoptVMsFrom(d)
	for _, id := range ids {
		if status, body := successor.apiDelete(t, "/vms/"+id+"?force=true"); status != 200 {
			t.Fatalf("cleanup %s: %d %v", id, status, body)
		}
	}
	t.Logf("real active/queued batch shutdown completed in %s; operations and runs concluded, possible effects retained reservations, restart cleanup succeeded", drainElapsed.Round(time.Millisecond))
}
