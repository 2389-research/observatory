// ABOUTME: Real Unix socket tests of disconnect, delayed replies, and duplicate mutation identity.
// ABOUTME: The backend writes real jail files; production KVM effects belong to the appliance gate.
//go:build linux

package privd

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type delayedStartOps struct {
	*stubOps
	entered chan struct{}
	finish  chan struct{}
}

func (o *delayedStartOps) StartVM(entry *VMEntry, req StartVMReq) (StartVMResp, error) {
	close(o.entered)
	<-o.finish
	return o.stubOps.StartVM(entry, req)
}

func serveOutcomeSocket(t *testing.T, s *Server) *Client {
	t.Helper()
	// /tmp avoids Unix socket path limits in nested Go temporary directories.
	dir, err := os.MkdirTemp("/tmp", "privd-outcome-")
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() { stopped <- s.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-stopped; err != nil {
			t.Error(err)
		}
		_ = os.RemoveAll(dir)
	})
	return &Client{SocketPath: socket}
}

func TestSocketLostReplyKeepsQueryableStart(t *testing.T) {
	for _, disconnect := range []bool{false, true} {
		t.Run(map[bool]string{false: "timeout", true: "disconnect"}[disconnect], func(t *testing.T) {
			s, base, stage := startVMFixture(t)
			allocate(t, s, "vm-rollback")
			ops := &delayedStartOps{stubOps: base, entered: make(chan struct{}), finish: make(chan struct{})}
			s.cfg.Ops = ops
			s.cfg.FramingTimeout = 10 * time.Millisecond
			client := serveOutcomeSocket(t, s)
			request := StartVMReq{VMID: "vm-rollback", UID: 30000, GID: 30000, CID: 3, StageDir: stage}
			if disconnect {
				conn, err := net.Dial("unix", client.SocketPath)
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := json.Marshal(request)
				if err := WriteMsg(conn, Request{V: ProtoVersion, Verb: "start_vm", OpID: "lost", Payload: raw}); err != nil {
					t.Fatal(err)
				}
				_ = conn.Close()
			} else {
				ctx, cancel := context.WithTimeout(WithOperationID(context.Background(), "lost"), 30*time.Millisecond)
				defer cancel()
				_, err := client.StartVM(ctx, request)
				var unknown *UnknownOutcomeError
				if !errors.As(err, &unknown) || unknown.OpID != "lost" {
					t.Fatalf("timeout loses identity: %v", err)
				}
			}
			select {
			case <-ops.entered:
			case <-time.After(time.Second):
				t.Fatal("start not received")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			outcome, err := client.QueryOperation(ctx, "lost")
			if err != nil || outcome.State != "pending" {
				t.Fatalf("pending query blocked: %+v %v", outcome, err)
			}
			_, err = client.StartVM(WithOperationID(ctx, "lost"), request)
			var unknown *UnknownOutcomeError
			if !errors.As(err, &unknown) {
				t.Fatalf("pending duplicate: %v", err)
			}
			close(ops.finish)
			for {
				outcome, err = client.QueryOperation(ctx, "lost")
				if err != nil {
					t.Fatal(err)
				}
				if outcome.State == "succeeded" {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("start did not settle")
				case <-time.After(time.Millisecond):
				}
			}
			if _, err := client.StartVM(WithOperationID(ctx, "lost"), request); err != nil {
				t.Fatalf("replay: %v", err)
			}
			if len(base.startCalls) != 1 {
				t.Fatalf("duplicate starts: %v", base.startCalls)
			}
			if _, err := os.Stat(filepath.Join(base.jailBase, "firecracker", "vm-rollback", "root", "rootfs.ext4")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAbortRefusesUncertainPIDFile(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "firecracker", "vm-uncertain", "root")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "firecracker.pid"), []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	ops := NewRealOps(RealOpsCfg{JailBase: dir})
	if err := ops.AbortStartVM(VMEntry{VMID: "vm-uncertain"}); err == nil {
		t.Fatal("uncertain pid reported gone")
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("uncertain ownership tree removed: %v", err)
	}
}

func TestAbortRetainsLaunchWithoutPIDWitness(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "firecracker", "vm-no-pid", "root")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	ops := NewRealOps(RealOpsCfg{JailBase: dir})
	if err := ops.AbortStartVM(VMEntry{VMID: "vm-no-pid", StartAttempted: true}); err == nil {
		t.Fatal("missing pid after exec reported gone")
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("uncertain tree removed: %v", err)
	}
}

func TestSocketExecutionOutlivesFramingDeadline(t *testing.T) {
	s, base, stage := startVMFixture(t)
	allocate(t, s, "vm-rollback")
	ops := &delayedStartOps{stubOps: base, entered: make(chan struct{}), finish: make(chan struct{})}
	s.cfg.Ops = ops
	s.cfg.FramingTimeout = 10 * time.Millisecond
	client := serveOutcomeSocket(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := client.StartVM(ctx, StartVMReq{VMID: "vm-rollback", UID: 30000, GID: 30000, CID: 3, StageDir: stage})
		result <- err
	}()
	select {
	case <-ops.entered:
	case <-ctx.Done():
		t.Fatal("start not received")
	}
	time.Sleep(30 * time.Millisecond)
	close(ops.finish)
	if err := <-result; err != nil {
		t.Fatalf("execution inherited framing deadline: %v", err)
	}
}

func TestStagedExecFailurePreservesOnlyStartedProcessUncertainty(t *testing.T) {
	for _, started := range []bool{false, true} {
		t.Run(map[bool]string{false: "executable-absent", true: "process-started"}[started], func(t *testing.T) {
			dir := t.TempDir()
			stage := filepath.Join(dir, "stage", "vm-exec")
			if err := os.MkdirAll(stage, 0o750); err != nil {
				t.Fatal(err)
			}
			executable := filepath.Join(dir, "missing-jailer")
			if started {
				executable = "/bin/false"
			}
			ops := NewRealOps(RealOpsCfg{StageRoot: filepath.Dir(stage), JailBase: filepath.Join(dir, "jail"), JailerPath: executable})
			entry := VMEntry{VMID: "vm-exec", UID: os.Getuid(), GID: os.Getgid(), CID: 3}
			_, err := startStagedForTest(t, ops, &entry, StartVMReq{VMID: entry.VMID, UID: entry.UID, GID: entry.GID, CID: entry.CID, StageDir: stage})
			if err == nil {
				t.Fatal("exec unexpectedly succeeded")
			}
			if !started && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("did not reach missing executable: %v", err)
			}
			if entry.StartAttempted != started {
				t.Fatalf("StartAttempted=%v, actual process started=%v: %v", entry.StartAttempted, started, err)
			}
			abortErr := ops.AbortStartVM(entry)
			if started {
				if abortErr == nil {
					t.Fatal("started process without PID witness reported settled")
				}
			} else {
				if abortErr != nil {
					t.Fatalf("no process started, cleanup must be provable: %v", abortErr)
				}
				if _, err := os.Stat(filepath.Join(dir, "jail", "firecracker", entry.VMID)); !os.IsNotExist(err) {
					t.Fatalf("known pre-exec debris remains: %v", err)
				}
			}
		})
	}
}
