// ABOUTME: Durable operation identity, replay, and restart uncertainty tests.
// ABOUTME: Exercises the real dispatcher, durable receipts, and filesystem side effects.
package privd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMutationReceiptReplayAndRestart(t *testing.T) {
	s, ops, stage := startVMFixture(t)
	allocate(t, s, "vm-rollback")
	raw, _ := json.Marshal(StartVMReq{VMID: "vm-rollback", UID: 30000, GID: 30000, CID: 3, StageDir: stage})
	req := Request{V: ProtoVersion, Verb: "start_vm", OpID: "start-1", Payload: raw}
	first := s.dispatch(req)
	if !first.OK {
		t.Fatalf("start: %+v", first)
	}
	if second := s.dispatch(req); !second.OK {
		t.Fatalf("replay: %+v", second)
	}
	if len(ops.startCalls) != 1 {
		t.Fatalf("duplicate effects: %v", ops.startCalls)
	}
	restarted := NewServer(s.cfg)
	if replay := restarted.dispatch(req); !replay.OK {
		t.Fatalf("restart replay: %+v", replay)
	}
	outcome := restarted.queryOperation("start-1")
	if outcome.State != "succeeded" {
		t.Fatalf("outcome: %+v", outcome)
	}
	req.Payload = json.RawMessage(`{"vm_id":"different"}`)
	if mismatch := restarted.dispatch(req); mismatch.Cause != "invalid_state" {
		t.Fatalf("identity reused: %+v", mismatch)
	}
}

func TestMutationRequiresIdentity(t *testing.T) {
	s, _, _ := startVMFixture(t)
	if r := s.dispatch(Request{V: ProtoVersion, Verb: "signal_vm", Payload: json.RawMessage(`{"vm_id":"vm-rollback","kind":"kill"}`)}); r.Cause != "bad_request" {
		t.Fatalf("missing identity: %+v", r)
	}
}

func TestInterruptedMutationRetainsOwnership(t *testing.T) {
	s, _, _ := startVMFixture(t)
	raw := json.RawMessage(`{"vm_id":"vm-other","cidr":"10.0.1.0/30"}`)
	record := operationRecord{Request: Request{V: ProtoVersion, Verb: "allocate_network", OpID: "interrupted", Payload: raw}, State: "pending"}
	if err := s.saveOperation(record); err != nil {
		t.Fatal(err)
	}
	restarted := NewServer(s.cfg)
	if got := restarted.queryOperation("interrupted"); got.State != "unknown" {
		t.Fatalf("restart uncertainty: %+v", got)
	}
	req := Request{V: ProtoVersion, Verb: "allocate_network", OpID: "replacement", Payload: raw}
	if got := restarted.dispatch(req); got.Cause != "outcome_unknown" {
		t.Fatalf("reclaimed unknown ownership: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(s.cfg.LedgerDir, ".operations", "interrupted.json")); err != nil {
		t.Fatal(err)
	}
}

type cancelledStartOps struct{ *stubOps }

func (o *cancelledStartOps) StartVMContext(ctx context.Context, _ *VMEntry, _ StartVMReq) (StartVMResp, error) {
	<-ctx.Done()
	return StartVMResp{}, ctx.Err()
}
func TestStartExecutionBudget(t *testing.T) {
	s, ops, stage := startVMFixture(t)
	allocate(t, s, "vm-rollback")
	s.cfg.Ops = &cancelledStartOps{ops}
	s.cfg.ExecutionTimeout = 10 * time.Millisecond
	raw, _ := json.Marshal(StartVMReq{VMID: "vm-rollback", UID: 30000, GID: 30000, CID: 3, StageDir: stage})
	result := make(chan Response, 1)
	go func() { result <- s.dispatch(Request{V: ProtoVersion, Verb: "start_vm", OpID: "budget", Payload: raw}) }()
	select {
	case got := <-result:
		if got.OK || !strings.Contains(got.Message, "deadline exceeded") {
			t.Fatalf("budget: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("execution budget did not reach backend")
	}
}

func TestNetworkLeaseInventory(t *testing.T) {
	s, _, _ := startVMFixture(t)
	allocate(t, s, "vm-rollback")
	result := s.dispatch(Request{V: ProtoVersion, Verb: "network_leases"})
	var leases map[string]string
	if !result.OK || json.Unmarshal(result.Payload, &leases) != nil || leases["vm-rollback"] != "10.201.0.0/30" {
		t.Fatalf("leases: %+v", result)
	}
}

func TestRestartRecoversCommittedStartBeforeReceipt(t *testing.T) {
	s, _, stage := startVMFixture(t)
	allocate(t, s, "vm-rollback")
	raw, _ := json.Marshal(StartVMReq{VMID: "vm-rollback", UID: 30000, GID: 30000, CID: 3, StageDir: stage})
	req := Request{V: ProtoVersion, Verb: "start_vm", OpID: "commit-window", Payload: raw}
	if got := s.dispatch(req); !got.OK {
		t.Fatalf("start: %+v", got)
	}
	if err := s.saveOperation(operationRecord{Request: req, State: "pending"}); err != nil {
		t.Fatal(err)
	}
	restarted := NewServer(s.cfg)
	if got := restarted.queryOperation(req.OpID); got.State != "succeeded" || got.Response == nil {
		t.Fatalf("commit witness ignored: %+v", got)
	}
}

func TestCancelledStagingReadStopsBeforeBytes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	source := strings.NewReader("boot bytes")
	_, err := io.ReadAll(contextReader{ctx: ctx, reader: source})
	if !errors.Is(err, context.Canceled) || source.Len() != len("boot bytes") {
		t.Fatalf("cancelled read consumed data: %v", err)
	}
}

type failedNetworkOps struct{ *stubOps }

func (o failedNetworkOps) AllocateNetwork(VMEntry, AllocateNetworkReq) error {
	return errors.New("allocation interrupted")
}
func (o failedNetworkOps) ReleaseNetwork(VMEntry) error { return errors.New("network remains") }
func TestNetworkRollbackFailureKeepsUnknownClaim(t *testing.T) {
	s, ops, _ := startVMFixture(t)
	s.cfg.Ops = failedNetworkOps{ops}
	req := Request{V: ProtoVersion, Verb: "allocate_network", OpID: "network-unknown", Payload: json.RawMessage(`{"vm_id":"vm-net","cidr":"10.0.0.0/30"}`)}
	if got := s.dispatch(req); got.Cause != "outcome_unknown" {
		t.Fatalf("unproved teardown reported failure: %+v", got)
	}
	if got := s.queryOperation(req.OpID); got.State != "unknown" {
		t.Fatalf("ownership lost: %+v", got)
	}
}

func TestRestartRecoversNetworkLedgerCommit(t *testing.T) {
	s, _, _ := startVMFixture(t)
	req := Request{V: ProtoVersion, Verb: "allocate_network", OpID: "network-commit", Payload: json.RawMessage(`{"vm_id":"vm-net","cidr":"10.0.0.0/30"}`)}
	if got := s.dispatch(req); !got.OK {
		t.Fatalf("allocate: %+v", got)
	}
	if err := s.saveOperation(operationRecord{Request: req, State: "unknown"}); err != nil {
		t.Fatal(err)
	}
	restarted := NewServer(s.cfg)
	if got := restarted.queryOperation(req.OpID); got.State != "succeeded" {
		t.Fatalf("durable network commit not recovered: %+v", got)
	}
}

func TestRestartDoesNotRecoverNetworkCommitWithoutHostGroup(t *testing.T) {
	dir := t.TempDir()
	s := NewServer(ServerCfg{LedgerDir: dir})
	req := Request{V: ProtoVersion, Verb: "allocate_network", OpID: "missing-group", Payload: json.RawMessage(`{"vm_id":"vm-net","cidr":"10.0.0.0/30"}`)}
	if err := s.ledger.put(VMEntry{VMID: "vm-net", NetCIDR: "10.0.0.0/30", NetworkOpID: req.OpID, NetworkComplete: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.saveOperation(operationRecord{Request: req, State: "pending"}); err != nil {
		t.Fatal(err)
	}
	restarted := NewServer(ServerCfg{LedgerDir: dir})
	if got := restarted.queryOperation(req.OpID); got.State != "unknown" || got.Response != nil {
		t.Fatalf("missing group became a commit witness: %+v", got)
	}
}

type blockedFailureOps struct {
	*stubOps
	entered, finish chan struct{}
}

func (o blockedFailureOps) StartVM(entry *VMEntry, req StartVMReq) (StartVMResp, error) {
	if req.VMID == "vm-rollback" {
		close(o.entered)
		<-o.finish
	}
	return o.stubOps.StartVM(entry, req)
}
func TestQueuedClaimCannotPassAnUnknownPredecessor(t *testing.T) {
	s, base, stage := startVMFixture(t)
	allocate(t, s, "vm-rollback")
	netreq := Request{V: ProtoVersion, Verb: "allocate_network", OpID: "net-next", Payload: json.RawMessage(`{"vm_id":"vm-next","cidr":"10.0.1.0/30"}`)}
	if got := s.dispatch(netreq); !got.OK {
		t.Fatal(got)
	}
	base.startErr = errors.New("launch failed")
	base.abortErr = errors.New("process remains")
	ops := &blockedFailureOps{stubOps: base, entered: make(chan struct{}), finish: make(chan struct{})}
	s.cfg.Ops = ops
	request := func(vm, id string) Request {
		raw, _ := json.Marshal(StartVMReq{VMID: vm, UID: 30000, GID: 30000, CID: 3, StageDir: filepath.Join(filepath.Dir(stage), vm)})
		return Request{V: ProtoVersion, Verb: "start_vm", OpID: id, Payload: raw}
	}
	finished := make(chan Response, 2)
	go func() { finished <- s.dispatch(request("vm-rollback", "first")) }()
	<-ops.entered
	go func() { finished <- s.dispatch(request("vm-next", "second")) }()
	deadline := time.Now().Add(time.Second)
	for s.queryOperation("second").State != "pending" {
		if time.Now().After(deadline) {
			t.Fatal("second request not admitted")
		}
		time.Sleep(time.Millisecond)
	}
	close(ops.finish)
	<-finished
	<-finished
	if len(base.startCalls) != 1 {
		t.Fatalf("queued claim reused unsettled UID/CID: %v", base.startCalls)
	}
}
