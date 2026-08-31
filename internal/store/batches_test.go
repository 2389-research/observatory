// ABOUTME: Tests for batch VM creation: atomic_reservation, best_effort,
// ABOUTME: idempotent replay (AT-015), and conflict detection.
package store_test

import (
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/2389-research/observatory-v2/internal/store"
)

var batchVMCounter atomic.Int64

// batchVMID returns a unique VM ID for batch test members.
func batchVMID() string {
	n := batchVMCounter.Add(1)
	return fmt.Sprintf("batchvm-%012d-0000-0000-0000-000000000000", n)
}

// batchMember returns a BatchMemberInput with a unique VMID.
func batchMember(name string) store.BatchMemberInput {
	return store.BatchMemberInput{
		Name:             name,
		VMID:             batchVMID(),
		TemplateID:       "tmpl-test",
		TemplateDigest:   "sha256:aabbcc0011",
		VCPUCount:        2,
		MemoryMiB:        1024,
		RootDiskMiB:      4096,
		WorkspaceDiskMiB: 8192,
		MemoryTotalMiB:   2048,
		NetworkProfile:   "transport",
		NetworkPolicyID:  "test-policy",
	}
}

func admitAlwaysOK(_ store.ReservationTotals) error { return nil }

func TestBatchAtomicRefusalLeavesNoVMs(t *testing.T) {
	s := openStore(t)
	ctx := t.Context()

	refusal := &store.AdmissionRefusal{Cause: "insufficient_capacity", Message: "no room"}

	result, err := s.CreateVMBatch(ctx, store.CreateVMBatchInput{
		Owner:           "local_operator",
		RequestHash:     "hash-atomic-refused",
		ReservationMode: "atomic_reservation",
		OnFailure:       "keep_successful",
		Members:         []store.BatchMemberInput{batchMember("vm-a"), batchMember("vm-b")},
		AdmitBatch:      func(_ store.ReservationTotals) error { return refusal },
	})
	if err != nil {
		t.Fatalf("CreateVMBatch: %v", err)
	}

	// Batch-level op must be failed with the refusal cause.
	if result.BatchOp == nil || result.BatchOp.State != "failed" {
		t.Fatalf("BatchOp.State = %q, want failed", result.BatchOp.State)
	}
	if result.BatchOp.ErrorCause == nil || *result.BatchOp.ErrorCause != "insufficient_capacity" {
		t.Errorf("BatchOp.ErrorCause = %v, want insufficient_capacity", result.BatchOp.ErrorCause)
	}

	// Every member carries the refusal; no VM or operation rows on members.
	for _, m := range result.Members {
		if m.VM != nil || m.Operation != nil {
			t.Errorf("member %d: vm/op should be nil on atomic refusal", m.Position)
		}
		if m.RefusalCause == nil || *m.RefusalCause != "insufficient_capacity" {
			t.Errorf("member %d: RefusalCause = %v, want insufficient_capacity", m.Position, m.RefusalCause)
		}
	}

	// Zero VM rows; zero reservations.
	vms, _ := s.ListVMs(ctx, store.VMQuery{Limit: 100})
	if len(vms) != 0 {
		t.Errorf("vm rows after atomic refusal = %d, want 0", len(vms))
	}
	totals, _ := s.ReservationTotals(ctx)
	if totals.ActiveVMs != 0 {
		t.Errorf("reservations after atomic refusal: active = %d, want 0", totals.ActiveVMs)
	}
}

func TestBatchAtomicAdmitCreatesAllMembers(t *testing.T) {
	s := openStore(t)
	ctx := t.Context()

	result, err := s.CreateVMBatch(ctx, store.CreateVMBatchInput{
		Owner:           "local_operator",
		RequestHash:     "hash-atomic-admit",
		ReservationMode: "atomic_reservation",
		OnFailure:       "keep_successful",
		Members:         []store.BatchMemberInput{batchMember("vm-1"), batchMember("vm-2")},
		AdmitBatch:      admitAlwaysOK,
	})
	if err != nil {
		t.Fatalf("CreateVMBatch: %v", err)
	}
	if result.BatchOp.State != "running" {
		t.Errorf("BatchOp.State = %q, want running", result.BatchOp.State)
	}
	for i, m := range result.Members {
		if m.VM == nil {
			t.Errorf("member %d: VM nil after admission", i)
		}
		if m.Operation == nil {
			t.Errorf("member %d: Operation nil after admission", i)
		}
		if m.RefusalCause != nil {
			t.Errorf("member %d: unexpected refusal %q", i, *m.RefusalCause)
		}
		if m.VM.ObservedState != "provisioning" {
			t.Errorf("member %d: ObservedState = %q, want provisioning", i, m.VM.ObservedState)
		}
	}
	vms, _ := s.ListVMs(ctx, store.VMQuery{Limit: 10})
	if len(vms) != 2 {
		t.Errorf("vm rows = %d, want 2", len(vms))
	}
}

func TestBatchBestEffortMiddleMemberRefused(t *testing.T) {
	s := openStore(t)
	ctx := t.Context()

	// Refuse exactly the second call (member at position 1).
	callN := 0
	admitMember := func(_ store.ReservationTotals, _ int64, _ int, _ int64) error {
		callN++
		if callN == 2 {
			return &store.AdmissionRefusal{Cause: "insufficient_capacity", Message: "refused second"}
		}
		return nil
	}

	result, err := s.CreateVMBatch(ctx, store.CreateVMBatchInput{
		Owner:           "local_operator",
		RequestHash:     "hash-best-effort-partial",
		ReservationMode: "best_effort",
		OnFailure:       "keep_successful",
		Members: []store.BatchMemberInput{
			batchMember("vm-first"),
			batchMember("vm-refused"),
			batchMember("vm-third"),
		},
		AdmitMember: admitMember,
	})
	if err != nil {
		t.Fatalf("CreateVMBatch: %v", err)
	}
	// Not all refused → batch op is running.
	if result.BatchOp.State != "running" {
		t.Errorf("BatchOp.State = %q, want running (partial success)", result.BatchOp.State)
	}
	if result.Members[0].VM == nil {
		t.Error("member 0 (first) should be admitted")
	}
	if result.Members[1].VM != nil || result.Members[1].RefusalCause == nil {
		t.Errorf("member 1: expected refusal, got vm=%v, cause=%v", result.Members[1].VM, result.Members[1].RefusalCause)
	}
	if result.Members[2].VM == nil {
		t.Error("member 2 (third) should be admitted")
	}
	// Two VMs in the store.
	vms, _ := s.ListVMs(ctx, store.VMQuery{Limit: 10})
	if len(vms) != 2 {
		t.Errorf("vm rows = %d, want 2", len(vms))
	}
}

func TestBatchBestEffortAllRefusedFailsOp(t *testing.T) {
	s := openStore(t)
	ctx := t.Context()

	refusal := &store.AdmissionRefusal{Cause: "insufficient_capacity", Message: "no room"}
	result, err := s.CreateVMBatch(ctx, store.CreateVMBatchInput{
		Owner:           "local_operator",
		RequestHash:     "hash-best-effort-all-refused",
		ReservationMode: "best_effort",
		OnFailure:       "keep_successful",
		Members:         []store.BatchMemberInput{batchMember("a"), batchMember("b")},
		AdmitMember:     func(_ store.ReservationTotals, _ int64, _ int, _ int64) error { return refusal },
	})
	if err != nil {
		t.Fatalf("CreateVMBatch: %v", err)
	}
	if result.BatchOp.State != "failed" {
		t.Errorf("BatchOp.State = %q, want failed (all refused)", result.BatchOp.State)
	}
}

func TestBatchIdempotentReplayAT015(t *testing.T) {
	s := openStore(t)
	ctx := t.Context()

	key := "replay-key-1"
	admitCallCount := 0

	in := store.CreateVMBatchInput{
		Owner:           "local_operator",
		IdempotencyKey:  &key,
		RequestHash:     "hash-idem-ok",
		ReservationMode: "atomic_reservation",
		OnFailure:       "keep_successful",
		Members:         []store.BatchMemberInput{batchMember("idm-vm-1"), batchMember("idm-vm-2")},
		AdmitBatch: func(_ store.ReservationTotals) error {
			admitCallCount++
			return nil
		},
	}

	first, err := s.CreateVMBatch(ctx, in)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if admitCallCount != 1 {
		t.Errorf("admit called %d times on first call, want 1", admitCallCount)
	}
	admitCallCount = 0

	// Replay: same key and hash. Members field is ignored on replay (matched on hash).
	second, err := s.CreateVMBatch(ctx, in)
	if err != nil {
		t.Fatalf("replay call: %v", err)
	}
	if admitCallCount != 0 {
		t.Errorf("admit called %d times on replay, want 0 (must not re-run admission)", admitCallCount)
	}
	if !second.IsReplay {
		t.Error("second result should be marked IsReplay")
	}
	if second.Batch.BatchID != first.Batch.BatchID {
		t.Errorf("replay batch_id %d != original %d", second.Batch.BatchID, first.Batch.BatchID)
	}
	if second.BatchOp.OperationID != first.BatchOp.OperationID {
		t.Errorf("replay op_id %d != original %d", second.BatchOp.OperationID, first.BatchOp.OperationID)
	}
	// Same member VM IDs.
	for i := range first.Members {
		if first.Members[i].VM == nil || second.Members[i].VM == nil {
			continue
		}
		if second.Members[i].VM.VMID != first.Members[i].VM.VMID {
			t.Errorf("member %d: replay vmid %q != original %q",
				i, second.Members[i].VM.VMID, first.Members[i].VM.VMID)
		}
	}
	// No new VM rows on replay.
	vms, _ := s.ListVMs(ctx, store.VMQuery{Limit: 100})
	if len(vms) != 2 {
		t.Errorf("vm rows after replay = %d, want 2 (no new rows)", len(vms))
	}
}

func TestBatchIdempotencyConflict(t *testing.T) {
	s := openStore(t)
	ctx := t.Context()

	key := "conflict-key"
	in := store.CreateVMBatchInput{
		Owner:           "local_operator",
		IdempotencyKey:  &key,
		RequestHash:     "hash-conflict-1",
		ReservationMode: "atomic_reservation",
		OnFailure:       "keep_successful",
		Members:         []store.BatchMemberInput{batchMember("vm-x")},
		AdmitBatch:      admitAlwaysOK,
	}
	if _, err := s.CreateVMBatch(ctx, in); err != nil {
		t.Fatalf("first call: %v", err)
	}

	in.RequestHash = "hash-DIFFERENT"
	_, err := s.CreateVMBatch(ctx, in)
	if err != store.ErrIdempotencyConflict {
		t.Errorf("error = %v, want ErrIdempotencyConflict", err)
	}
}

func TestGetVMBatch(t *testing.T) {
	s := openStore(t)
	ctx := t.Context()

	result, err := s.CreateVMBatch(ctx, store.CreateVMBatchInput{
		Owner:           "local_operator",
		RequestHash:     "hash-get",
		ReservationMode: "atomic_reservation",
		OnFailure:       "keep_successful",
		Members:         []store.BatchMemberInput{batchMember("get-vm-1"), batchMember("get-vm-2")},
		AdmitBatch:      admitAlwaysOK,
	})
	if err != nil {
		t.Fatalf("CreateVMBatch: %v", err)
	}

	got, err := s.GetVMBatch(ctx, result.Batch.BatchID)
	if err != nil {
		t.Fatalf("GetVMBatch: %v", err)
	}
	if got.Batch.BatchID != result.Batch.BatchID {
		t.Errorf("batch_id mismatch: got %d, want %d", got.Batch.BatchID, result.Batch.BatchID)
	}
	if len(got.Members) != 2 {
		t.Errorf("members = %d, want 2", len(got.Members))
	}
	// Members should have VM and operation linked.
	for i, m := range got.Members {
		if m.VM == nil {
			t.Errorf("member %d: VM nil on GET after create", i)
		}
	}
}

func TestGetVMBatchUnknown(t *testing.T) {
	s := openStore(t)
	ctx := t.Context()

	_, err := s.GetVMBatch(ctx, 99999)
	if err != store.ErrBatchUnknown {
		t.Errorf("error = %v, want ErrBatchUnknown", err)
	}
}

// Member rows must carry the batch's owner, not a hardcoded principal — P5
// replaces the local-operator identity and the batch path must follow.
func TestBatchMembersCarryOwner(t *testing.T) {
	s := openStore(t)
	result, err := s.CreateVMBatch(t.Context(), store.CreateVMBatchInput{
		Owner:           "someone-else",
		RequestHash:     "hash-owner-check",
		ReservationMode: "atomic_reservation",
		OnFailure:       "keep_successful",
		Members:         []store.BatchMemberInput{batchMember("owned-vm")},
		AdmitBatch:      admitAlwaysOK,
	})
	if err != nil {
		t.Fatal(err)
	}
	m := result.Members[0]
	if m.VM.Owner != "someone-else" {
		t.Errorf("member vm owner = %q, want someone-else", m.VM.Owner)
	}
	if m.Operation.Owner != "someone-else" {
		t.Errorf("member op owner = %q, want someone-else", m.Operation.Owner)
	}
}
