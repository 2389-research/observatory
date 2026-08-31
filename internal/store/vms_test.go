// ABOUTME: TDD tests for VM registry, operations, and admission reservations.
// ABOUTME: Real SQLite via openStore; no mocks, no shortcuts.
package store_test

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/2389-research/observatory-v2/internal/store"
)

// ptr returns a pointer to v; used to set optional fields inline.
func ptr[T any](v T) *T { return &v }

// mustCreateVM creates a VM with sensible defaults. Admit=nil means always admit.
func mustCreateVM(t *testing.T, st *store.Store, vmID, name string, admit func(store.ReservationTotals) error) (*store.VM, *store.Operation) {
	t.Helper()
	if admit == nil {
		admit = func(store.ReservationTotals) error { return nil }
	}
	vm, op, err := st.CreateVMWithOperation(t.Context(), store.CreateVMInput{
		VMID:             vmID,
		Name:             name,
		Owner:            "test-owner",
		TemplateID:       "tmpl-001",
		TemplateDigest:   "sha256:abc123",
		VCPUCount:        2,
		MemoryMiB:        2048,
		RootDiskMiB:      8192,
		WorkspaceDiskMiB: 10240,
		MemoryTotalMiB:   2048 + 768,
		NetworkProfile:   "transport",
		NetworkPolicyID:  "transport-public-web",
		Labels:           map[string]string{},
		Kind:             "vm.create",
		IdempotencyKey:   nil,
		RequestHash:      strings.Repeat("a", 64),
		Admit:            admit,
	})
	if err != nil {
		t.Fatalf("mustCreateVM %s: %v", vmID, err)
	}
	return vm, op
}

// --- tests ---

func TestVMCreateHappyPath(t *testing.T) {
	st := openStore(t)
	vmID := testUUID(1)

	vm, op, err := st.CreateVMWithOperation(t.Context(), store.CreateVMInput{
		VMID:             vmID,
		Name:             "alpha",
		Owner:            "test-owner",
		TemplateID:       "tmpl-001",
		TemplateDigest:   "sha256:abc",
		VCPUCount:        2,
		MemoryMiB:        2048,
		RootDiskMiB:      8192,
		WorkspaceDiskMiB: 10240,
		MemoryTotalMiB:   2048 + 768,
		NetworkProfile:   "transport",
		NetworkPolicyID:  "transport-public-web",
		Labels:           map[string]string{"env": "test"},
		Kind:             "vm.create",
		IdempotencyKey:   ptr("key-alpha"),
		RequestHash:      strings.Repeat("a", 64),
		Admit:            func(store.ReservationTotals) error { return nil },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vm == nil || op == nil {
		t.Fatal("expected non-nil vm and op")
	}
	if vm.VMID != vmID {
		t.Errorf("vm.VMID = %q, want %q", vm.VMID, vmID)
	}
	if vm.ObservedState != "provisioning" {
		t.Errorf("observed_state = %q, want provisioning", vm.ObservedState)
	}
	if vm.Revision != 1 {
		t.Errorf("revision = %d, want 1", vm.Revision)
	}
	if op.State != "running" {
		t.Errorf("op.State = %q, want running", op.State)
	}
	if op.Phase != "admitted" {
		t.Errorf("op.Phase = %q, want admitted", op.Phase)
	}
	if vm.Labels["env"] != "test" {
		t.Errorf("labels = %v", vm.Labels)
	}

	// reservation row must exist with correct totals
	res, err := st.GetReservation(t.Context(), vmID)
	if err != nil {
		t.Fatalf("GetReservation: %v", err)
	}
	if res.MemoryTotalMiB != 2048+768 {
		t.Errorf("reserved memory_total_mib = %d, want %d", res.MemoryTotalMiB, 2048+768)
	}
	if res.DiskMiB != 8192+10240 {
		t.Errorf("reserved disk_mib = %d, want %d", res.DiskMiB, 8192+10240)
	}

	// both vm.created and operation.state_changed events must appear
	result := queryAll(t, st, store.Query{Limit: 10})
	kinds := map[string]bool{}
	for _, e := range result.Events {
		kinds[e.Kind] = true
	}
	if !kinds["vm.created"] {
		t.Error("vm.created event missing from store")
	}
	if !kinds["operation.state_changed"] {
		t.Error("operation.state_changed event missing from store")
	}
}

func TestVMCreateIdempotentReplay(t *testing.T) {
	st := openStore(t)
	in := store.CreateVMInput{
		VMID:             testUUID(1),
		Name:             "beta",
		Owner:            "test-owner",
		TemplateID:       "tmpl-001",
		TemplateDigest:   "sha256:abc",
		VCPUCount:        2,
		MemoryMiB:        2048,
		RootDiskMiB:      8192,
		WorkspaceDiskMiB: 10240,
		MemoryTotalMiB:   2048 + 768,
		NetworkProfile:   "transport",
		NetworkPolicyID:  "transport-public-web",
		Labels:           map[string]string{},
		Kind:             "vm.create",
		IdempotencyKey:   ptr("idem-key-1"),
		RequestHash:      strings.Repeat("b", 64),
		Admit:            func(store.ReservationTotals) error { return nil },
	}

	vm1, op1, err := st.CreateVMWithOperation(t.Context(), in)
	if err != nil {
		t.Fatalf("first create: %v", err)
	}

	// exact replay: same key, same hash — no new writes
	vm2, op2, err := st.CreateVMWithOperation(t.Context(), in)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if vm2.VMID != vm1.VMID {
		t.Errorf("replay returned different vm_id: %s vs %s", vm2.VMID, vm1.VMID)
	}
	if op2.OperationID != op1.OperationID {
		t.Errorf("replay returned different operation_id: %d vs %d", op2.OperationID, op1.OperationID)
	}

	// exactly one vm row
	vms, err := st.ListVMs(t.Context(), store.VMQuery{})
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	if len(vms) != 1 {
		t.Errorf("expected 1 vm after replay, got %d", len(vms))
	}
}

func TestVMCreateIdempotencyConflict(t *testing.T) {
	st := openStore(t)
	base := store.CreateVMInput{
		VMID:             testUUID(1),
		Name:             "gamma",
		Owner:            "test-owner",
		TemplateID:       "tmpl-001",
		TemplateDigest:   "sha256:abc",
		VCPUCount:        2,
		MemoryMiB:        2048,
		RootDiskMiB:      8192,
		WorkspaceDiskMiB: 10240,
		MemoryTotalMiB:   2048 + 768,
		NetworkProfile:   "transport",
		NetworkPolicyID:  "transport-public-web",
		Labels:           map[string]string{},
		Kind:             "vm.create",
		IdempotencyKey:   ptr("conflict-key"),
		RequestHash:      strings.Repeat("c", 64),
		Admit:            func(store.ReservationTotals) error { return nil },
	}
	if _, _, err := st.CreateVMWithOperation(t.Context(), base); err != nil {
		t.Fatalf("first create: %v", err)
	}

	// same key, different hash → conflict
	base.RequestHash = strings.Repeat("d", 64)
	_, _, err := st.CreateVMWithOperation(t.Context(), base)
	if !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Errorf("expected ErrIdempotencyConflict, got %v", err)
	}
}

func TestVMCreateAdmissionRefusal(t *testing.T) {
	st := openStore(t)
	refusal := &store.AdmissionRefusal{Cause: "insufficient_capacity", Message: "host RAM full"}
	vm, op, err := st.CreateVMWithOperation(t.Context(), store.CreateVMInput{
		VMID:             testUUID(2),
		Name:             "delta",
		Owner:            "test-owner",
		TemplateID:       "tmpl-001",
		TemplateDigest:   "sha256:abc",
		VCPUCount:        2,
		MemoryMiB:        2048,
		RootDiskMiB:      8192,
		WorkspaceDiskMiB: 10240,
		MemoryTotalMiB:   2048 + 768,
		NetworkProfile:   "transport",
		NetworkPolicyID:  "transport-public-web",
		Labels:           map[string]string{},
		Kind:             "vm.create",
		IdempotencyKey:   nil,
		RequestHash:      strings.Repeat("e", 64),
		Admit:            func(store.ReservationTotals) error { return refusal },
	})
	if vm != nil {
		t.Error("expected nil vm on refusal")
	}
	if op == nil {
		t.Fatal("expected non-nil op (durable refusal evidence)")
	}
	if op.State != "failed" {
		t.Errorf("op.State = %q, want failed", op.State)
	}
	if op.Phase != "admission" {
		t.Errorf("op.Phase = %q, want admission", op.Phase)
	}
	if op.ErrorCause == nil || *op.ErrorCause != "insufficient_capacity" {
		t.Errorf("error_cause = %v", op.ErrorCause)
	}
	// refusal is in the error chain
	var ar *store.AdmissionRefusal
	if !errors.As(err, &ar) {
		t.Errorf("expected *AdmissionRefusal in error chain, got %v", err)
	}

	// no vm or reservation row
	vms, _ := st.ListVMs(t.Context(), store.VMQuery{})
	if len(vms) != 0 {
		t.Errorf("expected 0 vm rows after refusal, got %d", len(vms))
	}
}

func TestVMCreateRefusalIdempotentReplay(t *testing.T) {
	// SPEC §14 / AT-006: a repeated identical request returns the original
	// outcome. When the original was an admission refusal, the replay must
	// return the same failed operation AND the refusal error — without
	// re-running admission, even if capacity has since freed.
	st := openStore(t)
	key := "refused-once"
	input := store.CreateVMInput{
		VMID:             testUUID(3),
		Name:             "echo",
		Owner:            "test-owner",
		TemplateID:       "tmpl-001",
		TemplateDigest:   "sha256:abc",
		VCPUCount:        2,
		MemoryMiB:        2048,
		RootDiskMiB:      8192,
		WorkspaceDiskMiB: 10240,
		MemoryTotalMiB:   2048 + 768,
		NetworkProfile:   "transport",
		NetworkPolicyID:  "transport-public-web",
		Labels:           map[string]string{},
		Kind:             "vm.create",
		IdempotencyKey:   &key,
		RequestHash:      strings.Repeat("f", 64),
		Admit: func(store.ReservationTotals) error {
			return &store.AdmissionRefusal{Cause: "insufficient_capacity", Message: "host RAM full"}
		},
	}
	_, op1, err := st.CreateVMWithOperation(t.Context(), input)
	var ar *store.AdmissionRefusal
	if !errors.As(err, &ar) || op1 == nil {
		t.Fatalf("setup: err=%v op=%v", err, op1)
	}

	// Capacity has "freed": this Admit would allow. It must not be consulted.
	input.Admit = func(store.ReservationTotals) error {
		t.Error("Admit re-ran on idempotent replay of a refusal")
		return nil
	}
	vm, op2, err := st.CreateVMWithOperation(t.Context(), input)
	if vm != nil {
		t.Errorf("replayed refusal produced a vm: %+v", vm)
	}
	if op2 == nil || op2.OperationID != op1.OperationID {
		t.Fatalf("replay op = %+v, want operation %d", op2, op1.OperationID)
	}
	ar = nil
	if !errors.As(err, &ar) {
		t.Fatalf("replay error = %v, want *AdmissionRefusal", err)
	}
	if ar.Cause != "insufficient_capacity" || ar.Message != "host RAM full" {
		t.Errorf("replayed refusal = %+v, want original cause and message", ar)
	}
	vms, err := st.ListVMs(t.Context(), store.VMQuery{})
	if err != nil || len(vms) != 0 {
		t.Errorf("after replay: vms=%d err=%v, want 0 rows", len(vms), err)
	}
}

func TestVMConcurrentAdmission(t *testing.T) {
	// AT-012: 10 goroutines, Admit allows only while ActiveVMs < 3.
	// Exactly 3 admitted, 7 refused; totals consistent.
	st := openStore(t)

	const total = 10
	var admitted, refused int64
	var wg sync.WaitGroup
	for i := range total {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			vmID := testUUID(i + 10)
			reqHash := fmt.Sprintf("%064x", i)
			_, _, err := st.CreateVMWithOperation(t.Context(), store.CreateVMInput{
				VMID:             vmID,
				Name:             fmt.Sprintf("vm-%d", i),
				Owner:            "test-owner",
				TemplateID:       "tmpl-001",
				TemplateDigest:   "sha256:abc",
				VCPUCount:        2,
				MemoryMiB:        2048,
				RootDiskMiB:      8192,
				WorkspaceDiskMiB: 10240,
				MemoryTotalMiB:   2048 + 768,
				NetworkProfile:   "transport",
				NetworkPolicyID:  "transport-public-web",
				Labels:           map[string]string{},
				Kind:             "vm.create",
				IdempotencyKey:   nil,
				RequestHash:      reqHash,
				Admit: func(totals store.ReservationTotals) error {
					if totals.ActiveVMs >= 3 {
						return &store.AdmissionRefusal{Cause: "insufficient_capacity", Message: "cap reached"}
					}
					return nil
				},
			})
			if err == nil {
				atomic.AddInt64(&admitted, 1)
			} else {
				atomic.AddInt64(&refused, 1)
			}
		}(i)
	}
	wg.Wait()

	if admitted != 3 {
		t.Errorf("admitted = %d, want 3", admitted)
	}
	if refused != 7 {
		t.Errorf("refused = %d, want 7", refused)
	}

	totals, err := st.ReservationTotals(t.Context())
	if err != nil {
		t.Fatalf("ReservationTotals: %v", err)
	}
	if totals.ActiveVMs != 3 {
		t.Errorf("reservation totals ActiveVMs = %d, want 3", totals.ActiveVMs)
	}
	expectedMem := int64(3) * (2048 + 768)
	if totals.MemoryMiB != expectedMem {
		t.Errorf("totals.MemoryMiB = %d, want %d", totals.MemoryMiB, expectedMem)
	}
}

func TestVMTransitionLegalChain(t *testing.T) {
	st := openStore(t)
	vmID := testUUID(1)
	vm, op := mustCreateVM(t, st, vmID, "chain-vm", nil)

	chain := []struct {
		to      string
		relComp bool
		relAll  bool
	}{
		{"starting", false, false},
		{"running", false, false},
		{"paused", false, false},
		{"running", false, false},
		{"stopping", false, false},
		{"stopped", true, false},
		{"deleting", false, false},
		{"deleted", false, true},
	}

	prev := vm
	for _, step := range chain {
		next, err := st.TransitionVM(t.Context(), store.TransitionInput{
			VMID:           vmID,
			To:             step.to,
			Reason:         "test transition",
			OperationID:    op.OperationID,
			ReleaseCompute: step.relComp,
			ReleaseAll:     step.relAll,
		})
		if err != nil {
			t.Fatalf("transition %s→%s: %v", prev.ObservedState, step.to, err)
		}
		if next.ObservedState != step.to {
			t.Errorf("after %s→%s: observed_state = %q", prev.ObservedState, step.to, next.ObservedState)
		}
		if next.Revision != prev.Revision+1 {
			t.Errorf("revision did not bump: %d → %d", prev.Revision, next.Revision)
		}
		prev = next
	}

	// vm.state_changed events must be in the log
	result := queryAll(t, st, store.Query{Kind: "vm.state_changed", Limit: 20})
	if len(result.Events) != len(chain) {
		t.Errorf("expected %d vm.state_changed events, got %d", len(chain), len(result.Events))
	}
}

func TestVMTransitionIllegal(t *testing.T) {
	st := openStore(t)
	vmID := testUUID(1)
	_, op := mustCreateVM(t, st, vmID, "illegal-vm", nil)

	// provisioning → running is not in the matrix
	_, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID:        vmID,
		To:          "running",
		Reason:      "test",
		OperationID: op.OperationID,
	})
	var ie *store.InvalidTransitionError
	if !errors.As(err, &ie) {
		t.Errorf("expected *InvalidTransitionError, got %v", err)
	}
	if ie != nil && (ie.From != "provisioning" || ie.To != "running") {
		t.Errorf("InvalidTransitionError = %+v", ie)
	}
}

func TestVMTransitionRevisionMismatch(t *testing.T) {
	st := openStore(t)
	vmID := testUUID(1)
	_, op := mustCreateVM(t, st, vmID, "rev-vm", nil)

	stale := int64(99)
	_, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID:             vmID,
		To:               "starting",
		Reason:           "test",
		OperationID:      op.OperationID,
		ExpectedRevision: &stale,
	})
	var rme *store.RevisionMismatchError
	if !errors.As(err, &rme) {
		t.Errorf("expected *RevisionMismatchError, got %v", err)
	}
	if rme != nil && rme.Current != 1 {
		t.Errorf("RevisionMismatchError.Current = %d, want 1", rme.Current)
	}
}

func TestVMReservationReleases(t *testing.T) {
	// AT-013: paused keeps memory+cpu; stopped drops compute; deleted drops all.
	st := openStore(t)
	vmID := testUUID(1)
	_, op := mustCreateVM(t, st, vmID, "res-vm", nil)

	totals := func() store.ReservationTotals {
		t.Helper()
		tot, err := st.ReservationTotals(t.Context())
		if err != nil {
			t.Fatalf("ReservationTotals: %v", err)
		}
		return tot
	}

	// provisioning → starting → running: full reservation
	for _, to := range []string{"starting", "running"} {
		if _, err := st.TransitionVM(t.Context(), store.TransitionInput{
			VMID: vmID, To: to, OperationID: op.OperationID,
		}); err != nil {
			t.Fatalf("→%s: %v", to, err)
		}
	}
	t1 := totals()
	if t1.MemoryMiB == 0 || t1.VCPU == 0 || t1.DiskMiB == 0 {
		t.Errorf("running: expected non-zero totals, got %+v", t1)
	}

	// running → paused: memory/cpu must still be reserved (AT-013)
	if _, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vmID, To: "paused", OperationID: op.OperationID,
	}); err != nil {
		t.Fatalf("→paused: %v", err)
	}
	t2 := totals()
	if t2.MemoryMiB != t1.MemoryMiB {
		t.Errorf("paused released memory: before=%d after=%d", t1.MemoryMiB, t2.MemoryMiB)
	}

	// paused → stopping → stopped: compute released, disk stays
	for _, step := range []struct {
		to      string
		release bool
	}{{"stopping", false}, {"stopped", true}} {
		if _, err := st.TransitionVM(t.Context(), store.TransitionInput{
			VMID: vmID, To: step.to, OperationID: op.OperationID, ReleaseCompute: step.release,
		}); err != nil {
			t.Fatalf("→%s: %v", step.to, err)
		}
	}
	t3 := totals()
	if t3.MemoryMiB != 0 || t3.VCPU != 0 {
		t.Errorf("stopped: expected 0 memory/cpu, got mem=%d cpu=%d", t3.MemoryMiB, t3.VCPU)
	}
	if t3.DiskMiB == 0 {
		t.Errorf("stopped: disk should still be reserved, got 0")
	}

	// stopped → deleting → deleted: everything released
	for _, step := range []struct {
		to  string
		all bool
	}{{"deleting", false}, {"deleted", true}} {
		if _, err := st.TransitionVM(t.Context(), store.TransitionInput{
			VMID: vmID, To: step.to, OperationID: op.OperationID, ReleaseAll: step.all,
		}); err != nil {
			t.Fatalf("→%s: %v", step.to, err)
		}
	}
	t4 := totals()
	if t4.MemoryMiB != 0 || t4.VCPU != 0 || t4.DiskMiB != 0 {
		t.Errorf("deleted: expected all-zero totals, got %+v", t4)
	}
	if t4.ActiveVMs != 0 {
		t.Errorf("deleted: expected 0 active VMs, got %d", t4.ActiveVMs)
	}
}

func TestVMListKeysetAndFilter(t *testing.T) {
	st := openStore(t)
	for i := range 5 {
		mustCreateVM(t, st, testUUID(i+1), fmt.Sprintf("vm-%d", i), nil)
	}

	// first page of 3
	page1, err := st.ListVMs(t.Context(), store.VMQuery{Limit: 3})
	if err != nil {
		t.Fatalf("ListVMs page1: %v", err)
	}
	if len(page1) != 3 {
		t.Errorf("page1 len = %d, want 3", len(page1))
	}

	// second page using cursor
	page2, err := st.ListVMs(t.Context(), store.VMQuery{After: page1[len(page1)-1].RowID, Limit: 10})
	if err != nil {
		t.Fatalf("ListVMs page2: %v", err)
	}
	if len(page2) != 2 {
		t.Errorf("page2 len = %d, want 2", len(page2))
	}

	// no overlap
	seen := map[int64]bool{}
	for _, v := range append(page1, page2...) {
		if seen[v.RowID] {
			t.Errorf("duplicate row_id %d in pagination", v.RowID)
		}
		seen[v.RowID] = true
	}

	// state filter: all are provisioning
	filtered, err := st.ListVMs(t.Context(), store.VMQuery{States: []string{"provisioning"}})
	if err != nil {
		t.Fatalf("ListVMs filter: %v", err)
	}
	if len(filtered) != 5 {
		t.Errorf("filtered len = %d, want 5", len(filtered))
	}
	filtered2, err := st.ListVMs(t.Context(), store.VMQuery{States: []string{"running"}})
	if err != nil {
		t.Fatalf("ListVMs running filter: %v", err)
	}
	if len(filtered2) != 0 {
		t.Errorf("running filter len = %d, want 0", len(filtered2))
	}
}

func TestVMGetUnknown(t *testing.T) {
	st := openStore(t)
	_, err := st.GetVM(t.Context(), testUUID(99))
	if !errors.Is(err, store.ErrVMUnknown) {
		t.Errorf("expected ErrVMUnknown, got %v", err)
	}
}

func TestOperationGetUnknown(t *testing.T) {
	st := openStore(t)
	_, err := st.GetOperation(t.Context(), 9999)
	if !errors.Is(err, store.ErrOperationUnknown) {
		t.Errorf("expected ErrOperationUnknown, got %v", err)
	}
}

func TestUpdateOperation(t *testing.T) {
	st := openStore(t)
	_, op := mustCreateVM(t, st, testUUID(1), "update-op-vm", nil)

	updated, err := st.UpdateOperation(t.Context(), store.OperationUpdate{
		OperationID: op.OperationID,
		Phase:       "boot",
		State:       "succeeded",
	})
	if err != nil {
		t.Fatalf("UpdateOperation: %v", err)
	}
	if updated.State != "succeeded" {
		t.Errorf("state = %q, want succeeded", updated.State)
	}
	if updated.Phase != "boot" {
		t.Errorf("phase = %q, want boot", updated.Phase)
	}

	// operation.state_changed event with state=succeeded in the log
	result := queryAll(t, st, store.Query{Kind: "operation.state_changed", Limit: 20})
	found := false
	for _, e := range result.Events {
		if d, ok := e.Data["state"].(string); ok && d == "succeeded" {
			found = true
		}
	}
	if !found {
		t.Error("no operation.state_changed event with state=succeeded")
	}
}

func TestTransitionVMBootIDInEvent(t *testing.T) {
	// BootID should appear in the vm.state_changed event data when set.
	st := openStore(t)
	vm, op := mustCreateVM(t, st, testUUID(1), "alpha", nil)
	bootID := testUUID(99)
	_, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID:        vm.VMID,
		To:          "starting",
		Reason:      "launch",
		OperationID: op.OperationID,
		BootID:      &bootID,
	})
	if err != nil {
		t.Fatalf("TransitionVM: %v", err)
	}
	events := queryAll(t, st, store.Query{Kind: "vm.state_changed", Limit: 10})
	found := false
	for _, e := range events.Events {
		if bid, ok := e.Data["boot_id"].(string); ok && bid == bootID {
			found = true
		}
	}
	if !found {
		t.Error("boot_id not found in vm.state_changed event data")
	}
}

func TestTransitionVMDeletedEmitsVMDeleted(t *testing.T) {
	// Transitioning to "deleted" should emit a vm.deleted event (SPEC §5.4).
	st := openStore(t)
	vm, op := mustCreateVM(t, st, testUUID(1), "alpha", nil)
	// Walk the state machine to deleted.
	for _, step := range []string{"starting", "running", "stopping", "stopped", "deleting", "deleted"} {
		release := step == "stopped"
		releaseAll := step == "deleted"
		_, err := st.TransitionVM(t.Context(), store.TransitionInput{
			VMID:           vm.VMID,
			To:             step,
			Reason:         "test",
			OperationID:    op.OperationID,
			ReleaseCompute: release,
			ReleaseAll:     releaseAll,
		})
		if err != nil {
			t.Fatalf("transition to %s: %v", step, err)
		}
	}
	events := queryAll(t, st, store.Query{Kind: "vm.deleted", Limit: 10})
	if len(events.Events) != 1 {
		t.Errorf("expected 1 vm.deleted event, got %d", len(events.Events))
	}
	if vmID, _ := events.Events[0].Data["vm_id"].(string); vmID != vm.VMID {
		t.Errorf("vm.deleted event vm_id = %q, want %q", vmID, vm.VMID)
	}
}
