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

	"github.com/2389-research/observatory-v2/internal/lock"
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
	vm, op, _, err := st.CreateVMWithOperation(t.Context(), store.CreateVMInput{
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

	vm, op, _, err := st.CreateVMWithOperation(t.Context(), store.CreateVMInput{
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

	vm1, op1, _, err := st.CreateVMWithOperation(t.Context(), in)
	if err != nil {
		t.Fatalf("first create: %v", err)
	}

	// exact replay: same key, same hash — no new writes
	vm2, op2, _, err := st.CreateVMWithOperation(t.Context(), in)
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
	if _, _, _, err := st.CreateVMWithOperation(t.Context(), base); err != nil {
		t.Fatalf("first create: %v", err)
	}

	// same key, different hash → conflict
	base.RequestHash = strings.Repeat("d", 64)
	_, _, _, err := st.CreateVMWithOperation(t.Context(), base)
	if !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Errorf("expected ErrIdempotencyConflict, got %v", err)
	}
}

func TestVMCreateAdmissionRefusal(t *testing.T) {
	st := openStore(t)
	refusal := &store.AdmissionRefusal{Cause: "insufficient_capacity", Message: "host RAM full"}
	vm, op, _, err := st.CreateVMWithOperation(t.Context(), store.CreateVMInput{
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
	_, op1, _, err := st.CreateVMWithOperation(t.Context(), input)
	var ar *store.AdmissionRefusal
	if !errors.As(err, &ar) || op1 == nil {
		t.Fatalf("setup: err=%v op=%v", err, op1)
	}

	// Capacity has "freed": this Admit would allow. It must not be consulted.
	input.Admit = func(store.ReservationTotals) error {
		t.Error("Admit re-ran on idempotent replay of a refusal")
		return nil
	}
	vm, op2, _, err := st.CreateVMWithOperation(t.Context(), input)
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
			_, _, _, err := st.CreateVMWithOperation(t.Context(), store.CreateVMInput{
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

func TestListVMsFilterByOwner(t *testing.T) {
	st := openStore(t)
	// Create two VMs with different owners directly.
	vmAlice := testUUID(101)
	vmBob := testUUID(102)
	for _, tc := range []struct{ vmID, name, owner string }{
		{vmAlice, "alice-vm", "alice"},
		{vmBob, "bob-vm", "bob"},
	} {
		_, _, _, err := st.CreateVMWithOperation(t.Context(), store.CreateVMInput{
			VMID: tc.vmID, Name: tc.name, Owner: tc.owner,
			TemplateID: "tmpl-001", TemplateDigest: "sha256:abc",
			VCPUCount: 1, MemoryMiB: 512, RootDiskMiB: 4096, WorkspaceDiskMiB: 8192,
			MemoryTotalMiB: 1280, NetworkProfile: "transport", NetworkPolicyID: "net",
			Labels: map[string]string{}, Kind: "vm.create",
			RequestHash: strings.Repeat(tc.owner[:1], 64),
			Admit:       func(store.ReservationTotals) error { return nil },
		})
		if err != nil {
			t.Fatalf("create %s: %v", tc.owner, err)
		}
	}
	alice, err := st.ListVMs(t.Context(), store.VMQuery{Owner: "alice"})
	if err != nil {
		t.Fatalf("ListVMs alice: %v", err)
	}
	if len(alice) != 1 || alice[0].Owner != "alice" {
		t.Errorf("owner=alice: got %d VMs", len(alice))
	}
	bob, err := st.ListVMs(t.Context(), store.VMQuery{Owner: "bob"})
	if err != nil {
		t.Fatalf("ListVMs bob: %v", err)
	}
	if len(bob) != 1 || bob[0].Owner != "bob" {
		t.Errorf("owner=bob: got %d VMs", len(bob))
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

// TestTransitionVMRecordsCurrentBoot pins the boot identity on the VM row, not
// only in the event stream. A late observation about a VM — a vmm_exited notice
// that spent a poll interval in the spool — is only actionable if the reader can
// tell which boot it describes, and the event stream cannot answer that in one
// read of the row it is about to change.
func TestTransitionVMRecordsCurrentBoot(t *testing.T) {
	st := openStore(t)
	vm, op := mustCreateVM(t, st, testUUID(1), "alpha", nil)
	if vm.CurrentBootID != "" {
		t.Errorf("a VM that never booted: current_boot_id = %q, want empty", vm.CurrentBootID)
	}

	first := testUUID(90)
	started, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vm.VMID, To: "starting", Reason: "launch", OperationID: op.OperationID, BootID: &first,
	})
	if err != nil {
		t.Fatalf("TransitionVM starting: %v", err)
	}
	if started.CurrentBootID != first {
		t.Errorf("current_boot_id after launch = %q, want %q", started.CurrentBootID, first)
	}

	// A transition that establishes no boot leaves the recorded one alone:
	// running is the same boot that started.
	running, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vm.VMID, To: "running", Reason: "launch_complete", OperationID: op.OperationID,
	})
	if err != nil {
		t.Fatalf("TransitionVM running: %v", err)
	}
	if running.CurrentBootID != first {
		t.Errorf("current_boot_id after launch_complete = %q, want %q unchanged", running.CurrentBootID, first)
	}

	// A restart is a new boot, and the row says so from the transition onward.
	for _, step := range []string{"stopping", "stopped"} {
		if _, err := st.TransitionVM(t.Context(), store.TransitionInput{
			VMID: vm.VMID, To: step, Reason: "stop", OperationID: op.OperationID,
		}); err != nil {
			t.Fatalf("TransitionVM %s: %v", step, err)
		}
	}
	second := testUUID(91)
	restarted, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vm.VMID, To: "starting", Reason: "start", OperationID: op.OperationID, BootID: &second,
	})
	if err != nil {
		t.Fatalf("TransitionVM restart: %v", err)
	}
	if restarted.CurrentBootID != second {
		t.Errorf("current_boot_id after restart = %q, want %q", restarted.CurrentBootID, second)
	}

	// And a plain read agrees with what the transition returned.
	got, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if got.CurrentBootID != second {
		t.Errorf("GetVM current_boot_id = %q, want %q", got.CurrentBootID, second)
	}
}

// TestTransitionVMRecordsTheImagesTheBootStaged: the row answers what this VM
// booted, not only what the host would stage now. The two differ the moment
// runtime.lock.json changes under a running VM, which is the whole reason the
// field exists.
func TestTransitionVMRecordsTheImagesTheBootStaged(t *testing.T) {
	st := openStore(t)
	vm, op := mustCreateVM(t, st, testUUID(1), "alpha", nil)
	if vm.BootImages != nil {
		t.Errorf("a VM that never booted carries images: %+v", vm.BootImages)
	}

	boot := testUUID(90)
	if _, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vm.VMID, To: "starting", Reason: "launch", OperationID: op.OperationID, BootID: &boot,
	}); err != nil {
		t.Fatalf("TransitionVM starting: %v", err)
	}
	// The boot is established before the launch stages anything, so between the
	// two writes the row must say nothing rather than guess.
	mid, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if mid.BootImages != nil {
		t.Errorf("images before the launch reported any: %+v", mid.BootImages)
	}

	first := lock.Images{
		GuestKernel: lock.GuestKernelEntry{Version: "6.1.186", VmlinuxSHA256: "aaaa", VmlinuxPath: "images/dist/vmlinux"},
		RootImage:   lock.RootImageEntry{SHA256: "bbbb", Path: "images/dist/rootfs.ext4", BaseImageRef: "ubuntu:24.04", AptSnapshot: "2026-01-01"},
	}
	running, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vm.VMID, To: "running", Reason: "launch_complete", OperationID: op.OperationID, Images: &first,
	})
	if err != nil {
		t.Fatalf("TransitionVM running: %v", err)
	}
	if running.BootImages == nil || *running.BootImages != first {
		t.Fatalf("images after launch = %+v, want %+v", running.BootImages, first)
	}
	got, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if got.BootImages == nil || *got.BootImages != first {
		t.Errorf("GetVM images = %+v, want %+v", got.BootImages, first)
	}
}

// TestTransitionVMNewBootClearsTheOldImages: a boot inherits nothing. A VM
// stopped and started across a repin booted a different rootfs, and the row must
// not answer with the previous boot's images while the new one is still staging.
func TestTransitionVMNewBootClearsTheOldImages(t *testing.T) {
	st := openStore(t)
	vm, op := mustCreateVM(t, st, testUUID(1), "alpha", nil)
	first := testUUID(90)
	images := lock.Images{RootImage: lock.RootImageEntry{SHA256: "old", Path: "images/dist/rootfs.ext4"}}
	for _, in := range []store.TransitionInput{
		{To: "starting", Reason: "launch", BootID: &first},
		{To: "running", Reason: "launch_complete", Images: &images},
		{To: "stopping", Reason: "stop"},
		{To: "stopped", Reason: "stop_complete", ReleaseCompute: true},
	} {
		in.VMID, in.OperationID = vm.VMID, op.OperationID
		if _, err := st.TransitionVM(t.Context(), in); err != nil {
			t.Fatalf("TransitionVM %s: %v", in.To, err)
		}
	}
	stopped, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if stopped.BootImages == nil || stopped.BootImages.RootImage.SHA256 != "old" {
		t.Fatalf("a stop dropped the images of the boot that ran: %+v", stopped.BootImages)
	}

	second := testUUID(91)
	restarted, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vm.VMID, To: "starting", Reason: "start", OperationID: op.OperationID, BootID: &second,
	})
	if err != nil {
		t.Fatalf("TransitionVM restart: %v", err)
	}
	if restarted.BootImages != nil {
		t.Errorf("the new boot inherited the old boot's images: %+v", restarted.BootImages)
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

// --- last_event_id and delta tests (P-08: changed_vms is a deterministic materialization) ---

func TestLastEventIDAdvancesOnCreate(t *testing.T) {
	st := openStore(t)
	vm, _ := mustCreateVM(t, st, testUUID(1), "alpha", nil)
	if vm.LastEventID == 0 {
		t.Error("last_event_id must be non-zero after create")
	}
	// Reload from DB to confirm it was persisted.
	got, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastEventID != vm.LastEventID {
		t.Errorf("persisted last_event_id %d != returned %d", got.LastEventID, vm.LastEventID)
	}
}

func TestLastEventIDAdvancesOnTransition(t *testing.T) {
	st := openStore(t)
	vm, op := mustCreateVM(t, st, testUUID(1), "alpha", nil)
	afterCreate := vm.LastEventID

	vm2, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vm.VMID, To: "starting", Reason: "launch", OperationID: op.OperationID,
	})
	if err != nil {
		t.Fatalf("transition: %v", err)
	}
	if vm2.LastEventID <= afterCreate {
		t.Errorf("last_event_id did not advance after transition: %d <= %d",
			vm2.LastEventID, afterCreate)
	}
}

func TestChangedVMsDelta(t *testing.T) {
	st := openStore(t)

	// Create VM A; last_event_id = e1.
	vmA, opA := mustCreateVM(t, st, testUUID(1), "alpha", nil)
	e1 := vmA.LastEventID

	// Create VM B; last_event_id = e2 > e1.
	vmB, _ := mustCreateVM(t, st, testUUID(2), "beta", nil)
	e2 := vmB.LastEventID

	// ChangedVMs(e1) → only B (A's last_event_id == e1, not > e1).
	delta, err := st.ChangedVMs(t.Context(), e1, 100)
	if err != nil {
		t.Fatalf("ChangedVMs: %v", err)
	}
	if len(delta) != 1 || delta[0].VMID != vmB.VMID {
		t.Errorf("ChangedVMs(%d) = %d VMs, want 1 (vmB)", e1, len(delta))
	}

	// ChangedVMs(e2) → empty (nothing newer than B's creation).
	delta, err = st.ChangedVMs(t.Context(), e2, 100)
	if err != nil {
		t.Fatalf("ChangedVMs: %v", err)
	}
	if len(delta) != 0 {
		t.Errorf("ChangedVMs(%d) = %d VMs, want 0", e2, len(delta))
	}

	// Transition A → starting; A's last_event_id becomes e3 > e2.
	vmAtransitioned, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vmA.VMID, To: "starting", Reason: "launch", OperationID: opA.OperationID,
	})
	if err != nil {
		t.Fatalf("transition A: %v", err)
	}
	if vmAtransitioned.LastEventID <= e2 {
		t.Fatalf("expected last_event_id > e2 after transition, got %d", vmAtransitioned.LastEventID)
	}

	// ChangedVMs(e2) must now include A (transitioned after e2).
	delta, err = st.ChangedVMs(t.Context(), e2, 100)
	if err != nil {
		t.Fatalf("ChangedVMs after transition: %v", err)
	}
	found := false
	for _, v := range delta {
		if v.VMID == vmA.VMID {
			found = true
		}
	}
	if !found {
		t.Errorf("vmA (transitioned) missing from ChangedVMs(%d), got %v", e2, delta)
	}
}

func TestCountVMsByObservedState(t *testing.T) {
	st := openStore(t)

	// Two provisioning VMs.
	vm1, op1 := mustCreateVM(t, st, testUUID(1), "alpha", nil)
	vm2, _ := mustCreateVM(t, st, testUUID(2), "beta", nil)
	_ = vm2

	counts, err := st.CountVMsByObservedState(t.Context())
	if err != nil {
		t.Fatalf("CountVMsByObservedState: %v", err)
	}
	if counts["provisioning"] != 2 {
		t.Errorf("counts[provisioning] = %d, want 2", counts["provisioning"])
	}

	// Transition vm1 to starting.
	if _, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vm1.VMID, To: "starting", Reason: "launch", OperationID: op1.OperationID,
	}); err != nil {
		t.Fatalf("transition: %v", err)
	}
	counts, err = st.CountVMsByObservedState(t.Context())
	if err != nil {
		t.Fatalf("CountVMsByObservedState after transition: %v", err)
	}
	if counts["provisioning"] != 1 || counts["starting"] != 1 {
		t.Errorf("counts after transition = %v, want {provisioning:1, starting:1}", counts)
	}
}

// A From guard pins a transition to its intended origin. stopped→starting is
// legal (restart), so a launch racing a stop wave must declare it means
// provisioning→starting — otherwise it would revive a VM the wave stopped.
func TestTransitionFromGuard(t *testing.T) {
	st := openStore(t)
	ctx := t.Context()
	vmID := testUUID(41)
	mustCreateVM(t, st, vmID, "guard-vm", nil)

	if _, err := st.TransitionVM(ctx, store.TransitionInput{
		VMID: vmID, To: "starting", Reason: "launch", From: ptr("provisioning"),
	}); err != nil {
		t.Fatalf("guarded launch transition: %v", err)
	}
	for _, to := range []string{"stopping", "stopped"} {
		if _, err := st.TransitionVM(ctx, store.TransitionInput{
			VMID: vmID, To: to, Reason: "stop", ReleaseCompute: to == "stopped",
		}); err != nil {
			t.Fatalf("transition to %s: %v", to, err)
		}
	}

	// The VM is stopped. A launch guarded on provisioning must refuse even
	// though stopped→starting is a legal edge.
	_, err := st.TransitionVM(ctx, store.TransitionInput{
		VMID: vmID, To: "starting", Reason: "launch", From: ptr("provisioning"),
	})
	var invalid *store.InvalidTransitionError
	if !errors.As(err, &invalid) {
		t.Fatalf("stale-From launch: err = %v, want InvalidTransitionError", err)
	}
	if invalid.From != "stopped" {
		t.Errorf("error names From = %q, want stopped (the actual state)", invalid.From)
	}

	// A restart guarded on stopped goes through.
	if _, err := st.TransitionVM(ctx, store.TransitionInput{
		VMID: vmID, To: "starting", Reason: "restart", From: ptr("stopped"),
	}); err != nil {
		t.Fatalf("guarded restart: %v", err)
	}
}

// IfState makes operation updates conditional so a terminal record cannot be
// silently rewritten (a stop wave must not flip a succeeded create to failed).
func TestUpdateOperationIfState(t *testing.T) {
	st := openStore(t)
	ctx := t.Context()
	_, op := mustCreateVM(t, st, testUUID(42), "ifstate-vm", nil)

	if _, err := st.UpdateOperation(ctx, store.OperationUpdate{
		OperationID: op.OperationID, Phase: "complete", State: "succeeded", IfState: "running",
	}); err != nil {
		t.Fatalf("guarded succeed: %v", err)
	}

	before, err := st.Query(ctx, store.Query{Kind: "operation.state_changed"})
	if err != nil {
		t.Fatal(err)
	}

	cause := "batch_stop_successful"
	_, err = st.UpdateOperation(ctx, store.OperationUpdate{
		OperationID: op.OperationID, Phase: "stopped", State: "failed",
		ErrorCause: &cause, ErrorMessage: &cause, IfState: "running",
	})
	if !errors.Is(err, store.ErrOperationStale) {
		t.Fatalf("stale update: err = %v, want ErrOperationStale", err)
	}

	got, err := st.GetOperation(ctx, op.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "succeeded" || got.ErrorCause != nil {
		t.Errorf("op after stale update = %s/%v, want succeeded with no error", got.State, got.ErrorCause)
	}
	after, err := st.Query(ctx, store.Query{Kind: "operation.state_changed"})
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Events) != len(before.Events) {
		t.Errorf("stale update emitted an event: %d → %d", len(before.Events), len(after.Events))
	}

	// Unknown op stays its own error.
	_, err = st.UpdateOperation(ctx, store.OperationUpdate{
		OperationID: 999999, Phase: "complete", State: "failed", IfState: "running",
	})
	if !errors.Is(err, store.ErrOperationUnknown) {
		t.Errorf("unknown op: err = %v, want ErrOperationUnknown", err)
	}
}

// The replay flag is how the API serves is_replay honestly (AT-006 replays
// return the original outcome and must say so).
func TestCreateVMReplayFlag(t *testing.T) {
	st := openStore(t)
	in := store.CreateVMInput{
		VMID:             testUUID(43),
		Name:             "replay-flag",
		Owner:            "test-owner",
		TemplateID:       "tmpl-001",
		TemplateDigest:   "sha256:abc",
		VCPUCount:        1,
		MemoryMiB:        1024,
		RootDiskMiB:      4096,
		WorkspaceDiskMiB: 4096,
		MemoryTotalMiB:   1024 + 768,
		NetworkProfile:   "transport",
		NetworkPolicyID:  "p",
		Kind:             "vm.create",
		IdempotencyKey:   ptr("replay-flag-key"),
		RequestHash:      strings.Repeat("b", 64),
		Admit:            func(store.ReservationTotals) error { return nil },
	}
	_, _, replayed, err := st.CreateVMWithOperation(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	if replayed {
		t.Error("first create marked as replay")
	}
	vm2, _, replayed2, err := st.CreateVMWithOperation(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed2 {
		t.Error("second create not marked as replay")
	}
	if vm2.VMID != testUUID(43) {
		t.Errorf("replay vm = %q, want original", vm2.VMID)
	}
}

// startCycle walks a VM from provisioning to running, then stops it, returning
// the reservation totals seen while it ran. The compute a start must re-acquire
// is exactly what the stop gave back.
func startCycle(t *testing.T, st *store.Store, vmID string, opID int64) (running, stopped store.ReservationTotals) {
	t.Helper()
	totals := func() store.ReservationTotals {
		t.Helper()
		tot, err := st.ReservationTotals(t.Context())
		if err != nil {
			t.Fatalf("ReservationTotals: %v", err)
		}
		return tot
	}
	for _, to := range []string{"starting", "running"} {
		if _, err := st.TransitionVM(t.Context(), store.TransitionInput{
			VMID: vmID, To: to, OperationID: opID,
		}); err != nil {
			t.Fatalf("→%s: %v", to, err)
		}
	}
	running = totals()
	for _, step := range []struct {
		to      string
		release bool
	}{{"stopping", false}, {"stopped", true}} {
		if _, err := st.TransitionVM(t.Context(), store.TransitionInput{
			VMID: vmID, To: step.to, OperationID: opID, ReleaseCompute: step.release,
		}); err != nil {
			t.Fatalf("→%s: %v", step.to, err)
		}
	}
	return running, totals()
}

func TestVMStartReacquiresCompute(t *testing.T) {
	// A stop hands the VM's RAM and vCPU back to admission. Starting it again
	// must take them back, or admission under-counts by one VM's compute for
	// every stop/start round trip and eventually over-admits the host.
	st := openStore(t)
	vmID := testUUID(1)
	_, op := mustCreateVM(t, st, vmID, "cycle-vm", nil)

	running, stopped := startCycle(t, st, vmID, op.OperationID)
	if stopped.MemoryMiB != 0 || stopped.VCPU != 0 {
		t.Fatalf("stopped: expected compute released, got mem=%d vcpu=%d", stopped.MemoryMiB, stopped.VCPU)
	}

	if _, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vmID, To: "starting", OperationID: op.OperationID,
		AcquireCompute: true,
		Admit:          func(store.ReservationTotals) error { return nil },
	}); err != nil {
		t.Fatalf("→starting: %v", err)
	}

	after, err := st.ReservationTotals(t.Context())
	if err != nil {
		t.Fatalf("ReservationTotals: %v", err)
	}
	if after.MemoryMiB != running.MemoryMiB {
		t.Errorf("restarted memory = %d MiB, want %d MiB (the stop released it and the start must take it back)",
			after.MemoryMiB, running.MemoryMiB)
	}
	if after.VCPU != running.VCPU {
		t.Errorf("restarted vcpu = %d, want %d", after.VCPU, running.VCPU)
	}
	if after.DiskMiB != running.DiskMiB {
		t.Errorf("restarted disk = %d MiB, want %d MiB (disk is never released before delete)",
			after.DiskMiB, running.DiskMiB)
	}
}

func TestVMStartRefusedWhenComputeNoLongerFits(t *testing.T) {
	// The memory a stop released can be handed to another VM before the first
	// one is started again. Admission must be consulted on the way back in, and
	// a refusal must roll the whole transition back: no starting row, no
	// reservation taken.
	st := openStore(t)
	vmID := testUUID(1)
	_, op := mustCreateVM(t, st, vmID, "cycle-vm", nil)
	_, stopped := startCycle(t, st, vmID, op.OperationID)

	refusal := &store.AdmissionRefusal{
		Cause:   "insufficient_capacity",
		Message: "memory: need 2816 MiB, only 512 MiB free (usable 4096, reserved 3584)",
	}
	var seen store.ReservationTotals
	_, err := st.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vmID, To: "starting", OperationID: op.OperationID,
		AcquireCompute: true,
		Admit: func(totals store.ReservationTotals) error {
			seen = totals
			return refusal
		},
	})
	var got *store.AdmissionRefusal
	if !errors.As(err, &got) {
		t.Fatalf("TransitionVM err = %v, want *store.AdmissionRefusal", err)
	}
	if got.Message != refusal.Message {
		t.Errorf("refusal message = %q, want %q", got.Message, refusal.Message)
	}

	// The callback must see the host without this VM's compute — that is what
	// it has to fit back in. Counting the VM's own released memory as reserved
	// would refuse every restart on a full-enough host.
	if seen.MemoryMiB != stopped.MemoryMiB {
		t.Errorf("Admit saw reserved memory = %d MiB, want %d MiB (this VM's compute is released)",
			seen.MemoryMiB, stopped.MemoryMiB)
	}

	vm, err := st.GetVM(t.Context(), vmID)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.ObservedState != "stopped" {
		t.Errorf("observed_state = %q after a refused start, want %q", vm.ObservedState, "stopped")
	}
	after, err := st.ReservationTotals(t.Context())
	if err != nil {
		t.Fatalf("ReservationTotals: %v", err)
	}
	if after.MemoryMiB != stopped.MemoryMiB || after.VCPU != stopped.VCPU {
		t.Errorf("a refused start took compute anyway: mem=%d vcpu=%d, want mem=%d vcpu=%d",
			after.MemoryMiB, after.VCPU, stopped.MemoryMiB, stopped.VCPU)
	}
}
