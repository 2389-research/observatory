// ABOUTME: Portable tests for manifest round-trip, slot allocation, exhaustion, and restart reuse.
// ABOUTME: No linux build tag — these run on any OS.
package jailer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestManifestRoundTrip verifies that a Manifest survives a write+read cycle unchanged.
func TestManifestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	m := Manifest{
		VMID:      "vm-roundtrip",
		BootID:    "boot-abc123",
		Slot:      3,
		UID:       20003,
		GID:       36000,
		CID:       6,
		CIDR:      "192.168.1.4/30",
		VMMPID:    1234,
		VMMStart:  "99887766",
		RunnerPID: 5678,
		Stages:    []string{"reserved", "staged", "network", "vmm_started", "runner_spawned", "attached"},
	}

	if err := writeManifest(dir, m); err != nil {
		t.Fatalf("writeManifest: %v", err)
	}

	got, err := readManifest(dir, "vm-roundtrip")
	if err != nil {
		t.Fatalf("readManifest: %v", err)
	}

	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(m)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("round-trip mismatch:\n got  %s\n want %s", gotJSON, wantJSON)
	}
}

// TestStageAppendOrdering verifies that stages are appended in the order written.
func TestStageAppendOrdering(t *testing.T) {
	dir := t.TempDir()
	m := Manifest{VMID: "vm-order", Slot: 0, Stages: []string{}}

	stages := []string{"reserved", "staged", "network", "vmm_started", "runner_spawned", "attached"}
	for i, s := range stages {
		m.Stages = append(m.Stages, s)
		if err := writeManifest(dir, m); err != nil {
			t.Fatalf("writeManifest after stage %q: %v", s, err)
		}
		got, err := readManifest(dir, "vm-order")
		if err != nil {
			t.Fatalf("readManifest after stage %q: %v", s, err)
		}
		if len(got.Stages) != i+1 {
			t.Errorf("after stage %q: want %d stages, got %d", s, i+1, len(got.Stages))
		}
		if got.Stages[i] != s {
			t.Errorf("stages[%d] = %q, want %q", i, got.Stages[i], s)
		}
	}
}

// TestSlotAllocationPicksLowest verifies that slot allocation picks the lowest free slot
// when slots 0 and 2 are already taken — expects slot 1.
func TestSlotAllocationPicksLowest(t *testing.T) {
	dir := t.TempDir()

	// Occupy slots 0 and 2.
	for _, slot := range []int{0, 2} {
		m := Manifest{
			VMID:   slotToTestVMID(slot),
			Slot:   slot,
			Stages: []string{"reserved"},
		}
		// Write into per-VM state subdir.
		vmDir := filepath.Join(dir, "vms", m.VMID)
		if err := os.MkdirAll(vmDir, 0o755); err != nil {
			t.Fatalf("mkdir vm dir: %v", err)
		}
		if err := writeManifest(dir, m); err != nil {
			t.Fatalf("writeManifest slot %d: %v", slot, err)
		}
	}

	got, err := allocateSlot(dir, "vm-new", 4)
	if err != nil {
		t.Fatalf("allocateSlot: %v", err)
	}
	if got != 1 {
		t.Errorf("allocateSlot = %d, want 1", got)
	}
}

// TestSlotsExhausted verifies that allocateSlot returns ErrSlotsExhausted when all MaxSlots are taken.
func TestSlotsExhausted(t *testing.T) {
	dir := t.TempDir()
	maxSlots := 3

	// Occupy all slots.
	for slot := 0; slot < maxSlots; slot++ {
		m := Manifest{
			VMID:   slotToTestVMID(slot),
			Slot:   slot,
			Stages: []string{"reserved"},
		}
		vmDir := filepath.Join(dir, "vms", m.VMID)
		if err := os.MkdirAll(vmDir, 0o755); err != nil {
			t.Fatalf("mkdir vm dir slot %d: %v", slot, err)
		}
		if err := writeManifest(dir, m); err != nil {
			t.Fatalf("writeManifest slot %d: %v", slot, err)
		}
	}

	_, err := allocateSlot(dir, "vm-overflow", maxSlots)
	if err == nil {
		t.Fatal("expected ErrSlotsExhausted, got nil")
	}
	if err != ErrSlotsExhausted {
		t.Errorf("error = %v, want ErrSlotsExhausted", err)
	}
}

// TestRestartReusesSlotAndCIDR verifies that if a manifest for the given vm_id already
// exists, allocateSlot returns its slot and readManifest returns its CIDR.
func TestRestartReusesSlotAndCIDR(t *testing.T) {
	dir := t.TempDir()
	vmID := "vm-restart"
	existingSlot := 2
	existingCIDR := "10.99.0.8/30"

	// Pre-write the manifest as if from a prior launch.
	m := Manifest{
		VMID:   vmID,
		Slot:   existingSlot,
		CIDR:   existingCIDR,
		Stages: []string{"reserved", "staged"},
	}
	vmDir := filepath.Join(dir, "vms", vmID)
	if err := os.MkdirAll(vmDir, 0o755); err != nil {
		t.Fatalf("mkdir vm dir: %v", err)
	}
	if err := writeManifest(dir, m); err != nil {
		t.Fatalf("writeManifest: %v", err)
	}

	slot, err := allocateSlot(dir, vmID, 8)
	if err != nil {
		t.Fatalf("allocateSlot: %v", err)
	}
	if slot != existingSlot {
		t.Errorf("slot = %d, want %d (existing)", slot, existingSlot)
	}

	got, err := readManifest(dir, vmID)
	if err != nil {
		t.Fatalf("readManifest: %v", err)
	}
	if got.CIDR != existingCIDR {
		t.Errorf("CIDR = %q, want %q", got.CIDR, existingCIDR)
	}
}

// slotToTestVMID builds a vm_id string from a slot number for test purposes.
func slotToTestVMID(slot int) string {
	ids := []string{"vm-slot0", "vm-slot1", "vm-slot2", "vm-slot3"}
	if slot < len(ids) {
		return ids[slot]
	}
	return "vm-slotN"
}
