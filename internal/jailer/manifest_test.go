// ABOUTME: Portable tests for manifest round-trip, slot allocation, exhaustion, and restart reuse.
// ABOUTME: No linux build tag — these run on any OS.
package jailer

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
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

// TestManifestCarriesRunnerIdentity verifies that a runner's start time survives a
// write+read cycle under the on-disk key the format promises. RunnerPID alone is not
// an identity (SPEC §9.1): the pid can be recycled between the write and the read, and
// runner_starttime is the only field that tells the two processes apart. The key name
// is part of the contract because manifests outlive the process that wrote them —
// mirror vmm_starttime, whose partner field this is.
func TestManifestCarriesRunnerIdentity(t *testing.T) {
	dir := t.TempDir()
	m := Manifest{
		VMID:        "vm-runner-identity",
		Slot:        0,
		RunnerPID:   4242,
		RunnerStart: "8877665544",
		Stages:      []string{"reserved"},
	}
	if err := writeManifest(dir, m); err != nil {
		t.Fatalf("writeManifest: %v", err)
	}

	got, err := readManifest(dir, m.VMID)
	if err != nil {
		t.Fatalf("readManifest: %v", err)
	}
	if got.RunnerStart != m.RunnerStart {
		t.Errorf("RunnerStart = %q, want %q: the runner's start time did not survive the "+
			"manifest round-trip, so a recycled pid reads as the same runner", got.RunnerStart, m.RunnerStart)
	}

	raw, err := os.ReadFile(manifestPath(dir, m.VMID))
	if err != nil {
		t.Fatalf("read manifest file: %v", err)
	}
	var onDisk map[string]any
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatalf("unmarshal manifest file: %v", err)
	}
	if onDisk["runner_starttime"] != m.RunnerStart {
		t.Errorf("on-disk runner_starttime = %v, want %q (keys present: %v)",
			onDisk["runner_starttime"], m.RunnerStart, sortedKeys(onDisk))
	}

	// omitempty, like vmm_starttime: a manifest with no runner identity must not
	// write the key at all, so an old manifest and a new one with an unread start
	// time are the same shape on disk.
	empty := Manifest{VMID: "vm-no-runner", Slot: 1, Stages: []string{"reserved"}}
	if err := writeManifest(dir, empty); err != nil {
		t.Fatalf("writeManifest (empty): %v", err)
	}
	rawEmpty, err := os.ReadFile(manifestPath(dir, empty.VMID))
	if err != nil {
		t.Fatalf("read manifest file (empty): %v", err)
	}
	if bytes.Contains(rawEmpty, []byte("runner_starttime")) {
		t.Errorf("manifest without a runner identity wrote runner_starttime anyway: %s", rawEmpty)
	}
}

// sortedKeys returns the keys of a decoded manifest in a stable order, for failure
// messages that name what the file actually contains.
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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

// TestSlotAllocationIgnoresAVMDirectoryWithNoManifest covers the one window
// durable publication cannot close: writeManifest creates the VM state
// directory and then publishes the manifest into it, so a crash between those
// two steps leaves a directory with no record in it. That state is safe — at
// that point the launch has provisioned nothing but the directory — and
// allocateSlot has to read it as free rather than as a slot it cannot name.
func TestSlotAllocationIgnoresAVMDirectoryWithNoManifest(t *testing.T) {
	dir := t.TempDir()

	occupied := Manifest{VMID: slotToTestVMID(0), Slot: 0, Stages: []string{"reserved"}}
	if err := writeManifest(dir, occupied); err != nil {
		t.Fatalf("writeManifest: %v", err)
	}
	// The crash window: directory created, manifest never published.
	if err := os.MkdirAll(filepath.Join(dir, "vms", "vm-crashed"), 0o700); err != nil {
		t.Fatalf("mkdir crashed vm dir: %v", err)
	}

	got, err := allocateSlot(dir, "vm-new", 4)
	if err != nil {
		t.Fatalf("allocateSlot: %v", err)
	}
	if got != 1 {
		t.Errorf("allocateSlot = %d, want 1 (the empty directory must not reserve a slot)", got)
	}

	// The crashed VM itself is a stranger now: with no manifest there is no
	// identity to match, so it allocates like any new VM.
	retry, err := allocateSlot(dir, "vm-crashed", 4)
	if err != nil {
		t.Fatalf("allocateSlot (crashed vm retry): %v", err)
	}
	if retry != 1 {
		t.Errorf("allocateSlot for the crashed vm = %d, want 1", retry)
	}
}
