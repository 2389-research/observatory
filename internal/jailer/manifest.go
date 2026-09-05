// ABOUTME: Provisioning manifest: tracks staged resources so rollback targets exactly what was owned.
// ABOUTME: Published durably before each external side effect; pure-portable logic.
package jailer

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/2389-research/observatory-v2/internal/durable"
)

// ErrSlotsExhausted is returned by allocateSlot when no free slot < MaxSlots exists.
var ErrSlotsExhausted = errors.New("jailer: all VM slots exhausted")

// Finding is one entry from Reconcile: the adapter's verdict on a VM it found
// in <StateDir>/vms/ at startup. Outcome ∈ adopted | vmm_gone | ambiguous.
// Consumed by Task 12's startup wiring.
type Finding struct {
	VMID    string
	Outcome string // "adopted" | "vmm_gone" | "ambiguous"
	Detail  string // human-readable explanation for log/debug
}

// WriteManifestExported is exported for tests that need to create manifest fixtures.
// Internal code uses writeManifest directly.
func WriteManifestExported(stateDir string, m Manifest) error {
	return writeManifest(stateDir, m)
}

// Manifest tracks the resources provisioned for one VM launch. Written
// to <StateDir>/vms/<id>/manifest.json before each external side effect so
// rollback can target exactly the owned resources.
//
// Stages records each completed side-effect phase in order:
//
//	reserved → staged → network → vmm_started → runner_spawned → attached
//
// Each stage is appended AFTER the corresponding operation completes
// (§5.3: persist before the side effect, record after it completes).
type Manifest struct {
	VMID      string `json:"vm_id"`
	BootID    string `json:"boot_id"`
	Slot      int    `json:"slot"`
	UID       int    `json:"uid"` // JailUIDBase + Slot
	GID       int    `json:"gid"`
	CID       uint32 `json:"cid"` // CIDBase + Slot
	CIDR      string `json:"cidr"`
	VMMPID    int    `json:"vmm_pid,omitempty"`
	VMMStart  string `json:"vmm_starttime,omitempty"`
	RunnerPID int    `json:"runner_pid,omitempty"`
	// RunnerStart is /proc/<RunnerPID>/stat field 22 read just after the spawn.
	// It is to RunnerPID what VMMStart is to VMMPID: the pid alone cannot tell a
	// live runner from a recycled pid (SPEC §9.1). Empty when the spawn's read
	// failed or the manifest predates the field; runnerAlive answers those from
	// the runner's argv, and from a bare /proc entry when even that is unreadable.
	RunnerStart string   `json:"runner_starttime,omitempty"`
	Stages      []string `json:"stages"`
}

// Stage name constants live in launch.go (linux) and launch_other.go (stub) —
// they are only needed by the launch transaction implementation.

// manifestPath returns the path to the manifest file for a given state dir and vm_id.
func manifestPath(stateDir, vmID string) string {
	return filepath.Join(stateDir, "vms", vmID, "manifest.json")
}

// writeManifest durably publishes m to <stateDir>/vms/<m.VMID>/manifest.json,
// creating the containing directory if it does not exist.
//
// The manifest is the only record of what a launch has provisioned, and it is
// written before each side effect precisely so a crash leaves rollback a target
// list. That is worth nothing if the record can be lost with the crash, so both
// the directory and the file are made durable and a failed barrier is reported
// rather than swallowed. A caller that gets an error here has to treat the
// launch as unsettled: the manifest on disk may name either stage set.
func writeManifest(stateDir string, m Manifest) error {
	path := manifestPath(stateDir, m.VMID)
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("jailer: marshal manifest: %w", err)
	}
	if err := durable.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("jailer: mkdir manifest dir: %w", err)
	}
	if err := durable.WriteFile(path, 0o600, data); err != nil {
		return fmt.Errorf("jailer: write manifest: %w", err)
	}
	return nil
}

// ReadManifest reads and parses the manifest for vmID from stateDir.
// Exported for tests; internal code uses readManifest.
// Returns os.ErrNotExist if the manifest file is absent.
func ReadManifest(stateDir, vmID string) (Manifest, error) {
	return readManifest(stateDir, vmID)
}

// readManifest reads and parses the manifest for vmID from stateDir.
// Returns os.ErrNotExist if the manifest file is absent.
func readManifest(stateDir, vmID string) (Manifest, error) {
	path := manifestPath(stateDir, vmID)
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("jailer: unmarshal manifest %s: %w", vmID, err)
	}
	return m, nil
}

// allocateSlot scans existing manifests under stateDir/vms/ and returns the slot
// for this vmID. If the vm already has a manifest (stopped VM restarting), its
// existing slot is returned unchanged. Otherwise the lowest free slot < maxSlots
// is returned. Returns ErrSlotsExhausted when all slots are taken.
func allocateSlot(stateDir, vmID string, maxSlots int) (int, error) {
	vmsDir := filepath.Join(stateDir, "vms")

	// Collect all existing manifests.
	entries, err := os.ReadDir(vmsDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, fmt.Errorf("jailer: read vms dir: %w", err)
	}

	takenSlots := make(map[int]bool)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		m, err := readManifest(stateDir, e.Name())
		if err != nil {
			// Missing or corrupt manifest — treat as free.
			continue
		}
		// Restart: this vm_id already has a slot; reuse it.
		if m.VMID == vmID {
			return m.Slot, nil
		}
		takenSlots[m.Slot] = true
	}

	// Find the lowest free slot.
	for slot := 0; slot < maxSlots; slot++ {
		if !takenSlots[slot] {
			return slot, nil
		}
	}
	return 0, ErrSlotsExhausted
}
