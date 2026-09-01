// ABOUTME: Runner state type, atomic write (tempfile+fsync+rename), and ReadState.
// ABOUTME: State is the primary observable for the adapter (Task 10) polling this runner.
package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Phase constants — the brief's five exact strings.
const (
	PhaseStarting  = "starting"
	PhaseAttached  = "attached"
	PhaseDegraded  = "degraded"
	PhaseVMMExited = "vmm_exited"
	PhaseFinalized = "finalized"
)

// State is the runner's observable state, written atomically on every phase
// change and at each ping cycle. The spawn argv and struct fields are consumed
// verbatim by Task 10 — do not rename fields.
type State struct {
	VMID          string `json:"vm_id"`
	BootID        string `json:"boot_id"`
	InstanceID    string `json:"instance_id"`
	RunnerPID     int    `json:"runner_pid"`
	VMMPID        int    `json:"vmm_pid"`
	VMMStartTime  string `json:"vmm_starttime"` // decimal ticks, from privd StartVMResp
	Phase         string `json:"phase"`         // starting | attached | degraded | vmm_exited | finalized
	UpdatedAtUnix int64  `json:"updated_at_unix"`
}

// ReadState reads and unmarshals the state from path.
func ReadState(path string) (State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return State{}, fmt.Errorf("runner: read state: %w", err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return State{}, fmt.Errorf("runner: unmarshal state: %w", err)
	}
	return s, nil
}

// WriteState writes s atomically to path using tempfile+fsync+rename.
// It matches the writeCursor discipline from internal/spool: write, fsync,
// close, rename — durable before visible.
func WriteState(path string, s State) error {
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("runner: marshal state: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "runner-state-*.tmp")
	if err != nil {
		return fmt.Errorf("runner: create state temp: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("runner: write state temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("runner: fsync state temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("runner: close state temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("runner: rename state: %w", err)
	}
	return nil
}
