// ABOUTME: Persistent ledger for privd: each VM's entry lives in <LedgerDir>/<vm_id>.json.
// ABOUTME: Atomic tempfile+rename writes, 0600 permissions, single-writer (server mutex).
package privd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// VMEntry holds the per-VM identity and resource record stored in the ledger.
type VMEntry struct {
	VMID          string `json:"vm_id"`
	UID           int    `json:"uid"`
	GID           int    `json:"gid"`
	CID           uint32 `json:"cid"`
	PID           int    `json:"pid"`
	StartTime     string `json:"start_time"` // decimal string: /proc/<pid>/stat field 22
	NetCIDR       string `json:"net_cidr"`
	CreatedAtUnix int64  `json:"created_at_unix"`
}

// ledger manages per-VM JSON files in a directory.
// All methods must be called with the server mutex held.
type ledger struct {
	dir string
}

func newLedger(dir string) *ledger {
	return &ledger{dir: dir}
}

func (l *ledger) path(vmID string) string {
	return filepath.Join(l.dir, vmID+".json")
}

// get returns the entry for vmID, or an error wrapping fs.ErrNotExist if absent.
func (l *ledger) get(vmID string) (VMEntry, error) {
	data, err := os.ReadFile(l.path(vmID))
	if err != nil {
		return VMEntry{}, err
	}
	var e VMEntry
	if err := json.Unmarshal(data, &e); err != nil {
		return VMEntry{}, fmt.Errorf("ledger decode %s: %w", vmID, err)
	}
	return e, nil
}

// put writes entry atomically (tempfile+rename) with 0600 permissions.
func (l *ledger) put(entry VMEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("ledger encode %s: %w", entry.VMID, err)
	}
	tmp, err := os.CreateTemp(l.dir, ".ledger-*.tmp")
	if err != nil {
		return fmt.Errorf("ledger tempfile %s: %w", entry.VMID, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("ledger write %s: %w", entry.VMID, err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("ledger chmod %s: %w", entry.VMID, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("ledger close %s: %w", entry.VMID, err)
	}
	if err := os.Rename(tmpName, l.path(entry.VMID)); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("ledger rename %s: %w", entry.VMID, err)
	}
	return nil
}

// delete removes the ledger file for vmID. Returns nil if already absent.
func (l *ledger) delete(vmID string) error {
	err := os.Remove(l.path(vmID))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("ledger delete %s: %w", vmID, err)
	}
	return nil
}
