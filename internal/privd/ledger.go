// ABOUTME: Persistent ledger for privd: each VM's entry lives in <LedgerDir>/<vm_id>.json.
// ABOUTME: Durable atomic publication, 0600 permissions, single-writer (server mutex).
package privd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/2389-research/observatory-v2/internal/durable"
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
//
// Writes go through internal/durable, so a reader after any crash sees a
// complete entry or none — never a torn one whose uid, cid and pid could be
// handed to a second VM.
//
// Honest limit on what that buys here. The deployed ledger directory is
// /run/vmobs/privd, a tmpfs (M1a decision D8: VMs never survive a host reboot,
// so a record that clears at reboot is the correct one, and §5.5 cold reconcile
// reads the resulting empty ledger). fsync on a tmpfs is a no-op that returns
// success, so on the deployed path these barriers cost nothing and prove
// nothing about power loss. What they do buy is that the ledger stays correct
// if --ledger-dir is ever pointed at a real filesystem, rather than being
// correct only by accident of where systemd puts /run.
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

// put publishes entry durably with 0600 permissions. An error means the entry
// is unsettled: the caller does not know whether the old record or the new one
// is on disk, and must not act on either.
func (l *ledger) put(entry VMEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("ledger encode %s: %w", entry.VMID, err)
	}
	if err := durable.WriteFile(l.path(entry.VMID), 0o600, data); err != nil {
		return fmt.Errorf("ledger write %s: %w", entry.VMID, err)
	}
	return nil
}

// delete removes the ledger file for vmID. Returns nil if already absent, and
// an error if the removal happened but could not be made durable — the caller
// must not reclaim the identities the entry named on that answer.
func (l *ledger) delete(vmID string) error {
	if err := durable.Remove(l.path(vmID)); err != nil {
		return fmt.Errorf("ledger delete %s: %w", vmID, err)
	}
	return nil
}
