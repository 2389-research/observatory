// ABOUTME: Persistent ledger for privd: each VM's entry lives in <LedgerDir>/<vm_id>.json.
// ABOUTME: Durable atomic publication, 0600 permissions, single-writer (server mutex).
package privd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/2389-research/observatory/internal/durable"
	"golang.org/x/sys/unix"
)

// VMEntry holds the per-VM identity and resource record stored in the ledger.
type VMEntry struct {
	// StartAttempted distinguishes pre-exec debris from a launch requiring process-exit proof.
	StartAttempted bool   `json:"-"`
	NetworkOpID    string `json:"network_op_id,omitempty"`
	StartOpID      string `json:"start_op_id,omitempty"`
	VMID           string `json:"vm_id"`
	UID            int    `json:"uid"`
	GID            int    `json:"gid"`
	CID            uint32 `json:"cid"`
	PID            int    `json:"pid"`
	StartTime      string `json:"start_time"` // decimal string: /proc/<pid>/stat field 22
	BootID         string `json:"boot_id"`
	PIDNamespace   string `json:"pid_namespace"`
	NetCIDR        string `json:"net_cidr"`
	CreatedAtUnix  int64  `json:"created_at_unix"`
}

// ledger manages per-VM JSON files in a directory.
// All methods must be called with the server mutex held.
//
// Writes go through internal/durable, so a reader after any crash sees a
// complete entry or none — never a torn one whose uid, cid and pid could be
// handed to a second VM.
//
// The deployed directory lives on the runtime volume and survives appliance
// replacement. BootID and PIDNamespace bound process identity before any PID
// observation can authorize signaling or resource cleanup.
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
	data, err := readOwnershipFile(l.path(vmID))
	if err != nil {
		return VMEntry{}, err
	}
	var e VMEntry
	if err := json.Unmarshal(data, &e); err != nil {
		return VMEntry{}, fmt.Errorf("ledger decode %s: %w", vmID, err)
	}
	if e.VMID != vmID || e.PID < 0 {
		return VMEntry{}, fmt.Errorf("ledger %s: invalid ownership record", vmID)
	}
	// Network-only records carry no VM ownership fields. A missing PID in an
	// otherwise populated VM record is corruption, never evidence of exit.
	if e.PID == 0 {
		if e.UID != 0 || e.GID != 0 || e.CID != 0 || e.StartTime != "" || e.BootID != "" || e.PIDNamespace != "" {
			return VMEntry{}, fmt.Errorf("ledger %s: incomplete process ownership", vmID)
		}
	} else if _, err := strconv.ParseUint(e.StartTime, 10, 64); err != nil || e.CID < minGuestCID || e.UID < 0 || e.GID < 0 {
		return VMEntry{}, fmt.Errorf("ledger %s: incomplete process ownership", vmID)
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

// all returns every entry in the ledger, and fails naming any file it cannot
// read. An entry that will not parse held a subnet, a uid and a CID, and which
// ones is now unknown; callers use this to refuse a claim, so unknown must not
// read as free.
//
// A file is a VM record only when its name is <valid vm_id>.json. get() never
// had to care -- it addresses one name it was handed -- but a scan meets
// whatever else is in the directory, including the ".publish-*.tmp" file
// durable.WriteFile leaves behind if it crashes between create and rename.
// Every write path validates the vm_id first, so nothing this rejects was ever
// written by privd.
// LedgerLockName is the file vmobs-privd flocks inside its ledger directory to
// prove it is the only privd on this host (cmd/vmobs-privd/singleton.go). It
// lives here, beside the scan that has to ignore it, so the two cannot drift
// apart: ValidVMID drops it on the leading dot, and TestAllocateNetworkIgnores-
// DebrisInTheLedgerDirectory plants it by this name to keep that true.
const LedgerLockName = ".privd.lock"

func (l *ledger) all() ([]VMEntry, error) {
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("ledger scan: %w", err)
	}
	var out []VMEntry
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		if !ValidVMID(id) {
			continue
		}
		entry, err := l.get(id)
		if err != nil {
			return nil, fmt.Errorf("ledger scan: %s: %w", id, err)
		}
		out = append(out, entry)
	}
	return out, nil
}

func readOwnershipFile(name string) ([]byte, error) {
	// Refuse links and non-regular files before reading, then check the opened
	// inode. Only privd's uid may supply persistent signaling authority.
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || stat.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("ledger %s: untrusted ownership file", name)
	}
	data, err := io.ReadAll(io.LimitReader(f, 2*MaxMsgBytes+1))
	if len(data) > 2*MaxMsgBytes {
		return nil, fmt.Errorf("ownership record exceeds size bound")
	}
	return data, err
}
