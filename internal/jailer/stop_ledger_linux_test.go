// ABOUTME: Tests that a stop reports a cleanup debt only when one is real.
// ABOUTME: privd answering not_found is a missing ledger entry, not a leak.

//go:build linux

package jailer

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/runtime"
)

// stopAdapterWithPrivd is stopOnlyAdapter with a jail base and a privd of the
// caller's choosing: the two things a stop needs to tell a real cleanup debt
// from a missing ledger entry.
func stopAdapterWithPrivd(t *testing.T, pc PrivdClient) (*Adapter, string) {
	t.Helper()
	dir := t.TempDir()
	jailBase := filepath.Join(dir, "jail")
	if err := os.MkdirAll(jailBase, 0o755); err != nil {
		t.Fatalf("mkdir jail base: %v", err)
	}
	return &Adapter{
		cfg: Config{StateDir: filepath.Join(dir, "state"), JailBase: jailBase},
		pc:  pc,
	}, jailBase
}

// TestDoStopReportsNoDebtWhenPrivdHasNoLedgerEntry is the strand. privd's ledger
// lives on a tmpfs (deploy/README.md mounts /run that way), so a restart empties
// it while the jail chroots on the runtime volume survive. Every later stop then
// asked release_vm for a VM the ledger had never heard of and got the ordinary
// typed not_found back.
//
// doRelease has always run that answer through ignoreNotFound and taken its
// verdict from the filesystem; this path did neither, so it reported a cleanup
// debt for a chroot that is not there. Manager.Delete treats ErrCleanupPending as
// a failed force-stop, so the row could never leave "deleting" and its disk
// reservation was never released.
//
// Measured 2026-09-06 on aibox03, after the chroot had already been removed:
//
//	HTTP 500  ... stopped, but its jail chroot could not be reclaimed:
//	privd: not_found: vm not in ledger
func TestDoStopReportsNoDebtWhenPrivdHasNoLedgerEntry(t *testing.T) {
	pc := &ledgerPrivd{} // no entry: release_vm answers not_found
	a, _ := stopAdapterWithPrivd(t, pc)
	writeLiveRunnerManifest(t, a.cfg.StateDir, "vm-empty-ledger")

	_, err := a.doStop(t.Context(), "vm-empty-ledger", 30*time.Second, false)
	if err != nil {
		t.Errorf("doStop: %v; privd has no entry and no chroot is on disk, so there is no debt to report", err)
	}
}

// TestDoStopReportsTheDebtWhenTheChrootSurvives is the other half, and the
// reason not_found cannot simply be ignored here. A lost ledger is exactly the
// state where the chroot does survive -- the entry died with the tmpfs and the
// directory did not -- so the answer from privd proves nothing either way. The
// filesystem does.
func TestDoStopReportsTheDebtWhenTheChrootSurvives(t *testing.T) {
	pc := &ledgerPrivd{} // no entry: release_vm answers not_found
	a, jailBase := stopAdapterWithPrivd(t, pc)
	vmID := "vm-stranded-chroot"
	jailDir := writeOrphanChroot(t, jailBase, vmID)
	writeLiveRunnerManifest(t, a.cfg.StateDir, vmID)

	_, err := a.doStop(t.Context(), vmID, 30*time.Second, false)

	var pending *runtime.ErrCleanupPending
	if !errors.As(err, &pending) {
		t.Fatalf("doStop = %v; want ErrCleanupPending: %s outlived the stop and nothing else records that", err, jailDir)
	}
	if !strings.Contains(pending.Reason, jailDir) {
		t.Errorf("debt reason = %q; want it to name the chroot that survived (%s)", pending.Reason, jailDir)
	}
}
