// ABOUTME: Tests that doStop probes the host when the manifest is gone, instead of reporting success.
// ABOUTME: An orphaned jail chroot means the VM may still be running behind a "stopped" row.

//go:build linux

package jailer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2389-research/observatory-v2/internal/privd"
)

// errUnreachablePrivd is what a verb answers when no root daemon is behind the
// client, the same condition unreachablePrivd models.
var errUnreachablePrivd = errors.New("privd unreachable in test")

// orphanAdapter builds an Adapter with the two directories stopWithoutManifest
// reads, and returns its jail base. pc decides what the release does.
func orphanAdapter(t *testing.T, pc PrivdClient) (*Adapter, string) {
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

// writeOrphanChroot creates the jail chroot a failed rollback leaves behind: the
// directory privd's start_vm built, with no manifest anywhere naming it.
func writeOrphanChroot(t *testing.T, jailBase, vmID string) string {
	t.Helper()
	jailDir := filepath.Join(jailBase, "firecracker", vmID)
	if err := os.MkdirAll(filepath.Join(jailDir, "root"), 0o755); err != nil {
		t.Fatalf("mkdir jail chroot: %v", err)
	}
	if err := os.WriteFile(filepath.Join(jailDir, "root", "rootfs.ext4"), []byte("rootfs"), 0o600); err != nil {
		t.Fatalf("write rootfs: %v", err)
	}
	return jailDir
}

// TestStopWithNoManifestAndNoChrootIsANoOp pins the case that must stay silent.
// A VM that never launched, one that stopped cleanly and was then released, and one
// that was deleted all reach doStop with no manifest and nothing on disk. If the
// probe answered anything but (false, nil) here it would turn every ordinary stop
// into an error.
func TestStopWithNoManifestAndNoChrootIsANoOp(t *testing.T) {
	adapter, _ := orphanAdapter(t, &unreachablePrivd{})

	forced, err := adapter.doStop(context.Background(), "vm-never-launched", 0, false)
	if err != nil {
		t.Errorf("doStop with no manifest and no jail chroot: %v; want nil (idempotent no-op)", err)
	}
	if forced {
		t.Error("doStop reported a forced stop for a VM that does not exist")
	}
}

// TestStopWithNoManifestButLiveChrootDoesNotReportSuccess is the finding. doRollback
// deletes the manifest unconditionally while its own release can fail, so the chroot
// -- and the microVM inside it -- can outlive the record. doStop used to read the
// missing manifest as "already gone" and return (false, nil); Release then
// early-returns nil on the same missing manifest and Delete writes "deleted" over a
// running VM, every call in the chain reporting success.
//
// Here privd is unreachable, so the teardown cannot land and the chroot is still
// there when doStop looks again. The answer must be an error that names it.
func TestStopWithNoManifestButLiveChrootDoesNotReportSuccess(t *testing.T) {
	adapter, jailBase := orphanAdapter(t, &unreachablePrivd{})
	vmID := "vm-orphaned-chroot"
	jailDir := writeOrphanChroot(t, jailBase, vmID)

	_, err := adapter.doStop(context.Background(), vmID, 0, true)
	if err == nil {
		t.Fatalf("doStop returned success for %s: its manifest is gone but %s is still on disk, "+
			"so the VM may still be running", vmID, jailDir)
	}
	if !strings.Contains(err.Error(), jailDir) {
		t.Errorf("error = %q; want it to name the chroot that survived (%s)", err, jailDir)
	}

	// The verdict has to match the host: the chroot really is still there.
	if _, statErr := os.Stat(jailDir); statErr != nil {
		t.Errorf("stat %s after the failed teardown: %v; the test's own premise is broken", jailDir, statErr)
	}
}

// TestStopWithNoManifestReclaimsTheChroot: when the release lands, the resource is
// gone and the honest answer is success. The verdict comes from the filesystem after
// the release, not from what privd returned -- a release that reports nil while the
// chroot survives is still a failure.
func TestStopWithNoManifestReclaimsTheChroot(t *testing.T) {
	pc := &reclaimingPrivd{}
	adapter, jailBase := orphanAdapter(t, pc)
	vmID := "vm-reclaimed-chroot"
	jailDir := writeOrphanChroot(t, jailBase, vmID)
	pc.remove = jailDir

	forced, err := adapter.doStop(context.Background(), vmID, 0, true)
	if err != nil {
		t.Fatalf("doStop after a release that reclaimed %s: %v; want nil", jailDir, err)
	}
	if !forced {
		t.Error("forced = false; nothing asked the guest anything, so the stop was forced")
	}
	if _, statErr := os.Stat(jailDir); !os.IsNotExist(statErr) {
		t.Errorf("jail chroot %s still present (stat err: %v)", jailDir, statErr)
	}
	if pc.signals != 1 {
		t.Errorf("signal_vm calls = %d, want 1 (SIGKILL before the release, which privd "+
			"refuses while it can still see the process)", pc.signals)
	}
	if pc.releases != 1 {
		t.Errorf("release_vm calls = %d, want 1", pc.releases)
	}
}

// reclaimingPrivd stands in for the root daemon a unit test cannot run: its
// release_vm removes the chroot the way privd's RealOps.ReleaseVM does
// (internal/privd/vmops.go). Every other verb is unreachable, as in
// unreachablePrivd -- doStop calls none of them on this path.
type reclaimingPrivd struct {
	remove   string
	signals  int
	releases int
}

func (p *reclaimingPrivd) AllocateNetwork(context.Context, privd.AllocateNetworkReq) error {
	return errUnreachablePrivd
}

func (p *reclaimingPrivd) ReleaseNetwork(context.Context, privd.ReleaseNetworkReq) error {
	return errUnreachablePrivd
}

func (p *reclaimingPrivd) StartVM(context.Context, privd.StartVMReq) (privd.StartVMResp, error) {
	return privd.StartVMResp{}, errUnreachablePrivd
}

func (p *reclaimingPrivd) SignalVM(context.Context, privd.SignalVMReq) error {
	p.signals++
	return nil
}

func (p *reclaimingPrivd) ReleaseVM(context.Context, privd.ReleaseVMReq) error {
	p.releases++
	return os.RemoveAll(p.remove)
}
