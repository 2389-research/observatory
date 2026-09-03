// ABOUTME: Tests that Release asks the host when the manifest is gone, instead of reporting success.
// ABOUTME: A missing manifest is exactly the state a failed rollback leaves, chroot and all.

//go:build linux

package jailer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2389-research/observatory-v2/internal/privd"
)

// releaseAdapter builds an Adapter with the four directories doRelease touches.
func releaseAdapter(t *testing.T, pc PrivdClient) (*Adapter, string) {
	t.Helper()
	dir := t.TempDir()
	jailBase := filepath.Join(dir, "jail")
	if err := os.MkdirAll(jailBase, 0o755); err != nil {
		t.Fatalf("mkdir jail base: %v", err)
	}
	return &Adapter{
		cfg: Config{
			StateDir:  filepath.Join(dir, "state"),
			StageRoot: filepath.Join(dir, "stage"),
			JailBase:  jailBase,
		},
		pc: pc,
	}, jailBase
}

// notFound is the typed answer privd gives for a vm_id its ledger has no entry
// for (internal/privd/server.go). Both releases answer it, and for a VM that
// never launched it is the ordinary case, not a failure.
func notFound() error {
	return &privd.RemoteError{Cause: "not_found", Message: "vm not in ledger"}
}

// ledgerPrivd models the half of privd's ledger that decides what a release can
// still reach: one entry per VM, a network half and a VM half, and whichever
// release empties the last half deletes the entry (internal/privd/server.go).
// Its ReleaseVM removes the jail chroot the way RealOps.ReleaseVM does -- an
// unconditional RemoveAll, reached only while the entry exists.
type ledgerPrivd struct {
	entry    bool   // an entry exists in the ledger
	netCIDR  string // network half; "" means already released
	jailDir  string // what ReleaseVM removes
	calls    []string
	releases int
}

func (p *ledgerPrivd) AllocateNetwork(context.Context, privd.AllocateNetworkReq) error {
	return errUnreachablePrivd
}

func (p *ledgerPrivd) StartVM(context.Context, privd.StartVMReq) (privd.StartVMResp, error) {
	return privd.StartVMResp{}, errUnreachablePrivd
}

func (p *ledgerPrivd) SignalVM(context.Context, privd.SignalVMReq) error {
	return errUnreachablePrivd
}

func (p *ledgerPrivd) ReleaseVM(_ context.Context, _ privd.ReleaseVMReq) error {
	p.calls = append(p.calls, "release_vm")
	if !p.entry {
		return notFound()
	}
	p.releases++
	if err := os.RemoveAll(p.jailDir); err != nil {
		return err
	}
	if p.netCIDR == "" {
		p.entry = false
	}
	return nil
}

func (p *ledgerPrivd) ReleaseNetwork(_ context.Context, _ privd.ReleaseNetworkReq) error {
	p.calls = append(p.calls, "release_network")
	if !p.entry {
		return notFound()
	}
	p.netCIDR = ""
	// The VM half of every entry that reaches a manifest-less release is already
	// clear -- the pid is written on a successful start_vm and cleared by
	// release_vm -- so this empties the last half and deletes the entry.
	p.entry = false
	return nil
}

// TestReleaseWithNoManifestAndNoChrootStaysSilent pins the ordinary case. A VM
// that never launched, and one already released, both reach Release with no
// manifest and nothing on disk; privd answers not_found for both verbs. Release
// is documented idempotent, so that has to be nil -- and it has to ask, because
// the answer is what makes it true.
func TestReleaseWithNoManifestAndNoChrootStaysSilent(t *testing.T) {
	pc := &ledgerPrivd{}
	adapter, _ := releaseAdapter(t, pc)

	if err := adapter.doRelease(context.Background(), "vm-never-launched"); err != nil {
		t.Errorf("doRelease with no manifest, no chroot and no ledger entry: %v; want nil", err)
	}
	if len(pc.calls) != 2 {
		t.Errorf("privd calls = %v; want both releases attempted -- a missing manifest proves "+
			"nothing about what privd still holds", pc.calls)
	}
}

// TestReleaseWithNoManifestReclaimsTheOrphanedChroot is the finding. doRollback
// removes the state dir whether or not its own release landed
// (internal/jailer/launch.go), so the manifest can be gone while
// <JailBase>/firecracker/<id> is not. doRelease used to read that as "already
// gone" and return nil, and Delete then wrote "deleted" over a live chroot.
//
// The order is the load-bearing part: release_network on an entry whose VM half
// is already clear deletes the ledger entry, and release_vm would then answer
// not_found and never remove the tree.
func TestReleaseWithNoManifestReclaimsTheOrphanedChroot(t *testing.T) {
	pc := &ledgerPrivd{entry: true, netCIDR: "10.0.0.0/30"}
	adapter, jailBase := releaseAdapter(t, pc)
	vmID := "vm-orphaned-release"
	pc.jailDir = writeOrphanChroot(t, jailBase, vmID)

	if err := adapter.doRelease(context.Background(), vmID); err != nil {
		t.Fatalf("doRelease: %v; privd could reach both halves, so this had to succeed", err)
	}
	if _, statErr := os.Stat(pc.jailDir); !os.IsNotExist(statErr) {
		t.Errorf("jail chroot %s survived the release (stat err: %v)", pc.jailDir, statErr)
	}
	if len(pc.calls) < 1 || pc.calls[0] != "release_vm" {
		t.Errorf("privd calls = %v; release_vm has to run first: release_network empties the last "+
			"half of the entry and privd deletes it, after which release_vm answers not_found "+
			"and the chroot is unreachable forever", pc.calls)
	}
	if pc.releases != 1 {
		t.Errorf("release_vm calls that reached the ledger = %d, want 1", pc.releases)
	}
}

// TestReleaseWithNoManifestReportsASurvivingChroot: when the teardown cannot
// land, the resource outlives the record and Release must say so. Delete leaves
// the row at "deleting" on any error, which is the R1 invariant -- no row reads
// "deleted" while what Release owns survives it (internal/runtime/manager.go).
func TestReleaseWithNoManifestReportsASurvivingChroot(t *testing.T) {
	adapter, jailBase := releaseAdapter(t, &unreachablePrivd{})
	vmID := "vm-unreleasable"
	jailDir := writeOrphanChroot(t, jailBase, vmID)

	err := adapter.doRelease(context.Background(), vmID)
	if err == nil {
		t.Fatalf("doRelease returned success for %s: its manifest is gone but %s is still on disk",
			vmID, jailDir)
	}
	if !strings.Contains(err.Error(), jailDir) {
		t.Errorf("error = %q; want it to name the chroot that survived (%s)", err, jailDir)
	}
	if _, statErr := os.Stat(jailDir); statErr != nil {
		t.Errorf("stat %s: %v; the test's own premise is broken", jailDir, statErr)
	}
}

// TestReleaseWithNoManifestRemovesTheStageAndStateDirs: the manifest is one file
// in <StateDir>/vms/<id>/, and the rest of that directory -- the runner's
// §15.3 auth token among it -- outlives it. A release that skipped them left
// both behind.
func TestReleaseWithNoManifestRemovesTheStageAndStateDirs(t *testing.T) {
	pc := &ledgerPrivd{}
	adapter, _ := releaseAdapter(t, pc)
	vmID := "vm-leftover-dirs"

	stageDir := filepath.Join(adapter.cfg.StageRoot, vmID)
	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		t.Fatalf("mkdir stage dir: %v", err)
	}
	vmStateDir := filepath.Join(adapter.cfg.StateDir, "vms", vmID)
	if err := os.MkdirAll(vmStateDir, 0o755); err != nil {
		t.Fatalf("mkdir vm state dir: %v", err)
	}
	// Everything but the manifest: this is the state a failed rollback leaves if
	// it removed manifest.json and stopped there.
	if err := os.WriteFile(filepath.Join(vmStateDir, "token"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	if err := adapter.doRelease(context.Background(), vmID); err != nil {
		t.Fatalf("doRelease: %v; want nil", err)
	}
	if _, statErr := os.Stat(stageDir); !os.IsNotExist(statErr) {
		t.Errorf("stage dir %s survived the release (stat err: %v)", stageDir, statErr)
	}
	if _, statErr := os.Stat(vmStateDir); !os.IsNotExist(statErr) {
		t.Errorf("vm state dir %s survived the release, auth token and all (stat err: %v)",
			vmStateDir, statErr)
	}
}

// TestReleaseWithManifestReclaimsTheJailChroot is the leak itself. doRelease
// used to read a present manifest as reason enough to skip release_vm, so
// <JailBase>/firecracker/<id> and its privd ledger entry outlived a VM that
// shut itself down: Manager.NotifyVMMExit reaches "stopped" with no runtime
// call at all (internal/runtime/manager.go), so the manifest is untouched
// when Delete's force-stop skips it and goes straight to Release. This is
// the state that leaves behind -- every stage a normal launch records, and a
// chroot nothing has asked privd to remove.
//
// The order matters the same way it does with no manifest at all: an entry
// whose VM half is already clear has release_network as its last occupied
// half, so calling that first deletes the ledger entry and release_vm then
// answers not_found without ever removing the tree.
func TestReleaseWithManifestReclaimsTheJailChroot(t *testing.T) {
	pc := &ledgerPrivd{entry: true, netCIDR: "10.0.0.0/30"}
	adapter, jailBase := releaseAdapter(t, pc)
	vmID := "vm-self-shutdown"
	pc.jailDir = writeOrphanChroot(t, jailBase, vmID)

	m := Manifest{
		VMID:   vmID,
		Slot:   0,
		UID:    os.Getuid(),
		GID:    os.Getgid(),
		CID:    5,
		CIDR:   "10.0.0.0/30",
		Stages: []string{stageReserved, stageStaged, stageNetwork, stageVMMStarted, stageRunnerSpawned, stageAttached},
	}
	if err := writeManifest(adapter.cfg.StateDir, m); err != nil {
		t.Fatalf("writeManifest: %v", err)
	}

	if err := adapter.doRelease(context.Background(), vmID); err != nil {
		t.Fatalf("doRelease: %v; privd could reach both halves, so this had to succeed", err)
	}
	if _, statErr := os.Stat(pc.jailDir); !os.IsNotExist(statErr) {
		t.Errorf("jail chroot %s survived the release (stat err: %v)", pc.jailDir, statErr)
	}
	if len(pc.calls) < 1 || pc.calls[0] != "release_vm" {
		t.Errorf("privd calls = %v; release_vm has to run first: release_network empties the last "+
			"half of the entry and privd deletes it, after which release_vm answers not_found "+
			"and the chroot is unreachable forever", pc.calls)
	}
	if pc.releases != 1 {
		t.Errorf("release_vm calls that reached the ledger = %d, want 1", pc.releases)
	}
}

// TestReleaseWithManifestReportsASurvivingChroot: a present manifest must not
// change the verdict when the teardown cannot land. The chroot outlives the
// record either way, and Release has to say so rather than let Delete write
// "deleted" over it.
func TestReleaseWithManifestReportsASurvivingChroot(t *testing.T) {
	adapter, jailBase := releaseAdapter(t, &unreachablePrivd{})
	vmID := "vm-manifest-unreleasable"
	jailDir := writeOrphanChroot(t, jailBase, vmID)

	m := Manifest{
		VMID:   vmID,
		Stages: []string{stageReserved, stageStaged, stageNetwork, stageVMMStarted, stageRunnerSpawned, stageAttached},
	}
	if err := writeManifest(adapter.cfg.StateDir, m); err != nil {
		t.Fatalf("writeManifest: %v", err)
	}

	err := adapter.doRelease(context.Background(), vmID)
	if err == nil {
		t.Fatalf("doRelease returned success for %s: its manifest lists every stage but %s is still on disk",
			vmID, jailDir)
	}
	if !strings.Contains(err.Error(), jailDir) {
		t.Errorf("error = %q; want it to name the chroot that survived (%s)", err, jailDir)
	}
	if _, statErr := os.Stat(jailDir); statErr != nil {
		t.Errorf("stat %s: %v; the test's own premise is broken", jailDir, statErr)
	}
}

// TestReleaseIgnoresStageRecordAndReleasesBothResources pins the lesson
// behind every fix wave on this branch: a manifest's Stages list is a record
// of what launch.go believed it had done, not evidence about what privd or
// the filesystem still hold. launch.go sets currentStage = stageVMMStarted
// before it calls StartVM and appends stageVMMStarted to the manifest only
// after (internal/jailer/launch.go), so a VMM can be running -- and a netns
// allocated -- with neither stage recorded. A manifest missing both stages,
// with both resources present anyway, still has to see both release verbs
// run and both resources go.
func TestReleaseIgnoresStageRecordAndReleasesBothResources(t *testing.T) {
	pc := &ledgerPrivd{entry: true, netCIDR: "10.0.0.0/30"}
	adapter, jailBase := releaseAdapter(t, pc)
	vmID := "vm-unrecorded-stages"
	pc.jailDir = writeOrphanChroot(t, jailBase, vmID)

	m := Manifest{
		VMID:   vmID,
		Stages: []string{stageReserved, stageStaged}, // vmm_started and network omitted
	}
	if err := writeManifest(adapter.cfg.StateDir, m); err != nil {
		t.Fatalf("writeManifest: %v", err)
	}

	if err := adapter.doRelease(context.Background(), vmID); err != nil {
		t.Fatalf("doRelease: %v; privd could reach both halves, so this had to succeed", err)
	}

	var sawReleaseVM, sawReleaseNetwork bool
	for _, c := range pc.calls {
		switch c {
		case "release_vm":
			sawReleaseVM = true
		case "release_network":
			sawReleaseNetwork = true
		}
	}
	if !sawReleaseVM {
		t.Error("release_vm was never called: the manifest's Stages omitted vmm_started")
	}
	if !sawReleaseNetwork {
		t.Error("release_network was never called: the manifest's Stages omitted network")
	}
	if _, statErr := os.Stat(pc.jailDir); !os.IsNotExist(statErr) {
		t.Errorf("jail chroot %s survived the release: stages omitted vmm_started, so a guard "+
			"on the record would have skipped release_vm (stat err: %v)", pc.jailDir, statErr)
	}
	if pc.netCIDR != "" {
		t.Errorf("network half of the ledger entry still held (%q): stages omitted network, "+
			"so a guard on the record would have skipped release_network", pc.netCIDR)
	}
}
