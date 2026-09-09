// ABOUTME: Launch transaction: §5.3 manifest-tracked staging, network, VMM start, runner, attach wait.
// ABOUTME: Ordered rollback on failure; exactly one outstanding launch at a time (launchMu).

//go:build linux

package jailer

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/2389-research/observatory/internal/durable"
	"github.com/2389-research/observatory/internal/guest"
	"github.com/2389-research/observatory/internal/guest/proto"
	"github.com/2389-research/observatory/internal/lock"
	"github.com/2389-research/observatory/internal/privd"
	"github.com/2389-research/observatory/internal/runner"
	"github.com/2389-research/observatory/internal/runtime"
)

// readyTimeout and readyBackoff mirror the M0 fixture's values (D5: the jailer package
// owns its own copy — do not import the test fixture from production code).
const (
	readyTimeout  = 60 * time.Second
	readyBackoff  = 500 * time.Millisecond
	configDiskMiB = 1 // config.ext4 size in MiB
)

// Stage name constants for the provisioning manifest (§5.3 ordered side-effect stages).
// Linux-only: the non-linux stub (launch_other.go) never references stage names.
const (
	stageReserved      = "reserved"
	stageStaged        = "staged"
	stageNetwork       = "network"
	stageVMMStarted    = "vmm_started"
	stageRunnerSpawned = "runner_spawned"
	stageAttached      = "attached"
)

// Launch executes the §5.3 launch transaction for the given VMSpec and reports
// the images it staged — the lock entries doStage verified the copied bytes
// against, which is the only honest answer to what this boot runs: the lock file
// is read fresh at stage time and can differ from the one the daemon loaded.
// Exactly one Launch call executes at a time; concurrent calls queue on launchMu.
func (a *Adapter) Launch(ctx context.Context, spec runtime.VMSpec) (*lock.Images, error) {
	return a.launchBounded(ctx, spec, a.launch)
}

// launch is the real implementation, called with launchMu held.
func (a *Adapter) launch(ctx context.Context, spec runtime.VMSpec) (*lock.Images, error) {
	vmID := spec.VMID
	if err := a.restoreNetworkLeases(); err != nil {
		return nil, fmt.Errorf("launch %s failed at stage reserved: %w", vmID, err)
	}

	// ── Step 1: Slot ──────────────────────────────────────────────────────────
	slot, err := allocateSlot(a.cfg.StateDir, vmID, a.cfg.MaxSlots)
	if err != nil {
		return nil, fmt.Errorf("launch %s failed at stage reserved: %w", vmID, err)
	}

	uid := a.cfg.JailUIDBase + slot
	gid := a.cfg.JailGID
	cid := a.cfg.CIDBase + uint32(slot)

	// Whether a failed publication may remove the state directory depends on
	// whether an earlier manifest lived there before this launch.
	_, existingErr := readManifest(a.cfg.StateDir, vmID)

	// ── Step 2: Manifest (reserved) ───────────────────────────────────────────
	bootID := spec.BootID
	if bootID == "" {
		bootID, err = newUUID()
		if err != nil {
			return nil, fmt.Errorf("launch %s failed at stage reserved: generate boot ID: %w", vmID, err)
		}
	}

	vmStateDir := filepath.Join(a.cfg.StateDir, "vms", vmID)
	if err := durable.MkdirAll(vmStateDir, 0o700); err != nil {
		return nil, fmt.Errorf("launch %s failed at stage reserved: mkdir state dir: %w", vmID, err)
	}
	prefix, err := a.cfg.Allocator.Acquire(vmID)
	if err != nil {
		return nil, fmt.Errorf("launch %s failed at stage reserved: allocate CIDR: %w", vmID, err)
	}
	cidr := prefix.String()
	m := Manifest{
		VMID: vmID, BootID: bootID, Slot: slot, UID: uid, GID: gid, CID: cid, CIDR: cidr,
		Stages: []string{},
	}

	m.Stages = append(m.Stages, stageReserved)
	if err := writeManifest(a.cfg.StateDir, m); err != nil {
		// No manifest, so doRollback would find nothing to read: reclaim the
		// state dir the mkdir above made — but only for a fresh VM. On a restart
		// the dir holds the previous launch's manifest, which writeManifest left
		// intact and which Release still needs to find the network it must free.
		if os.IsNotExist(existingErr) {
			if err := durable.RemoveAll(vmStateDir); err == nil {
				a.cfg.Allocator.Release(vmID)
			}
		}
		return nil, fmt.Errorf("launch %s failed at stage reserved: write manifest: %w", vmID, err)
	}

	// Rollback state is tracked by manifest.Stages; rollback runs in reverse.
	// currentStage names the stage being attempted when a failure occurs so the
	// error message surfaces which step failed (§5.3).
	currentStage := stageReserved
	rollback := func(stageErr error) error {
		rescued := a.doRollback(vmID)
		if rescued == "" {
			return fmt.Errorf("launch %s failed at stage %s: %w", vmID, currentStage, stageErr)
		}
		// The stage says which step failed; the archive is the only place the
		// answer to "why" survives the rollback that just removed the state dir.
		return fmt.Errorf("launch %s failed at stage %s: %w; runner output rescued to %s",
			vmID, currentStage, stageErr, rescued)
	}

	// ── Step 3: Stage ─────────────────────────────────────────────────────────
	currentStage = stageStaged
	stageDir := filepath.Join(a.cfg.StageRoot, vmID)
	staged, stageErr := a.doStage(ctx, vmID, bootID, cid, uid, gid, stageDir, prefix, spec)
	if stageErr != nil {
		// doRollback removes the state dir and whatever doStage left in the stage dir.
		return nil, rollback(stageErr)
	}
	m.Stages = append(m.Stages, stageStaged)
	if err := writeManifest(a.cfg.StateDir, m); err != nil {
		return nil, rollback(err)
	}

	// ── Step 4: Network ───────────────────────────────────────────────────────
	currentStage = stageNetwork
	if err := a.pc.AllocateNetwork(ctx, privd.AllocateNetworkReq{
		VMID:        vmID,
		CIDR:        cidr,
		Profile:     spec.NetworkProfile,
		PolicyID:    spec.NetworkPolicyID,
		GuestBootID: bootID,
	}); err != nil {
		return nil, rollback(fmt.Errorf("allocate_network: %w", err))
	}
	m.Stages = append(m.Stages, stageNetwork)
	if err := writeManifest(a.cfg.StateDir, m); err != nil {
		return nil, rollback(err)
	}

	// ── Step 5: VMM ───────────────────────────────────────────────────────────
	currentStage = stageVMMStarted
	// Compute SHA-256s of the staged files for privd's TOCTOU-safe staging, and
	// hold the two lock-backed ones to the digests staged carries back from the
	// lock this launch read.
	stagedFiles, err := computeStagedFiles(stageDir, map[string]string{
		"vmlinux":     staged.GuestKernel.VmlinuxSHA256,
		"rootfs.ext4": staged.RootImage.SHA256,
	})
	if err != nil {
		return nil, rollback(fmt.Errorf("compute staged file hashes: %w", err))
	}

	m.StartOpID = uuid.NewString()
	if err := writeManifest(a.cfg.StateDir, m); err != nil {
		return nil, rollback(err)
	}
	startResp, err := a.pc.StartVM(privd.WithOperationID(ctx, m.StartOpID), privd.StartVMReq{
		VMID:     vmID,
		UID:      uid,
		GID:      gid,
		CID:      cid,
		StageDir: stageDir,
		Files:    stagedFiles,
	})
	if err != nil {
		var unknown *privd.UnknownOutcomeError
		if errors.As(err, &unknown) {
			return nil, fmt.Errorf("start_vm: %w", err)
		}
		m.StartOpID = ""
		if writeErr := writeManifest(a.cfg.StateDir, m); writeErr != nil {
			return nil, fmt.Errorf("start_vm: %w; retain manifest: %v", err, writeErr)
		}
		return nil, rollback(fmt.Errorf("start_vm: %w", err))
	}
	m.VMMPID = startResp.PID
	m.VMMStart = startResp.StartTime
	m.Stages = append(m.Stages, stageVMMStarted)
	if err := writeManifest(a.cfg.StateDir, m); err != nil {
		return nil, rollback(err)
	}

	// ── Step 6: Runner ────────────────────────────────────────────────────────
	currentStage = stageRunnerSpawned
	instanceID, err := newUUID()
	if err != nil {
		return nil, rollback(fmt.Errorf("generate instance ID: %w", err))
	}

	// vSock path: the adapter polls runner-state.json for the attached phase;
	// the runner connects to this UDS to speak to guestd.
	stateFile := filepath.Join(vmStateDir, "runner-state.json")
	runnerLog := filepath.Join(vmStateDir, "runner.log")

	logFile, err := os.OpenFile(runnerLog, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, rollback(fmt.Errorf("open runner log: %w", err))
	}

	cmd, err := a.startRunner(ctx, m, instanceID, logFile)
	if err != nil {
		logFile.Close()
		return nil, rollback(fmt.Errorf("spawn runner: %w", err))
	}
	logFile.Close()

	m.RunnerPID = cmd.Process.Pid
	m.RunnerStart = readRunnerStart(cmd.Process.Pid)
	m.Stages = append(m.Stages, stageRunnerSpawned)
	if err := writeManifest(a.cfg.StateDir, m); err != nil {
		return nil, rollback(err)
	}

	// ── Step 7: Attach wait ───────────────────────────────────────────────────
	currentStage = stageAttached
	attachTimeout := a.cfg.AttachTimeout
	if attachTimeout <= 0 {
		attachTimeout = readyTimeout
	}
	attachCtx, attachCancel := context.WithTimeout(ctx, attachTimeout)
	defer attachCancel()

	attachErr := a.waitAttached(attachCtx, stateFile, cmd)
	if attachErr != nil {
		return nil, rollback(attachErr)
	}
	m.Stages = append(m.Stages, stageAttached)
	if err := writeManifest(a.cfg.StateDir, m); err != nil {
		// Attached successfully but manifest write failed — best-effort log and proceed.
		// The runner is running; Task 11's Reconcile owns recovery for the missing stage record.
		fmt.Fprintf(os.Stderr, "jailer: warn: failed to record attached stage for %s: %v\n", vmID, err)
	}

	return &staged, nil
}

// doStage builds the staging directory for the VM:
//  1. Copy vmlinux + rootfs.ext4 from paths recorded in the lock (resolved against RepoRoot),
//     verifying SHA-256 against the lock's pinned hashes.
//  2. Generate a per-boot token, write to token file, and build config.ext4.
//  3. Create workspace.ext4.
//  4. Write fc-config.json.
func (a *Adapter) doStage(ctx context.Context, vmID, bootID string, cid uint32, uid, gid int, stageDir string, transit netip.Prefix, spec runtime.VMSpec) (lock.Images, error) {
	// Load and verify lock artifacts.
	lk, err := lock.Load(a.cfg.LockPath)
	if err != nil {
		return lock.Images{}, fmt.Errorf("load lock: %w", err)
	}
	// RepoRoot is the directory the lock's artifact paths resolve against.
	// Lock paths like "images/dist/vmlinux" are relative to it — one source of truth.
	repoRoot := a.cfg.RepoRoot

	// Open both artifacts before creating anything: an admission refusal must
	// leave no stage directory behind, and neither artifact should be copied if
	// the other one is going to be refused.
	//
	// The descriptors, not the paths, are what gets copied below. Verifying a
	// path and then reopening it to read would stage whatever the name pointed
	// at the second time, which is not what the digest covered.
	vmlinuxSrc, err := lock.OpenPinned(repoRoot, lk.GuestKernel.VmlinuxPath, lk.GuestKernel.VmlinuxSHA256)
	if err != nil {
		return lock.Images{}, fmt.Errorf("guest kernel: %w", err)
	}
	defer func() { _ = vmlinuxSrc.Close() }()

	rootfsSrc, err := lock.OpenPinned(repoRoot, lk.RootImage.Path, lk.RootImage.SHA256)
	if err != nil {
		return lock.Images{}, fmt.Errorf("root image: %w", err)
	}
	defer func() { _ = rootfsSrc.Close() }()

	// Create stage dir.
	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		return lock.Images{}, fmt.Errorf("mkdir stage dir: %w", err)
	}

	if err := copyVerified(vmlinuxSrc, filepath.Join(stageDir, "vmlinux")); err != nil {
		return lock.Images{}, fmt.Errorf("copy vmlinux: %w", err)
	}
	if err := copyVerified(rootfsSrc, filepath.Join(stageDir, "rootfs.ext4")); err != nil {
		return lock.Images{}, fmt.Errorf("copy rootfs: %w", err)
	}

	// Generate capability token — 32 random bytes, hex-encoded.
	// §15.3: token never appears in logs, argv, manifests, or error strings.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return lock.Images{}, fmt.Errorf("generate token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	// Write token file 0600.
	tokenFile := filepath.Join(filepath.Join(a.cfg.StateDir, "vms", vmID), "token")
	if err := os.MkdirAll(filepath.Dir(tokenFile), 0o700); err != nil {
		return lock.Images{}, fmt.Errorf("mkdir token dir: %w", err)
	}
	if err := os.WriteFile(tokenFile, []byte(token), 0o600); err != nil {
		return lock.Images{}, fmt.Errorf("write token file: %w", err)
	}

	// Build config.ext4 containing guest.BootConfig as context.json.
	networkCfg, err := guest.NewNetworkConfig(vmID, transit)
	if err != nil {
		return lock.Images{}, fmt.Errorf("derive guest network config: %w", err)
	}
	bootCfg := guest.BootConfig{
		Schema:          guest.GuestContextSchema,
		VMID:            vmID,
		BootID:          bootID,
		CapabilityToken: token,
		ProtocolVersion: proto.ProtocolVersion,
		Network:         networkCfg,
	}
	contextJSON, err := json.Marshal(bootCfg)
	if err != nil {
		return lock.Images{}, fmt.Errorf("marshal boot config: %w", err)
	}

	diskStageDir := filepath.Join(stageDir, "disk-stage")
	if err := os.MkdirAll(diskStageDir, 0o755); err != nil {
		return lock.Images{}, fmt.Errorf("mkdir disk stage: %w", err)
	}
	if err := os.WriteFile(filepath.Join(diskStageDir, "context.json"), contextJSON, 0o644); err != nil {
		return lock.Images{}, fmt.Errorf("write context.json: %w", err)
	}

	configDiskPath := filepath.Join(stageDir, "config.ext4")
	mkfs := exec.CommandContext(ctx, "mkfs.ext4",
		"-d", diskStageDir,
		configDiskPath,
		fmt.Sprintf("%dK", configDiskMiB*1024),
	)
	if out, err := mkfs.CombinedOutput(); err != nil {
		return lock.Images{}, fmt.Errorf("mkfs config.ext4: %w\n%s", err, out)
	}

	// Create workspace.ext4: truncate to WorkspaceDiskMiB, then mkfs.ext4.
	workspacePath := filepath.Join(stageDir, "workspace.ext4")
	workspaceMiB := spec.WorkspaceDiskMiB
	if workspaceMiB <= 0 {
		workspaceMiB = 1024
	}
	truncCmd := exec.CommandContext(ctx, "truncate",
		"-s", fmt.Sprintf("%dM", workspaceMiB),
		workspacePath,
	)
	if out, err := truncCmd.CombinedOutput(); err != nil {
		return lock.Images{}, fmt.Errorf("truncate workspace: %w\n%s", err, out)
	}
	mkfsWS := exec.CommandContext(ctx, "mkfs.ext4", "-F", "-t", "ext4", workspacePath)
	if out, err := mkfsWS.CombinedOutput(); err != nil {
		return lock.Images{}, fmt.Errorf("mkfs workspace: %w\n%s", err, out)
	}

	// Write fc-config.json using the same FCConfig shape as the M0 fixture.
	// Drive order: rootfs (/dev/vda), config (/dev/vdb, ro), workspace (/dev/vdc).
	type fcBootSource struct {
		KernelImagePath string `json:"kernel_image_path"`
		BootArgs        string `json:"boot_args"`
	}
	type fcDrive struct {
		DriveID      string `json:"drive_id"`
		PathOnHost   string `json:"path_on_host"`
		IsRootDevice bool   `json:"is_root_device"`
		IsReadOnly   bool   `json:"is_read_only"`
	}
	type fcMachineConfig struct {
		VCPUCount  int `json:"vcpu_count"`
		MemSizeMiB int `json:"mem_size_mib"`
	}
	type fcVsock struct {
		GuestCID uint32 `json:"guest_cid"`
		UDSPath  string `json:"uds_path"`
	}
	type fcNetIface struct {
		IfaceID     string `json:"iface_id"`
		HostDevName string `json:"host_dev_name"`
		GuestMAC    string `json:"guest_mac"`
	}
	type fcConfig struct {
		BootSource        fcBootSource    `json:"boot-source"`
		Drives            []fcDrive       `json:"drives"`
		MachineConfig     fcMachineConfig `json:"machine-config"`
		Vsock             fcVsock         `json:"vsock"`
		NetworkInterfaces []fcNetIface    `json:"network-interfaces"`
	}

	vcpu := spec.VCPUCount
	if vcpu <= 0 {
		vcpu = 1
	}
	memMiB := int(spec.MemoryMiB)
	if memMiB <= 0 {
		memMiB = 512
	}

	fc := fcConfig{
		BootSource: fcBootSource{
			KernelImagePath: "vmlinux",
			BootArgs:        "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw",
		},
		Drives: []fcDrive{
			{DriveID: "rootfs", PathOnHost: "rootfs.ext4", IsRootDevice: true, IsReadOnly: false},
			{DriveID: "config", PathOnHost: "config.ext4", IsRootDevice: false, IsReadOnly: true},
			{DriveID: "workspace", PathOnHost: "workspace.ext4", IsRootDevice: false, IsReadOnly: false},
		},
		MachineConfig: fcMachineConfig{VCPUCount: vcpu, MemSizeMiB: memMiB},
		Vsock:         fcVsock{GuestCID: cid, UDSPath: "v.sock"},
		NetworkInterfaces: []fcNetIface{
			{IfaceID: "eth0", HostDevName: "tap0", GuestMAC: networkCfg.MAC},
		},
	}
	fcJSON, err := json.MarshalIndent(fc, "", "  ")
	if err != nil {
		return lock.Images{}, fmt.Errorf("marshal fc-config: %w", err)
	}
	if err := os.WriteFile(filepath.Join(stageDir, "fc-config.json"), fcJSON, 0o644); err != nil {
		return lock.Images{}, fmt.Errorf("write fc-config.json: %w", err)
	}

	return lk.Images(), nil
}

// computeStagedFiles builds the list of StagedFiles for privd.StartVM by computing
// the SHA-256 of each file in the stage directory that privd will copy.
//
// pinned maps a staged name to the digest the lock pins for it, and a staged
// file that disagrees with its pin refuses the launch. Without that comparison
// the chain proves nothing: privd verifies the staged bytes against a digest
// this function computes from those same bytes, so a stage directory replaced
// after doStage wrote it would be hashed faithfully, accepted by privd, and
// booted. The lock is the only party in the chain that can disagree.
//
// The three staged files with no pin — config.ext4, workspace.ext4 and
// fc-config.json — are built by this adapter for this boot and no earlier
// authority describes them, so their digests stay self-reported and privd's
// check of them proves only that the copy into the jail was faithful.
func computeStagedFiles(stageDir string, pinned map[string]string) ([]privd.StagedFile, error) {
	// privd validates every name against this same list and refuses anything
	// else, so the list lives on its side of the wire and is read from there.
	var files []privd.StagedFile
	for _, name := range privd.StagedFileNames {
		path := filepath.Join(stageDir, name)
		digest, err := sha256File(path)
		if err != nil {
			return nil, fmt.Errorf("hash %s: %w", name, err)
		}
		if want, ok := pinned[name]; ok && digest != want {
			return nil, fmt.Errorf("staged %s has %s, but the lock pins %s: the stage directory changed after it was written", name, digest, want)
		}
		files = append(files, privd.StagedFile{Name: name, SHA256: digest})
	}
	return files, nil
}

// waitAttached polls runner-state.json until Phase == "attached", ctx expires, or the runner exits.
func (a *Adapter) waitAttached(ctx context.Context, stateFile string, cmd *exec.Cmd) error {
	// Channel that fires when the runner process exits.
	runnerExited := make(chan error, 1)
	go func() {
		runnerExited <- cmd.Wait()
	}()

	ticker := time.NewTicker(readyBackoff)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for runner to attach: %w", ctx.Err())
		case exitErr := <-runnerExited:
			return fmt.Errorf("runner exited before attaching: %v", exitErr)
		case <-ticker.C:
			s, err := runner.ReadState(stateFile)
			if err != nil {
				// State file not written yet — keep polling.
				continue
			}
			if s.Phase == runner.PhaseAttached {
				return nil
			}
			if s.Phase == runner.PhaseVMMExited || s.Phase == runner.PhaseFinalized {
				return fmt.Errorf("runner reached phase %q before attaching", s.Phase)
			}
		}
	}
}

// doRollback reads the current manifest and tears down owned resources in reverse order.
// Best-effort on each step: an already-gone resource is not an error, and a step that
// fails does not stop the steps after it. Best-effort is not silent — a step that
// reports the resource is still there says so on stderr, because "tolerated" and
// "gone" are different answers and only one of them is safe to assume.
//
// Returns the archive its rescue wrote, or "" when there was nothing to rescue.
// A successful release deletes the VM's state directory, which is
// where the runner's log lives, so the rescue has to happen here and the caller
// has to be told where it went.
//
// Called with launchMu held by design (§5.3): the launch slot must not be reused
// until the transaction is fully unwound. Two 2s sleeps (SIGTERM grace for the
// runner, then for the VMM) mean worst-case ~4s of queueing for concurrent Launch
// calls — that is intentional and acceptable.
func (a *Adapter) doRollback(vmID string) string {
	m, err := readManifest(a.cfg.StateDir, vmID)
	if err != nil {
		// If we can't read the manifest we can't know what to clean up — skip.
		// Nothing below runs, including the state dir removal, so the runner's
		// log is still where the launch left it and needs no rescue.
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := a.resolveStartOutcome(ctx, &m); err != nil {
		fmt.Fprintf(os.Stderr, "jailer rollback %s: %v; ownership retained\n", vmID, err)
		return ""
	}
	// Determine which stages completed.
	stageSet := make(map[string]bool)
	for _, s := range m.Stages {
		stageSet[s] = true
	}

	// Kill runner by recorded pid.
	if stageSet[stageRunnerSpawned] && m.RunnerPID > 0 {
		killRunnerByPID(m.RunnerPID)
	}

	// Signal VMM: SIGTERM, 2s wait, then SIGKILL.
	if stageSet[stageVMMStarted] && m.VMMPID > 0 {
		_ = a.pc.SignalVM(ctx, privd.SignalVMReq{VMID: vmID, Kind: "term"})
		time.Sleep(2 * time.Second)
		_ = a.pc.SignalVM(ctx, privd.SignalVMReq{VMID: vmID, Kind: "kill"})

	}

	// Rescue the runner's log and phase file before the removal below takes them.
	// The runner was killed at the top of this function, so the log is complete;
	// rescuing any earlier would archive a half-written one.
	rescued, rescueErr := rescueFailedLaunch(a.cfg.StateDir, vmID, m.BootID)
	if rescueErr != nil {
		fmt.Fprintf(os.Stderr, "jailer: rollback: warn: rescue runner artifacts for %s: %v\n", vmID, rescueErr)
	}

	// Use the same host proofs and durable barriers as Delete. Even a stage
	// write or an RPC reply can fail after its side effect; release both halves
	// unconditionally, retaining the manifest and lease if anything is unsettled.
	if err := a.doRelease(ctx, vmID); err != nil {
		fmt.Fprintf(os.Stderr, "jailer: rollback: cleanup for %s: %v; manifest and network lease retained\n", vmID, err)
	}

	return rescued
}

// killRunnerByPID sends SIGTERM to the runner pid, waits 2s, then SIGKILL.
func killRunnerByPID(pid int) {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	_ = proc.Signal(syscall.SIGTERM)
	time.Sleep(2 * time.Second)
	_ = proc.Signal(syscall.SIGKILL)
}

// newUUID returns a random v4 UUID string.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// sha256File reads path and returns its lowercase hex SHA-256.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copyVerified writes the contents of an already-open, already-verified source
// to dst. It takes a descriptor rather than a path because that is the whole
// point: the bytes written are the bytes the caller's digest check covered.
func copyVerified(in *os.File, dst string) error {
	if _, err := in.Seek(0, io.SeekStart); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// Ensure Adapter satisfies runtime.Runtime on Linux (where Launch is implemented).
var _ runtime.Runtime = (*Adapter)(nil)
