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
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/2389-research/observatory-v2/internal/guest"
	"github.com/2389-research/observatory-v2/internal/guest/proto"
	"github.com/2389-research/observatory-v2/internal/lock"
	"github.com/2389-research/observatory-v2/internal/privd"
	"github.com/2389-research/observatory-v2/internal/runner"
	"github.com/2389-research/observatory-v2/internal/runtime"
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

// Launch executes the §5.3 launch transaction for the given VMSpec.
// Exactly one Launch call executes at a time; concurrent calls queue on launchMu.
func (a *Adapter) Launch(ctx context.Context, spec runtime.VMSpec) error {
	a.launchMu.Lock()
	defer a.launchMu.Unlock()
	return a.launch(ctx, spec)
}

// launch is the real implementation, called with launchMu held.
func (a *Adapter) launch(ctx context.Context, spec runtime.VMSpec) (retErr error) {
	vmID := spec.VMID

	// ── Step 1: Slot ──────────────────────────────────────────────────────────
	slot, err := allocateSlot(a.cfg.StateDir, vmID, a.cfg.MaxSlots)
	if err != nil {
		return fmt.Errorf("launch %s failed at stage reserved: %w", vmID, err)
	}

	uid := a.cfg.JailUIDBase + slot
	gid := a.cfg.JailGID
	cid := a.cfg.CIDBase + uint32(slot)

	// Determine CIDR: reuse from existing manifest (restart), or allocate fresh.
	var cidr string
	if existing, err := readManifest(a.cfg.StateDir, vmID); err == nil && existing.CIDR != "" {
		cidr = existing.CIDR
	} else {
		prefix, err := a.cfg.Allocator.Next()
		if err != nil {
			return fmt.Errorf("launch %s failed at stage reserved: allocate CIDR: %w", vmID, err)
		}
		cidr = prefix.String()
	}

	// ── Step 2: Manifest (reserved) ───────────────────────────────────────────
	bootID := spec.BootID
	if bootID == "" {
		bootID, err = newUUID()
		if err != nil {
			return fmt.Errorf("launch %s failed at stage reserved: generate boot ID: %w", vmID, err)
		}
	}

	m := Manifest{
		VMID:   vmID,
		BootID: bootID,
		Slot:   slot,
		UID:    uid,
		GID:    gid,
		CID:    cid,
		CIDR:   cidr,
		Stages: []string{},
	}
	vmStateDir := filepath.Join(a.cfg.StateDir, "vms", vmID)
	if err := os.MkdirAll(vmStateDir, 0o700); err != nil {
		return fmt.Errorf("launch %s failed at stage reserved: mkdir state dir: %w", vmID, err)
	}
	m.Stages = append(m.Stages, stageReserved)
	if err := writeManifest(a.cfg.StateDir, m); err != nil {
		return fmt.Errorf("launch %s failed at stage reserved: write manifest: %w", vmID, err)
	}

	// Rollback state is tracked by manifest.Stages; rollback runs in reverse.
	// currentStage names the stage being attempted when a failure occurs so the
	// error message surfaces which step failed (§5.3).
	currentStage := stageReserved
	rollback := func(stageErr error) error {
		a.doRollback(vmID)
		return fmt.Errorf("launch %s failed at stage %s: %w", vmID, currentStage, stageErr)
	}

	// ── Step 3: Stage ─────────────────────────────────────────────────────────
	currentStage = stageStaged
	stageDir := filepath.Join(a.cfg.StageRoot, vmID)
	stageErr := a.doStage(ctx, vmID, bootID, cid, uid, gid, stageDir, spec)
	if stageErr != nil {
		// No side effects beyond the state dir — rollback cleans up.
		return rollback(stageErr)
	}
	m.Stages = append(m.Stages, stageStaged)
	if err := writeManifest(a.cfg.StateDir, m); err != nil {
		return rollback(err)
	}

	// ── Step 4: Network ───────────────────────────────────────────────────────
	currentStage = stageNetwork
	if err := a.pc.AllocateNetwork(ctx, privd.AllocateNetworkReq{VMID: vmID, CIDR: cidr}); err != nil {
		return rollback(fmt.Errorf("allocate_network: %w", err))
	}
	m.Stages = append(m.Stages, stageNetwork)
	if err := writeManifest(a.cfg.StateDir, m); err != nil {
		return rollback(err)
	}

	// ── Step 5: VMM ───────────────────────────────────────────────────────────
	currentStage = stageVMMStarted
	// Compute SHA-256s of the staged files for privd's TOCTOU-safe staging.
	stagedFiles, err := a.computeStagedFiles(stageDir)
	if err != nil {
		return rollback(fmt.Errorf("compute staged file hashes: %w", err))
	}

	startResp, err := a.pc.StartVM(ctx, privd.StartVMReq{
		VMID:     vmID,
		UID:      uid,
		GID:      gid,
		CID:      cid,
		StageDir: stageDir,
		Files:    stagedFiles,
	})
	if err != nil {
		return rollback(fmt.Errorf("start_vm: %w", err))
	}
	m.VMMPID = startResp.PID
	m.VMMStart = startResp.StartTime
	m.Stages = append(m.Stages, stageVMMStarted)
	if err := writeManifest(a.cfg.StateDir, m); err != nil {
		return rollback(err)
	}

	// ── Step 6: Runner ────────────────────────────────────────────────────────
	currentStage = stageRunnerSpawned
	instanceID, err := newUUID()
	if err != nil {
		return rollback(fmt.Errorf("generate instance ID: %w", err))
	}

	// vSock path: the adapter polls runner-state.json for the attached phase;
	// the runner connects to this UDS to speak to guestd.
	vSockPath := filepath.Join(a.cfg.JailBase, "firecracker", vmID, "root", "v.sock")
	tokenFile := filepath.Join(vmStateDir, "token")
	spoolDir := filepath.Join(a.cfg.SpoolRoot, vmID)
	stateFile := filepath.Join(vmStateDir, "runner-state.json")
	ctlSock := filepath.Join(vmStateDir, "runner.sock")
	runnerLog := filepath.Join(vmStateDir, "runner.log")

	logFile, err := os.OpenFile(runnerLog, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return rollback(fmt.Errorf("open runner log: %w", err))
	}

	argv := []string{
		a.cfg.RunnerBin,
		"--vm-id", vmID,
		"--boot-id", bootID,
		"--instance-id", instanceID,
		"--uds", vSockPath,
		"--token-file", tokenFile,
		"--spool-dir", spoolDir,
		"--state-file", stateFile,
		"--ctl-sock", ctlSock,
		"--vmm-pid", strconv.Itoa(startResp.PID),
		"--vmm-starttime", startResp.StartTime,
		"--ping-interval", "5s",
	}

	cmd := buildRunnerCmd(argv, logFile)

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return rollback(fmt.Errorf("spawn runner: %w", err))
	}
	logFile.Close()

	m.RunnerPID = cmd.Process.Pid
	m.Stages = append(m.Stages, stageRunnerSpawned)
	if err := writeManifest(a.cfg.StateDir, m); err != nil {
		return rollback(err)
	}

	// ── Step 7: Attach wait ───────────────────────────────────────────────────
	currentStage = stageAttached
	attachCtx, attachCancel := context.WithTimeout(ctx, readyTimeout)
	defer attachCancel()

	attachErr := a.waitAttached(attachCtx, stateFile, cmd)
	if attachErr != nil {
		return rollback(attachErr)
	}
	m.Stages = append(m.Stages, stageAttached)
	if err := writeManifest(a.cfg.StateDir, m); err != nil {
		// Attached successfully but manifest write failed — best-effort log and proceed.
		// The runner is running; Task 11's Reconcile owns recovery for the missing stage record.
		fmt.Fprintf(os.Stderr, "jailer: warn: failed to record attached stage for %s: %v\n", vmID, err)
	}

	return nil
}

// doStage builds the staging directory for the VM:
//  1. Copy vmlinux + rootfs.ext4 from paths recorded in the lock (resolved against RepoRoot),
//     verifying SHA-256 against the lock's pinned hashes.
//  2. Generate a per-boot token, write to token file, and build config.ext4.
//  3. Create workspace.ext4.
//  4. Write fc-config.json.
func (a *Adapter) doStage(ctx context.Context, vmID, bootID string, cid uint32, uid, gid int, stageDir string, spec runtime.VMSpec) error {
	// Load and verify lock artifacts.
	lk, err := lock.Load(a.cfg.LockPath)
	if err != nil {
		return fmt.Errorf("load lock: %w", err)
	}
	// RepoRoot is the directory the lock's artifact paths resolve against.
	// Lock paths like "images/dist/vmlinux" are relative to it — one source of truth.
	repoRoot := a.cfg.RepoRoot
	if mismatches := lk.VerifyArtifacts(repoRoot); len(mismatches) > 0 {
		return fmt.Errorf("artifact hash mismatch: %+v", mismatches)
	}

	// Create stage dir.
	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		return fmt.Errorf("mkdir stage dir: %w", err)
	}

	// Copy vmlinux — path comes from the lock, resolved against repoRoot.
	vmlinuxSrc := filepath.Join(repoRoot, lk.GuestKernel.VmlinuxPath)
	if err := copyFile(vmlinuxSrc, filepath.Join(stageDir, "vmlinux")); err != nil {
		return fmt.Errorf("copy vmlinux: %w", err)
	}

	// Copy rootfs.ext4 — path comes from the lock, resolved against repoRoot.
	rootfsSrc := filepath.Join(repoRoot, lk.RootImage.Path)
	if err := copyFile(rootfsSrc, filepath.Join(stageDir, "rootfs.ext4")); err != nil {
		return fmt.Errorf("copy rootfs: %w", err)
	}

	// Generate capability token — 32 random bytes, hex-encoded.
	// §15.3: token never appears in logs, argv, manifests, or error strings.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return fmt.Errorf("generate token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	// Write token file 0600.
	tokenFile := filepath.Join(filepath.Join(a.cfg.StateDir, "vms", vmID), "token")
	if err := os.MkdirAll(filepath.Dir(tokenFile), 0o700); err != nil {
		return fmt.Errorf("mkdir token dir: %w", err)
	}
	if err := os.WriteFile(tokenFile, []byte(token), 0o600); err != nil {
		return fmt.Errorf("write token file: %w", err)
	}

	// Build config.ext4 containing guest.BootConfig as context.json.
	bootCfg := guest.BootConfig{
		Schema:          guest.GuestContextSchema,
		VMID:            vmID,
		BootID:          bootID,
		CapabilityToken: token,
		ProtocolVersion: proto.ProtocolVersion,
	}
	contextJSON, err := json.Marshal(bootCfg)
	if err != nil {
		return fmt.Errorf("marshal boot config: %w", err)
	}

	diskStageDir := filepath.Join(stageDir, "disk-stage")
	if err := os.MkdirAll(diskStageDir, 0o755); err != nil {
		return fmt.Errorf("mkdir disk stage: %w", err)
	}
	if err := os.WriteFile(filepath.Join(diskStageDir, "context.json"), contextJSON, 0o644); err != nil {
		return fmt.Errorf("write context.json: %w", err)
	}

	configDiskPath := filepath.Join(stageDir, "config.ext4")
	mkfs := exec.CommandContext(ctx, "mkfs.ext4",
		"-d", diskStageDir,
		configDiskPath,
		fmt.Sprintf("%dK", configDiskMiB*1024),
	)
	if out, err := mkfs.CombinedOutput(); err != nil {
		return fmt.Errorf("mkfs config.ext4: %w\n%s", err, out)
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
		return fmt.Errorf("truncate workspace: %w\n%s", err, out)
	}
	mkfsWS := exec.CommandContext(ctx, "mkfs.ext4", "-F", "-t", "ext4", workspacePath)
	if out, err := mkfsWS.CombinedOutput(); err != nil {
		return fmt.Errorf("mkfs workspace: %w\n%s", err, out)
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
			{IfaceID: "eth0", HostDevName: "tap0"},
		},
	}
	fcJSON, err := json.MarshalIndent(fc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal fc-config: %w", err)
	}
	if err := os.WriteFile(filepath.Join(stageDir, "fc-config.json"), fcJSON, 0o644); err != nil {
		return fmt.Errorf("write fc-config.json: %w", err)
	}

	return nil
}

// computeStagedFiles builds the list of StagedFiles for privd.StartVM by computing
// the SHA-256 of each file in the stage directory that privd will copy.
func (a *Adapter) computeStagedFiles(stageDir string) ([]privd.StagedFile, error) {
	names := []string{"vmlinux", "rootfs.ext4", "config.ext4", "workspace.ext4", "fc-config.json"}
	var files []privd.StagedFile
	for _, name := range names {
		path := filepath.Join(stageDir, name)
		digest, err := sha256File(path)
		if err != nil {
			return nil, fmt.Errorf("hash %s: %w", name, err)
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
// Tolerates already-gone resources — rollback is best-effort on each step.
//
// Called with launchMu held by design (§5.3): the launch slot must not be reused
// until the transaction is fully unwound. Two 2s sleeps (SIGTERM grace for the
// runner, then for the VMM) mean worst-case ~4s of queueing for concurrent Launch
// calls — that is intentional and acceptable.
func (a *Adapter) doRollback(vmID string) {
	m, err := readManifest(a.cfg.StateDir, vmID)
	if err != nil {
		// If we can't read the manifest we can't know what to clean up — skip.
		return
	}

	// Determine which stages completed.
	stageSet := make(map[string]bool)
	for _, s := range m.Stages {
		stageSet[s] = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Kill runner by recorded pid.
	if stageSet[stageRunnerSpawned] && m.RunnerPID > 0 {
		killRunnerByPID(m.RunnerPID)
	}

	// Signal VMM: SIGTERM, 2s wait, then SIGKILL.
	if stageSet[stageVMMStarted] && m.VMMPID > 0 {
		_ = a.pc.SignalVM(ctx, privd.SignalVMReq{VMID: vmID, Kind: "term"})
		time.Sleep(2 * time.Second)
		_ = a.pc.SignalVM(ctx, privd.SignalVMReq{VMID: vmID, Kind: "kill"})
		_ = a.pc.ReleaseVM(ctx, privd.ReleaseVMReq{VMID: vmID})
	}

	// Release network.
	if stageSet[stageNetwork] {
		_ = a.pc.ReleaseNetwork(ctx, privd.ReleaseNetworkReq{VMID: vmID})
	}

	// Remove stage dir.
	if stageSet[stageStaged] {
		stageDir := filepath.Join(a.cfg.StageRoot, vmID)
		_ = os.RemoveAll(stageDir)
	}

	// Remove VM state dir.
	vmStateDir := filepath.Join(a.cfg.StateDir, "vms", vmID)
	_ = os.RemoveAll(vmStateDir)
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

// copyFile copies src to dst as a new regular file (no hardlinks).
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
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
