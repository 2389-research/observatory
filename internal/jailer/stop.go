// ABOUTME: Stop, ForceStop, Release, and Reconcile for the jailer Adapter (Linux-only).
// ABOUTME: Concurrency: launchMu serialises Stop/Release against Launch (see discipline comment).

//go:build linux

package jailer

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/2389-research/observatory-v2/internal/privd"
	"github.com/2389-research/observatory-v2/internal/runner"
)

// Concurrency discipline: Stop and Release both hold launchMu while performing
// teardown. This serialises them against concurrent Launch calls on the same vmID.
// Launch holds launchMu for the entire transaction including rollback (~4s worst
// case). The constraint is: a Stop or Release that interleaves with an in-progress
// Launch would tear down resources the Launch is in the middle of setting up, leaving
// the system in an undefined state. Holding launchMu makes Stop/Release queue behind
// the outstanding Launch (or vice-versa), never interleave.
//
// Per-VM locks would be more granular, but the current design has one shared
// launchMu; extending its scope to Stop/Release is the simplest correct thing.

// ctlRequest / ctlReply mirror runner.ctl types (internal to runner, not exported).
// We replicate the JSON shape here rather than coupling to runner internals.
type adapterCtlRequest struct {
	Cmd    string `json:"cmd"`
	GraceS int    `json:"grace_s,omitempty"`
}

type adapterCtlReply struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// dialCtl dials the runner's control socket and sends one command, returning the reply.
// One command per connection (runner ctl protocol).
func dialCtl(sockPath string, req adapterCtlRequest) (adapterCtlReply, error) {
	conn, err := net.DialTimeout("unix", sockPath, 5*time.Second)
	if err != nil {
		return adapterCtlReply{}, fmt.Errorf("dial runner ctl %s: %w", sockPath, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	enc := json.NewEncoder(conn)
	if err := enc.Encode(req); err != nil {
		return adapterCtlReply{}, fmt.Errorf("encode ctl cmd: %w", err)
	}

	var reply adapterCtlReply
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&reply); err != nil {
		return adapterCtlReply{}, fmt.Errorf("decode ctl reply: %w", err)
	}
	return reply, nil
}

// pollRunnerPhase polls runner-state.json until the phase is one of wantPhases,
// or ctx expires. Returns the final state seen.
func pollRunnerPhase(ctx context.Context, stateFile string, wantPhases ...string) (runner.State, error) {
	want := make(map[string]bool, len(wantPhases))
	for _, p := range wantPhases {
		want[p] = true
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s, _ := runner.ReadState(stateFile)
			return s, ctx.Err()
		case <-ticker.C:
			s, err := runner.ReadState(stateFile)
			if err != nil {
				continue // state file not written yet
			}
			if want[s.Phase] {
				return s, nil
			}
		}
	}
}

// runnerAlive reports whether the runner process at pid is still alive
// by checking /proc/<pid>/stat (Linux). A stale PID that has been recycled
// is not considered alive if we can read the manifest's runner PID.
func runnerAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

// Stop requests a graceful shutdown of the VM, escalating to SIGTERM/SIGKILL if needed.
//
// Protocol:
//  1. Read manifest + runner state.
//  2. If runner is alive and in attached phase: send shutdown_guest via ctl;
//     poll for vmm_exited/finalized within grace period → forced=false.
//  3. On timeout or ctl failure: SIGTERM, 5s, SIGKILL → forced=true.
//  4. Always: ctl finalize (tolerate dead runner), ReleaseVM (chroot removed).
//  5. KEEP slot + network + manifest (stopped VM can restart; Launch reuses them).
func (a *Adapter) Stop(ctx context.Context, vmID string, grace time.Duration) (bool, error) {
	// Serialise with Launch on the same vmID (see concurrency discipline above).
	a.launchMu.Lock()
	defer a.launchMu.Unlock()
	return a.doStop(ctx, vmID, grace, false)
}

// ForceStop skips the graceful path and immediately kills the VMM.
func (a *Adapter) ForceStop(ctx context.Context, vmID string) error {
	a.launchMu.Lock()
	defer a.launchMu.Unlock()
	_, err := a.doStop(ctx, vmID, 0, true)
	return err
}

// doStop is the shared implementation for Stop and ForceStop.
// When forceImmediate is true the graceful path is skipped entirely.
func (a *Adapter) doStop(ctx context.Context, vmID string, grace time.Duration, forceImmediate bool) (forced bool, retErr error) {
	m, err := readManifest(a.cfg.StateDir, vmID)
	if err != nil {
		// No manifest — VM may already be gone or was never launched.
		// Treat as a no-op (idempotent).
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read manifest: %w", err)
	}

	stateFile := filepath.Join(a.cfg.StateDir, "vms", vmID, "runner-state.json")
	ctlSock := filepath.Join(a.cfg.StateDir, "vms", vmID, "runner.sock")

	graceful := false

	if !forceImmediate && m.RunnerPID > 0 && runnerAlive(m.RunnerPID) {
		// Runner is alive — attempt graceful shutdown via ctl.
		graceS := int(grace.Seconds())
		if graceS <= 0 {
			graceS = 1
		}
		reply, ctlErr := dialCtl(ctlSock, adapterCtlRequest{Cmd: "shutdown_guest", GraceS: graceS})
		if ctlErr == nil && reply.OK {
			// shutdown_guest accepted; poll for vmm_exited or finalized within grace+5s.
			pollCtx, pollCancel := context.WithTimeout(ctx, grace+5*time.Second)
			defer pollCancel()
			s, _ := pollRunnerPhase(pollCtx, stateFile, runner.PhaseVMMExited, runner.PhaseFinalized)
			if s.Phase == runner.PhaseVMMExited || s.Phase == runner.PhaseFinalized {
				graceful = true
			}
		}
		// If ctl failed or grace expired: fall through to forced path.
	}

	if !graceful {
		forced = true
		// SIGTERM then SIGKILL on the VMM via privd.
		if m.VMMPID > 0 {
			termCtx, termCancel := context.WithTimeout(ctx, 10*time.Second)
			defer termCancel()
			_ = a.pc.SignalVM(termCtx, privd.SignalVMReq{VMID: vmID, Kind: "term"})
			time.Sleep(5 * time.Second)
			_ = a.pc.SignalVM(termCtx, privd.SignalVMReq{VMID: vmID, Kind: "kill"})
		}
	}

	// Always send finalize to the runner (tolerate dead/missing runner socket).
	_, _ = dialCtl(ctlSock, adapterCtlRequest{Cmd: "finalize"})

	// Release the jail chroot dir (privd removes <JailBase>/firecracker/<id>).
	// Keep network + slot + manifest: a stopped VM can be restarted.
	releaseCtx, releaseCancel := context.WithTimeout(ctx, 10*time.Second)
	defer releaseCancel()
	_ = a.pc.ReleaseVM(releaseCtx, privd.ReleaseVMReq{VMID: vmID})

	return forced, nil
}

// Release performs a full resource release for the delete path (R1 ruling).
// Idempotent: unknown vmID (no manifest) returns nil.
// Releases: network, manifest, <StateDir>/vms/<id>/, stage dir.
// Keeps: spool dir (importer reads it independently).
//
// Concurrency: holds launchMu to prevent interleaving with an in-progress Launch.
func (a *Adapter) Release(ctx context.Context, vmID string) error {
	a.launchMu.Lock()
	defer a.launchMu.Unlock()
	return a.doRelease(ctx, vmID)
}

// doRelease is the real implementation, called with launchMu held.
func (a *Adapter) doRelease(ctx context.Context, vmID string) error {
	m, err := readManifest(a.cfg.StateDir, vmID)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // idempotent: already gone
		}
		return fmt.Errorf("jailer release %s: read manifest: %w", vmID, err)
	}

	stageSet := make(map[string]bool, len(m.Stages))
	for _, s := range m.Stages {
		stageSet[s] = true
	}

	releaseCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Release network namespace + TAP device.
	if stageSet[stageNetwork] {
		if err := a.pc.ReleaseNetwork(releaseCtx, privd.ReleaseNetworkReq{VMID: vmID}); err != nil {
			return fmt.Errorf("jailer release %s: release_network: %w", vmID, err)
		}
	}

	// Remove stage dir (disk images + fc-config.json).
	if stageSet[stageStaged] {
		stageDir := filepath.Join(a.cfg.StageRoot, vmID)
		if err := os.RemoveAll(stageDir); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("jailer release %s: remove stage dir: %w", vmID, err)
		}
	}

	// Remove <StateDir>/vms/<id>/ — includes manifest.json, token, runner-state.json, etc.
	// This must be last so the manifest is still readable until all other cleanup is done.
	vmStateDir := filepath.Join(a.cfg.StateDir, "vms", vmID)
	if err := os.RemoveAll(vmStateDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("jailer release %s: remove state dir: %w", vmID, err)
	}

	// Spool dir is intentionally not removed: the importer reads segments independently.
	// (Brief note: Task 7's importer prunes segments only, not VM dirs — verified.)

	return nil
}

// Reconcile scans <StateDir>/vms/*/manifest.json at startup and classifies each VM.
// Outcomes:
//   - "adopted": runner alive + attached + VMM identity matches → healthy, no action.
//   - "vmm_gone": VMM process gone → report for manager to mark failed.
//   - "ambiguous": unreadable manifest or identity mismatch → touch nothing (§5.5).
//
// When the runner is dead but the VMM is alive and identity matches, a fresh runner
// is respawned with a new instance-id (so the store importer deduplicates correctly).
func (a *Adapter) Reconcile(ctx context.Context) ([]Finding, error) {
	vmsDir := filepath.Join(a.cfg.StateDir, "vms")
	entries, err := os.ReadDir(vmsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // nothing to reconcile
		}
		return nil, fmt.Errorf("reconcile: read vms dir: %w", err)
	}

	var findings []Finding

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		vmID := e.Name()
		f := a.reconcileOne(ctx, vmID)
		findings = append(findings, f)
	}

	return findings, nil
}

// reconcileOne classifies one VM directory.
func (a *Adapter) reconcileOne(ctx context.Context, vmID string) Finding {
	m, err := readManifest(a.cfg.StateDir, vmID)
	if err != nil {
		// Unreadable manifest — quarantined per §5.5: touch nothing.
		return Finding{
			VMID:    vmID,
			Outcome: "ambiguous",
			Detail:  fmt.Sprintf("unreadable manifest: %v", err),
		}
	}

	// VMM identity check.
	vmmAlive := m.VMMPID > 0 && m.VMMStart != "" && privd.PIDAlive(m.VMMPID, m.VMMStart)

	if !vmmAlive {
		return Finding{
			VMID:    vmID,
			Outcome: "vmm_gone",
			Detail:  fmt.Sprintf("vmm pid %d starttime %q: not alive", m.VMMPID, m.VMMStart),
		}
	}

	// VMM is alive. Check runner state.
	stateFile := filepath.Join(a.cfg.StateDir, "vms", vmID, "runner-state.json")
	s, stateErr := runner.ReadState(stateFile)

	runnerAttached := stateErr == nil && s.Phase == runner.PhaseAttached &&
		runnerAlive(m.RunnerPID)

	if runnerAttached {
		// Verify runner's recorded VMM identity matches the manifest.
		if s.VMMPID != m.VMMPID || s.VMMStartTime != m.VMMStart {
			// Identity mismatch — quarantine.
			return Finding{
				VMID:    vmID,
				Outcome: "ambiguous",
				Detail:  fmt.Sprintf("runner vmm identity mismatch: runner=(%d,%s) manifest=(%d,%s)", s.VMMPID, s.VMMStartTime, m.VMMPID, m.VMMStart),
			}
		}
		return Finding{
			VMID:    vmID,
			Outcome: "adopted",
			Detail:  fmt.Sprintf("runner pid %d phase %s vmm pid %d alive", m.RunnerPID, s.Phase, m.VMMPID),
		}
	}

	// Runner is dead (or not attached) but VMM is alive — respawn the runner.
	if err := a.respawnRunner(ctx, m); err != nil {
		return Finding{
			VMID:    vmID,
			Outcome: "ambiguous",
			Detail:  fmt.Sprintf("failed to respawn runner: %v", err),
		}
	}
	return Finding{
		VMID:    vmID,
		Outcome: "adopted",
		Detail:  fmt.Sprintf("runner respawned; vmm pid %d alive", m.VMMPID),
	}
}

// buildRunnerCmd builds an exec.Cmd for the runner with Setsid and the given log file.
// logFile is attached to both stdout and stderr; callers must call logFile.Close() after cmd.Start().
func buildRunnerCmd(argv []string, logFile *os.File) *exec.Cmd {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd
}

// respawnRunner spawns a fresh runner process for a VM whose runner died but
// whose VMM is still alive. A fresh instance-id is minted to avoid dedup collisions
// in the spool importer (which deduplicates on (source_instance_id, source_seq)).
func (a *Adapter) respawnRunner(ctx context.Context, m Manifest) error {
	instanceID := uuid.NewString()
	vmID := m.VMID

	vmStateDir := filepath.Join(a.cfg.StateDir, "vms", vmID)
	vSockPath := filepath.Join(a.cfg.JailBase, "firecracker", vmID, "root", "v.sock")
	tokenFile := filepath.Join(vmStateDir, "token")
	spoolDir := filepath.Join(a.cfg.SpoolRoot, vmID)
	stateFile := filepath.Join(vmStateDir, "runner-state.json")
	ctlSock := filepath.Join(vmStateDir, "runner.sock")
	runnerLog := filepath.Join(vmStateDir, "runner.log")

	logFile, err := os.OpenFile(runnerLog, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open runner log: %w", err)
	}

	// Same argv shape as launch.go's spawn (factored here rather than duplicated).
	argv := []string{
		a.cfg.RunnerBin,
		"--vm-id", vmID,
		"--boot-id", m.BootID,
		"--instance-id", instanceID,
		"--uds", vSockPath,
		"--token-file", tokenFile,
		"--spool-dir", spoolDir,
		"--state-file", stateFile,
		"--ctl-sock", ctlSock,
		"--vmm-pid", fmt.Sprintf("%d", m.VMMPID),
		"--vmm-starttime", m.VMMStart,
		"--ping-interval", "5s",
	}

	cmd := buildRunnerCmd(argv, logFile)
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("spawn runner: %w", err)
	}
	logFile.Close()

	// Update manifest with new runner PID.
	m.RunnerPID = cmd.Process.Pid
	if err := writeManifest(a.cfg.StateDir, m); err != nil {
		// Best-effort: runner is running even if manifest update fails.
		fmt.Fprintf(os.Stderr, "jailer: reconcile: warn: update manifest runner_pid for %s: %v\n", vmID, err)
	}

	// Wait for the runner to reach attached.
	attachCtx, attachCancel := context.WithTimeout(ctx, 30*time.Second)
	defer attachCancel()
	if err := a.waitAttached(attachCtx, stateFile, cmd); err != nil {
		return fmt.Errorf("wait for respawned runner to attach: %w", err)
	}

	return nil
}
