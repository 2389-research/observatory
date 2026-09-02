// ABOUTME: Stop, ForceStop, Release, and Reconcile for the jailer Adapter (Linux-only).
// ABOUTME: Concurrency: launchMu serialises Stop/Release against Launch (see discipline comment).

//go:build linux

package jailer

import (
	"context"
	"encoding/json"
	"errors"
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
		if m.VMMPID > 0 {
			signalCtx, signalCancel := context.WithTimeout(ctx, 10*time.Second)
			defer signalCancel()
			// ForceStop goes straight to SIGKILL; graceful-timeout path sends SIGTERM first.
			if !forceImmediate {
				_ = a.pc.SignalVM(signalCtx, privd.SignalVMReq{VMID: vmID, Kind: "term"})
				select {
				case <-time.After(5 * time.Second):
				case <-ctx.Done():
				}
			}
			_ = a.pc.SignalVM(signalCtx, privd.SignalVMReq{VMID: vmID, Kind: "kill"})
		}
	}

	// Always send finalize to the runner (tolerate dead/missing runner socket).
	_, _ = dialCtl(ctlSock, adapterCtlRequest{Cmd: "finalize"})

	// Release the jail chroot dir (privd removes <JailBase>/firecracker/<id>).
	// Keep network + slot + manifest: a stopped VM can be restarted.
	//
	// The error is logged and then discarded on purpose, and what the discard
	// costs is worth stating plainly: doStop does not know the VM is dead. The
	// graceful poll above is the only path that observes the VMM exit. On the
	// forced path SignalVM's errors are dropped and forced is set unconditionally,
	// and SIGKILL cannot reap a task in uninterruptible sleep -- privd then answers
	// invalid_state "vm process is still alive" for the whole retry window. So this
	// stop may not have stopped anything, and doAction still writes "stopped" with
	// ReleaseCompute, handing the VM's RAM back to admission while the process runs.
	//
	// It is recorded that way because the alternative is worse. Any error returned
	// here reaches Manager.doAction, which routes it into failAction: the operation
	// is recorded failed and the VM row is left in "stopping". Every release
	// failure that says nothing about the VM's liveness -- privd unreachable,
	// exec_failed on the jail dir -- would then produce a wrong verdict on a VM
	// that really did stop. A false "failed" on a dead VM is worse than a leak on a
	// live one, so the verdict stands and the error goes to stderr instead, where
	// the daemon log and savePostmortem will carry it. What is left behind when it
	// fires: <JailBase>/firecracker/<vmID>, a pinned privd ledger entry, and
	// possibly a running VM behind a "stopped" row. Settling those needs a cleanup
	// backlog, which is M1b work.
	releaseCtx, releaseCancel := context.WithTimeout(ctx, 10*time.Second)
	defer releaseCancel()
	if err := a.releaseVMWhenDead(releaseCtx, vmID); err != nil {
		fmt.Fprintf(os.Stderr,
			"jailer: stop: warn: release jail chroot for %s: %v; chroot and privd ledger entry retained, and the VM may still be running\n",
			vmID, err)
	}

	return forced, nil
}

// releaseVMWhenDead asks privd to release the VM's jail chroot, retrying while
// privd answers with cause invalid_state.
//
// SIGKILL is asynchronous: a force-stop can reach privd before the kernel has
// reaped the VMM, and privd then refuses with invalid_state "vm process is still
// alive; signal first" (internal/privd/server.go). Taking that refusal as an
// answer leaves the chroot on disk and pins the ledger entry -- release_network
// sees a non-zero PID and writes the partial entry back instead of deleting the
// file. The refusal is explicit and typed, so asking again until privd accepts is
// what the protocol asks for; after a SIGKILL the process is normally gone in
// milliseconds. Every other cause is a real failure and is returned on the first
// attempt rather than spinning out the deadline.
func (a *Adapter) releaseVMWhenDead(ctx context.Context, vmID string) error {
	const retryInterval = 50 * time.Millisecond
	for {
		err := a.pc.ReleaseVM(ctx, privd.ReleaseVMReq{VMID: vmID})
		if err == nil {
			return nil
		}
		var re *privd.RemoteError
		if !errors.As(err, &re) || re.Cause != "invalid_state" {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(retryInterval):
		}
	}
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
	// os.RemoveAll on a missing path is a no-op — no stage guard needed.
	stageDir := filepath.Join(a.cfg.StageRoot, vmID)
	if err := os.RemoveAll(stageDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("jailer release %s: remove stage dir: %w", vmID, err)
	}

	// Remove <StateDir>/vms/<id>/ — includes manifest.json, token, runner-state.json, etc.
	// This must be last so the manifest is still readable until all other cleanup is done.
	// os.RemoveAll on a missing path is a no-op — no stage guard needed.
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
func (a *Adapter) respawnRunner(_ context.Context, m Manifest) error {
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

	// Do NOT wait for the runner to attach here. The runner attaches on its own;
	// its state file is the source of truth. Blocking here would stall daemon
	// startup on guest handshakes — Task 12 wires Reconcile into startup.
	return nil
}
