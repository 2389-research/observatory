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
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/2389-research/observatory/internal/durable"
	"github.com/2389-research/observatory/internal/privd"
	"github.com/2389-research/observatory/internal/runner"
	"github.com/2389-research/observatory/internal/runtime"
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

// finalizeCtlDeadline is the socket deadline for the finalize ctl command. The
// runner answers finalize as soon as its channel loop notices finalizeCh, with
// no guest round trip in the way, so no grace period applies to it.
const finalizeCtlDeadline = 30 * time.Second

// ctlTransportSlack is the headroom ctlDeadline adds on top of the runner's own
// ceiling: time for the runner to write the reply and for this process to read
// it once the answer is decided. Without it a client and a server that both
// behave perfectly still race at the boundary.
const ctlTransportSlack = 10 * time.Second

// ctlDeadline is the socket deadline for a shutdown_guest ctl command at the
// given grace. The runner waits grace + runner.ShutdownReplySlack for the
// guest's ack and only then writes its reply, so a deadline that does not
// outlive that cuts off a runner which is answering on time — and every stop is
// then recorded forced no matter how the guest behaved. A constant deadline
// guarding a configurable wait is the bug this replaces: at the documented
// default grace of 30s (docs/examples/host-config.yaml) the old fixed 30s
// expired 5s before the runner could possibly answer.
func ctlDeadline(grace time.Duration) time.Duration {
	return grace + runner.ShutdownReplySlack + ctlTransportSlack
}

// dialCtlFn is the ctl dialer doStop sends its commands through. Production
// always uses dialCtl; it is a variable so a test can see which deadline each
// call site picks, which is otherwise only observable by waiting out the
// deadline itself.
var dialCtlFn = dialCtl

// dialCtl dials the runner's control socket and sends one command, returning the reply.
// One command per connection (runner ctl protocol). deadline bounds the whole
// exchange after the dial: the caller chooses it from what its own command can
// legitimately take to answer.
func dialCtl(sockPath string, req runner.CtlRequest, deadline time.Duration) (runner.CtlReply, error) {
	conn, err := net.DialTimeout("unix", sockPath, 5*time.Second)
	if err != nil {
		return runner.CtlReply{}, fmt.Errorf("dial runner ctl %s: %w", sockPath, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(deadline))

	enc := json.NewEncoder(conn)
	if err := enc.Encode(req); err != nil {
		return runner.CtlReply{}, fmt.Errorf("encode ctl cmd: %w", err)
	}

	var reply runner.CtlReply
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&reply); err != nil {
		return runner.CtlReply{}, fmt.Errorf("decode ctl reply: %w", err)
	}
	return reply, nil
}

// ctlRefusalReason renders a not-OK ctl reply for the log. The runner sends its
// reason verbatim -- "shutdown_ack timeout" means the guest never answered the
// shutdown message, and a write error means the channel was already broken --
// so it is passed through untouched rather than summarised into a verdict this
// layer has no standing to make.
func ctlRefusalReason(reply runner.CtlReply) string {
	if reply.Error == "" {
		return "no reason given"
	}
	return reply.Error
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

// runnerAlive reports whether the process at pid is still the runner the manifest
// recorded for vmID.
//
// Three facts answer it, in order of how much they prove.
//
// The runner's own argv is the strongest: every spawn site passes "--vm-id <id>",
// and the runner is a host process, so /proc/<pid>/cmdline is the argv it started
// with. An argv naming some other VM — or naming none — is proof this pid is not
// ours, whatever the other two say. This is the identity check the VMM cannot have:
// firecracker pivot_roots into its jail, so nothing about a jailed process may be
// read from paths under its /proc entry.
//
// The recorded start time is next: privd.PIDAlive compares /proc/<pid>/stat field 22
// against it, so a pid the kernel has handed on reads dead (SPEC §9.1 — a pid alone
// is not an identity).
//
// A bare /proc/<pid> existence check is last, and it does report a recycled pid
// alive. It is reached only when neither of the others can speak: a manifest written
// before runner_starttime existed, or by a spawn whose start-time read lost the race,
// whose pid also has no readable argv. Calling those runners dead would send doStop
// straight past the graceful path and let Reconcile spawn a second runner onto a live
// VM — worse than the false positive it keeps.
func runnerAlive(pid int, starttime, vmID string) bool {
	if pid <= 0 {
		return false
	}
	switch named, known := runnerNamesVM(pid, vmID); {
	case known && !named:
		return false
	case starttime != "":
		return privd.PIDAlive(pid, starttime)
	case known:
		// named is true here: the argv supplies the identity this manifest lacks.
		return true
	default:
		_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
		return err == nil
	}
}

// pidAliveFn is the /proc liveness check the proof gate runs. Production always
// uses privd.PIDAlive; it is a variable so a test can drive the gate without a
// process it has to keep alive on the host.
var pidAliveFn = privd.PIDAlive

// vmmDeathPollInterval is how often the proof gate re-reads /proc. Signals are
// asynchronous, so a process that is going to die from one normally does so in
// milliseconds.
const vmmDeathPollInterval = 50 * time.Millisecond

// vmmProofWindow bounds how long doStop waits for a signalled VMM to be reaped
// before reporting the stop unproven. It is the same 10s budget the signal and
// release calls get, for the same reason: doStop holds launchMu, so every launch,
// stop and release on the host queues behind whatever it is waiting for.
const vmmProofWindow = 10 * time.Second

// vmmTermWindow is how long a SIGTERM gets to land before the stop escalates to
// SIGKILL. Firecracker exits on SIGTERM, so this normally ends in milliseconds.
const vmmTermWindow = 5 * time.Second

// vmmProvenGone reports whether the VMM this manifest names is gone, and says
// what it observed either way.
//
// Only proof returns true. That is the asymmetry the whole stop path rests on:
// calling a live VMM dead releases its memory to admission and invites a second
// VM onto it, while calling a dead one alive costs a retry.
//
// A pid with no recorded start time is the trap this function exists to close.
// privd.PIDAlive compares /proc/<pid>/stat field 22 against the recorded value,
// and an empty recorded value matches nothing -- so it answers false for a
// perfectly healthy VMM. Reading that as death would be proof extracted from an
// absence of evidence. The pid's absence from /proc is still proof, because
// nothing at all is running there; its presence is not, because there is no
// identity to check what is running there against.
func vmmProvenGone(m Manifest) (bool, string) {
	switch {
	case m.VMMPID <= 0:
		return true, "manifest records no vmm pid, so there is no process to end"
	case m.VMMStart == "":
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", m.VMMPID)); os.IsNotExist(err) {
			return true, fmt.Sprintf("no process at pid %d (manifest records no vmm start time)", m.VMMPID)
		}
		return false, fmt.Sprintf("pid %d exists and the manifest records no vmm start time to identify it by", m.VMMPID)
	case pidAliveFn(m.VMMPID, m.VMMStart):
		return false, fmt.Sprintf("vmm pid %d start time %s is alive", m.VMMPID, m.VMMStart)
	default:
		return true, fmt.Sprintf("vmm pid %d start time %s is gone", m.VMMPID, m.VMMStart)
	}
}

// awaitVMMGone polls vmmProvenGone until it proves the VMM gone, the window
// closes, or ctx ends. It returns the last thing it observed, which is the
// reason a stop that never got its proof reports.
func awaitVMMGone(ctx context.Context, m Manifest, window time.Duration) (bool, string) {
	gone, detail := vmmProvenGone(m)
	if gone {
		return true, detail
	}
	deadline := time.NewTimer(window)
	defer deadline.Stop()
	ticker := time.NewTicker(vmmDeathPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false, detail
		case <-deadline.C:
			return false, detail
		case <-ticker.C:
			if gone, detail = vmmProvenGone(m); gone {
				return true, detail
			}
		}
	}
}

// runnerNamesVM asks the process at pid which VM it is running, and says when it
// has no answer rather than guessing one.
//
// known is false when the argv cannot be read at all — a reaped pid has no /proc
// entry, and a zombie's cmdline is empty. That is no evidence either way, and must
// not turn a live runner dead. When known is true, named is proof: this pid either
// is running vmID or is not.
func runnerNamesVM(pid int, vmID string) (named, known bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(data) == 0 {
		return false, false
	}
	// cmdline is NUL-separated with a trailing NUL.
	argv := strings.Split(strings.TrimSuffix(string(data), "\x00"), "\x00")
	for i, arg := range argv {
		switch {
		case arg == "--vm-id" && i+1 < len(argv):
			return argv[i+1] == vmID, true
		case strings.HasPrefix(arg, "--vm-id="):
			// Go's flag package takes the joined form as readily as the separated
			// one, so a runner restarted by hand can carry it.
			return strings.TrimPrefix(arg, "--vm-id=") == vmID, true
		}
	}
	// Every spawn site passes --vm-id, so an argv without it belongs to whatever
	// the kernel handed this pid to next.
	return false, true
}

// readRunnerStart reads a freshly spawned runner's start time from /proc/<pid>/stat
// so the manifest records an identity rather than a bare pid.
//
// Best-effort by design: a runner that exits before the read, or a /proc that will
// not answer, leaves this empty and runnerAlive falls back to the pid-only check for
// that manifest. Failing the spawn over an unreadable stat file would trade a
// weakened check for a dead VM. Callers must assign the result unconditionally —
// keeping a previous boot's start time next to a new pid is worse than keeping none,
// because it makes a live runner read dead.
func readRunnerStart(pid int) string {
	data, err := os.ReadFile(privd.ProcStatPath(pid))
	if err != nil {
		return ""
	}
	return privd.ParseStartTime(string(data))
}

// Stop requests a graceful shutdown of the VM, escalating to SIGTERM/SIGKILL if needed.
//
// Protocol:
//  1. Read manifest + runner state.
//  2. If runner is alive and in attached phase: send shutdown_guest via ctl;
//     poll for vmm_exited/finalized within grace period → forced=false.
//  3. On timeout, ctl failure, or a terminal phase over a VMM /proc still shows
//     alive: SIGTERM, wait for it to land, SIGKILL if it did not → forced=true.
//  4. Prove the VMM is gone. Without that proof the stop returns
//     *runtime.ErrStopNotProven and steps 5-6 do not run at all.
//  5. ctl finalize (tolerate dead runner), ReleaseVM (chroot removed). A failed
//     release returns *runtime.ErrCleanupPending: the VM stopped, the chroot did
//     not go with it.
//  6. KEEP slot + network + manifest (stopped VM can restart; Launch reuses them).
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
		// No manifest. Usually the genuine no-op it looks like -- never launched,
		// or already released -- but the record going missing is not proof the
		// resource did. doRollback deletes the manifest unconditionally while its
		// own release can fail, so the chroot, and the VM running inside it, can
		// outlive the only file that names them. Ask the host, not the record.
		if os.IsNotExist(err) {
			return a.stopWithoutManifest(ctx, vmID)
		}
		return false, fmt.Errorf("read manifest: %w", err)
	}

	stateFile := filepath.Join(a.cfg.StateDir, "vms", vmID, "runner-state.json")
	ctlSock := filepath.Join(a.cfg.StateDir, "vms", vmID, "runner.sock")

	graceful := false

	if !forceImmediate && m.RunnerPID > 0 && runnerAlive(m.RunnerPID, m.RunnerStart, vmID) {
		// Runner is alive — attempt graceful shutdown via ctl.
		graceS := int(grace.Seconds())
		if graceS <= 0 {
			graceS = 1
		}
		reply, ctlErr := dialCtlFn(ctlSock, runner.CtlRequest{Cmd: "shutdown_guest", GraceS: graceS}, ctlDeadline(grace))
		switch {
		case ctlErr != nil:
			// The request never got an answer: the runner is gone, the socket is
			// stale, or the deadline expired. Nothing here says what the guest did.
			fmt.Fprintf(os.Stderr,
				"jailer: stop: warn: graceful shutdown request for %s did not reach the runner: %v; escalating to a forced stop\n",
				vmID, ctlErr)
		case !reply.OK:
			// The runner answered and declined. Its wording is the only account of
			// what happened inside the guest, and this is where it is recorded.
			fmt.Fprintf(os.Stderr,
				"jailer: stop: warn: runner refused graceful shutdown for %s: %s; escalating to a forced stop\n",
				vmID, ctlRefusalReason(reply))
		default:
			// shutdown_guest accepted; poll for vmm_exited or finalized within grace+5s.
			pollWindow := grace + 5*time.Second
			pollStart := time.Now()
			pollCtx, pollCancel := context.WithTimeout(ctx, pollWindow)
			defer pollCancel()
			s, _ := pollRunnerPhase(pollCtx, stateFile, runner.PhaseVMMExited, runner.PhaseFinalized)
			if s.Phase == runner.PhaseVMMExited || s.Phase == runner.PhaseFinalized {
				graceful = true
			} else {
				// The runner accepted the request — the guest acknowledged it — but
				// the VMM never reached a terminal phase inside the poll window.
				// This is the one branch that can tell "the guest never answered"
				// apart from "the guest answered and then did not go down."
				//
				// The elapsed window leads, because the allotted one is often not
				// what happened: this poll is nested inside the operation context
				// and dies with it, so it can end long before its allotment runs
				// out. Reporting "35s" for a poll that lasted 300ms sends an
				// operator after a guest that would not die, when what they have is
				// a stop that was cut short. Both are printed because they answer
				// different questions — how long the VMM actually got, and how long
				// it was supposed to get.
				fmt.Fprintf(os.Stderr,
					"jailer: stop: warn: runner accepted graceful shutdown for %s but the VMM did not reach vmm_exited or finalized within %s of an allotted %s (last phase observed: %q); escalating to a forced stop\n",
					vmID, time.Since(pollStart).Round(time.Millisecond), pollWindow, s.Phase)
			}
		}
		// If ctl failed or grace expired: fall through to forced path.
	}

	// The runner's phase is its claim about the VMM; the manifest's pid is the
	// fact. They part company on a path that really happens: onFinalize answers
	// the finalize ctl command without looking at anything, and cleanExit writes
	// "finalized" on any runner error exit (internal/runner/runner.go), so a
	// guest that breaks the channel just after acking the shutdown reaches a
	// terminal phase with its VMM untouched. Reading the phase as a completed
	// stop sent no signal at all and released the chroot of a running microVM.
	if graceful {
		if gone, detail := vmmProvenGone(m); !gone {
			graceful = false
			fmt.Fprintf(os.Stderr,
				"jailer: stop: warn: runner reported a terminal phase for %s but %s; escalating to a forced stop\n",
				vmID, detail)
		}
	}

	var signalErrs []string
	if !graceful {
		forced = true
		if m.VMMPID > 0 {
			// ForceStop goes straight to SIGKILL; the graceful-timeout path sends
			// SIGTERM first. Both results are kept: privd refusing a signal is the
			// whole explanation of why nothing died, and discarding it left an
			// operator with an unproven stop and no reason for it.
			//
			// Each call gets its own budget rather than sharing one across the
			// pair, because the wait between them can spend nearly all of a
			// shared allotment and leave the SIGKILL with the remainder.
			signal := func(kind string) {
				sigCtx, cancel := context.WithTimeout(ctx, vmmProofWindow)
				defer cancel()
				if err := a.pc.SignalVM(sigCtx, privd.SignalVMReq{VMID: vmID, Kind: kind}); err != nil {
					signalErrs = append(signalErrs, fmt.Sprintf("%s: %v", kind, err))
				}
			}
			gone := false
			if !forceImmediate {
				signal("term")
				// Wait for the SIGTERM to land instead of for a fixed five seconds.
				// Firecracker exits on SIGTERM, so this normally ends in
				// milliseconds -- and a VMM observed gone gets no SIGKILL, because
				// the only thing a signal to a reaped pid can reach is whatever the
				// kernel handed that pid to next.
				gone, _ = awaitVMMGone(ctx, m, vmmTermWindow)
			}
			if !gone {
				signal("kill")
			}
		}
	}

	// The proof gate. Everything above it is a request; this is the only place
	// doStop learns whether the VM ended, and nothing downstream may read
	// "stopped" without it. The wait is real work rather than a formality:
	// signals are asynchronous, and SIGKILL cannot reap a task in
	// uninterruptible sleep at all.
	//
	// Returning here skips both the finalize and the release on purpose. The
	// runner still has a VMM to supervise, and privd refuses to remove the
	// chroot of a live process anyway (internal/privd/server.go) -- so the
	// retry loop below would spend the whole release deadline collecting the
	// same refusal.
	gone, detail := awaitVMMGone(ctx, m, vmmProofWindow)
	if !gone {
		reason := detail
		if len(signalErrs) > 0 {
			reason += " (" + strings.Join(signalErrs, "; ") + ")"
		}
		return forced, &runtime.ErrStopNotProven{VMID: vmID, Reason: reason}
	}

	// Always send finalize to the runner (tolerate dead/missing runner socket).
	_, _ = dialCtlFn(ctlSock, runner.CtlRequest{Cmd: "finalize"}, finalizeCtlDeadline)

	// Release the jail chroot dir (privd removes <JailBase>/firecracker/<id>).
	// Keep network + slot + manifest: a stopped VM can be restarted.
	//
	// A failure here is not a failed stop, and it is not a silent one either.
	// The VMM is proven gone, so the compute is genuinely free and the row
	// belongs at "stopped": returning a plain error would route the operation
	// into failAction, park the VM at "stopping" and hold its memory against
	// admission over a jail directory. The debt is real all the same --
	// <JailBase>/firecracker/<vmID> and a pinned privd ledger entry survive, and
	// allocateSlot goes on counting the manifest against MaxSlots. This is what
	// used to go to stderr and nowhere else, leaving the leak invisible to every
	// surface an operator reads.
	//
	// ErrCleanupPending carries both facts together: the stop succeeded, and
	// this is what it left behind. The stop path settles the VM and records the
	// debt beside it; the delete path takes it as a failure, because a "deleted"
	// row promises more than a stopped one has to.
	releaseCtx, releaseCancel := context.WithTimeout(ctx, 10*time.Second)
	defer releaseCancel()
	if debt := a.chrootDebt(vmID, a.releaseVMWhenDead(releaseCtx, vmID)); debt != nil {
		return forced, &runtime.ErrCleanupPending{
			VMID:     vmID,
			Resource: "jail chroot",
			Reason:   debt.Error(),
		}
	}

	return forced, nil
}

// stopWithoutManifest answers a stop for a VM whose manifest is gone, by probing
// what is actually on the host.
//
// No jail chroot: the no-op the missing manifest suggests. privd's release_vm
// removes <JailBase>/firecracker/<id> whole, and a normal stop runs it while
// keeping the manifest, so a VM that stopped cleanly and one that never launched
// both leave nothing here. false, nil, exactly as before.
//
// A delete does not always run it. Manager.Delete force-stops only from a live
// state, and a guest that shuts itself down reaches "stopped" through
// NotifyVMMExit without any runtime call at all (internal/runtime/manager.go), so
// its jail chroot outlives the delete that follows. That leak never reaches this
// seam -- the manifest is still there, so doRelease takes its ordinary path.
// doRelease is what closes it: both of its release verbs run unconditionally
// now, manifest present or not, the same way the two below do.
//
// Jail chroot present: the record is gone and the resource is not. Answering success
// there is the lie this seam exists to prevent. It used to travel: Release took the
// same missing manifest as "already gone" and returned nil, and Delete wrote
// "deleted" over a microVM that was still running. doRelease closed that half;
// this one is still the first to notice.
//
// Tearing it down beats only complaining about it. The caller that reaches this state
// most often is runLaunch's cleanup behind a failed launch, which discards
// ForceStop's error (internal/runtime/manager.go), so an error alone would change
// nothing on the host and leave the chroot and a possibly-live VM standing. Manager's
// Delete takes the opposite line and aborts the delete on any non-Unavailable error
// from its force-stop, so answering with an unconditional error would wedge the
// delete of an orphaned VM with no way out. The teardown needs nothing from the manifest: privd's ledger is keyed
// by vm_id and holds the pid and start time, and privd re-verifies that identity
// itself before it signals anything.
//
// The verdict comes from the filesystem afterwards, not from what privd returned: an
// error only when the chroot is still there.
func (a *Adapter) stopWithoutManifest(ctx context.Context, vmID string) (bool, error) {
	jailDir := filepath.Join(a.cfg.JailBase, "firecracker", vmID)
	if _, statErr := os.Stat(jailDir); statErr != nil {
		if os.IsNotExist(statErr) {
			return false, nil
		}
		return false, fmt.Errorf("jailer stop %s: stat jail chroot %q: %w", vmID, jailDir, statErr)
	}

	fmt.Fprintf(os.Stderr,
		"jailer: stop: warn: %s has no manifest but its jail chroot %s is still on disk; "+
			"killing and releasing it\n", vmID, jailDir)

	// Nothing here asked the guest anything, so whatever happens next is a forced
	// stop. SIGKILL first: privd refuses release_vm while it can still see the
	// process. A ledger entry that is already gone answers not_found, which is a
	// fine outcome -- the release below then reports the chroot nobody can remove.
	//
	// Its own budget, and the reason is the caller's context, not this call's cost:
	// privd.Client.call sets a socket deadline only when the context carries one
	// (internal/privd/client.go), and both callers that reach a manifest-less stop
	// pass a deadline-free context -- runLaunch's cleanup and Manager.Reconcile both
	// run on the manager's root context (internal/runtime/manager.go). A privd that
	// accepts the connection and never answers would block this read forever while
	// doStop holds launchMu, queueing every launch, stop and release on the host
	// behind it. 10s is the same bound doStop's force path and the release below use.
	signalCtx, signalCancel := context.WithTimeout(ctx, 10*time.Second)
	_ = a.pc.SignalVM(signalCtx, privd.SignalVMReq{VMID: vmID, Kind: "kill"})
	signalCancel()

	releaseCtx, releaseCancel := context.WithTimeout(ctx, 10*time.Second)
	releaseErr := a.releaseVMWhenDead(releaseCtx, vmID)
	releaseCancel()

	if _, statErr := os.Stat(jailDir); os.IsNotExist(statErr) {
		return true, nil
	}
	if releaseErr != nil {
		return true, fmt.Errorf("jailer stop %s: manifest gone and jail chroot %s could not be released: %w",
			vmID, jailDir, releaseErr)
	}
	return true, fmt.Errorf("jailer stop %s: manifest gone and jail chroot %s survives a release privd accepted",
		vmID, jailDir)
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
// Releases: the VM (jail chroot), network, manifest, <StateDir>/vms/<id>/, stage dir.
// Keeps: spool dir (importer reads it independently).
//
// Concurrency: holds launchMu to prevent interleaving with an in-progress Launch.
func (a *Adapter) Release(ctx context.Context, vmID string) error {
	a.launchMu.Lock()
	defer a.launchMu.Unlock()
	return a.doRelease(ctx, vmID)
}

// doRelease is the real implementation, called with launchMu held. There is one
// path here regardless of whether vmID has a manifest -- there used to be two,
// and the gap between them is why this function looks the way it does now.
//
// A present manifest used to gate release_network on stageSet[stageNetwork] and
// never called release_vm at all. Most releases never noticed: a normal
// Stop/ForceStop already calls release_vm before Release runs. The case that did
// notice is a guest that shuts itself down -- it reaches "stopped" through
// Manager.NotifyVMMExit (internal/runtime/manager.go), which makes no runtime
// call at all, so Delete's force-stop skips it and goes straight to Release with
// the manifest still there. Nothing had ever called release_vm, so
// <JailBase>/firecracker/<id> and its privd ledger entry outlived a row that read
// "deleted". A missing manifest tells the same lie from the other side:
// doRollback removes <StateDir>/vms/<id> whether or not its own release landed
// (internal/jailer/launch.go), so a failed launch can leave no manifest and a
// live chroot too. Neither a present manifest nor a missing one is evidence
// about what privd or the filesystem still hold, so both release verbs below run
// unconditionally, on every call, with no stage or manifest gate on either.
//
// release_vm runs first, and the order is load-bearing, not cosmetic. An entry
// whose VM half is already clear -- the pid is written only by a successful
// start_vm and cleared by release_vm -- has release_network as its last occupied
// half; calling that first deletes the ledger entry, and release_vm then answers
// not_found without ever removing the tree. Both are attempted even when the
// first fails: a refused release_vm leaves a non-zero pid in the entry, and
// release_network then writes the partial entry back rather than losing it. Both
// verbs also tolerate not_found on their own -- privd's ordinary answer for a
// vm_id its ledger does not know (internal/privd/server.go), and success here,
// not failure.
//
// The verdict comes from the host, not from what privd returned. The jail chroot
// is the one thing here that can be stat'd, so a chroot still on disk is an
// error whatever the release said; a release that failed for any reason other
// than not_found is a resource privd knows about and could not clear, which is
// an error too. Either one leaves Delete's row at "deleting" -- a delete that
// lies is worse than one that has to be retried.
//
// The manifest is removed only after that verdict, because it is the lease on
// the slot -- and so on the jail uid and guest CID derived from it. A release
// that reports failure must not have already handed those identities to the
// next launch.
// chrootDebt answers what a release of the jail chroot left behind, given what
// privd returned and what is on disk. nil means nothing survives; an error names
// the path that does, and why.
//
// The verdict comes from the filesystem rather than from privd's answer, because
// the two disagree in exactly the state this exists to get right. privd's ledger
// lives on a tmpfs (deploy/README.md mounts /run that way) while the chroots live
// on the runtime volume, so a privd restart answers not_found for VMs whose
// directories are still there. Reading not_found as "already clean" would report
// a leak as reclaimed; reading it as a failure -- which the force-stop path did
// -- reports a debt for a chroot that is not there, and Manager.Delete treats
// ErrCleanupPending as a failed force-stop, so the row can never leave
// "deleting" and its disk reservation is never released.
//
// A non-not_found error still counts as a debt once the directory is gone: the
// ledger entry it pins is a held uid and CID, which is a resource whether or not
// anything remains on disk.
func (a *Adapter) chrootDebt(vmID string, vmErr error) error {
	vmErr = ignoreNotFound(vmErr)
	jailDir := filepath.Join(a.cfg.JailBase, "firecracker", vmID)
	_, statErr := os.Stat(jailDir)
	switch {
	case statErr == nil && vmErr != nil:
		return fmt.Errorf("jail chroot %s could not be released: %w", jailDir, vmErr)
	case statErr == nil:
		return fmt.Errorf("jail chroot %s survives a release privd accepted", jailDir)
	case !os.IsNotExist(statErr):
		return fmt.Errorf("stat jail chroot %q: %w", jailDir, statErr)
	case vmErr != nil:
		return fmt.Errorf("release_vm: %w", vmErr)
	}
	return nil
}

func (a *Adapter) doRelease(ctx context.Context, vmID string) error {
	releaseCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	vmErr := ignoreNotFound(a.releaseVMWhenDead(releaseCtx, vmID))
	netErr := ignoreNotFound(a.pc.ReleaseNetwork(releaseCtx, privd.ReleaseNetworkReq{VMID: vmID}))

	// Remove stage dir (disk images + fc-config.json).
	// Removing a missing path is a no-op — no stage guard needed.
	stageDir := filepath.Join(a.cfg.StageRoot, vmID)
	if err := durable.RemoveAll(stageDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("jailer release %s: remove stage dir: %w", vmID, err)
	}

	if debt := a.chrootDebt(vmID, vmErr); debt != nil {
		return fmt.Errorf("jailer release %s: %w", vmID, debt)
	}
	if netErr != nil {
		return fmt.Errorf("jailer release %s: release_network: %w", vmID, netErr)
	}

	// Remove <StateDir>/vms/<id>/ — includes manifest.json, token, runner-state.json, etc.
	// Removing a missing path is a no-op — no stage guard needed.
	//
	// This runs last, after the verdict rather than before it, because the
	// manifest is not only a record of what the launch provisioned: it is the
	// lease on the slot, and through the slot on the jail uid and the guest CID
	// (uid = JailUIDBase + slot, cid = CIDBase + slot, see Launch). allocateSlot
	// reads a slot as taken for exactly as long as some manifest names it, so
	// removing the manifest IS the act of reclaiming those identities. Doing it
	// before the verdict surrendered the lease on the failure path: the chroot
	// survives under uid N while the next launch is handed slot N and starts a
	// different VM's firecracker under the same uid, on the same CID as a VM
	// that is still alive. The row parked at "deleting" and Reconcile's retry
	// were both correct and both too late.
	//
	// The removal is made durable before this returns nil, because nil is what
	// lets the caller reclaim those identities. A removal that a crash could
	// undo would put them back in use under a VM already told they are free.
	vmStateDir := filepath.Join(a.cfg.StateDir, "vms", vmID)
	if err := durable.RemoveAll(vmStateDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("jailer release %s: remove state dir: %w", vmID, err)
	}

	// Spool dir is intentionally not removed: the importer reads segments independently.
	// (Brief note: Task 7's importer prunes segments only, not VM dirs — verified.)
	return nil
}

// ignoreNotFound drops privd's not_found, the answer for a vm_id its ledger has
// no entry for. Release is idempotent by contract, so "there was nothing to
// release" is the success case, not a failure to report.
func ignoreNotFound(err error) error {
	var re *privd.RemoteError
	if errors.As(err, &re) && re.Cause == "not_found" {
		return nil
	}
	return err
}

// Reconcile scans <StateDir>/vms/*/manifest.json at startup and classifies each VM.
// Outcomes:
//   - "adopted": runner alive, attached, naming this VM in its argv, and agreeing
//     with the manifest about which VMM it is attached to → healthy, no action.
//   - "vmm_gone": VMM process gone → report for manager to mark failed.
//   - "ambiguous": unreadable manifest or identity mismatch → touch nothing (§5.5).
//
// When the runner is dead but the VMM is alive and identity matches, a fresh runner
// is respawned with a new instance-id (so the store importer deduplicates correctly).
//
// These findings are what tells a controller restart from a fleet outage: the
// manager fails every running VM it cannot account for, so an "adopted" that never
// reaches it costs a live VM its row (ManagerConfig.AdoptedVMs).
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
		runnerAlive(m.RunnerPID, m.RunnerStart, vmID)

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

	// Update manifest with the new runner's identity. The start time is assigned
	// unconditionally: an empty read must clear the previous runner's value, not
	// leave it paired with the new pid.
	m.RunnerPID = cmd.Process.Pid
	m.RunnerStart = readRunnerStart(cmd.Process.Pid)
	if err := writeManifest(a.cfg.StateDir, m); err != nil {
		// Best-effort: runner is running even if manifest update fails.
		fmt.Fprintf(os.Stderr, "jailer: reconcile: warn: update manifest runner_pid for %s: %v\n", vmID, err)
	}

	// Do NOT wait for the runner to attach here. The runner attaches on its own;
	// its state file is the source of truth. Blocking here would stall daemon
	// startup on guest handshakes — Task 12 wires Reconcile into startup.
	return nil
}
