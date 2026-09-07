// ABOUTME: M2a gate test: real guest telemetry over vsock on a live Firecracker VM.
// ABOUTME: Requires VMOBS_FIXTURE=1 and scripts/aibox03/setup.sh (incl. vmobs-privd).

//go:build linux

package integration_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	// m2aHeartbeatKind is the guest agent's periodic self-report — the only
	// guest_reported kind M2a puts on the wire (§138).
	m2aHeartbeatKind = "guest.sensor_health"
	// m2aChannelLostKind and m2aChannelEstablishedKind are the host's own record
	// of the same outage. They are host_observed, which is why they survive the
	// guest's stream being the thing in question.
	m2aChannelLostKind        = "guest.channel_lost"
	m2aChannelEstablishedKind = "guest.channel_established"
)

// guestdStateProbe asks the guest whether its agent is running, and guestdActive
// is the answer that means yes.
//
// The tag is not decoration. `systemctl is-active` answers the bare words active,
// inactive or failed, so a substring test for "active" passes on "inactive" — the
// assertion would hold in exactly the case it exists to catch. Tagging the answer
// makes the two words disjoint. The echoed command itself cannot forge a match:
// what it contains is "guestd-state=/".
const (
	guestdStateProbe = `systemctl is-active guestd | sed 's/^/guestd-state=/'`
	guestdActive     = "guestd-state=active"
)

// m2aRingCapacity is telemetryRingCapacity in internal/guest/telemetry.go. The
// gate asserts the guest reports the bound it was built with: §139's drop count
// says nothing without the capacity it was measured against.
const m2aRingCapacity = 1024

// m2aStalenessBudget is how long the gate waits for a stopped guestd to show up
// as degraded. internal/situation/telemetry_health.go calls a heartbeat stale
// after stalenessIntervals (3) × the interval the guest reports (10s), so the
// answer is due about 30s after the last beat; the rest is room for the poll and
// a busy host.
const m2aStalenessBudget = 3 * time.Minute

// m2aReviveDelay is how long guestd stays stopped before a transient systemd
// unit inside the guest starts it again.
//
// A scheduled revive is the only way back. The guest's PTY is a child of
// guestd's own cgroup, so stopping guestd takes the terminal with it, and a new
// terminal cannot be created while the agent that would serve it is down. The
// delay is what makes the observation safe rather than raced: degraded is due at
// ~35s, and an agent that returned at 60s could refresh the heartbeat before the
// poll ever saw the transition — a red gate reporting the opposite of what
// happened. 150s buys four times the margin the derivation needs.
const m2aReviveDelay = 150 * time.Second

// TestM2aGate is the M2a gate: guest telemetry over vsock on real Firecracker
// VMs via the installed vmobs-privd. Guard: VMOBS_FIXTURE=1, plus the privd
// socket and stage dir the M1a gate already checks for.
//
// Evidence is captured into tests/integration/evidence/m2a-gate-<hostname>.txt.
//
// Run it with a timeout that clears the two waits it cannot shorten: a real boot
// (~1 min per VM, two VMs) and the revive delay above.
//
//	scripts/linux 'env -u GOROOT VMOBS_FIXTURE=1 go test ./tests/integration/ \
//	    -run TestM2aGate -v -count=1 -timeout 25m'
func TestM2aGate(t *testing.T) {
	if os.Getenv("VMOBS_FIXTURE") != "1" {
		t.Skip("set VMOBS_FIXTURE=1 to run the M2a telemetry gate (requires installed vmobs-privd; must NOT run as root)")
	}
	gateSkipChecks(t)
	m1aSkipChecks(t)

	if os.Getuid() == 0 {
		t.Fatal("M2a gate must not run as root; privileged ops flow through privd socket only")
	}

	repoRoot := findRepoRoot(t)
	daemonBin := buildBinary(t, "github.com/2389-research/observatory/cmd/vmobsd")
	runnerBin := buildBinary(t, "github.com/2389-research/observatory/cmd/vmobs-runner")

	daemon := startDaemon(t, repoRoot, daemonBin, runnerBin, "m2a-primary",
		withRequiredAuth(m1bOperator, m1bPassword))

	hostname, _ := os.Hostname()
	var evidence strings.Builder
	fmt.Fprintf(&evidence, "# M2a gate evidence\n")
	fmt.Fprintf(&evidence, "# hostname: %s\n", hostname)
	fmt.Fprintf(&evidence, "# date: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&evidence, "# pid: %d\n", os.Getpid())
	fmt.Fprintf(&evidence, "# paths.runtime: %s\n", daemon.runtimeDir)
	fmt.Fprintf(&evidence, "# paths.state: %s\n", daemon.stateDir)

	bootCtx, cancelBoot := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancelBoot()

	vmID := daemon.createVM(t, "m2a-telemetry")
	daemon.waitVMState(bootCtx, t, vmID, "running")
	fmt.Fprintf(&evidence, "# vm: %s\n", vmID)

	// One terminal, opened here rather than inside a subtest: the guest commands
	// below span two subtests, and a terminal registered on a subtest's t would
	// be closed before the second one ran.
	term := daemon.openTerm(t, daemon.createTerminal(t, vmID).ID, "m2a-guest")
	term.takeWriter()

	// ── Telemetry arrives ──────────────────────────────────────────────────────
	// The transport, end to end: guest ring → vsock 10001 → runner → spool →
	// store → API, with the runner's stream identity on it and the guest's own
	// sequence inside it.
	t.Run("telemetry_arrives", func(t *testing.T) {
		page := daemon.waitHeartbeats(t, vmID, 2, 90*time.Second)
		first := page[0]

		if got := stringField(first, "provenance"); got != "guest_reported" {
			t.Errorf("heartbeat provenance = %q, want %q — the agent's self-report is the guest's claim", got, "guest_reported")
		}
		if got := stringField(first, "sensor"); got != "guestd" {
			t.Errorf("heartbeat sensor = %q, want %q", got, "guestd")
		}
		streamID := stringField(first, "source_instance_id")
		if !isLowercaseUUID(streamID) {
			t.Errorf("source_instance_id = %q, want a lowercase uuid; the runner derives it, the guest never names it", streamID)
		}
		bootID := stringField(first, "boot_id")
		if bootID == "" {
			t.Error("heartbeat carries no boot_id; telemetry_health scopes the newest heartbeat to the current boot")
		}
		mf, err := readM1aManifest(daemon.stateDir, vmID)
		if err != nil {
			t.Fatalf("read manifest: %v", err)
		}
		if bootID != mf.BootID {
			t.Errorf("heartbeat boot_id = %q, manifest boot_id = %q", bootID, mf.BootID)
		}

		// One stream, sequence counting from one inside it, strictly increasing.
		order, seqs := telemetryStreams(page)
		if len(order) != 1 {
			t.Errorf("a VM whose agent never restarted has %d stream identities, want 1: %v", len(order), order)
		}
		if got := seqs[streamID][0]; got != "1" {
			t.Errorf("first source_seq on stream %s = %q, want %q", streamID, got, "1")
		}
		assertSeqIncreases(t, streamID, seqs[streamID])

		// The ring block rides every heartbeat: §507 wants loss measured, and a
		// drop count with no capacity beside it cannot be read.
		ring := mapField(mapField(first, "data"), "ring")
		if ring == nil {
			t.Fatalf("heartbeat data carries no ring block: %v", first["data"])
		}
		capacity := intField(t, ring, "capacity")
		if capacity != m2aRingCapacity {
			t.Errorf("ring capacity = %d, want %d", capacity, m2aRingCapacity)
		}
		if got, ok := ring["dropped"].(string); !ok {
			t.Errorf("ring dropped = %v (%T), want a decimal string — the count can outgrow a JSON number", ring["dropped"], ring["dropped"])
		} else if got != "0" {
			t.Errorf("ring dropped = %q on a VM that has beaten twice, want %q", got, "0")
		}

		// The agent's declared interval is what the host derives staleness from,
		// so a heartbeat that does not carry it silently buys the widest window
		// the host allows.
		agent := mapField(mapField(first, "data"), "agent")
		intervalNS := stringField(agent, "heartbeat_interval_ns")
		interval, convErr := strconv.ParseInt(intervalNS, 10, 64)
		if convErr != nil || interval <= 0 {
			t.Errorf("agent heartbeat_interval_ns = %q, want a positive decimal string of nanoseconds", intervalNS)
		}

		// M2a registers no sensor. An empty list is the honest answer and has to
		// arrive as [] — a null would read as "the agent does not know".
		sensors, ok := mapField(first, "data")["sensors"].([]any)
		if !ok {
			t.Errorf("heartbeat sensors = %v (%T), want an array (empty until M2b registers one)",
				mapField(first, "data")["sensors"], mapField(first, "data")["sensors"])
		} else if len(sensors) != 0 {
			t.Errorf("heartbeat reports %d sensors, want 0 — M2a registers none", len(sensors))
		}

		vm := daemon.apiGet(t, "/vms/"+vmID)
		health := stringField(vm, "telemetry_health")
		lifecycle := stringField(vm, "observed_state")
		if health != "healthy" {
			t.Errorf("telemetry_health = %q with heartbeats flowing, want %q", health, "healthy")
		}
		if lifecycle != "running" {
			t.Errorf("observed_state = %q, want %q", lifecycle, "running")
		}

		evidenceSubtest(t, &evidence, "telemetry_arrives", fmt.Sprintf(
			"vm=%s boot_id=%s (manifest boot_id matches: %v)\n"+
				"kind=%s provenance=%q sensor=%q\n"+
				"stream identities on this boot: %d (%v); source_seq: %v\n"+
				"ring: capacity=%d queued=%v dropped=%q\n"+
				"agent: heartbeat_interval_ns=%q sensors=%d (M2a registers none)\n"+
				"GET /vms/%s: telemetry_health=%q observed_state=%q",
			vmID, bootID, bootID == mf.BootID,
			m2aHeartbeatKind, stringField(first, "provenance"), stringField(first, "sensor"),
			len(order), order, seqs[streamID],
			capacity, ring["queued"], ring["dropped"],
			intervalNS, len(sensors),
			vmID, health, lifecycle,
		))
	})

	// ── AT-074: the agent dies, the VM does not ────────────────────────────────
	t.Run("at074_guestd_stopped_degrades", func(t *testing.T) {
		if out := term.runGuest(guestdStateProbe, m1bCommandTimeout); !strings.Contains(out, guestdActive) {
			t.Fatalf("guestd is not active in the guest before the test starts: %s", tailOf(out, 400))
		}

		// Scheduled from inside the guest because stopping guestd takes this
		// terminal with it: the PTY lives in guestd's cgroup, and no new terminal
		// can be created while the agent is down.
		cycle := fmt.Sprintf("systemd-run --collect /bin/sh -c 'sleep 5; systemctl stop guestd; sleep %d; systemctl start guestd'",
			int(m2aReviveDelay.Seconds()))
		out := term.runGuest(cycle, m1bCommandTimeout)
		if strings.Contains(out, "not found") {
			t.Fatalf("the guest has no systemd-run, so the stop could not be scheduled: %s", tailOf(out, 400))
		}
		scheduledAt := time.Now()

		// The host's own record that the agent went away, independent of any
		// health derivation: the runner's control channel broke and it said so.
		lostCtx, cancelLost := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancelLost()
		lost := daemon.waitEventKind(lostCtx, t, vmID, m2aChannelLostKind)
		lostAfter := time.Since(scheduledAt)

		degradedAfter, lifecycle := daemon.waitTelemetryHealth(t, vmID, "degraded", m2aStalenessBudget)
		// §138: a telemetry outage is not a lifecycle outage. Nothing consumes
		// guest.channel_lost to fail a VM, and this is the assertion that keeps
		// it that way.
		if lifecycle != "running" {
			t.Errorf("observed_state = %q while telemetry_health went degraded, want %q — §138 forbids folding "+
				"observation quality into lifecycle state", lifecycle, "running")
		}

		// The agent comes back on the schedule set above, and the host notices
		// without being told.
		healthyAfter, backLifecycle := daemon.waitTelemetryHealth(t, vmID, "healthy", m2aReviveDelay+m2aStalenessBudget)
		if backLifecycle != "running" {
			t.Errorf("observed_state = %q after the agent returned, want %q", backLifecycle, "running")
		}

		evidenceSubtest(t, &evidence, "at074_guestd_stopped_degrades", fmt.Sprintf(
			"guest command: %s\n"+
				"host record of the outage: %s reason=%v after %.0fs\n"+
				"telemetry_health healthy -> degraded after %.0fs (due at 3 x the agent's 10s interval)\n"+
				"observed_state at that moment: %q (§138: the two dimensions did not fold together)\n"+
				"agent restarted on schedule; telemetry_health -> healthy after %.0fs, observed_state %q\n"+
				"unavailable is NOT reachable this way and the gate does not claim it: deriveTelemetryHealth "+
				"returns degraded for a stale heartbeat, and unavailable needs a non-running VM, an empty "+
				"current boot, or no heartbeat at all for the boot. §952 asks for degraded OR unavailable; "+
				"stopped_vm_is_unavailable below walks the other one.",
			cycle,
			m2aChannelLostKind, mapField(lost, "data")["reason"], lostAfter.Seconds(),
			degradedAfter.Seconds(), lifecycle,
			healthyAfter.Seconds(), backLifecycle,
		))
	})

	// ── A restarted agent is a new stream, not a continuation ──────────────────
	t.Run("guestd_restart_new_stream", func(t *testing.T) {
		before := daemon.heartbeatPage(t, vmID)
		knownOrder, knownSeqs := telemetryStreams(before)
		known := map[string]int{}
		for _, id := range knownOrder {
			known[id] = len(knownSeqs[id])
		}

		// The terminal from the previous subtest died with guestd. The agent is
		// back, so a new one can be created — and that it can is itself the proof
		// the control channel recovered.
		revived := daemon.openTerm(t, daemon.createTerminal(t, vmID).ID, "m2a-guest-revived")
		revived.takeWriter()
		if out := revived.runGuest(guestdStateProbe, m1bCommandTimeout); !strings.Contains(out, guestdActive) {
			t.Fatalf("guestd is not active again: %s", tailOf(out, 400))
		}
		// Detached for the same reason as before, with a shorter fuse: this
		// restart is meant to be brief, and nothing here waits on staleness.
		restart := "systemd-run --collect /bin/sh -c 'sleep 3; systemctl restart guestd'"
		if out := revived.runGuest(restart, m1bCommandTimeout); strings.Contains(out, "not found") {
			t.Fatalf("the guest has no systemd-run: %s", tailOf(out, 400))
		}

		newID, after := daemon.waitNewTelemetryStream(t, vmID, known, 2*time.Minute)
		order, seqs := telemetryStreams(after)

		// A new epoch restarts the guest-owned sequence. It is a different stream,
		// so (source_instance_id, source_seq) stays unique and nothing is
		// deduplicated against the stream that came before it.
		if got := seqs[newID][0]; got != "1" {
			t.Errorf("first source_seq on the new stream %s = %q, want %q", newID, got, "1")
		}
		assertSeqIncreases(t, newID, seqs[newID])

		// Same boot: the agent restarted, the VM did not.
		bootIDs := map[string]bool{}
		for _, e := range after {
			bootIDs[stringField(e, "boot_id")] = true
		}
		if len(bootIDs) != 1 {
			t.Errorf("heartbeats span %d boots, want 1 — a guestd restart is not a VM boot: %v", len(bootIDs), bootIDs)
		}

		// Nothing already stored was rewritten or replaced.
		for id, n := range known {
			if got := len(seqs[id]); got < n {
				t.Errorf("stream %s had %d heartbeats before the restart and %d after; stored events are append-only", id, n, got)
			}
		}

		healthyAfter, lifecycle := daemon.waitTelemetryHealth(t, vmID, "healthy", 90*time.Second)
		if lifecycle != "running" {
			t.Errorf("observed_state = %q after the agent restarted, want %q", lifecycle, "running")
		}

		evidenceSubtest(t, &evidence, "guestd_restart_new_stream", fmt.Sprintf(
			"guest command: %s\n"+
				"stream identities before: %d %v\n"+
				"stream identities after:  %d %v\n"+
				"new stream %s first source_seq=%q (a new agent epoch restarts the guest-owned sequence)\n"+
				"distinct boot_ids across all heartbeats: %d (a guestd restart is not a VM boot)\n"+
				"telemetry_health -> healthy after %.0fs, observed_state %q",
			restart,
			len(knownOrder), knownOrder,
			len(order), order,
			newID, seqs[newID][0],
			len(bootIDs),
			healthyAfter.Seconds(), lifecycle,
		))
	})

	// ── The ring's own report, and what this gate cannot settle ────────────────
	t.Run("ring_report_is_on_the_wire", func(t *testing.T) {
		page := daemon.heartbeatPage(t, vmID)
		if len(page) == 0 {
			t.Fatal("no heartbeats to read a ring block from")
		}
		newest := page[len(page)-1]
		ring := mapField(mapField(newest, "data"), "ring")
		if ring == nil {
			t.Fatalf("newest heartbeat carries no ring block: %v", newest["data"])
		}
		for _, key := range []string{"capacity", "queued", "dropped"} {
			if _, ok := ring[key]; !ok {
				t.Errorf("ring block has no %q; §139 wants observed drops reported, not inferred", key)
			}
		}
		dropped, _ := ring["dropped"].(string)
		if dropped != "0" {
			t.Errorf("ring dropped = %q; nothing in this run could have overflowed a %d-item ring", dropped, m2aRingCapacity)
		}

		evidenceSubtest(t, &evidence, "ring_report_is_on_the_wire", fmt.Sprintf(
			"newest heartbeat ring: capacity=%v queued=%v dropped=%q (all three fields present on the wire)\n"+
				"INCONCLUSIVE — a non-zero drop count was not observed live, and this gate does not claim one.\n"+
				"The ring holds %d items and drops the oldest only when full. Items leave it on host "+
				"acknowledgement, and in M2a the heartbeat is its only producer (health.go's Beat is the sole "+
				"Push call site; no sensor exists until M2b). At one push per 10s, filling it takes about 2.8 "+
				"hours with the host deliberately not acknowledging — longer than any gate should run, and a "+
				"guestd built to push faster would be a test-only agent shipped into the product.\n"+
				"What is proven instead: the drop count's wire path is exercised on every heartbeat above, and "+
				"the drop accounting itself is covered by internal/guest/telemetry/ring_test.go "+
				"(TestRingDropsOldestAndCounts, TestRingDropCountDoesNotResetOnDrain). Only the live "+
				"observation of a non-zero value is unproven.",
			ring["capacity"], ring["queued"], ring["dropped"], m2aRingCapacity,
		))
	})

	// ── AT-075: a controller restarts, the VM it owns does not ─────────────────
	//
	// The kill and the restart run here, in the parent body, and the subtest below
	// only reads what they produced. Two structural reasons. A daemon started
	// under a subtest's t is torn down when that subtest returns, and the last
	// subtest still needs a controller to answer. And the assertions compare facts
	// captured on both sides of the kill, so the capture has to outlive whichever
	// t.Run reads it.
	//
	// It is the primary controller that dies, and the VM this gate has been
	// watching all along that gets adopted.
	//
	// An earlier draft ran the restart on a private state dir instead, booting a
	// third VM under a pair of throwaway daemons while the primary was still up.
	// That never reached the restart: the launch failed at stage attached with
	// "runner exited before attaching", and doRollback removed the VM state dir
	// with runner.log inside it, so the fatal step was never isolated. What is
	// certain is that the setup put two live controllers on one host, which
	// production never does, and that allocateSlot scans only its own state dir —
	// so both handed out slot 0, and slot is what the jail uid and the guest CID
	// are derived from. The scenario AT-075 names needs one controller anyway.
	beforeVM := daemon.apiGet(t, "/vms/"+vmID)
	beforeRevision := stringField(beforeVM, "revision")
	beforeState := stringField(beforeVM, "observed_state")
	beforeManifest, err := readM1aManifest(daemon.stateDir, vmID)
	if err != nil {
		t.Fatalf("read manifest before the controller restart: %v", err)
	}
	if beforeManifest.VMMPID == 0 || beforeManifest.RunnerPID == 0 {
		t.Fatalf("manifest records no process identity to reconcile from: %+v", beforeManifest)
	}
	vmmStart := procStartTime(t, beforeManifest.VMMPID)
	runnerStart := procStartTime(t, beforeManifest.RunnerPID)
	// Read through the doomed controller while it can still answer.
	beforePage := daemon.heartbeatPage(t, vmID)
	beforeStreams, _ := telemetryStreams(beforePage)

	// SIGKILL, not a shutdown: a controller that got to run its own teardown
	// proves nothing about reconciliation.
	daemon.cancel()
	waitControllerGone(t, daemon, 30*time.Second)

	// The successor needs its own daemon directory. startDaemon installs
	// vmobs-runner beside the daemon binary with O_TRUNC, and the whole premise
	// here is that the dead controller's runner is still executing that file —
	// Linux answers ETXTBSY for a running executable opened for writing. Each
	// buildBinary call answers a fresh temp dir, which is all it takes.
	successorDaemonBin := buildBinary(t, "github.com/2389-research/observatory/cmd/vmobsd")
	successorRunnerBin := buildBinary(t, "github.com/2389-research/observatory/cmd/vmobs-runner")
	successor := startDaemon(t, repoRoot, successorDaemonBin, successorRunnerBin, "m2a-successor",
		withRequiredAuth(m1bOperator, m1bPassword), withStateDir(daemon.stateDir))
	// Teardown follows ownership: the VM belongs to whoever can still delete it.
	successor.adoptVMsFrom(daemon)

	// Reconcile has already run — it happens inside NewManager, before the daemon
	// answers the readiness probe startDaemon waited on — so these read the
	// verdict rather than race it.
	afterVM := successor.apiGet(t, "/vms/"+vmID)
	afterState := stringField(afterVM, "observed_state")
	afterRevision := stringField(afterVM, "revision")
	afterManifest, err := readM1aManifest(daemon.stateDir, vmID)
	if err != nil {
		t.Fatalf("read manifest after the controller restart: %v", err)
	}

	t.Run("at075_adoption_across_controller_restart", func(t *testing.T) {
		if afterState != "running" {
			t.Errorf("observed_state = %q after the controller restarted, want %q — a live VM the new "+
				"controller could account for must not be failed", afterState, "running")
		}
		// Adoption is the absence of a write. running → running is not a §5.2
		// edge, and a bump would invalidate every operator's If-Match pin across
		// a restart they should not have noticed.
		if afterRevision != beforeRevision {
			t.Errorf("revision %s -> %s across the restart; adoption writes no transition", beforeRevision, afterRevision)
		}
		// The same VMM, by pid and start time together: a pid alone cannot tell a
		// live process from a recycled one.
		if afterManifest.VMMPID != beforeManifest.VMMPID {
			t.Errorf("vmm pid %d -> %d; the VM was relaunched, not adopted", beforeManifest.VMMPID, afterManifest.VMMPID)
		}
		if got := procStartTime(t, afterManifest.VMMPID); got != vmmStart {
			t.Errorf("vmm pid %d start time %q -> %q; that pid is a different process now", afterManifest.VMMPID, vmmStart, got)
		}
		// The runner too, which is what says WHICH adoption branch ran. A dead
		// runner beside a live VMM is also reported "adopted" — with a respawn —
		// and a test that accepted either would not be measuring §320's claim
		// that a healthy runner is adopted as it stands.
		if afterManifest.RunnerPID != beforeManifest.RunnerPID {
			t.Errorf("runner pid %d -> %d; the runner was respawned, so this run did not exercise "+
				"adoption of a healthy attached runner", beforeManifest.RunnerPID, afterManifest.RunnerPID)
		}
		if got := procStartTime(t, afterManifest.RunnerPID); got != runnerStart {
			t.Errorf("runner pid %d start time %q -> %q; the pid survived but the process behind it "+
				"did not", afterManifest.RunnerPID, runnerStart, got)
		}

		// Adoption that cannot observe is cosmetic. The heartbeats keep arriving
		// on the same stream the dead controller's runner opened — the runner was
		// never restarted, so a new identity here would mean the transport was
		// rebuilt rather than inherited.
		page := successor.waitHeartbeats(t, vmID, len(beforePage)+1, 90*time.Second)
		afterStreams, _ := telemetryStreams(page)
		if len(afterStreams) != len(beforeStreams) {
			t.Errorf("stream identities %d -> %d across the controller restart (%v -> %v); the runner "+
				"kept running, so its stream should have too", len(beforeStreams), len(afterStreams), beforeStreams, afterStreams)
		}

		evidenceSubtest(t, &evidence, "at075_adoption_across_controller_restart", fmt.Sprintf(
			"vm=%s primary controller SIGKILLed (no teardown), successor started over the same state dir\n"+
				"observed_state: %q -> %q\n"+
				"revision: %s -> %s (unchanged: adoption writes no transition)\n"+
				"vmm pid %d start %q -> pid %d start %q (same process, identity checked by both)\n"+
				"runner pid %d start %q -> pid %d start %q (unchanged: the attached-runner branch ran, not a respawn)\n"+
				"telemetry stream identities across the restart: %v -> %v (%d heartbeats after)\n"+
				"PARTIAL — the runner-kill half of AT-075 is not exercised here; it is unit-covered in "+
				"internal/jailer (reconcile_adoption_linux_test.go, runner_argv_linux_test.go).",
			vmID,
			beforeState, afterState,
			beforeRevision, afterRevision,
			beforeManifest.VMMPID, vmmStart, afterManifest.VMMPID, procStartTimeOrGone(afterManifest.VMMPID),
			beforeManifest.RunnerPID, runnerStart, afterManifest.RunnerPID, procStartTimeOrGone(afterManifest.RunnerPID),
			beforeStreams, afterStreams, len(page),
		))
	})

	// ── The other half of §952: nothing to observe ─────────────────────────────
	// It runs against the successor, which is also the last thing AT-075 needs: a
	// controller that adopted a VM but cannot act on it has claimed nothing.
	t.Run("stopped_vm_is_unavailable", func(t *testing.T) {
		successor.stopVM(t, vmID)
		stopCtx, cancelStop := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancelStop()
		successor.waitVMState(stopCtx, t, vmID, "stopped")

		vm := successor.apiGet(t, "/vms/"+vmID)
		health := stringField(vm, "telemetry_health")
		lifecycle := stringField(vm, "observed_state")
		if health != "unavailable" {
			t.Errorf("telemetry_health = %q on a stopped VM, want %q — a guest that is not executing cannot report",
				health, "unavailable")
		}

		// The heartbeats the VM sent while it ran are still there. Telemetry
		// health is a fact about now; the record is not.
		page := successor.heartbeatPage(t, vmID)
		order, _ := telemetryStreams(page)

		successor.deleteVM(t, vmID)

		evidenceSubtest(t, &evidence, "stopped_vm_is_unavailable", fmt.Sprintf(
			"vm=%s observed_state=%q telemetry_health=%q\n"+
				"%d heartbeats across %d stream identities remain queryable after the stop",
			vmID, lifecycle, health, len(page), len(order),
		))
	})

	evidencePath := filepath.Join(repoRoot, evidenceDir, fmt.Sprintf("m2a-gate-%s.txt", hostname))
	if err := os.MkdirAll(filepath.Join(repoRoot, evidenceDir), 0755); err != nil {
		t.Logf("write evidence: mkdir: %v", err)
	} else if err := os.WriteFile(evidencePath, []byte(evidence.String()), 0644); err != nil {
		t.Logf("write evidence: %v", err)
	} else {
		t.Logf("evidence written to %s", evidencePath)
	}
}

// ---------------------------------------------------------------------------
// M2a helpers.
// ---------------------------------------------------------------------------

// heartbeatPage returns this VM's guest.sensor_health events, oldest first.
//
// The page is taken from the oldest end deliberately. The sequence a new agent
// begins at is one of the things under test, and the newest page would not show
// it: tail=true answers the other question.
func (d *m1aDaemon) heartbeatPage(t *testing.T, vmID string) []map[string]any {
	t.Helper()
	result := d.apiGet(t, "/events?vm_id="+vmID+"&kind="+m2aHeartbeatKind+"&limit=1000")
	raw, _ := result["events"].([]any)
	page := make([]map[string]any, 0, len(raw))
	for _, e := range raw {
		if m, ok := e.(map[string]any); ok {
			page = append(page, m)
		}
	}
	return page
}

// waitHeartbeats polls until at least n heartbeats have arrived for this VM and
// returns the page. Two is the smallest number that shows a stream advancing;
// one only shows that something arrived.
func (d *m1aDaemon) waitHeartbeats(t *testing.T, vmID string, n int, budget time.Duration) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(budget)
	var page []map[string]any
	for time.Now().Before(deadline) {
		page = d.heartbeatPage(t, vmID)
		if len(page) >= n {
			return page
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("vm %s: %d %s events after %s, want at least %d", vmID, len(page), m2aHeartbeatKind, budget, n)
	return nil
}

// waitNewTelemetryStream polls until a heartbeat arrives on a stream identity
// that is not in known, and returns that identity with the page carrying it.
func (d *m1aDaemon) waitNewTelemetryStream(t *testing.T, vmID string, known map[string]int, budget time.Duration) (string, []map[string]any) {
	t.Helper()
	deadline := time.Now().Add(budget)
	var order []string
	for time.Now().Before(deadline) {
		page := d.heartbeatPage(t, vmID)
		order, _ = telemetryStreams(page)
		for _, id := range order {
			if _, seen := known[id]; !seen {
				return id, page
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("vm %s: no new stream identity within %s; still %v", vmID, budget, order)
	return "", nil
}

// waitTelemetryHealth polls the VM record until telemetry_health reaches want,
// and returns how long that took together with the lifecycle state it saw at
// that moment. Both, because §138's claim is about the pair: a telemetry answer
// with no lifecycle answer beside it cannot show that the two stayed separate.
func (d *m1aDaemon) waitTelemetryHealth(t *testing.T, vmID, want string, budget time.Duration) (time.Duration, string) {
	t.Helper()
	start := time.Now()
	var health, lifecycle string
	for time.Since(start) < budget {
		vm := d.apiGet(t, "/vms/"+vmID)
		health = stringField(vm, "telemetry_health")
		lifecycle = stringField(vm, "observed_state")
		if health == want {
			return time.Since(start), lifecycle
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("vm %s: telemetry_health = %q after %s, want %q (observed_state %q)",
		vmID, health, budget, want, lifecycle)
	return 0, ""
}

// telemetryStreams groups a heartbeat page by the stream identity the runner
// assigned, keeping each stream's sequences in arrival order and the streams
// themselves in the order they first appeared.
func telemetryStreams(page []map[string]any) ([]string, map[string][]string) {
	order := []string{}
	seqs := map[string][]string{}
	for _, e := range page {
		id := stringField(e, "source_instance_id")
		if _, seen := seqs[id]; !seen {
			order = append(order, id)
		}
		seqs[id] = append(seqs[id], stringField(e, "source_seq"))
	}
	return order, seqs
}

// assertSeqIncreases checks a stream's sequences are strictly increasing. They
// are decimal strings that can outgrow a JSON number, so they are compared as
// numbers of possibly different length rather than lexically.
func assertSeqIncreases(t *testing.T, streamID string, seqs []string) {
	t.Helper()
	for i := 1; i < len(seqs); i++ {
		prev, err := strconv.ParseUint(seqs[i-1], 10, 64)
		if err != nil {
			t.Errorf("stream %s: source_seq %q is not a decimal string", streamID, seqs[i-1])
			return
		}
		cur, err := strconv.ParseUint(seqs[i], 10, 64)
		if err != nil {
			t.Errorf("stream %s: source_seq %q is not a decimal string", streamID, seqs[i])
			return
		}
		if cur <= prev {
			t.Errorf("stream %s: source_seq went %d -> %d; the guest assigns it at enqueue and never reuses one", streamID, prev, cur)
			return
		}
	}
}

// waitControllerGone polls the daemon's own /meta until it stops answering.
//
// The killed process is a zombie until this test's cleanup reaps it, so /proc
// would say it is still there; a refused connection is the fact that matters —
// nothing is serving this state dir any more.
func waitControllerGone(t *testing.T, d *m1aDaemon, budget time.Duration) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		resp, err := client.Get(d.baseURL + "/meta")
		if err != nil {
			return
		}
		resp.Body.Close()
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("controller %s still answering %s after %s", d.label, d.baseURL+"/meta", budget)
}

// procStartTime reads field 22 of /proc/<pid>/stat, the process's start time in
// clock ticks since boot. With the pid it is an identity: a recycled pid gets a
// different one, which is what lets this gate say the VMM a restarted controller
// adopted is the same process rather than a pid that happens to match.
//
// The comm field is parenthesised and may hold anything, spaces and ')'
// included, so the fields are counted from the last ')' rather than from the
// start of the line. After it the fields run state(3), ppid(4), … starttime(22),
// so starttime is the twentieth of what is left.
func procStartTime(t *testing.T, pid int) string {
	t.Helper()
	start, err := readProcStartTime(pid)
	if err != nil {
		t.Fatalf("start time of pid %d: %v", pid, err)
	}
	return start
}

// procStartTimeOrGone is procStartTime for an evidence line, where a pid that
// has since exited is a fact to record rather than a test failure.
func procStartTimeOrGone(pid int) string {
	start, err := readProcStartTime(pid)
	if err != nil {
		return "gone"
	}
	return start
}

func readProcStartTime(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	line := string(data)
	i := strings.LastIndex(line, ")")
	if i < 0 {
		return "", fmt.Errorf("/proc/%d/stat has no comm field: %q", pid, line)
	}
	fields := strings.Fields(line[i+1:])
	if len(fields) < 20 {
		return "", fmt.Errorf("/proc/%d/stat has %d fields after comm, need 20", pid, len(fields))
	}
	return fields[19], nil
}

// stringField reads a string out of a decoded JSON object. A missing or
// wrongly-typed key answers "", which every caller checks: the gate reports what
// the daemon actually sent instead of panicking on a shape change.
func stringField(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// mapField reads a nested object out of a decoded JSON object, nil when absent.
func mapField(m map[string]any, key string) map[string]any {
	v, _ := m[key].(map[string]any)
	return v
}

// intField reads a JSON number as an int. encoding/json decodes every number
// into a float64, so the conversion happens here rather than at each call site.
func intField(t *testing.T, m map[string]any, key string) int {
	t.Helper()
	f, ok := m[key].(float64)
	if !ok {
		t.Errorf("field %q = %v (%T), want a number", key, m[key], m[key])
		return 0
	}
	return int(f)
}

// isLowercaseUUID reports whether s has the canonical lowercase uuid shape the
// event schema requires of source_instance_id.
func isLowercaseUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			isDigit := c >= '0' && c <= '9'
			isHex := c >= 'a' && c <= 'f'
			if !isDigit && !isHex {
				return false
			}
		}
	}
	return true
}
