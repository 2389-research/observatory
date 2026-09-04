# Firecracker Observatory — Acceptance and Evidence Plan

This file is part of `SPEC.md`. Every row starts **SPECIFIED / NOT RUN**. These are tests to implement, not claims of successful execution.

## Evidence rules

For each test, record: stable test ID; linked requirement; exact procedure/fixture revision; expected and actual result; status; host hardware and nested/bare-metal context; runtime-lock digest; relevant event/artifact IDs; logs; defects; and the command that reproduces the result.

Use statuses `SPECIFIED`, `TESTED_PASS`, `TESTED_FAIL`, `BLOCKED`, and `VERIFIED`. `VERIFIED` requires rerunning after any relevant fix. A skipped test is not a pass. A UI screenshot is not proof of host isolation. Fake-runtime results must be explicitly labeled and cannot satisfy real-KVM gates.

Use a dedicated controlled network fixture for deterministic HTTP, HTTPS, DNS, pinned certificates, streaming, redirects and failure responses. Fixture-network exceptions must be confined to the isolated test installation and never silently added to production policies. Internet smoke tests are supplementary, not the sole evidence.

## A. Host, images and provisioning

| Test | Requirement | Procedure and required result |
|---|---|---|
| AT-001 | R-01, R-11 | Run doctor without usable KVM. Launch is rejected with the failed check; no silent emulation or half-created VM. |
| AT-002 | R-01, R-11 | Change a runtime/image hash or make a privileged path writable by an ordinary account. Startup rejects the unsafe configuration. |
| AT-003 | R-05, R-12 | Boot a guest missing a required sensor feature. Report the exact missing capability and refuse strict-observation launch. No false healthy state. |
| AT-004 | R-01, R-11 | Boot a real jailed VM; inspect actual identity, cgroup, namespace, approved disks and socket ownership. Capture evidence from the host. |

<!-- L0 M0 status notes (2026-09-01)

AT-001: TESTED_PASS (partial — M0 scope only; doctor-gated launch admission completes in M1).
  What M0 demonstrates:
  - arch_kvm check reports EACCES honestly on aibox03 with `re-login for kvm group` remediation.
    Test: internal/preflight/checks_linux_test.go:TestArchKVMHonest (linux, aibox03; PASS — verified
    pre-kvm-group, EACCES branch accepted; both branches covered, test does not skip).
  - Launch refusal names the failed preflight check per L0-R12: UnavailableError reason appends
    "; preflight: <overall> (<first failing check ID>)" when a non-pass report exists.
    Test: internal/runtime/manager_test.go:TestForHostPreflightSummaryAppended (unit; asserts the
    UnavailableError reason carries the "preflight: fail (arch_kvm)"-style suffix).
  - internal/api integration: preflight block present in /host/status when runner wired.
  Doctor-gated launch admission (full AT-001 flow: doctor runs + refuses launch + names check) is M1.

AT-002: TESTED_PASS.
  - Hash mismatch at startup: cmd/vmobsd/lock_startup_test.go:TestServeRefusesHashMismatch —
    daemon startup returns error naming the mismatched subject when runtime.lock.json hash is wrong.
  - Unit: internal/lock/lock_test.go:TestVerifyBinariesHashMismatch — flip one byte → exactly
    one Mismatch naming the subject and carrying correct want/got values.
  - Also: TestVerifyBinariesAbsentFile (absent binary → Mismatch with Got="absent"),
    TestServeBothMismatchesListed (both fc+jailer mismatches listed in one error).

AT-003: SPECIFIED.
  Capability report exists (vmobs-guestd ProbeCapabilities, guest agent capabilities round-trip —
  see tests in internal/guest). Strict-observation launch refusal when a required feature is missing
  is M1/M2 work; no launch path exists yet. The guest_channel doctor check is permanently
  not_implemented in M0 (TestGuestChannelAlwaysNotImplemented).

AT-004: TESTED_PASS (2026-09-01, aibox03 bare-metal, Ubuntu 24.04 kernel 6.8, Firecracker v1.16.1).
  Gate: scripts/linux 'VMOBS_FIXTURE=1 go test ./tests/integration/ -v -timeout 600s' —
  TestM0Boot PASS (7.55s). Four assertions executed: vsock handshake + identity isolation
  (cross-auth token rejected), capability report (btf/fanotify/vsock/virtio_blk/virtio_net/
  cgroup_v2/ext4 Present on both VMs, kernel 6.1.186), independent disk ownership (uids
  20000/20001, distinct inodes, sockets owned by each VM's uid — captured while VMs were live),
  teardown (no jail or netns leaks).
  Evidence: tests/integration/evidence/m0-boot-aibox03.txt (lock digests inside; rootfs sha256
  54426c1c…, vmlinux b6067686…).
  Defects found and fixed by running the gate (branch m0-gate-fixes; PLAN.md L0-R13/L0-R14):
  jailer chroot-root traverse chmod race; vsock wait masking the real dial error; guestd config
  mountpoint never created (ENOENT — /run is a fresh tmpfs under systemd); rootfs build quoting
  regression (be420fd) that produced a guestd-less image and exposed two silent-failure holes
  in build verification.

AT-009: SPECIFIED (seed evidence executed 2026-09-01 with the M0 gate; full row is M1 scope).
  TestM0Boot boots two simultaneous VMs with distinct VM IDs, UIDs (20000/20001), CIDs (3/4),
  and network namespaces — identity isolation is asserted at the vsock level. Full four-VM
  simultaneous launch is M1 scope.

AT-011: SPECIFIED (seed evidence executed 2026-09-01 with the M0 gate; full row is M1 scope).
  TestM0Boot assertion 4 (teardown): stops VM A while VM B still runs, asserts B still answers ping,
  then stops both and asserts no m0-* entries remain in the jail dir or netns. The independent
  teardown seed is the first evidence for this row; broader multi-VM stop/delete testing is M1.

AT-018: SPECIFIED (seed evidence executed 2026-09-01 with the M0 gate; full row is M1 scope).
  TestM0Boot teardown asserts netns and jail dirs contain no m0-* entries after both VMs stop —
  the seed assertion for leak detection. Repeat create/stop/delete cycles with baseline comparison
  is M1 scope.

-->

<!-- L1 M1a status notes (2026-09-02)

M1a live gate: aibox03 bare-metal, Ubuntu 24.04 kernel 6.8, Firecracker v1.16.1. Two consecutive
PASS runs of TestM1aGate (tests/integration/m1a_gate_test.go), invoked both times as
`scripts/linux 'env VMOBS_FIXTURE=1 go test ./tests/integration/ -run TestM1aGate -v -count=1
-timeout 600s'`: run A started 2026-09-02T23:25:14Z (92.40s), run B started 2026-09-02T23:27:03Z
(98.44s), eight subtests each, eight passes, zero skips. Evidence quoted below is run B's,
committed at tests/integration/evidence/m1a-gate-aibox03.txt; the two runs' evidence, normalized
for UUIDs/timestamps/pid/temp-dir, is byte-identical. A §15.3 scan of all 33 evidence lines for
token/secret/bearer/authorization/password/key= found nothing, both runs. AT-005 draws on a
separate test binary and is noted at its own row.
Runtime lock at aa12929 (runtime.lock.json, unchanged since the 0881e69 rootfs re-pin): vmlinux
b6067686…, rootfs c6a92bba…, firecracker 2fd01713…, jailer 1f3a0c1f…. The daemon verifies both
binaries against the lock at startup (cmd/vmobsd/main.go:197) and every launch verifies both
images against it before staging (internal/jailer/launch.go:268), so a passing run proves the
artifacts matched those digests. The evidence file itself records no digest — unlike M0's, which
carries a "Lock artifact verification" section — so these are read from the lock at the gate
commit, not captured on the host.

AT-001: TESTED_PASS.
  Completes the M0 note. A second real vmobsd daemon, pointed at a nonexistent privd socket, is
  sent a real POST /vms; the refusal names the failing check. That it happens before any
  provisioning side effect is by construction (internal/runtime/manager.go:411-414 checks
  availability before the row insert at :492), not by assertion: the gate checks only the
  response body (m1a_gate_test.go:1470-1512) and never inspects the refusing daemon's store or
  state dir.
  Test: tests/integration/m1a_gate_test.go:at001_privd_refusal (subtest of TestM1aGate; aibox03,
    PASS both runs). Asserts status=501, cause="runtime_unavailable", and that the reason names
    both the failing check (guest_channel) and the dial failure (cannot reach privd socket) with
    the exact bad socket path — and does not contain the M0 stub's "not configured" wording.
  Evidence (run B): `status=501 cause="runtime_unavailable" message="runtime not available on
    this host: guest_channel: cannot reach privd socket: dial unix /nonexistent/privd.sock:
    connect: no such file or directory" ... guest_channel_found=true dial_failure_found=true
    socket_named=true not_configured_found=false`.
  The trigger is an unreachable privd socket, not a literally-absent KVM device — the doctor
  check that fails and is named is guest_channel, not arch_kvm. That is still the full flow the
  M0 note was waiting on: doctor runs, launch is refused, the failing check is named, before any
  side effect occurs (by construction, as above — not asserted).

AT-005: TESTED_PASS (partial — nine injection points; not injected: a failure between a
  stage's side effect and the manifest write that records it, at the three writes
  launch.go:150/:176/:226, where doRollback reads a manifest that does not yet name the stage
  and skips its release — the runner case, 4db1081, is a known instance — and, on a restart
  only, any failure before the write at :150, because the reserved write at :111 replaces the
  stopped VM's manifest and with it the network record that rollback and Release act on. Not a
  real-KVM result: fake VMM — a privd test backend's `sleep 300` stand-in — with real privd,
  runner and guest.Agent code; labeled per this file's fake-runtime rule; does not satisfy a
  real-KVM gate).
  Test: internal/jailer/inject_linux_test.go:TestInject (PASS 9/9 in 19.95s at 02ea171, in a
    linux/arm64 Docker container on the darwin workstation — go1.26.8, uid 1000, no KVM — not
    on aibox03; before this round, PASS 6/6 in 14.5s on aibox03 at 11864b9, the commit that
    made the exact-sequence and runner-gone assertions bite, and `-race -run TestInject
    -count=5` ok in 88.593s after e6172f8. The runs are recorded in PLAN.md's M1a session log:
    the Task 13 entry for the aibox03 runs, with the earlier 6/6 in 14s at 6747f7c before the
    assertions were hardened, and the rollback-leak entry for the 9/9 run) —
    state_dir_mkdir_failure, manifest_write_fresh_vm, manifest_write_restart,
    staging_digest_mismatch, stage_copy_failure, allocate_network_failure, start_vm_failure,
    runner_spawn_failure, wrong_token_attach_timeout.
  Each subtest makes one step fail — the state-dir mkdir at launch.go:107 (vms/ made
  read-only; the subtest refuses to run as root), the reserved manifest write at :111 for a
  fresh VM and again for a restart (the launch runs in a child process under RLIMIT_FSIZE=0,
  so writeManifest's first write fails with the state dir already made), artifact verification
  at :268, the rootfs copy inside doStage after :273 (a directory planted where the file goes,
  after vmlinux has been copied), the allocate_network verb at :146, the start_vm verb at
  :162, the runner spawn at :218, or the guest attach (wrong token, timeout) — and asserts what
  the failure leaves and the exact backend call sequence the rollback issues, proving cleanup
  calls only the release verbs for what was actually allocated: the five failures before the
  first privd verb see no backend call at all and, except for the restart, no state dir,
  manifest or stage dir afterwards — manifest_write_restart instead sees the stopped VM's
  previous manifest untouched, since it is the only record of the network Release still has to
  free; allocate_network_failure sees exactly `[allocate_network]` with no release (network was
  never marked allocated); start_vm_failure sees exactly
  `[allocate_network, start_vm, release_network]` (the VMM never started, so nothing signals or
  releases it); runner_spawn_failure sees the full
  `[allocate_network, start_vm, signal_vm/term, signal_vm/kill, release_vm, release_network]`
  (the VMM was running, so it is killed and released). Every subtest ends with a real recovery
  launch of the same VM ID that succeeds after the injected failure, over the same privd server
  and prefix pool; manifest_write_restart's recovery must keep the stopped VM's slot and CIDR.
  What that proves: the VM's state dir, manifest and slot — and the uid and CID
  derived from the slot (launch.go:63-70) — are gone, because allocateSlot's manifest scan
  (internal/jailer/manifest.go:127) hands the slot out again. What it does not prove: the /30
  prefix is NOT returned — internal/network/alloc.go has Next() (:152) and Exclusions() (:146)
  and no release path, so a rolled-back launch keeps its prefix for the daemon's lifetime, and
  each subtest's pool is sized for two launches (inject_linux_test.go:98); and the compute
  reservation is a manager-layer object this suite never touches — its release after a failed
  launch is evidenced only by TestManagerLaunchFailure (internal/runtime/manager_test.go:176,
  :212-218), a SPEC §18 fake-runtime unit test. wrong_token_attach_timeout also asserts
  the runner process is gone before recovery and that the injected wrong token never appears in
  any error string (§15.3).
  Harness: a real privd.Server and a real *privd.Client, wrapped by a decorator that injects one
  failure on demand and records every call; a real vmobs-runner binary; for the two
  manifest-write subtests, the test binary re-executed as a child with RLIMIT_FSIZE lowered to
  zero (launchWriteFailHelper), so the launch's first file write fails with EFBIG and nothing
  else in the launch is touched; and, in the last subtest, a real guest.Agent-shaped listener
  on a real vsock UDS. The VMM itself is a `sleep 300` stand-in recording its own real PID, and
  AllocateNetwork/ReleaseNetwork are no-op call recorders — no real netns or veth. This is not
  the SPEC §18 fake runtime, and it is never wired into a served mode.
  Not injected: a failure between a stage's side effect and the manifest write that records it.
  Each stage's side effect precedes its record (allocate_network at :146 precedes :150; start_vm
  at :162 precedes :176; the runner spawn at :218 precedes :226), and doRollback (:479-522)
  releases only the stages the on-disk manifest names, so a failure in any of those three
  windows leaks that stage past delete: the netns and privd ledger entry, the VMM, or the
  runner is reclaimed by neither the rollback nor Release — Release calls release_network only
  for a manifest that names network (stop.go:361) and never signals a VMM or a runner, and the
  rollback has already deleted the manifest. The runner case is a known instance (4db1081).
  The staging window no longer leaks: doRollback removes the stage dir without a stage guard
  (:513-517), so a doStage failure after :273 — stage_copy_failure — and a failed write at
  :140, which is not injected but takes the identical rollback path, both leave no stage dir.
  Earlier revisions of this paragraph said the stage dir was "reclaimed later by Release on
  delete"; it never was — doRelease returns before its stage-dir removal when the manifest is
  gone (stop.go:346-347), and the rollback had just deleted it. Also not injected, and a fourth
  escape: on a restart the reserved write at :111 replaces the stopped VM's manifest with one
  naming only reserved, so any failure before the write at :150 rolls back without
  release_network and deletes the record Release needed — the stopped VM's netns and ledger
  entry leak past delete. The comment above the doStage call (launch.go:136, :126 before this
  round) said until this round that a stage dir doStage left was "reclaimed by Release on
  delete"; docs/VALIDATION.md revision 12 certified that text as a correction, and it was
  false for the reason just given. It now says doRollback removes the state dir and whatever
  doStage left in the stage dir.

AT-006: TESTED_PASS (partial — VM identity and key-reuse conflict; operation identity not
  compared, timeout replay not simulated).
  Test: tests/integration/m1a_gate_test.go:at006_idempotency (subtest of TestM1aGate; aibox03,
    PASS both runs). A real POST /vms is replayed with the same idempotency key: the replay
    returns the same VM ID with is_replay:true; a third request reusing the key with a changed
    payload gets 409 idempotency_key_reused.
  Evidence (run B): `first_create=201 vm_id=60271f9f-e799-469b-bf6a-df33eaabc2d7 is_replay1=false
    replay=201 vm_id=60271f9f-e799-469b-bf6a-df33eaabc2d7 is_replay=true conflict=409
    cause="idempotency_key_reused"`.
  The row asks for exactly the original VM/operation across a timeout. The subtest
  (m1a_gate_test.go:1696-1764) compares vm_id and is_replay only: the create response also
  carries the operation (internal/api/vms.go:628) and the subtest never compares the replay's
  against the original's, and the replay is sent immediately after the first create — no client
  timeout is simulated.

AT-007: TESTED_PASS (partial — one of the row's four procedure elements).
  The row asks that user jobs cannot start before guestd readiness, workspace seeding, baseline
  creation and required sensor checks. The live gate covers guestd readiness only, as a proxy:
  Test: tests/integration/m1a_gate_test.go:at007_ordering (subtest of TestM1aGate; aibox03, PASS
    both runs). Creates one VM, reads its running-transition timestamp and its
    guest.channel_established timestamp from GET /events, and asserts running never precedes the
    channel.
  Evidence (run B): `running_transition_at="2026-09-02T23:28:36.211898Z"
    channel_established_at="2026-09-02T23:28:35.719357Z" running_not_before_channel=true` — a
    real 492ms interval, not a boolean.
  Not covered: workspace seeding and baseline creation are M4 scope (SPEC Milestone 4); required
  sensor checks are M2 scope (SPEC Milestone 2 — process sensor and filesystem notifications do
  not exist yet).

AT-009: TESTED_PASS (partial — concurrent launch and channel establishment only).
  Test: tests/integration/m1a_gate_test.go:at009_four_concurrent_vms (subtest of TestM1aGate;
    aibox03, PASS both runs). Four goroutines issue four simultaneous real POST /vms; all four
    reach running with channel_established; all four are then stopped and deleted.
  Evidence (run B): `four VMs [76357a29-... e373cb6c-... 239a30ab-... 0ea84265-...]: created
    concurrently (four simultaneous POST /vms launches); all reached running with
    channel_established; all stopped and deleted`.
  POST /vms is itself the create-and-launch request (SPEC §14); M1a has no separate "start"
  action, so four concurrent creates are the simultaneous-launch shape the product offers. Not
  covered: the row's distinctness claims are not asserted by this subtest at all
  (m1a_gate_test.go:1767-1838 checks that four VMs reach running with channel_established, then
  stop and delete); the only distinctness the gate asserts anywhere is two_real_vms
  (:1528-1599), for two VMs: distinct uid and CID read from their manifests, and both netns
  present. Per-VM writable-disk-content isolation is AT-010's row, not this one; terminal
  sessions do not exist yet (L1b, planned after L1a).

AT-011: TESTED_PASS (partial — VM-lifecycle independence only).
  Test: tests/integration/m1a_gate_test.go:at011_graceful_stop (subtest of TestM1aGate; aibox03,
    PASS both runs). Stops vmA while vmB keeps running; asserts vmA's stop event carries
    reason=graceful_stop; asserts vmB stays "running" both immediately after vmA's stop and after
    vmA's full delete; asserts vmB records no state-change event with host_received_at after
    vmA's stop time.
  Evidence (run B): `vmA stopped graceful_stop=true; vmB state after vmA stop="running"; vmB
    state after vmA delete="running"; ... vmB no state departure after stop=verified`.
  The row's text also names terminal and network-worker continuity; M1a has neither subsystem
  built (terminal is L1b), so this row proves VM-lifecycle independence only: a sibling's own
  recorded state is untouched by a VM's stop or delete. The gate asserts vmB's state and the
  absence of vm.state_changed events for vmB; it does not assert the absence of
  guest.channel_lost for vmB (m1a_gate_test.go:1622 and :1656 query kind=vm.state_changed only).
  guest.channel_lost is registered (internal/events/registry.go:233) and is what the runner
  appends when the guest control channel drops and it redials (internal/runner/runner.go:248-250,
  in supervisionLoop) — the product's own record of a ping interruption, and the mechanism gate
  run 6 saw on the VM being stopped. A sibling whose channel dropped and redialed stays
  "running", so the assertion the gate makes cannot see that interruption.

AT-018: TESTED_PASS (partial — six host-side counters, delta-zero against an in-run baseline;
  cgroups, reservation counts and privd's network ledger not counted).
  Test: tests/integration/m1a_gate_test.go:at018_no_resource_leaks (subtest of TestM1aGate,
    aibox03, PASS both runs). Captures a baseline over six counters (netns, veth, jail chroot
    entries, firecracker process count, state-dir entries, stage-dir entries), runs 5 graceful
    create/stop/delete cycles plus 1 force-delete cycle (DELETE ?force=true with no stop first —
    the only path that had leaked a chroot in an earlier run), recaptures within 60s, and hard-
    asserts all six deltas at zero.
  Evidence (run B): `baseline: netns=1 veth=1 jail=1 fc_procs=1 state_entries=1 stage_entries=1`
    / `after 5 graceful cycles + 1 force-delete: netns=1 veth=1 jail=1 fc_procs=1
    state_entries=1 stage_entries=1` / `delta: netns=+0 veth=+0 jail=+0 fc_procs=+0 state=+0
    stage=+0`.
  The row's text names cgroups and reservation counts among what to compare, against the
  documented idle baseline; four things it asks for this subtest does not measure. (a) The
  baseline is not the documented idle one: captureBaseline (m1a_gate_test.go:1118) runs inside
  the subtest at :1843 with one live VM left by an earlier subtest — every counter reads 1 in
  the evidence — and the assertion is delta-zero against that, not against an idle host. (b)
  Reservation counts are never read: none of the six counters queries GET /host/status, which
  reports reserved_memory_mib, reserved_vcpu and reserved_disk_mib (internal/api/vms.go:509-515),
  so a leaked reservation would pass. (c) privd's network ledger (internal/privd/ledger.go, one
  file per VM) is not counted — the record 7934423 had left immortal. (d) The baseline struct
  carries no cgroup counter — jail/state/stage entry counts catch a leaked chroot or socket, but
  nothing here separately counts cgroups. All four gaps are real and unclaimed.

-->

<!-- L1 M1b status notes (2026-09-04)

M1b live gate: aibox03 bare-metal, Ubuntu 24.04 kernel 6.8, Firecracker v1.16.1, guest kernel
6.1.186. Two consecutive PASS runs of TestM1bGate (tests/integration/m1b_gate_test.go), invoked
both times as `scripts/linux 'env -u GOROOT VMOBS_FIXTURE=1 go test ./tests/integration/ -run
TestM1bGate -v -count=1 -timeout 25m'`: run A recorded 2026-09-04T19:52:56Z (53.05s), run B
recorded 2026-09-04T19:54:30Z (53.21s), twelve subtests each, twelve passes, zero skips. Evidence
quoted below is run A's, committed at tests/integration/evidence/m1b-gate-aibox03.txt; the two
runs' evidence, normalized for UUIDs, timestamps, pids and guest pids, differs in one field — the
byte offset at which the guest declared its dropped range under AT-027 (from=65590 in run A,
from=54 in run B), which is where the flood happened to be when the browser stalled.

The whole gate runs with require_authentication: true against a real vmobsd on the real jailer
runtime; AT-030's denials are meaningless otherwise. A §15.3 scan of the 90 evidence lines for
token/secret/bearer/authorization/password/key= returns two lines, both clean: AT-030 prints the
intruder token's record id (auth.Store.CreateToken returns the secret separately from the record,
tokens.go:99, and the gate prints rec.ID), and one HTTP message contains the words "bearer token".

Runtime lock unchanged from the M1a note: vmlinux b6067686…, firecracker 2fd01713…, jailer
1f3a0c1f…. Gate commit 37d2e1b.

Two product defects were found by running this gate and fixed before it passed, both with a
regression test first:
  - Terminal lifecycle events were recorded for the first VM only. A source stream binds to one
    VM scope (internal/store/append.go), and the API emitted every VM's terminal events on one
    stream, so every later VM's session_opened/session_closed was refused at ingest and survived
    as a log line. Fixed at 114a03e: one source stream per VM.
  - A VM stopped and started inside one spool-importer poll was marked failed by its own previous
    boot. NotifyVMMExit was boot-blind, so the first boot's vmm_exited — delivered 4s later, into
    the second boot — read as the current VMM dying. The VM row now records the boot it is on and
    an exit notice naming a different boot is ignored. Fixed at 320cfe1. This is what made AT-028
    fail with `409 invalid_transition from "failed" to "running"` over a live firecracker.

SPEC §18's own M1 gate line — "demonstrate two simultaneously running VMs with independent
terminals, storage and stop actions", gated on "no host shell proxy masquerading as a guest
terminal; reconnect does not spawn a duplicate shell" — is satisfied by four of the subtests
below, and one clause of it is only partly satisfied. Two simultaneous VMs with independent
terminals and independent storage: at025_session_isolation, which writes each VM's own id into
/tmp/m1b.mark inside that guest and reads it back, with neither stream ever carrying the other's
marker. No host shell proxy: at019_real_guest_pty, where tty names a guest /dev/pts device,
/proc/self/cgroup and ls /dev/vd* answer as the guest, and no new descendant of vmobsd or
vmobs-runner appears for the duration. Reconnect spawns no duplicate shell: at022, same guest pid
across a drop and reattach with one replay, and at026, which asserts the guest re-ran nothing.
Stop actions: at028, stop then start, with a new boot id.

One clause needs a word about how those actions were driven. §18 says demonstrate; the plan's
Task 14 step 7 asked for storage and stop actions "through the web UI's own controls". This gate
drives them through the public API the UI is a client of, not through a browser. The controls
themselves are asserted in vitest against real components with fetch and WebSocket stubbed
(web/src/components/BulkActions.test.tsx, VMTable.test.tsx, LaunchForm.test.tsx, LaunchBatch.test.tsx,
web/src/VMDetail.test.tsx, Terminal.test.tsx), so both halves are tested and neither half is
tested against the other. The gate below is API-driven throughout; nothing in it is browser
evidence.

That browser run was then done separately, and it is the record for §18's "storage and stop
actions" clause. On 2026-09-04 a real Chrome (agent-browser, 1440x900) loaded /ui/ from a real
vmobsd on aibox03 serving three VMs at 1 vCPU / 512 MiB / 2048 MiB root / 1024 MiB workspace,
launched by scripts/aibox03/demo. Storage: the fleet page's capacity panel read `Disk 9216 /
35966 MiB, 26750 MiB free` and each VM row read `2048 MiB root / 1024 MiB workspace`, both
matching GET /api/v1/host/status. Stop: demo-3's own Stop button was clicked, and the API then
reported that VM `stopped/stopped rev 5` with `op-000005 succeeded`; its Start button, disabled
while it ran, became enabled and the other four actions took their disabled reasons ("Pause needs
a running VM; this one is stopped"). Start: that Start button was clicked, and the VM returned to
`running/running rev 7` with `op-000006 succeeded`. Screenshots of all three states were taken
and are not committed — the numbers they show are quoted above and are reproducible from
/api/v1/host/status and /api/v1/vms.

That run found a defect the API-driven gate did not. After the round trip, with all three VMs
running, host status reported `active_vms: 3` but `reserved_memory_mib: 2560` and `reserved_vcpu:
2` — two VMs' worth — while `reserved_disk_mib: 9216` stayed correct at three. Stopping a VM
releases its compute reservation and starting it never takes the reservation back:
internal/store/vms.go writes `compute_released` in exactly two places (lines 579 and 585) and
both set it to 1, and the start case at internal/runtime/manager.go:753 never touches the
reservation row. Admission sums those rows, so every VM that has been stopped and started once
is invisible to the check that keeps the host from overcommitting. Filed as kata r799 (P1),
unfixed at this commit. It is not an M1 gate blocker — no AT below asserts capacity accounting
across a stop/start — and it is recorded here because the gate's evidence must say what the gate
did not cover.

AT-019: TESTED_PASS.
  Test: m1b_gate_test.go:at019_real_guest_pty. Asserts the session's tty is a guest pts, that the
    guest's hostname and kernel differ from the host's, that guest-only paths exist (/dev/vd*,
    a guestd cgroup), that `sleep 120 &; jobs` yields a job table, that a foreground reader sees
    a typed line twice (pty echo plus the program), and that vmobsd gains no shell descendant on
    the host across the whole subtest.
  Evidence: `guest tty="/dev/pts/0" hostname="localhost" kernel="6.1.186"` against `host
    hostname="aibox03" kernel="6.8.0-138-generic"`; `guest /dev/vd*="/dev/vda  /dev/vdb
    /dev/vdc"`; `job control: ... [1] + Running                    sleep 120`; `vmobsd
    descendants before="vmobs-runner=2" after="vmobs-runner=2" (no shell in either)`.

AT-020: TESTED_PASS.
  Test: m1b_gate_test.go:at020_fullscreen_and_encoding. Resizes four times and reads the guest's
    own `stty size` back each time; asserts café, 日本, an SGR color sequence and the alternate-
    screen enter/leave pair arrive verbatim; sends an ESC[200~…ESC[201~ paste into `cat > file`
    and reads the file back with `od -c`; runs the installed `vi` and `top`, asserts each paints
    a screen and that the shell answers after each quits.
  Evidence: `resize: 40 120->"40 120" 30 100->"30 100" 50 132->"50 132" 24 80->"24 80"`;
    `utf8 café/日本=true color CSI=true alt-screen 1049h/l=true`; the od dump shows
    `033   [   2   0   0   ~   p   a   s   t   e   d   -   t   e   x   t 033   [   2   0   1   ~`;
    `vi drew a screen and exited=true; top drew a screen and exited=true`.

AT-021: TESTED_PASS (partial — `bg` is exercised, `fg` is not).
  Test: m1b_gate_test.go:at021_signals_and_jobs. Asserts Ctrl-C on a foreground `sleep` leaves
    the shell answering, that Ctrl-Z produces a suspended job in `jobs`, and that Ctrl-D on an
    empty line closes the session with a terminal control message.
  Evidence: `ctrl-c interrupted the foreground process and left the shell alive=true`;
    `ctrl-z jobs: ... [1] + Stopped                    sleep 300`; `after bg, jobs: ... [1] +
    Running                    sleep 300`; `ctrl-d on session ... closed it=true reason="exited"
    exit_code=0`.
  The row names foreground/background job commands. The subtest sends `bg %1` and records the
  job back in Running, but asserts only that Ctrl-Z produced a Stopped job — the post-`bg`
  Running line is recorded, not asserted — and it never sends `fg`.

AT-022: TESTED_PASS (partial — "commands do not rerun" is AT-026's assertion, not this one).
  Test: m1b_gate_test.go:at022_reconnect_same_shell. Reads the guest shell's `$$` before the
    disconnect and after reattaching by session id and asserts they match; asserts a canary
    printed before the disconnect appears exactly once in everything the reattached connection
    received.
  Evidence: `pid_before=715 pid_after=715 canary_occurrences_after_reattach=1`;
    `writer_on_reattach=false (lease grace window held by the departed connection), steal
    succeeded`.
  The reattach lands read-only and has to steal the writer lease: the departed connection's lease
  survives its disconnect for the grace window (internal/terminal/lease.go). That is what the
  UI's own button does, and it is recorded rather than worked around.

AT-023: TESTED_PASS.
  Test: m1b_gate_test.go:at023_replay_gap. Prints a canary, disconnects, floods past the retained
    window, reattaches, and asserts the host declares a gap rather than presenting the ring as
    continuous history — and that the pre-disconnect canary is genuinely gone from the replay.
  Evidence: `gap=true resume_offset=837965 replay_bytes=262144`; `pre-disconnect canary
    "GAP-CANARY-4471" still in the replay=false (false is the point: it aged out)`.

AT-024: TESTED_PASS.
  Test: m1b_gate_test.go:at024_writer_lease. Attaches two connections to one session; asserts the
    second is read-only, that its keystrokes and its resize are both refused with a lease message,
    that the guest's `stty size` is unchanged by the refused resize, that a steal demotes the
    first connection, and that the demoted writer's next keystroke is refused.
  Evidence: `second attached read-only, holder="9851e6e5-…"`; `read-only input refused with a
    lease message=true reason="this connection is read-only, so those keystrokes were not
    delivered; steal the writer lease to type"`; `guest stty size after the refused resize="24 80"
    (unchanged)`; `steal demoted the old writer=true`; `old writer's next keystroke refused=true`.

AT-025: TESTED_PASS (partial — cwd, shell state, pid and dimensions; exit state is AT-021's).
  Test: m1b_gate_test.go:at025_session_isolation. Asserts two VMs' streams carry only their own
    markers, then within one VM asserts two sessions have different cwds, that a shell variable
    set in one is unset in the other, that they report different guest pids, and that resizing
    one does not change the other's `stty size`.
  Evidence: `cross_vm_leak=false marker_a_seen_in_a=true marker_b_seen_in_b=true`; `same_vm
    sessions=… pid1=701 pid2=702 cwd1="/tmp/one" cwd2="/tmp/two"`; `resize session1 -> 40x120;
    stty size: session1="40 120" session2="24 80"`.
  The row also names exit state. This subtest never exits a session; AT-021 closes one with
  Ctrl-D and reads its exit reason and code, on a different session in the same VM.

AT-026: TESTED_PASS, with a recorded deviation from SPEC §8.2.
  Test: m1b_gate_test.go:at026_duplicate_input. Sends one input frame twice under the same
    sequence number and asserts the command ran once; reconnects and asserts the guest re-ran
    nothing.
  Evidence: `frame seq=2 sent twice; the command ran 1 time(s)`; `after a reconnect the guest
    re-ran nothing: 0 occurrence(s) of the marker`.
  Deviation: SPEC §8.2 describes the input high-water mark as per session. The implementation
  keeps it per connection (internal/api/terminal_stream.go, streamRelay.lastClientSeq), and
  web/src/terminalSocket.ts resets its sequence to 0 on every open and never resends across a
  reconnect — so no duplicate typing is reachable through the product's own client, and the
  subtest proves that directly. A client that did resend across a reconnect would not be caught
  by the host.

AT-027: TESTED_PASS (partial — the ceiling is measured on the wire, not in host memory).
  Test: m1b_gate_test.go:at027_slow_browser. Reads the in-flight ceiling the attach announced,
    stops acking, floods PTY output, and asserts the host never sends more than the ceiling in
    unacked bytes, that control messages are still answered while the window is full, that the
    guest declares the range it dropped, and that the stream resumes after an ack.
  Evidence: `max_inflight_bytes=1048576`; `bytes delivered to a browser that stopped acking:
    1048576 (ceiling 1048576)`; `control channel answered while the window was full=true`;
    `guest declared a dropped range=true from=65590 to=595377`; `stream resumed once the browser
    acked again=true`.
  The row says memory stays bounded. What is asserted is the unacked-byte ceiling on the wire and
  a declared drop; no host RSS or buffer occupancy is measured.

AT-028: TESTED_PASS (partial — pause and resume are INCONCLUSIVE; this build has no reboot).
  Test: m1b_gate_test.go:at028_lifecycle_while_attached. Posts pause the way the UI's button
    does and records what came back; asserts a refused action leaves the VM running with its
    attached shell still working; stops the VM while attached and asserts the stream ends while
    the session stays listed; starts it again and asserts the old session id cannot attach to the
    new boot.
  Evidence: `pause: INCONCLUSIVE — this runtime does not implement VMM pause. POST
    /vms/…/actions {action: pause} -> HTTP 501 cause="runtime_unavailable" message="runtime not
    available on this host: pause not supported in M1a" … The VM stayed "running" and the attached
    session survived the refusal: shell still works=true.` / `resume: INCONCLUSIVE — paired with
    pause (internal/jailer/adapter.go).` / `stop: the attached stream ended=true; session still
    listed on the VM=true state="open"` / `new boot via stop+start (this build has no reboot
    action): reattach with the old session id -> HTTP 503 cause="attach_refused"`.
  Two parts of the row are unproven and say so. Adapter.Pause and Adapter.Resume return a typed
  UnavailableError by design (internal/jailer/adapter.go; the M1a scope decision is recorded in
  PLAN.md Task 10), so the gate records the refusal rather than inventing a pass. There is no
  reboot action in the API at all (§5.3 lists start, pause, resume, stop, force_stop), so the new
  boot the row wants is produced by stop then start, which is the same claim about session
  identity across boots.

AT-029: TESTED_PASS (partial — the host half here, the browser half in the web suite).
  Test: m1b_gate_test.go:at029_hostile_output asserts the relay delivers `<img src=x
    onerror=alert(1)>`, an OSC 0 title, an OSC 52 clipboard write and an OSC 8 javascript:
    hyperlink to the browser byte for byte, and that the served config declares
    automatic_clipboard_write=false and automatic_download=false.
  Evidence: all four `delivered verbatim=true`; `config automatic_clipboard_write=false: true;
    automatic_download=false: true`.
  The row's required result is about the browser: no DOM execution, no automatic clipboard write,
  no automatic download. This Go gate runs no DOM and does not claim to — it proves the relay is
  byte-transparent and interprets nothing. The browser half is web/src/Terminal.test.tsx, which
  drives real xterm.js and asserts OSC 52 never reaches navigator.clipboard and that hostile
  output renders as text. Two suites, one row, and neither one covers it alone.

AT-030: TESTED_PASS.
  Test: m1b_gate_test.go:at030_denied_upgrades. Attempts the WebSocket upgrade on a live session
    four ways — no credentials, a wrong Origin, a valid token owned by someone else, an expired
    session cookie — and asserts each is denied with its own typed cause, and that the VM's count
    of open sessions is unchanged, so no PTY was reached.
  Evidence: `unauthenticated HTTP 401 cause="no_credentials"` / `wrong_origin HTTP 403
    cause="origin_rejected"` / `wrong_owner HTTP 404 cause="terminal_session_unknown"` /
    `expired_session HTTP 401 cause="session_invalid_or_expired"`; `open sessions on the VM
    before=1 after=1 (no PTY was reached)`.
  The wrong-owner denial is a 404 naming no session rather than a 403: a token that owns nothing
  on this host is told the session does not exist, which is the non-enumerable answer.

-->

| AT-005 | R-01, R-10 | Inject a failure after every provisioning side effect. Cleanup removes only owned resources and releases reservations or reports a retryable cleanup backlog. |
| AT-006 | R-01, R-10 | Retry the same create request across a timeout. Exactly the original VM/operation is returned; a changed payload with the same key conflicts. |
| AT-007 | R-01, R-05 | Verify user jobs cannot start before guestd readiness, workspace seeding, baseline creation and required sensor checks. |
| AT-008 | R-11 | Supply malicious seed archives: traversal, symlink/hardlink escape, device entries, huge expansion and too many files. Reject safely inside the preparation sandbox. |

## B. Multiple VMs and resource limits

| Test | Requirement | Procedure and required result |
|---|---|---|
| AT-009 | R-02 | Launch four admitted VMs simultaneously. Each has a distinct VM/boot identity, network allocation, writable disk set, terminal session and event binding. |
| AT-010 | R-02, R-11 | Write identical pathnames with different contents in two VMs. Reads, final hashes and exports show no shared writable state. |
| AT-011 | R-01, R-02 | Stop and delete one VM while others run commands and stream logs. No unrelated VM, terminal or network worker is interrupted. |
| AT-012 | R-02, R-09 | Submit simultaneous creates that exceed remaining RAM. Transactional admission does not over-reserve or start unaccounted VMs. |
| AT-013 | R-02, R-09 | Pause a VM and launch another request. Paused memory remains reserved; no false capacity is advertised. |
| AT-014 | R-02 | Test atomic-reservation batch rejection and a post-reservation boot failure. Per-VM results and configured keep/stop-successful behavior are correct. |
| AT-015 | R-02 | Retry a partially completed batch with its original key. The original member IDs/results return; no duplicate batch appears. |
| AT-016 | R-09 | Exhaust CPU, guest process count, guest RAM, terminal sessions and network concurrency in one VM. Limits activate and other VMs/control plane remain usable. |
| AT-017 | R-09 | Fill a workspace and event spool. Guest/storage-specific failure does not exhaust the host system filesystem or another VM's disk. |
| AT-018 | R-09, R-10 | Repeat create/start/stop/delete cycles and compare owned namespaces, cgroups, images, sockets and reservation counts with the documented idle baseline. No growing leaks. |

## C. Browser terminal

| Test | Requirement | Procedure and required result |
|---|---|---|
| AT-019 | R-03 | Run `tty`, shell job control and a foreground process in the browser. It is a real guest PTY, not a host shell or pipes-only imitation. |
| AT-020 | R-03 | Run installed `vi` and a full-screen process viewer; resize repeatedly; type UTF-8; use color, alternate screen and bracketed paste. Output and dimensions remain correct. |
| AT-021 | R-03 | Send Ctrl-C, Ctrl-D, suspend/resume and foreground/background job commands. Correct guest terminal/process-group behavior occurs. |
| AT-022 | R-03, R-10 | Disconnect/reload the browser and reattach by session ID. The same shell remains, commands do not rerun, and available output replays once. |
| AT-023 | R-03, R-12 | Overflow the retained terminal window while detached. Reattach shows a replay gap/reset rather than claiming an exact historical screen. |
| AT-024 | R-03, R-11 | Attach two browsers to one session. Only the lease owner can input/resize; transfer invalidates the old writer immediately. |
| AT-025 | R-03 | Open independent sessions in the same VM. Cwd, shell state, dimensions and exit state do not leak between PTYs. |
| AT-026 | R-03, R-12 | Duplicate terminal input frames and simulate an ambiguous broker restart. Accepted frame retries do not duplicate typing; ambiguous input is not blindly resent. |
| AT-027 | R-03, R-09 | Flood PTY output with a deliberately slow browser. Memory stays bounded, lost ranges are declared, and telemetry/control are not starved. |
| AT-028 | R-03, R-10 | Pause, resume, reboot and stop the VM while attached. The UI distinguishes these states; an old session cannot attach to a new boot. |
| AT-029 | R-03, R-11 | Emit HTML, malicious titles/links, OSC clipboard sequences and download-like control sequences. No DOM execution, automatic clipboard write or automatic download occurs. |
| AT-030 | R-03, R-11 | Attempt unauthenticated, wrong-Origin, wrong-owner and expired-session WebSocket upgrades. Deny each without reaching a guest PTY. |

## D. Structured execution and process events

| Test | Requirement | Procedure and required result |
|---|---|---|
| AT-031 | R-13 | Execute argv with stdout and stderr interleaving. Return separate cursorable streams, a stable exec ID, exact exit code/signal and correct limits. |
| AT-032 | R-13 | Pass shell metacharacters as ordinary argv. They remain arguments unless the caller explicitly selected a shell executable. No host shell runs. |
| AT-033 | R-13, R-10 | Retry an exec creation after connection loss. Query the original exec ID; do not execute a second copy. |
| AT-034 | R-13, R-09 | Cancel/timeout an exec that spawned descendants. All tracked guest job processes terminate; a detached child cannot survive by only orphaning its parent. |
| AT-035 | R-05 | Run a rapid short-lived process tree with forks and successful exec transitions. Sensor events preserve identities/parentage even when later `/proc` lookup is impossible. |
| AT-036 | R-05, R-12 | Attempt a nonexistent executable and an exec denied by permissions. Distinguish attempt/failure from successful execution. |
| AT-037 | R-05, R-12 | Force PID reuse and multiple execs in one PID. Process keys and exec generations remain distinct and historical rows are not overwritten. |
| AT-038 | R-05, R-12 | Use long argv and unavailable cwd/path data. Truncation/capture-failure fields are visible; missing data is not invented. |
| AT-039 | R-05, R-12 | Run shell builtins and interpreted in-process operations. The product does not claim they are all separately captured execs or a complete command transcript. |

## E. Filesystem events and final state

| Test | Requirement | Procedure and required result |
|---|---|---|
| AT-040 | R-05 | Execute deterministic create/write/close/rename/unlink/chmod operations on root and workspace. Supported events have correct scope and appropriate process/path evidence. |
| AT-041 | R-05, R-12 | Open a file writable and close without changing bytes. `fs.close_write` appears where supported; no unsupported `content_changed` assertion is made. |
| AT-042 | R-05, R-08, R-12 | Modify a persisted file via shared mmap and flush it. The final diff finds the change; notification coverage does not falsely claim a complete write history. |
| AT-043 | R-05, R-12 | Exercise rapid rename/unlink, hard links, non-UTF-8 names and bind-mount access. Preserve byte names/identities and mark unresolved/inferred paths honestly. |
| AT-044 | R-05, R-12 | Create a new mount or use an unsupported filesystem. Coverage reports the newly monitored scope or an explicit exclusion/gap. |
| AT-045 | R-05, R-12 | Overflow fanotify and eBPF queues deliberately. Loss health records and visible degraded coverage appear, with unknown counts represented as unknown. |
| AT-046 | R-05, R-09 | Trigger collector housekeeping, hashing and dependency-cache churn. No unbounded self-observation loop; UI noise filters do not silently erase supported captured evidence. |
| AT-047 | R-08 | Change content while preserving mtime; create/delete/type-change/symlink/hard-link/metadata-only cases. Final manifest/diff classifies them correctly without relying on mtime equality. |
| AT-048 | R-08, R-12 | Create then delete a file between baseline and final capture; modify tmpfs. Final diff scope is honest and does not claim to include vanished intermediate versions. |
| AT-049 | R-08, R-11 | Inspect a normal captured disk set. Verify no inspected filesystem is mounted in the host kernel and the inspector boots its own image without network access. |
| AT-050 | R-08, R-11 | Supply corrupted/hostile filesystem images, huge filenames/manifests and special-file trees. Inspector time/memory/output limits hold; no captured code executes. |
| AT-051 | R-08, R-12 | Force-stop during filesystem activity. Preserve the original disk digest; recovery, if needed, occurs only on a copy and the diff is labeled recovered/incomplete. |
| AT-052 | R-08, R-14 | Compare displayed before/after previews with actual retained artifacts and hashes. Missing/truncated historical content is not reconstructed from a current file. |

## F. Networking and interception

| Test | Requirement | Procedure and required result |
|---|---|---|
| AT-053 | R-06 | Test offline, transport and inspection profiles against controlled services. Allowed paths work and denied paths have correct outcomes/coverage indicators. |
| AT-054 | R-06, R-11 | Attempt cross-VM traffic, address/MAC spoofing, host API access, LAN/loopback/link-local/metadata access. Host enforcement blocks the prohibited paths. |
| AT-055 | R-06, R-11 | Re-enable IPv6 in a root-enabled guest and attempt IPv6 egress. Host boundary still drops it under the V1 IPv4-only policy. |
| AT-056 | R-06, R-11 | Change guest routes/DNS, unset proxy variables, connect directly to public IPs, use UDP/443 or alternate DNS in inspection mode. No silent bypass. |
| AT-057 | R-06 | Compare controlled flow tuples/counters and DNS records with fixture truth. Distinguish attempted/completed connections and DNS query evidence from request identity. |
| AT-058 | R-06, R-12 | Reuse network tuples, use UDP and connect through the proxy. Exact associations stay exact; ambiguous guest process attribution is shown as unknown/inferred. |
| AT-059 | R-06, R-11 | Test DNS rebinding, redirects to private addresses, mismatched CONNECT/Host authority, literals and unauthorized ports. Validate the actual upstream destination and deny bypasses. |
| AT-060 | R-06, R-12 | Exceed denial-log rate limits or drop packet/conntrack observations. Counters, sampling and gap metadata remain visible; missing individual records are not fabricated. |
| AT-061 | R-07 | Intercept controlled HTTPS using the per-VM CA with template curl/Python/Node/Git/package-manager clients. Verify upstream validation remains enabled. |
| AT-062 | R-07, R-12 | Use a pinned-certificate client or incompatible trust store. Show inspection failure or explicit passthrough status; never claim body visibility. |
| AT-063 | R-07, R-09 | Stream SSE/model-like responses, large package bodies, HTTP/2 multiplexed requests and WebSocket upgrades. Bounded records appear before close; no indefinite whole-body buffering. |
| AT-064 | R-06, R-07, R-10 | Kill proxy, resolver and flow workers separately. Policy stays installed; inspection has no direct fail-open fallback; required observation policy reacts as specified. |
| AT-065 | R-06, R-11 | Attempt to use another VM's proxy listener/CA identity. Connections and records cannot acquire another VM's network authority or log binding. |

## G. Durability, replay and crash behavior

| Test | Requirement | Procedure and required result |
|---|---|---|
| AT-066 | R-04, R-10 | Kill the controller after runner fsync/guest ACK but before database indexing. Restart indexes every acknowledged event once through deduplication. |
| AT-067 | R-04, R-10 | Kill after database commit but before spool-prune acknowledgment. Replay does not duplicate canonical event rows. |
| AT-068 | R-04, R-10 | Crash mid-record/segment creation before durable ACK. Recover an unacknowledged tail safely; corrupt interior data is flagged, not silently ignored. |
| AT-069 | R-04, R-11 | Replay a source sequence with different payload or spoof VM/provenance fields. Reject/quarantine contradiction; guest data cannot overwrite authoritative metadata. |
| AT-070 | R-04, R-12 | Reset guest wall clock, restart a collector and delay buffered streams. Source ordering, boot/source identity and host capture/ingestion times remain distinct. |
| AT-071 | R-04 | Publish events exactly while subscribing/reconnecting. Cursor-based replay/live delivery has no unreported gap or duplicate UI rows. |
| AT-072 | R-04, R-12 | Request a retained cursor and an expired cursor. Replay the former; return explicit expiry/earliest cursor for the latter. |
| AT-073 | R-04, R-09 | Saturate one VM's spool/index stream while others run. Fair ingestion and bounded memory hold; every loss/truncation policy is visible. |
| AT-074 | R-10, R-12 | Kill guestd in both privilege profiles. Host indicates degraded/unavailable health and maintains egress enforcement; strict mode pauses/stops within its documented detection bound. |
| AT-075 | R-10 | Kill/restart runner and controller independently. Reconcile the actual owned VMM using identity/cgroup evidence, and never signal a PID-reused unrelated process. |
| AT-076 | R-01, R-10 | Race start/stop/pause/delete and cancel during provisioning. Valid transitions serialize; reservations and resource ownership remain correct. |
| AT-077 | R-10, R-14 | Simulate host reboot/power interruption on the test host. Reconcile interrupted runs and retained data; state the durability boundary and any unacknowledged unknown interval. |
| AT-078 | R-10, R-14 | Back up and restore metadata/artifacts to a separate test installation. Verify canonical event counts, artifact digests, retention metadata and no accidental live-VM resurrection. |

## H. Security, UI, export and load

| Test | Requirement | Procedure and required result |
|---|---|---|
| AT-079 | R-11 | Attempt cross-owner API/terminal/artifact access, CSRF mutations, forged proxy identity headers and unauthorized helper RPC. Deny without host side effects. |
| AT-080 | R-11 | Submit host path traversal, symlink substitutions, executable-path injection and arbitrary nft/shell fragments through exposed inputs. Helper rejects them; no generic host exec exists. |
| AT-081 | R-11, R-14 | Inject known canary secrets into headers, query strings, argv, structured bodies and error paths. Search spools, DB, debug/proxy logs and default exports; prohibited plaintext is absent. |
| AT-082 | R-11, R-12 | Enable sensitive body/terminal/pcap/disk capture explicitly. UI/ACL/retention labels are correct and do not falsely promise complete redaction or erasure. |
| AT-083 | R-04, R-11 | Render malicious filenames, URLs, bidi text and JSON fields in every UI view. They remain escaped data; no injected markup, script or misleading hidden action. |
| AT-084 | R-02, R-03, R-04 | Complete the real user workflow: batch launch, correct terminal selection, side-by-side events, filter, pause scrolling, stop one VM and inspect others. Keyboard/refresh/error states work. |
| AT-085 | R-14 | Export a complete bounded run with a known gap, redaction and incomplete preview. Export includes the same coverage, consistency, policy/runtime-lock and digest metadata shown in UI. |
| AT-086 | R-09 | On the documented reference host, measure four-VM workloads, terminal p95 echo, event p95 latency, steady metadata load and burst behavior. Publish measurements; do not mark targets met without data. |
| AT-087 | R-09, R-10 | Exhaust optional capture quota and then approach the host reserve threshold. New launches stop; durable ACK semantics hold; health/control remain usable. |
| AT-088 | R-01, R-11 | Trigger authenticated host emergency stop while guest control is unresponsive. Owned VM uplinks/processes are stopped without touching unrelated host workloads. |

## I. Agent operations: situation, attention, runs and self-description

These rows verify the agent-interface principles P-01 through P-08 defined in `SPEC.md` section 1.4.

| Test | Requirement | Procedure and required result |
|---|---|---|
| AT-089 | R-15 | Populate mixed fleet states: running, failed, paused, degraded telemetry, active run. `/situation` lists each VM exactly once, matches the underlying records, and stays within the configured byte bound; `?since` returns only changed entries; an unchanged system returns a small quiet response with valid cursors (P-01, P-02). |
| AT-090 | R-15 | Induce each enumerated attention trigger class once. Exactly one item per condition appears with evidence links, recorded system action and typed suggested actions; execute one suggested action verbatim and it succeeds; acknowledgment removes the item from the default view, retains history, and survives controller restart. |
| AT-091 | R-15, R-12 | Kill a sensor or collector feeding triggers, then quiesce the fleet. The quiet situation response reports the reduced watch scope and degraded trigger classes; blind calm is never presented as monitored calm (P-03). |
| AT-092 | R-16 | Submit a batch of launches with attached runs (`exec_exit_zero`, `stop_and_finalize`). Runs conclude, VMs stop and finalize per policy, and each report validates against `run-report.schema.json`; re-run every `reproduce_query` in one report and confirm each count matches (P-05). |
| AT-093 | R-16, R-10 | Resubmit run creation with its original idempotency key across connection loss and controller restart: exactly one run exists. Crash the runner mid-run: the run resumes or concludes with an explicit interruption reason; accepted exec work is not executed twice. |
| AT-094 | R-16, R-12 | Fail the success criteria; separately make them unevaluable by killing guestd before the verdict and by submitting a malformed result. Failed runs report `failed` with evidence; unevaluable runs report `inconclusive` with the reason; a report is produced in every terminal phase; no verdict is fabricated. |
| AT-095 | R-16, R-12 | Workload emits progress and a result at the size cap and beyond it. In-bound submissions appear as ordered `run.progress` and result records labeled guest_reported; oversized or malformed submissions are rejected with a bounded recorded reason and cannot crash guestd, the runner, or the indexer. |
| AT-096 | R-17 | Compare `/meta` against `runtime.lock.json` and the loaded configuration: versions, limits, enabled features and active trigger classes match the running truth. Change a configured limit and restart: the manifest reflects it. No manifest field contradicts behavior observed elsewhere in the suite. |
| AT-097 | R-17, R-12 | Collect every distinct event kind emitted across the full acceptance run. Each exists in `/meta/event-kinds` with schema reference, provenance class, semantics and caveats; the registry is generated from the emitting code's own tables; an unregistered kind is rejected at ingress with a health record. |
| AT-098 | R-17, R-06 | For each network and privilege profile, read `context.json` inside the guest and behaviorally verify each stated expectation: stated-allowed egress succeeds, stated-denied egress fails, the stated workspace layout and result convention work. The context never promises what enforcement denies. |
| AT-099 | R-13, R-09 | Induce capacity exhaustion, revision conflict, expired cursor, missing capability and idempotency-conflict errors. Each returns a typed cause and retryability; where remediation is defined, the options are executable exactly as returned — execute the capacity remediation and the follow-up request succeeds (P-06). |
| AT-100 | R-14, R-15 | Annotate a VM, a run and an event; conclude a run with an operator verdict. Annotations are immutable, author-attributed, queryable by target ref, survive restart, appear in exports, and outlive VM compute deletion under the retention policy (P-04). |
| AT-101 | R-14 | Walk a defined checklist of every UI view: fleet, VM detail, timeline row and drawer, runs, coverage, diff, network. Every displayed fact is retrievable through the public API with the same value and provenance/quality labels; no UI-only data path exists (P-07). |
| AT-102 | R-16, R-13 | Drive the reference four-VM loop end to end through the CLI in JSON mode only: batch launch with runs, situation delta polling, report harvest, attention acknowledgment. Record round-trips and default-form response bytes; publish the trace against the SPEC.md section 19 interaction budget. No per-VM busy-polling is required. |

## Traceability and release gate

Every requirement R-01 through R-17 is represented above. The builder must add tests when implementation choices introduce new behavior, not replace this matrix with a handful of happy-path checks. New tests take the next sequential ID; existing IDs are never renumbered or reused.

Acceptance evidence accretes under stable IDs in `tests/acceptance-evidence/AT-xxx/` as machine-readable records plus referenced logs and artifacts. Successive builder sessions append runs; they never overwrite recorded history.

V1 mandatory gate: all 102 rows are implemented and run in their relevant environment, with every failure or blockage explicitly reported. Any scoped exception requires a documented product limitation and must not contradict the core requirements. Memory snapshot/restore is not part of these 102 V1 rows.
