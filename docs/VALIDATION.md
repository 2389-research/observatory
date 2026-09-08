# Specification Package Validation

## Revision 27 (2026-09-06) — a VM boots confined, a terminal opens, and two bugs it found

Kata `q4b2`, closing half. The last thing §7 asked for is measured: a VM reached
`running / running / healthy` with `vmobs-jailer` in enforce mode on the firecracker
process itself, zero denials, guest channel authenticated over vsock. A terminal opened
on a second VM under the same profile — `101` on the upgrade, `attached` with the writer
lease, `echo <marker>` typed in and the marker echoed back with a fresh prompt. Two of
§7's remaining bullets closed, not one; §10 carries both transcripts.

Reaching that took a fifth AppArmor denial and found two product bugs.

The denial was `mount fstype=sysfs -> /sys/`: `ip netns exec` replaces `/sys` with a
sysfs instance describing the namespace it enters, and privd runs every network command
that way. Granting the three mounts `ip netns add` makes never reaches it — startup
passed and every launch failed at network allocation. privd's jail probe now runs
`ip netns exec` too, and caught the next instance of this in under a second instead of
a rebuild, a restart and a launch. **A startup probe is worth exactly the production
verbs it runs**: all five denials were operations the probe did not perform.

The first product bug: terminals were unreachable on every VM in the shipped
configuration. `cmd/vmobsd/main.go` set `PublicOrigin` only on the branch where
authentication is enabled, and the appliance ships with `require_authentication: false`.
It is not an authentication field — the WebSocket origin gate compares it on every
upgrade — so every terminal was refused `403 public_origin_unset` while the config set a
public origin two lines above the listen address. Every API test builds `AuthConfig` by
hand, which is why the suite never saw it.

The second: a container restart could strand a VM beyond any API call. privd's ledger is
on tmpfs; the chroots are not. The force-stop path reported privd's ordinary `not_found`
as a cleanup debt, `Manager.Delete` treats a debt as a failed force-stop, and the row sat
at `failed` with 5120 MiB reserved and `free_disk` at `-2536`. `doRelease` had always
taken its verdict from the filesystem; the stop path now shares that rule. The deeper
half is unfixed and §7 says so: a chroot whose ledger entry is gone is still reclaimable
only by hand.

Also corrected: the profile had never been installed, only parsed — `/etc/apparmor.d/vmobs-jailer`
did not exist, so it died at every reboot. `deploy/install-apparmor.sh` installs it where
boot looks and `start` refuses when the installed copy is missing or stale, naming the
script. `deploy/README.md` listed three rules; the profile has ten.

`env -u GOROOT mise exec -- ./scripts/check`: all ten gates passed.
`uv run docs/validation/check.py`: 47/47 package checks passed. The confined boot,
terminal round trip and strand were measured on aibox03 against the container built from
this branch; the acceptance gate has still never run in a container.

## Revision 26 (2026-09-06) — verified systems review recorded in Kata

Checked the eight supplied review findings against source at `bd65d80` and existing
Kata history. Filed `3dnv`, `bm7v`, `bxm8`, `ryvx`, `exf0`, `8bdk`, `00e7`, and
`apwk` with evidence, corrected scope and acceptance criteria. PLAN.md records
the session; gotchas.md corrects the unconditional shutdown-order advice.

`env -u GOROOT mise exec -- ./scripts/check`: all ten local gates passed.
`uv run docs/validation/check.py`: 47/47 package checks passed. Concurrent unrelated
deployment edits were present during the full gate; reviewed source files remained
unchanged. These checks establish the local baseline, not fixes for these findings.
No Linux/KVM fault or power-loss tests ran in this review.

## Revision 25 (2026-09-06) — the boundary document stops predicting and starts reporting

Kata `q4b2`, implementation half. `docs/design/container-boundary.md` gains §10, the
record of what the built appliance actually did on aibox03, and §7 shrinks to what is
genuinely still unmeasured. §0 and §9 are corrected: they described a document with no
Dockerfile, no shipping profile and a pending review, and all three have moved.

The correction worth reading is `/dev/kvm`. §7 predicted that the jailed uid would fail
to open the device and that `--group-add 108` was the likely fix — "the next thing that
breaks". It was wrong in its premise. The jailer `mknod`s its own `dev/kvm` inside the
chroot while it is still root and chowns it to the jail uid, so firecracker opens a node
it owns while holding no supplementary groups at all. The host's kvm gid does matter one
layer out, for vmobsd's `arch_kvm` preflight, and `--group-add` cannot deliver it there
either: `setpriv --init-groups` rebuilds the supplementary set from `/etc/group` and
discards whatever docker granted. The prediction and its correction are both kept, in
§7's pointer and §10's answer, because a document that quietly deletes its wrong guesses
teaches nothing about which guesses to trust.

Also moved from prediction to measurement: a real boot (two VMs to `running` in 7s each,
authenticated guest channel, clean teardown with zero leaks), what a container restart
does to a running VM (kills it, empties privd's tmpfs ledger, and strands its chroot
permanently — filed as its own kata), and the narrow seccomp profile, which §7 had
called "very likely sufficient" while declining to write that down as a fact.

What §7 still owes is named rather than glossed: the AppArmor profile ships and has
never been loaded, so every measurement in the document ran with `apparmor=unconfined`.
AT-002 has not run in a container, and no console PTY has been opened in one.

`deploy/README.md` gains the matching note on why no `--group-add` appears in the run
line. Package checks: 47/47 passing, unchanged in count — no file was added or removed.

## Revision 24 (2026-09-06) — the container boundary is measured, not inherited

Kata `q4b2`. `docs/design/container-boundary.md` names every privileged operation v2's
launch chain performs — privd's five verbs, the jailer's argv, the guest channel — and
what each asks of the kernel, set against Docker's defaults measured on aibox03
(Docker 27.2.1, kernel 6.8.0-138-generic, jailer/Firecracker v1.16.1).

Method note, because it is the finding: v1's container measurements were re-derived
rather than copied. v1 ran Firecracker directly and its own plan records that its
passing test "did not validate guest authentication, jailer isolation, TAP/network
namespaces, the helper, restart recovery, or AT-002". Re-running the chain under v2's
own argv killed two inherited assumptions — the read-only cgroup mount does not block
v2's jailer, and `/dev/vhost-vsock` is never opened because the guest channel is a unix
socket — and surfaced one v1 could not have seen: Docker's default seccomp profile
blocks `pivot_root`, so the jailer fails at no capability level until seccomp is lifted.
Two exceptions are required where v1 needed one.

The document authorizes no configuration. It is the input to the device/cgroup/security
review the kata makes a precondition, and §7 lists what remains unmeasured — starting
with whether the jailed uid can open `/dev/kvm` after the privilege drop.

Package checks after the addition: 47/47 passing, unchanged in count — `check.py`'s
README inventory check reaches `design/` since Revision 23, so the new file is verified
to exist and to be listed.

## Revision 23 (2026-09-06) — the agent-control gap map joins the package, and the inventory check reaches it

Kata `3tn6`. `docs/design/agent-control-contract.md` maps v1's agent control protocol
(`../observatory/docs/AGENT-PROTOCOL.md`, pinned at `d432cdc`) onto what v2's API actually
serves: the nine v1 verbs against v2's twelve, v1 §5's objects against v2's tables and wire
types, the vertical slice a cold agent can walk today, and seven ranked gaps. Every "v2 has
this" row was read against the implementing code rather than against `SPEC.md`, and citations
name a file and a symbol — a line number in a doc `check.py` never opens is a citation that
rots in silence.

It is a review artifact, not a contract. `SPEC.md` still binds, nothing here changes it, and
every route the map proposes is marked unimplemented. Two of its findings are against v2's own
rules: `handleMeta` builds `links` by hand while `features` comes from the route table, so a
feature can be advertised with no path to reach it — against the builder directive in this
package's own README — and `/situation` sheds `attention_head` and `changed_vms` by halving
while reporting no omission count, discarding an `attention_open` the engine computes on every
request. The map also records a trap: v1's AT-089..095 and v2's AT-089..095 are different
tests wearing the same IDs, so its proposed scenarios are numbered AT-103 and later.

One check changed. The README file inventory matched only `schemas/`, `examples/` and
`validation/check.py`, so a README line naming any other path was never verified to exist.
The pattern now covers `design/` as well; removing the new document drops the run to 46/47 on
"Every file listed in README exists", which is the check doing its job. No schema, example, or
acceptance row changed, and the acceptance sequence is still exactly 102 rows.

47 checks, all passing.

## Revision 22 (2026-09-06) — privd enforces one instance, and the runbook says how to read the refusal

Kata `c3f2`. `cmd/vmobs-privd/main_linux.go` removed the socket path before listening, and a unix
socket's name is not held by the process bound to it, so a second privd unlinked a live first
one's socket and bound its own. The first kept serving a name nothing could reach while every
client moved to the second — and with two privds come two ledgers, which turns off every refusal
revision 20's registry work rests on. `acquireSingleton` now takes two non-blocking flocks,
`<socket>.lock` and `<ledger-dir>/.privd.lock`, before anything is removed or bound, and clears
the stale socket only once that hold proves nothing is listening (`8a1f90a`).

`docs/runbooks/aibox03.md` gains a "One instance, enforced" section: the two lock paths, the
refusal an operator sees, and the one thing they must not do about it — deleting a lock file to
get past the message is deleting the only thing standing between two privds. The hold belongs to
the open file description, so the kernel drops it however the process ends; a lock file on disk
with nothing holding it blocks nothing, and both paths sit under the unit's `RuntimeDirectory`,
which systemd removes when the unit stops (`6501aca`).

Nothing this revision touches is a schema, an example `check.py` parses, or `check.py` logic. The
runbook is prose, and `gotchas.md` — three entries replacing the one that called single-instance
"an assumption, not an enforcement" — is outside the validated package.

47 checks, all passing.

## Revision 21 (2026-09-06) — a failed launch keeps its runner log, and AT-005's line citations are corrected

Kata `b2t2`. `doRollback` removes the VM state directory, and for a launch that failed at
`runner_spawned` or `attached` that directory held `runner.log` — the only account of the fatal
step. The stage name survived and the cause did not. `internal/jailer/postmortem.go` now copies
`runner.log` and `runner-state.json` into `<StateDir>/failed/<timestamp>-<vm>-<boot>/` before the
removal, and the launch error names the archive, so the reason reaches the operator through the
failure record the API already exposes. The capability token is never copied (§15.3); the copies
are capped at 256 KiB with a first line naming what was dropped; sixteen archives are kept.

`docs/ACCEPTANCE.md` changes in two ways. The AT-075 note that said recovering that log "needs a
product change outside M2a's scope" is replaced by what the product now does, with the run it
describes still marked unexplained — the fix does not retroactively diagnose a run that predates
it. AT-005's status block gains the assertion the injection suite now makes about the archive.

Nine line citations into `internal/jailer/launch.go` were already wrong before this change and
are corrected: the three post-side-effect manifest writes (`:150/:176/:226` → `:160/:191/:242`),
the reserved write (`:111` → `:115`), the state-dir mkdir (`:107` → `:111`), artifact
verification (`:268` → `:292`), the rootfs copy (`:273` → `:312`), the `allocate_network` verb
(`:146` → `:156`), `start_vm` (`:162` → `:177`), the runner spawn (`:218` → `:233`), and the
uid/CID derivation (`:63-70` → `:72-74`). They drifted by different amounts because separate
commits added lines at separate places, which is why nothing caught them. `check.py` verifies the
package's structure, not that a number points where its sentence says — a line citation into code
is the same failure mode as a digest quoted into prose, and it rots the same way.

47 checks, all passing.

## Revision 20 (2026-09-06) — acceptance evidence becomes a record, and revision 19's lock claim is withdrawn

Adds an "Execution records" section to the evidence rules in `docs/ACCEPTANCE.md` and replaces
the hand-quoted runtime lock in the M1a status block with the 2026-09-06 re-run. `check.py`
gained one check: the row count `internal/evidence` mirrors must equal the number of rows this
document defines, so the package cannot drift into refusing a row that exists (47 checks, all
passing).

Kata `2jt1` asked for immutable, digest-bound acceptance executions. A gate transcript said what
happened; it did not say what ran. Each real-host gate now publishes one machine-readable record
per acceptance row (`internal/evidence`), binding that row's outcome to the commit, the sha256 of
every binary that ran, the runtime-lock digest, the artifact digests the lock pins, the host's
identity and preflight verdict, and the digest of the transcript the subtest wrote. Publishing an
execution ID twice is refused. The rules this page states are enforced there rather than
described: portable evidence cannot record a pass, a result other than `blocked` needs an
executed procedure, a real-host run names the bytes that ran, and a cleanup claim carries both
host inventories and an observed terminal state or it is refused.

Revision 19 said the 2026-09-05 M1a re-run used the "same host and runtime lock as the 2026-09-02
runs". The host was the same; the lock was not. `runtime.lock.json` was re-pinned on 2026-09-04
(`e70224f`) and again at 12:12 on 2026-09-05 (`3ec51bf`), three hours before that evidence
landed (`5f97695`, 15:44). The M1a status block carried a rootfs digest of `c6a92bba…` from
2026-09-02 that had by then been wrong for two days. Both claims were written by hand from a lock
read at some earlier moment, which is the whole failure this kata removes: the 2026-09-06 records
carry the lock digest the run actually verified against, and no lock digest on that page is
hand-written any more.

Evidence: `tests/integration/evidence/executions/`, seven records from the 2026-09-06 aibox03 run
— eight subtests, eight passes, zero skips, 102.1s. Normalized for UUIDs, timestamps, pids and
temp-dir names, that run's transcript is byte-identical to the 2026-09-05 one apart from the list
of records it published. Each record reads back through `evidence.Load`, which validates it, and
`evidence.Verify`, which re-hashes its artifact.

## Revision 19 (2026-09-05) — AT-011 and AT-018 now assert VMM death and reservation totals

Amends the "L1 M1a status notes (2026-09-02)" block in `docs/ACCEPTANCE.md`: the AT-011 and
AT-018 rows, and a paragraph in the block's header recording the re-run that produced the
evidence they now quote. No requirement text changed; the rows say more about the same subtests.

Kata `b33f` asked for end-to-end fault cases "proving process liveness and reservation totals
together. Sending a signal is not the assertion." Both rows had passed on neither. AT-011 read
the stop event's reason and the sibling VM's state; AT-018 counted six host-side observables, of
which the firecracker process count is an aggregate that cannot name which process left. Each
subtest now reads the VMM identity out of the manifest before the stop — pid and `/proc` start
time together, so a recycled pid does not answer for a dead one — and asserts it is gone from
`/proc` afterwards, alongside the reservation the release was supposed to return: memory and
vCPU for AT-011's graceful stop, which keeps its disk, and all three pools for AT-018's
force-delete, which does not.

Three things the rows state rather than assume. The liveness read parses `/proc` in the test
instead of calling `privd.PIDAlive`, which is what the stop path's own proof gate calls — the
gate is the code under test, so asking it to check itself would make the evidence agree by
construction. A positive control runs against the live VM first, because "not alive" is the
passing answer and a field read at the wrong offset would give it about every process on the
host. And a zero charge fails the subtest instead of making the release arithmetic vacuous.

AT-018's gap (b) is narrowed, not closed, and now says so: the six-counter delta still never
queries `/host/status`, the five graceful cycles still assert nothing about totals, and no cycle
compares against an idle baseline. One delete out of six is measured.

Evidence: `tests/integration/evidence/m1a-gate-aibox03.txt`, replaced with the 2026-09-05 run —
eight subtests, eight passes, zero skips, 102.6s on aibox03, same host and runtime lock as the
2026-09-02 runs. The §15.3 scan over the new file returns nothing.

## Revision 18 (2026-09-05) — M2a live-gate evidence: AT-074 and AT-075 recorded, both partial

Adds one dated HTML comment block to `docs/ACCEPTANCE.md` — "L2 M2a status notes (2026-09-05)" —
recording what the M2a telemetry gate observed on aibox03: six subtests, six passes, 223.62s,
one VM for the whole run, evidence committed at `tests/integration/evidence/m2a-gate-aibox03.txt`.
Gate commit `1b05136`.

Two criteria are claimed and both are marked partial in the block itself. AT-074 covers one
privilege profile (the host has one) and no egress enforcement or strict mode, neither of which
M2a ships. AT-075 covers the controller half live; the runner half and "never signal a PID-reused
unrelated process" are proven at the `internal/jailer` unit seam, and the cgroup half of
"identity/cgroup evidence" is not implemented at all — identity here is argv plus pid plus
`/proc/<pid>/stat` field 22.

Two things the run did not settle are recorded as not settled rather than forced. A live ring
overflow is `INCONCLUSIVE`: 1024 items, drained on host acknowledgement, one producer at one push
per 10s is ~2.8 hours, and a guestd built to push faster would be a test-only agent shipped into
the product. The wire path is exercised on every heartbeat and the accounting is unit-covered;
only the live observation of a non-zero `dropped` is unproven. And the M2a plan's phrase
"degraded then unavailable" is corrected in the block: `deriveTelemetryHealth` returns `degraded`
for a stale heartbeat, and `unavailable` needs a non-running VM, an empty current boot, or no
heartbeat at all — SPEC §952 asks for either, and the gate walks both paths separately.

### Results

- 46 package checks passed (`uv run docs/validation/check.py`, exit 0).
- All revision-17 results hold. The edit adds one HTML comment block and changes nothing outside
  it: no acceptance ID added, removed or renumbered, no matrix row changed, no fenced code block
  opened or closed, `check.py` untouched.
- The AT-074 and AT-075 matrix rows are unchanged. Their status lives in the comment block, the
  same place M0, M1a and M1b record theirs.

## Revision 17 (2026-09-04) — the capacity leak closed, and the acceptance record kept honest

Run after kata `r799` was fixed: the `stopped -> starting` transition now re-acquires the memory and
vCPU that the stop released, inside the writer transaction, gated by the same admission check a
create runs. `TransitionInput` gained `AcquireCompute` and an `Admit` callback; the check runs before
any write, so a host with no room refuses the start and leaves the VM stopped rather than parking it
in `starting` with a launch already under way. The start asks for zero disk, because the reservation
row never released the disk — asking again would count it twice and refuse a restart that fits.
`failAction` now carries a typed `AdmissionRefusal`'s own cause and message onto the failed
operation, so the actions route answers 409 `insufficient_capacity` the way a refused create does.

The docs change is small and additive. `docs/ACCEPTANCE.md`'s M1b status block records what the M1
gate saw, and what it saw was a live host with the defect in it; that paragraph is not rewritten. A
parenthesis after it names the fix commit, the live numbers, and says the paragraph stands as
evidence of the gate. Revision 16's "unfixed at this commit" gains a dated correction clause
pointing here, the same treatment revision 16 gave revision 15.

### Results

- 46 package checks passed (`uv run docs/validation/check.py`, exit 0).
- All revision-16 results hold. The `docs/ACCEPTANCE.md` edit adds 6 lines inside the same "L1 M1b
  status notes" HTML comment and removes none: no acceptance ID added, removed or renumbered, no
  matrix row changed, no fenced code block opened or closed, check.py untouched.
- No AT is claimed for the fix. It has unit, API and live evidence (below), but SPEC §18's acceptance
  IDs do not cover capacity accounting across a stop/start — the gap that let the defect ship. An AT
  for it belongs to whichever milestone next revises the ID set, not to a retroactive edit here.
- Live evidence, aibox03, two real Firecracker VMs at 1 vCPU / 512 MiB (1280 MiB reserved each with
  the 768 MiB per-VM host overhead): `reserved_memory_mib` 2560 -> 1280 -> 2560 across a stop and a
  start, `reserved_vcpu` 2 -> 1 -> 2, `reserved_disk_mib` 6144 throughout, `free_memory_mib` back to
  48589 exactly. Operations `op-000009` and `op-000010` both succeeded; the VM reached `running` at
  revision 7. Host clean after teardown: 36 GB free, no firecracker processes.
- The refusal half has no live evidence, deliberately. Refusing a start is a decision the writer
  transaction makes before it writes anything and before `rt.Launch` runs, so a real host would show
  nothing a fake runtime does not. It is covered by unit tests at the store and manager layers and by
  an API test asserting the 409, each mutation-proven.

## Revision 16 (2026-09-04) — a real browser against a real daemon, and the capacity leak it found

Run after the M1b live gate's last open clause was closed by hand. SPEC §18 asks for storage and stop
actions to be demonstrated, and revision 15 recorded honestly that the Go gate drives them through
the public API rather than through a browser — the one thing in the M1 gate line no automated run had
covered. That run has now happened: a real Chrome loaded `/ui/` from a real `vmobsd` on aibox03 with
three VMs up, and demo-3 was stopped and started again by clicking its own buttons in the fleet
table. The two sentences saying the run was unrun are replaced by what it did, with the numbers the
page rendered and the operation ids the host recorded, all of them re-derivable from
`/api/v1/host/status` and `/api/v1/vms`.

The run earned its keep. With all three VMs running again, host status reported `active_vms: 3`
alongside `reserved_memory_mib: 2560` and `reserved_vcpu: 2` — two VMs' worth — while reserved disk
stayed correct at three VMs' worth. Stopping a VM releases its compute reservation and starting it
never takes the reservation back: `internal/store/vms.go` writes `compute_released` in two places
and both set it to 1, and the `start` case in `internal/runtime/manager.go` never touches the
reservation row. Admission sums those rows, so a VM that has been stopped and started once is
invisible to the check that keeps the host from overcommitting. It is filed as kata `r799` (P1) and
unfixed at this commit (Corrected 2026-09-04: fixed later the same day in `816ae18`, recorded in
revision 17); the acceptance block names it, states it is not an M1 gate blocker because no
AT asserts capacity across a stop/start, and says why it is recorded there anyway. Fixing it inside
the gate task would have changed the binaries the two recorded PASS runs were measured against.

### Results

- 46 package checks passed (`uv run docs/validation/check.py`, exit 0).
- All revision-15 results hold. The edit changes 31 lines and removes 6 in `docs/ACCEPTANCE.md`, all
  of them inside the same "L1 M1b status notes" HTML comment: no acceptance ID was added, removed or
  renumbered, no matrix row changed, no fenced code block was opened or closed, and check.py logic is
  untouched.
- Revision 15's claim that no browser run had happened is superseded, not deleted; a dated correction
  clause on that revision points here.

### Check log

- PASS — All 46 checks (identical list to revision 15; output elided for brevity).

## Revision 15 (2026-09-04) — M1b live-gate evidence: AT-019..AT-030 recorded, four of them partial

Run after the M1b terminal gate went green on aibox03 (code at `37d2e1b`; this revision carries the
docs). `docs/ACCEPTANCE.md` gained one HTML comment block, "L1 M1b status notes (2026-09-04)",
recording what two consecutive PASS runs of `TestM1bGate` establish and — as importantly — what they
do not. Each of AT-019..AT-030 gets a status, the test function that produced it, the assertion that
bites, and a quoted line from `tests/integration/evidence/m1b-gate-aibox03.txt`. Four entries are
labelled partial and say which half is unproven: AT-021 exercises `bg` and never sends `fg`; AT-022
proves scrollback replays but leaves "commands do not rerun" to AT-026; AT-025 measures the wire and
not host RSS; AT-028 records pause/resume as `inconclusive` because `Adapter.Pause` returns a typed
`UnavailableError` in M1a and no `reboot` action exists, so its new-boot proof goes stop then start.
AT-026 carries the §8.2 deviation it depends on: input sequence numbers are per connection, not per
session. The block opens by mapping SPEC §18's own M1 gate line onto the four subtests that satisfy
it and naming the clause that is only partly satisfied: §18 says demonstrate, and the plan asked for
storage and stop actions driven "through the web UI's own controls", while this gate drives them
through the public API the UI is a client of. The controls have their own vitest coverage against
real components; no run in this milestone drove a real browser against a real daemon, and the block
says so rather than letting the reader infer it. (Corrected 2026-09-04: that browser run was done
later the same day and is recorded in revision 16, which rewrites those two sentences of the block.) AT-029's browser half is asserted by `web/src/Terminal.test.tsx`, not by the Go gate, and
the entry says so. The gate found two product defects on its way to green, both fixed before the
evidence was recorded and both named in the block: a terminal event stream bound API-wide when
`internal/store/append.go` scopes a source stream to one VM, so every VM after the first lost its
session events (`114a03e`); and a `vm.vmm_exited` that crossed the spool boot-blind, letting one
boot's exit notice fail the boot after it (`320cfe1`). No requirement was weakened to pass a test.

### Results

- 46 package checks passed (`uv run docs/validation/check.py`, exit 0).
- All revision-14 results hold. The edit adds 200 lines to `docs/ACCEPTANCE.md`, all of them inside
  one HTML comment: no acceptance ID was added, removed or renumbered, no matrix row changed, no
  fenced code block was opened or closed (the block contains none), and check.py logic is untouched.
  The twelve IDs the block discusses, AT-019 through AT-030, already existed in the matrix.

### Check log

- PASS — All 46 checks (identical list to revision 14; output elided for brevity).

## Revision 14 (2026-09-03) — the jailer's argv spelling is `--id <id>`, not `--id=<id>`

Run after the rollback kill-target fix (code at `e3fb98d`; this revision carries the docs). `docs/runbooks/aibox03.md` asserted in its `jail-stop` paragraph that "the process title is `firecracker --id=<id> ...` (using `=`, not space)". That is false, and it points the wrong way at exactly the moment it matters: privd's `AbortStartVM` now proves a kill target by `--id` and the VM id as two adjacent argv elements, so an operator or agent reading the runbook would conclude the predicate can never match and undo it. Jailer v1.16.1 builds the child command with `.args(["--id", &self.id])` (`src/jailer/src/env.rs`) — two separate elements — and a live `/proc/<pid>/cmdline` sample from aibox03 agrees; on that same sampled line `--config-file fc-config.json` and `--api-sock api.sock` are unambiguously four elements, so the sampler was not rendering `=` as a space. The paragraph keeps its conclusion — the pid file is authoritative — on reasons that hold: every path under the jail carries the VM id, so `pgrep -f <id>` also matches a runner dialing that jail's `v.sock`, and any pattern that pins the flag bets on jailer's argv spelling. The same claim was corrected outside the validated package, in `gotchas.md` (the entry now leads with the pid file as the handle and records the upstream spelling) and in `scripts/aibox03/vmobs-root-helper`'s `jail-stop` comment (commit `c3c7dae`). `PLAN.md`'s L0 Task 1 entry carried the claim as that session believed it; rather than rewrite a dated log, a `Corrected 2026-09-03:` clause was appended to it, following the same practice the deviations log above already uses — the entry keeps what that session concluded and says what is true.

### Results

- 46 package checks passed (`uv run docs/validation/check.py`, exit 0).
- All revision-13 results hold; no acceptance ID was added, removed, or renumbered, no schema or example changed, and check.py logic is untouched. The only file this revision edits inside `docs/` is the runbook, which check.py does not parse.

### Check log

- PASS — All 46 checks (identical list to revision 13; output elided for brevity).

## Revision 13 (2026-09-02) — rollback leak fix: AT-005 at nine subtests, stage dir reclaimed by rollback, revision 12's comment certification withdrawn

Run after the rollback-leak fix round (code at `02ea171`; this revision carries the docs). Two launch-rollback leaks are fixed: `doRollback` removes the stage dir without a stage guard, so a `doStage` failure no longer orphans it, and a failed reserved manifest write removes the state dir it made for a fresh VM. `docs/ACCEPTANCE.md`: AT-005's status parenthetical names the three remaining escape windows (`launch.go:150/:176/:226`) and the restart path instead of five windows; its Test line lists nine subtests and records the 9/9 run in a linux/arm64 container on the darwin workstation, not on aibox03; the "Each subtest makes one step fail" list now matches the real injection points — the subtest formerly named `manifest_write_failure` injected at the state-dir mkdir (`:107`) and is now `state_dir_mkdir_failure`, and two new subtests inject at the write (`:111`) — and the "Not injected" paragraph no longer says the stage dir is "reclaimed later by Release on delete": it never was, because `doRelease` returns before its stage-dir removal when the manifest is gone. `PLAN.md`: the deviation entry says the same, the allocator entry's `launch.go` citations follow the moved lines, and a session-log entry carries the mutation-proof failure lines and the container runs. Correction to revision 12: it certified the comment at `internal/jailer/launch.go:126` as corrected in place. The rewritten comment — "Rollback removes the state dir only; a stage dir doStage left is reclaimed by Release on delete" — was false for the same reason as the paragraph it echoed, and revision 12 certified it without checking the claim against `doRelease`. The comment now sits at `:136` and reads "doRollback removes the state dir and whatever doStage left in the stage dir"; this revision checked that against `doRollback` (`:513-521`) before writing it down.

### Results

- 46 package checks passed (`uv run docs/validation/check.py`, exit 0).
- All revision-12 results hold; no acceptance ID was added, removed, or renumbered, and the only parsed example check.py inspects (`docs/examples/host-config.yaml`) is untouched this revision.

### Check log

- PASS — All 46 checks (identical list to revision 12; output elided for brevity).

## Revision 12 (2026-09-02) — M1a close-out wave B ruling: AT-005 partial, SDD evidence carried into PLAN.md, two comments corrected

Run after the ruling on the wave B fix report, prose and comments only. `docs/ACCEPTANCE.md`: AT-005 is now `TESTED_PASS (partial — …)`, naming the five windows the injection suite does not cover (a failure between a stage's side effect and the manifest write that records it, where the rollback reads a manifest that does not yet name the stage), and its Test line points at PLAN.md's Task 13 entry instead of the untracked SDD ledger. `PLAN.md`: the three citations into `.superpowers/sdd/` (poweroff probes 1 and 2, the Docker-residue evidence, gate run 6) are replaced by the facts they pointed at, because that workspace is deleted at close-out; a rollback-escape deviation entry and a gate-limitation note (no runner log for a VM its subtest deletes itself) are recorded; the Task 13 entry carries the `11864b9` 6/6 run and the `-race -count=5` run. Two false comments were corrected in place with line counts unchanged, so the committed citations hold: `internal/jailer/launch.go:126` and `tests/integration/m1a_gate_test.go:1653-1655`.

### Results

- 46 package checks passed (`uv run docs/validation/check.py`, exit 0).
- All revision-11 results hold; no acceptance ID was added, removed, or renumbered, and the only parsed example check.py inspects (`docs/examples/host-config.yaml`) is untouched this revision.

### Check log

- PASS — All 46 checks (identical list to revision 11; output elided for brevity).

## Revision 11 (2026-09-02) — M1a close-out wave B: acceptance qualifiers, allocator limitation, run history, revision-10 corrections

Run after the close-out wave B fix round, prose only. `docs/ACCEPTANCE.md`: the M1a block header now records the runtime-lock digests the gate ran under; AT-001 says its "before any side effect" is by construction, not asserted; AT-005's label names the fake VMM and the real privd/runner/guest.Agent code around it, its citation names the 6/6 run at `11864b9` and the `-race -count=5` run after `e6172f8`, and its recovery-launch sentence says what the launch proves (state dir, manifest, slot gone) and what it does not (the /30 prefix is never returned; compute-reservation release rests on a SPEC §18 fake-runtime test); AT-006, AT-009, AT-011 and AT-018 gain qualifiers for what their subtests do not assert (operation identity and timeout; distinctness; `guest.channel_lost`; reservation counts, the in-run baseline, privd's ledger, cgroups). `PLAN.md`: a deviations-log entry for the prefix allocator that never reclaims (32,768 /30s per daemon lifetime, reset only by restart); the gate-run history now reads nine runs (six blocked, an excluded diagnostic pass, runs A and B) and the bug list is a narrative rather than a count; three citations corrected (SPEC §4.2, a ten-line block, `supervisionLoop`); a session-log line for the shutdown-budget fix `54d571b` and its sole evidence. `gotchas.md`: the allocator entry. This file: four sentences in revision 10 were inaccurate and are corrected in place, because they describe the same run and leaving them would keep a false record standing — it said `docs/examples/host-config.yaml` is not an example check.py parses (it is, `check.py:110`), that check.py's checks cover `PLAN.md` (check.py never reads it), that every acceptance note quotes an evidence line (AT-005's does not), and it counted seven bugs. Not in this revision: the AT-005 status qualifier for the rollback-escape gap, because reading the suite found the gap larger than the ruling described, so it stopped for a decision. None of these changes touch check.py logic or a schema; no example the checks parse changed.

### Results

- 46 package checks passed (`uv run docs/validation/check.py`, exit 0).
- All revision-10 results hold; no acceptance ID was added, removed, or renumbered, and the only parsed example check.py inspects (`docs/examples/host-config.yaml`) is untouched this revision.

### Check log

- PASS — All 46 checks (identical list to revision 10; output elided for brevity).

## Revision 10 (2026-09-02) — M1a close-out: runtime path fix, live-gate acceptance notes, deviations and session log

Run after the M1a close-out landed three changes. `docs/examples/host-config.yaml` moved the example `paths.runtime` from `/run/vmobs` (a tmpfs) to `/srv/vmobs`, matching what the privd unit, `setup.sh`, and the live gate actually use, with a comment explaining that the daemon derives its staging dir and jailer chroot base from that one root; `privileged_socket` stays on `/run/vmobs` because it is a socket whose parent the unit's `RuntimeDirectory` creates. `docs/runbooks/aibox03.md` gained one paragraph in its privd section stating the `paths.runtime`/`--stage-root`/`--jail-base` coupling explicitly, so an operator editing either side sees what the other has to match (commit `86dade1`). `docs/ACCEPTANCE.md` gained a second dated status block (`L1 M1a status notes`) recording AT-001, AT-005, AT-006, AT-007, AT-009, AT-011 and AT-018 against the two consecutive real-Firecracker gate runs on aibox03, each note quoting the run's own evidence line where the gate produced one (AT-005's cites a separate suite and quotes none) and naming what the row still leaves uncovered (revision 11 corrected six of those qualifiers as incomplete). `PLAN.md` gained M1a deviation-log entries (six deferred-to-M1b items, five recorded-not-fixed deviations, two not-done-in-M1a follow-ups, and the graceful-stop-path root-cause account) and a session-log entry covering the gate run history and the real product bugs the live gate found that the unit suite had missed (this revision said "seven"; revision 11 dropped the number — the list is a narrative, not a count). None of these changes touch check.py logic or a schema; `docs/examples/host-config.yaml` is an example check.py does parse (`check.py:110`), and its edit is a path value and a comment, which is why the run below still passes.

### Results

- 46 package checks passed (`uv run docs/validation/check.py`, exit 0).
- All revision-9 results hold; the changed files carry no schema or example content check.py inspects — `docs/examples/host-config.yaml`'s edit is a path value and a comment, and `docs/ACCEPTANCE.md` is prose the acceptance-ID and requirement-coverage checks already covered before this revision (ID uniqueness and sequencing are unchanged; no acceptance ID was added, removed, or renumbered); check.py does not read `PLAN.md` at all.

### Check log

- PASS — All 46 checks (identical list to revision 9; output elided for brevity).

## Revision 9 (2026-09-01) — L0 close-out: runbook, guest-protocol, schemas, images README, integration README

Run after L0 Tasks 1–8 landed the following docs files: `docs/runbooks/aibox03.md` (host facts, setup.sh walkthrough, root-helper verbs, Firecracker re-pin), `docs/guest-protocol.md` (wire framing, handshake, deadlines), `docs/schemas/guest-hello.schema.json`, `docs/schemas/guest-capability.schema.json`, `images/README.md` (kernel config fragment rationale, symbol exclusions, rootfs pipeline, artifact reproducibility notes), `tests/integration/README.md` (how to run the M0 gate, env vars, evidence location). None of these files add new check.py logic; all 46 existing checks continue to pass.

### Results

- 46 package checks passed (`uv run docs/validation/check.py`, exit 0).
- All revision-8 results hold; only the docs files listed above were added.

### Check log

- PASS — All 46 checks (identical list to revision 8; output elided for brevity).

## Revision 8 (2026-09-01) — L0 Task 2: add guest-protocol.md and two schemas

Run after adding `docs/guest-protocol.md` (wire framing, handshake sequence, deadlines), `docs/schemas/guest-hello.schema.json`, and `docs/schemas/guest-capability.schema.json`. The new doc and schemas add no new check.py logic; all 46 existing checks continue to pass and the new schemas are Draft 2020-12 compliant.

### Results

- 46 package checks passed (`uv run docs/validation/check.py`, exit 0).
- All revision-7 results hold; only the three new docs files were added.

### Check log

- PASS — All 46 checks (identical list to revision 7; output elided for brevity).

## Revision 7 (2026-09-01) — L0 Task 1: add docs/runbooks/aibox03.md

Run after adding `docs/runbooks/aibox03.md` (aibox03 host runbook: host facts, setup.sh walkthrough, root-helper verbs, Firecracker re-pin procedure). The runbook is prose only; no schema, example, or check.py logic changed.

### Results

- 46 package checks passed (`uv run docs/validation/check.py`, exit 0).
- All revision-6 results hold; only `docs/runbooks/aibox03.md` was added.

### Check log

- PASS — All 46 checks (identical list to revision 6; output elided for brevity).

## Revision 6 (2026-09-01) — update require_authentication comment in example config

Run after rewording the `require_authentication` comment in `docs/examples/host-config.yaml` from a forward reference to a past-tense statement of truth (P5 Task 13 closed; smoke runs with auth on; the example shows the dev default).

### Results

- 46 package checks passed (`uv run docs/validation/check.py`, exit 0).
- All revision-5 results hold; only the comment text in `docs/examples/host-config.yaml` changed (value `false` preserved for the dev-default example).

### Check log

- PASS — All 46 checks (identical list to revision 5; output elided for brevity).

These checks validate the handoff documents and synthetic interface examples. **They are not tests of a running Firecracker Observatory implementation.** No VMM, guest sensor, proxy, terminal, isolation, crash-recovery or performance acceptance test was executed as part of preparing this package.

The canonical check is `validation/check.py`, run as `uv run docs/validation/check.py`. Re-run it after changing any file in `docs/` and append a dated revision below. Earlier revisions are the historical record; never rewrite them.

## Revision 5 (2026-09-01) — auth and https-mode fields in example config

Run after adding `session_ttl_minutes: 720`, `tls_cert_file: ""`, and `tls_key_file: ""` to `docs/examples/host-config.yaml` to match the new struct fields introduced by the P5 auth validation matrix.

### Results

- 46 package checks passed (`uv run docs/validation/check.py`, exit 0).
- All revision-4 results hold; only `docs/examples/host-config.yaml` changed.

### Check log

- PASS — All 46 checks (identical list to revision 4; output elided for brevity).

These checks validate the handoff documents and synthetic interface examples. **They are not tests of a running Firecracker Observatory implementation.** No VMM, guest sensor, proxy, terminal, isolation, crash-recovery or performance acceptance test was executed as part of preparing this package.

The canonical check is `validation/check.py`, run as `uv run docs/validation/check.py`. Re-run it after changing any file in `docs/` and append a dated revision below. Earlier revisions are the historical record; never rewrite them.

## Revision 4 (2026-08-31) — fix reproduce_query params in run-report example

Run after rewriting all `reproduce_query` fields and the `links.events` URL in `docs/examples/run-report.json` to match what `internal/report/generate.go` actually emits. The old example used `kind_prefix=` and `run_id=` params that the `/api/v1/events` endpoint does not accept — silently ignored → 0 results (P-05 hazard). The new URLs use `vm_id=`, `family=`, `after=`, and `until=` only, matching the generator's `fmt.Sprintf` patterns exactly.

### Results

- 46 package checks passed (`uv run docs/validation/check.py`, exit 0).
- Run-report example continues to satisfy the run-report schema.
- All revision-3 results hold; only `docs/examples/run-report.json` changed.

### Check log

- PASS — All 46 checks (identical list to revision 3; output elided for brevity).

## Revision 3 (2026-08-31) — relax boot_ids to allow empty array

Run after relaxing `boot_ids` `minItems` from 1 to 0 in `run-report.schema.json`. Rationale (R5): a run whose VM fails before boot has zero boot identities in durable records; AT-094 requires a report in every terminal phase; inventing a boot ID would be fabricated evidence.

### Results

- 46 package checks passed (`uv run docs/validation/check.py`, exit 0).
- All three JSON schemas passed Draft 2020-12 metaschema validation.
- The run-report positive example (which already includes boot_ids) continues to validate; no negative boundary cases were removed.
- All other revision-2 results hold; only `run-report.schema.json` changed.

### Check log

- PASS — event-envelope schema validates against Draft 2020-12
- PASS — launch-request schema validates against Draft 2020-12
- PASS — run-report schema validates against Draft 2020-12
- PASS — Synthetic event satisfies envelope schema
- PASS — Synthetic launch satisfies launch schema
- PASS — Launch-with-run example satisfies launch schema
- PASS — Run-report example satisfies run-report schema
- PASS — Reject numeric 64-bit counter in envelope
- PASS — Reject unknown provenance enum
- PASS — Reject HTTP header capture in transport mode
- PASS — Reject strict telemetry with degrade-only action
- PASS — Reject exec_exit_zero criteria without initial_exec
- PASS — Reject unknown run completion policy
- PASS — Reject oversized run goal
- PASS — Reject empty run goal
- PASS — Launch with null run block remains valid
- PASS — Reject rollup count without reproduce_query
- PASS — Reject outcome without evidence links
- PASS — Reject unknown attention severity
- PASS — Reject unknown run outcome status
- PASS — YAML host configuration parses as a mapping
- PASS — YAML body-capture off remains a string
- PASS — Spool limit matches 512 MiB prose target
- PASS — Frame cap matches 256 KiB prose target
- PASS — Terminal replay cap matches 4 MiB prose target
- PASS — Config run goal cap matches launch schema bound
- PASS — Config report tail cap matches report schema bound
- PASS — Attention trigger classes enumerate as booleans
- PASS — Acceptance test IDs are unique
- PASS — Exactly 102 unique sequential acceptance IDs
- PASS — SPEC defines exactly R-01 through R-17
- PASS — Acceptance matrix covers all 17 requirements
- PASS — SPEC defines exactly P-01 through P-08
- PASS — Every referenced principle ID is defined
- PASS — Exactly 22 unique sequential source-verification IDs
- PASS — Every inline source reference is defined
- PASS — Exactly 17 primary source definitions
- PASS — Markdown fenced code blocks balance in SPEC.md
- PASS — Markdown fenced code blocks balance in ACCEPTANCE.md
- PASS — Markdown fenced code blocks balance in README.md
- PASS — Markdown fenced code blocks balance in VALIDATION.md
- PASS — All 4 embedded JSON examples in SPEC parse
- PASS — Embedded event example satisfies envelope schema
- PASS — Prose test counts state 102
- PASS — No stale 88-test count remains
- PASS — Every file listed in README exists

## Revision 2 (2026-08-31) — agent-interface revision

Run after adding the agent-operations layer: principles P-01..P-08, requirements R-15..R-17, acceptance tests AT-089..AT-102, the run block in the launch schema, the run-report schema, two new examples and the `agent_interface` host-config block. The check script itself is new in this revision; it re-implements and extends the revision-1 checks.

### Results

- 46 package checks passed (`uv run docs/validation/check.py`, exit 0).
- All three JSON schemas passed Draft 2020-12 metaschema validation.
- Four positive examples validated; 13 invalid boundary examples were rejected as required, including the new run-block and run-report rules (exec_exit_zero without initial_exec, unknown completion policy, oversized/empty goal, rollup count without `reproduce_query`, outcome without evidence links, unknown severity and status enums).
- YAML parsed; the `agent_interface` caps match the schema bounds they mirror (`run_goal_max_bytes` = goal maxLength, `report_tail_max_bytes` = tail maxLength) and all 8 attention trigger classes enumerate as booleans.
- 102 unique sequential acceptance test IDs cover all 17 product requirements.
- P-01 through P-08 are defined once in SPEC §1.4 and every principle reference in SPEC and ACCEPTANCE resolves.
- 22 verification-ledger entries refer to the 17 primary source definitions.
- All 4 embedded JSON examples in SPEC parse; the embedded event still satisfies the envelope schema.
- No stale revision-1 counts (88 tests, 14 requirements) remain in prose.

### Check log

- PASS — event-envelope schema validates against Draft 2020-12
- PASS — launch-request schema validates against Draft 2020-12
- PASS — run-report schema validates against Draft 2020-12
- PASS — Synthetic event satisfies envelope schema
- PASS — Synthetic launch satisfies launch schema
- PASS — Launch-with-run example satisfies launch schema
- PASS — Run-report example satisfies run-report schema
- PASS — Reject numeric 64-bit counter in envelope
- PASS — Reject unknown provenance enum
- PASS — Reject HTTP header capture in transport mode
- PASS — Reject strict telemetry with degrade-only action
- PASS — Reject exec_exit_zero criteria without initial_exec
- PASS — Reject unknown run completion policy
- PASS — Reject oversized run goal
- PASS — Reject empty run goal
- PASS — Launch with null run block remains valid
- PASS — Reject rollup count without reproduce_query
- PASS — Reject outcome without evidence links
- PASS — Reject unknown attention severity
- PASS — Reject unknown run outcome status
- PASS — YAML host configuration parses as a mapping
- PASS — YAML body-capture off remains a string
- PASS — Spool limit matches 512 MiB prose target
- PASS — Frame cap matches 256 KiB prose target
- PASS — Terminal replay cap matches 4 MiB prose target
- PASS — Config run goal cap matches launch schema bound
- PASS — Config report tail cap matches report schema bound
- PASS — Attention trigger classes enumerate as booleans
- PASS — Acceptance test IDs are unique
- PASS — Exactly 102 unique sequential acceptance IDs
- PASS — SPEC defines exactly R-01 through R-17
- PASS — Acceptance matrix covers all 17 requirements
- PASS — SPEC defines exactly P-01 through P-08
- PASS — Every referenced principle ID is defined
- PASS — Exactly 22 unique sequential source-verification IDs
- PASS — Every inline source reference is defined
- PASS — Exactly 17 primary source definitions
- PASS — Markdown fenced code blocks balance in SPEC.md
- PASS — Markdown fenced code blocks balance in ACCEPTANCE.md
- PASS — Markdown fenced code blocks balance in README.md
- PASS — Markdown fenced code blocks balance in VALIDATION.md
- PASS — All 4 embedded JSON examples in SPEC parse
- PASS — Embedded event example satisfies envelope schema
- PASS — Prose test counts state 102
- PASS — No stale 88-test count remains
- PASS — Every file listed in README exists

### Not re-executed from revision 1

Revision 1 ran several boundary cases the current script does not repeat (invalid VM UUID, undeclared envelope property, boot-scoped event without VM scope, string boolean in quality, unbounded RAM, zero vCPU, undeclared host command, unpinned template, empty initial executable, filename-encoding match, resource-default match, status-labeling greps). The schemas those cases exercised are unchanged in this revision except for the additive `run` property; their revision-1 results stand as recorded below.

## Revision 1 (2026-08-30) — initial package

### Results

- 39 package checks passed.
- Both JSON schemas passed Draft 2020-12 metaschema validation.
- Positive examples and 13 invalid boundary examples behaved as expected under the schemas.
- YAML parsed; units/defaults checked for consistency.
- 88 unique sequential acceptance test IDs cover all 14 product requirements.
- 22 verification-ledger entries refer to the 17 primary source definitions.
- Embedded JSON examples parsed; the embedded event matched its schema.

### Check log

- PASS — event-envelope schema validates against Draft 2020-12
- PASS — launch-request schema validates against Draft 2020-12
- PASS — Synthetic event satisfies schema
- PASS — Synthetic launch satisfies schema
- PASS — Encoded example filename matches display bytes
- PASS — offline metadata-only launch is valid
- PASS — transport metadata-only launch is valid
- PASS — Strict telemetry with pause is valid
- PASS — Host-wide pre-index envelope is valid
- PASS — Reject numeric 64-bit counter
- PASS — Reject invalid VM UUID
- PASS — Reject unknown provenance enum
- PASS — Reject undeclared envelope property
- PASS — Reject boot-scoped event without VM scope
- PASS — Reject string boolean in quality
- PASS — Reject unbounded launch RAM
- PASS — Reject zero vCPU
- PASS — Reject undeclared launch host command
- PASS — Reject HTTP header capture in transport mode
- PASS — Reject strict telemetry with degrade-only action
- PASS — Reject unpinned template syntax
- PASS — Reject empty initial executable
- PASS — YAML host configuration parses as a mapping
- PASS — YAML body-capture off remains a string
- PASS — Launch resource examples match host defaults
- PASS — Spool limit matches 512 MiB prose target
- PASS — Frame cap matches 256 KiB prose target
- PASS — Terminal replay cap matches 4 MiB prose target
- PASS — Exactly 88 unique sequential acceptance IDs
- PASS — Acceptance matrix covers all 14 requirements
- PASS — Exactly 22 unique sequential source-verification IDs
- PASS — Every inline source reference is defined
- PASS — Exactly 17 primary source definitions
- PASS — Markdown fenced code blocks balance
- PASS — Embedded JSON example 1 parses
- PASS — Embedded JSON example 2 parses
- PASS — Embedded event example 2 satisfies envelope
- PASS — Specification labels unimplemented status
- PASS — Acceptance suite labels all rows not run

## Explicitly not established

Runtime correctness, safety against attacks, TLS-client compatibility, actual resource overhead, supported concurrent-VM count, terminal latency, event throughput, durable recovery and final-diff accuracy all require implementation and the real acceptance evidence described in `ACCEPTANCE.md`. The source verification ledger establishes external design premises only. The agent-interface additions raise the bar further: interaction-budget compliance (AT-102), situation/attention correctness (AT-089..091) and run-report truthfulness (AT-092..095) are all implementation claims that only the acceptance suite can establish.

## Revision — 2026-09-07, Compose policy loader

Updated the installation and gate guidance to use the short-lived Compose
AppArmor loader, with no host installer. `uv run docs/validation/check.py`
returned **47/47 package checks passed** (exit 0). This validates the docs
package; the real Compose and VM measurements are recorded in
`docs/design/container-boundary.md` §11 and `PLAN.md`.

## Revision — 2026-09-07, published Compose verification

Recorded the merged revision, successful image publication and the real Compose
test against the registry image. `uv run docs/validation/check.py` returned
**47/47 package checks passed** (exit 0). No implementation or acceptance verdict
was changed by this documentation update.

## Revision — 2026-09-07, archive the P4 plan

Added the previously untracked P4 implementation plan with a historical-status
note pointing to `PLAN.md` and `gotchas.md`. The original plan text remains
unchanged. `uv run docs/validation/check.py` passed **47/47** (exit 0).

## Revision — 2026-09-07, privileged restart recovery

Updated the deployment boundary and recovery design for persistent privileged
ownership and host PID identity. Recorded the real Compose restart/delete/reuse
result and its limits, including the separate `n0vw` disk-capacity issue.
`uv run docs/validation/check.py` passed **47/47** (exit 0).

## Revision — 2026-09-08, kata implementation progress

Added credential lifetime/durability, HTTP budgets, importer health, network
lease and live disk-capacity design notes, plus the active kata execution plan.
`uv run docs/validation/check.py` passed **47/47** (exit 0). The plan records
dirty-candidate Docker/KVM results and remaining review work; this package check
does not close any kata or establish final release acceptance.

## Revision — 2026-09-08, agent and recovery contracts

Documented the executable agent slice and deferred controls, stopped cleanup debt,
queryable privileged mutations, bounded shutdown, and separate-filesystem disk
accounting. `uv run docs/validation/check.py` passed **47/47** (exit 0). Runtime
acceptance and unresolved reviews remain recorded in the kata completion plan;
this is documentation-package validation only.
