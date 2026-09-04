# Specification Package Validation

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
session. AT-029's browser half is asserted by `web/src/Terminal.test.tsx`, not by the Go gate, and
the entry says so. The gate found two product defects on its way to green, both fixed before the
evidence was recorded and both named in the block: a terminal event stream bound API-wide when
`internal/store/append.go` scopes a source stream to one VM, so every VM after the first lost its
session events (`114a03e`); and a `vm.vmm_exited` that crossed the spool boot-blind, letting one
boot's exit notice fail the boot after it (`320cfe1`). No requirement was weakened to pass a test.

### Results

- 46 package checks passed (`uv run docs/validation/check.py`, exit 0).
- All revision-14 results hold. The edit adds 179 lines to `docs/ACCEPTANCE.md`, all of them inside
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
