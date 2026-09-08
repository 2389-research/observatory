# Kata completion implementation plan

> **For agentic workers:** Use subagent-driven-development for independent units. Root coordinates shared files, reviews, canonical checks and real Docker acceptance.

**Goal:** Complete every remaining Observatory kata with implementation and evidence matching its acceptance criteria.

**Architecture:** Keep SQLite as the control authority and the root-owned privd ledger as privileged ownership authority. Extend existing lifecycle, auth, HTTP, importer and allocator components; do not add alternate deployment paths or fake served modes.

**Tech stack:** Go, SQLite, Docker Compose, Firecracker, existing TypeScript UI.

## Global constraints

- Doctor Biz delegated design decisions and directed execution without further discussion.
- Deployment stays entirely Docker Compose; no host install scripts.
- TDD at real owned seams, independent review, `scripts/check`, Linux tests and real VM coverage where relevant.
- Unknown host effects retain ownership and reservations until resolved. Failure must never imply proven absence.
- Do not close a kata from a passing narrow test when its acceptance scope is broader.
- Work on `kata-hardening`; no day-to-day worktrees. Commit verified units, publish through PRs, and keep this plan current.

## Acceptance authority

The live Kata bodies and comments supply each unit's complete acceptance criteria. Initial inventory on 2026-09-08: ten open, no P0. Snapshot was read through `kata --json list --status open`; closure requires re-reading the individual issue and attaching commit/test evidence.

## Batch 1: independent safety fixes

- [ ] **8bdk / ryvx — credential lifetime and durability.** `internal/auth`, `internal/api/auth.go`, `cmd/vmobs/auth.go`. One checked maximum; omitted/zero remains permanent, negatives/overflow refuse without minting. Reuse durable file/directory publication; ambiguous revocation retries must confirm durability. Verify real HTTP/CLI/files, reopen, permissions and process-crash behavior; do not claim power-loss testing.
- [ ] **bxm8 — bounded HTTP.** `cmd/vmobs/main.go`, `cmd/vmobsd/main.go`, `internal/api/terminal_stream.go`. Finite configurable CLI timeout, context-bound requests, bounded responses, retained transport defaults, server body/idle/header bounds and explicit terminal heartbeat. Verify real HTTP/TLS slow peers and WebSocket sessions.
- [ ] **exf0 — importer health.** `internal/spool`, `internal/situation`, importer status API. Isolate failing VMs, retain bounded diagnostics/counts/success time, coalesce attention and retry with backoff while healthy VMs progress. Verify actual SQLite, segment/cursor faults, recovery and public status. Root wires the importer into the engine in daemon main after HTTP changes land.

Each implementer owns its named files, reports red/green evidence and leaves commits/closure to root after review. Global docs and daemon main wiring are coordinated to avoid concurrent edits.

## Batch 2: owned resources and capacity

- [ ] **00e7 — network lease restoration/release.** `internal/network/alloc.go`, `internal/jailer/launch.go`, `internal/jailer/stop.go`, `cmd/vmobsd/runtime_linux.go`. Allocate by VM owner, restore from existing authoritative resources, preserve host-route exclusions and privileged collision checks. Return prefixes only after proven durable teardown. Verify small-pool exhaustion/reuse, failed launch/cleanup, restart with survivors and real Linux networking.
- [ ] **n0vw — disk admission after restart/reclamation.** `internal/runtime/admission.go`, manager capacity/admission wiring and reservation queries. Refresh real filesystem availability and distinguish already materialized allocation from outstanding reservations conservatively. Do not subtract allocated disk twice or weaken inspection scratch reserves. Verify concurrent creates, surviving allocations, failed observation, and low-headroom real restart/delete/successor admission.

## Batch 3: bounded lifecycle and uncertain effects

- [ ] **bm7v / 3dnv — recoverable mutations and shutdown.** `internal/privd/client.go`, `server.go`, `proto.go`, `vmops.go`, `internal/jailer`, `internal/runtime/manager.go`, `batch.go`. First make lost mutation replies distinguishable from failure through queryable identity/outcome or verified host recovery. Preserve atomic UID/CID/subnet claims. Then bound initial/batch launches and shutdown cancellation/drain, retaining independent finalization contexts and preventing workers from accessing closed storage. Verify real socket disconnect/lost reply/duplicate/restart, late effects, queued cancellation and real KVM fault coverage.
- [ ] **apwk — stalled cleanup retries.** Add a bounded retry pass for unowned stalled work using fresh host observations and per-VM claims. Do not call startup Reconcile from a ticker. Preserve active operations, reservations and manual retry; test transient failures, competing lifecycle work, stale observations and shutdown against real components and real Linux cleanup.

## Batch 4: agent control contract

- [ ] **3tn6 — bounded agent vertical slice.** Audit the existing gap map against current code and pinned v1 reference `d432cdced2a346974bf3ca1afa20b56c96c890be`. Preserve v2 routes, boot/revision authority and exact approval/budget semantics. Complete the smallest discoverable executable slice with typed recovery, safe retries and cursor resume; label remaining proposed mechanisms truthfully and record precise follow-up scope rather than importing the v1 roadmap. Verify docs and cold-agent scenarios against actual routes.

## Completion audit

- [ ] Review every issue's numbered acceptance requirements against current code and direct evidence.
- [ ] Run final canonical and Linux suites, relevant real Docker/KVM and terminal flows, and docs validation.
- [ ] Commit, PR, publish and deploy verified changes; preserve known limits honestly.
- [ ] Re-read live Kata inventory. Every remaining issue must be actually completed; new defects discovered in scope cannot disappear into a status summary.
- [ ] Mark the thread goal complete only after the full backlog and completion audit pass.

## Session state

2026-09-08: previous work merged/deployed at `056bcf6`; worktree was clean. Batch 1 delegated with disjoint ownership. Root owns plan, integration, resource work and verification. Goal turn classification: progress (live inventory verified and implementation underway). Compactions in this goal session: 0.

2026-09-08 continuation: all ten kata remain open. Batch 1 and 2 implementations
exist in the working tree; review and final acceptance remain required. The
canonical check passed before review fixes. Linux component tests exposed stale
rollback call expectations and a fixture that acknowledged release without
removing its test chroot; the fixture and expectations now exercise the stricter
release proof. Review found and reproduced directory-publication retry failure,
privd-only subnet omission, and unsettled manifest deletion barriers. Auth retry
and TTL remediation fixes passed their focused tests; resource fixes are underway.

Real Docker/KVM candidate gate passed both new scenarios on 2026-09-08:
`TestKataImportAndTerminalGate` (61.79s), with actual spool permission failure,
retry/recovery and a terminal usable after 45s; and
`TestKataRestartDiskAndNetworkGate` (13.76s), with controller restart while a VM
survives, then deletion and equal-size successor admission without another
restart, reusing the same subnet. Measured restart free=28741 MiB,
scratch=27307 MiB, requested=4160 MiB. These are dirty-candidate results, not
final commit acceptance. Logs and review reports live in `.superpowers/sdd/`.

Active ownership: `privd_outcomes` owns mutation receipts and jailer uncertain
start handling; `resources_review` owns resource review fixes;
`bounded_lifecycle` owns manager/batch shutdown and launch budgets. Root owns
integration tests, final review/gates, documentation and commits. Safety fixes
are ready for root review. Batch 3 automatic cleanup retries and Batch 4 remain
to implement. No published or deployed change is claimed. The interrupted SSH
approval did not run; Linux verification resumed after sandbox restrictions
were removed. Current goal turn classification: progress.

2026-09-08 continuation, compaction count 1: root disk observer now supports
separate configured filesystems using minimum free-plus-own-device-credit;
separate-filesystem regressions passed. Independent lifecycle review found and
fixed startup ambiguous findings incorrectly releasing compute and attempted
launch rollback trusting guest-owned dead PID files. Regression evidence uses
real SQLite and real Linux child/zombie processes. Review fixes await combined
canonical and Linux verification. Real KVM active/queued shutdown scenario
passed (6.14s total test), with terminal operations/runs, retained reservations
for possible live effects, and restart cleanup. Cold-agent scenario reached
real launch/conclusion but report remained pending; diagnosis active. Automatic
cleanup and low-headroom disk gate running. Cleanup adds durable stopped debt
so periodic retries preserve restart disks without sweeping every stopped VM.
All kata still open, no commit/deploy claimed. Active owners: cleanup_retry
(runtime/store), agent_contract (API/docs/agent scenario), review_lifecycle
(privd/daemon fixes and independent disk review); root integration and gates.

Candidate final review: all ten implementations now exist. The daemon now wires
real report generation before startup repair; the real serve regression catches
missing wiring. A detached privileged mutation can outlive the jailer caller,
so disk materialization credit now requires a settled privileged inventory within
100ms as well as the lifecycle lock. Missing, busy or unknown authority receives
zero credit. Real Linux late-start and late-release regressions passed. Full
canonical `scripts/check` passed on the combined candidate; full Linux package
suite passed and the six `TestKata` Docker/KVM scenarios are running. The agent
scenario now passes discovery, exact replay, linked operation, operator verdict,
digest report, revision stop and nine resumed event pages. No issue closed yet.

## Verified candidate — 2026-09-08

Canonical `env -u GOROOT mise exec -- ./scripts/check`: all gates passed,
including both platform linters, complete Go suite, web typecheck/tests/build,
and documentation validation. `VMOBS_LINUX_HOST=aibox03 scripts/linux
'go test ./... -count=1'`: full Linux suite passed. Focused race checks passed
for auth/durable, runtime/store, daemon handoff, API/report and disk observation.
Documentation package: 47/47. Independent safety, resource, lifecycle, cleanup
and agent-contract reviews have no unresolved blocker after fixes.

All six real Docker/KVM scenarios passed together in 172.986s:

| Scenario | Result and direct observation |
|---|---|
| Agent contract | 7.80s; discovered routes/request, exact launch replay, linked operation and run verdict/report digest, revision recovery and 9 resumed event pages. |
| Automatic cleanup | 71.17s; real helper socket outage retained compute and network across a retry; restoring transport let the timer delete without restart. |
| Import and terminal | 61.56s; real spool permission failure retried and recovered; terminal still usable after 45s idle. |
| Restart disk/network | 14.11s; surviving VM preserved reservation totals, deletion returned totals to baseline, equal successor restored the same charge and subnet without another restart. Free28512 MiB, scratch27079 MiB, request4160 MiB. |
| Lost start reply | 11.93s; real successful start reply dropped, durable outcome queried, cleanup proved, exact replay caused no new launch and successor ran. |
| Active/queued shutdown | 6.37s total; daemon exited in41ms after an actual start with its reply held, operations/runs settled, possible live effects retained reservations, restart cleanup succeeded. |

Separate root Linux network lifecycle test passed actual namespace/interface
creation, canceled teardown retention and final proven release. Real Linux
start/release socket regressions additionally prove detached host work grants
no disk materialization credit; attempted-start zombie PID substitution retains
unknown ownership. These candidate checks used the Docker deployment boundary
and actual Firecracker guests, not a served fake runtime.

Known limits: indefinite mutation receipt retention preserves exact replay;
unknown host identity still needs operator resolution; contexts cannot interrupt
every kernel filesystem call. Disk accounting conservatively retains debt when
privd is busy/unavailable and includes existing stage allocations in measured free
space, but does not add a new reservation for future staging overhead. This
change is not a filesystem quota. Process-crash tests do not prove power-loss
behavior. No blocker remains for this kata scope; review before claiming broader
quota guarantees or adding receipt pruning.

Next: commit and PR, publish the exact merge SHA, back up idle deployment volumes,
deploy through the existing Compose checkout, verify actual container stop and
restart, then attach evidence and close the ten live kata. Compaction count1.
