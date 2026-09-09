# VM introspection implementation plan

> For agentic workers: use subagent-driven-development with clean task contexts, TDD and independent review. The live Kata bodies are the full acceptance contracts.

**Goal:** Complete epic `s8e2`: real file and network evidence in the deployed VM workspace, including final diffs and opt-in request inspection.

**Architecture:** Follow `docs/SPEC.md` §§9–13 and M2–M4. Guest fanotify/process sensors feed the existing bounded telemetry ring, runner spool and SQLite event index. Host namespace collectors supply host-owned network evidence. Coverage, API queries, reports and browser views share that authority. Final persisted disks are inspected in an isolated trusted microVM. HTTP inspection uses the spec's explicit per-VM proxy profile.

**Stack:** Existing Go daemon/guest/runner, Linux fanotify/network facilities, React/TypeScript, Docker/KVM, pinned guest images and the specified mitmdump addon.

## Constraints

- Preserve VM/boot identity, owner checks, durable event identity, bounded queues, declared loss and the existing privilege boundary.
- The user approved the epic and its existing specification. Do not ask again for those decisions; discuss any necessary architecture/security departure before implementing it.
- One shared checkout on `vm-introspection-s8e2`; no worktrees. Root owns integration, commits, image pins, deployment, plan and shared event registry. Agents own explicit disjoint paths and report required integration edits.
- Leave `Fleet and VM improvements.zip` untouched. Preserve live user VMs during testing; use disposable gate fixtures. Deployment interruptions require the already-established user-VM check.
- Write failing tests before implementation. Unit plus real-component integration plus real Linux/KVM/browser evidence are required for each acceptance scope. `scripts/check` is canonical; `scripts/vmobs-gate` is the Linux gate. Do not claim collector completeness from heartbeat-only tests.
- Keep notification, actual content comparison, transport flow and HTTP request semantics distinct. Missing data and uncertain attribution stay explicit.
- Do not close a child until its full live Kata contract is satisfied, reviewed and supported by evidence. The final gate requires the published image, not only source tests.

## Work units and ownership

- [ ] `nwcg`: truthful coverage. Add `internal/situation/coverage.go` and API handler/tests; wire `/vms/{id}/coverage`. Extend sensor health only where needed. Show transport separately from filesystem/network coverage in fleet/detail. Agent owns situation/API coverage and shared sensor health contract; root owns final browser integration.
- [ ] `689x`: guest filesystem sensor. New `internal/guest/fswatch` package, real Linux filesystem scenarios and guestd startup wiring. Consume existing `telemetry.Reporter` ring and sensor registry. Sensor ID `filesystem`; preserve event payload quality and supported scope. Root registers emitted event kinds and repins/delivers guest images.
- [ ] `kygy`: host flows. Audit current namespace/policy paths, implement bounded collector lifecycle, real tuple/counter observations and host-owned source identity. Coordinate privileged integration with root before edits outside the collector package.
- [ ] `1m87`: managed DNS and denials. Root first audits actual gateway/enforcement wiring and implements the spec's managed boundary, then integrates durable DNS/denial observations and failure/pressure coverage. Share namespace identity with the flow collector.
- [ ] `hy1s`: process/socket attribution. Capability-tested guest process evidence and exact/unknown correlations; initial file/network delivery remains useful without attribution.
- [ ] `tsrb`: live timeline and Filesystem Activity. Consume persisted event query/cursor and coverage APIs; complete live delivery contract. Bounded rendering, safe strings, reconnect and usable adjacent terminal.
- [ ] `9g0p`: Network workspace. Separate Flows, DNS, Denials and Requests; consume actual collectors and explain transport-only/disabled inspection accurately.
- [ ] `d18y`: baseline/final manifests, isolated disk inspector, immutable bounded artifacts and Filesystem Final Diff. Preserve originals, consistency and incomplete-result labels.
- [ ] `n634`: explicit opt-in HTTP inspection. Per-VM pinned proxy/addon and CA, bounded redacted capture, upstream TLS verification and fail-closed egress. Do not silently enable for existing transport VMs.
- [ ] `6wf7`: complete Docker/KVM/browser acceptance and published deployment. Two VM isolation, file/flow/DNS/denial/request/diff evidence, loss and recovery, measured overhead, cleanup and exact source/image/guest digests.

## Execution cycle

For each unit, read its live Kata body; write the named failing unit/integration scenario; run and record the failure; implement the smallest complete production path; run focused green checks; exercise real Linux/KVM behavior; obtain independent review; fix findings; run canonical checks; commit only verified named files. Root coordinates shared-file changes and updates this ledger with evidence. UI and publication gates follow the actual dependency graph in Kata.

## Completion audit

Read every numbered acceptance requirement back from Kata and match it to source, test commands/results and real deployed evidence. Check all registered routes are implemented, image pins include enabled collectors, coverage is accurate, UI renders real events, disk inspection stays isolated and HTTP mode remains explicit. Missing or partial proof keeps the issue open.

## Session state

2026-09-08: goal started on main `7739dec`; all ten children and epic remain open. Branch: `vm-introspection-s8e2`. Filesystem checkpoint `c663d0e`, process/network prerequisite checkpoint `fcc5818`, gateway checkpoint `c3e6f77` and observer/DNS checkpoint `9260ae8` are pushed. Runner network collection checkpoint evidence (2026-09-09) follows below. No deployment or child completion claimed. Compaction count: 7; resume in a fresh turn after saving this checkpoint.

## Filesystem checkpoint evidence — 2026-09-08

- Red/green integration: the first real guest gate exposed an unmounted workspace. The image now mounts the third block device, `/dev/vdc`, at `/workspace` before guestd starts. Linux 6.1 then exposed `open_by_handle_at` rejecting an O_PATH mount descriptor with EBADF. The mount descriptor now uses O_RDONLY; a real live-parent resolution assertion prevents silently accepting unresolved paths everywhere.
- `scripts/check` passed all gates: gofmt, vet, native and Linux lint, Go tests, web typecheck/tests, generated bundle and documentation checks. Log: `.superpowers/sdd/introspection-check-final.log`. Web build: 246 tests across 29 files. An initial check caught an unused platform helper and a CLI test still treating the now-live SSE endpoint as a stub; both were corrected before the green run.
- Real Docker/KVM command: `VMOBS_LINUX_HOST=aibox03 scripts/linux 'scripts/vmobs-gate env VMOBS_GUEST_SENSOR_TESTS=1 VMOBS_BROWSER_REVIEW_DIR=/evidence go test ./tests/integration -run TestFilesystemIntrospectionGate -count=1 -v -timeout 14m'`. Exit 0. Root/workspace create, modify, close-write, metadata, rename and delete reached the durable API under the exact VM/boot identity. Guest tests exercised real fanotify overflow, failure/reopen and the declared mmap limitation without skips. Log: `.superpowers/sdd/filesystem-final-browser-gate.log`.
- Browser verification used the actual fixture terminal and API, with no mocked network: VM `c71e65cc-30a6-4ccd-a4db-d25d7f7695e7`, boot `eb9be7fc-1499-48c2-bc44-5b67cebfed20`. Typed writes to `/root/browser-path-check` and `/workspace/browser-path-check`; seven live mutation rows displayed inferred full paths. Selecting Network flows displayed unavailable capture while the terminal remained attached. Current capture recovered to healthy while retaining measured drops from the pressure test. Screenshots inspected: `/tmp/vmobs-introspection-final-files.png` and `/tmp/vmobs-introspection-final-network.png`. Fixture cleanup passed; the live user's VM was preserved.
- Earlier real browser checks also exercised pause/unread/resume, live SSE messages, hostile filenames displayed as literal text, and terminal continuity across family changes. Evidence log: `.superpowers/sdd/filesystem-browser-verified.log`. That earlier image preceded the mount-descriptor correction and is not the path-resolution acceptance evidence.
- Independent reviews covered sensor recovery, loss semantics, UI coverage labels, boot identity, normalization, SSE authentication and network parsing. The final coverage/API review found no blocking issue. Root reread the changed production paths and integration fixture after the green checks.

### Artifact status and limits

That checkpoint's development root image pin was `9a9c3b92d75422e5746945fef0aaa7b8ada10c4c914f4f2a0695a4d2117b70da`; its download URL was deliberately empty because it had not been published. Its final gate used a disposable copy augmented with the sensor test executable, SHA `9b0dd2fdc05863dc70715fd0f8c7d477aacacd1a121aae204d72b45a305c6c72`. The kernel remained `b606768652b4ecf5d8a2651d258e70d8f1892fca9f74c6b5fc2c9031a50ddd31`; its existing config already enabled file handles. Gate evidence names base revision `7739dec` with a dirty source tree, not a released commit. After that image build, a lint-only change inlined the identical endian writes into the Linux sensor; rebuild the guest from the final source before publication.

Shipping blockers remain: host routing/policy and network collector acquisition are incomplete; process attribution is unknown; final content diffs and HTTP inspection are unimplemented; the development image is unpublished. The current browser provides filesystem activity and generic event families, not the completed Network workspace. Notifications are bounded guest-reported evidence, with inferred paths, explicit exclusions and loss, not exact write bytes or content diffs. All child contracts stay open until their complete acceptance and published deployment pass.

### Next execution unit

Implement the approved per-VM routed boundary and acquire host-owned conntrack/NFLOG evidence before guest traffic starts. First prove namespace-local interface forwarding and nft conntrack accounting under the shipped AppArmor/seccomp boundary, with unchanged host settings and denied traffic still denied. Then wire authenticated descriptor handoff, bounded runner collection, managed DNS/denials and truthful coverage. Do not broaden AppArmor/sysctl access or restart the live appliance implicitly. Continue with process attribution, isolated final disk inspection, explicit HTTP inspection and the complete two-VM published acceptance gate.

## Process and network prerequisite checkpoint — 2026-09-08

- Guest process capture now runs in guestd: raw scheduler and native amd64 syscall hooks report fork, successful exec, failed exec, task exit and connect attempts/results. The runner registers and persists these kinds with guest provenance and validated boot/TGID/start-time process keys. Unknown lifetime evidence remains unknown. The browser offers Processes and Connect attempts, bounded arguments, normalized identity and raw event details beside the same terminal.
- The old pinned kernel rejected even a trivial raw tracepoint program with EINVAL. Enabling FTRACE/KPROBE_EVENTS/FTRACE_SYSCALLS/BPF_EVENTS fixed the actual guest load. New kernel SHA is `90f1ffba91252c70be098bfb37e1b41af6e300a42c1719bac9782bdfbfd52f1c`, config SHA `7439d9116d7aea08f33d9ca7e4fc01459511d3d0adee6e398b2abac041e6f1df`. The root image built after the final loss-label edit is `51fcc41cdf13b94442796f902614e77f8095b462089b0ec7649d01120e6e1ed2`. Both artifact download URLs remain empty until publication.
- TDD evidence: registry and normalized spool tests failed before wiring; the real startup test failed because the prior image never started process capture. Independent review exposed nonleader exec resetting task start time. A bounded kernel token now preserves the exact transition without exporting a task pointer or weakening PID reuse checks. Real nonleader exec failed before that fix and passed afterward. Logs: `.superpowers/sdd/process-startup-supervisor-red.log`, `process-nonleader-exec-red.log`, `process-production-capture-gate.log`.
- Final automated Docker/KVM verification: `VMOBS_LINUX_HOST=aibox03 scripts/linux 'scripts/vmobs-gate env VMOBS_PROCESS_SENSOR_TESTS=1 VMOBS_PROCESS_CAPTURE_TESTS=1 go test ./tests/integration -run TestFilesystemIntrospectionGate -count=1 -v -timeout 6m'` exited 0. Filesystem mutations, guestd startup, command arguments through the durable API, all real process package tests, nonleader exec and failure/reopen passed without skips; teardown passed. Log: `.superpowers/sdd/process-final-verification-gate.log`.
- Real browser fixture VM `2db13fce-723f-4a86-91c5-88c556fe0196`, boot `dab2bc13-a75f-4a36-8972-0d4bd77cb315`, augmented image `fede89351c6ac019e4e49c25b70f5905af2e42cd0822070144e4646f3479bcd6`: typed `/bin/sh -c 'exit 0' 'browser-live-proof-<img src=x>'`, opened event 163 with matching arguments/process key and zero rendered image elements. Switched to Connect attempts and typed a guest loopback port-9 connection; event 181 records syscall result -111 and unknown host-flow attribution. Terminal stayed attached. Evidence JSON: `.superpowers/sdd/process-browser-evidence.json`; inspected screenshots `/tmp/vmobs-process-browser-live.png` and `/tmp/vmobs-process-browser-connect.png`. Closing the multiplexed SSH forwarding connection truncated the final gate output after cleanup began; this run supplies browser evidence, while the subsequent uninterrupted automated gate supplies exit/cleanup proof. Only the original live VM's VMM/runner remained afterward.
- Network prerequisites: the shipped AppArmor/seccomp gate proved owned-interface forwarding, namespace-local TCP/UDP conntrack accounting and denial behavior with unchanged parent settings (`network-boundary-primitives-verified.log`). Real descriptor tests cover split frames, bounded SCM_RIGHTS, CLOEXEC and failure closure. Conntrack acquisition subscribes before requesting its privileged baseline; the reader must validate completion. Independent review strengthened the real acquisition test to parse DONE errors/interruption; its disposable Linux run passed (`conntrack-acquisition-reviewed-green.log`).
- Shared network layout and strict, bounded policy loading now derive the transit/guest addresses and MAC and validate explicit public-web/offline profiles. Effective policy state is private with copy-returning accessors. FIFO/symlink rejection and immutability regressions pass. This is a new policy file contract, not a configured upstream choice; Doctor Biz's DNS upstream selection remains pending. Gateway rule generation is a separate active unit; production routing, resolver and collector acquisition are not wired.
- `env -u GOROOT GOLANGCI_LINT_CACHE=<fresh directory> mise exec -- scripts/check` passed all gates (`.superpowers/sdd/introspection-process-check-final.log`): native/Linux lint, vet, Go tests, web typecheck/tests, current generated assets and docs package checks. The prior run passed code checks but required staging the intentionally rebuilt web assets before the repository's index comparison could pass. An agent's plain-shell check had selected Go 1.27 against a linter built with Go 1.26; the final command explicitly selected the repository's Go 1.26.6 toolchain.
- Independent process review verified the token fix and browser identity handling; network reviews verified descriptor/acquisition and sealed policy contracts. Root fresh-eyes review checked the 45 staged files, trust boundaries, loss/recovery, process keys, image pins and real evidence. No blocking finding remains in this checkpoint. Gateway generator files remain uncommitted while their separate review completes; they are not part of this checkpoint's shipping claim.

### Remaining shipping work

All ten Kata contracts remain open. Process capture still lacks UID/GID, executable/cwd/cgroup fields, supported file associations, stable socket identity and exact host-flow links. Bounded argv is four arguments of at most 63 bytes each; raw connect results do not prove transport completion. The bounded pending-call scan has an unmeasured CPU concern to assess in the noisy-VM overhead gate. Complete the routed gateway and immutable boot/generation lifecycle, managed DNS/NFLOG/conntrack delivery, Network workspace, isolated final file inspection, opt-in request inspection, and published two-VM acceptance/deployment. Rebuild artifacts from the final shipping source and obtain interruption approval before any live user-VM restart.

## Closed gateway integration checkpoint — 2026-09-08

- Generated namespace and host nft policy passed real packets through two NAT
  stages, managed UDP/TCP relay, direct-DNS/private/spoof denials, host-local DNAT
  rejection, closed transport and offline behavior in disposable local Docker.
  Root found and reproduced a calling-thread namespace restoration bug in the
  test harness; the fix passed three repetitions
  (`gateway-packet-thread-green.log`). Independent review requested stronger
  upstream-negative/counter proof; the fixes passed three packet repetitions and
  a race run, and root accepted their review. This is not a production resolver
  or real Firecracker proof.
- Guest boot configuration derives address, gateway, DNS and MAC from the shared
  allocated layout. Guestd starts management paths before its one-shot network
  worker and reports pending/degraded configuration independently of traffic
  coverage. A real FIFO regression proves authenticated control remains usable
  during blocked setup and late results cannot replace a deadline failure.
  Real Linux guest/jailer/component checks passed. Final review found that link
  lookup could accept failed or interrupted dumps. It now validates completion
  status and interruption on every matching message; RED/GREEN tests, full Linux
  guest/guestd tests and vet, and the real NET_ADMIN component passed. Root updated the integration fixture
  and ran its real config builder against the pinned aibox03 artifacts, exit 0
  (`fixture-network-green.log`). The guest image has not been rebuilt.
- Final independent guest re-review approved the checkpoint with no remaining
  finding (`guest-network-review.md`), including fresh Linux startup repetitions.
  Root completed fresh-eyes review of all 42 checkpoint files. The fixed dump
  handling was its final blocker; full shipping acceptance remains outstanding.
- Closed offline gateway lifecycle now persists policy/boot/generation/namespace
  ownership, installs closed rules before raising links, probes retries without
  repair, and retains uncertain claims. Real component checks passed. Independent
  review found two blockers: privileged host route overlap was unchecked, and
  allocation rollback discarded the execution deadline. Both were reproduced,
  fixed and accepted in independent re-review. The actual closed lifecycle passed
  under the shipped AppArmor/seccomp profiles in an isolated aibox03 child
  namespace, including boot-bound probes, verified release and unchanged parent
  settings (`gateway-confinement-reviewed.log`, Docker exit 0). Transport remains explicitly unavailable until
  resolver, observer acquisition and activation are integrated.
- A real SCM_RIGHTS test proves that an unprivileged recipient can read the
  privileged conntrack baseline but cannot issue a privileged conntrack deletion.
  Its isolated Linux run passed (`descriptor-authority-verified.log`); independent
  review found no blocker. This does not prove production collector handoff.
- Copying now hashes actual destination bytes before ownership transfer. A real
  same-inode mutation regression failed before the fix and passes for JSON,
  config disk and root disk. The final ownership assertion and existing pinned
  rename test passed (`copy-digest-ownership-green.log`, Docker exit 0).
- Public StartVM now probes the completed persisted gateway before staging and
  immediately before jailer execution. It validates copied Firecracker JSON on
  the destination descriptor before ownership transfer: exact TAP/MAC/CID and
  the allowed kernel, disk and socket paths. Real closed-gateway refusal cases
  and a valid marker-executable case passed; independent review found no blocker
  (`start-network-binding-review.md`). Existing symlink/PID tests now exercise
  private staging/exec helpers directly without a production bypass. A distinct
  mutation-during-staging regression for the second probe remains a low-priority
  test gap; full KVM launch proof remains outstanding.
- Canonical `scripts/check` passed all gates after the final guest fixes
  (`introspection-gateway-check-release-retry.log`, exit 0). The preceding attempt
  collided with another golangci-lint process; its failed log is retained as
  `introspection-gateway-check-release.log`. Native/Linux lint, vet, Go tests,
  web typecheck/tests/assets and docs checks passed on retry. No artifact
  publication or deployment is claimed.
- Scope correction: prior scratch reports called immutable guest config sealing
  a launch blocker. SPEC requires host resource/policy/boot binding and enforcement
  independent of guest settings. Implement the actual StartVM topology and
  Firecracker resource checks; do not introduce privileged guest-disk parsing or
  new mount permissions for an unsupported byte-sealing requirement.
- NFLOG acquisition is the next unit. Its incomplete test initially made Linux
  lint fail with undefined implementation symbols. The exact untracked test is
  preserved in `.superpowers/sdd/nflog-pending-test.go` while this separate gateway
  checkpoint is checked and committed. It is not part of the checkpoint or a
  capture-completeness claim. Restore it and resume its recorded RED after the
  commit; no implemented collector test has been removed.

## Network observer and DNS checkpoint — 2026-09-08

- NFLOG acquisition now binds a bounded current-namespace socket, validates its
  kernel configuration ACK and refuses an existing owner. Real isolated Linux
  tests prove packet reception, duplicate refusal, close/reacquisition, and mixed
  netdev IPv4/unsupported-EtherType batches. Unsupported metadata survives with
  unknown tuple fields. NFLOG's opaque batch DONE payload is distinct from a
  conntrack dump status. Fresh root package evidence:
  `.superpowers/sdd/network-observer-root-linux.log` (exit 0). The separate older
  conntrack opt-in test was not enabled in that run.
- The managed DNS worker serves supplied UDP/TCP listeners with bounded queries,
  connections, wire sizes, timeouts and retained observations. It validates reply
  identity, handles EDNS and TCP fallback, and reports loss separately from DNS
  outcomes. Tests use real loopback upstreams and clients. Root DNS/netobserve
  race checks passed (`network-observer-root-race.log`). Namespace-bound socket
  adapters and durable DNS events remain integration work.
- Host denial groups are assigned per VM from durable ledger claims. Namespace
  groups remain local to each VM. Topology proof binds the assigned host group;
  release refuses reuse while an old reader survives. Review caught valid ledger
  entries with missing ownership being treated as free or recovered success;
  the fix requires explicit ownership and preserves uncertainty.
- The privileged observer API binds three transferred sockets to the VM, guest
  boot, host boot, namespace inode/device, policy digest, gateway generation and
  a fresh acquisition UUID. It authenticates the existing UID boundary, verifies
  root on the client, validates actual socket properties and closes partial
  acquisitions. It does not activate transport or claim a completed baseline.
- Root's normal Linux test command passed closed gateway lifecycle and all
  observer checks with no skips (`observer-handoff-root-linux-final.log`, exit 0,
  0.509s). It exercises the real server, ledger, namespace and an unprivileged
  recipient. The first run failed because Go's private build directory blocked
  child execution; the fixture now copies only its executable into an owned
  traversable directory. The original failure log is retained. The implementer's
  final normal Linux race component also passed (8.789s).
- Final `scripts/check` passed native/Linux lint, vet, Go tests, web checks and
  docs validation (`network-observer-check-final.log`, exit 0). The separate docs
  validator passed 47/47. Independent group re-review accepted the missing-group
  fix; root acquisition/parser and DNS reviews found no remaining unit blocker.
- Independent observer handoff review and root fresh-eyes review accepted the
  final checkpoint. The full Linux privd package passed as non-root (5.695s,
  `observer-root-linux-nonroot-suite.log`). An extra root-run package attempt
  failed older recording-backend tests that derive jail UID zero from the test
  user; the same `TestHappyPath` failure reproduces on unchanged `c3e6f77`
  (`observer-root-uid-baseline.log`). That existing fixture limitation is not
  evidence against or a substitute for the passing real privileged components.

## Runner network collection checkpoint — 2026-09-09

- The jailer adapter is privd's client of record for network observers. On
  every launch and respawn it calls `AcquireNetworkObservers` for the VM and
  guest boot, hands the three validated AF_NETLINK descriptors to the runner
  through `ExtraFiles` from fd 3, and passes either `--network-observers`
  (the binding) or a bounded `--network-unavailable-reason`, never neither.
  The runner adopts the descriptors (restores close-on-exec, validates the
  socket properties), keeps the masters for its lifetime, dups a fresh set per
  reader generation, re-baselines on the same sockets after failures with
  backoff to 30 s, and never dials privd. A refused acquisition never blocks a
  launch; it becomes durable unavailable coverage carrying the reason.
- The acquisition boundary is a declared scope limitation ("observation began
  at …; earlier traffic unobserved"), not a counted unknown interval. The first
  independent review caught the opposite: every collector reported permanent
  degraded loss, hidden by a hand-written fixture. Coverage fixtures are now
  built from the runner's own status functions.
- Runner status, `net.collector.health`/`net.collector.loss` events and the
  runner ctl `network-status` reply feed `Adapter.Coverage`, the situation
  host coverage source and `/vms/{id}/coverage`. Counts are bounded at the
  JSON-safe limit; untracked flow identities and unsupported families are
  their own limitations, not packet loss.
- Evidence: canonical `scripts/check` with a fresh lint cache
  (`runner-network-fix{1,2,3,4,5,5b}-check-macos.log`, exit 0); aibox03
  non-root runner, jailer, cmd/vmobsd, situation, events, privd, network and
  netobserve suites (`runner-network-fix{1,2,3}-linux-nonroot.log`; rounds 4,
  5 and 5b re-ran the runner, jailer, situation, cmd/vmobsd and events suites,
  `runner-network-fix{4,5,5b}-linux-nonroot.log`); confined root runs:
  50 netobserve reader checks including the credential-dropped reader
  (`runner-network-fix1-netobserve-confined.log`), the production-shaped
  `TestNetworkRunnerKernelPipeline` — real privd server, uid-65534 child
  receives the descriptors, six real denied observations imported into SQLite
  by protocol, unknown intervals "0" with a declared observation start, dup
  independence, respawn re-acquisition
  (`runner-network-fix{1,2,3,4}-runner-pipeline.log`, docker exit 0), seven privd
  observer checks (`runner-network-fix1-privd-observer.log`) and the two
  integration gates (`runner-network-fix1-integration-gate.log`). RED logs are
  retained per fix round.
- Reviews: first independent review (`runner-network-review-report.md`, one
  Critical, four Important, nine Minor) → two fix rounds → scoped re-review
  (`runner-network-fix-review-report.md`: spec compliance met, two Important,
  four Minor) → fix round 3 → scoped re-review
  (`runner-network-fix3-review-report.md`: all six fixed; one Important — the
  never-acquired runner status carried no acquisition identity, so the coverage
  gate refused it with a wrong cause and the refusal reason never reached the
  API — and three Minor) → fix round 4 → scoped re-review
  (`runner-network-fix4-review-report.md`: all four fixed; three Minor — an
  untested refusal clause, a fixture staleness race, a limitation worded as a
  boot-wide verdict) → fix round 5 with an in-round follow-up that made two adapter tests
  assert the refusal they prove → scoped re-review
  (`runner-network-fix5-review-report.md`: spec met, quality approved, all
  three fixed, the follow-up's RED real; two Minor parked at the round-5
  breaker with rulings — the adapter's live-path freshness gate has no
  stale-status test, and the status-identity clause pins one of seven
  fields — both carried into the egress/DNS unit's jailer sub-unit).
- Declared limits: no conntrack-confirmed `net.flow.observed` exists yet
  because privd installs only the offline profile
  (`internal/privd/gateway_lifecycle_linux.go:302` pins `Ready: false`); the
  kernel test asserts that absence and names the condition that flips it.
  Acquisition failure at launch recovers only by runner respawn or VM restart.
  Strict/`require_telemetry` reaction is not built. Wiring is tested through
  `installFirecrackerRuntime`, not `serve()`. The adapter's freshness gate is
  proven only through `coverageFromNetworkStatus`; no live test serves a
  stale runner status yet. Jailer suite runs ~79 s.

### Next execution unit and shipping limits

Egress activation and namespace-bound managed DNS (kata `1m87`, `kygy`,
`nwcg`); the brief is `.superpowers/sdd/egress-dns-unit-brief.md`, the ground
map `.superpowers/sdd/dns-activation-map.md`. The generated gateway rules
already assume the resolver sits inside the VM gateway namespace at the guest
gateway address, so DNS sockets ride the existing observer acquisition: for a
transport VM privd also opens the UDP and TCP listeners on the gateway address,
one upstream UDP socket and a bounded pool of upstream TCP sockets inside the
namespace, all under the same acquisition id. Activation is two typed privd
mutations that reinstall the ruleset with `Ready` true or false once the
ownership marker, topology digest and current acquisition match the request.
The jailer adapter is the activation client of record: it activates only when
the runner reports flow, both denial collectors and the `dns` collector healthy
under the acquisition it handed over, and deactivates when the runner exits,
reports another acquisition or reports `dns` unavailable. Transient reader
failures that re-baseline stay measured loss with egress open; strict mode is
not built and coverage says so. The runner runs the managed DNS worker as its
fourth collector, emits `dns.query` through the same spool, and on worker exit
closes the listeners so guest queries fail fast with no alternate upstream.
`policy.egress_activated` and `policy.egress_closed` are registered before
emission; the manifest holds the last confirmed egress state.

Sub-units in order: U1 privd (transport accepted, DNS acquisition, the
activate/deactivate verbs, confined root rule-digest tests); U2 runner and
jailer (worker, activation supervisor, coverage `dns` seam, a confined pipeline
pass that produces a conntrack-confirmed `net.flow.observed` and a fail-closed
denial after a worker kill); U3 a two-guest KVM gate under transport.
Controlled fixtures sit on a public-classified address the gate host routes
locally.

Shipping limits: no policy file ships in the image although `deploy/config.yaml`
names `transport-public-web`, so the deployed appliance cannot launch a VM from
this branch until one lands with a real public upstream, a product choice for
Doctor Biz that lands under `6wf7`. Then network UI/correlation, final disk
diffs, explicit HTTP inspection, guest-image rebuild, publication and the full
two-VM acceptance. No live restart, deployment or host policy change occurred.
