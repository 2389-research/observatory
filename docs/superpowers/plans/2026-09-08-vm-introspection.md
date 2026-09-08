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

2026-09-08: goal started on main `7739dec`; all ten children and epic remain open. Branch: `vm-introspection-s8e2`. The first checkpoint implements filesystem notifications, coverage, boot-filtered replay/SSE and an adjacent browser timeline. Portable network parsers and a namespace-local forwarding primitive have component tests; neither is wired into production network collection. No deployment or child completion claimed. Compaction count: 2.

## Filesystem checkpoint evidence — 2026-09-08

- Red/green integration: the first real guest gate exposed an unmounted workspace. The image now mounts the third block device, `/dev/vdc`, at `/workspace` before guestd starts. Linux 6.1 then exposed `open_by_handle_at` rejecting an O_PATH mount descriptor with EBADF. The mount descriptor now uses O_RDONLY; a real live-parent resolution assertion prevents silently accepting unresolved paths everywhere.
- `scripts/check` passed all gates: gofmt, vet, native and Linux lint, Go tests, web typecheck/tests, generated bundle and documentation checks. Log: `.superpowers/sdd/introspection-check-final.log`. Web build: 246 tests across 29 files. An initial check caught an unused platform helper and a CLI test still treating the now-live SSE endpoint as a stub; both were corrected before the green run.
- Real Docker/KVM command: `VMOBS_LINUX_HOST=aibox03 scripts/linux 'scripts/vmobs-gate env VMOBS_GUEST_SENSOR_TESTS=1 VMOBS_BROWSER_REVIEW_DIR=/evidence go test ./tests/integration -run TestFilesystemIntrospectionGate -count=1 -v -timeout 14m'`. Exit 0. Root/workspace create, modify, close-write, metadata, rename and delete reached the durable API under the exact VM/boot identity. Guest tests exercised real fanotify overflow, failure/reopen and the declared mmap limitation without skips. Log: `.superpowers/sdd/filesystem-final-browser-gate.log`.
- Browser verification used the actual fixture terminal and API, with no mocked network: VM `c71e65cc-30a6-4ccd-a4db-d25d7f7695e7`, boot `eb9be7fc-1499-48c2-bc44-5b67cebfed20`. Typed writes to `/root/browser-path-check` and `/workspace/browser-path-check`; seven live mutation rows displayed inferred full paths. Selecting Network flows displayed unavailable capture while the terminal remained attached. Current capture recovered to healthy while retaining measured drops from the pressure test. Screenshots inspected: `/tmp/vmobs-introspection-final-files.png` and `/tmp/vmobs-introspection-final-network.png`. Fixture cleanup passed; the live user's VM was preserved.
- Earlier real browser checks also exercised pause/unread/resume, live SSE messages, hostile filenames displayed as literal text, and terminal continuity across family changes. Evidence log: `.superpowers/sdd/filesystem-browser-verified.log`. That earlier image preceded the mount-descriptor correction and is not the path-resolution acceptance evidence.
- Independent reviews covered sensor recovery, loss semantics, UI coverage labels, boot identity, normalization, SSE authentication and network parsing. The final coverage/API review found no blocking issue. Root reread the changed production paths and integration fixture after the green checks.

### Artifact status and limits

The current development root image pin is `9a9c3b92d75422e5746945fef0aaa7b8ada10c4c914f4f2a0695a4d2117b70da`; its download URL is deliberately empty because it has not been published. The final gate used a disposable copy augmented with the sensor test executable, SHA `9b0dd2fdc05863dc70715fd0f8c7d477aacacd1a121aae204d72b45a305c6c72`. The kernel remained `b606768652b4ecf5d8a2651d258e70d8f1892fca9f74c6b5fc2c9031a50ddd31`; its existing config already enabled file handles. Gate evidence names base revision `7739dec` with a dirty source tree, not a released commit. After that image build, a lint-only change inlined the identical endian writes into the Linux sensor; rebuild the guest from the final source before publication.

Shipping blockers remain: host routing/policy and network collector acquisition are incomplete; process attribution is unknown; final content diffs and HTTP inspection are unimplemented; the development image is unpublished. The current browser provides filesystem activity and generic event families, not the completed Network workspace. Notifications are bounded guest-reported evidence, with inferred paths, explicit exclusions and loss, not exact write bytes or content diffs. All child contracts stay open until their complete acceptance and published deployment pass.

### Next execution unit

Implement the approved per-VM routed boundary and acquire host-owned conntrack/NFLOG evidence before guest traffic starts. First prove namespace-local interface forwarding and nft conntrack accounting under the shipped AppArmor/seccomp boundary, with unchanged host settings and denied traffic still denied. Then wire authenticated descriptor handoff, bounded runner collection, managed DNS/denials and truthful coverage. Do not broaden AppArmor/sysctl access or restart the live appliance implicitly. Continue with process attribution, isolated final disk inspection, explicit HTTP inspection and the complete two-VM published acceptance gate.
