# L1b (M1b) — Fleet Actions and Guest Terminal

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the §18 M1 gate. An operator opens `/ui/`, launches VMs from a form, acts on several at once, and types into a real guest PTY in the browser — two VMs at the same time, each with its own shell, each shell surviving a browser reload without spawning a second one.

**Architecture:** Two halves that share a branch and nothing else.

*Phase A* is browser-only plus one small API addition. The fleet page already reads `GET /host/status`, `GET /vms` and `GET /attention`; Phase A gives it a mutation client (session-cookie + `X-CSRF-Token`), a launch form, a batch form, multi-select actions, and a recent-operations panel read from `GET /events?kind=operation.state_changed`. The one server change is publishing the admission parameters in `GET /host/status` so the reservation preview restates API-served numbers instead of inventing arithmetic of its own (§13 opening: the UI holds no private truth).

*Phase B* builds the §8.1 chain end to end, in the direction the bytes flow:

```text
xterm.js  <->  WSS /api/v1/terminals/{id}/stream  <->  internal/terminal (lease, ring, cursor)
          <->  vmobs-runner relay  <->  vsock port 10002  <->  guestd PTY broker  <->  guest shell
```

`guestd` opens a real PTY with `TIOCSCTTY` and `setsid`, owns it independently of any browser, and drains it into a bounded per-session ring with a monotonic byte offset. The runner relays typed `FramePTY` frames (already in `internal/guest/proto`) between vsock and a Unix control socket. `internal/terminal` holds the session registry, the single writer lease and the replay window. The API layer authorizes the upgrade and relays bounded frames. No host shell appears anywhere in that chain.

**Tech Stack:** Go 1.26 (project toolchain). Two new dependencies, both verified against their registries on 2026-09-04: `github.com/coder/websocket v1.8.15` (server WebSocket, no transitive deps) and `@xterm/xterm 6.0.0` + `@xterm/addon-fit 0.11.0` (browser terminal, no transitive deps). React 19 + Vite as landed. One guest rootfs rebuild.

**Spec:** `docs/SPEC.md` (binding contract — §7.3, §7.4, §8.1–8.4, §9 health records, §12.4, §13.1, §13.7, §14, §15.1, §15.3, §18 M1). Acceptance IDs: AT-019..AT-030 (`docs/ACCEPTANCE.md` §C), plus AT-101 for the UI-has-no-private-truth rule.

## Global Constraints

- SPEC §1.4 principles P-01..P-08 bind every surface: bounded, cursorable, linked, honest.
- Evidence honesty: never fabricate counts, verdicts, or coverage; `inconclusive` beats an invented answer. No `TESTED_PASS` on any AT row without an executed run and committed evidence. A screenshot is not proof of a guest PTY.
- §8.1 verbatim: "Allocate a real guest PTY. Pipes and a JavaScript text box do not implement an interactive terminal." And: "No host shell participates in this chain." A relay that runs `sh -c` anywhere on the host fails the gate by construction.
- §8.2 verbatim: "Test with a shell, `vi`, and a full-screen process viewer actually installed in the image." Task 8 makes that true; no task may soften it by testing with `cat`.
- §8.3 verbatim: "Bound every queue. A slow browser must not stop sensor ingestion or the control channel." Every buffer in this plan has a byte cap and a declared drop behaviour.
- §8.4: authenticate the upgrade; validate the exact allowed Origin independently of CORS; never place long-lived bearer tokens in URLs; no OSC 52 clipboard write, no automatic download, no third-party analytics, restrictive CSP.
- §13 opening: "Anything it displays is obtainable from the API with identical values and provenance labels (AT-101); the UI holds no private data path and no private truth." A number the browser computes from numbers the API did not publish is a violation.
- §13.7: every mutating control shows in-progress state and its operation ID; refreshing a page does not repeat a launch; errors carry an actionable reason, not only a toast; filters and selected VM persist in the URL without credentials; keyboard navigation, visible focus, accessible labels, readable contrast.
- §15.3: secrets never in argv, logs, events, evidence, or error messages. This now includes PTY bytes: guest output can echo secrets, so it is never written to the event log or an artifact in L1b.
- Counters that can exceed JS safe integers are decimal strings in JSON. Everywhere — terminal byte offsets included, and they will exceed it.
- Event kinds must be registered in `internal/events` before anything emits them; ingress rejects unregistered kinds.
- The fake runtime (`internal/runtime/runtimetest`) is unit-test-only; never reachable from served modes. Same rule for any fake PTY or fake broker this plan adds.
- TDD with real components at the seams we own: real SQLite, real HTTP, real `os.Pipe`/`pty`, real WebSocket handshakes. Linux-only tests carry `//go:build linux` and run via `scripts/linux '<cmd>'`.
- Browser tests use `@testing-library/react` with a real DOM (jsdom) and a stubbed `fetch`/`WebSocket` at the network boundary only — never a mocked component under test.
- Canonical gate: `scripts/check` before claiming anything works. It rebuilds `web/dist` and fails on drift, so every web task ends with `scripts/build-web` and a committed `dist`.
- New source files start with two `ABOUTME:` comment lines.
- NEVER run password sudo on aibox03. Agents may invoke only `sudo -n /usr/local/sbin/vmobs-root-helper <verb>`. A rootfs rebuild runs as the ordinary user through `images/rootfs/build.sh` (docker); installing anything privileged is a Doctor Biz handoff.
- Conventional commits, imperative, present tense. Never `--no-verify`. Never `git add -A`.

## Decisions this plan fixes (record in PLAN.md deviations log at close-out)

- **D1 — Phase A pulls §18 M4's "batch UI" forward, on Doctor Biz's explicit direction.** §18 M1 asks only for "the minimal fleet page and one xterm terminal"; §18 M4 lists "filters and batch UI". §13.1 describes Launch Batch as part of the fleet view, and the batch API (`POST /vm-batches`) already works, so the UI is the only missing half. This is a re-sequencing, not a weakened requirement. If scope has to be cut to reach the M1 gate, Task 5 (batch) is the piece §18 permits deferring — nothing else in this plan is.

- **D2 — no terminal tickets.** §15.1 says "Bind terminal tickets, **if used**, to owner/VM/session and a short lifetime; do not put persistent tokens into query strings or access logs." The browser sends its `HttpOnly` session cookie on a same-origin upgrade automatically, and a non-browser client can set an `Authorization` header on the upgrade. A ticket would add a credential class whose only job is to travel in a URL — the exact thing §8.4 and §15.1 forbid. The P5 deferral "WebSocket origin checks + terminal tickets: L0" is therefore answered as: origin checks built (Task 13), tickets declined with reasons. Recorded, not skipped.

- **D3 — the upgrade requires an exact `Origin`; the existing mutation check does not.** `internal/api/auth.go` today rejects a mismatched Origin only when it is present and the method is mutating. A WebSocket upgrade is a `GET`, so it gets no check at all right now. Task 13 adds an upgrade-specific gate: `Origin` must be present and exactly equal to `server.public_origin`, for cookie **and** bearer callers, with cause `origin_rejected`. Absent Origin is a denial, not a pass — a browser always sends one, and a client that cannot is not a browser.

- **D4 — PTY bytes never enter the event store.** §8.3 forbids automatic keystroke recording and warns that output carries echoed secrets. `terminal.*` events in L1b carry session lifecycle and byte *counts* only: created, attached, detached, lease transferred, output dropped, closed. `record_input` and `persist_output_default` stay `false` and unimplemented; turning them on is M5 work with its own authorization path.

- **D5 — replay lives in the guest broker's ring, not on the host.** §8.2 says reconnect "request[s] output after the last consumed byte offset" and §8.3 says "The guest broker continuously drains into a bounded reconnect ring". The host keeps only the in-flight window it has not yet acknowledged. One ring, one source of truth, and a controller restart does not lose the shell's recent output. Ring size comes from `terminal.max_replay_bytes_per_session` (default 256 KiB, given its meaning and default in Task 10) and reaches the guest in the `terminal.create` message.

- **D6 — one writer lease per session, held by connection identity, released on disconnect after a grace window.** `terminal.writer_lease_seconds` (default 30) is the grace, not a heartbeat interval: a browser that vanishes keeps its lease that long so a reload does not hand the shell to a bystander, and `POST /terminals/{id}/lease` with `{"action":"transfer"}` takes it immediately and invalidates the old writer's next input frame by sequence.

- **D7 — `github.com/coder/websocket`, not a hand-rolled RFC 6455 server.** Framing, masking, fragmentation, close handshakes and the permessage-deflate refusal are a security surface, not an exercise. The library has no transitive dependencies and the repo already carries six direct third-party modules. Compression stays disabled (§7.4: "Disable compression initially").

- **D8 — the reservation preview restates published parameters.** Task 3 adds an `admission` block to `GET /host/status` carrying `reserve_per_vm_host_overhead_mib`, `cpu_overcommit_ratio`, `allow_memory_overcommit`, `max_batch_size` and `max_parallel_provisions`. §14 describes `GET /host/status` as "Capacity, reservations, doctor/capability state, service health", so this is a field addition inside an existing route, not a new one. The preview then shows `count × (memory_mib + overhead)` against `free_memory_mib` using only numbers the API served. "Why it cannot fit" on submit is the daemon's own typed refusal, quoted, never a browser guess.

- **D9 — the launch form offers the fields `POST /vms` actually accepts, and names the rest.** The API takes `name`, `template_id`, `vcpu_count`, `memory_mib`, `root_disk_mib`, `workspace_disk_mib`, `labels`, `run`, `idempotency_key`, and rejects unknown keys (`DisallowUnknownFields`). §13.1 also lists privilege profile, network profile/policy, workspace seed, initial exec command and retention/capture policy — none of which the API accepts today (privilege and network come from `vm_defaults`; workspace seed is M4 per M1a-D7; exec is a stub route; capture is M3). The form renders those as disabled controls showing the host's effective value and the milestone that makes them settable. Hiding them would make the gap invisible; faking them would 400.

- **D10 — `top`, not `htop`, and `vim-tiny` for `vi`.** Measured on aibox03 against `images/dist/rootfs.inventory.txt` and the pinned base image on 2026-09-04: `bash`, `dash`, `procps` (so `/usr/bin/top`) and `ncurses-base` (so `xterm-256color` terminfo) are already in the image; `vim`, `vim-tiny`, `nano`, `busybox` and `less` are all absent. Task 8 adds exactly `vim-tiny`, which provides `/usr/bin/vi`. One package, because AT-020 needs an editor and nothing else is missing.

## File map

| Path | Responsibility |
|---|---|
| `web/src/api.ts` | + `postJSON`/`deleteJSON` with `X-CSRF-Token`, session probe, `ApiFailure` preserved |
| `web/src/session.ts` | Session context: owner, auth method, CSRF token, refresh on 403 `csrf_rejected` |
| `web/src/operation.ts` | Mutation state machine: idempotency key, in-flight, operation ID, typed failure |
| `web/src/components/LaunchForm.tsx` | §13.1 single launch: fields, reservation preview, disabled-with-reason controls |
| `web/src/components/LaunchBatch.tsx` | §13.1 batch: members, reservation mode, on-failure policy, per-member results |
| `web/src/components/BatchProgress.tsx` | Independent per-member progress; never green because member 1 started |
| `web/src/components/VMTable.tsx` | + selection checkboxes, per-row action state, per-row result |
| `web/src/components/BulkActions.tsx` | Multi-select stop/pause/resume/delete with per-VM outcomes |
| `web/src/components/RecentOperations.tsx` | `GET /events?kind=operation.state_changed`, bounded, cursorable |
| `web/src/components/Terminal.tsx` | xterm.js pane: writer/read-only badge, connection taxonomy, replay gap notice |
| `web/src/terminalSocket.ts` | WebSocket client: frame codec, cursor, ack after xterm write callback, backoff |
| `web/src/url.ts` | Filter + selection state in the URL query string, credential-free |
| `web/src/VMDetail.tsx` | §13.2 minimal: identity header, terminal pane, session tabs |
| `internal/api/vms.go` | + `admission` block in `GET /host/status` (D8) |
| `internal/api/terminals.go` | `POST`/`GET /vms/{id}/terminals`, `DELETE /terminals/{id}`, `POST /terminals/{id}/lease` |
| `internal/api/terminal_stream.go` | `GET /terminals/{id}/stream`: upgrade auth, exact-Origin gate (D3), bounded relay |
| `internal/api/auth.go` | + `checkUpgradeOrigin` used only by the stream route |
| `internal/terminal/session.go` | Session registry, identity, boot binding, state machine |
| `internal/terminal/lease.go` | Writer lease: acquire/transfer/release, grace window, sequence invalidation |
| `internal/terminal/window.go` | Host-side in-flight window, cursor arithmetic, decimal-string offsets |
| `internal/terminal/transport.go` | Runner control-socket client: create/attach/resize/input/close |
| `internal/runner/terminal.go` | Runner relay: vsock port 10002 dial, `FramePTY` pump, bounded queues |
| `internal/runner/ctl.go` | + terminal verbs on the existing runner control socket |
| `internal/guest/pty/broker.go` | guestd PTY broker: `openpty`, `setsid`, `TIOCSCTTY`, exec argv, reap |
| `internal/guest/pty/ring.go` | Bounded per-session reconnect ring with byte offset and drop marks |
| `internal/guest/proto/messages.go` | + `terminal.*` control messages: create, created, attach, resize, close, dropped |
| `cmd/vmobs-guestd/main.go` | + listen on vsock 10002, serve the broker |
| `internal/events/registry.go` | + `terminal.session_created`, `terminal.attached`, `terminal.detached`, `terminal.lease_transferred`, `terminal.output_dropped`, `terminal.session_closed` |
| `internal/config/config.go` | + defaults and validation for the existing `terminal:` block |
| `images/rootfs/build.sh` | + `vim-tiny` in the snapshot install list (D10) |
| `images/rootfs/pins.env` | unchanged pins; `runtime.lock.json` re-pinned after rebuild |
| `tests/integration/m1b_gate_test.go` | AT-019..AT-030 driver: two VMs, independent terminals, reconnect, lease |
| `docs/ACCEPTANCE.md` | AT-019..AT-030 status notes with evidence |

Existing seams consumed (exact, from the current tree):
- `proto.FramePTY = 0x02`, `proto.MaxBinaryFrame = 256 << 10`, `proto.WriteFrame(w, typ, payload)` / `ReadFrame` (internal/guest/proto/frame.go). PTY framing already exists; this plan uses it, it does not redefine it.
- `proto.Envelope{V, Kind, ...}` with `KindHello`/`KindHelloAck`/`KindPing`/`KindPong`/`KindError`/`KindShutdown`/`KindShutdownAck` (internal/guest/proto/messages.go:15-25).
- vsock control port `10000` (`internal/runner/runner.go:26`, `cmd/vmobs-guestd/main.go:25`). Terminal port is `10002` per §7.3's table.
- `api.New(st, eng, mgr, ac AuthConfig, pf PreflightFunc)`; route table at `internal/api/api.go:55` with four terminal patterns already present as `nil`-handler stubs at lines 76-79 that serve 501 `missing_capability`. Filling them in is a handler swap, not a table redesign.
- `AuthConfig.PublicOrigin`, `SessionCookieName = "vmobs_session"`, `csrfHeader = "X-CSRF-Token"`, constant-time compare against `sess.CSRFToken` (internal/api/auth.go:22-25, 142-143).
- `GET /auth/session` returns `{owner, method, expires_at, csrf_token}` for `method == "session"` and `{owner, method: "none"}` when authentication is off (internal/api/auth.go:354).
- `vmActionBody{Action string, ExpectedRevision string}` — actions take a revision and **no** idempotency key (internal/api/vms.go:745). Valid actions: `start`, `pause`, `resume`, `stop`, `force_stop` (internal/runtime/manager.go:81).
- `createVMBody` and `createBatchBody` field lists (internal/api/vms.go:581, internal/api/batches.go:129) — both `DisallowUnknownFields`.
- Reservation math: `memTotal = memory_mib + cfg.Admission.ReservePerVMHostOverheadMiB` (internal/runtime/manager.go:478, mirrored in batch.go:281).
- `config.Terminal` struct already exists with `MaxReplayBytesPerSession`, `MaxWireChunkBytes`, `MaxInflightBrowserBytes`, `WriterLeaseSeconds`, `RecordInput`, `PersistOutputDefault`, `AutomaticClipboardWrite`, `AutomaticDownload` (internal/config/config.go:196). This plan gives them defaults and meaning; it does not add fields.
- `events.Envelope` + registry gate: `store.Append` rejects unregistered kinds.
- `uiPrefix = "/ui/"` SPA shell with a genuine 404 under `assets/` (internal/api/ui.go).
- `scripts/check` gate 9 rebuilds `web/dist` and fails on `git diff --quiet -- web/dist`.
- Test harnesses to extend rather than replace: `newTemplateServerWrapped` (internal/api/vms_test.go:49-88) stands up a server with the fake runtime exposed for failure injection and a `wrap` hook for request-context inspection; `requireTeaching` (internal/api/api_test.go:107-119) mechanically fails any error path lacking a message, a cause, and a remediation with a rationale. Every typed error this plan adds passes `requireTeaching`.
- Every mutating handler already shares one shape (internal/api/vms.go:750-818): fetch, then owner-check with no side effect on denial, `MaxBytesReader` + `DisallowUnknownFields`, required `expected_revision`, a `manager.OperationContext` that outlives client disconnect, and one `write*Error` mapper per package. New handlers match it.
- WebSocket handling and any ticket mechanism are absent repo-wide — zero matches for `websocket`, `Hijacker`, or `ticket`. Task 12 is the first of its kind here, not an edit to something existing.

---

# Phase A — Fleet actions (§13.1, §13.7)

### Task 1: Mutation client, session context, operation state machine

**Files:**
- Modify: `web/src/api.ts`
- Create: `web/src/session.ts`, `web/src/operation.ts`
- Test: `web/src/api.test.ts` (extend), `web/src/session.test.ts`, `web/src/operation.test.ts`

**Interfaces:**
- Produces: `postJSON<T>(path, body, opts?): Promise<T>`, `deleteJSON<T>(path): Promise<T>`; `SessionProvider` / `useSession(): {owner, method, csrfToken?}`; `useOperation<T>()` returning `{state: 'idle'|'in_flight'|'done'|'failed', operationId?, failure?, run(fn)}`.
- Consumes: existing `getJSON`, `ApiFailure`, `ApiError` from `web/src/types.ts`.

`postJSON` sets `content-type: application/json`, `credentials: 'same-origin'`, and adds `X-CSRF-Token` **only** when the session's `method === 'session'` — the loopback dev config runs with `require_authentication: false`, where `GET /auth/session` answers `{"owner":"local_operator","method":"none"}` and there is no token to send. On a 403 with cause `csrf_rejected`, refetch `GET /auth/session` once and retry exactly once; a second 403 surfaces to the caller. Never retry any other status: a 409 is a real conflict and a 5xx may have taken effect.

Idempotency keys are generated with `crypto.randomUUID()` and cached in `sessionStorage` under a caller-supplied form key. §13.7: "Refreshing a page does not repeat a launch" — reload reuses the stored key, so a replayed submit is the daemon's idempotent replay rather than a second VM. The key is cleared when the operation reaches a terminal state.

- [ ] **Step 1: Write failing tests.** `api.test.ts`: `postJSON` sends `X-CSRF-Token` when method is `session`; omits it when method is `none`; a 403 `csrf_rejected` triggers exactly one session refetch and one retry; a 409 is not retried. `session.test.ts`: provider exposes owner/method/token from a stubbed `GET /auth/session`; a 401 renders the sign-in state. `operation.test.ts`: `run()` moves idle→in_flight→done and exposes `operation_id` from the response; a failure keeps the typed `ApiFailure`; the idempotency key is stable across two `useOperation` mounts with the same form key and different after reset.
- [ ] **Step 2: Run** `cd web && npm test` — FAIL (modules absent).
- [ ] **Step 3: Implement** the three modules. Stub `fetch` at the network boundary only; render real components.
- [ ] **Step 4: Run** `cd web && npm test && npm run typecheck` — green.
- [ ] **Step 5: Run** `scripts/build-web` and stage `web/dist`.
- [ ] **Step 6: Commit** `feat(web): mutation client with CSRF, session context and operation state`

### Task 2: Publish admission parameters in `GET /host/status`

**Files:**
- Modify: `internal/api/vms.go` (`handleHostStatus`)
- Test: `internal/api/vms_test.go`

**Interfaces:**
- Produces: `host/status` response gains `"admission": {"reserve_per_vm_host_overhead_mib": <int>, "cpu_overcommit_ratio": <float>, "allow_memory_overcommit": <bool>, "max_batch_size": <int>, "max_parallel_provisions": <int>}`.
- Consumes: `runtime.ManagerConfig.Admission` — the same struct `Manager.CreateVM` reads at internal/runtime/manager.go:478.

This is D8's server half. The values come from the manager's live config, not a copy: if the daemon admits on a number, that number is what it publishes. Adding a `Manager` accessor (`AdmissionParams()`) is preferable to reaching into config from the handler.

- [ ] **Step 1: Write failing test** `TestHostStatusPublishesAdmissionParams`: build a server with a known `ManagerConfig.Admission`, `GET /host/status`, assert every field is present and equal to the configured value. Add `TestHostStatusAdmissionMatchesReservationMath`: create a VM through the same manager and assert `reserved_memory_mib` grew by exactly `memory_mib + reserve_per_vm_host_overhead_mib` — the published number and the enforced number are the same number.
- [ ] **Step 2: Run** `env -u GOROOT mise exec -- go test ./internal/api/ -run TestHostStatusAdmission -v` — FAIL.
- [ ] **Step 3: Implement** `Manager.AdmissionParams()` and the response block.
- [ ] **Step 4: Run** the tests green; run `env -u GOROOT mise exec -- ./scripts/check`.
- [ ] **Step 5: Commit** `feat(api): publish admission parameters in host status`

### Task 3: Launch VM form with reservation preview

**Files:**
- Create: `web/src/components/LaunchForm.tsx`, `web/src/components/LaunchForm.test.tsx`
- Modify: `web/src/App.tsx`, `web/src/types.ts`, `web/src/styles.css`

**Interfaces:**
- Consumes: Task 1's `postJSON`/`useOperation`, Task 2's `admission` block, `GET /templates`.
- Produces: `POST /vms` with `{name, template_id, vcpu_count, memory_mib, root_disk_mib, workspace_disk_mib, labels, run?, idempotency_key}`.

Settable fields are exactly D9's list. The remaining §13.1 fields — privilege profile, network profile/policy, workspace seed, initial exec command, retention/capture policy — render as **disabled** controls showing the host's effective value where the API publishes one, each with a visible note naming the milestone that makes it settable (M2 network, M3 capture, M4 seed/exec). A hidden gap is a lie; a disabled control with a reason is a map.

The reservation preview shows `count × (memory_mib + reserve_per_vm_host_overhead_mib)` against `free_memory_mib`, disk as `count × (root_disk_mib + workspace_disk_mib)` against `free_disk_mib`, and vCPU against `free_vcpu`. Every input is a number `GET /host/status` served. When the preview exceeds free capacity the submit button stays enabled and the daemon's typed refusal is rendered in full — the browser warns, the daemon decides.

- [ ] **Step 1: Write failing tests** `LaunchForm.test.tsx`: preview arithmetic matches the published overhead for count 1 and count 4; a request larger than `free_memory_mib` shows the over-capacity warning but leaves submit enabled; submit posts the exact body with the stored idempotency key; the operation ID appears on screen after a 202/201; a typed failure renders `message`, `cause` and every `remediation` entry (not a toast); the disabled fields are present, disabled, and labelled with their milestone; every input has an associated `<label>`; the form is submittable by keyboard alone.
- [ ] **Step 2: Run** `cd web && npm test` — FAIL.
- [ ] **Step 3: Implement** the form and mount it on the fleet page.
- [ ] **Step 4: Run** `cd web && npm test && npm run typecheck`, then `scripts/build-web`.
- [ ] **Step 5: Commit** `feat(web): launch form with reservation preview and honest field gaps`

### Task 4: Launch Batch with independent per-member results

**Files:**
- Create: `web/src/components/LaunchBatch.tsx`, `web/src/components/BatchProgress.tsx` (+ tests)
- Modify: `web/src/App.tsx`, `web/src/types.ts`

**Interfaces:**
- Produces: `POST /vm-batches` with `{members[], reservation_mode, on_failure, idempotency_key}`; polls `GET /vm-batches/{id}`.
- Consumes: Task 1 and Task 3's field editor, reused — one shared member editor, never a second copy of the launch form.

§13.1 verbatim: "Do not make a batch look successful because its first member started." The batch header state is derived from the *weakest* member: it reads `succeeded` only when every member reached a terminal success, `partial` when at least one member failed and at least one succeeded, `failed` when none succeeded, and `in progress` otherwise. Each member row carries its own VM ID (when created), state, and typed failure. `reservation_mode` and `on_failure` are exposed with their meanings, defaulted from `GET /meta` limits where published.

- [ ] **Step 1: Write failing tests.** Given a batch response where member 1 is `running` and member 2 is `failed`, the header says `partial` and never `succeeded`; each member row shows its own error's `cause` and `remediation`; a batch larger than the published `max_batch_size` is warned about before submit; the member editor is the same component the single-launch form uses (assert by rendering both and comparing the accessible field set); polling stops when every member is terminal.
- [ ] **Step 2: Run** `cd web && npm test` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** tests + typecheck + `scripts/build-web`.
- [ ] **Step 5: Commit** `feat(web): batch launch with per-member progress and honest rollup`

### Task 5: Multi-select lifecycle actions with per-VM results

**Files:**
- Create: `web/src/components/BulkActions.tsx` (+ test)
- Modify: `web/src/components/VMTable.tsx` (+ test), `web/src/App.tsx`

**Interfaces:**
- Produces: one `POST /vms/{id}/actions` per selected VM with that VM's own `expected_revision`; `DELETE /vms/{id}` (with `?force=true` only after an explicit confirm) for delete.
- Consumes: `revision` from the VM list rows, Task 1's operation machine.

There is no bulk endpoint and no idempotency key on actions (internal/api/vms.go:745), so the browser fans out and reports honestly. Requests go out with bounded concurrency (4) and each row shows its own in-flight state, operation ID and outcome. A `409` is **not** retried: the row shows the conflict, re-reads the VM, and offers a single explicit retry with the fresh revision — a silent retry would act on a VM whose state changed under the operator. An action illegal for a row's state is disabled on that row with the reason, not attempted and refused.

Delete of a live VM requires `force=true`; the confirm dialog names the VMs and says what force means. Never send `force=true` without that gesture.

- [ ] **Step 1: Write failing tests.** Selecting three VMs and pressing Stop issues three posts, each carrying that row's revision; one 409 among three leaves the other two successful and shows the conflicting row's own error; the conflicting row's retry re-reads and resubmits with the new revision; delete without confirming sends nothing; delete after confirming sends `?force=true`; rows in a state that forbids the action render the button disabled with an accessible reason; the header count reflects selection and is keyboard-togglable.
- [ ] **Step 2: Run** `cd web && npm test` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** tests + typecheck + `scripts/build-web`.
- [ ] **Step 5: Commit** `feat(web): multi-select lifecycle actions with per-VM outcomes`

### Task 6: Recent operations, URL-persisted state, §13.7 sweep

**Files:**
- Create: `web/src/components/RecentOperations.tsx` (+ test), `web/src/url.ts` (+ test)
- Modify: `web/src/App.tsx`, `web/src/components/VMTable.tsx`, `web/src/styles.css`

**Interfaces:**
- Consumes: `GET /events?kind=operation.state_changed&limit=20` — the only registered operation kind (internal/events/registry.go:115). Bounded and cursorable like every other list.
- Produces: `readState(search): {stateFilter[], selectedVM?}` / `writeState(state): string`.

§13.7 is a checklist, and this task closes it: filters and selected VM live in the URL query string and carry no credentials; every mutating control from Tasks 3–5 shows in-progress state and an operation ID; no error is toast-only; keyboard navigation reaches every control with a visible focus ring; contrast meets 4.5:1 for body text against `styles.css` tokens; the layout stays dense.

Recent operations render from events, not from a client-side log of what this tab did — a second browser's launches appear too, and a reload does not empty the panel.

- [ ] **Step 1: Write failing tests.** URL round-trip for filters and selection, including an empty state and an unknown key left untouched; the operations panel renders from a stubbed events page and shows the operation ID, kind and outcome; selecting a state filter changes the `/vms` query and the URL together; `document.location` never contains a token or cookie value; a focus-order test tabs through the page and asserts every interactive element is reachable; an axe-style label assertion that every input and button has an accessible name.
- [ ] **Step 2: Run** `cd web && npm test` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify contrast** with a computed-style assertion on the token pairs used for body text, table text and the alert banner; fix `styles.css` where it falls short.
- [ ] **Step 5: Run** tests + typecheck + `scripts/build-web`, then `env -u GOROOT mise exec -- ./scripts/check`.
- [ ] **Step 6: Commit** `feat(web): recent operations, URL-persisted fleet state, accessibility pass`

---

# Phase B — Guest terminal (§8.1–8.4, §18 M1 gate)

## Protocol contract (Tasks 7, 9, 10, 12 all implement this; none may redefine it)

**Session management rides the existing control port 10000.** §7.3 assigns port 10000 "Control, capabilities, health, exec/session management". The runner already holds an authenticated, framed connection there. New control envelopes, both directions:

| Kind | Direction | Payload |
|---|---|---|
| `terminal.create` | host → guest | `{session_id, user, cwd, argv[], term, rows, cols, ring_bytes}` |
| `terminal.created` | guest → host | `{session_id, pid, started_at}` |
| `terminal.close` | host → guest | `{session_id}` |
| `terminal.closed` | guest → host | `{session_id, exit_code?, signal?, reason}` |
| `terminal.list` | host → guest | `{}` |
| `terminal.sessions` | guest → host | `{sessions: [{session_id, pid, rows, cols, head_offset, tail_offset}]}` |

`head_offset` and `tail_offset` are decimal strings: a busy shell passes 2^53 bytes in days, not years.

**The control loop stays request/response.** Verified on 2026-09-04: `ReadControl` rejects any frame that is not a `FrameControl`, the loop serves four verbs, and nothing is ever pushed unsolicited. This plan adds verbs; it does not add a push channel. So a session that exits announces itself on the paths that already exist:

- **Attached:** the guest sends `terminal.closed` as a `FrameControl` on that session's own port-10002 connection and closes it. That connection is already duplex.
- **Detached:** nobody is waiting, so nothing needs waking. The exit surfaces on the next `terminal.list`, and an attach to a dead session fails with the exit status rather than opening an empty stream.

Do not widen the control loop to carry pushes for this. A terminal that has no reader has no urgency.

**Byte streams ride port 10002, one vsock connection per attached session.** §7.3: "PTY/session byte streams, with an authenticated attach handshake." The connection opens with the existing `proto.Hello` envelope — same `AuthProof` per-boot capability token, same constant-time compare, same error-frame scrubbing already proven in `internal/guest/agent.go:147` — extended with `{session_id, after_offset}`. The guest answers `hello_ack` carrying `{resume_offset, gap}`: `gap` is true when `after_offset` is older than the ring's tail, and `resume_offset` is then the tail. After the handshake the connection carries only:

- `FramePTY` **guest → host**: `[offset: 8 bytes big-endian][output bytes]`, where `offset` is the stream position of the first byte in this chunk. Chunks are at most `proto.MaxBinaryFrame - 8`.
- `FramePTY` **host → guest**: `[seq: 8 bytes big-endian][input bytes]`. The broker applies a frame only when `seq > last_applied_seq`, then advances it. §8.2: "A retransmitted accepted frame must not type the same text twice."
- `FrameControl` either direction for `terminal.resize {rows, cols}` (writer only), `terminal.dropped {from_offset, to_offset}` (guest → host, when the ring overwrote unread bytes), and `terminal.error`.

**Browser ↔ host WebSocket frames mirror that exactly**, so the relay copies rather than translates. Every WS message is binary with a one-byte opcode: `0x01` control (JSON payload), `0x02` PTY bytes carrying the same 8-byte prefix. Browser → host control kinds: `ack {consumed_offset}` (sent after xterm's write callback, §8.3), `resize {rows, cols}`. Host → browser control kinds: `attached {session_id, resume_offset, gap, writer}`, `dropped {from_offset, to_offset}`, `lease {writer: bool, reason}`, `closed {reason, exit_code?, signal?}`, `error {cause, message, remediation[]}`.

**Buffer rules (§8.3), each with a declared behaviour at its limit:**

| Buffer | Bound | At the limit |
|---|---|---|
| Guest PTY ring | `ring_bytes`, from `terminal.max_replay_bytes_per_session` (default 256 KiB) | Overwrite oldest, emit `terminal.dropped` naming the lost range. The guest process is never blocked. |
| Guest → runner vsock write | `proto.MaxBinaryFrame` per frame, write deadline | Deadline exceeded → drop the connection, keep the PTY and the ring alive |
| Runner relay queue | `terminal.max_wire_chunk_bytes` × 8 (default 8 × 32 KiB) | Stop reading vsock; the ring absorbs it and reports the drop |
| Host in-flight to browser | `terminal.max_inflight_browser_bytes` (default 1 MiB) | Stop reading from the runner until an `ack` advances the consumed offset |

No buffer in this chain is unbounded, and no buffer's overflow is silent.

### Task 7: guestd PTY broker and bounded reconnect ring

**Files:**
- Create: `internal/guest/pty/broker.go`, `internal/guest/pty/ring.go`, `internal/guest/pty/pty_linux.go`
- Test: `internal/guest/pty/ring_test.go`, `internal/guest/pty/broker_linux_test.go` (`//go:build linux`)
- Modify: `internal/guest/proto/messages.go` (the control kinds in the table above)

**Interfaces:**
- Produces: `pty.Open(rows, cols uint16) (master *os.File, slaveName string, err error)`; `pty.NewBroker(cfg BrokerConfig) *Broker` with `Create(spec SessionSpec) (*Session, error)`, `Get(id string) (*Session, bool)`, `Close(id string) error`, `List() []SessionInfo`; `Session.Attach(after uint64) (io.ReadCloser, uint64, bool, error)` returning a reader, the resume offset, and whether a gap occurred; `Session.Input(seq uint64, b []byte) (applied bool)`; `Session.Resize(rows, cols uint16) error`; `ring.New(size int)` with `Append([]byte) (dropped Range, ok bool)` and `ReadFrom(offset uint64) ([]byte, uint64, bool)`.
- Consumes: `golang.org/x/sys/unix` — verified present on 2026-09-04: `TIOCSPTLCK`, `TIOCGPTN`, `TIOCSWINSZ`, `IoctlSetPointerInt`, `IoctlGetInt`, `IoctlSetWinsize(fd int, req uint, value *Winsize) error`, `Winsize`.

Open the PTY through `/dev/ptmx`: `unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0)` to unlock, `unix.IoctlGetInt(fd, unix.TIOCGPTN)` for the slave number, then `/dev/pts/N`. The child gets the slave as fds 0/1/2 with `syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}` — that is the controlling terminal §8.1 requires, and it is what makes job control and `SIGWINCH` real. Exec the session's argv array directly. **No `sh -c` anywhere**: the shell is a member of the argv, not an interpreter wrapped around it.

The guest reads no host configuration. Ring size arrives as `ring_bytes` in the `terminal.create` message and `ring.New` takes it as a plain argument, so this task does not wait on Task 10's config work. Clamp it to a compile-time floor and ceiling and report the clamp, rather than trusting a number off the wire.

The broker owns each session independently of any attachment (§8.1: "Disconnecting a tab detaches it, not the underlying shell"). One goroutine per session drains the master into the ring forever, so the guest process never blocks on a missing reader. Reap the child, record exit code or signal, and emit `terminal.exited`.

- [ ] **Step 1: Write failing ring tests** (portable, no PTY): append past capacity reports the exact dropped range and advances the tail; `ReadFrom` an offset inside the window returns the bytes and the next offset; `ReadFrom` an offset older than the tail returns `gap=true` and the tail; `ReadFrom` the head returns empty and no gap; offsets are `uint64` and a ring driven past `1<<53` still reports exact offsets.
- [ ] **Step 2: Write failing broker tests** (`//go:build linux`): `Create` with argv `["/bin/sh","-c","..."]` is **rejected** — argv[0] must be an executable path and the broker never interprets; `Create` with `["/bin/bash","-i"]` yields a live child whose `/proc/<pid>/stat` tty is the allocated pts and whose session id equals its pid (proving `setsid`+`TIOCSCTTY`); writing `stty size\n` returns the rows and cols the session was created with; `Resize` changes what `stty size` reports and the child observes `SIGWINCH`; `Input` with a repeated seq applies once (write `echo hi\n` twice with the same seq, assert one `hi`); detaching a reader leaves the child alive and the ring still filling; `Close` reaps and reports the exit code; killing the child reports the signal.
- [ ] **Step 3: Run** `scripts/linux 'env -u GOROOT go test ./internal/guest/pty/ -v'` — FAIL.
- [ ] **Step 4: Implement** `ring.go`, `pty_linux.go`, `broker.go`, and the new proto kinds.
- [ ] **Step 5: Run** the suite green on Linux; run `env -u GOROOT mise exec -- ./scripts/check` locally (the linux-only files are covered by the `GOOS=linux` lint gate).
- [ ] **Step 6: Commit** `feat(guest): PTY broker with controlling terminal and bounded reconnect ring`

### Task 8: Guest rootfs gains `vi`; rebuild and re-pin

**Files:**
- Modify: `images/rootfs/build.sh` (add `vim-tiny` to the snapshot install list)
- Modify: `runtime.lock.json` (new rootfs digest + inventory)
- Modify: `docs/runbooks/aibox03.md` (rebuild note)

**Interfaces:** none in code. This task exists because §8.2 says "Test with a shell, `vi`, and a full-screen process viewer **actually installed in the image**", and AT-020 says "Run installed `vi` and a full-screen process viewer".

Measured on aibox03 on 2026-09-04, against `images/dist/rootfs.inventory.txt` (119 packages) and the pinned base `ubuntu@sha256:33ceb719…`: `bash 5.2.21`, `dash 0.5.12`, `procps 2:4.0.4` (so `/usr/bin/top` exists) and `ncurses-base 6.4` (so `/usr/share/terminfo/x/xterm-256color` exists) are already there. `vim`, `vim-tiny`, `nano`, `busybox` and `less` are all absent — the image has no editor. Adding `vim-tiny` is the whole change (D10).

The rootfs build also embeds the current `vmobs-guestd`, so this task runs **after** Task 7 and the rebuild ships the PTY broker and the editor together. One rebuild, not two.

No kernel change: the pinned guest kernel already carries `CONFIG_UNIX98_PTYS=y`, so `/dev/ptmx` works as shipped (verified 2026-09-04). Do not rebuild the kernel for this.

- [ ] **Step 1: Add** `vim-tiny` to the `apt-get -S ${APT_SNAPSHOT} install` list in `images/rootfs/build.sh`.
- [ ] **Step 2: Rebuild** on aibox03: `scripts/linux 'bash images/rootfs/build.sh'`. This writes only into `images/dist/` and is the one sanctioned write there. Check free disk first — the build needs headroom and the live gate needs ~21 GB (gotchas.md).
- [ ] **Step 3: Verify from the inventory**, not from hope: assert `vim-tiny` appears in `images/dist/rootfs.inventory.txt`, and that `bash`, `procps` and `ncurses-base` are still present. Record the four lines in the task report.
- [ ] **Step 4: Re-pin** `runtime.lock.json` with the new rootfs digest and inventory path, following the existing re-pin procedure in `docs/runbooks/aibox03.md`.
- [ ] **Step 5: Boot one VM** through the existing fixture path and confirm it reaches `running` with the new image. A rootfs that does not boot is a blocker to report, not a step to skip.
- [ ] **Step 6: Run** `env -u GOROOT mise exec -- ./scripts/check`.
- [ ] **Step 7: Commit** `build(images): install vim-tiny in the guest rootfs and re-pin the runtime lock`

### Task 9: Runner terminal relay

**Files:**
- Create: `internal/runner/terminal.go`, `internal/runner/terminal_test.go`
- Modify: `internal/runner/ctl.go` (+ terminal verbs), `internal/runner/runner.go` (session-management passthrough on port 10000)

**Interfaces:**
- Produces: runner control-socket verbs `terminal-create`, `terminal-close`, `terminal-list` (which forward to the guest over the existing port-10000 channel), and `terminal-attach`, which turns the calling connection into a byte stream for one session.
- Consumes: the port-10000 channel the runner already owns; a fresh vsock dial to port 10002 per attach, using the same `AuthProof` the runner already holds.

Two shapes, not one. `runner.sock` today is JSON one-shot request/reply — send a request, read a reply, done — serving `shutdown_guest` and `finalize`. The three management verbs keep exactly that shape. `terminal-attach` cannot: it sends the JSON request, reads the JSON reply, and then **the same connection becomes a frame stream** for the life of the attachment, framed identically to vsock. One connection per attachment; closing it detaches. Do not try to express a byte stream as a sequence of one-shot replies.

Firecracker's vsock device multiplexes arbitrary ports over one CID via the `CONNECT <port>` handshake, so port 10002 needs **no change to `internal/jailer/launch.go` and no change to the Firecracker machine config** — only a listener in the guest and a dial in the runner. Verified 2026-09-04.

The runner is the fault boundary (§3: "A runner is also the per-VM fault boundary for collection and terminal relay"). It never interprets PTY bytes — it copies frames. Queue bound: `max_wire_chunk_bytes × 8`; at the limit it stops reading vsock and lets the guest ring absorb and report the drop. A dropped browser is a closed control-socket stream; the vsock connection closes; the guest session and its ring live on.

One rule with teeth: the relay contains no `exec` of any kind. A reviewer should be able to `grep -n 'exec\.' internal/runner/terminal.go` and find nothing.

- [ ] **Step 1: Write failing tests** against a real in-process guest broker over a real `socketpair` (no VM needed): `terminal-create` round-trips to `terminal.created`; `terminal-attach` streams output frames with correct offsets; input frames reach the broker and duplicate seqs apply once; the relay stops reading when its queue fills and resumes after the consumer drains; closing the caller's stream leaves the session listed by `terminal-list`; a guest-side `terminal.dropped` reaches the caller verbatim.
- [ ] **Step 2: Run** `scripts/linux 'env -u GOROOT go test ./internal/runner/ -run Terminal -v'` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** green; `env -u GOROOT mise exec -- ./scripts/check`.
- [ ] **Step 5: Commit** `feat(runner): terminal relay over vsock 10002 with bounded queues`

### Task 10: Host session rules — lease, window, transport

**Files:**
- Create: `internal/terminal/session.go`, `internal/terminal/lease.go`, `internal/terminal/window.go`, `internal/terminal/transport.go`
- Test: `internal/terminal/session_test.go`, `internal/terminal/lease_test.go`, `internal/terminal/window_test.go`
- Modify: `internal/events/registry.go`, `internal/config/config.go`, `docs/examples/host.yaml` (if the example config carries a terminal block)

**Interfaces:**
- Produces: `terminal.Registry` with `Create(ctx, vmID string, spec Spec) (Session, error)`, `Get(id string) (Session, bool)`, `ListForVM(vmID string) []Session`, `Close(ctx, id string) error`; `Session` carrying `ID, VMID, BootID, Owner, CreatedAt, State`; `lease.Lease` with `Acquire(connID string) (bool, string)`, `Release(connID string)`, `Steal(connID string) (previous string)`, `Holder() string`; `window.Window` bounding unacked bytes with `Reserve(n int) bool` and `Ack(offset uint64)`.
- Consumes: `internal/config`'s existing `Terminal` block (`internal/config/config.go:196` — `MaxReplayBytesPerSession`, `MaxWireChunkBytes`, `MaxInflightBrowserBytes`, `WriterLeaseSeconds`, `RecordInput`, `PersistOutputDefault`, `AutomaticClipboardWrite`, `AutomaticDownload`); the runner control socket from Task 9.

**The registry is the only thing in the host that talks to a runner about terminals.** `Registry.Attach(ctx, sessionID, afterOffset) (Attachment, error)` dials the runner, sends `terminal-attach`, and hands back the connection as an opaque `io.ReadWriteCloser` plus the resume offset and gap flag. It owns the connection's lifetime; it never inspects a PTY byte. The HTTP handler in Task 12 gets its stream from here and never dials a runner itself — one owner, so a leaked attachment has one place to be found.

§18's repository shape names this package: `internal/terminal/` — "bounded transport and session rules". It holds the rules, not the bytes: no PTY, no vsock, no HTTP.

The lease is D6. One writer at a time; every other attachment is read-only and says so. `Steal` is how §8.2's "writer transfer" works: the previous holder is told it is now read-only in a `lease` control message, and its input frames are refused from that instant — not on its next reconnect. Release on disconnect is deferred by `writer_lease_seconds` (default 30) so a flaky connection does not hand the shell to a bystander, but a `Steal` overrides the grace window immediately.

Boot binding is D-level too: a session records the `boot_id` it was created under. §8.2: "A VM reboot must invalidate the old session rather than silently reattaching." Attach with a stale `boot_id` fails with a typed `session_stale` error naming the reboot — not a fresh shell wearing the old session's name.

Config fields are currently declared and unused, and the demo config sets every one to `0`. Zero means "use the documented default", so an existing config keeps starting; a negative value or one above the ceiling is a validation error naming the field and the range.

Register three event kinds (D4 — lifecycle and counts, never PTY bytes). Registration is one `KindInfo` literal appended to the `registry` slice in `internal/events/registry.go`; `registryByKind`, `Kinds()` and `/meta/event-kinds` all derive from it, and ingress enforcement at `internal/store/append.go:56` starts rejecting unregistered kinds for free.

| Kind | Payload |
|---|---|
| `terminal.session_opened` | `{session_id, vm_id, boot_id, owner, rows, cols, argv}` |
| `terminal.session_closed` | `{session_id, vm_id, reason, exit_code?, signal?, output_bytes, input_bytes, dropped_bytes}` — counts as decimal strings |
| `terminal.output_dropped` | `{session_id, vm_id, from_offset, to_offset}` — offsets as decimal strings |

- [ ] **Step 1: Write failing tests:** a second attach is read-only and carries a reason; `Steal` flips the badge on the old holder and its next input frame is refused by sequence; release after disconnect waits out the grace window and an attach inside that window still finds the old holder; `Steal` beats the grace window; the window refuses a reserve past the in-flight bound and admits it again after an ack; an ack for an offset behind the current one does not move the window backwards; an attach with a stale `boot_id` fails `session_stale`; zero-valued config fields resolve to the documented defaults and a negative one fails validation naming the field; the three event kinds round-trip through the registry with counters as decimal strings.
- [ ] **Step 2: Run** `env -u GOROOT mise exec -- go test ./internal/terminal/... ./internal/events/... ./internal/config/...` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `env -u GOROOT mise exec -- ./scripts/check`.
- [ ] **Step 5: Commit** `feat(terminal): session registry, writer lease, and bounded in-flight window`

### Task 11: Terminal session API routes

**Files:**
- Create: `internal/api/terminals.go`, `internal/api/terminals_test.go`
- Modify: `internal/api/api.go` (swap four `nil` handlers for real ones)

**Interfaces:**
- Produces: `POST /vms/{id}/terminals` → `201 {session_id, vm_id, boot_id, rows, cols, created_at, writer_available}`; `GET /vms/{id}/terminals` → bounded, cursorable list; `DELETE /terminals/{id}` → `204`; `POST /terminals/{id}/lease` with `{mode: "acquire"|"steal"|"release"}` → `{writer: bool, holder, reason}`.
- Consumes: `terminal.Registry` (Task 10); the ownership check and typed-error mapper already used by every mutating handler.

The four route patterns already exist at `internal/api/api.go:76-79` as `nil` handlers answering `501 missing_capability`. This task replaces the stubs; it does not add routes.

Follow the shape every other mutating handler already uses (`internal/api/vms.go:750-818`, `handleVMAction`): fetch-then-owner-check with no side effect on denial, `http.MaxBytesReader` plus `DisallowUnknownFields`, a `manager.OperationContext` so the work outlives a client disconnect, and the package's single `write*Error` mapper. Extend the existing `newTemplateServerWrapped` harness (`internal/api/vms_test.go:49-88`) rather than building a new one — it already exposes the fake runtime for failure injection. `requireTeaching` (`internal/api/api_test.go:107-119`) mechanically enforces that every new error path carries a message, a cause, and a remediation with a rationale; every typed error this task adds must pass it.

Cap concurrent sessions per VM at `vm_defaults.max_terminal_sessions` and refuse past it with a typed error naming the cap and the current count. Refuse on a VM that is not running with a typed error naming the actual state.

- [ ] **Step 1: Write failing tests:** create returns a session bound to the VM's current `boot_id`; create on a `stopped` VM fails with the state named; create past the cap fails naming cap and count; list is bounded and cursorable and shows only that VM's sessions; delete is idempotent (second call is still `204`); a cross-owner create, list, delete and lease each fail `403` with no side effect; lease acquire/steal/release round-trip; every new error passes `requireTeaching`; `terminal.session_opened` and `terminal.session_closed` land in the event store with decimal-string counters.
- [ ] **Step 2: Run** `env -u GOROOT mise exec -- go test ./internal/api/ -run Terminal -v` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `env -u GOROOT mise exec -- ./scripts/check`.
- [ ] **Step 5: Commit** `feat(api): terminal session create, list, close, and lease routes`

### Task 12: The WebSocket stream — authenticated at the upgrade, bounded in the relay

**Files:**
- Create: `internal/api/terminal_stream.go`, `internal/api/terminal_stream_test.go`
- Modify: `internal/api/auth.go` (upgrade-specific origin gate), `go.mod`, `go.sum`
- Add dependency: `github.com/coder/websocket v1.8.15` (published 2026-06-15; no transitive dependencies)

**Interfaces:**
- Produces: `GET /terminals/{id}/stream` — the browser end of §8.1's chain.
- Consumes: `terminal.Registry` (Task 10) — including `Registry.Attach`, which is how this handler reaches the runner; `window.Window` (Task 10); `AuthConfig.PublicOrigin` and `SessionCookieName` (`internal/api/auth.go:23,34`).

**This is the security task of the phase.** Today's origin check (`internal/api/auth.go:129`) is `origin != "" && origin != PublicOrigin`, and it runs only for mutating methods (`isMutating`, line 208). A WebSocket upgrade is a `GET` — so as the code stands it gets no origin check at all. D3 closes that: for an upgrade, `Origin` must be **present and exactly equal** to `public_origin`. Absent is a denial, not a pass. The check is the API's own, independent of any CORS middleware, per §8.4.

Order of gates, each denying before any PTY exists (AT-029, AT-030):

1. Origin present and exactly `public_origin`, else `403 origin_rejected`.
2. Authenticated — session cookie or `Authorization` header, whichever the deployment's auth mode requires — else `401`.
3. Session exists, else `404`.
4. Caller owns the session's VM, else `403`, with no observable difference in timing or body between "not yours" and "does not exist" beyond the status the other handlers already use.
5. Session's `boot_id` still current, else `409 session_stale`.

Only then does the handler upgrade. Denials answer as plain HTTP with the typed error body — never by upgrading and then closing, which would leak existence to a cross-origin page.

D2 stands: no tickets. A same-origin browser upgrade carries the `HttpOnly` session cookie automatically, and a non-browser client sets an `Authorization` header. A ticket would exist only to ride in a query string, which §8.4 and §15.1 both forbid. Record the reasoning in the deviations log against `PLAN.md:24`, which had named tickets as a P5 deferral.

Use `coder/websocket`, not a hand-rolled RFC 6455 server. Disable permessage-deflate (§7.4 forbids compressing attacker-influenced bytes beside secrets in one stream). Relay only: this handler contains no `exec`, and the bytes it copies are never parsed, logged, or written to the event store (D4).

- [ ] **Step 1: Add the dependency:** `env -u GOROOT mise exec -- go get github.com/coder/websocket@v1.8.15 && go mod tidy`. Confirm `go.sum` gained nothing else.
- [ ] **Step 2: Write failing tests** against a real `httptest` server and a real client websocket: an upgrade with no `Origin` is denied `403` and never upgrades; wrong `Origin` denied; unauthenticated denied `401`; wrong owner denied `403`; unknown session `404`; stale `boot_id` `409`; each denial's body passes `requireTeaching` and no session or PTY is created (assert against the registry); a good upgrade receives `attached` first with `resume_offset` and `writer`; the second attachment is read-only and its input frames are dropped, with the drop visible as a `lease` message rather than silence; a `steal` flips both sides' badges live; output stops flowing once unacked bytes reach `max_inflight_browser_bytes` and resumes on `ack`; a guest `terminal.dropped` surfaces as a `dropped` control message with both offsets; a duplicate input frame with a repeated seq reaches the guest once; the negotiated extensions list is empty (compression off).
- [ ] **Step 3: Run** `env -u GOROOT mise exec -- go test ./internal/api/ -run Stream -v` — FAIL.
- [ ] **Step 4: Implement** the upgrade gate in `auth.go` and the relay in `terminal_stream.go`.
- [ ] **Step 5: Prove the relay has no shell:** `grep -rn 'os/exec\|exec\.Command' internal/api/terminal_stream.go internal/runner/terminal.go` returns nothing. Paste the empty result into the task report — §18's gate is "no host shell proxy masquerading as a guest terminal", and this is the evidence for it.
- [ ] **Step 6: Run** `env -u GOROOT mise exec -- ./scripts/check`.
- [ ] **Step 7: Commit** `feat(api): authenticated, origin-checked WebSocket terminal relay`

### Task 13: xterm.js terminal and the VM detail page (§13.2)

**Files:**
- Create: `web/src/Terminal.tsx`, `web/src/terminalSocket.ts`, `web/src/VMDetail.tsx`, `web/src/Terminal.test.tsx`, `web/src/terminalSocket.test.ts`
- Modify: `web/src/App.tsx` (route to detail), `web/src/url.ts` (selected VM in the URL), `web/package.json`, `web/package-lock.json`, `web/index.html` (CSP)
- Add dependencies: `@xterm/xterm 6.0.0`, `@xterm/addon-fit 0.11.0` (both published 2025-12-22; zero dependencies)

**Interfaces:**
- Produces: `<Terminal sessionId rows cols />`; `openTerminal(sessionId): TerminalSocket` with `onOutput`, `onControl`, `send(bytes)`, `resize(rows, cols)`, `close()`; a VM detail view with state, template, addresses, and the terminal.
- Consumes: `GET /terminals/{id}/stream`, the session routes from Task 11, the mutation client from Task 1.

xterm.js against a real PTY — §8.1 again: "Pipes and a JavaScript text box do not implement an interactive terminal." The fit addon computes rows and cols from the container and every change is sent as a `resize` control message; the writer's resize is the only one the guest applies (§8.2).

**Ack after the write callback, never on receive** (§8.3). `term.write(data, callback)` fires when the bytes are actually on screen; the callback sends `ack {consumed_offset}`. Acking on WS receive would make the host's in-flight window measure the network instead of the browser, and the whole backpressure chain becomes decorative.

Five disconnect states, each named on screen with what it means and what to do — §8.2 forbids "an ambiguous spinner": `connecting`, `attached (writer)`, `attached (read-only — <holder> is writing)`, `reconnecting (attempt N)`, `closed (<reason>)`. A replay gap renders as an explicit divider — "output between byte X and byte Y was dropped" — and the screen resets rather than pretending continuity (§8.2, AT-023).

§8.4 and AT-028 in the client: no OSC 52 (disable clipboard escape handling explicitly, do not rely on a default), no automatic downloads, no third-party analytics, and a CSP that permits no remote script. Terminal output is written to xterm, never to `innerHTML`.

- [ ] **Step 1: Add the dependencies** with exact versions; `npm ci` clean; confirm the lockfile gained only these two.
- [ ] **Step 2: Write failing tests** stubbing only `WebSocket` (the network boundary), never the terminal: output frames reach `term.write` with bytes intact through UTF-8 multi-byte splits across two frames; `ack` is sent from the write callback and carries the consumed offset, and no ack is sent if the callback never fires; a `dropped` control message renders the gap divider and resets; a read-only attach renders the badge and swallows keystrokes without sending; `lease` flipping to read-only mid-session updates the badge live; a resize sends rows and cols once, debounced; a closed socket moves through `reconnecting (attempt N)` with named attempts and lands on `closed` with the reason; OSC 52 in the output stream does not touch `navigator.clipboard` (assert the mock was never called); an `<img onerror>` in the output stream never becomes DOM.
- [ ] **Step 3: Run** `cd web && npm test` — FAIL.
- [ ] **Step 4: Implement.**
- [ ] **Step 5: Run** `scripts/build-web` and commit `web/dist` in the same commit — `scripts/check:65` fails the build if the committed bundle differs from a fresh one.
- [ ] **Step 6: Run** `env -u GOROOT mise exec -- ./scripts/check`.
- [ ] **Step 7: Commit** `feat(web): xterm terminal and VM detail page`

### Task 14: The M1 gate on real hardware

**Files:**
- Create: `tests/integration/m1b_gate_test.go` (`//go:build integration && linux`)
- Modify: `docs/ACCEPTANCE.md` (AT-019..AT-030 evidence), `PLAN.md` (session log, deviations D1..D10), `gotchas.md` (whatever the run teaches)

**Interfaces:** consumes everything above, against real Firecracker on aibox03.

§18's M1 gate, stated exactly: "demonstrate two simultaneously running VMs with independent terminals, storage and stop actions. Gate: no host shell proxy masquerading as a guest terminal; reconnect does not spawn a duplicate shell."

Check free disk before starting. The live gate needs about 21 GB, and a short disk fails AT-009 in a way that reads exactly like a regression (gotchas.md). Two VMs, not one — the independence claim is the point.

Evidence rules from CLAUDE.md apply without exception. A test that cannot run records `inconclusive` with the reason. No AT is marked passing on a manual squint; each one names the assertion that proved it.

- [ ] **Step 1: Two VMs, two terminals.** Assert each session's output reflects only its own VM (AT-025): write a unique marker into each guest and assert it appears in exactly one stream.
- [ ] **Step 2: No host shell (the gate).** In one terminal run `hostname`, `cat /proc/self/cgroup` and `ls /dev/vd*` and assert the answers are the guest's, not aibox03's. From the host side, assert the guest shell's pid exists in the VM and no new descendant appeared under `vmobsd` or `vmobs-runner` for the duration (AT-019).
- [ ] **Step 3: Reconnect spawns no duplicate shell (the gate).** Record the guest shell's pid, drop the WebSocket, reattach, assert the same pid and one replay (AT-022). Then assert `ps` inside the guest shows exactly one shell.
- [ ] **Step 4: Real terminal behaviour** (AT-020, AT-021): run `vi`, quit it cleanly; run `top` and quit; resize mid-session and confirm the program redraws; UTF-8, color, alt-screen restore, bracketed paste; `Ctrl-C` interrupts a sleep and leaves the shell alive; `Ctrl-D` ends the session.
- [ ] **Step 5: The bounded, honest failure paths** (AT-023, AT-024, AT-026, AT-027): flood with `yes` against a slow consumer and assert the stream stays bounded and declares its loss with offsets; reattach past the ring and assert the gap divider, not a fake screen; two browsers, one writer, and a steal that immediately silences the old writer; duplicate input frames type once; reboot invalidates the session with `session_stale` while pause/resume keeps it.
- [ ] **Step 6: The denials** (AT-029, AT-030): unauthenticated, absent-Origin, wrong-Origin, wrong-owner and stale-session upgrades each denied before a PTY exists — assert the session count on the host did not move.
- [ ] **Step 7: Storage and stop actions** through the web UI's own controls, closing §18's "storage and stop actions" clause with the Phase A work.
- [ ] **Step 8: Record evidence** in `docs/ACCEPTANCE.md` — per AT, the command, the observation, and the verdict. `inconclusive` where it is inconclusive.
- [ ] **Step 9: Tear down.** `scripts/aibox03/demo stop`, confirm no orphaned firecracker processes and that free disk returned. Never touch `/tmp/vmobs-kernel-src`, `/srv/vmobs/fixture`, or the journal.
- [ ] **Step 10: Run** `env -u GOROOT mise exec -- ./scripts/check` and the integration suite.
- [ ] **Step 11: Commit** `test(integration): M1 gate — two VMs, independent guest terminals, no host shell`

---

## Explicitly out of scope

Named here so no task drifts into them and no reviewer reports them missing.

- **Runs, reports and the agent-facing run API (§10, §11).** M2. The launch form's `run` block stays absent from the UI even though `POST /vms` accepts one.
- **Telemetry views, timelines and rollups (§9, §13.4).** M3. The fleet page shows lifecycle state, not observation data.
- **Filters beyond the URL-persisted state Task 6 adds (§13.5).** M4. Task 6 persists what the page already has; it does not build a filter builder.
- **Session recording and playback (§8.3).** Opt-in, separately authorized, and not in M1. `record_input` and `persist_output_default` stay `false` and unimplemented; the config fields exist and validate.
- **`exec` and non-interactive command execution over the guest channel.** The control port's "exec/session management" wording covers both; this plan implements sessions only.
- **Multiple concurrent terminals per VM beyond the configured cap.** The cap is enforced; raising it is a config change, not a feature.
- **Terminal tickets** (D2). Declined with reasons, not deferred.
- **Adoption of orphaned VMs, the Reconcile startup stall, the /30 allocator that never reclaims, the two launch-rollback escapes, and `RealOps.AbortStartVM` coverage.** Carried in `PLAN.md` from M1a. Fix them in M2 unless one of them breaks this phase's gate, in which case it is in scope the moment it does.
- **Mobile layout.** §13.7 asks for a dense workstation layout. Small screens get a readable page, not a redesign.
