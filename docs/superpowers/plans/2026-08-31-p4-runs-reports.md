# P4: Declarative Runs + Reports Implementation Plan

> Historical plan, archived on 2026-09-07. P4 is complete in `PLAN.md`.
> The original instructions and unchecked steps below preserve the design at
> the time; they are not outstanding tasks or current implementation guidance.
> Consult `PLAN.md` and `gotchas.md` for later decisions and corrections.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build SPEC §8.6/§8.7 (R-16): declarative runs with a phase machine, criteria evaluation, on_completion policy, guest progress/result ingress, and machine-readable run reports whose every count carries a working `reproduce_query`.

**Architecture:** Runs live in the store (migration v6) with guarded transitions like VMs; the runtime Manager orchestrates conclusion (evaluate criteria → record outcome → on_completion policy → report operation); `internal/report` is a pure deterministic rollup generator validated against `docs/schemas/run-report.schema.json`. Guest submissions enter through trusted Manager methods (the L0 vsock bridge will call them; tests call them directly) — never HTTP.

**Tech Stack:** Go, modernc.org/sqlite (existing), `github.com/santhosh-tekuri/jsonschema/v6` (new, test-scoped use, for report schema validation).

**Spec:** `docs/SPEC.md` §8.6, §8.7, §12.2, §12.7, §14 (runs rows), R-16; `docs/ACCEPTANCE.md` AT-092..AT-095, AT-100, AT-102; `docs/schemas/run-report.schema.json`, `docs/schemas/launch-request.schema.json` (run block).

## Global Constraints

- Canonical gate: `scripts/check` before every commit claim. Go invocations outside it need `env -u GOROOT mise exec -- go ...`.
- TDD per feature; tests use real components (real SQLite, real HTTP) at seams we own. The fake runtime (`internal/runtime/runtimetest`) is unit-test only, never a served mode.
- Counters that can exceed JS safe integers are decimal strings in JSON. Report-schema `count` fields are JSON integers by schema design (bounded ≤ 2^53−1) — that is the one sanctioned exception, defined by the schema itself.
- Every API response bounded; keyset pagination only (never OFFSET); errors carry typed `cause` + `remediation` where the system knows the remediation space.
- Event kinds MUST be registered in `internal/events` before anything emits them. Operation kinds (operations table) are NOT event kinds.
- Store-synthesized events ride the store's host-wide stream (envelope `vm_id` null; VM/run linkage in event `data`) — established P2/P3 deviation.
- Async-job transitions carry a `From` pin; operation finalizers pin `IfState: "running"` (see gotchas.md).
- Provenance labels are assigned by trusted ingress only. §12.2: `run.*` family is `host_observed` except `run.progress` (`guest_reported`).
- Conventional commit per component. No pushes.
- Deviations from spec get recorded in PLAN.md's deviation log (Task 11 collects the ones this plan already rules; new ones found mid-build get added too).

## Design rulings fixed by this plan (record in PLAN.md deviations, Task 11)

- R1 — All three criteria types are accepted at run creation. Criteria that cannot be evaluated at conclusion (no exec subsystem, no guest result) conclude `inconclusive` with a typed reason — §8.6 sanctions exactly this; refusing would invent a capability-gating mechanism the spec doesn't ask for.
- R2 — `on_completion: stop_and_finalize` is refused with `missing_capability` while filesystem finalization is unbuilt: the report schema's `final_diff.status` enum has no honest value for requested-but-impossible finalization (`not_requested` would lie, `diff_incomplete` implies a diff ran).
- R3 — The guest result is a run-row record served with `"provenance": "guest_reported"`, plus a `run.result_recorded` event that is `host_observed` (per §12.2's letter) with a registry caveat that `data` content is guest-supplied.
- R4 — One non-terminal run per VM, enforced by partial unique index. §12.7 serves a singular `active_run`; queued runs are YAGNI.
- R5 — `run-report.schema.json` `boot_ids` relaxes `minItems` 1→0: a run whose VM failed before boot honestly has zero boots, and AT-094 requires a report in every terminal phase.
- R6 — Rejected guest submissions (oversized/malformed) are recorded as `run.submission_rejected` events (host_observed, bounded reason) per AT-095.
- R7 — Report retry mechanism (spec names none): Manager re-enqueues generation on reconcile for terminal runs without a stored report, and a GET of a failed report re-enqueues one attempt. Generation is deterministic and idempotent, so the GET side effect is repair, not mutation.
- R8 — A launch-attached run whose VM fails before running concludes `inconclusive`, `evaluated_by: "system"` (criteria never evaluable; `aborted` is reserved for operator abort).
- R9 — `exec_exit_zero` evaluation branch exists but no exec can attach until L0; such runs conclude only via operator abort or VM-terminal (→ `inconclusive`, reason `no exec attached; exec capability not built`).
- R10 — Guest ingress surface is `Manager.SubmitRunProgress` / `Manager.SubmitRunResult` (Go methods), not HTTP routes. The spec's guest paths (guestd vsock, result.json) are L0; inventing an HTTP ingress would create an untrusted provenance path.
- R11 — Progress submissions share the `guest_result_max_bytes` bound (one guest-submission bound; a separate progress bound is config surface the spec doesn't name).
- R12 — Run phase machine: every terminal phase is reached through `concluding` (§8.6 lists phases in strict order). Abort transitions to `concluding` and records `aborted` in the same tx (two `run.state_changed` events, one tx).

## Run phase machine (single source of truth for Tasks 2, 6, 8)

```
pending    → running     (VM entered running; or standalone create on a running VM, same tx as creation)
pending    → concluding  (launch failed / operator verdict / abort / reconcile interruption)
running    → concluding  (result arrived / operator verdict / abort / VM terminal / reconcile interruption)
concluding → succeeded | failed | inconclusive | aborted
```

Terminal phases: `succeeded`, `failed`, `inconclusive`, `aborted`. No other edges. Store rejects everything else with `InvalidRunTransitionError`.

Criteria evaluation truth table (Task 6):

| criteria_type | evidence at conclusion | outcome | evaluated_by |
|---|---|---|---|
| operator_verdict | verdict in conclude call | verdict (`succeeded`/`failed`) | `operator` |
| operator_verdict | no verdict (VM terminal, interruption) | `inconclusive`, reason states no verdict was submitted | `system` |
| guest_result | recorded result `status: "succeeded"` | `succeeded` | `guest_result` |
| guest_result | recorded result `status: "failed"` | `failed` | `guest_result` |
| guest_result | no result recorded | `inconclusive`, reason states no result before <trigger> | `system` |
| exec_exit_zero | (no exec subsystem in portable core) | `inconclusive`, reason `no exec attached; exec capability not built` | `system` |
| any | operator abort | `aborted`, reason from request | `operator` |
| any | VM failed before run started (R8) | `inconclusive`, reason `vm launch failed before the run started` | `system` |

---

### Task 1: Relax report schema boot_ids (docs)

**Files:**
- Modify: `docs/schemas/run-report.schema.json` (boot_ids: `"minItems": 1` → `"minItems": 0`)
- Modify: `docs/VALIDATION.md` (append dated revision)

**Interfaces:**
- Produces: schema that Task 7's generator validates against. Nothing else.

- [ ] **Step 1:** Edit `docs/schemas/run-report.schema.json`: in `properties.boot_ids`, change `"minItems": 1` to `"minItems": 0`. Rationale (R5): a run attached to a launch that fails before boot has zero boot identities in durable records; AT-094 requires a report in every terminal phase; inventing a boot id would be fabricated evidence.
- [ ] **Step 2:** Run `uv run docs/validation/check.py`. Expected: all checks pass.
- [ ] **Step 3:** Append a dated revision entry to `docs/VALIDATION.md` (match the existing entry format exactly; include the real check.py output summary and the R5 rationale). Never rewrite earlier revisions.
- [ ] **Step 4:** Commit: `docs(schemas): allow zero boot_ids in run reports for never-booted runs`

---

### Task 2: Register run.* event kinds

**Files:**
- Modify: `internal/events/registry.go` (append to `registry` slice)
- Test: `internal/events/registry_test.go`

**Interfaces:**
- Produces: registered kinds `run.created`, `run.state_changed`, `run.progress`, `run.result_recorded`, `run.submission_rejected`. Ingress (store.Append) accepts them once registered — no other code change needed.

- [ ] **Step 1:** Write failing tests in `registry_test.go` (follow the existing table-driven pattern): each of the five kinds resolves via `LookupKind`, with `Family: "run"`, `SchemaVersion: 1`, and provenance `GuestReported` for `run.progress`, `HostObserved` for the other four.
- [ ] **Step 2:** Run `env -u GOROOT mise exec -- go test ./internal/events/...`. Expected: FAIL (kinds unregistered).
- [ ] **Step 3:** Append five `KindInfo` entries to `registry`:
  - `run.created` — semantics: "A declarative run was created and bound to a VM. Data carries run_id, vm_id, goal, success_criteria, on_completion, progress_events, and the initial phase." Caveat: "creation is not evaluation; the outcome exists only in the terminal run.state_changed".
  - `run.state_changed` — semantics: "A run phase transition. Data carries run_id, vm_id, from, to, and on terminal transitions outcome fields (evaluated_by, reason)." Caveat: "terminal outcome stands even if a later report generation fails".
  - `run.progress` (GuestReported) — semantics: "Bounded structured progress submitted by the guest workload. Data carries run_id, vm_id, seq, and the payload." Caveats: "guest-supplied content: tamperable in developer_root and not verified by the host"; "seq orders submissions within one run".
  - `run.result_recorded` — semantics: "Trusted ingress recorded a guest-submitted final result. Data carries run_id, vm_id, status, and size_bytes; the full result is served on the run resource." Caveat: "the event is host_observed (the recording); the result content itself is guest-supplied and labeled guest_reported where served" (R3).
  - `run.submission_rejected` — semantics: "Ingress refused an oversized or malformed guest submission. Data carries run_id, vm_id, submission (progress|result), reason, and size_bytes." Caveat: "rejection is bounded and durable; the refused payload is not retained" (R6).
- [ ] **Step 4:** Run `env -u GOROOT mise exec -- go test ./internal/events/...`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(events): register run.* event kinds`

---

### Task 3: Store — runs table, phase machine, idempotent create

**Files:**
- Modify: `internal/store/store.go` (append migration v6)
- Create: `internal/store/runs.go`
- Test: `internal/store/runs_test.go`

**Interfaces:**
- Consumes: `appendSystemInTx`, `scanVMInTx`, transition/idempotency patterns from `internal/store/vms.go` (study `CreateVMWithOperation`, `TransitionVM` before writing code).
- Produces (later tasks rely on these exact names):

```go
type Run struct {
    RowID          int64
    RunID          string // uuid
    VMID           string
    Owner          string
    Goal           string
    CriteriaType   string // exec_exit_zero | guest_result | operator_verdict
    OnCompletion   string // keep_running | stop  (stop_and_finalize refused upstream, R2)
    ProgressEvents bool
    Phase          string
    EvaluatedBy    string // "", or exec_exit|guest_result|operator|system on terminal
    Reason         string // outcome/interruption reason, "" until set
    ResultJSON     string // "" until a result is recorded
    ResultStatus   string // "" | succeeded | failed
    IdempotencyKey *string
    RequestHash    string
    CreatedEventID int64  // event_id of run.created — report window start
    ConcludedEventID int64 // event_id of terminal run.state_changed, 0 until terminal
    CreatedAt, StartedAt, ConcludedAt, UpdatedAt string // StartedAt/ConcludedAt "" until set
}

type CreateRunInput struct {
    VMID, Owner, Goal, CriteriaType, OnCompletion string
    ProgressEvents bool
    IdempotencyKey *string
    RequestHash    string
    InitialPhase   string // "pending" (launch-attach) or "running" (standalone on a running VM)
}

func (s *Store) CreateRun(ctx context.Context, in CreateRunInput) (*Run, bool, error) // (run, isReplay, err)
type RunTransitionInput struct {
    RunID, From, To string
    Reason, EvaluatedBy string // recorded on terminal transitions
}
func (s *Store) TransitionRun(ctx context.Context, in RunTransitionInput) (*Run, error)
func (s *Store) GetRun(ctx context.Context, runID string) (*Run, error)
type RunQuery struct { VMID, Phase, After string; Limit int }
func (s *Store) ListRuns(ctx context.Context, q RunQuery) ([]*Run, string, error) // (runs, nextAfter, err)
func (s *Store) ActiveRunForVM(ctx context.Context, vmID string) (*Run, error) // nil, nil when none
func (s *Store) ListRunsInPhases(ctx context.Context, phases ...string) ([]*Run, error)
var ErrRunNotFound = errors.New(...)
var ErrActiveRunExists = errors.New(...)
type InvalidRunTransitionError struct{ RunID, From, To string }
```

- [ ] **Step 1:** Append migration v6 to `store.go`:

```sql
CREATE TABLE runs (
    row_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL UNIQUE,
    vm_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    goal TEXT NOT NULL,
    criteria_type TEXT NOT NULL,
    on_completion TEXT NOT NULL,
    progress_events INTEGER NOT NULL DEFAULT 0,
    phase TEXT NOT NULL,
    evaluated_by TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    result_json TEXT NOT NULL DEFAULT '',
    result_status TEXT NOT NULL DEFAULT '',
    idempotency_key TEXT,
    request_hash TEXT NOT NULL,
    created_event_id INTEGER NOT NULL,
    concluded_event_id INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    started_at TEXT NOT NULL DEFAULT '',
    concluded_at TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_runs_idem ON runs (owner, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX idx_runs_active ON runs (vm_id) WHERE phase IN ('pending','running','concluding');
CREATE INDEX idx_runs_vm ON runs (vm_id, row_id);
CREATE TABLE run_reports (
    run_id TEXT PRIMARY KEY,
    report_json TEXT NOT NULL,
    digest TEXT NOT NULL,
    operation_id INTEGER NOT NULL,
    generated_at TEXT NOT NULL
);
```

- [ ] **Step 2:** Write failing tests in `runs_test.go` (real SQLite via the existing test-open helper). Cover, at minimum:
  - Create with `InitialPhase: "running"` sets `started_at`, emits `run.created` (query events table: kind, data.run_id, data.phase), returns replay=false; `CreatedEventID` matches the emitted event.
  - Create with same owner+idempotency_key+request_hash returns the SAME run, replay=true, no second event row. Same key different hash → `ErrIdempotencyConflict` (reuse the existing exported error from batches/vms — check its name in `vms.go`/`batches.go` and use it, don't mint a new one).
  - NULL idempotency keys never replay each other (two creates, two runs).
  - Second non-terminal run on the same VM → `ErrActiveRunExists` (the partial index fires; map the constraint error). A terminal run + new create succeeds.
  - `TransitionRun` legal edges from the phase-machine table all succeed and emit `run.state_changed` with from/to in data; terminal transitions require and record `EvaluatedBy`+`Reason`, set `concluded_at` and `concluded_event_id`.
  - Illegal edges (`pending→succeeded`, `running→succeeded`, `succeeded→running`, `concluding→running`) → `InvalidRunTransitionError`; a From pin that doesn't match current phase → `InvalidRunTransitionError` (stale caller walks away, per gotchas).
  - Terminal transitions bump the VM's `last_event_id` (situation `?since` delta must notice run conclusions — assert `vms.last_event_id` equals the run.state_changed event id). Non-terminal transitions bump it too (active_run phase is in the situation summary).
  - `ActiveRunForVM` returns the one non-terminal run, nil when none. `ListRuns` pages by `row_id` keyset (After cursor semantics identical to events `next_after`: decimal row_id, exclusive), filters by VMID and Phase, bounded by `DefaultPageLimit`/`MaxPageLimit`.
- [ ] **Step 3:** Run `env -u GOROOT mise exec -- go test ./internal/store/ -run TestRun`. Expected: FAIL (compile — types missing).
- [ ] **Step 4:** Implement `runs.go`. Requirements beyond the signatures: run_id = `uuid.NewString()`; all writes in single writer transactions; events via `appendSystemInTx` with envelope vm_id null and run/vm linkage in data (host-wide stream constraint); a `validRunTransitions` map mirroring the phase-machine section verbatim; `TransitionRun` reads the row `FOR UPDATE`-equivalent (single writer makes plain SELECT safe), checks `in.From` against stored phase before checking edge legality; VM `last_event_id` update in the same tx.
- [ ] **Step 5:** Run `env -u GOROOT mise exec -- go test ./internal/store/...`. Expected: PASS, including all pre-existing tests (migration v6 must not disturb v1–v5).
- [ ] **Step 6:** Commit: `feat(store): runs table with guarded phase machine and idempotent create`

---

### Task 4: Store — guest submissions, launch-attach, batch-member runs, report rows

**Files:**
- Modify: `internal/store/runs.go`, `internal/store/vms.go` (CreateVMWithOperation), `internal/store/batches.go` (CreateVMBatch)
- Test: `internal/store/runs_test.go`, `internal/store/vms_test.go`, `internal/store/batches_test.go`

**Interfaces:**
- Consumes: Task 3's types; `CreateVMInput`/`BatchMemberInput` shapes in `vms.go`/`batches.go`.
- Produces:

```go
// On CreateVMInput and on the batch member input struct (find its name in batches.go):
Run *RunAttachment // nil = no run
type RunAttachment struct {
    Goal, CriteriaType, OnCompletion string
    ProgressEvents bool
}
// CreateVMWithOperation creates the run (phase pending, owner = VM owner, no separate
// idempotency key — the VM create's key covers the whole submission) in the SAME tx.
// Replays return the same run. New method for callers to fetch it:
func (s *Store) RunForVM(ctx context.Context, vmID string) (*Run, error) // most recent run for vm, ErrRunNotFound if none

type SubmitProgressInput struct { RunID string; Payload json.RawMessage; MaxBytes int64 }
func (s *Store) SubmitRunProgress(ctx context.Context, in SubmitProgressInput) (seq int64, err error)
type SubmitResultInput struct { RunID string; Result json.RawMessage; MaxBytes int64 }
func (s *Store) SubmitRunResult(ctx context.Context, in SubmitResultInput) (*Run, error)
var ErrSubmissionRejected = errors.New(...) // wrapped with the bounded reason
var ErrRunNotAcceptingSubmissions = errors.New(...) // run not in pending/running

func (s *Store) PutRunReport(ctx context.Context, runID, reportJSON, digest string, operationID int64) error
type RunReport struct { RunID, ReportJSON, Digest, GeneratedAt string; OperationID int64 }
func (s *Store) GetRunReport(ctx context.Context, runID string) (*RunReport, error) // ErrReportNotFound if absent
var ErrReportNotFound = errors.New(...)
```

- [ ] **Step 1:** Write failing tests:
  - Launch-attach: `CreateVMWithOperation` with `Run` set creates VM + operation + run (phase `pending`) atomically; `run.created` event exists; idempotent replay returns the same run_id (assert via `RunForVM` after both calls). Admission refusal → no run row (whole tx rolled back — assert `RunForVM` → `ErrRunNotFound`).
  - Batch: members with `Run` set each get a pending run in the batch tx; refused members (best_effort partial admission) get NO run.
  - Progress: valid payload within MaxBytes → `run.progress` event (GuestReported provenance comes from the registry; assert data.run_id, data.seq); seq increments 1,2,3 across calls; payload over MaxBytes → `ErrSubmissionRejected` AND a `run.submission_rejected` event with reason + size_bytes; invalid JSON → rejected likewise; run in `concluding`/terminal → `ErrRunNotAcceptingSubmissions` (no event); progress on a run created with `ProgressEvents: false` → `ErrSubmissionRejected` with reason `progress_events disabled for this run`.
  - Result: valid `{"status":"succeeded","detail":"..."}` → stored on row (`ResultJSON`, `ResultStatus`), `run.result_recorded` event with status+size_bytes, run returned with phase UNCHANGED (conclusion is the Manager's job); result missing `status` or status ∉ {succeeded, failed} → rejected + `run.submission_rejected`; oversized → rejected; second result → rejected with reason `result already recorded` (first result stands — never silently overwrite evidence); `detail` over 1024 bytes → rejected.
  - Report rows: Put then Get round-trips; Get absent → `ErrReportNotFound`; Put twice → second Put refused (report is immutable once stored; error naming the existing digest) — regeneration only happens when no report exists.
- [ ] **Step 2:** Run store tests. Expected: FAIL.
- [ ] **Step 3:** Implement. Progress seq: `SELECT COUNT(*) FROM events WHERE kind='run.progress' AND json_extract(payload,'$.data.run_id')=?` is O(n) — instead store a `progress_seq INTEGER NOT NULL DEFAULT 0` counter column on runs (increment in the submission tx). Add the column to the v6 migration (v6 is unreleased — editing it is safe while it has shipped nowhere; do NOT add a v7).
- [ ] **Step 4:** Run `env -u GOROOT mise exec -- go test ./internal/store/...`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(store): guest submission ingress, launch-attached runs, report rows`

---

### Task 5: /events family and until filters

**Files:**
- Modify: `internal/store/query.go`, `internal/api/events.go`
- Test: `internal/store/query_test.go` (or `store_test.go` — wherever Query is tested), `internal/api/api_test.go`

**Interfaces:**
- Consumes: `events.Kinds()` (registry — family expansion), existing `store.Query`.
- Produces: `store.Query` gains `Family string` and `Until string` (decimal event_id, inclusive upper bound; "" = no bound). API accepts `?family=` and `?until=`. These make report `reproduce_query` strings executable: `/api/v1/events?vm_id=X&family=F&after=A&until=B`.

- [ ] **Step 1:** Write failing store tests: family filter returns only kinds whose registry `Family` matches (seed events of ≥2 families via Append); unknown family → typed error (add `ErrUnknownFamily`); `Until` bounds the page inclusively (seed 5 events, after=id1&until=id3 → events 2,3); family+kind both set → error (`ErrConflictingFilters` — one axis at a time keeps reproduce queries unambiguous).
- [ ] **Step 2:** Write failing API tests: `?family=run` filters; `?family=nope` → 400 `malformed_request` cause `family_unknown` with remediation pointing at `/meta/event-kinds`; `?until=abc` → 400 cause `query_parameter_invalid`; `?kind=X&family=Y` → 400 cause `conflicting_filters`.
- [ ] **Step 3:** Run tests. Expected: FAIL.
- [ ] **Step 4:** Implement: family→kinds expansion via registry at query time (`kind IN (...)`), `Until` parsed like the After cursor (decimal, else `ErrInvalidCursor`).
- [ ] **Step 5:** Run `env -u GOROOT mise exec -- go test ./internal/store/... ./internal/api/...`. Expected: PASS.
- [ ] **Step 6:** Commit: `feat(api): family and until filters on /events for reproducible rollups`

---

### Task 6: Runtime — run engine (create, conclude, on_completion, reconcile)

**Files:**
- Create: `internal/runtime/runs.go`
- Modify: `internal/runtime/manager.go` (CreateRequest gains `Run *store.RunAttachment`; launch/stop/fail paths call the VM-terminal and VM-running hooks; `Reconcile` sweeps runs), `internal/runtime/batch.go` (member run threading)
- Test: `internal/runtime/runs_test.go` (fake runtime)

**Interfaces:**
- Consumes: Task 3/4 store surface; existing Manager patterns (`doAction`, `failLaunch`, `Reconcile`, worker `wg` + Close ordering — study `manager.go` first; gotchas: `wg.Wait()` BEFORE `cancel()`, From pins, `IfState: "running"`).
- Produces:

```go
type RunRequest struct {
    VMID, Owner, Goal, CriteriaType, OnCompletion string
    ProgressEvents bool
    IdempotencyKey *string
}
func (m *Manager) CreateRun(ctx context.Context, req RunRequest) (*store.Run, bool, error) // standalone; VM must be observed running
func (m *Manager) ConcludeRun(ctx context.Context, runID string, verdict *string, abort bool, reason string) (*store.Run, error)
func (m *Manager) SubmitRunProgress(ctx context.Context, runID string, payload json.RawMessage) (int64, error)
func (m *Manager) SubmitRunResult(ctx context.Context, runID string, result json.RawMessage) (*store.Run, error)
// Errors the API maps: ErrVMNotRunning, ErrRunConcluded (conclude on terminal run),
// ErrVerdictCriteriaMismatch (verdict on non-operator_verdict run), store errors pass through.
```

Internal design (implement exactly this shape):
- `concludeRun(ctx, runID, trigger concludeTrigger)` — single conclusion path. Transition to `concluding` with From pin (loser of a race gets `InvalidRunTransitionError` and walks away silently); evaluate per the plan's truth table; `TransitionRun` to terminal; then post-terminal actions: on_completion `stop` → reuse the existing action path as a system-initiated stop operation on the VM (only if VM still observed running/paused; skip silently if already stopping/stopped); enqueue report generation (Task 7 wires the generator — this task leaves a `m.reportGen func(runID string)` field, nil-safe no-op when unset, set in Task 7; tests here assert it was invoked via a recorded stub func, which is call-recording on our own seam, not a mock of behavior under test).
- VM hooks: after every successful `TransitionVM` inside manager code paths, two checks: transition to `running` → `ActiveRunForVM` pending run → `TransitionRun pending→running` (sets started_at); transition to `stopped`/`failed` → active run in pending/running/concluding → `concludeRun(vmTerminal)`. Grep every `TransitionVM` call site in `manager.go`/`batch.go` and thread the hooks — a missed site is a run that never concludes (Reconcile is the net, not the path).
- `Reconcile` addition: `ListRunsInPhases("pending","running","concluding")`; for each, if VM is stopped/failed/deleted → `concludeRun(interrupted)` with reason `interrupted: daemon restarted; vm no longer live` (AT-093 explicit interruption reason); if VM live → leave alone (event-driven hooks own it). Also: terminal runs with no stored report and no running report op → re-enqueue report generation (R7).

- [ ] **Step 1:** Write failing tests (fake runtime; remember `CPUOvercommitRatio > 0` in test admission config, per gotchas):
  - Standalone create on running VM → phase running; on provisioning/stopped/paused VM → `ErrVMNotRunning`.
  - Launch-attach: CreateVM with Run → run pending; fake completes launch → run transitions to running (started_at set). Fake launch failure (`FailCall("Launch", ...)`) → run concludes `inconclusive`, evaluated_by `system`, reason contains `vm launch failed` (R8).
  - operator_verdict happy path: ConcludeRun with verdict `succeeded` → phases running→concluding→succeeded, evaluated_by `operator`; verdict on guest_result run → `ErrVerdictCriteriaMismatch`; abort on any non-terminal run → `aborted` with reason; conclude on terminal run → `ErrRunConcluded`.
  - guest_result: SubmitRunResult (status failed) → run concludes `failed`, evaluated_by `guest_result`; VM stops before any result → `inconclusive` evaluated_by `system`.
  - exec_exit_zero: VM stop → `inconclusive`, reason mentions exec capability (R9).
  - on_completion stop: guest_result run with `stop` → after conclusion the VM reaches stopped through the fake (assert eventual observed_state via store polling, the store-state pattern from gotchas); `keep_running` → VM stays running.
  - Conclusion race: result submission and VM-stop racing → exactly one terminal outcome, no error surfaced (loser walked away); assert single terminal `run.state_changed` event.
  - Reconcile: seed store with a running-phase run whose VM row says stopped (write directly via store transitions before NewManager); NewManager+Reconcile → run `inconclusive` with `interrupted` reason.
  - Report enqueue: stub `reportGen` records the runID on every terminal path (verdict, result, abort, vm-terminal, launch-fail).
- [ ] **Step 2:** Run `env -u GOROOT mise exec -- go test ./internal/runtime/...`. Expected: FAIL.
- [ ] **Step 3:** Implement per the internal design above.
- [ ] **Step 4:** Run the full package suite. Expected: PASS including all P3 tests (hooks must not break existing lifecycle paths).
- [ ] **Step 5:** Commit: `feat(runtime): run engine — conclusion orchestration, completion policy, interruption reconcile`

---

### Task 7: Report generation

**Files:**
- Create: `internal/report/report.go` (types mirroring the schema), `internal/report/generate.go`
- Modify: `internal/runtime/runs.go` + `manager.go` (wire real generator as a report operation)
- Test: `internal/report/generate_test.go`, `internal/report/schema_test.go` (external package `report_test` — it imports `internal/api`, which imports `internal/runtime`, which imports `internal/report`; the external test package breaks the cycle)

**Interfaces:**
- Consumes: store runs/reports/query surface; `/events?family=&until=` (Task 5); attention items store queries (see `internal/store/attention.go` for the list/query surface).
- Produces:

```go
package report
type Options struct { TailMaxBytes int64 } // from cfg.AgentInterface.ReportTailMaxBytes; unused until execs exist but part of the contract
func Generate(ctx context.Context, st *store.Store, runID string, opts Options) (json.RawMessage, string, error) // (canonical JSON, sha256:<hex> digest, err)
```

Generation rules (deterministic rollup of durable records; NOTHING invented):
- Only terminal-phase runs generate; a non-terminal run → error (the Manager only calls post-terminal; the guard is honesty, not flow).
- Window: events with `event_id > run.CreatedEventID AND event_id <= run.ConcludedEventID`, VM-scoped. Because store-synthesized events ride the host-wide stream with vm_id in data, the rollup matches events by `vm_id` column OR `json data.vm_id`/`data.run_id` equal to this run's — implement one SQL helper in the report package using the store's reader pool via a new narrow store method `CountEventsForReport(ctx, vmID, runID string, family string, afterID, untilID int64) (int64, error)` added in this task (keeps SQL in the store package). The matching reproduce_query is `/api/v1/events?vm_id=<vm>&family=<f>&after=<A>&until=<B>` — and for the counts to reproduce, the API family filter must apply the same vm-or-data matching; extend Task 5's implementation here if the round-trip test exposes drift (the test is the authority).
- `boot_ids`: distinct non-empty `data.boot_id` values on `vm.state_changed` events in window (may be empty — Task 1).
- `outcome`: from run row; `evidence_links` always includes `/api/v1/events?kind=run.state_changed&vm_id=<vm>&after=<concluded-1>&until=<concluded>` (the terminal record) plus, when a result exists, `/api/v1/runs/<id>` .
- `timing`: created/started/concluded from row (started_at "" → null).
- `execs`: `[]` (none exist; honest empty).
- `event_rollup`: per family present in window (count > 0 only), sorted by family, each with reproduce_query.
- `coverage`: `telemetry_health_final: "unavailable"`, gaps: `[{kind: "guest_channel_not_built", detail: "no guest telemetry channel exists in this build; guest-side facts limited to explicit submissions", evidence_link: "/api/v1/meta"}]` — the portable-core truth.
- `network_summary`: profile from VM row; flows/dns_queries/policy_denials counted via families `net.flow`/`dns`/`policy` (zero counts with reproduce queries are honest and reproducible).
- `filesystem_summary`: `live_mutation_events` from family `fs`; `final_diff: {status: "not_requested"}` (stop_and_finalize refused, R2).
- `artifacts`: `[]`. `anomalies`: omitted (schema-optional).
- `attention`: items where `run_id = <run>` OR (`vm_id = <vm>` AND raised_event_id in window), ascending attention_id, cap 128; overflow → `quality.truncated: true` + note.
- `quality`: truncated (any cap hit), redacted: false (no redaction applied to reports today), notes bounded.
- `links`: run `/api/v1/runs/<id>`, vm `/api/v1/vms/<id>`, events `/api/v1/events?vm_id=<vm>&after=<A>&until=<B>`.
- Canonical JSON: single `json.Marshal` of the typed struct (field order fixed by struct definition); digest = `sha256:` + hex of those bytes.

Manager wiring: report generation is an operation — kind `run.report_generate` (operations table, NOT the event registry), vm_id set, finalizers pin `IfState: "running"`. Async goroutine tracked by the manager `wg`. On success `PutRunReport` + op succeeded; on Generate/Put failure op failed with cause `report_generation_failed`; run outcome untouched either way (§8.7). Set `m.reportGen` to enqueue this operation.

- [ ] **Step 1:** `env -u GOROOT mise exec -- go get github.com/santhosh-tekuri/jsonschema/v6` AFTER writing the first import (gotcha: tidy prunes unimported deps).
- [ ] **Step 2:** Write failing tests:
  - `schema_test.go`: build a fleet scenario end-to-end against the fake-runtime manager (create VM with attached guest_result run, submit progress ×2, submit result succeeded, let conclusion + wired report op finish), load `../../docs/schemas/run-report.schema.json` (path per the established deviation: schemas live in docs/), compile with santhosh-tekuri, assert the stored report validates. Repeat for: aborted run, launch-failed run (never booted — boot_ids empty), operator_verdict run. Four terminal shapes, four validations (AT-092/AT-094 shape).
  - `generate_test.go` round-trip (THE P-05 test): for every `counted` field and every `event_rollup` entry in a generated report, execute its `reproduce_query` against a real `httptest.Server` wrapping `api.New(...)`, page through counting, assert equality with the report's count. Walk the report JSON generically (find every object holding both `count` and `reproduce_query`) so new counted fields can't dodge the test.
  - Determinism: generate twice on the same store → byte-identical JSON, identical digest (generated_at lives on the report ROW, not inside the report JSON — the schema has no generated_at field; timing comes from run records).
  - Manager wiring: terminal run → op `run.report_generate` succeeded + `GetRunReport` returns it; forced Generate failure (delete the run row? no — inject failure by pointing Generate at a runID with store closed? Simplest honest failure: a test hook is NOT acceptable in prod code — instead test retry via R7's reconcile path: seed terminal run with no report, NewManager+Reconcile → report appears).
- [ ] **Step 3:** Run. Expected: FAIL.
- [ ] **Step 4:** Implement `report.go` types (struct per schema, `additionalProperties: false` means no extra fields; `omitempty` only on schema-optional fields), `generate.go` per rules, store `CountEventsForReport`, manager wiring.
- [ ] **Step 5:** Run `env -u GOROOT mise exec -- go test ./internal/report/... ./internal/runtime/... ./internal/store/...`. Expected: PASS.
- [ ] **Step 6:** Commit: `feat(report): deterministic run reports with reproducible rollups`

---

### Task 8: API — runs endpoints

**Files:**
- Create: `internal/api/runs.go`
- Modify: `internal/api/api.go` (route table: five run routes get handlers; meta links gain `runs`), `internal/api/vms.go` (POST /vms body accepts `run` block), `internal/api/batches.go` (member `run` block)
- Test: `internal/api/runs_test.go`

**Interfaces:**
- Consumes: Manager surface from Task 6, store reports from Task 4, error-mapping conventions in `internal/api/errors.go` + `vms.go` (`writeVMError` — the batch lesson: ONE error mapping, never a parallel one).
- Produces (wire contracts):
  - `POST /vms/{id}/runs` body `{goal, success_criteria: {type}, on_completion, progress_events?, idempotency_key?}` → 201 `{run}` (+`is_replay: true` on replay). Validation: goal 1..`cfg RunGoalMaxBytes` bytes; type ∈ enum; on_completion ∈ {keep_running, stop} — `stop_and_finalize` → 501 `missing_capability`, cause `capability_not_built`, remediation listing `keep_running`/`stop` (R2). VM not running → 409 `conflict` cause `vm_not_running`. Active run exists → 409 cause `active_run_exists` with the existing run_id in details.
  - `POST /vms` + batch member: same `run` block nested (matches `launch-request.schema.json`), same validation, run rides the create tx.
  - `GET /runs?vm_id=&phase=&after=&limit=` → `{runs: [...], next_after}` keyset page.
  - `GET /runs/{id}` → full run: goal, criteria, phase, outcome {status(phase when terminal), evaluated_by, reason}, timing, `result` when recorded as `{provenance: "guest_reported", status, detail?, data?, received_at}` (R3), `progress_seq`, links {events window, report}.
  - `POST /runs/{id}/conclude` body `{verdict: "succeeded"|"failed", reason?}` XOR `{abort: true, reason}` → 200 `{run}`. Verdict on non-operator_verdict criteria → 409 cause `criteria_mismatch` + remediation (abort). Terminal → 409 cause `already_concluded` with outcome in details. Both/neither of verdict|abort → 400.
  - `GET /runs/{id}/report` → 200 `{status: "generated", generated_at, digest, report: {...}}` | 200 `{status: "pending"|"failed", operation_id, retryable: true}` (failed GET re-enqueues one attempt, R7). Unknown run → 404.
- Run JSON representation: phase/outcome strings as stored; `row_id` never serialized; timestamps RFC3339 as stored; no decimal-string fields needed (no unbounded counters in the run resource; `progress_seq` is bounded by submission caps — serialize as JSON number).

- [ ] **Step 1:** Write failing tests (httptest against `api.New` with fake-runtime manager — use the VM-capable server helper per gotchas): one test per contract bullet above, plus: `/meta` features.runs true + links.runs present; conclude flow end-to-end (create standalone operator_verdict run → conclude succeeded → GET run shows outcome → GET report eventually generated — poll store).
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement. Route table: replace the five nil `runs` entries with method+handler pairs (GET+POST split for `/runs/{id}/...` paths follows the existing pattern).
- [ ] **Step 4:** Run `env -u GOROOT mise exec -- go test ./internal/api/...`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(api): runs endpoints — create, inspect, conclude, report`

---

### Task 9: Situation — active_run and run_concluded trigger

**Files:**
- Modify: `internal/situation/engine.go` (rulesByKind gains `run.state_changed`), `internal/api/working_set.go` (per-VM summary gains `active_run`)
- Test: `internal/situation/engine_test.go`, `internal/api/working_set_test.go`

**Interfaces:**
- Consumes: `store.ActiveRunForVM`, `run.state_changed` event shape (Task 3), rule/raise plumbing in `engine.go` (study existing `lifecycle_failed` rule first).
- Produces: situation per-VM summary field `"active_run": {"run_id": "...", "phase": "..."}` (omitted when none — §12.7 example shape); trigger class `run_concluded` in `ActiveClasses()` when enabled in config.

- [ ] **Step 1:** Write failing engine tests: `run.state_changed` to `succeeded` raises attention severity `info`; to `failed`/`inconclusive`/`aborted` raises `needs_decision`; non-terminal transitions raise nothing; the item carries trigger_class `run_concluded`, the run's vm_id/run_id, evidence links (run + report paths), suggested actions (get report, ack); `ActiveClasses()` includes `run_concluded` when config enables it. Working-set test: VM with active run shows `active_run`; without shows no key; `?since` delta after a run transition includes the VM (Task 3 bumps last_event_id — assert it surfaces).
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement. Severity mapping is deterministic per the test list. Check the default/example config enables `run_concluded` wherever the other implemented classes are enabled (grep for `attention_triggers` defaults/examples).
- [ ] **Step 4:** Run `env -u GOROOT mise exec -- go test ./internal/situation/... ./internal/api/...`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(situation): active_run summaries and run_concluded attention trigger`

---

### Task 10: CLI — run subcommands

**Files:**
- Modify: `cmd/vmobs/main.go` (or wherever subcommands register — study the existing `vm`/`attention` subcommand structure and match it exactly)
- Test: `cmd/vmobs/main_test.go`

**Interfaces:**
- Consumes: Task 8 wire contracts; CLI conventions (exit codes 0/1/2/3; `--json` parity; flags BEFORE positional args — Go flag package, per gotchas).
- Produces:
  - `vmobs run submit --vm <id> --goal <text> --criteria <type> --on-completion <policy> [--progress-events] [--idempotency-key <k>]`
  - `vmobs run list [--vm <id>] [--phase <p>]`, `vmobs run get <run-id>`, `vmobs run report <run-id>`
  - `vmobs run conclude <run-id> (--verdict succeeded|failed [--reason r] | --abort --reason r)`
  - `vmobs vm create` gains `--run-goal`, `--run-criteria`, `--run-on-completion`, `--run-progress-events` (attach at launch; all-or-none validation: goal+criteria+on-completion together)

- [ ] **Step 1:** Write failing tests against a real httptest API server (existing `newServer` CLI-test pattern): submit on running VM → exit 0, human and `--json` outputs; structured refusal (VM not running) → exit 1 with the API error surfaced; conclude verdict flow → exit 0; report of unconcluded run → exit 0 printing pending status; usage errors (missing --goal, verdict+abort together) → exit 3.
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement matching existing subcommand style.
- [ ] **Step 4:** Run `env -u GOROOT mise exec -- go test ./cmd/...`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(cli): run subcommands — submit, list, get, conclude, report`

---

### Task 11: Smoke, PLAN.md close-out

**Files:**
- Modify: `scripts/smoke`, `PLAN.md`, `gotchas.md` (if new traps surfaced)

**Interfaces:** none new.

- [ ] **Step 1:** Extend `scripts/smoke` (live daemon on loopback, real CLI): `vmobs run submit` against a non-running VM → structured refusal exit 1; `run list` empty → exit 0; `run get` unknown id → exit 1; run routes reachable (no 501 from the five run paths); `/meta` shows features.runs true. On macOS no VM can run — the smoke asserts honest refusals, which is the served truth of this host.
- [ ] **Step 2:** Run `scripts/smoke` and `scripts/check`. Expected: both fully green.
- [ ] **Step 3:** PLAN.md: mark P4 done in the phase table; append deviation entries R1–R12 from this plan's rulings section (condensed, dated); append the session log entry (state, commits, next: P5).
- [ ] **Step 4:** Commit: `docs(plan): close P4 — runs and reports landed with deviations recorded`

---

## Self-review notes

- Spec coverage: §8.6 creation/attach/idempotency/phases/inconclusive-honesty (Tasks 3,4,6), progress/result submission + caps + rejection records (Task 4, AT-095), §8.7 report artifact + reproduce_query + retryable generation op (Task 7), API rows for runs (Task 8, AT-100 conclude), situation active_run + run_concluded (Task 9, §12.7), CLI loop shape (Task 10, AT-102 portable half), interruption reconcile (Task 6, AT-093 portable half). exec_exit_zero full path and guest vsock ingress are Linux-track by design; their portable seams exist (R9, R10).
- The one cross-task risk: report round-trip (Task 7) may force the Task 5 family filter to match data-scoped vm ids; Task 7's brief owns that adjustment explicitly.
- Migration v6 is edited (not appended past) within this plan only while unreleased — Tasks 3 and 4 both touch it; Task 4 notes the rule.
