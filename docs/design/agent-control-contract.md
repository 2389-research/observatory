<!-- ABOUTME: Maps the pinned v1 agent protocol to v2's executable bounded HTTP slice. -->
<!-- ABOUTME: Separates implemented discovery/recovery from deferred approval, budgets and checkpoints. -->

# Agent control contract and gap map

Kata `3tn6`. Reference: sibling `observatory` commit
`d432cdced2a346974bf3ca1afa20b56c96c890be`, specifically
`docs/AGENT-PROTOCOL.md`, `docs/plans/agent-first-system.md` and
`docs/ACCEPTANCE.md`. The source is a design reference, not implementation evidence.
`docs/SPEC.md` §14.2 binds the slice described here.

Doctor Biz delegated the design and completion on 2026-09-08. The earlier
review-only gate is superseded by that authorization. The choice is additive
metadata on existing routes, concrete resource links, honest summary omissions
and conservative error recovery. SQLite remains the single control authority.
No guest, privileged protocol, authentication boundary or schema migration is
part of this slice.

## What exists, checked against code

| v1 verb/object | v2 implementation and limit |
|---|---|
| Describe / manifest (§5.2, §7) | `api.New` generates `meta.routes` and collection `links` from its route table. Each route has method, path template, feature and built state. `describeRoute` adds typed examples/instructions for the first slice. `meta.agent` states workflow, resume and deferred capabilities. This is not OpenAPI or a complete schema catalog. |
| Snapshot (§5.3) | `api.handleSituation` uses `situation.Engine.Snapshot`. `as_of_cursor`, `since_cursor`, watch scope, host counts, attention and changed VMs are live projections from separate reads, not an atomic historical snapshot. `attention_open` and `omitted` describe section loss. |
| Query | `api.handleEvents` / `store.Query`: bounded keyset pages with exclusive `after`, inclusive optional `until`, `next_after` and `latest_event_id`. `GET /vms` and `/runs` have separate bounded collection cursors. No generic cross-resource query language. |
| Apply / safe replay (§5.5) | `api.handleCreateVM`, `runtime.Manager.CreateVM`, `store.CreateVMWithOperation`: authenticated owner, canonical request hash, idempotency key and atomic VM/run/operation/reservation creation. Exact keyed launch replay returns the same VM and operation; changed payload conflicts. Unkeyed launch and lifecycle actions are not replay-transparent. |
| Revision-bound action | `api.handleVMAction` requires `expected_revision`; the runtime/store apply the transition pin. This is concurrency control, not human approval of an exact plan. Boot identities and reservation accounting remain the existing runtime/store contracts. |
| Watch (§5.5, §7) | `wireOperation.links.self` is directly pollable; VM links include self/actions/runs. `/events/stream` remains a 501 stub. A pre-mutation snapshot cursor provides a conservative event anchor; no mutation `watch_cursor` is implemented. |
| Explain / problem (§5.6) | `api.writeError` emits `retry_strategy`. Known stale revisions/cursors require refresh; errors carrying operations require querying them; limit/capacity or other retryable failures require a precondition; other failures default to never. `writeVMErrorForOperation` resolves known VM/operation placeholders. No general state-explanation endpoint. |
| Evaluate (§5.7) | `handleConcludeRun`, `renderRun`, `handleGetRunReport`, `report.Generate`, wired before reconciliation in `cmd/vmobsd.serve`: operator-verdict runs carry an explicit operator outcome; guest result fields are present only when guest result ingestion actually occurred. Reports carry a digest and reproduce queries. Run self/conclude/report links are executable. |
| Checkpoint (§5.8) | Client-owned handoff file containing exact request, cursor and returned resource links. Server records survive client reconnection; no checkpoint object, server-side handoff storage, checkpoint provenance or retention-gap detection exists. |
| Budget (§5.9) | Host admission reservations for memory/vCPU/disk. No per-work budget, usage ledger or budget-exhaustion stop. Runtime timeout budgets are lifecycle deadlines, not an implementation of v1 work budgets. |

`vmobs --json meta`, `vmobs --json situation`, `vmobs --json events` and the
raw `vmobs --json api` command expose these same JSON fields. No parallel
controller or renamed v1 command family is introduced. VM, operation and run
resources retain owner scope; situation/events describe shared host observation.
Neither those views nor a client handoff should be called owner-private storage.

## Cold-agent flow

The bootstrap is `GET /api/v1/meta` (not v1's `GET /api/v1`). Only credentials
and this path are needed; subsequent paths and mutation examples come from
`routes`, and concrete resource paths from response `links`.

1. Read metadata, capacity and templates. Select a returned template. Read the
   situation, its watch scope and `omitted` entries. Save `as_of_cursor` before
   any mutation, together with the exact launch example after replacing its
   named placeholders. Use a unique nonempty idempotency key.
2. Submit the discovered launch example with its attached `operator_verdict`
   run. Poll `operation.links.self`; inspect `vm.links.self` and `vm.links.runs`.
   If the launch response was lost, repeat the saved keyed body exactly. Do not
   change the key to recover an uncertain response.
3. Assess the actual evidence, submit the discovered conclude example, then
   read `run.links.self` and `run.links.report`. A successful caller verdict
   asserts the caller's judgment; it does not manufacture a guest result.
4. Refresh the VM, then submit the discovered stop example with that revision.
   A stale revision uses `after_refresh`: read and reassess. An error carrying
   an operation offers its concrete read link. A lost action response requires
   inspection, not an automatic repeat.
5. Persist resource links and the event cursor in the caller's own durable
   handoff. On reconnect read the operation/run/VM links and request bounded
   events after the saved cursor. Process the entire page, then save only
   `next_after`. Preserve filters. Never advance to `latest_event_id` without
   consuming intervening pages. Use `until` to freeze an event interval.

An empty event page preserves `next_after`. Cursor resume assumes the same
SQLite installation and retained history. Replacing/restoring the database can
invalidate anchors; v2 does not detect that as a typed retention gap. Situation
`since` is orientation, not proof that all events through `as_of_cursor` were
consumed. The snapshot's separate live reads may observe later state.

## Snapshot omission contract

`omitted.attention_head` and `omitted.changed_vms` each contain `count` and
`expand`. Counts include both the item cap and subsequent byte shedding.
`at_least:true` marks a lower bound: the changed-VM query reads at most 51 rows,
returns at most 50, and refuses to invent a total beyond that. Without
`at_least`, the count describes the rows observed by that read. The attention
count comes from the engine's open-queue count. Concurrent queue updates may
change a later expansion.

Attention expands through its bounded queue endpoint. Changed VMs expand to
`/vms`, a current owner-scoped inventory, not a historical delta or a full
host-wide reconstruction. Raw host observations remain available through the
event cursor. With no `since`, `changed_vms` intentionally stays empty; the
inventory is a separate read. Counts and watch scope survive byte shedding.
A configured ceiling that cannot fit the irreducible watch/omission envelope
returns 503 `situation_envelope_exceeds_bound`, with configured/minimum bytes
and a configuration remediation. The fixed error envelope is exempt from the
situation-summary ceiling; no successful response silently exceeds it. The
700-byte shedding and 100-byte refusal fixtures exercise both cases.

## Supplemental acceptance scenarios

These are v2-owned scenario identifiers, separate from the fixed 102-row AT
evidence registry. The earlier AT-103..106 labels were proposals and never
allocated. v1 AT-089..095 already mean different things in v2 and are not reused.

| ID | Required observation | Executable evidence |
|---|---|---|
| V2-AGENT-001 | Discover launch request/path, use a returned template, reach running, poll linked operation, conclude operator run, fetch linked digest report, then perform a revision-bound stop. | `tests/integration/agent_contract_gate_test.go: TestKataAgentContractGate`; API metadata/link seam tests in `internal/api/agent_contract_test.go`. |
| V2-AGENT-002 | Exceed attention head and byte bounds; report open/omitted counts and expansion. Exceed 50 changed VMs and report a lower-bound omission, never a fabricated exact total. | `TestAgentSnapshotReportsOmissions`, `TestSituationResponseByteBound`, `TestAgentChangedVMOmissionsAreLowerBounded`, `TestAgentSituationRefusesImpossibleByteCeiling`. |
| V2-AGENT-003 | Exact keyed launch returns the same VM/operation. Persist a processed event-page cursor and resource links in a file, reload them, resume bounded pages with no duplicates or missing events against the frozen interval. | `TestKataAgentContractGate`. This tests client reconnection, not daemon/database restore or server checkpoints. |
| V2-AGENT-004 | A stale revision offers `after_refresh` and concrete VM read; operation failures offer `query_operation`; malformed cursor and oversized page teach distinct recovery; unavailable stream says `never`. | `TestAgentStaleRevisionRecoveryUsesConcreteRead`, `TestAgentErrorsDeclareSafeRecovery`, `TestNamingTheOperationAddsSafeRecovery`, plus the KVM stale-action path. |

The first real gate exposed missing daemon report wiring: package tests had wired the generator, while `serve` had not. `TestServeGeneratesReportsForDurableTerminalRuns` now proves the real startup constructor recovers a stored terminal run into a generated report.

Local API seam tests use real HTTP/SQLite and a runtime unit fixture. They are not
Firecracker evidence. The Linux gate uses the real daemon, runner, Firecracker
and authenticated HTTP. Final execution status belongs in `docs/VALIDATION.md`
and the kata completion evidence, not in inferred claims from this source map.

## Exact approval design — unimplemented

Reference `AGENT-PROTOCOL.md` §§5.4–5.5 and §8. A future plan is immutable and
side-effect free: exact targets/revisions, canonical request digest, material
capability/policy/precondition bindings, impact class, resource quote with
measurement quality, expiry and non-guarantees. Planning reserves nothing.
Apply revalidates the exact digest and all material bindings before effects.

A human approval must bind human identity/authentication context, plan digest,
allowed targets/actions, maximum resource/security delta, expiry and single-use
policy. Acceptance atomically consumes it into one operation ID. Exact replay,
query, reconciliation and owned stop/cleanup remain valid after consumption or
expiry; another operation gets `approval_consumed`. A material pre-acceptance
change invalidates the approval. Grants, capability facts and human approval
are distinct. Neither an idempotency key nor `expected_revision` substitutes
for this approval. No public plan/apply/approval route is implemented.

## Budget design — unimplemented

Reference `AGENT-PROTOCOL.md` §5.9 and v1 AT-095. Future limits are hierarchical
(host, principal, work, run, VM, exec/artifact), with limit, reserved, used,
remaining, projected use, unit, enforcement and measurement quality per dimension.
Dimensions include wall time, guest CPU, boot/exec counts, RAM reservation, disk,
egress, event and artifact bytes. Tokens/money require harness measurements;
unknown spend is unknown, never zero. Estimates include sample count, runtime
tuple and recency. Admission must reserve against hard limits atomically, then
settle actual use. Hard exhaustion stops further costly work while preserving
read-only context, evidence, owned stop and cleanup. No enforcement is claimed
for these dimensions today.

## Implementation follow-ups

| Item | Source → destination | Completion condition |
|---|---|---|
| Durable server checkpoints | v1 §5.8 → new owner-scoped store object, `internal/api`, `cmd/vmobs` | Bounded append-only agent assertions with anchor/references/next actions; read authorization, exact retry identity, restart test. Add only when server-owned handoff is needed. |
| Mutation watch cursor | v1 §5.5/§7 → `store` operation event linkage, `renderOperation` | Stable pre-effect cursor survives exact replay and operation lookup; cannot skip early operation events. |
| Cursor retention/install identity | v1 AT-094 / §5.8 → `store.Query`, events API and client handoff | Detect replaced history and pruned anchors; return typed gap/earliest cursor instead of silent continuity. Required before claiming restore/retention-safe resume. |
| Full request schemas | v1 §5.2/§7 → route metadata generation and API schema endpoint | Generate every request/result schema and required constraints from executed definitions; current examples cover only the first slice. |
| Exact approval | v1 §5.4/§8 → design/SPEC review, store transaction, runtime/API | Implement the exact consumption/replay rules above before adding a multi-step or approval-gated intent. |
| Per-work budgets | v1 §5.9 / AT-095 → admission/store, work/run model, report | Measured dimension ledger and exhaustion tests preserving evidence/cleanup; host reservations alone do not close it. |

Evaluated-knowledge caches, generalized workflows, recipes, multi-agent leases
and fencing remain deferred until a concrete need. No v1 controller, cell store
or broad roadmap is transplanted.
