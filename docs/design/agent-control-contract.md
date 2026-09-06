<!-- ABOUTME: The contract/gap map between v1's bounded agent control protocol and v2's built API. -->
<!-- ABOUTME: A review artifact, not a contract: nothing here is binding until it lands in SPEC.md. -->

# Agent control contract — what v2 has, what it lacks

Kata `3tn6`. Source: `../observatory/docs/AGENT-PROTOCOL.md`,
`../observatory/docs/plans/agent-first-system.md` and `../observatory/docs/ACCEPTANCE.md`,
all pinned at `d432cdc` (2026-09-05 review).

## 0. What this document is

A gap map for review. It states, row by row, which parts of v1's agent control
protocol v2 already implements, which it implements differently, and which it
does not have — with a pointer to the code behind every "v2 has this" claim.

**It is not a contract.** `docs/SPEC.md` is the binding contract, and nothing
here changes it. The kata that produced this document authorizes backlog and
design work, not an unreviewed API or security-boundary change. Every proposed
route below is marked unimplemented and stays unimplemented until Doctor Biz
reviews this page and a change lands in `SPEC.md` and `ACCEPTANCE.md`.

**Every "v2 has this" row was read against the code, not against the spec.**
That is the difference between "`/events/stream` is specified" and what
`api.New` actually registers, which is a stub answering 501. Citations name a
file and a symbol rather than a line number: line citations into code rot
silently, because `check.py` validates the docs package's structure and never
opens a Go file.

## 1. The nine verbs

v1's machine-facing CLI has nine semantic verbs (`AGENT-PROTOCOL.md` §7). v2's
`cmd/vmobs` has twelve resource-shaped ones (`meta`, `events`, `situation`,
`attention`, `vm`, `run`, `operation`, `template`, `host`, `doctor`, `auth`,
`api`). They are not the same list and should not become one by renaming.

| v1 verb | v2 surface today | Verdict |
|---|---|---|
| `describe` | `GET /api/v1/meta` — `api.Server.handleMeta` | **Partial.** Features are generated from the route table; `links` is a hand-written map that already trails it. §4.1. |
| `snapshot` | `GET /api/v1/situation` — `api.Server.handleSituation`, `situation.Engine.Snapshot` | **Partial.** Bounded and cursor-anchored; sheds silently and reports no omission counts. §4.2. |
| `query` | `GET /api/v1/events` (keyset, `next_after` + `latest_event_id`), `GET /vms`, `GET /runs` | **Partial.** Bounded and cursorable per resource; no typed cross-resource filter surface. |
| `plan` | — | **Missing.** No preview object, no plan digest, no resource quote. §4.3. |
| `apply` | `POST /vms`, `POST /vms/{id}/actions`, `POST /vms/{id}/runs`, `POST /vm-batches` | **Different by design.** Direct typed mutation with `expected_revision` and an idempotency key; no plan digest to revalidate. §4.3. |
| `watch` | `GET /operations/{id}` (poll); `/events/stream` answers 501 | **Partial.** No watch cursor on a mutation response; the stream route is a registered stub. §4.4. |
| `explain` | Typed `Error` with `cause`, `retryable`, `details`, `remediation` — `api.Error` | **Partial.** Errors teach (P-06); nothing explains a *state*, only a failure. |
| `evaluate` | `POST /runs/{id}/conclude`, `GET /runs/{id}/report` — `report.Generate` | **Close.** Runs carry goal and criteria and produce a digest-bound report; the evaluator is the guest or the caller, not a declared evaluator identity. |
| `checkpoint` | — | **Missing.** `POST /annotations` accretes text on durable records but has no anchor, cursor, or next-step contract. §4.5. |

## 2. The objects

| v1 object (§5) | v2 record | Verdict |
|---|---|---|
| Work order revision | — | Missing. `runs.goal` + `criteria_type` carry an objective; nothing carries authority scope, non-goals, or a limits envelope. |
| Run | `runs` table (`store`), `POST /vms/{id}/runs` | Present, narrower: one run per VM at a time (`idx_runs_active`), bound to one VM rather than to a work-order revision. |
| Capability manifest | `meta.features`, `GET /meta/event-kinds` (`events.Kinds()`) | Present in shape; no parameter/result schema digests, no implementation digest. |
| Affordance | `Error.Remediation` — typed action + params + rationale | Present on the failure path only. There is no "what is legal now" read. |
| Situation snapshot | `situation.Snapshot` / `situationResponse` | Present, bounded, `as_of_cursor` / `since_cursor`. Missing: omission counts, expansion selectors, budgets, blockers-as-data. |
| Control plan | — | Missing. |
| Operation | `operations` table; `wireOperation` | Present: `operation_id` (decimal string), `kind`, `phase`, `state`, `error.cause`, `attempt`. Missing: watch cursor, request digest on the wire, permanent tombstone. §4.4. |
| Action journal | Event log (`events` table, registered kinds) | Adjacent. The event log is append-only and cursorable but is not per-action phase state (`intent_recorded` … `quarantined`). |
| Problem | `api.Error` | Present, one shape everywhere. Missing: `retry_strategy` as a typed token — v2 ships a boolean `retryable`, which v1 explicitly says is not the public recovery contract. §4.6. |
| Fact envelope | `events.Envelope` with `host_observed` / `guest_reported` / `derived` provenance | **Stronger than v1's row.** Provenance is assigned at trusted ingress and unregistered kinds are refused. |
| Evidence manifest / outcome | `internal/evidence` (`Manifest`, `Outcome`, `Execution`) | Present but for a different subject: it binds *acceptance rows* to the bytes that ran, not work-order outcomes to facts. Its shape is the right one to copy — `unmeasured`, `cleanup_claimed`, binary digests. |
| Checkpoint | — | Missing. |
| Budget | `reservations` table; `manager.Capacity` | Host capacity only. No per-run or per-work-order budget, and no dimension carrying limit, reserved, used, remaining, projected and measurement quality. §4.7. |
| Claims, recipes, cache | — | Missing, and deliberately deferred. §6. |
| Multi-agent lease | — | Missing, and deliberately deferred. §6. |

## 3. What a cold agent can actually do today

Walked against the route table in `api.New` and the handlers behind it. This is
the vertical slice that already exists; it is shorter than v1's §10 workflow and
it hits a wall in three places.

1. `GET /api/v1/meta` — service and API version, which features are built, size
   limits, active attention trigger classes, auth mode. **Works.** A feature the
   build does not serve answers 501 `missing_capability` with a remediation
   pointing back at `/meta`, so probing the spec surface teaches instead of
   stonewalling. v1's bootstrap is the base path itself; v2 answers `GET
   /api/v1` with 404 `route_unknown` — and that 404 carries the same `/meta`
   remediation, so an agent arriving with v1's habit is redirected rather than
   stopped. Measured against a live test server:

   ```json
   {"code":"not_found","message":"no route for /api/v1","retryable":false,
    "cause":"route_unknown","remediation":[{"action":"get",
    "params":{"path":"/api/v1/meta"},
    "rationale":"the manifest lists the routes and features this build actually serves"}]}
   ```
2. `GET /api/v1/host/status` — capacity and preflight verdict. **Works.**
3. `GET /api/v1/templates` — what can be launched. **Works.**
4. `POST /api/v1/vms` with an idempotency key — returns `{vm, operation}`, HTTP
   201. **Works.** Reusing the key with a different payload is refused with
   `idempotency_conflict` / `idempotency_key_reused`.
5. `GET /api/v1/operations/{id}` — poll to a terminal phase. **Works, but the
   agent had to construct the poll itself:** the create response carries no
   watch cursor and no link to the operation. *Wall 1.*
6. `GET /api/v1/situation?since=<cursor>` — bounded delta, `changed_vms`,
   attention head, watch scope. **Works, but the agent cannot tell a calm host
   from a truncated response.** *Wall 2.*
7. `POST /api/v1/vms/{id}/runs` → `GET /runs/{id}` → `GET /runs/{id}/report` —
   goal-carrying run with a machine-readable, digest-bound report whose counts
   each carry a `reproduce_query`. **Works, and is the strongest part of the
   surface.**
8. `POST /api/v1/vms/{id}/actions` with `expected_revision` — refuses a stale
   revision rather than racing. **Works.**
9. Hand off to the next agent session. **Nothing to write to.** *Wall 3.*

## 4. Gaps, ranked

Ranked by what a bounded agent session loses, not by implementation size. Each
names a source in v1 and a destination in v2.

### 4.1 `/meta`'s link map is hand-maintained

`api.Server.handleMeta` builds `links` as a literal map of ten paths while
`features` comes from the route table in `api.New`. The map carries a rule in a
comment — *"Links name only what answers 200 today"* — which is a good rule
held by hand, so nothing catches a route that arrives without its link.

The drift is visible now. `features` reports `"vm_batches": true`, and no key in
`links` names a batch path, because batches have no GET collection route: only
`POST /vm-batches` and `GET /vm-batches/{id}`. An agent reading `/meta` learns
that batch launch is built and does not learn where to send it. The same holds
for `POST /attention/{id}/ack` and `POST /vms/{id}/actions` — the feature is
advertised, the affordance is not. Feature names are not paths, so `features`
cannot stand in for `links`.

This is against v2's own directive, not just v1's §5.2 ("hand-maintained
capability lists are forbidden"). `docs/README.md`: *"Documentation the running
system serves — capability manifest, event-kind registry, operator guide — is
generated from the same sources the implementation executes. Never maintain a
second copy by hand."* P-07 says the same thing.

Proposed: derive `links` from the table, keeping its stated rule — a link per
built route, template form (`/vms/{id}/actions`) for the ones that take an id,
so the map answers "where" for every feature that answers `true`. A test then
fails when a built route has no link. Additive to the response; no route
changes. **Unimplemented.**

### 4.2 `/situation` sheds silently, and drops a count it already computed

`handleSituation` bounds the response by halving `attention_head`, then halving
`changed_vms`, until it fits `SituationMaxResponseBytes`. The body says nothing
about what was dropped. An agent that receives three attention items cannot tell
whether three exist or three hundred.

`situation.Engine.Snapshot` computes `AttentionOpen` from
`store.CountOpenAttention` on every request — and `situationResponse` has no
field for it, so the number is computed and discarded. `changed_vms` is capped
at 50 with no indication that more changed.

Whether this breaks P-01 as written is arguable: the full attention queue *is*
one link away at `GET /attention`, and the full delta at `GET /vms`. P-03 is not
arguable. "A quiet summary states what it watched… Quiet-because-blind is
reported as blindness, never as calm." The shed loop honours that for watch
scope — its comment says a truncated watch scope would violate P-03, and it
never sheds one — and then truncates the two lists next to it in silence. A
short `attention_head` reads as a calm host for the same reason a narrowed watch
scope would, and the response says as little about one as it says much about the
other. v1 §5.3 asks for the fix directly: "omission counts, expansion selectors,
and continuation cursors".

Proposed: `attention_open` (the count already computed) and an `omitted` block
naming each shed section with its count and the link that expands it.
**Unimplemented.**

### 4.3 No preview

v2 mutates directly. There is no plan object, no plan digest, no resource quote,
and no way to ask "what would this do" without doing it. `expected_revision` on
`POST /vms/{id}/actions` gives concurrency safety, which is the *other* half of
v1's apply contract; the missing half is the one that lets a human approve an
exact effect.

This is the largest gap and the one to defer longest. v2's launch path is a
single typed request against a template with fixed resources, so a plan for it
would mostly restate the request. The case that needs a preview is the one v2
does not have yet: a multi-step or destructive intent. **Unimplemented, and not
recommended before there is an intent that needs it.**

### 4.4 A mutation response has no watch cursor

v1 §7: "Every control-mutation response includes its operation ID, canonical
semantic mutation kind, watch cursor, and resulting revisions when known."

v2 returns the operation id and kind, and the resulting revision inside the `vm`
object. It returns no cursor, so an agent that wants to watch has to call
`/events` to learn where "now" is — a race it can only lose in the direction of
re-reading events it already saw. `GET /events` already returns
`latest_event_id`, so the value exists; it is not on the mutation response.

`/events/stream` is a registered stub answering 501, which is honest and also
means watch is polling today.

Proposed: `watch_cursor` on every mutation response, taken from the same event
id the operation's first event got. **Unimplemented.**

### 4.5 No checkpoint

Nothing in v2 lets an agent write down what it concluded, against which cursor,
with what open questions and what it intended to do next. `POST /annotations`
accretes text on a durable record, which is adjacent but has no anchor, no
cursor, and no next-step field.

This matters more here than in v1, because v2's own P-04 already claims the
ground: "The system is the shared memory between bounded agent sessions." Today
that memory holds goals, verdicts and annotations but not the agent's own state.
A session that ends mid-investigation leaves nothing the next one can resume
from except the event log.

Proposed: `POST /checkpoints` and `GET /checkpoints?scope=`, append-only,
`agent_asserted` provenance, carrying objective, conclusion, anchor cursor,
decisions, open questions, and next intended actions. Small: one table, two
routes, no privileged surface. **Unimplemented.** This is the gap I would close
first.

### 4.6 `retryable` is a boolean

v1 §5.6 names five retry strategies — `never`, `same_request`,
`query_operation`, `after_refresh`, `after_precondition` — and says a boolean
"may be derived for compatibility inside one process, but it is not the public
recovery contract."

v2 ships the boolean. `retryable: false` covers both "this will never work" and
"re-read the revision and try again", which are different instructions.
`Remediation` partly covers the difference in prose the agent must interpret.

Proposed: add `retry_strategy` alongside `retryable`, populated at each existing
`writeError` call site. Additive; the boolean stays until a review says
otherwise. **Unimplemented.**

### 4.7 Budgets are host capacity only

`reservations` tracks memory, vCPU and disk against host admission.
`manager.Capacity` reports free memory. There is no per-run budget, nothing
carrying v1's dimensions — limit, reserved, used, remaining, projected, unit and
measurement quality — and no wall-time, boot-count or event-byte axis at all.

v1's AT-095 exhausts a hard work-order budget and requires read-only context,
evidence, owned stop and cleanup to stay usable. v2 cannot express the
precondition. **Unimplemented, and blocked on §4.3-adjacent design** — a budget
without a plan has nothing to quote against.

## 5. A trap in the kata's own reference

The kata says to reference `../observatory/docs/ACCEPTANCE.md` AT-089 through
AT-095. **Those IDs are already taken in v2 by seven different tests.** v1's
AT-089 is cold-agent discovery; v2's AT-089 is `/situation` correctness under a
mixed fleet. v1's AT-095 is budget exhaustion; v2's AT-095 is oversized run
progress submissions.

v2's `docs/validation/check.py` asserts exactly 102 sequential acceptance IDs,
and `internal/evidence` mirrors that count so a record for an undefined row is
refused. Any row added for this work is **AT-103 or later**, and copying a v1 ID
into v2 would either fail the package check or silently rebind an existing row.

Proposed rows, all unimplemented:

- **AT-103** — cold-agent discovery. Given only credentials and `GET /api/v1/meta`,
  reach a running VM with a concluded run and its report without reading prose.
  Every route used comes from the manifest.
- **AT-104** — bounded snapshot honesty. Drive `/situation` past its byte bound
  with a large attention queue; the response reports every omitted section with
  its count and an expansion link, and the reported open count matches
  `GET /attention`.
- **AT-105** — checkpoint resume. Write a checkpoint, disconnect, resume from it
  plus the exact delta since its anchor. Expired history reports a gap and the
  earliest cursor rather than fabricating continuity.
- **AT-106** — typed recovery. Every distinct `cause` the API emits carries a
  `retry_strategy`, and following it verbatim either succeeds or returns a
  different cause. No cause instructs an agent into a loop.

## 6. Deliberately deferred

Not designed here, and no follow-up item filed: evaluated-knowledge caches,
claims and freshness, recipes with a promotion lifecycle, generalized workflows,
multi-agent leases and fencing epochs, content-addressed pure-step caching, and
the `explain` verb as a state explainer. Each needs a concrete demand v2 does
not have — one host, one operator, no second agent competing for a VM. v1's own
§11 puts them in later milestones for the same reason.

The one v1 idea worth importing early and cheaply is its brown M&M: *silent
ambiguity is the failure*. If an agent has to guess whether a fact is current, an
action is legal, or a retry is safe, the interface has failed. §4.2 and §4.6 are
both that failure, in small.

## 7. Recommended order

1. §4.1 `/meta` links generated — smallest, and it is a live violation of P-07.
2. §4.2 situation omission counts — restores a computed number the response drops.
3. §4.5 checkpoints — the one missing object v2's own P-04 already promises.
4. §4.4 watch cursor — cheap once §4.2 is being touched.
5. §4.6 `retry_strategy` — mechanical, one token per `writeError` call site.
6. §4.3 plan/apply and §4.7 budgets — not until an intent needs a preview.

Items 1, 2, 4 and 5 are additive response fields against existing routes. Item 3
adds a table and two routes. None touches the privileged boundary, `privd`, or
the guest protocol.
