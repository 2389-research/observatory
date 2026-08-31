# Firecracker Observatory (`vmobs`)

Crew names, recorded once per the naming rite: the agent building this is **SCOPE DOGG** (chief telescope officer, vsock slammer). The boss is **DOCTOR BIZMUTH, DUKE OF HYPERJAIL**. Normal address stays "Doctor Biz".

## What this is

A single-host Linux/KVM platform running multiple inspectable Firecracker microVMs, designed agent-first. `docs/SPEC.md` is the binding contract — especially §1.4 principles P-01..P-08 (bounded, cursorable, linked, honest) and §18's repository shape. `docs/ACCEPTANCE.md` holds the stable test IDs. Do not weaken a requirement to make a test pass; record deviations in PLAN.md.

## Ground rules

- Evidence honesty is the product. Never fabricate counts, verdicts, or coverage; `inconclusive` beats an invented answer. Provenance labels (`host_observed`, `guest_reported`, `derived`) are assigned by trusted ingress only.
- Counters that can exceed JS safe integers are decimal strings in JSON. Everywhere.
- SQLite: WAL, `synchronous=FULL`, exactly one logical writer. Keyset pagination, never OFFSET.
- Every API response is bounded; every rollup count carries a `reproduce_query`; errors carry typed cause + remediation.
- Event kinds must be registered in `internal/events` before anything emits them; ingress rejects unregistered kinds.
- The fake runtime exists for unit tests only (SPEC §18). Never wire it into a served mode; acceptance evidence requires real Firecracker on Linux.

## Working here

- Canonical gate: `scripts/check` (gofmt, vet, golangci-lint, `go test ./...`, docs package check). Run it before claiming anything works.
- Docs-only changes: `uv run docs/validation/check.py`, then append a dated revision to `docs/VALIDATION.md`.
- TDD for every feature and bugfix; tests use real components (real SQLite, real HTTP) at the seams we own.
- Read `PLAN.md` at session start; update its session log before ending one. Read `gotchas.md` too.
- Build sequence and current status live in PLAN.md, not in anyone's memory.
