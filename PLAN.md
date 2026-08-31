# vmobs build plan

Working state for building the system in `docs/SPEC.md`. Update the session log at the end of every session. Spec milestones M0–M5 (SPEC §18) remain the acceptance structure; the phase order below front-loads everything buildable and honestly testable on a macOS dev host, because M0/M1 gates need a KVM Linux host we haven't picked yet.

## Strategy

Two tracks:

- **Portable core** (buildable now, real-component tests on any OS): protocol types, event store, API, CLI, situation/attention, run objects and reports, admission bookkeeping. The runtime sits behind an interface; unit tests use the SPEC §18-sanctioned fake runtime. No fake ever serves as a mode of the real daemon.
- **Linux track** (needs the KVM host): privd, runner + spool, jailer/Firecracker adapter, doctor, guest image + guestd, eBPF/fanotify sensors, network namespaces/nftables/mitmdump, terminal path, final-disk inspection, and every acceptance test that touches a real VM.

## Phases

| Phase | Content | Spec refs | Status |
|---|---|---|---|
| P0 | Scaffold: module, plan, conventions, `scripts/check` | §0, §18 | done |
| P1 | Evidence spine: `internal/events` (envelope, validation, kind registry), `internal/store` (WAL SQLite, dedup, integrity, keyset queries), `internal/api` (/meta, /meta/event-kinds, /events, structured errors), `cmd/vmobsd`, `cmd/vmobs` CLI | §12, §14, §14.1, R-04, R-12, R-17 partial | done |
| P2 | Situation + attention + annotations: attention queue (collapse, ack, overflow health record), /situation snapshot + `?since` delta, /annotations | §12.7, R-15, R-14 partial | next |
| P3 | VM registry, operations, admission reservations, runtime interface + fake runtime, lifecycle event emission | §5, §6, R-01, R-02, R-09 partial, R-10 partial | pending |
| P4 | Declarative runs + reports: run state machine, criteria evaluation, report generation with reproduce_query rollups | §8.6, §8.7, R-16 | pending |
| P5 | Auth (local operator, sessions, CSRF), owner scoping | §15.1, R-11 | pending — must land before any non-loopback bind or the web UI |
| L0.. | Linux track per spec milestones M0–M5; then web/ frontend against the stabilized API | §18 | blocked on host decision |

Auth note: P1–P4 expose read endpoints plus idempotent mutations on loopback only; `mode: loopback_only` is enforced in the listener. First non-loopback capability requires P5 done.

## Open questions for Doctor Biz

1. Which Linux/KVM host do we target for the real track — a tailnet box, a rented bare-metal machine, or a local VM? Architecture (x86_64 vs arm64) decides the kernel/image pipeline and doesn't need answering until L0.

## Deviations log (SPEC §0: record deviations as architecture decisions)

- 2026-08-31 — Build order deviates from spec milestones: portable core first because the dev host is macOS (no KVM). All M0–M5 gates still require the real Linux host; nothing is claimed accepted without it.
- 2026-08-31 — Interchange schemas stay in `docs/schemas/` (the docs package validates them); implementation tests read them from there instead of a root `schemas/` dir. Revisit if/when generated protocol docs land.
- 2026-08-31 — CLI exit codes fixed as: 0 success, 1 structured API failure, 2 transport failure, 3 usage error (SPEC §14.1 names the classes but not the numbers).

## Session log

- 2026-08-31 (session 1, compactions: 1) — Docs package agent-interface revision landed on `agent-ergonomics` (spec + acceptance + schemas + check.py, 46/46). Then P0+P1 built on `build-foundation` (branched off agent-ergonomics). Next: P2 situation/attention.
