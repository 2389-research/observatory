# Real-daemon flow coverage

Run `scripts/check` for the full gate. It includes Go format/vet/lint/tests,
web type checks/unit tests/build freshness, the real-daemon browser/API E2E
suite, the real-daemon CLI/auth smoke, and the docs package check.

Run just the browser/API suite with `cd web && npm ci && npm run test:e2e`.
Dependencies are pinned to `e2e@0.17.0` and `@e2e-dev/web@0.12.0` in the
npm lockfile. No AI model or credentials are needed. Telemetry is disabled.
Chromium installs on first use; CI can preinstall it with
`cd web && npx e2e-web install chromium --with-deps`.

The runner starts `scripts/e2e-server` on a free loopback port. That script
builds the real daemon, uses a fresh SQLite database and a test template
manifest, and removes its temporary state on exit. Its explicit `unavailable`
runtime is an existing supported daemon configuration, not a fake runtime.
The missing lock and real host preflight remain visible. It never creates a
Firecracker VM or writes to deployed state. The daemon serves committed
`web/dist`; `scripts/check` also rebuilds it to check freshness.

## Observed on 2026-10-04

| User flow | Evidence/test | Result and limit |
|---|---|---|
| Discover API routes, feature flags, event kinds | `web/tests/control-plane.e2e.ts`: API discovery | Passed; execs remain explicitly unbuilt |
| Read templates, host capacity/preflight, situation, attention, event history, runs, VMs, import health, annotations, dev identity | API discovery | Passed JSON/content checks, empty collections, identity, template digest, capacity arithmetic, admission/watch/count relationships; does not prove populated guest data |
| Malformed event/annotation queries and login in dev mode | API discovery | Passed typed 400 query errors and 409 auth_disabled |
| Unsupported event stream; wrong method; absent VM/run/batch/operation | API discovery | Passed typed 501, 405, 404 outcomes |
| Write annotation, read it from SQLite, find its linked event; refuse empty text | Annotation test | Passed against real daemon/store |
| Page stored annotations with limit=1 until exhaustion | Cursor test | Passed: bounded pages, every new row found, no duplicate IDs |
| View fleet and empty states | Fleet browser test; named agent-browser session | Passed against embedded UI, screenshot `.e2e/fleet.png` |
| Filter VMs by lifecycle, copy/reload URL | Fleet browser test | Passed filter and reload persistence |
| Open missing VM workspace and return | Fleet browser test | Passed real API failure banner and back button |
| Edit single launch and submit | Launch browser test | Passed real `runtime_unavailable` refusal; no guest created |
| Expand batch, choose admission mode, add/remove member, submit | Launch browser test | Passed real refusal and zero admitted VMs |
| Bootstrap local operator; bearer identity/list/revocation; denied anonymous access | `scripts/smoke` | Passed real daemon/credential store/CLI |
| Password login, session identity, missing-CSRF rejection, CSRF token creation | `scripts/smoke` | Passed real cookie/CSRF/token flow |
| CLI template/host/VM/run probes, unsupported exec, daemon shutdown and offline error | `scripts/smoke` | Passed actual process/API exit codes |
| Guest launch/stop/restart/pause/resume/delete and bulk actions | Linux fixture gates in `tests/integration` | Not run this session: native Darwin arm64 lacks KVM; shared Linux host has 6.2G free and production VMs |
| Real browser terminal creation/attach/input/output/replay/writer lease/close | Terminal/API unit and integration tests exist | Guest-dependent E2E not run; requires isolated Linux KVM guest |
| Successful batch admission/idempotency/failure policy | Batch/runtime tests exist | Guest-dependent E2E not run; local suite verifies refusals only |
| Guest telemetry, spool loss/recovery, coverage and attention acknowledgement with real guest events | Linux fixture gates and spool tests exist | Guest-dependent E2E not run; empty reads are not proof of event delivery |
| Runs with guest result/report/conclusion | Linux fixture gates and run/report tests exist | Successful real guest run E2E not run; existing smoke checks route/error reachability |
| Exports, execs, coverage, disk diff, artifact downloads, event streaming | `/meta` and route stubs | Unimplemented product capabilities; 501 is honest, not completed functionality |

`web/.e2e/report.json` and artifacts hold automated outcomes. Root `.e2e/logs`
holds this session's check/smoke evidence. The suite does not claim exhaustive
coverage from five tests. Existing React unit tests use mocked HTTP, so they
prove component behavior and are not counted as real E2E.

## Linux gate isolation required

Read-only SSH verified `aibox03` is Linux x86_64 with `/dev/kvm`; operator
`harper` belongs to `kvm` and `docker`. On 2026-10-04 `df -h / /tmp` reported
94% used and 6.2G free. Existing `vmobs` uses host networking and deployment
image `ghcr.io/2389-research/observatory:7739dec`. This is not an isolated test
host. No guest, container, network namespace, AppArmor policy, or remote file
was changed. Do not run `scripts/linux` there for this task: it uses
`rsync --delete` against an existing build tree.

Before a Linux acceptance run, use a disposable x86_64 KVM host or obtain an
approved isolated fixture and enough free disk for guest copies, build layers
and inspector reserve. The canonical `scripts/vmobs-gate` loads AppArmor into
the host kernel and builds a disposable gate container; it needs KVM and TUN.
See `tests/integration/README.md` for gate commands and evidence requirements.
Do not count Linux-gated skips in `go test ./...` as a KVM pass.

## Fixed fixture failure

The old `scripts/smoke` inherited relative `runtime.lock.json` from the
checkout. Its deployment lock names missing Firecracker/jailer binaries on
the native workstation, so startup aborted before the auth/API tests. The
recorded red run exited 1 with `runtime lock verification failed`. The script
now selects an absent lock under its own temporary config directory and the
supported unavailable runtime. Verification stays enabled; the daemon logs
the absent lock, serves the control plane and refuses launches. The green
run and full gate verify that exact smoke, not a replacement fixture.
