# Firecracker Observatory (`vmobs`)

Run several Firecracker microVMs on one Linux host and watch what happens inside
them. Each VM gets a browser terminal on its guest PTY, a durable event history,
and an HTTP API built for an agent to drive rather than a person to click.

The API is the product. Every response is bounded and cursorable, every rollup
count carries the query that reproduces it, and every error names a typed cause
and a remedy. Evidence is labelled by where it came from — `host_observed`,
`guest_reported`, `derived` — and a question the system cannot answer returns
`inconclusive` instead of a guess.

## Install

You need a Linux host with x86_64 hardware virtualisation (`/dev/kvm`) and
Docker. Each VM takes a 4 GiB root disk and a 1 GiB workspace by default, so
size the disk for how many you intend to run. Then:

    sudo sh deploy/install-apparmor.sh   # once per host, the only root step
    docker compose up -d

The API comes up on `127.0.0.1:8787`; the UI is at `/ui/`.

Two commands, and the first one is root because Docker takes an AppArmor profile
by *name* and asks the kernel for one already loaded — there is no Docker API
that loads a profile, so no compose file can. `deploy/README.md` explains what
the profile grants, and what running without it costs.

`scripts/vmobs-container up` does the same thing with preflight checks in front
of it: it tests the devices, notices a stale profile rather than a missing one,
and names the single thing to change. Prefer it when something is wrong.

## What is built

Real Firecracker VMs under the jailer, network namespaces per VM, a guest agent
over vsock, the browser terminal, guest telemetry with a bounded ring and an
honest health signal, declarative runs with machine-readable reports, an
attention queue, and local operator auth.

Not built: the eBPF and fanotify sensors, traffic capture, and final-disk diff.
The guest probes report whether the kernel supports those, and nothing collects
through them yet. `docs/ACCEPTANCE.md` carries the test IDs and their real
status; a row that has not run says so.

A path the spec names but this build does not implement answers `501` with the
code `missing_capability` and points at `GET /meta`, which lists the features
that are actually wired. Nothing pretends.

## Layout

| Path | What |
|---|---|
| `docs/SPEC.md` | The binding contract. §1.4 holds the principles everything answers to. |
| `docs/ACCEPTANCE.md` | Stable test IDs and their status. |
| `docs/runbooks/` | Host bring-up and operation. |
| `docs/design/` | Decisions with their measurements attached. |
| `deploy/` | Container image, seccomp and AppArmor profiles, install script. |
| `internal/` | The daemon: store, API, runtime, jailer, privd, guest, spool. |
| `cmd/` | `vmobsd` (daemon), `vmobs` (CLI), `vmobs-privd`, `vmobs-runner`, `vmobs-guestd`. |
| `web/` | The UI. Its build output is committed and embedded in the binary. |
| `gotchas.md` | What bit us, and why. Read it before debugging anything. |

## Working on it

    scripts/check                      # the whole gate: fmt, vet, lint, tests, docs
    uv run docs/validation/check.py    # docs-only changes

`scripts/check` is the only verification that counts. Tests use real components
at the seams — real SQLite, real HTTP. The fake runtime exists for unit tests and
is never reachable from a served mode; the gate fails if it becomes so.

Acceptance evidence requires real Firecracker on a real Linux host. Results from
the fake runtime are labelled as such and cannot satisfy a KVM gate.
