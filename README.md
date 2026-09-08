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
Docker with Compose and AppArmor enabled. Each VM takes a 4 GiB root disk and
a 1 GiB workspace by default, so size the disk for how many you intend to run.
Then:

    docker compose up -d

The command pulls `ghcr.io/2389-research/observatory:latest`, which includes
the guest kernel, root image, AppArmor parser and profile. The API comes up on
`0.0.0.0:8787`; open `http://<host>:8787/ui/`. Authentication is disabled by
default. Set `server.public_origin` to your browser's origin in a mounted
config to use the terminal; see [deployment configuration](deploy/README.md#http-listener).

A short-lived Compose service loads the profile into the shared host kernel
before the appliance starts. It installs no host packages or configuration files.
After a host reboot, run `docker compose up -d` again to reload the policy and
start the appliance. `deploy/README.md` explains the loader's authority and the
appliance's confinement.

`scripts/vmobs-container up` does the same thing with preflight checks in front
of it: it tests the devices, builds from the checkout, and uses the same Compose
loader before starting the appliance. Prefer it for local builds.

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
| `deploy/` | Container image, seccomp and AppArmor profiles, operator guide. |
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

## Licence

MIT — see [LICENSE](LICENSE).

That covers this repository. The appliance image is not only this repository:
it bundles Firecracker v1.16.1 (Apache-2.0), a Linux 6.1.186 guest kernel
(GPL-2.0), and an Ubuntu userland, each under its own terms.
`runtime.lock.json` names every pinned component.
