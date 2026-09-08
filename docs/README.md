# Firecracker Observatory — Builder Handoff

Build a single-host platform where autonomous agents each get an inspectable computer: multiple Firecracker VMs with a real browser terminal, filesystem/process/network activity, durable history and final disk diffs — plus an operations layer built for an agent operator: situation summaries, an attention queue, goal-carrying runs with machine-readable reports, and a self-describing API.

The operator is usually an agent. `SPEC.md` sections 1.3–1.4 define the system model (the L0–L4 tower of linked abstractions) and the agent-interface principles P-01 through P-08. They bind every interface.

## Read this when

| Doing | Read |
|---|---|
| Anything, first | `SPEC.md` sections 0–1: outcome, scope, system model, principles |
| Designing any component | Its SPEC section, then section 17 (failure matrix) |
| Touching interchange shapes | `schemas/` and `examples/`, then SPEC section 12 |
| Implementing the agent operations layer | SPEC sections 1.3–1.4, 8.5–8.7, 12.7, 14 |
| Writing or running tests | `ACCEPTANCE.md` — 102 mandatory V1 rows, all initially SPECIFIED / NOT RUN |
| Judging what this package itself verified | `VALIDATION.md` — package checks only, no runtime claims |
| Operating the bounded agent slice | `design/agent-control-contract.md` — the v1/v2 gap map, executable slice and explicit deferred controls |
| Asking whether vmobs can run in a container | `design/container-boundary.md` — the privileged surface, measured against Docker's defaults |
| Changing any file in `docs/` | Re-run `uv run docs/validation/check.py`; record results in `VALIDATION.md` |

## Builder directive

Inspect the repository and actual Linux/KVM environment before changing anything. Implement the smallest coherent design satisfying the spec. Start with one real jailed VM and a browser terminal connected to its guest PTY, then demonstrate two independently running VMs before expanding the interface.

Keep the host API unprivileged. Do not expose a generic root shell or Firecracker API socket to the browser or guest. Add collection, durability and failure handling in the defined milestones. No mock-only integration passes, silent sensor fallbacks, unbounded queues, or claims of perfectly complete telemetry.

Use existing compatible libraries for PTYs, BPF loading and TLS interception. Keep the implementation single-host; do not introduce Kubernetes, a distributed message bus or multiple data stores.

Documentation the running system serves — capability manifest, event-kind registry, operator guide — is generated from the same sources the implementation executes. Never maintain a second copy by hand.

Maintain acceptance evidence with stable IDs, accreted under `tests/acceptance-evidence/AT-xxx/`; append runs, never overwrite history. Run tests, inspect failures and iterate. Report changes, actual verification and remaining uncertainty. Performance targets in the spec are not benchmark results.

## Files

- `SPEC.md` — architecture, threat model, lifecycle, guest instrumentation, agent operations layer, web UI, APIs, durability, build sequence and verified source premises.
- `ACCEPTANCE.md` — 102 mandatory V1 tests, all initially SPECIFIED / NOT RUN.
- `schemas/event-envelope.schema.json` — normalized event contract.
- `schemas/launch-request.schema.json` — launch contract, including the optional declarative `run` block.
- `schemas/run-report.schema.json` — machine-readable run conclusion contract.
- `examples/event.json`, `examples/launch.json`, `examples/launch-with-run.json`, `examples/run-report.json` — synthetic interface examples.
- `examples/host-config.yaml` — proposed starting configuration, not an installer.
- `validation/check.py` — canonical package check; validates schemas, examples, ID sequences, requirement/principle coverage and cross-references.
- `design/agent-control-contract.md` — what v2's API implements and defers from v1's agent protocol, with supplemental scenarios; `SPEC.md` binds.
- `design/container-boundary.md` — every privileged operation v2's launch chain performs and what each needs from the kernel, measured on aibox03. A review artifact; no shipping profile is authorized by it.
- `VALIDATION.md` — results of package checks, not runtime tests.

The supplied payloads are synthetic. Template digests, IDs and policy names illustrate the contracts and are not existing resources.
