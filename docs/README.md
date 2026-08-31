# Firecracker Observatory — Builder Handoff

Build a single-host platform for multiple inspectable Firecracker VMs, with a real browser terminal, filesystem/process/network activity, durable history and final disk diffs.

## Read order

1. `SPEC.md` — architecture, threat model, lifecycle, guest instrumentation, web UI, APIs, durability, build sequence and verified source premises.
2. `ACCEPTANCE.md` — 88 mandatory V1 tests, all initially SPECIFIED / NOT RUN.
3. `schemas/` and `examples/` — machine-readable contracts and synthetic examples.

## Builder directive

Inspect the repository and actual Linux/KVM environment before changing anything. Implement the smallest coherent design satisfying the spec. Start with one real jailed VM and a browser terminal connected to its guest PTY, then demonstrate two independently running VMs before expanding the interface.

Keep the host API unprivileged. Do not expose a generic root shell or Firecracker API socket to the browser or guest. Add collection, durability and failure handling in the defined milestones. No mock-only integration passes, silent sensor fallbacks, unbounded queues, or claims of perfectly complete telemetry.

Use existing compatible libraries for PTYs, BPF loading and TLS interception. Keep the implementation single-host; do not introduce Kubernetes, a distributed message bus or multiple data stores.

Maintain acceptance evidence with stable IDs. Run tests, inspect failures and iterate. Report changes, actual verification and remaining uncertainty. Performance targets in the spec are not benchmark results.

## Files

- `SPEC.md`
- `ACCEPTANCE.md`
- `schemas/event-envelope.schema.json`
- `schemas/launch-request.schema.json`
- `examples/event.json`
- `examples/launch.json`
- `examples/host-config.yaml`
- `VALIDATION.md` — checks performed on this specification package, not runtime tests.

The supplied launch and event payloads are synthetic. The template digest, IDs and policy names illustrate the contract and are not existing resources. The host configuration is a proposed starting configuration, not an installer.
