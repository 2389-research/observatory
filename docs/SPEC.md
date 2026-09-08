# Firecracker Observatory
## Build-ready specification for an inspectable, multi-VM agent workstation

**Working name:** Firecracker Observatory (`vmobs`)  
**Specification revision:** 1.0 — August 30, 2026  
**Deployment target:** One Linux/KVM host; one authenticated operator initially; multiple simultaneous microVMs.  
**Status:** Proposed implementation contract, not an implemented or benchmarked product.

> Give each agent a computer. Make its activity inspectable without turning its computer into the host computer.

## 0. Instructions to the builder

Build the system described here, not a dashboard mockup or a generic cloud platform. Deliver an actual browser terminal connected to a guest PTY, real guest and host observations, concurrent independent VMs, persistent history, and evidence from fault-injection tests.

Use the smallest coherent implementation that satisfies the contracts. Prefer a single-host Go codebase, an embedded React application, SQLite, a narrow privileged helper, and a few explicitly supervised per-VM processes. Do not introduce Kubernetes, a distributed message broker, multiple databases, or a service mesh.

Implement a working vertical slice first, then harden it. Use real Firecracker on a KVM-capable Linux test host for integration acceptance. A fake runtime is useful for unit and frontend tests but cannot establish VM isolation, terminal correctness, egress enforcement, or telemetry coverage.

The implementation may change internal structure after inspecting dependencies, but must preserve observable behavior, privilege boundaries, protocol contracts, and acceptance criteria. Record deviations as architecture decisions with tests. Do not silently substitute weaker sensors or quietly remove a requirement to make tests pass.

The companion `ACCEPTANCE.md` supplies stable test IDs. `schemas/` and `examples/` define concrete interchange examples. All examples are proposed interfaces; no command in this document claims an existing released `vmobs` product.

The operator this system serves is usually an autonomous agent. Sections 1.3 and 1.4 state the system model and agent-interface principles; they are binding contract for every interface, not garnish on a human dashboard. Serve self-description and operator documentation from the build itself, generated from the sources the implementation executes, never as a second hand-maintained copy.

## 1. Product outcome

The operator opens a web application, selects a machine template, launches one or several VMs, interacts with each through a terminal, and inspects a timeline of processes, filesystem changes, network flows, DNS, and—when enabled—HTTP requests. Each VM has independent storage, lifecycle, network policy, sessions, logs, and resource limits.

After a run, the operator can inspect its exit reason, telemetry coverage, final disk changes, commands launched through the execution API, and retained artifacts. A controller restart must not silently terminate unrelated VMs or lose already acknowledged telemetry.

### 1.1 Required capabilities

| ID | Requirement |
|---|---|
| R-01 | Create, start, pause, resume, stop, force-stop, and delete independently identified VMs. |
| R-02 | Launch multiple VMs concurrently, including a batch operation from the UI and API. |
| R-03 | Provide an interactive web terminal with a real guest PTY, resize, reconnect, and session ownership. |
| R-04 | Display a durable, filterable, resumable event timeline per VM and across selected VMs. |
| R-05 | Observe guest process execution/exit and filesystem mutation activity with explicit capability and loss reporting. |
| R-06 | Enforce egress outside the guest and observe network flows and managed DNS. |
| R-07 | Offer opt-in HTTPS inspection for compatible clients; distinguish inspection from transport-only visibility. |
| R-08 | Produce final persisted-filesystem manifests and diffs without mounting untrusted disks in the host kernel. |
| R-09 | Enforce per-VM and host resource budgets, including disks, logs, terminals, and helper processes. |
| R-10 | Reconcile after controller/runner crashes, partial provisioning, and unexpected guest or VMM termination. |
| R-11 | Authenticate all control/terminal access; keep the browser, guest, and privileged host interfaces separated. |
| R-12 | Record gaps, truncation, redaction, uncertainty, and provenance rather than claiming perfect visibility. |
| R-13 | Expose a stable execution API suitable for an autonomous coding-agent harness. |
| R-14 | Export machine-readable history, final-state evidence, configuration, and coverage summaries. |
| R-15 | Serve a bounded fleet situation summary with delta cursors and a durable, acknowledgeable attention queue driven by enumerated deterministic triggers. |
| R-16 | Support declarative runs: goal and success criteria at submission, a completion policy, a linked machine-readable run report, and guest progress/result submission. |
| R-17 | Serve machine-readable self-description: capability manifest, event-kind registry with semantic caveats, template capabilities, and structured doctor output, generated from the sources the implementation executes. |

### 1.2 V1 scope and exclusions

V1 includes a working single-host deployment, a CLI, a web interface, cold boots, persistent per-VM disks, the agent operations layer (situation, attention, declarative runs, self-description), all requirements above, and the acceptance suite.

Defer multi-host scheduling, public multi-tenant hosting, billing, live migration, arbitrary device passthrough, shared writable filesystems, Kubernetes integration, deterministic replay, MCP or other protocol adapters layered over the public API, and generalized whole-system virtual-machine introspection from the hypervisor. Adapters stay deferrable precisely because the public API must already be complete and self-describing; nothing may exist only in the web interface.

Memory snapshot/restore and cloning a running VM are deliberately deferred. V1 cloning means creating a new VM from an immutable template. Copying a stopped VM's disks may be added only with new identity, independent disks, and explicit provenance; never implement it by sharing writable image files.

### 1.3 The operator is an agent

Design every interface for an autonomous agent operator first and a human second. The human uses the web application; the agent uses the API and CLI. Both see the same facts through the same contracts.

An agent operator differs from a human in ways this specification treats as engineering constraints, not personas:

- It pays for every byte it reads. Responses compete with its working memory.
- It runs in bounded sessions. Continuity across sessions exists only in what the system durably records.
- It cannot watch. It polls, subscribes, or is invoked; it never glances at a dashboard.
- It automates retries, so an ambiguous mutation outcome is more dangerous than a clean failure.
- It can verify claims mechanically when, and only when, claims link to their evidence.

The system therefore forms a tower of linked abstractions. Each level is bounded, cursorable, and linked one level down (drill) and one level up (context):

| Level | View | Question it answers |
|---|---|---|
| L4 | Situation and attention | What matters right now? |
| L3 | Runs and reports | What are we trying, and how did it go? |
| L2 | VM lifecycle, coverage, sessions | What is each computer doing? |
| L1 | Normalized events and rollups | What happened, with honest labels? |
| L0 | Raw artifacts: disks, spools, outputs | The bytes. |

Read at the highest level that answers the question; write at the highest level that expresses the intent; intervene at lower levels only on exception. Control mirrors evidence: a goal-carrying run (L3) compiles into lifecycle operations (L2) and primitives (L1), and its report rolls the evidence back up.

### 1.4 Agent-interface principles

These principles are contract, referenced by ID from the acceptance suite. They bind every API response, CLI output, error, and exported artifact.

| ID | Principle |
|---|---|
| P-01 | Bounded by default. Every response has a size bound; summaries come first and full detail stays one link away. Never push a raw firehose at the operator. |
| P-02 | Deltas everywhere. Every level of state is cursorable, not only the event stream. "Nothing changed" must be cheap and trustworthy. |
| P-03 | Silence is evidence. A quiet summary states what it watched: active trigger classes, cursors, and any reduction in watch scope. Quiet-because-blind is reported as blindness, never as calm. |
| P-04 | Intent lives in the system. Runs carry goals and success criteria; annotations and verdicts accrete on durable records. The system is the shared memory between bounded agent sessions. |
| P-05 | Every claim links. Any rollup count, flag, or verdict resolves to the queryable records behind it. No dead-end numbers. |
| P-06 | Errors teach. Structured cause, retryability, and, where the system knows the remediation space, typed executable remediation options; never prose alone. |
| P-07 | Self-describing. Capability manifest, event-kind registry with caveats, and template capability metadata are served by the running system and generated from the same sources the implementation executes. Zero out-of-band knowledge is required to drive it. |
| P-08 | Typed operations, mechanical summaries. No natural-language command surface; no model-generated summaries inside the system. Rollups and triggers are deterministic and auditable, so the operator can trust them without re-deriving them. |

The system spends bounded host CPU to save operator tokens: streaming counters and materialized rollups, not repeated scans and not raw dumps.

## 2. What “introspection” means

The product must not describe itself as seeing every request, every file byte written, or every instruction. Its contract is **bounded observation with declared coverage, host-enforced boundaries, and retained evidence**.

### 2.1 Verified platform facts

Firecracker exposes TAP-backed networking and host-file-backed virtual block devices; each Firecracker process contains one microVM. It does not perform guest egress filtering. These are the integration points for this design. [S1]

Firecracker's vsock implementation bridges guest AF_VSOCK streams to host Unix-domain sockets. This design uses that channel for guest control and telemetry without opening guest SSH or HTTP management ports. [S3]

Filesystem notification is not a write journal: fanotify can lose events on overflow and does not report modifications arising through mmap/msync/munmap. A close-write notification means a write-open file was closed; it does not, by itself, prove content changed. [S4]

Tracing the Firecracker host process therefore cannot be the guest file/process sensor: the host sees a virtual machine and virtual-device operations, not a direct mapping of guest syscalls to host syscalls. This is an architectural consequence of the interfaces above, not a claim of a hidden Firecracker tracing feature.

### 2.2 Evidence classes

| Evidence | Source | Meaning and limitation |
|---|---|---|
| VM lifecycle, cgroup limits, image hashes | Host controller/runner | Host-observed records under the assumption that the host is trusted. |
| Firewall policy and counters | Host networking | Host-enforced policy; detailed packet/deny logs can still be sampled or dropped. |
| Network flow / DNS / proxy records | Host collectors | Observations at specified network boundaries; coverage depends on collector health and mode. |
| Process, path, command attribution | Guest collector | Guest-reported kernel observations, not tamper-proof against guest root/kernel compromise. |
| HTTP content | Inspection proxy | Available only for successfully intercepted compatible traffic, subject to capture/redaction limits. |
| Disk-image digest | Host byte hashing | Identifies retained image bytes; does not prove all guest memory was flushed to disk. |
| Final file manifest/diff | Isolated inspection environment | Interpretation of captured disks; report parser errors, unsupported content, and crash consistency. |
| Inferred process/request associations | Correlation engine | A best-effort join, explicitly labeled with confidence and evidence. |

The UI must distinguish `host_observed`, `guest_reported`, and `derived`. Those labels identify origin, not universal truth or cryptographic attestation.

### 2.3 Two independent health dimensions

A VM may be **running** while its telemetry is **degraded**. Never encode observation quality only in lifecycle state.

Show at least:

- `lifecycle_state`: provisioning, starting, running, paused, stopping, stopped, failed, deleting, deleted.
- `telemetry_health`: starting, healthy, degraded, unavailable.
- Per-sensor coverage, last event/heartbeat time, observed drops, unknown loss intervals, exclusions, and enabled capture mode.

“Healthy” means the configured supported sensors are active and no current health failure is known. It does not mean all possible behavior is observable.

## 3. Architecture and implementation choices

### 3.1 Recommended stack

These are design decisions, not measured capacity claims.

| Area | Decision |
|---|---|
| Host control plane, runner, guest agent | Go; one repository and shared versioned protocol types. |
| HTTP API | Go HTTP server with generated OpenAPI contract and typed validation. |
| Frontend | React + TypeScript + Vite; build assets embedded in the host service. |
| Terminal | xterm.js with a custom authenticated, bounded transport and fit/resize integration. |
| Metadata and event index | SQLite on a local filesystem; WAL; one logical writer. |
| Durable ingestion queues | Per-runner bounded, redacted, append-only spool segments. |
| Guest process/network sensors | Small eBPF programs plus Go loaders; use cilium/ebpf rather than inventing a loader. [S7] |
| Guest filesystem sensor | fanotify with capability-tested filesystem marks and file-handle/name reporting. |
| Host egress | Linux network namespaces, TAP/veth routing, nftables, managed DNS, bounded flow observation. |
| Optional HTTP/TLS inspection | An isolated per-VM mitmdump process and a small version-pinned addon; no custom TLS implementation. |
| Deployment | Native Linux services supervised by systemd; no Docker socket exposed to the application or guest. |
| Final disk inspection | A purpose-built, network-disabled inspection microVM; never execute the inspected guest OS. |

Use pinned module dependencies and lockfiles. Resolve and record compatible runtime/kernel/proxy versions during implementation; do not download an unpinned `latest` at launch time.

### 3.2 Component layout

```text
Browser
  | HTTPS: API / events        | WSS: terminal
  +---------------------------+
                 |
       vmobsd (unprivileged)
       - authentication and authorization
       - templates, scheduler, lifecycle operations
       - SQLite metadata / event index
       - event queries, live subscriptions, exports
       - situation rollups, attention queue, run reports
       - capability manifest and event-kind registry
       - embedded React application
                 |
       narrow Unix-socket RPC
                 |
       vmobs-privd (privileged, no HTTP listener)
       - approved cgroups, namespaces, TAP/veth, nftables
       - approved jailer startup and termination
       - validated resource cleanup
                 |
       +---------+----------------------------+
       |                                      |
  per-VM runner A                        per-VM runner B
  - VMM supervision                      - same isolation
  - guest channels                       - independent spool
  - durable spool                        - independent disks
  - network workers
       |
  jailer -> Firecracker A
       |
  +----+--------------------------------------------+
  | Guest                                           |
  | guestd: telemetry + exec + persistent PTY broker |
  | agent jobs / interactive shells                 |
  | root disk + workspace disk + bootstrap config   |
  +-------------------------------------------------+

Guest network -> TAP -> VM-specific gateway namespace
                        |- managed DNS
                        |- flow/policy observation
                        |- optional HTTP proxy
                        `-> host-approved uplink only
```

A runner exists separately from the API process so browser refreshes and controller restarts do not own the VMM's lifetime. A runner is also the per-VM fault boundary for collection and terminal relay. Per-VM gateway processes are independently resource-limited.

### 3.3 Privilege boundaries

The browser must never receive a Firecracker API socket, a privileged-helper endpoint, a host filesystem path, or a generic host command execution primitive.

`vmobs-privd` accepts only typed requests such as `AllocateNetwork`, `CreateCgroup`, `StartApprovedVM`, `SignalOwnedVM`, and `ReleaseResources`. It validates ownership, state, path roots, template digests, numeric limits, and operation IDs. Authenticate the caller using Unix peer credentials and filesystem permissions.

Do not accept an arbitrary shell command, arbitrary nftables text, arbitrary executable path, arbitrary device path, or an unrestricted mount request. Invoke approved binaries with argument arrays, not `sh -c`. Keep privilege-bearing paths and their parents non-writable by unprivileged users. Assign independent nonprivileged identities to VMMs and resources rather than reusing a shared VM UID. Firecracker recommends jailed execution and unique identities for concurrent instances. [S2]

Do not assume the jailer supplies routing, egress policy, disk snapshots, or an observability pipeline. Those remain platform responsibilities.

## 4. Host preflight and version contract

### 4.1 `vmobs doctor`

Before accepting a launch, report pass/fail and an actionable explanation for:

1. Linux architecture and usable KVM: open `/dev/kvm`, perform required KVM capability checks, and run a real test guest.
2. Pinned Firecracker and matching jailer executables with verified hashes.
3. Host/guest kernel tuple supported by the chosen release and verified by this project.
4. cgroup v2 controllers and the service's delegated subtree.
5. Network namespace, TAP, veth, nftables, routing, DNS and proxy prerequisites.
6. Available memory, CPU budget, disk bytes/inodes, filesystem allocation behavior, and log reserve.
7. Ownership/permissions of runtime directories, sockets, templates and credentials.
8. Working guest vsock, sensor capability probes, and terminal handshake.
9. Configured API bind/authentication mode and TLS or explicit loopback-only access.

Doctor output is machine-readable: per-check ID, status, evidence, and typed remediation, with the human rendering derived from the same data. Serve the current doctor state through `GET /host/status` so a driving agent never has to re-run preflight to learn why a launch is refused.

A nested Linux VM is acceptable only if these real KVM and guest tests pass. Do not infer nested virtualization from the presence of a device node or offer silent software emulation with different performance/security properties.

### 4.2 Runtime lock

Maintain `runtime.lock.json` containing exact Firecracker/jailer versions and hashes, host support constraints, guest kernel version/source/hash/config hash, root image digest, guest agent version, eBPF object digests, proxy/addon version, protocol schema version, and template manifest digest.

Firecracker documents specific tested kernel combinations and notes that other configurations are not equivalently validated. Use the selected release's policy and matched kernel source/configuration; do not transplant a minimal config onto an unrelated kernel and assume compatibility. [S16]

Build images reproducibly from pinned inputs. Generate a software inventory and retain build logs. An image is publishable only after its capability and fixture tests pass.

## 5. Domain model and lifecycle

### 5.1 Entities

| Entity | Important fields |
|---|---|
| Template | Immutable ID/digest, kernel/root image, guest user profiles, tooling, supported sensors, protocol versions. |
| VM | UUID, owner, template digest, desired state, observed state, resources, network profile, disks, labels, timestamps. |
| Boot | Host-generated boot-generation UUID, VM ID, guest boot ID, runner instance, kernel/agent versions. |
| Run | Goal text, typed success criteria, VM/boot binding, phase, outcome with evidence links, completion policy, report artifact, parent harness correlation IDs. |
| Operation | Idempotency key, request hash, target VM, phase, state, error, attempt history. |
| Terminal session | UUID, VM/boot, shell PID identity, owner, writer lease, output cursor, retained window. |
| Exec session | UUID, VM/boot, argv/cwd/user policy, process identity, stdout/stderr offsets, exit result. |
| Event stream | Source instance UUID, VM/boot binding, sequence/ack cursors, loss and schema metadata. |
| Artifact | UUID, VM/run, media type, digest, byte size, capture policy, provenance, retention, ACL. |
| Attention item | Durable ID, severity, trigger kind, VM/run refs, summary, system action already taken, evidence links, typed suggested actions, ack state. |
| Annotation | Immutable ID, author identity, target entity ref, bounded text, structured tags, created time. |

An existing VM can cold-start again from its stopped disks with a **new boot identity**. Never reuse process, terminal, or telemetry identities across boots.

### 5.2 State machine

```text
requested -> provisioning -> starting -> running <-> paused
                 |             |           |
                 +-------------+----------> failed
                                           |
running / paused -> stopping -> stopped ----+
                                  |
                                  +-> starting (new boot)
                                  +-> deleting -> deleted
failed -> deleting -> deleted
```

Implement `requested` as an operation state if VM rows are created immediately. `failed` must retain its last completed stage and reason; it is not an excuse to leave resources unaccounted for. A failed, recoverable VM may be retried only through an explicit validated transition.

A requested stop while provisioning cancels launch and runs cleanup. A force-stop while paused terminates the owned VMM; it must not wait for guest cooperation.

Pause suspends execution, not reservation: paused VMs retain memory/disk reservations and must not free admission capacity as though stopped. Pause is not a saved memory snapshot.

### 5.3 Launch transaction

1. Authenticate and validate the complete request, template, profiles, quotas and idempotency key.
2. In a transaction, create the operation and reserve resources. Concurrent launches must not oversubscribe the same capacity.
3. Allocate opaque VM/boot IDs, independent disks, unique network resources and per-VM identities.
4. Persist a provisioning manifest before each external side effect; include enough identifiers for rollback.
5. Start network policy in deny-by-default state and start bounded logging workers.
6. Start the runner, configure the jailed VMM, and boot only approved images.
7. Establish authenticated guest channels; validate protocol and capability reports.
8. Seed the workspace, install ephemeral launch material, prepare the baseline manifest, and verify requested sensors before releasing the workload.
9. Activate the approved egress policy only when its enforcement and required logging path are ready.
10. Mark the VM `running` and the operation successful. Terminal creation is permitted only after the required guest services are ready.

Every stage is repeatable or detects an already-completed effect. On failure, undo owned resources in reverse dependency order; record cleanup failures and retry them. Never delete by a fuzzy name match or reuse a resource that might still belong to a live VM.

### 5.4 Stop and delete

Graceful stop closes admission to new jobs, asks the guest to terminate selected workloads, flushes telemetry, and requests guest shutdown. Use a bounded grace period, then force termination if required. Record graceful versus forced outcome separately from workload exit status.

Finalize spools and retain a captured disk set after the VMM has exited and cannot write it. Start final inspection as an operation with its own progress and resource reservation. `stopped` does not mean the diff is ready.

Delete is idempotent. Reject deletion of a live VM unless the request explicitly includes force-stop behavior. Deleting VM compute resources must not implicitly delete retained audit history and artifacts; expose retention/deletion as a separate policy-controlled operation.

### 5.5 Restart reconciliation

On startup, inventory durable VM/operation records, per-VM runner manifests, owned cgroups, namespaces and socket directories. Verify VMM identity using more than PID alone: include process start identity, cgroup membership and the intended executable/runtime manifest.

Adopt healthy owned runners. Resume unfinished operations. Mark disappeared VMMs stopped/failed with an explicit unknown/crash reason. Quarantine ambiguous resources rather than signaling an unrelated process. Never automatically restart an arbitrary command whose acceptance or completion status is unknown.

The runner is independently supervised. A runner crash must leave the VMM/network resource ownership discoverable. Reattach guest channels and begin a new source-instance identity when collection resumes. A controller outage must not remove firewall rules.

## 6. Multi-VM admission and fairness

### 6.1 Reservation model

Reserve guest RAM **plus measured or conservatively configured host overhead** for its VMM, runner, network workers, queue buffers and optional proxy. The guest's configured RAM is not the total host cost.

Host cgroups apply to host processes; guest task counts need guest-side limits as well. Use cgroup v2 CPU, memory and process controls for host services, and a separate workload cgroup inside the guest. [S8]

Default policy: no memory overcommit; CPU overcommit requires an explicit host configuration. Account for running, starting and paused VMs. Reserve disk allocation and log space before boot, including headroom for final capture/inspection.

Use a transaction-backed reservation table and a single admission authority. Export reserved and observed usage separately. A full host returns a structured `insufficient_capacity` error or queues the operation according to the request; never starts an underprovisioned VM silently.

### 6.2 Starting configuration targets

The following are tunable engineering starting points, **not verified performance or minimum-hardware claims**:

| Setting | Proposed initial value |
|---|---|
| VM default | 2 vCPU; 2 GiB guest RAM. |
| VM disks | 8 GiB root; 10 GiB workspace, independently allocated. |
| Per-VM host overhead reserve | 768 MiB initially, including proxy allowance; replace with measured sizing. |
| Host reserve | Greater of 4 GiB or 20% of host RAM; also reserve CPU and inspection capacity. |
| VM launch parallelism | 2 provisioning workers; configurable. |
| Batch size limit | 8 per request; capacity may admit fewer only in explicit best-effort mode. |
| Terminal session cap | 4 per VM initially; 1 active writer per session. |
| Event spool | 512 MiB per VM initially; additional reserved host emergency space. |
| PTY reconnect window | 4 MiB output per session, bounded in guest memory. |
| Event frame limit | 256 KiB after framing; separate bounded streams for bulk data. |
| API event page | 200 default, 1,000 maximum rows. |

Expose these values in configuration and the UI. Avoid hidden fixed limits. Verify memory overhead with and without TLS interception before advertising VM counts.

### 6.3 Batch launch semantics

Support `atomic_reservation` and `best_effort` explicitly.

`atomic_reservation` checks and reserves the entire batch before provisioning. It is **not** an atomic distributed boot: a later VM may fail. Return the result per VM and honor a declared `on_failure` policy (`keep_successful` by default or `stop_successful`).

`best_effort` admits individual VMs and reports rejections. A retried batch idempotency key must resolve to the original members, not create another batch. Different payloads using the same key return conflict.

### 6.4 Isolation under load

Round-robin or weighted event ingestion prevents one noisy VM monopolizing the writer. Per-VM limits apply to network bandwidth, DNS rate, proxy concurrency, terminal throughput, event buffers, artifacts and log retention. One full workspace must not fill the host's system filesystem or corrupt another VM's volume.

## 7. Guest image, privilege, and control channels

### 7.1 Guest contents

Use a pinned, ordinary Linux userspace with the toolchains required by the template, an init/service manager that reaps children, `vmobs-guestd`, sensor objects, a shell and terminal database, CA bundles, and utilities needed by fixture tests.

Start guestd before user workloads. Keep guestd/control resources in a separate guest cgroup from jobs. Mount and enumerate root/workspace before marking observation ready. Cap `/tmp`, `/run`, process counts and user-job memory as appropriate to the image.

The image build must verify required kernel facilities rather than assuming a stock minimal Firecracker kernel includes tracing support. Maintain a config fragment for BPF/tracing/BTF, fanotify/file handles, cgroups, PTYs, virtio networking/block/vsock, and the selected filesystems. Probe exact enabled features at runtime and export a capability manifest.

### 7.2 Privilege profiles

Support both profiles in V1:

- `unprivileged`: agent user without unrestricted sudo or administrative capabilities; use preinstalled toolchains. This is the default for stronger guest-collector resistance to ordinary workload tampering.
- `developer_root`: agent user with deliberate root/sudo access inside the VM. Useful for agents modifying their computer, but prominently label guest telemetry as tamperable. Do not add host privileges when this profile is selected.

Selecting a profile is a launch decision, not a permission prompt before every ordinary command. Neither profile provides proof against a guest kernel exploit. Killing or replacing guestd must generate host health degradation; a root adversary capable of fabricating believable guest reports may evade that detection. State this limitation in the UI/help and exports.

### 7.3 Vsock channels

Use distinct logical ports/connections so terminal output cannot starve control and telemetry. Proposed guest ports:

| Port | Purpose |
|---|---|
| 10000 | Control, capabilities, health, exec/session management. |
| 10001 | Telemetry stream and durable acceptance acknowledgments. |
| 10002 | PTY/session byte streams, with an authenticated attach handshake. |
| 10003 | Bounded artifact transfer when requested. |

For host-initiated connections, connect to that VM's configured Unix socket and perform Firecracker's documented `CONNECT <port>\n` / `OK <port>\n` handshake before the application protocol. Do not treat the host Unix socket as a raw guest shell. [S3]

Bootstrap a random per-boot capability in an independently generated read-only config device. Bind its scope to this VM/boot and protocol; never reuse it across clones. Treat it as accessible to guest root, not an attestation key. Do not store broad host/API credentials in this device.

The same read-only device carries `context.json` for the workload: the VM's own IDs and name, resource budget, network profile with effective egress expectations, workspace layout, the run goal and success criteria when a run is attached, and the progress/result submission conventions. The context states what the cage actually enforces so the workload does not spend its budget probing it or retrying egress that policy will deny; AT-098 verifies each statement behaviorally. It is configuration, not a secret and not an attestation. Leave Firecracker MMDS disabled in V1; the bootstrap disk is the explicit configuration path. Any future metadata service is an additional guest-to-host surface requiring its own policy and tests.

The runner supplies authoritative VM/boot identity from the owned socket/resource mapping. Guest payload fields cannot choose another VM ID, source trust class or owner. Authenticate and bound every channel before accepting data.

### 7.4 Framing and protocol rules

Use a fixed-size length prefix followed by versioned JSON control/event messages; transport PTY and artifact bytes in separate typed binary frames. Define byte order and maximum length in the implementation protocol document. Reject oversized lengths before allocation, invalid types, unsupported versions and decompression bombs. Disable compression initially.

Handshakes include protocol version, capability list, boot identity, source instance, resume cursor and authentication proof. Counters that can exceed JavaScript's safe-integer range are decimal strings in JSON.

Apply handshake, idle and write deadlines. Retry reconnects with bounded exponential backoff and jitter. Do not retry mutating commands blindly: creation commands carry idempotency keys, and recovery queries their actual status.

## 8. Terminal, execution and declarative runs

### 8.1 Terminal architecture

```text
xterm.js
  <-> authenticated WSS
  <-> vmobsd authorization / bounded relay
  <-> per-VM runner
  <-> vsock terminal stream
  <-> guestd PTY broker
  <-> guest shell and foreground process group
```

Allocate a real guest PTY. Pipes and a JavaScript text box do not implement an interactive terminal. A PTY provides terminal-device behavior and an associated controlling terminal for the guest process. [S9]

Create a new session with a server-generated UUID, approved guest user, cwd, shell argv, terminal type, rows and columns. Use an argument array. No host shell participates in this chain.

The guest PTY broker owns the PTY independently of a browser connection. Disconnecting a tab detaches it, not the underlying shell. Session termination is a separate explicit operation, and VM shutdown ends all sessions.

### 8.2 Required terminal behavior

Support resize/SIGWINCH propagation, UTF-8, color, alternate screen applications, bracketed paste, Ctrl-C/Ctrl-D, job control, scrolling and reconnect to an existing session. Test with a shell, `vi`, and a full-screen process viewer actually installed in the image.

One session permits one writer lease; additional attachments are read-only until control is explicitly transferred. Only the writer can resize. Independent sessions have independent PTYs and leases. A stale connection cannot keep writing after transfer.

On reconnect, request output after the last consumed byte offset. If output aged out, show an explicit replay gap and reset/resynchronize the terminal; never replay an arbitrary partial escape sequence into an assumed exact screen state. A VM reboot invalidates the old session; the UI must not reconnect to a different shell under the same ID.

Input frames have a per-session sequence. A retransmitted accepted frame must not type the same text twice. After broker loss or ambiguous input status, show the ambiguity rather than automatically resending destructive input. “Input accepted by broker” is not a guarantee that a shell command completed.

### 8.3 Backpressure and output limits

Acknowledge browser consumption after xterm's write callback, not merely after receiving a WebSocket message. xterm's guidance describes application-level flow control across WebSockets because buffering otherwise grows independently at multiple layers. [S11]

Bound every queue. A slow browser must not stop sensor ingestion or the control channel. The guest broker continuously drains into a bounded reconnect ring; mark dropped output ranges. If an optional lossless terminal-recording policy is enabled, explicitly document that throttling can block the guest process—this is different from the default live-console policy.

Disable automatic keystroke recording. PTY output can include echoed commands and secrets; do not call output safe merely because input logging is disabled. Keep default replay in bounded memory only. Persistent terminal recording is opt-in, separately authorized, size-limited, and marked sensitive.

### 8.4 Terminal security

Authenticate the upgrade request and authorize the VM/session. Validate the exact allowed Origin independently of CORS. Use WSS for non-loopback deployment, secure same-site session cookies, and CSRF protection for session creation and mutations. Never place long-lived bearer tokens in URLs.

Treat terminal titles, hyperlinks and all guest bytes as untrusted. Do not insert terminal output into HTML. Disable automatic clipboard writes/OSC 52 integration, automatic downloads, and execution of terminal-provided links. Links may open only with an explicit user gesture, permitted schemes, and a separate protected browser context. Set a restrictive content security policy and load no third-party analytics into the terminal application. xterm explicitly cautions against using its demo/attach example as a production security solution. [S10]

### 8.5 Structured execution for agents

The execution API is distinct from a terminal:

```json
{
  "argv": ["python", "-m", "pytest", "-q"],
  "cwd": "/workspace",
  "timeout_seconds": 600,
  "stdout_limit_bytes": 10485760,
  "stderr_limit_bytes": 10485760,
  "idempotency_key": "task-42-tests-attempt-3"
}
```

Return an exec ID immediately, then separate stdout/stderr streams, process identity, exit code or signal, timeout/cancellation state, and output truncation metadata. PTYs merge terminal output and must not be used when exact stdout/stderr separation is required.

Default to argv execution. Running shell syntax requires an explicit shell executable/argv selected by the caller. Cancellation kills the entire tracked guest job cgroup/process tree, not just its first shell. A malicious root-enabled workload can tamper with guest cgroups; in that case report unverified cleanup and use a policy-selected VM stop when full containment is required. Do not claim a guest process-tree kill is root-resistant. On reconnect, query the exec ID; do not run the command again. The harness attaches its task/run/parent IDs as correlation metadata, not as authority to cross VM boundaries.

### 8.6 Declarative runs

A run is the unit of delegated work: launch-and-babysit collapsed into one submission. Attach a run to a launch request (`run` block in `schemas/launch-request.schema.json`) or create one on a running VM.

A run carries a bounded `goal` (why this work exists, readable by the next operator session), typed `success_criteria` (`exec_exit_zero` for the attached exec, `guest_result` for a workload-submitted verdict, or `operator_verdict`), and an `on_completion` policy (`keep_running`, `stop`, or `stop_and_finalize`). Run phases: pending, running, concluding, then exactly one of succeeded, failed, inconclusive, aborted.

`inconclusive` is mandatory honesty, not a soft failure. When criteria cannot be evaluated — guestd dead, result malformed, required telemetry lost — report that; never fabricate a verdict. Run creation is idempotent by key like every mutation; after a controller or runner crash the run resumes or concludes with an explicit interruption reason and never re-executes accepted work.

The workload can submit bounded structured progress (`run.progress` events through guestd) and a final result (a guestd call or `/workspace/.vmobs/result.json`, size-capped and schema-validated). Both carry `guest_reported` provenance with the same trust labeling as all guest telemetry, including its tamperability in `developer_root`.

### 8.7 Run reports

Concluding a run produces a report: one machine-readable artifact (`schemas/run-report.schema.json`) that answers "how did it go" without replaying the event stream. It contains the goal, criteria, outcome with evidence links, exec results with output digests and bounded tails, event rollups by family, coverage and gaps, network and filesystem summaries, artifacts, attention items raised, and deterministic rule-based anomalies.

Every count in a report carries a `reproduce_query`: the API filter that regenerates it (P-05). Report generation is an operation; if it fails, the run outcome stands and the report is retryable. Lifecycle never blocks on rendering.

The fleet loop an orchestrating agent actually runs is: submit N launches with runs, poll situation deltas, harvest N reports, acknowledge attention. Section 19 sets a measured interaction budget for that loop.

## 9. Guest telemetry

### 9.1 Process observation

Capture process fork/clone relationships, successful exec transitions, exec failures where supported, and process exits. Include PID/TGID, parent identity, UID/GID, executable, bounded argv, cwd when available, guest cgroup, timestamps, exit status/signal, and sensor origin.

Use `(boot_id, tgid, process_start_monotonic_ns)` as a process identity, with an exec generation for image replacement. PID alone is not an identity. Preserve unknown fields as unknown.

Prefer stable tracepoints where available. Capture exec arguments before they disappear and correlate with a successful exec event; an attempted exec is not automatically a successful process launch. Record `argv_truncated`, byte/argument limits, and capture failures. A periodic `/proc` inventory is a reconciliation aid, not the primary short-lived-process sensor.

Shell builtins, scripts interpreted in an already-running process, and in-process language operations are not all separate exec events. Terminal history and exec tracing must not be mislabeled as a complete source-level command transcript.

Maintain explicit eBPF loss counters. Kernel ring-buffer reservations can fail; the loader must not interpret a quiet stream as proof that nothing happened. [S6]

### 9.2 Filesystem observation

V1 records create, modify notification, close-after-write-open, rename/move, unlink/delete, metadata change and supported open/access events. File reads are optional and off by default because of volume and incomplete semantics; advertise the exact enabled event classes.

Use filesystem-level marks on supported root/workspace filesystems rather than racing to attach one directory watch per newly created subdirectory. Filesystem and mount mark capabilities differ; validate the exact mask/flags against the selected kernel. [S5]

Each event should carry filesystem identity, mount context, file handle/inode where available, reported name(s), process identity when available, operation, and path resolution status. Preserve original byte names as base64 when they are not valid UTF-8; provide an escaped display form separately.

Paths are not stable identities. Rename/unlink, multiple hard links, bind mounts and short-lived processes can defeat late pathname resolution. Do not invent a pathname from the nearest subsequent `/proc` observation. Record `unresolved`, `exact_at_capture`, or `inferred` and keep the underlying evidence.

Track newly mounted filesystems and coverage changes. An unmonitored mount or unsupported filesystem creates an explicit exclusion/coverage gap. Pseudo-filesystems such as `/proc`, `/sys`, device I/O, deleted-open files, and tmpfs content must not be confused with the final persisted disk scope.

Do not use `FAN_CLOSE_WRITE` as the UI event “file contents changed.” Call it `fs.close_write`; create `fs.content_changed` only from actual content comparison. Do not report modification byte counts unless the sensor actually observed them.

### 9.3 Noise, self-observation and optional deep tracing

Collect mutation metadata for the declared supported disk scope. Collapse dependency caches, package-manager churn and `.git` activity in the UI, but do not silently stop collecting them. Record any sensor-side exclusions in the run manifest.

Exclude the collector's own bounded spool/housekeeping activity using explicit internal scope/identity rules to avoid feedback loops. Do not allow ordinary workloads to choose those exclusions. Root-enabled guests can undermine such distinctions; the trust label must remain unchanged.

Detailed write/read syscall tracing is an optional later diagnostic profile, not the V1 completeness mechanism. It requires accounting for fd reuse, vectored I/O, mmap, asynchronous I/O, truncation, and failure/partial-return semantics. Do not make a write-syscall hook a prerequisite for shipping the useful mutation timeline and final diff.

### 9.4 Guest network attribution

Collect socket connect attempts/results and supported socket lifecycle observations to associate guest processes with flows. Use namespace and socket identity where available, not only a destination address. Keep socket tuple, guest process identity, event time and attribution confidence.

UDP, reused tuples, proxies, short connections and sensor losses can make attribution ambiguous. The host may know a request belonged to VM A without knowing which guest process caused it. Display “process unknown” instead of fabricating a connection to the last command.

## 10. Network enforcement and visibility

### 10.1 Topology

Give each VM a dedicated namespace with its TAP and a routed veth uplink. Do not attach all guest interfaces to an unrestricted shared bridge. Use an independently allocated transit network; detect overlap with host LAN/VPN routes before allocation.

Identify traffic by its owned interface/namespace or dedicated proxy listener, not a guest-supplied IP address alone. Enforce anti-spoofing for guest MAC/IP and deny access between VM networks. Guest root changing its route, address or DNS must not create an alternate host uplink.

V1 is deliberately IPv4-only at the guest boundary. Drop IPv6 traffic at the host enforcement boundary as well as configuring it off in the template. IPv6 support is a later feature requiring equal routing, observation, policy and test coverage; a guest sysctl alone is not the enforcement mechanism.

### 10.2 Network profiles

| Profile | Behavior | Observable detail |
|---|---|---|
| `offline` | No guest Internet access; only the fixed management vsock protocol. | Denied network attempts when captured; guest socket activity; no invented external requests. |
| `transport` | Host-filtered TCP and explicitly allowed UDP/services through the managed gateway. | VM-scoped flows, managed DNS, bytes/counters, allowed/denied outcomes, opportunistic TLS metadata. No promise of URLs or HTTPS bodies. |
| `http_inspect` | Guest can reach only managed DNS and a per-VM explicit HTTP(S) proxy. Direct guest egress is denied. | Parsed HTTP requests/responses for compatible clients; bounded optional content. Unsupported or pinned connections fail unless a declared tunnel exception exists. |

Default to `transport` with conservative public-Internet destination policy and no LAN/metadata access. Operators select `http_inspect` for request-level debugging. A policy file describes allowed ports, DNS/domain constraints, exceptions and capture level.

Do not implement an implicit fail-open fallback from inspection to unobserved direct access. Mitmproxy recommends explicit regular proxy mode as the simplest initial setup and notes that some applications bypass proxy settings. This design compensates by enforcing the path outside the guest, not by trusting `HTTP_PROXY`. [S12]

### 10.3 Egress policy

Start from default deny and allow only the selected profile's path. Cover private, loopback, link-local, multicast, special-use/reserved, host interface addresses, the configured VM/transit ranges, and cloud/host metadata destinations. Keep the address classification policy versioned and test it; a short list of three RFC1918 ranges is not a complete boundary.

Only the managed DNS resolver may send upstream DNS. In inspection mode, deny direct guest TCP egress, UDP/443, arbitrary UDP, alternate DNS and tunneling paths by default. A proxy cannot guarantee that an allowed web endpoint will not carry an encrypted tunnel or exfiltrated data; domain allowlists are not data-loss prevention.

For a domain policy, normalize names and ports, resolve through the controlled resolver, validate every resolved connection address, and bind approval to the address actually dialed. Recheck redirects and new connections. Do not approve `example.com` once and then permit a later private address because its name was previously allowed. Enforce public-address restrictions at the namespace layer as defense in depth for the proxy itself.

Explicit proxy requests, CONNECT authority, SNI/HTTP authority and upstream identity require consistency rules. Do not trust an arbitrary Host header as the destination policy decision. Block CONNECT to unauthorized ports or address literals unless explicitly approved. Authenticate or isolate listeners so one VM cannot use another VM's egress identity.

Transport mode cannot truthfully enforce an arbitrary hostname policy by guessing hostnames from IP addresses shared by many services. Restrict such policies to the inspecting proxy path or reject the unsupported combination.

### 10.4 Flow, DNS and denial collection

At the TAP/gateway boundary, capture bounded transport observations and correlate with connection tracking/counters. Track start/end/timeout, protocol, original tuple, translated tuple when known, direction, byte counters, observed TCP state, policy outcome and collection boundary.

Do not call a SYN a completed connection or a TCP flow an HTTP request. Clearly distinguish guest-to-proxy flow and proxy-to-upstream flow. Attach a host-created request/flow ID where the proxy can provide an exact relationship.

Managed DNS records include query name/type, response outcome, returned records, duration and policy decision. A DNS name is evidence of a query, not proof that all traffic to a returned address is for that name. Record encrypted/unknown DNS limitations under transport mode.

Packet/conntrack/NFLOG streams and sampling can lose detail. Maintain available drop counters and rate-limit indicators. A firewall counter can show that more packets were denied than individual log records retained. Report both; never multiply one sampled deny event into fictitious complete individual records.

Packet capture is optional, capped and sensitive. Do not persist raw pcap by default. If enabled, record interface, snap length, retained interval, packet drops, and access policy.

### 10.5 HTTPS and HTTP content

In `http_inspect`, run mitmdump in a per-VM resource-limited gateway context with a unique CA/private key and a pinned addon. Install only its CA certificate into that disposable guest. Never install the CA on the user's browser or host trust store; never expose the private key in artifacts.

The template must test CA/proxy configuration with its actual tools—curl, Python's HTTP stack, Node, Git and relevant package managers. Do not disable upstream certificate verification to make interception work. Certificate pinning can reject the inspection CA; record a clear compatibility error or an explicit `tls_passthrough` exception without pretending content was inspected. [S13]

Default retained request data: method, sanitized authority/path, HTTP version, status, duration, byte counts, policy result, redacted selected headers, truncation flags, and TLS inspection outcome. Capture request/response bodies only under explicit policy, using byte limits and allowed content types.

Stream large bodies and long-lived connections. Emit start/progress/end/abort events so SSE and streaming model responses appear before the connection closes. Bound decompression, header sizes and preview parsing. Do not buffer a model response or package download indefinitely to make a log row.

Handle redirects as distinct requests. Identify HTTP/2 streams independently. Unsupported HTTP/3/QUIC is denied in inspection mode rather than silently escaping visibility. WebSocket upgrades require a clear metadata-only or bounded-frame capture policy; they are not ordinary finite HTTP bodies.

The addon must redact before persistence and must not also write an unredacted mitmproxy flow dump or debug log.

## 11. Storage, manifests and filesystem diffs

### 11.1 V1 storage strategy

Use an immutable approved root template and an **independent writable raw root image per VM**, plus a separate independent workspace image. A reflink copy may optimize creation when the host filesystem supports it; otherwise use a real copy with explicit admission cost. Reflinks are an optimization, never permission to share one writable image between VMMs.

Do not require OverlayFS for V1. Independent images avoid conflating overlay upper-layer presence with actual content changes and keep the initial disk model straightforward. Templates remain immutable and content-addressed; their clones are not automatically transactional filesystems.

Reserve actual capacity. Sparse image length is not physical allocation. Either preallocate the promised writable capacity or use a tested host quota/reservation scheme that prevents overcommit from exhausting the host. Separately budget logs, artifact copies and inspection scratch space.

No host working directory, home directory, SSH agent socket, Docker socket or host block device is mounted into the guest. Source is imported as a bounded seed artifact and results are exported as artifacts.

### 11.2 Workspace seeding and baseline

Seed archives are untrusted input. Extract only inside the guest/preparation sandbox with path traversal, symlink/hardlink, special-file, file-count and expanded-size controls. Do not untar a user archive directly into a privileged host directory.

Before releasing untrusted jobs, create a baseline workspace manifest and retain the template-root manifest. Root changes relative to the template include ordinary boot/package-system changes; group them separately from workspace changes rather than hiding them.

A manifest entry includes encoded path, type, logical size, content digest for regular files, symlink target, mode, uid/gid, selected xattrs, hard-link information, and read/error status. Record scope and excluded paths explicitly. Do not use mtime alone to prove content equality.

### 11.3 Live versus final views

Live file previews come from a bounded guest service and are labeled guest-reported, time-specific and potentially racy. File content fetched after a modify event is not necessarily the version that generated the event.

The final diff compares captured persisted state with the baseline. Report additions, deletions, type changes, content changes and metadata-only changes. Rename inference must be labeled unless an exact event/identity supports it. Preserve the add/delete facts even when suggesting a rename.

A final diff does not reveal a file created and deleted between captures, all intermediate content versions, memory-only changes, or complete transient tmpfs state. A successful live mutation event and an unchanged final file are not contradictory.

### 11.4 Safe final inspection

Only inspect a stable disk set after the VMM has stopped and ownership confirms no writer remains. Hash original image bytes on the host and preserve the captured originals.

Start a trusted inspector microVM with no network, bounded memory/time/output and the captured data disks attached read-only. Boot the inspector's own kernel/userspace, not the captured guest root. Treat disk contents, filenames and parsed output as hostile. Do not follow symlinks into the inspector's own filesystem or execute anything from the captured disks.

Untrusted filesystems must not be loop-mounted into the host kernel: libguestfs's security guidance explicitly describes this attack surface and the benefit of an isolated appliance. This design applies that isolation principle using a dedicated inspection microVM. [S15]

For dirty filesystems that require journal recovery, work only on a disposable copy. Preserve original and recovered digests, record recovery actions, and label the diff `crash_recovered`. A clean graceful result may be `clean_shutdown`; a forced stop is at best crash-consistent unless independently demonstrated otherwise. An inspector failure means `diff_incomplete`, not “no changes.”

Reject oversized or malformed manifests and kill hung inspectors. Reserve separate inspection capacity so finalization cannot deadlock waiting for a slot held indefinitely by paused workloads.

## 12. Events, durability and querying

### 12.1 Event envelope

See `schemas/event-envelope.schema.json` and the validated example in `examples/event.json`. The core shape is:

```json
{
  "schema_version": 1,
  "event_id": "18442",
  "vm_id": "1ed7fdbf-7007-43f3-b5b2-8071e96b2df5",
  "boot_id": "10e6210d-d21f-4f8d-8c69-5370f1e6d44f",
  "source_instance_id": "190be15a-9470-40c6-b7df-c1b541a8e005",
  "source_seq": "918",
  "kind": "fs.modify",
  "provenance": "guest_reported",
  "sensor": "fanotify",
  "host_received_at": "2026-08-30T20:00:00.000000Z",
  "guest_monotonic_ns": "4138100021",
  "process_key": "10e6210d:441:3900100000",
  "run_id": null,
  "quality": {
    "path_resolution": "exact_at_capture",
    "attribution": "exact",
    "truncated": false,
    "redacted": false
  },
  "data": {
    "path_display": "/workspace/server.py",
    "path_bytes_base64": "L3dvcmtzcGFjZS9zZXJ2ZXIucHk=",
    "filesystem_id": "workspace",
    "content_capture": "not_requested"
  }
}
```

The example is synthetic interface data. The short process key is illustrative; the implementation must retain the full boot/process identity internally.

The envelope permits `event_id` to be absent/null in a durable spool before indexing; indexed API responses must populate it. Host-wide events can use null VM/boot fields, and preboot VM events can use a null boot. Those scopes must still have a bound source identity.

Host identity/time/provenance fields are assigned by trusted ingress. A guest cannot self-label `host_observed`. A later enrichment is a new linked record or a separate derived index entry, not a rewrite of original evidence.

### 12.2 Event families

Use versioned schemas for `vm.*`, `operation.*`, `process.*`, `exec.*`, `fs.*`, `net.flow.*`, `dns.*`, `http.*`, `terminal.*`, `telemetry.*`, `policy.*`, `artifact.*`, `run.*`, `attention.*`, `annotation.*`, and `security.*`. The `run.*`, `attention.*`, and `annotation.*` families are `host_observed`, except `run.progress`, which is `guest_reported`.

At minimum define explicit health records for sequence gaps, source restart, kernel-buffer drop, spool overflow, collector timeout, unsupported capability, path-resolution failure, dropped terminal output and artifact truncation.

### 12.3 Ordering and identity

Every producer has a source-instance UUID and increasing sequence number. Deduplicate by `(vm_id, boot_id, source_instance_id, source_seq)`. The same key with different payload bytes is a protocol-integrity failure, not an update.

Bind each globally unique source-instance UUID to one VM/boot scope in a streams table. Enforce database uniqueness on `(source_instance_id, source_seq)` so nullable VM/boot fields for host-wide or preboot events cannot weaken deduplication. Reject any attempt to rebind a source instance to a different scope.

The event index assigns a global ingestion cursor when indexing. Source order and observed timestamps remain separately available. Buffered events indexed later may have earlier capture times; do not imply a total causal order across unrelated guest and host clocks.

Store host receive wall time, host boot/monotonic context and available guest wall/monotonic time. Use monotonic clocks for durations within a clock domain. UI timeline defaults to host observation order and can display reported guest time with an offset/uncertainty label.

### 12.4 Durable ingestion protocol

The guarantee is **at-least-once transport with deduplicated storage**, not exactly-once observation.

1. Guest generates a bounded, sequenced event and retains it until host acceptance or explicit overflow.
2. Runner validates schema/size, binds identity, applies redaction and writes the normalized event to its durable per-VM spool.
3. Only after the spool record and required filesystem metadata are durably flushed may the runner acknowledge acceptance to the guest.
4. The controller imports records in batches into SQLite, atomically inserts deduplicated events and advances that spool's indexed cursor.
5. Only after database commit may the runner prune indexed spool segments.

An acknowledgment means “durably accepted on this host,” not “visible in the browser” or “replicated off-host.” The database is the canonical query/history store after indexing; the spool is a durable delivery queue, not a second independently editable history.

Segment files have a versioned header, bounded records, checksums and an end marker. Recovery tolerates an unacknowledged truncated trailing record, rejects corrupt interior records, and emits a recovery/gap record. Sync directory metadata when required to make a newly created segment durable. Do not acknowledge merely because bytes reached an in-memory channel.

SQLite WAL supports concurrent readers but still one writer. Use a single scheduled writer, bounded batches, short read transactions, busy handling, WAL checkpoint monitoring and `synchronous=FULL` for durability-dependent commits. Keep the DB on local storage, not a network filesystem. [S14]

### 12.5 Bounded loss and strict observation

All queues have limits. Guest kernel buffers can drop before user-space sequencing; guest restart may destroy its unacknowledged memory queue. Report measured drops where possible and unknown intervals otherwise. Do not invent a numerical drop count for an unobservable crash interval.

Default overflow policy is `degrade`: preserve host safety and control responsiveness, emit an explicit loss interval, and continue according to configured capture priorities. Lifecycle/security/health records have a separately reserved path so an event flood cannot hide its own loss indefinitely.

An optional `require_telemetry` run policy pauses or stops the VM when required sensor heartbeat/durable-spool health fails. This is a bounded reaction, **not proof of zero events escaping before detection**. Gate egress as well when required host network logging is unhealthy. Never use synchronous, unbounded filesystem permission blocking to manufacture a lossless guarantee.

On low host disk: reject new launches, close optional content capture, preserve reserved health/control space, then stop/pause affected runs according to policy before general filesystem exhaustion. Do not silently disable persistence while continuing to acknowledge durable events.

### 12.6 Query and live stream semantics

Support filters by VM set, boot/run, time range, event kind, process identity, path prefix, hostname, address/port, outcome, provenance and health state. Use indexes for common filters; cap free-text queries and page size.

Use keyset pagination on ingestion cursor rather than large OFFSET scans. SSE live streams carry durable cursor IDs. Subscribe/replay must close the race between history and new events by using a high-watermark plus replay or a cursor-driven database tailer.

Browser reconnect supplies its last cursor. If retention has expired it, return `cursor_expired` with the earliest available cursor and show a visible history gap. UI auto-scroll pause does not stop ingestion; show unread counts and queue limits.

### 12.7 Situation and attention

The event stream is history; situation and attention are the operator's working set. Both are deterministic materializations of durable records (P-08): the attention queue is a view over `attention.*` events plus acknowledgment state, and the situation summary rolls up lifecycle, telemetry health, runs, capacity, and open attention.

`GET /situation` returns a bounded snapshot: host capacity and watch state, per-VM one-line summaries with open-attention counts and active-run phase, the head of the attention queue, and an `as_of` cursor. With `?since=<cursor>` it returns only what changed. A quiet response is small and self-vouching: it enumerates active trigger classes and sensor watch scope, so silence distinguishes "nothing happened" from "nobody was watching" (P-03).

```json
{
  "as_of_cursor": "184532",
  "since_cursor": "180001",
  "quiet": false,
  "host": {
    "vms_running": 3,
    "vms_total": 4,
    "capacity_free_mib": 4096,
    "watch": {
      "trigger_classes_active": ["lifecycle_failed", "run_concluded", "telemetry_degraded", "capacity_exhausted"],
      "sensors_degraded": 1
    }
  },
  "changed_vms": [
    {
      "vm_id": "1ed7fdbf-7007-43f3-b5b2-8071e96b2df5",
      "name": "agent-python-02",
      "lifecycle_state": "running",
      "telemetry_health": "degraded",
      "active_run": {"run_id": "3f1c2c53-42a2-46bb-9f21-6c0f6f8d6b2e", "phase": "running"},
      "attention_open": 1,
      "links": {"vm": "/api/v1/vms/1ed7fdbf-7007-43f3-b5b2-8071e96b2df5"}
    }
  ],
  "attention_head": []
}
```

Attention items are raised only by enumerated deterministic triggers: lifecycle failures, run conclusions, telemetry degradation, spool and disk thresholds, policy-denial anomalies, capacity exhaustion, and reconciliation surprises. The active set is configured and served through `GET /meta`, not hardcoded in prose. Each item states what happened, what the system already did under policy, evidence links, and typed suggested actions executable as returned (P-06). Acknowledgment is per-item and durable; unacknowledged items survive restart. The queue is bounded: duplicates collapse by VM and kind with counts, and overflow raises its own health record rather than dropping silently.

```json
{
  "attention_id": "att-000341",
  "cursor": "184530",
  "severity": "needs_decision",
  "kind": "telemetry_degraded",
  "vm_id": "1ed7fdbf-7007-43f3-b5b2-8071e96b2df5",
  "run_id": "3f1c2c53-42a2-46bb-9f21-6c0f6f8d6b2e",
  "summary": "fanotify queue overflow; 1240 events lost (measured); capture continuing",
  "system_action": "per configured degrade policy: loss interval recorded, egress unchanged",
  "evidence_links": ["/api/v1/events?vm_id=1ed7fdbf-7007-43f3-b5b2-8071e96b2df5&kind=telemetry.loss&from_cursor=184100"],
  "suggested_actions": [
    {"action": "stop", "params": {"vm_id": "1ed7fdbf-7007-43f3-b5b2-8071e96b2df5"}, "rationale": "conclude now if complete evidence matters more than finishing"},
    {"action": "ack", "params": {"attention_id": "att-000341"}, "rationale": "accept the recorded gap and continue"}
  ],
  "acked": false
}
```

Severity has three levels only: `info` (harvest at leisure), `needs_decision` (system is stable but waiting on operator judgment), and `critical` (system took protective action; review it). Grade severity by whether and when the operator must act, not by adjective inflation.

## 13. Web interface

The web interface is a client of the public API. Anything it displays is obtainable from the API with identical values and provenance labels (AT-101); the UI holds no private data path and no private truth.

### 13.1 Fleet view

The landing page shows host capacity, reservations, health, recent operations, the attention queue head (unacknowledged count, severity, one-line summaries, links — the same queue the API serves) and a table of VMs. Columns: name/ID, template, lifecycle, telemetry health, CPU/RAM allocation and usage, disk usage, network mode, age and owner/labels.

Provide Launch VM and Launch Batch. The launch form includes template, count, resources, privilege profile, network profile/policy, workspace seed, optional initial exec command, an optional run block (goal, success criteria, completion policy), retention/capture policy and labels. Preview total reservation and explain why a request cannot fit.

Batch operations show independent progress and errors. Selecting multiple VMs enables explicit stop/pause/resume/delete operations with per-VM results. Do not make a batch look successful because its first member started.

### 13.2 VM detail workspace

```text
VM: agent-03    RUNNING    Telemetry: DEGRADED — filesystem queue gap
Template: python-dev@digest   2 vCPU / 2 GiB   Egress: http_inspect
[Pause] [Stop] [Force stop] [Export] [Clone template]

[Terminal] [Timeline] [Runs] [Filesystem] [Network] [Processes] [Metrics] [Settings]

+--------------------------------+--------------------------------------+
| Active guest terminal          | Live event feed                      |
| session tabs / reconnect state | source / event / process / target    |
|                                | filters / pause scroll / unread     |
+--------------------------------+--------------------------------------+
```

The terminal and event feed should be usable side by side with resizable panes. The VM identity and writer/read-only state remain visible while typing. Distinguish browser disconnected, runner disconnected, guest unresponsive, VM paused and shell exited.

### 13.3 Timeline

Use a virtualized list with live-tail controls, filter chips, saved per-operator filter state and a details drawer. Rows show host time, event family, process when known, target and outcome. Drawer shows structured data, provenance, redaction/truncation, correlation evidence, raw normalized JSON and related events.

Do not use color as the only signal. Escape all strings. A filename containing HTML, bidi control characters or terminal escapes must remain data, not executable markup or a misleading invisible action.

### 13.4 Filesystem tab

Provide Activity and Final Diff views. Activity filters by path/process/operation and exposes path uncertainty. Final Diff shows baseline, capture time, consistency class, inspector status and A/M/D/type/metadata changes.

Text previews have byte/line caps, binary detection, visible truncation and a sensitive-content policy. Show before/after content only when actually retained. Do not reconstruct an earlier file from current contents and label it historical. Diff download references immutable artifacts with ACLs.

### 13.5 Network tab

Separate Requests, Flows, DNS and Policy Denials. Never mix a TCP connect row into a request table with a guessed URL.

Requests show method, sanitized host/path, status, timing, sizes and capture outcome. A selected request displays related flow/DNS/process evidence, permitted headers/previews and reasons content is unavailable: TLS passthrough, pinning, disabled body capture, truncation, unsupported protocol or collector loss.

Show policy hits and counters, effective egress configuration, proxy health and CA fingerprint. Display “transport only” prominently when URL/content capture is not enabled.

### 13.6 Processes and metrics

Process tree includes exited processes, exec transitions, UID, command with truncation markers, start/end, and links to related files/network. Distinguish observed parentage from inferred parentage. Offer cancellation only for managed exec jobs, or a clearly authorized guest signal action; never signal a host PID derived from guest data.

Metrics show guest-reported usage separately from host cgroup usage, disk reservations versus usage, network bytes, event rate/drop counters, spool backlog, ingestion delay and control health. VMM logs are separate from application/terminal output.

### 13.7 UX acceptance

All mutating controls show in-progress state and operation IDs. Refreshing a page does not repeat a launch. Dead/disconnected terminals cannot accept apparently successful input. Errors include an actionable reason, not only a toast. Persist filters and selected VM in the URL without credentials.

The UI must be functional with keyboard navigation, visible focus, accessible labels and readable contrast. Prefer a dense workstation layout over decorative charts that obscure the terminal and event timeline.

## 14. API contract

Use `/api/v1`; generate OpenAPI and client types. Web and CLI share the same semantics. All state-changing requests are authenticated, authorized and audited.

| Method and path | Contract |
|---|---|
| `GET /meta` | Capability manifest: versions, enabled features, limits in force, active attention trigger classes, links to registry, guide and OpenAPI. |
| `GET /meta/event-kinds` | Event-kind registry: schema reference, provenance class, semantics and caveats per kind, generated from the emitting code's own tables. |
| `GET /host/status` | Capacity, reservations, doctor/capability state, service health. |
| `GET /templates` | Approved immutable templates, supported profiles, sensor support and toolchain inventory. |
| `GET /situation` | Bounded fleet snapshot or `?since` delta: capacity, per-VM summaries, attention head, cursors. |
| `GET /attention` / `POST /attention/{id}/ack` | Durable attention queue with per-item acknowledgment. |
| `POST /vms` | Create/start request; idempotency key; returns VM and operation IDs. |
| `POST /vm-batches` | Explicit batch admission/failure policy; per-member IDs/results. |
| `GET /vms` / `GET /vms/{id}` | List/details with separate lifecycle and telemetry state. |
| `POST /vms/{id}/actions` | Typed start/pause/resume/stop/force-stop; expected revision. |
| `DELETE /vms/{id}` | Idempotent resource deletion; no implicit historical purge. |
| `GET /operations/{id}` | Stage, result, retries and structured failure. |
| `POST /vms/{id}/terminals` | Create guest PTY session, scoped identity and initial size. |
| `GET /vms/{id}/terminals` | Existing sessions, ownership, state and retained window. |
| `GET /terminals/{id}/stream` | Authenticated WebSocket upgrade; cursor and writer lease. |
| `POST /terminals/{id}/lease` | Acquire/transfer/release writer permission. |
| `DELETE /terminals/{id}` | Explicitly terminate the guest session. |
| `POST /vms/{id}/execs` | Idempotent structured argv execution. |
| `GET /execs/{id}` / `POST /execs/{id}/cancel` | Query or cancel tracked guest execution. |
| `GET /execs/{id}/output` | Independently cursorable stdout/stderr and truncation metadata. |
| `POST /vms/{id}/runs` | Create a declarative run on a running VM; idempotency key. |
| `GET /runs` / `GET /runs/{id}` | List/inspect runs: goal, criteria, phase, outcome, evidence links. |
| `GET /runs/{id}/report` | Machine-readable run report; retryable generation status. |
| `POST /runs/{id}/conclude` | Submit an operator verdict for `operator_verdict` criteria, or abort with a reason. |
| `POST /annotations` / `GET /annotations` | Immutable operator notes on any entity ref; queryable by ref. |
| `GET /events` | Keyset-paged historical events with bounded filters. |
| `GET /events/stream` | SSE replay/live stream using durable cursors. |
| `GET /vms/{id}/coverage` | Sensors, gaps, exclusions and trust/capture mode. |
| `GET /vms/{id}/filesystem/diff` | Finalization state and paged manifest changes. |
| `POST /vms/{id}/exports` | Start bounded export; returns operation/artifact IDs. |
| `GET /artifacts/{id}` | Authorized metadata/download with digest and capture labels. |

Require an expected revision on conflicting lifecycle changes. Return structured errors with `code`, `message`, `retryable`, `operation_id` and safe details. Distinguish malformed request, unauthorized/not found, conflict, missing capability, capacity rejection, timeout and upstream/runtime failure.

Errors additionally carry a typed `cause` and, where the system knows the remediation space, a `remediation` array of executable action descriptors with rationale (P-06). For example, `insufficient_capacity` returns the shortfall, current reservations, and options such as `{"action": "queue"}` or candidate idle VMs to stop. Remediation options are suggestions, never auto-executed. OpenAPI descriptions of every mutation declare its effect scope and reversibility so a driving agent can weigh an operation without out-of-band knowledge.

Use one idempotency key scope per owner/action; persist request hashes and results for a configured retention period. A repeated identical request returns the original outcome. Do not return guest/host paths or secret material in error details.

### 14.1 CLI contract

The CLI is a first-class operator interface, not a demo wrapper. Every command supports `--json` with the same shapes the API returns; human-readable output is a formatting of the same data, never a different truth. Exit codes are typed: success, structured failure, transport failure, usage error. Provide at minimum `vmobs doctor|situation|attention|launch|runs|report|events|vm|export` and a raw authenticated `vmobs api <method> <path>` escape hatch. `vmobs situation --since <cursor>` and `vmobs attention ack` make the poll loop scriptable without the browser.

Serve a terse agent operating guide from the running daemon (`GET /meta` links it): how to launch, watch, harvest and diagnose, with one worked fleet-loop example. Its reference material is generated from the OpenAPI contract and event-kind registry, not maintained by hand (P-07).

### 14.2 Bounded agent slice

The implemented bootstrap is `GET /api/v1/meta` (CLI: `vmobs --json meta`). Its
`routes` array derives method, path template, feature and built state from the
routing table; collection `links` derive from built GET routes. Auth-management
routes stay in the catalog rather than generic collection links. Nil handlers
remain `built:false`, including the SSE stream. The `agent` block states the
workflow and current limitations. Selected route `purpose`, `request_example`
and `instructions` describe launch with an attached operator-verdict run,
conclusion, revision-bound stop, snapshot and event resume. Examples use the
handler request types; this is not a full OpenAPI schema surface.

VMs expose self/actions/runs links, operations expose self/VM links, and runs
expose self/conclude/report links. A client starts from metadata, captures a
snapshot cursor before mutation, persists its exact keyed launch request, then
follows response links to watch, assess and stop. Launch replay requires the
same owner, key and canonical request; lifecycle actions are not replay-safe
merely because they carry a revision. An uncertain action must be inspected.

Every structured non-2xx API error adds `retry_strategy`: stale revisions/cursors use `after_refresh`;
otherwise an error with an operation uses `query_operation` and its concrete
read link; bounds/capacity or other retryable errors use `after_precondition`;
other failures use `never`. Strategies guide recovery rather than promise that
an automatic repeat succeeds. `same_request` is reserved in the described
vocabulary; the slice specifically permits exact keyed launch replay and safe
reads, not blind repeats of arbitrary mutations. Existing `retryable` remains.

Situation includes `attention_open` and `omitted` entries for attention head
and changed VMs, each with `count` and `expand`. `at_least:true` denotes a lower
bound from a one-extra-row changed-VM probe, including later byte shedding.
Expansion is a current queue/inventory read, not an atomic historical snapshot.
Counts and watch scope are never shed. If the irreducible envelope cannot
fit the configured ceiling, return 503 `situation_envelope_exceeds_bound` with
configured/minimum bytes and a configuration remediation. That fixed error
envelope is exempt from the successful-summary byte ceiling.

Client resume persists a processed event page's `next_after` and resource links.
Use exclusive `after`, preserve filters, and optionally freeze `until`. Never
skip to `latest_event_id` after a partial page. An empty page preserves the
cursor. Situation `as_of_cursor` is an orientation anchor from separate live
reads, not proof of consumption. Resume assumes the same retained database;
installation/retention-gap detection and server checkpoints are unimplemented.
Situation/events remain shared host observations; resource ownership rules do
not make those views private.

Exact plan approval, plan/apply, per-work budgets and mutation watch cursors are
unimplemented and reported false in metadata. Host reservations and lifecycle
deadlines do not substitute for work-budget accounting or human plan approval.
The precise deferred approval/budget semantics, code-backed gap map and
supplemental V2-AGENT scenarios live in `design/agent-control-contract.md`.

## 15. Security, secrets and operator authentication

### 15.1 Deployment mode

The appliance defaults to HTTP on `0.0.0.0:8787` with authentication disabled,
as requested for remote deployment. Every client that can reach that listener
can use the API. `server.mode: http` permits this bind; `loopback_only` restricts
the listener to loopback, and `https` requires TLS and authentication. Browser
WebSockets still require an exact match against `server.public_origin`.
Support a single local operator account or a trusted reverse-proxy identity
integration with explicit trusted proxy addresses and stripped/validated
identity headers. Do not trust arbitrary inbound `X-User` headers.

Use secure, HttpOnly, SameSite cookies for browser sessions, CSRF protection on mutations, exact-origin checks for WebSockets, session expiration and per-resource authorization. CLI uses scoped tokens. Bind terminal tickets, if used, to owner/VM/session and a short lifetime; do not put persistent tokens into query strings or access logs.

Even in single-user V1, carry owner IDs through storage and authorization and test cross-owner denial. This avoids building an unauthenticated local shell server that later becomes exposed by a reverse proxy.

### 15.2 Threat model

In scope: buggy/adversarial agent programs, guest root attempts, malicious filenames/output, resource exhaustion, proxy bypass, source spoofing, credential leakage in logs, cross-VM access, browser-origin attacks, and partial host-service crashes.

Out of scope for a guarantee: a compromised host kernel/admin, undetected hardware vulnerabilities, perfect guest-root-resistant path/process telemetry, and preventing all exfiltration to intentionally allowed services. Apply Firecracker's production host guidance and normal patching rather than treating KVM alone as a complete security program. [S2]

### 15.3 Secret handling

Reference host-managed secret IDs in launch requests; do not embed literal keys in templates, launch-history JSON or URLs. Deliver only requested scoped secrets after authenticated guest readiness. Do not expose cloud metadata credentials or forward the host's entire environment.

Redact authorization/cookie headers, configured secret literals, sensitive query parameters and supported structured body fields **before spool/database persistence**. Do not collect full process environments. Bound/redact argv because credentials can be passed as arguments. Apply the same policy to error messages, debug logs, exports and proxy records. Run goals, guest-submitted results, annotations and attention summaries pass the same redaction policy before persistence as argv and headers.

Redaction is defense in depth, not a proof that arbitrary binary/encoded content contains no secrets. Default body, pcap, full-file and persistent terminal recording to off. Content capture that can contain secrets is explicitly sensitive even after attempted redaction. Record policy version and redaction/truncation actions without storing the secret that triggered them.

Protect retained disks: secrets written by the workload may remain in a disk image even when event logs are redacted. Restrict disk exports separately, support retention/secure storage policies, and never describe wiping a file inside a guest as guaranteed erasure of all retained copies.

### 15.4 Untrusted host input handling

Normalize and bound guest messages before indexing. Avoid regex denial-of-service in user filters and proxy rules. Use safe descriptor-relative path handling for owned host files and prevent symlink escapes. Escape HTML, spreadsheet-dangerous strings in any future CSV export, and terminal control characters in ordinary logs.

An agent's control channel may request guest operations, not arbitrary host network fetches, host file reads, host execs or host socket connections. Artifact paths are constrained to guest-approved scopes and returned bytes never choose a host destination path.

## 16. Operations, retention and observability

Expose service health for API, database writer, scheduler, privilege helper, each runner, proxy/DNS/flow worker and guest sensor. Monitor queue depth, dropped counts, durable acceptance/indexing lag, WAL size, disk reserve, process health, operation duration and cleanup backlog.

Run reconcilers periodically as well as on startup. Maintain a host-wide emergency stop that cuts guest uplinks and stops owned VMMs without waiting on guest telemetry. Authenticate and audit its use.

Separate retention of event metadata, body/previews, terminal recordings, pcaps and disk images. Retention must never prune records still needed by an active spool/index transaction. Cursor expiry and artifact deletion remain visible as metadata. Pinning/exporting evidence does not make it tamper-proof against host administrators.

Back up SQLite using a consistent database backup mechanism, not an arbitrary copy of a live DB file while ignoring WAL. Back up immutable artifacts and manifests consistently. Test restoration to a separate test installation. This is host-local durability unless an actual off-host backup is configured.

Exports contain normalized events, manifest/diff, image/artifact digests, VM/template/runtime-lock metadata, network/capture policy, coverage gaps, run reports, annotations, attention history and truncation/redaction summaries. Include start/end capture boundaries and a schema version. Exporting a hash manifest provides integrity checking against retained data, not automatic nonrepudiation.

Upgrade guest agent, kernel and host components through a compatibility matrix. Refuse incompatible protocols with an actionable error. Database migrations require a backup/rollback plan and must not run concurrently with a second writer. Do not kill running VMs as an undocumented side effect of a UI upgrade.

## 17. Failure behavior matrix

| Failure | Required behavior |
|---|---|
| Browser disconnect | Keep VM and PTY alive; permit bounded replay and show gaps. |
| Controller restart | Runners/VMMs keep operating; spool queues telemetry; replay into DB without duplicates. |
| Runner restart | Reconcile owned VMM; reconnect channels; mark collection interruption/new source identity. |
| Guestd killed | Host health becomes degraded/unavailable; egress enforcement remains; apply strict policy if enabled. |
| Guest spoofs VM ID | Ignore/reject supplied authority; source remains bound to owned channel. |
| VMM exits | Stop jobs/sessions from UI perspective; finalize available spool/disks; preserve exit reason. |
| API socket unresponsive | Bounded health checks; independent owned-process termination path. |
| Network observer dies | Policy stays enforced; mark observation unavailable; block egress under strict policy. |
| Inspection proxy dies | `http_inspect` egress fails closed; no direct-route fallback. |
| DNS worker dies | Managed resolution fails visibly; no fallback to an arbitrary external resolver. |
| SQLite busy/down | Bounded spool growth; no false indexed/visible claim; capacity/loss policy at limit. |
| Spool/disk fills | Stop acknowledging undurable data; preserve control/health reserve; degrade or stop per policy. |
| Kernel ring/fanotify overflow | Emit explicit measured/unknown loss information and mark affected coverage. |
| VM workspace full | Guest gets a storage error; other VMs and host remain healthy. |
| Dirty/corrupt captured filesystem | Isolated inspection/recovery only; incomplete/recovered diff labeling. |
| Concurrent stop/delete/start | Serialize per-VM transitions with revisions and operation IDs; no double allocation. |
| Host reboot/power loss | Cold reconcile persisted resources; retain acknowledged host data within stated storage guarantees; report interrupted runs. |
| Attention queue overflow | Collapse duplicates by VM and kind with counts; never drop unacknowledged critical items silently; overflow raises its own health record. |
| Run report generation fails | The run outcome stands; the report is marked incomplete and retryable as an operation; VM lifecycle never blocks on rendering. |
| Guest submits malformed/oversized result | Bounded rejection with a recorded reason; criteria become unevaluable per policy (`inconclusive`), with no invented verdict and no crash. |
| Emitter produces unregistered event kind | Reject at ingress normalization with a health record; the build/test gate should have prevented it, but runtime stays honest. |

No test should pass by suppressing the error banner, dropping a sensor, or changing the profile silently.

## 18. Build sequence and deliverables

### Milestone 0 — Real host and image foundation

Implement `doctor`, version locking, image build, guest capability probe, private networking and a jailed boot fixture. Deliver a documented Linux host setup and a reproducible known-good image. Gate: real KVM boot, vsock handshake, sensor capability report and independent disk ownership.

### Milestone 1 — Vertical slice with a real terminal

Build the API/CLI, narrow privilege helper, runner and lifecycle operations. Add the minimal fleet page and one xterm terminal backed by a guest PTY. Then demonstrate two simultaneously running VMs with independent terminals, storage and stop actions. Include `GET /meta`, structured errors with typed cause, and `--json` on every CLI command from this first slice; retrofitting self-description later always loses. Gate: no host shell proxy masquerading as a guest terminal; reconnect does not spawn a duplicate shell.

### Milestone 2 — Durable events and guest sensors

Implement event schemas, runner spool, SQLite index/replay, capability/health model, process sensor and filesystem notifications. Add the live timeline and process view. Wire the event-kind registry to the emitters, streaming rollup counters, the annotation store, and situation v0 (lifecycle, telemetry health, delta cursors). Gate: deterministic fixture observations, explicit mmap limitation, forced overflow visibility, controller-restart recovery, deduplication, and rejection of unregistered event kinds.

### Milestone 3 — Host network observation and policy

Implement transport/offline profiles, managed DNS, namespace isolation, flow/deny views and bypass tests. Add `http_inspect` with per-VM CA, streaming capture and redaction. Gate: proxy failure does not leak direct egress; pinned/unsupported traffic is accurately labeled; no cross-VM attribution.

### Milestone 4 — Final state, artifacts and full workspace UI

Implement workspace seed/baseline, isolated stopped-disk inspection, manifests/diffs, bounded previews, exports, filters and batch UI. Implement declarative runs end to end: guest context device, progress/result submission, run reports, and the full attention trigger set. Gate: detect content/metadata/type changes correctly and refuse unsafe host mounts; malformed disk/output fixtures cannot escape their limits; report counts reproduce through their linked queries; the guest context never promises what enforcement denies.

### Milestone 5 — Recovery, load and security acceptance

Complete race, capacity, crash, authentication, secret-leak, browser-security and noisy-neighbor tests. Measure actual overhead and update reservations/targets. Measure the interaction economy of the reference fleet loop and publish the trace. Gate: every V1 mandatory acceptance row has evidence or an explicitly reported failure; no mocked integration evidence.

### Required repository shape

```text
cmd/vmobs/                 CLI
cmd/vmobsd/                API/controller/indexer
cmd/vmobs-privd/           narrow privileged helper
cmd/vmobs-runner/          per-VM supervision / spool / channels
cmd/vmobs-guestd/          guest control, PTYs, execs, telemetry
internal/api/             OpenAPI, auth, handlers
internal/runtime/         Firecracker adapter, reconciliation
internal/network/         topology, policy, managed workers
internal/events/          schemas, normalization, redaction, spool
internal/store/           SQLite, migrations, cursor queries
internal/runs/            declarative runs, criteria evaluation, reports
internal/situation/       fleet rollups and attention queue
internal/terminal/        bounded transport and session rules
internal/guest/           sensor/control implementations
bpf/                      small BPF programs and generated bindings
proxy/                    pinned mitmdump addon and tests
web/                      React application
images/                   guest and inspector image definitions
schemas/                  versioned interchange contracts
tests/fixtures/           deterministic guest/network/filesystem fixtures
tests/integration/        real KVM lifecycle and multi-VM tests
tests/security/           boundary and malformed-input tests
docs/                     architecture decisions and operating runbooks
```

Interfaces should permit a fake runtime for isolated tests, but the production path should use Firecracker's pinned API contract over its Unix socket. Keep runtime-specific details out of the browser.

## 19. Acceptance and performance contract

`ACCEPTANCE.md` is part of this specification, not an optional appendix. The builder must track each test with status, actual result, environment/runtime lock, relevant logs/artifacts and unresolved defects. Initial status is **SPECIFIED / NOT RUN**.

A release candidate must demonstrate concurrent VMs, terminal functionality, honest telemetry coverage, host egress enforcement, durable replay, final disk diff, secret handling and crash recovery together—not as isolated demo screenshots.

Performance numbers below are **acceptance targets to measure**, not existing benchmark results:

- Reference validation machine: KVM-capable Linux, at least 12 logical CPUs, 32 GiB RAM, and SSD storage with 200 GiB free. Record exact hardware and bare-metal/nested context. Smaller hosts remain useful with lower concurrency; this is a test profile, not a product minimum.
- Four simultaneous default-sized VMs performing bounded fixture workloads with independent terminals and logs.
- On a local browser/LAN, interactive terminal echo target p95 below 150 ms under the reference load.
- Event observation-to-UI target p95 below 1 second at 1,000 aggregate normalized metadata events/second.
- A 10,000-event/second short burst must cause either bounded catch-up or explicit loss/degradation, not unbounded memory or a frozen control plane.
- Memory/disk/throughput metrics include per-VM proxy and logging overhead, not just VMM RSS.
- Measure repeated create/start/stop/delete cycles and ensure owned resources return to the documented idle baseline. Report distributions and failures rather than a single best run.

Cold boot and package-install time targets should be established after the actual images are built. Do not inherit a microbenchmark boot number from Firecracker marketing as the application SLO.

Interaction-economy targets, to measure like all targets: driving the reference four-VM fixture loop — batch launch with runs, situation delta polling, report harvest, attention acknowledgment — through the CLI in JSON mode must fit a documented budget, proposed at most 16 API round-trips and 64 KiB of default-form response bytes excluding raw artifact downloads. AT-102 measures it; publish the measured trace. This budget is the concrete meaning of "least expenditure": an orchestrating agent's cost to drive the fleet is a first-class performance dimension beside latency and throughput.

## 20. Deferred snapshot/restore contract

Do not accidentally ship half a snapshot implementation. Firecracker memory/state snapshot files do not remove the caller's responsibility to preserve matching block-device contents, and snapshot operations can reset vsock connections. [S17]

Before enabling this later, require a coordinated VM/disk capture barrier, immutable matching disk versions, compatibility metadata, new clone identities/credentials, reconnect epochs and replay deduplication, uniqueness of vsock/socket/network resources, RNG/identity validation, and explicit guest clock/network discontinuity handling. Never resume a saved memory image against an unrelated newer workspace disk.

These deferred requirements do not block V1's cold start, pause/resume of the same running VMM, or concurrent template launches.

## 21. Verification ledger

The following **22 external platform-capability claims** were checked against the primary sources listed below while preparing this specification. They verify design premises, not the future implementation. All proposed defaults, architecture choices, APIs and performance goals elsewhere are requirements or recommendations, not externally verified product behavior.

| ID | Verified claim | Source |
|---|---|---|
| V-01 | Firecracker relies on Linux/KVM and processor virtualization for its isolation boundary. | S1, S2 |
| V-02 | A Firecracker process encapsulates one microVM. | S1 |
| V-03 | Firecracker network interfaces are backed by host TAP devices. | S1 |
| V-04 | Firecracker's emulated block devices are backed by host files. | S1 |
| V-05 | Firecracker does not itself perform guest egress filtering. | S1 |
| V-06 | Production guidance recommends jailed/constrained execution and separate VM identities. | S2 |
| V-07 | Firecracker mediates host Unix-domain sockets and guest AF_VSOCK, including a host-initiated CONNECT handshake. | S3 |
| V-08 | Fanotify has modification/create/delete/move-related notification classes; CLOSE_WRITE describes closing a write-open file. | S4 |
| V-09 | Fanotify can miss mmap-related modifications and lose events through queue overflow. | S4 |
| V-10 | Fanotify filesystem/mount marks have specific supported-mask and filesystem constraints. | S5 |
| V-11 | BPF ring-buffer reservation can fail; a bounded buffer is not a lossless promise. | S6 |
| V-12 | cilium/ebpf provides Go support for loading and attaching eBPF programs. | S7 |
| V-13 | Linux cgroup v2 exposes CPU, memory and process resource controls. | S8 |
| V-14 | Linux PTYs provide paired terminal interfaces for interactive terminal behavior. | S9 |
| V-15 | xterm documents untrusted terminal data and explicit WebSocket authentication/security requirements. | S10 |
| V-16 | xterm documents application-level flow-control acknowledgments over WebSockets. | S11 |
| V-17 | Mitmproxy regular proxy mode requires clients to use the proxy; some applications bypass proxy settings. | S12 |
| V-18 | TLS interception requires client trust configuration and may fail with certificate pinning. | S13 |
| V-19 | SQLite WAL permits concurrent readers but one writer; FULL commits sync the WAL, unlike NORMAL's durability tradeoff. | S14 |
| V-20 | Untrusted guest filesystems should not be mounted directly in the host kernel; isolated appliances reduce that exposure. | S15 |
| V-21 | Firecracker documents tested host/guest kernel combinations and warns that other configurations are not equivalently validated. | S16 |
| V-22 | Snapshot users must preserve matching block-device files separately, and snapshot operations can reset vsock connections. | S17 |

The ledger deliberately does not assert that an unpinned current release or kernel tuple will work. The builder must select and empirically verify its exact locked combination.

### Primary sources

Checked August 30, 2026. Moving documentation must be rechecked and pinned to the actual release used by the builder.

- **S1 — Firecracker design:** https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md
- **S2 — Firecracker production host setup:** https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md
- **S3 — Firecracker virtio-vsock:** https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md
- **S4 — Linux fanotify(7):** https://man7.org/linux/man-pages/man7/fanotify.7.html
- **S5 — Linux fanotify_mark(2):** https://man7.org/linux/man-pages/man2/fanotify_mark.2.html
- **S6 — Linux BPF ring-buffer documentation:** https://docs.kernel.org/bpf/ringbuf.html
- **S7 — cilium/ebpf project:** https://github.com/cilium/ebpf
- **S8 — Linux cgroup v2 documentation:** https://docs.kernel.org/admin-guide/cgroup-v2.html
- **S9 — Linux pty(7):** https://man7.org/linux/man-pages/man7/pty.7.html
- **S10 — xterm.js security guidance:** https://xtermjs.org/docs/guides/security/
- **S11 — xterm.js flow-control guidance:** https://xtermjs.org/docs/guides/flowcontrol/
- **S12 — Mitmproxy proxy modes:** https://docs.mitmproxy.org/stable/concepts/modes/
- **S13 — Mitmproxy certificates:** https://docs.mitmproxy.org/stable/concepts/certificates/
- **S14 — SQLite WAL documentation:** https://www.sqlite.org/wal.html
- **S15 — libguestfs security:** https://libguestfs.org/guestfs-security.1.html
- **S16 — Firecracker kernel support policy:** https://github.com/firecracker-microvm/firecracker/blob/main/docs/kernel-policy.md
- **S17 — Firecracker snapshot support:** https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md

## 22. Definition of done

An operator can launch several real Firecracker VMs from the browser, type into the correct guest terminals, see attributed observations and declared gaps, inspect external traffic at the enabled capture level, stop one without disrupting the others, recover through controller failure, and export retained evidence plus an accurate final-state diff.

The system remains useful when telemetry is incomplete because it tells the truth about the boundary and the missing evidence. It does not obtain observability by handing the guest access to the host.

And an agent operator with no prior context can, through the CLI and API alone, reconstruct the situation, dispatch goal-carrying runs across the fleet, be drawn to exactly the events that need judgment, and harvest linked evidence — within the documented interaction budget. What one operator session learns, the next one finds waiting in the system.
