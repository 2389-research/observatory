# M2a — Guest telemetry transport and sensor health

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Open a guest→host telemetry channel and prove it end to end with one kind. A running VM's guest agent pushes a sensor-health heartbeat on its own vsock port; the runner stamps it `guest_reported`, spools it, and the store indexes it. `GET /situation` then answers SPEC §138's question — *is this VM's telemetry healthy while the VM is running?* — from measurement rather than from a zero-valued struct field.

M2 is four slices, each with its own branch, gate and merge:

| Slice | Content |
|---|---|
| **M2a** | telemetry transport + `guest.sensor_health` end to end + Reconcile adopts healthy runners |
| M2b | process sensor (eBPF, cilium/ebpf) |
| M2c | filesystem sensor (fanotify) |
| M2d | `/events/stream`, live timeline, process view |

M2a builds the pipe every later sensor pushes through, and the health block every later sensor registers into. It deliberately ships with **zero sensors**: the heartbeat honestly reports an empty sensor list, and M2b/M2c fill it.

**Architecture:** a third vsock port beside the two that exist.

```text
                          guest                     |            host
  sensors (none in M2a) -> bounded ring -> guestd  -[10001]->  runner -> spool -> store
  guest shell           -> PTY broker   -> guestd  -[10002]->  runner -> terminal relay
                                            guestd <-[10000]-  runner (ping / control)
```

Port 10001 was reserved and unused. It gets telemetry for the same reason 10002 got PTY bytes, recorded verbatim at `internal/runner/terminal.go:20`: *"Control verbs stay on vsockPort: that channel is strictly request/response, and a terminal's bytes would starve the ping cycle sharing it."* A sensor firehose starves it harder than a terminal does. guestd listens on all three; the runner dials all three.

**Trust boundary.** The guest is not trusted ingress; the runner is. Three consequences bind every task:

1. The runner stamps `Provenance: guest_reported` on everything arriving on 10001. The guest never states its own provenance, and a guest-supplied provenance field is a protocol error, not a value to read.
2. The runner **assigns** the telemetry stream's `source_instance_id` at handshake, derived from its own trusted `InstanceID`. The guest never picks it. `streams.source_instance_id` is a host table's primary key; an untrusted party does not write it.
3. The guest **owns** the `source_seq` within that assigned identity, monotonically. The runner validates: a seq that does not increase is dropped and reported as `telemetry.integrity_failure`.

The payoff for (3) is idempotence across a reconnect. The store already dedups on `(source_instance_id, source_seq)` with identical payload and raises `seq_payload_conflict` on a differing one. A guest that reconnects and re-sends its unacknowledged tail is therefore free of duplicates. Had the runner re-stamped with its own counter, every re-send would land as a fresh event.

**Tech Stack:** Go 1.26 (project toolchain), no new dependencies. One guest rootfs rebuild and lock re-pin.

**Spec:** `docs/SPEC.md` — §7.3 (vsock ports), §9 (health records), §110 (telemetry rides vsock), §112/§507/§961 (loss is measured or explicitly unknown), §138–§139 (`telemetry_health`, per-sensor coverage/heartbeat/drops), §320 (Reconcile adopts healthy runners), §952 (guestd killed → degraded), §12.2/§17 (kind registry is ingress law), §18 M2.

## Global Constraints

- SPEC §1.4 principles P-01..P-08 bind every surface: bounded, cursorable, linked, honest.
- **Evidence honesty is the product.** Never fabricate counts, verdicts, or coverage; `inconclusive` beats an invented answer. An empty sensor list is the honest M2a answer and no task may pad it.
- **Provenance labels are assigned by trusted ingress only.** The runner labels; the guest reports. A guest field named `provenance`, `host_received_at`, `source_instance_id`, or `event_id` is rejected at the runner, not copied through.
- §507/§961: every loss path carries an explicit counter or an explicitly-unknown interval. The guest ring is bounded and its drop count is reported; a silent drop anywhere in this plan is a defect.
- §8.3 verbatim: "Bound every queue. A slow browser must not stop sensor ingestion or the control channel." Read symmetrically here — a slow host must not stop the guest, and a chatty guest must not stop the ping cycle. Every buffer in this plan has a byte or item cap and a declared drop behaviour.
- Counters that can exceed JS safe integers are decimal strings in JSON. Everywhere — `source_seq`, drop counts and monotonic nanoseconds included.
- Event kinds must be registered in `internal/events` before anything emits them; ingress rejects unregistered kinds. Registration and emitter land in the same task.
- §15.3: the auth token is read from `--token-file` only, and never appears in argv, State, logs, error strings, spooled events or evidence. The telemetry handshake reuses the existing `AuthProof` path and adds no second secret.
- The fake runtime (`internal/runtime/runtimetest`) is unit-test-only; never reachable from served modes. Same rule for any fake sensor or fake ring this plan adds.
- TDD with real components at the seams we own: real SQLite, real HTTP, real vsock where the platform allows and a real `net.Pipe`/Unix socket where it does not. Linux-only tests carry `//go:build linux` and run via `scripts/linux '<cmd>'`.
- Canonical gate: `env -u GOROOT mise exec -- ./scripts/check` before claiming anything works.
- New source files start with two `ABOUTME:` comment lines.
- NEVER run password sudo on aibox03. Agents may invoke only `sudo -n /usr/local/sbin/vmobs-root-helper <verb>`. A rootfs rebuild runs as the ordinary user through `images/rootfs/build.sh` (docker); installing anything privileged is a Doctor Biz handoff.
- Conventional commits, imperative, present tense. No attribution lines or trailers. Never `--no-verify`. Never `git add -A` without first running `git status`.

## Decisions this plan fixes (record in PLAN.md deviations log at close-out)

- **D1 — M2 ships as four slices, transport first.** Each slice gets its own branch, gate and merge. A sensor and the pipe it pushes through must not land together: a transport bug and a sensor bug look identical from the store.
- **D2 — telemetry gets vsock port 10001, not a multiplexed 10000.** Reserved and free. The precedent is `terminal.go:20`; the argument is stronger for a sensor firehose than it was for a terminal.
- **D3 — the host names the stream, the guest counts within it.** The runner derives the telemetry `source_instance_id` from its own `InstanceID` at handshake and hands it to the guest. The guest supplies a monotonic `seq`; the runner validates it and drops-with-report on a regression. Cost if wrong: an untrusted party influences a key the store indexes on, bounded by the runner's validation and by `stream_scope_rebind` catching a cross-VM collision.
- **D4 — the first kind is `guest.sensor_health`, a new one.** `fs.modify` is already registered and would work, but it pulls the whole fanotify slice into M2a and entangles the transport with a sensor. `telemetry.loss` is already registered and host-observed, but under M2a nothing emits guest events, so its count would always be zero — a loss counter with nothing to lose. The heartbeat is not a kind invented to exercise the pipe: §138 and §139 mandate `telemetry_health` and a per-sensor block with heartbeat time and observed drops, and neither exists. Cost if wrong: one registered kind whose sensor list is empty until M2b.
- **D5 — the heartbeat belongs to the `guest` family, not `telemetry`.** The `telemetry.*` family is host-side facts about the pipeline (`loss`, `integrity_failure`, `unregistered_kind`), all `host_observed`. A guest agent's self-report is a different thing with a different provenance. `guest.*` already means "facts about the guest agent". Cost if wrong: a rename before anything external consumes it.
- **D6 — the eBPF toolchain question is deferred to M2b.** Nothing in M2a compiles BPF. §247's "`runtime.lock.json` should carry eBPF object digests" is M2b's problem, decided when there is an object to digest.

## File map

**New**
- `internal/guest/proto/telemetry.go` — telemetry frame types and the port constant.
- `internal/guest/telemetry/ring.go` — the guest's bounded ring with an explicit drop counter.
- `internal/guest/telemetry/health.go` — the sensor registry and the heartbeat producer; the registry is empty in M2a.
- `internal/guest/telemetry.go` — the guest's third listener: handshake, drain loop, ack reader, heartbeat ticker.
- `internal/runner/telemetry.go` — the host half: dialer, instance-id assignment, seq validation, stamping, spool.
- `internal/situation/telemetry_health.go` — `telemetry_health` derivation from heartbeat age and sensor states.

**Changed**
- `internal/events/registry.go` — register `guest.sensor_health` with its caveats.
- `cmd/vmobs-guestd/main.go` — a third listener and a `--telemetry-port` flag.
- `internal/guest/agent.go` (package `guest`) — `ServeTelemetry`, beside `ServeControl` and `ServeStreams`.
- `internal/runner/runner.go` — start the telemetry loop beside the ping loop; `newGuestEnvelope`.
- `internal/situation/engine.go` — `SensorsDegraded` computed, not zero.
- `internal/api/working_set.go`, `internal/api/vms.go` — publish `telemetry_health`.
- `internal/runtime/` — Reconcile adopts a healthy runner (ffxv).
- `runtime.lock.json`, `images/` — rootfs rebuild and re-pin.
- `docs/ACCEPTANCE.md`, `PLAN.md`, `gotchas.md`.

## Protocol contract (Tasks 1, 2, 3 all implement this; none may redefine it)

Port **10001**. guestd listens, runner dials, same as 10000 and 10002.

**Handshake.** The runner sends the existing `Hello` (carrying `AuthProof` from `--token-file`, `VMID`, `BootID`). guestd replies `hello_ack`. The ack on this port carries one extra field: the telemetry stream identity the runner assigns.

```text
runner -> guest   hello       { protocol_version, vm_id, boot_id, source_instance, auth_proof }
guest  -> runner  hello_ack   { accepted, reason, telemetry_instance_id }
```

- `telemetry_instance_id` is echoed by the guest but **chosen by the runner** and carried in `Hello`; the guest stores it and stamps nothing with it. If the echo disagrees with what the runner sent, the runner closes the connection and reports `telemetry.integrity_failure`.

**Acknowledgements.** After the handshake the host sends `telemetry.ack` — `{ "through_seq": "41" }` — the only frame travelling host to guest on this port. It is cumulative: acking 41 releases 1 through 41 from the guest's ring. The runner sends it after the spool append returns, because the spool is the host's durable boundary.

The guest forgets an event when it is acknowledged, never when a write to the socket returned. A write that returned proves the bytes reached a kernel buffer, which is no evidence the host kept them; releasing there loses every in-flight event on a broken connection and counts nothing. So a reconnect re-sends everything unacknowledged and the store's dedup absorbs the duplicates, while a host that stops acking makes the bounded ring drop — and count — instead.

**Push frames.** One direction, guest to host, riding the existing `FrameControl` path (`proto.WriteControl` / `proto.ReadControl`) with kind `telemetry.push`. Not a second framing: `ReadFrame` already validates a hostile length *before* allocating, which is exactly what a port fed by an untrusted guest needs, and the 1 MiB ceiling it enforces is one the same guest already reaches on port 10000. The telemetry layer caps the decoded payload at 64 KiB on top of that.

```json
{ "seq": "41", "kind": "guest.sensor_health", "guest_wall_at": "...", "guest_monotonic_ns": "...", "data": { ... } }
```

**Those five keys and no others.** `DecodeTelemetryPush` runs an allow-list, not a deny-list naming the fields the host assigns — a deny-list would silently start permitting whichever field `events.Envelope` grows next, while an allow-list refuses it until someone decides otherwise. A guest offering `provenance`, `source_instance_id`, `host_received_at` or any other unlisted key is a protocol violation, not an input to sanitize.

**Seq rule.** Strictly increasing within a connection *and* across reconnects on the same `telemetry_instance_id`. `seq <= last_accepted` is dropped, counted, and reported once per connection as `telemetry.integrity_failure` with `failure: "guest_seq_regression"`.

**`guest.sensor_health` data shape** (§139: coverage, last heartbeat, drops, unknown loss, exclusions, capture mode):

```json
{
  "agent":   { "version": "...", "started_at": "...", "uptime_ns": "...", "heartbeat_interval_ns": "..." },
  "ring":    { "capacity": 1024, "queued": 0, "dropped": "0" },
  "sensors": []
}
```

Each sensor entry, once M2b/M2c add one:

```json
{ "id": "process", "state": "healthy|degraded|unavailable", "last_event_at": "...",
  "dropped": "0", "unknown_loss_intervals": 0, "capture_mode": "...", "exclusions": [] }
```

# Phase A — the pipe

### Task 1: Register `guest.sensor_health` and define the telemetry frames

- [x] `internal/events/registry.go`: register `guest.sensor_health`, family `guest`, schema version 1, provenance `guest_reported`, with caveats stating honestly that a heartbeat proves the agent is alive and not that any sensor observed anything, that an empty sensor list means no sensor is registered rather than no activity, and that drop counts are the guest's own measurement.
- [x] `internal/guest/proto/telemetry.go`: `TelemetryPort = 10001`, `KindTelemetryPush`, `MaxTelemetryPayload`, the `TelemetryPush` type and `DecodeTelemetryPush`. `HelloAck` gains `telemetry_instance_id` and `resume_after_seq`, both `omitempty`, exactly as `resume_offset`/`gap` already serve only the stream port.
- [x] Tests: the kind is registered as `guest_reported` in family `guest` with caveats; the port is 10001; a push frame round-trips with a `guest_monotonic_ns` past 2^53 intact; each of thirteen host-assigned keys is refused by name; a missing or non-decimal `seq` and a missing `kind` are refused; an over-cap payload is refused.
- **Ruling: allow-list, not deny-list.** The plan first said "reject a frame carrying any of `provenance`, `source_instance_id`, …". A deny-list is wrong here for a reason that outlives this slice: it silently starts permitting whatever field the envelope grows next. The frame admits `seq`, `kind`, `guest_wall_at`, `guest_monotonic_ns`, `data` and nothing else. Cost if wrong: a later sensor wanting `process_key` or `run_id` on the frame adds it to the list deliberately, which is the point.
- **Ruling: reuse `FrameControl`, do not invent a telemetry frame type.** The plan sketched newline-delimited JSON; the repo already has length-prefixed framing that bounds a hostile length before allocation, which is strictly better against an untrusted guest — a newline-delimited reader scans for a delimiter that may never arrive. A dedicated frame type would buy a smaller pre-allocation ceiling, but the guest already reaches the 1 MiB control ceiling on port 10000, so it is not new exposure. Cost if wrong: telemetry shares a size ceiling with control verbs, and the 64 KiB cap sits one layer up.
- Six mutation proofs, all killed: the allow-list accepting any key; no payload cap; `seq` unvalidated; the port set to 10000; the kind registered `host_observed`; the kind registered with no caveats.

### Task 2: The guest's bounded ring, sensor registry, and third listener

- [x] `internal/guest/telemetry/ring.go`: fixed-capacity ring, drop-oldest, `dropped` as a decimal-string counter that never resets while the agent lives. Capacity 1024 — a heartbeat is a few hundred bytes, so a full ring stays under a megabyte in a small guest, and it holds hours of heartbeats across a host outage. A sensor firehose gets its own number, measured rather than guessed.
- [x] `internal/guest/telemetry/health.go`: the sensor registry rendering the `sensors` array, and the `Reporter` that turns registry plus ring stats into a heartbeat. Empty in M2a — no task registers a placeholder.
- [x] `internal/guest/telemetry.go`: `ServeTelemetry`, the drain loop, the ack reader, and `RunHeartbeat`.
- [x] `cmd/vmobs-guestd/main.go`: `--telemetry-port` (default 10001), a third `vsock.Listen`, `ServeTelemetry` started the way `ServeStreams` already is — a failure to listen degrades that port only and never takes down control, and the heartbeat runs either way.
- [x] Tests: a full ring drops oldest and counts; the counter is a decimal string past 2^53; a heartbeat with no sensors renders `"sensors": []` not `null`; a closed connection leaves the ring filling rather than blocking the heartbeat; a wrong token is refused on 10001; the ack echoes the host's assigned id; an unacknowledged event comes back on the next connection under the same seq; an acknowledged one does not.
- **Ruling: the ack releases the item, not the write.** The plan said "the sender writes what it peeks and pops once the write returned". That is wrong in a way that matters: a successful write means the bytes are in a kernel buffer, so a connection that dies in flight loses events and counts nothing — the silent loss §507 forbids, in the transport whose whole job is carrying evidence. The guest now holds what it sent, rewinds on reconnect, and drops only at the bound where the drop is counted. Cost if wrong: one extra frame kind, a reader goroutine, and duplicates on every reconnect that the store's dedup already absorbs.
- **Ruling: the guest reports its heartbeat interval.** A staleness threshold hardcoded on the host silently becomes wrong the day the guest's interval changes, and the two live in different binaries with different release cadences. `agent.heartbeat_interval_ns` rides every beat and Task 5 derives from it. Cost if wrong: one more field a guest could lie about, which is bounded by Task 5 clamping it.
- **Ruling: `agent.version` reports the protocol version.** Nothing stamps a build id into `vmobs-guestd` — no ldflags, no build info — so `vmobs-guestd/proto-1` is the only version fact the binary actually knows. Cost if wrong: the field is uninformative until a build stamp exists, which beats inventing one.
- Eight mutation proofs, all killed with verified clean reverts: drop-newest instead of drop-oldest; the drop counter removed; release-on-write instead of release-on-ack; an exact-match ack instead of a cumulative one; a `Rewind` that does not rewind; the telemetry port skipping authentication; the guest naming the stream instead of echoing the host; `sensors` rendered as `null` when empty.

### Task 3: The runner's telemetry loop — assign, validate, stamp, spool

- [ ] `internal/runner/telemetry.go`: dial 10001 with the same retry/backoff shape the supervision loop uses; derive `telemetry_instance_id` from `cfg.InstanceID` plus a per-connection generation counter so a guestd restart is visible as a new stream; handshake; then read frames.
- [ ] Per frame: reject reserved fields; validate `seq` strictly increasing; build the envelope with `Provenance: guest_reported`, `Sensor: "guestd"`, `HostReceivedAt: now`, the guest's `GuestWallAt`/`GuestMonotonicNS` carried through as reported; spool it.
- [ ] On a seq regression or a disagreeing identity echo: drop the frame, emit one `telemetry.integrity_failure` (host_observed, the runner's own stream) per connection, and keep the connection.
- [ ] Wire it beside the ping loop in `runner.go` so telemetry failure never ends supervision, and channel loss on 10000 does not silently stop telemetry.
- [ ] Tests: a pushed heartbeat reaches the spool with `guest_reported` and the assigned instance id; a frame carrying `provenance` is rejected; a regressed seq is dropped and reported exactly once; a reconnect re-sending its tail produces no duplicate rows through a real store; a guestd restart yields a distinct instance id; telemetry stalling does not stop the ping cycle.

### Task 4: Rootfs rebuild and lock re-pin

- [ ] Rebuild the guest rootfs with the new guestd via `images/rootfs/build.sh` (docker, ordinary user).
- [ ] Re-pin `runtime.lock.json` with the new root image SHA-256; confirm `/host/status` and a fresh VM's `images` block both report it.
- [ ] Never write to `~/vmobs-build/images/dist/` except through the sanctioned rebuild (PLAN.md ruling 38).

# Phase B — the answer

### Task 5: `telemetry_health` and a real `SensorsDegraded`

- [ ] `internal/situation/telemetry_health.go`: derive per-VM `telemetry_health` ∈ {starting, healthy, degraded, unavailable} from the newest `guest.sensor_health` for the VM's current boot — its age against the heartbeat interval, and its sensor states. No channel and no heartbeat is `unavailable` (§952); a stale heartbeat is `degraded`, not healthy.
- [ ] `internal/situation/engine.go`: `SensorsDegraded` counts degraded and unavailable sensors across running VMs instead of returning zero.
- [ ] Publish `telemetry_health` on the VM record and in the situation snapshot (§138: "Never encode observation quality only in lifecycle state").
- [ ] Tests: a running VM with no heartbeat reads `unavailable`; a fresh heartbeat reads `healthy`; a heartbeat older than the threshold reads `degraded` while the VM stays `running`; a heartbeat from a previous boot does not count for the current one.

### Task 6: Reconcile adopts a healthy runner (kata `ffxv`, adoption half)

- [ ] On daemon restart, a VM whose runner is alive and whose channel is healthy is adopted rather than treated as lost. See the `failed-vm-unreapable` gotcha for what currently happens instead.
- [ ] Identify the runner by the VM id in its argv, never by `/proc/<pid>/root` — see the `firecracker-jailer-pivot-root` gotcha.
- [ ] Tests: a live healthy runner is adopted across a daemon restart; a dead runner is not; a runner whose argv names a different VM is not.

# Phase C — evidence

### Task 7: The M2a gate on aibox03

- [ ] A live gate: boot a VM, observe heartbeats arriving, kill guestd and watch `telemetry_health` go `degraded` then `unavailable` (§952), restart it and watch a new stream identity appear, force a ring overflow and confirm the drop count is non-zero and reported, restart the daemon and confirm adoption.
- [ ] Record results in `docs/ACCEPTANCE.md` against real AT IDs. `inconclusive` where the run does not settle it. Never `TESTED_PASS` without an executed run and committed evidence.
- [ ] Gate needs ~21 GB free — see the `m1a-gate-disk-floor` gotcha; short disk mimics a regression.

## Explicitly out of scope

- Any sensor. No eBPF, no fanotify, no `process.*` kind. M2b and M2c.
- `/events/stream` and the live timeline. M2d — the route is a registered stub with a nil handler today and stays one.
- Backfill or replay of guest events across a host restart beyond what the guest's bounded ring already holds.
- Guest-side persistence of the ring across a guestd restart. A restart is a new stream by design.
- `require_telemetry` run policy (§717).
