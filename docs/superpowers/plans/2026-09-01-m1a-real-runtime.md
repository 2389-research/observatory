# M1a — Real Runtime Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Real Firecracker VMs launched, stopped, and deleted through the existing API/CLI on aibox03 — privd (narrow privilege daemon), jailer adapter, per-VM runner with durable spool, and doctor-gated admission.

**Architecture:** `vmobsd` (controller) drives the launch transaction through a new `internal/jailer` adapter implementing the existing `runtime.Runtime` interface. All root operations go through `vmobs-privd`, a root daemon speaking typed, validated requests over a Unix socket (peer-credential authenticated). Each VM gets an unprivileged `vmobs-runner` process that survives controller restarts: it supervises the VMM by identity (pid + start time + argv), owns the guest vsock control channel, and writes events to a durable per-VM spool that the controller imports into SQLite through the existing dedup path.

**Tech Stack:** Go 1.26 (project toolchain), Firecracker v1.16.1 + jailer, vsock, SQLite (existing store), systemd units on aibox03. No new third-party Go dependencies.

**Spec:** `docs/SPEC.md` (binding contract — §3.2, §3.3, §4.1, §5.2–5.5, §6.2, §6.4, §7.3, §7.4, §12.4, §12.5, §15.3, §15.4, §17, §18 M1). Acceptance IDs: `docs/ACCEPTANCE.md`. Terminal path and fleet page are the M1b plan, not this one.

## Global Constraints

- SPEC §1.4 principles P-01..P-08 bind every surface: bounded, cursorable, linked, honest.
- Evidence honesty: never fabricate counts, verdicts, or coverage; `inconclusive` beats an invented answer. No TESTED_PASS without an executed run and committed evidence.
- §3.3 verbatim: privd accepts "only typed requests"; "Do not accept an arbitrary shell command, arbitrary nftables text, arbitrary executable path, arbitrary device path, or an unrestricted mount request. Invoke approved binaries with argument arrays, not `sh -c`."
- §12.4 verbatim: "Only after the spool record and required filesystem metadata are durably flushed may the runner acknowledge acceptance"; "Do not acknowledge merely because bytes reached an in-memory channel." Store guarantee is at-least-once transport with deduplicated storage.
- §15.3: secrets never in argv, logs, events, evidence, or error messages. Capability tokens ride files with 0600 modes.
- §5.3: persist a provisioning manifest before each external side effect; on failure undo owned resources in reverse dependency order; never delete by fuzzy name match.
- Counters that can exceed JS safe integers are decimal strings in JSON. Everywhere.
- SQLite: WAL, `synchronous=FULL`, exactly one logical writer. Keyset pagination only.
- Event kinds must be registered in `internal/events` before anything emits them.
- The fake runtime (`internal/runtime/runtimetest`) is unit-test-only; never reachable from served modes. Same rule for any test transport this plan adds.
- TDD with real components (real SQLite, real files, real processes at seams we own). Linux-only tests carry `//go:build linux` and run via `scripts/linux '<cmd>'` (rsyncs tree to aibox03 and executes there).
- Canonical gate: `scripts/check` before claiming anything works. New source files start with two `ABOUTME:` comment lines.
- NEVER run password sudo on aibox03. Agents may invoke only `sudo -n /usr/local/sbin/vmobs-root-helper <verb>` (existing fixture surface). Installing privd requires `scripts/aibox03/setup.sh` — a Doctor Biz handoff via `ssh -t` (Task 5 blocks the on-host gate until he runs it once).
- Conventional commits, imperative, present tense. Never `--no-verify`.

## Decisions this plan fixes (record in PLAN.md deviations log at close-out)

- **D1 — privd's clients are vmobsd and runners, authenticated by peer uid.** Both run as the same service uid (harper on aibox03 for V1 dev). privd validates every request against its own resource ledger regardless of caller. §3.3 names the verb set; this fixes the topology.
- **D2 — the controller spawns runners; jailer daemonizes the VMM, so neither controller nor runner owns the VMM's process lifetime.** Runner supervises by identity (pidfile + `/proc/<pid>/stat` start time + comm), satisfying §5.5 "more than PID alone".
- **D3 — spool scope in M1a is the runner's own lifecycle observations** (channel established/lost, vmm exited, spool recovery gaps), not guest sensor telemetry (M2). The segment format, ack barrier, importer, and prune protocol are built to §12.4 in full; M2 adds producers, not plumbing.
- **D4 — no CreateCgroup privd verb.** The jailer owns cgroup placement (`--cgroup-version 2`). YAGNI until a spec requirement needs independent cgroup ops.
- **D5 — the M0 boot fixture and root helper stay untouched** as the AT-004/M0 evidence path. The adapter reimplements staging/config in `internal/jailer`; accepted duplication, recorded. Root helper ABOUTME already says fixture-scoped.
- **D6 — shared jail group stays `vmobs-fixture` (gid 36000)** for socket traverse; per-VM identity independence comes from distinct uids (20000+slot). Renaming a live system group buys a label at real churn cost.
- **D7 — workspace seeding (§5.3 step 8) is an empty ext4 workspace disk in M1a**; baseline manifests are M4. Egress activation (step 9) is a no-op because the L0 network baseline is deny-by-default with no egress profiles until M3. Both recorded, not skipped silently.
- **D8 — privd ledger lives in `/run/vmobs/privd/`** (tmpfs): VMs never survive host reboot, so reboot-clearing state is correct; §5.5 cold reconcile then sees an empty ledger and marks persisted VM rows failed with reason.
- **D9 — guest kernel stays pinned at 6.1.186 through M1a** despite the series EOL (2026-09-02, per L0-T6-eol). Task 9 rebuilds only the rootfs; migrating to a live LTS kernel is its own pre-M2 task (rebuild via images/kernel/build.sh, boot revalidation, re-pin).

## File map

| Path | Responsibility |
|---|---|
| `internal/privd/proto.go` | Wire protocol: framing, request/response envelopes, verb payload types, typed causes |
| `internal/privd/client.go` | Client (one request per connection) used by adapter and runner |
| `internal/privd/server.go` | Server: accept loop, peer-cred check, dispatch, ledger |
| `internal/privd/ledger.go` | Per-VM resource ledger persisted under `/run/vmobs/privd/` |
| `internal/privd/netops.go` | AllocateNetwork/ReleaseNetwork implementation (argv execs; Go port of root-helper net verbs) |
| `internal/privd/vmops.go` | StartApprovedVM (fd-pinned digest-verified staging + jailer), SignalOwnedVM, ReleaseResources |
| `cmd/vmobs-privd/main.go` | Daemon entry: flags, socket setup, serve |
| `internal/spool/segment.go` | Segment format: header, checksummed records, end marker, durability barriers |
| `internal/spool/writer.go` | Spool writer with size bounds and fsync-before-ack |
| `internal/spool/reader.go` | Segment reader + recovery (truncated tail tolerated, corrupt interior rejected, gap record) |
| `internal/spool/importer.go` | Controller-side import loop: batch into store, cursor, prune after commit |
| `cmd/vmobs-runner/main.go` | Runner entry: flags, state file, supervision loop |
| `internal/runner/runner.go` | Supervision core: VMM identity watch, guest handshake, pings, spool emission |
| `internal/runner/ctl.go` | Runner control socket (`runner.sock`): shutdown-guest / finalize commands |
| `internal/jailer/adapter.go` | `runtime.Runtime` implementation: doctor-gated Availability, Launch/Stop/ForceStop |
| `internal/jailer/launch.go` | §5.3 transaction: manifest, staging, network, start, runner spawn, handshake wait, rollback |
| `internal/jailer/manifest.go` | Provisioning manifest read/write under state dir |
| `internal/jailer/reconcile.go` | Startup inventory/adoption (§5.5) |
| `internal/guest/proto/messages.go` | + `KindShutdown`/`KindShutdownAck` control messages |
| `internal/guest/agent.go` | + shutdown handler (argv `systemctl poweroff`) |
| `internal/events/registry.go` | + runner-emitted kinds |
| `internal/runtime/manager.go` | + `NotifyVMMExit`; reconcile alignment with real adapter |
| `internal/config/config.go` | + `runtime.mode`, jail identity bands, validation |
| `cmd/vmobsd/main.go` | Wire adapter + importer behind `runtime.mode: firecracker` |
| `scripts/aibox03/setup.sh` | + install privd binary, systemd unit, socket dir |
| `scripts/aibox03/vmobs-privd.service` | systemd unit for privd |
| `docs/runbooks/aibox03.md` | + privd install/upgrade/handoff section |
| `tests/integration/m1_gate_test.go` | API-driven gate: 2-VM launch/stop/delete, 4-VM AT-009, AT-011, AT-018 loop |

Existing seams consumed (exact, from the current tree):
- `runtime.Runtime` interface (internal/runtime/runtime.go:32): `Availability(ctx)`, `Launch(ctx, VMSpec)`, `Pause`, `Resume`, `Stop(ctx, vmID, grace) (forced bool, err error)`, `ForceStop`.
- `runtime.VMSpec` fields: `VMID, BootID, VCPUCount int, MemoryMiB int64, RootDiskMiB int64, WorkspaceDiskMiB int64, NetworkProfile, NetworkPolicyID, TemplateID, TemplateDigest string`.
- `runtime.NewManager(st *store.Store, rt Runtime, cfg ManagerConfig)`; manager calls `rt.Availability` inside `CreateVM` before reserving.
- `api.New(st, eng, mgr, ac AuthConfig, pf PreflightFunc)` — unchanged by this plan.
- `store.Append(ctx, *events.Envelope) (AppendResult, error)` — dedup on `(source_instance_id, source_seq)`.
- `proto.WriteControl/ReadControl`, `proto.DialHostVsock(ctx, udsPath, port)`, `Hello{ProtocolVersion, VMID, BootID, SourceInstance, ResumeCursor, AuthProof}`, port 10000.
- `preflight.Runner.Run(ctx) Report` with `Report.Overall` ∈ pass/fail/warn/not_implemented and per-check IDs.
- `lock.Load`, `Lock.VerifyBinaries()`, `Lock.VerifyArtifacts(repoRoot)`.

---

### Task 1: privd wire protocol and client

**Files:**
- Create: `internal/privd/proto.go`
- Create: `internal/privd/client.go`
- Test: `internal/privd/proto_test.go`

**Interfaces:**
- Consumes: nothing (leaf package; stdlib only).
- Produces: `privd.Request`, `privd.Response`, verb payload structs, `privd.WriteMsg(w io.Writer, v any) error`, `privd.ReadMsg(r io.Reader, dst any) error`, `privd.Client{SocketPath string}` with methods `AllocateNetwork(ctx, AllocateNetworkReq) error`, `ReleaseNetwork(ctx, ReleaseNetworkReq) error`, `StartVM(ctx, StartVMReq) (StartVMResp, error)`, `SignalVM(ctx, SignalVMReq) error`, `ReleaseVM(ctx, ReleaseVMReq) error`. Error type `privd.RemoteError{Cause, Message string}`.

Wire format (fixed by this task, documented in the file header): 4-byte big-endian length prefix + JSON body, max 64 KiB either direction; one request per connection (dial → write request → read response → close). Oversized length rejected before allocation (§7.4 spirit).

```go
// Request/response envelopes and verbs — proto.go
const (
	ProtoVersion  = 1
	MaxMsgBytes   = 64 * 1024
)

type Request struct {
	V       int             `json:"v"`
	Verb    string          `json:"verb"`
	OpID    string          `json:"op_id"` // operation id for audit; "" allowed for reconcile-time calls
	Payload json.RawMessage `json:"payload"`
}

type Response struct {
	OK      bool            `json:"ok"`
	Cause   string          `json:"cause,omitempty"`   // typed: bad_request | not_owner | invalid_state | digest_mismatch | exec_failed | not_found | internal
	Message string          `json:"message,omitempty"` // safe detail; never secrets, never raw host paths outside approved roots
	Payload json.RawMessage `json:"payload,omitempty"`
}

type AllocateNetworkReq struct {
	VMID string `json:"vm_id"`
	CIDR string `json:"cidr"` // /30, host side .1, guest side .2 — same contract as root-helper net-setup
}
type ReleaseNetworkReq struct{ VMID string `json:"vm_id"` }
type StagedFile struct {
	Name   string `json:"name"`   // basename only: vmlinux | rootfs.ext4 | config.ext4 | workspace.ext4 | fc-config.json
	SHA256 string `json:"sha256"` // hex; privd verifies on the opened fd before copying
}
type StartVMReq struct {
	VMID     string       `json:"vm_id"`
	UID      int          `json:"uid"`
	GID      int          `json:"gid"`
	CID      uint32       `json:"cid"`
	StageDir string       `json:"stage_dir"` // must resolve under the approved stage root
	Files    []StagedFile `json:"files"`
}
type StartVMResp struct {
	PID       int    `json:"pid"`
	StartTime string `json:"starttime_ticks"` // decimal string: /proc/<pid>/stat field 22
}
type SignalVMReq struct {
	VMID string `json:"vm_id"`
	Kind string `json:"kind"` // "term" | "kill"
}
type ReleaseVMReq struct{ VMID string `json:"vm_id"` }
```

`vmID` validation is shared: `^[a-z0-9][a-z0-9-]{0,62}$` (same class the root helper enforces); reject anything else with cause `bad_request` before touching the filesystem.

- [ ] **Step 1: Write failing tests** in `internal/privd/proto_test.go`: round-trip `WriteMsg`/`ReadMsg` for a `Request`; `ReadMsg` rejects a length prefix of `MaxMsgBytes+1` with an error mentioning "message too large" WITHOUT allocating (construct the 4-byte prefix by hand into a `bytes.Buffer`); `ReadMsg` on truncated body returns `io.ErrUnexpectedEOF`-wrapped error; `ValidVMID` table test (accept `m1-a`, `vm-000042`; reject empty, uppercase, `../etc`, 64+ chars, leading `-`).
- [ ] **Step 2: Run** `go test ./internal/privd/ -run 'TestMsg|TestValidVMID' -v` — expect FAIL (undefined symbols).
- [ ] **Step 3: Implement** `proto.go` (types above + `WriteMsg`, `ReadMsg`, `ValidVMID`) and `client.go`. Client method shape (all five follow it):

```go
func (c *Client) call(ctx context.Context, verb, opID string, payload, out any) error {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return fmt.Errorf("dial privd %s: %w", c.SocketPath, err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal %s payload: %w", verb, err)
	}
	if err := WriteMsg(conn, Request{V: ProtoVersion, Verb: verb, OpID: opID, Payload: raw}); err != nil {
		return fmt.Errorf("send %s: %w", verb, err)
	}
	var resp Response
	if err := ReadMsg(conn, &resp); err != nil {
		return fmt.Errorf("read %s response: %w", verb, err)
	}
	if !resp.OK {
		return &RemoteError{Cause: resp.Cause, Message: resp.Message}
	}
	if out != nil && len(resp.Payload) > 0 {
		if err := json.Unmarshal(resp.Payload, out); err != nil {
			return fmt.Errorf("decode %s response payload: %w", verb, err)
		}
	}
	return nil
}
```

- [ ] **Step 4: Add a client↔fake-listener round-trip test** (portable): start a `net.Listener` on a temp-dir unix socket inside the test, serve one canned `Response`, assert `Client.StartVM` decodes it and that a `{"ok":false,"cause":"digest_mismatch"}` reply surfaces as `*RemoteError` with that cause. This tests the client against a real unix socket, not a mock of the protocol.
- [ ] **Step 5: Run** `go test ./internal/privd/ -v` — expect PASS. Run `scripts/check`.
- [ ] **Step 6: Commit** `feat(privd): wire protocol and client`

### Task 2: privd server core — peer auth, dispatch, ledger

**Files:**
- Create: `internal/privd/server.go`
- Create: `internal/privd/ledger.go`
- Test: `internal/privd/server_linux_test.go` (`//go:build linux`)

**Interfaces:**
- Consumes: Task 1 types.
- Produces: `privd.Server` with `NewServer(cfg ServerCfg) *Server`, `(*Server).Serve(ctx, ln net.Listener) error`; `ServerCfg{AllowedUID int, LedgerDir string, StageRoot string, JailBase string, UIDMin, UIDMax int, Ops OpsBackend}`; `OpsBackend` interface `{ AllocateNetwork(VMEntry, AllocateNetworkReq) error; ReleaseNetwork(VMEntry) error; StartVM(*VMEntry, StartVMReq) (StartVMResp, error); SignalVM(VMEntry, string) error; ReleaseVM(VMEntry) error }`; `ledger` with `get/put/delete` of `VMEntry{VMID string; UID, GID int; CID uint32; PID int; StartTime string; NetCIDR string; CreatedAtUnix int64}` persisted as `<LedgerDir>/<vm_id>.json` (0600, tempfile+rename).

The `OpsBackend` seam exists so server dispatch/validation logic is testable without root: linux tests use a recording backend struct defined IN THE TEST (allowed — it exercises real dispatch over a real unix socket with real peer credentials; the backend boundary is ours and the real one is wired in Task 3/4). Server rules, all enforced before the backend is called:

- Peer uid from `SO_PEERCRED` must equal `AllowedUID`, else close without response (log locally).
- `Request.V != ProtoVersion` → `bad_request`. Unknown verb → `bad_request`.
- `allocate_network` for a vm_id already in ledger with a DIFFERENT CIDR → `invalid_state`; same CIDR → idempotent OK without calling backend twice (repeatability, §5.3).
- `start_vm`: vm_id must have a network allocation; UID must be in `[UIDMin, UIDMax)`; `StageDir` must resolve (after `filepath.EvalSymlinks`) under `StageRoot`; already-started vm_id → `invalid_state`.
- `signal_vm`/`release_vm` on unknown vm_id → `not_found`. `release_vm` while ledger says PID alive and identity still matches → `invalid_state` (caller must signal first).

- [ ] **Step 1: Write failing linux tests** in `server_linux_test.go`: (a) full happy path over a real unix socket — allocate → start → signal → release — asserting the recording backend saw exactly those calls with validated entries and the ledger file appears/updates/disappears; (b) wrong-uid rejection: run privd `Serve` with `AllowedUID: os.Getuid() + 1`, connect, assert the connection closes with no response bytes; (c) `start_vm` with `StageDir` outside `StageRoot` (use a symlink escaping it) → `RemoteError{Cause: "bad_request"}` and backend NOT called; (d) duplicate `allocate_network` same CIDR → OK once-called; different CIDR → `invalid_state`; (e) ledger survives server restart: `NewServer` with same `LedgerDir` sees the entry.
- [ ] **Step 2: Run** `scripts/linux 'go test ./internal/privd/ -v'` — expect FAIL (undefined `NewServer`).
- [ ] **Step 3: Implement** `server.go` + `ledger.go`. Peer cred read:

```go
func peerUID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return -1, err
	}
	if credErr != nil {
		return -1, credErr
	}
	return int(cred.Uid), nil
}
```

Dispatch runs one goroutine per accepted connection; ledger operations take a single server-wide mutex (privd throughput is not a bottleneck; correctness first).
- [ ] **Step 4: Run** `scripts/linux 'go test ./internal/privd/ -v'` — expect PASS. `scripts/check` locally (linux files vet via `env -u GOROOT mise exec -- env GOOS=linux go vet ./internal/privd/`).
- [ ] **Step 5: Commit** `feat(privd): server core with peer-cred auth and resource ledger`

### Task 3: privd network verbs (real backend, part 1)

**Files:**
- Create: `internal/privd/netops.go`
- Test: `internal/privd/netops_linux_test.go` (`//go:build linux`)

**Interfaces:**
- Consumes: Task 2 `OpsBackend`, `VMEntry`; existing `network.NamespaceName(id)`, `network.VethName(id)` (internal/network/names.go).
- Produces: `privd.RealOps` implementing `OpsBackend` (network half here; VM half Task 4): `NewRealOps(cfg RealOpsCfg) *RealOps`, `RealOpsCfg{JailBase, StageRoot string; FirecrackerPath, JailerPath string; NftPath, IPPath string}`.

Port the root helper's `net-setup`/`net-teardown` to Go, command for command, as argv arrays via `exec.CommandContext` — never a shell. The sequence is the binding reference (scripts/aibox03/vmobs-root-helper): create netns `vmobs-<id>`; bring up lo and a tap0 inside; veth pair `veth-<id>` ↔ `eth-up` bridged into the netns; nft table with a default-deny forward chain. Teardown: delete `veth-<id>`, delete netns. Every exec failure wraps stderr (bounded to 512 bytes) into the returned error with cause `exec_failed`. Idempotency: setup detects an existing netns of the same name with the expected interfaces and returns success; teardown of an absent netns is success (§5.3 "repeatable or detects an already-completed effect").

- [ ] **Step 1: Write failing linux test** `TestRealOpsNetworkLifecycle`: skip unless running as root (`os.Geteuid() != 0` → `t.Skip("needs root — run under privd's own integration path")`). Because agent tests never run as root on aibox03, ALSO write `TestNetArgvConstruction` (non-root): factor argv construction into pure functions `netSetupCommands(id, cidr) [][]string` / `netTeardownCommands(id) [][]string` and assert the exact command sequences match the root helper's, including the nft deny-by-default chain args and that no element contains shell metacharacters requiring interpretation.
- [ ] **Step 2: Run** `scripts/linux 'go test ./internal/privd/ -run TestNet -v'` — FAIL (undefined).
- [ ] **Step 3: Implement** `netops.go`: pure argv builders + `runAll(ctx, cmds)` executor + idempotency probes (`ip netns list` parse for setup skip; absent-netns success on teardown).
- [ ] **Step 4: Run** the argv tests green via `scripts/linux`. The root-path execution is exercised end-to-end in Task 5's on-host smoke and Task 14's gate (privd runs as root under systemd there).
- [ ] **Step 5: Commit** `feat(privd): network verbs as argv execs with idempotent setup/teardown`

### Task 4: privd VM verbs (real backend, part 2)

**Files:**
- Modify: `internal/privd/vmops.go` (new file, same `RealOps` type)
- Test: `internal/privd/vmops_linux_test.go` (`//go:build linux`)

**Interfaces:**
- Consumes: Task 2/3 types; jailer argv contract from the root helper (`jailer --id <id> --exec-file <fc> --uid --gid --chroot-base-dir <JailBase> --netns /var/run/netns/vmobs-<id> --cgroup-version 2 --daemonize -- --config-file fc-config.json --api-sock api.sock`).
- Produces: `RealOps.StartVM`, `RealOps.SignalVM`, `RealOps.ReleaseVM`.

`StartVM` closes the TOCTOU the root helper accepted (its own comment: "plain sh cannot pin an fd the way privd (M1) will"):

1. For each `StagedFile`: `os.Open(filepath.Join(stageDir, f.Name))` — O_NOFOLLOW via `unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)`; `fstat` to confirm regular file; stream SHA-256 from the OPEN fd; mismatch → cause `digest_mismatch`, name which file, abort before any copy.
2. Copy each verified fd into `<JailBase>/firecracker/<id>/root/` (create dirs 0750 root:gid), `chown uid:gid`, mode 0644 (fc-config.json 0640). Copy from the pinned fd (`io.Copy` from the same `*os.File` after `Seek(0,0)`), never by reopening the path.
3. Exec jailer with the argv above. Wait for `<root>/v.sock` to appear (100 × 100ms, same budget as the helper), then `chmod 0750` the chroot root (jailer re-tightens to 0700 during setup — same race the helper fix documented).
4. Read `<root>/firecracker.pid`, read `/proc/<pid>/stat` field 22 (starttime ticks), record both in the ledger entry, return `StartVMResp{PID, StartTime}`.

`SignalVM{Kind:"term"|"kill"}`: verify identity first — re-read `/proc/<pid>/stat`; if starttime differs from ledger, DO NOT signal (cause `invalid_state`, message "pid recycled"; §5.5 "never signal a PID-reused unrelated process"). Then `unix.Kill(pid, SIGTERM|SIGKILL)`.

`ReleaseVM`: refuse while identity-verified pid is alive; else `os.RemoveAll(<JailBase>/firecracker/<id>)` and drop the ledger entry.

- [ ] **Step 1: Write failing tests** (non-root testable pieces): `TestStagedFileVerification` — build a temp stage dir with a real file, correct digest passes fd-verify helper, wrong digest returns `digest_mismatch`, a symlink in place of the file fails O_NOFOLLOW; `TestJailerArgv` — pure builder returns the exact argv; `TestSignalIdentityGate` — helper `procStartTime(pid)` against `os.Getpid()` self-read, and the gate function refuses when ledger starttime differs.
- [ ] **Step 2: Run** `scripts/linux 'go test ./internal/privd/ -run 'TestStaged|TestJailerArgv|TestSignalIdentity' -v'` — FAIL.
- [ ] **Step 3: Implement** `vmops.go` per the numbered contract above.
- [ ] **Step 4: Run** green via `scripts/linux`; `scripts/check`.
- [ ] **Step 5: Commit** `feat(privd): VM verbs — fd-pinned digest-verified staging, identity-gated signals`

### Task 5: cmd/vmobs-privd, systemd unit, setup.sh, runbook — HANDOFF

**Files:**
- Create: `cmd/vmobs-privd/main.go`
- Create: `scripts/aibox03/vmobs-privd.service`
- Modify: `scripts/aibox03/setup.sh`
- Modify: `docs/runbooks/aibox03.md`
- Test: `cmd/vmobs-privd/main_test.go` (flag/config parsing only)

**Interfaces:**
- Consumes: `privd.NewServer`, `privd.NewRealOps`.
- Produces: the installed daemon at `/usr/local/sbin/vmobs-privd` and its socket at `/run/vmobs/privd.sock`. Socket permissions: after listen, privd runs `os.Chown(sock, 0, allowedGID)` then `os.Chmod(sock, 0660)`, where `--allowed-uid`/`--allowed-gid` are flags setup.sh writes into the unit from `$SUDO_UID`/`$SUDO_GID`. The peer-cred uid check (Task 2) remains the real boundary; the socket mode is defense in depth.

Flags: `--socket /run/vmobs/privd.sock --ledger-dir /run/vmobs/privd --allowed-uid N --allowed-gid N --stage-root /srv/vmobs/stage --jail-base /srv/vmobs/jail --firecracker /usr/local/bin/firecracker --jailer /usr/local/bin/jailer`.

Unit (`vmobs-privd.service`): `Type=simple`, `ExecStart` with the full argv (uid/gid substituted by setup.sh via sed from `$SUDO_UID`), `Restart=on-failure`, `RuntimeDirectory=vmobs vmobs/privd`, no `User=` (runs as root — that is its job), `ProtectHome=read-only`, `NoNewPrivileges=no`.

setup.sh additions (idempotent, same style as existing): build `cmd/vmobs-privd` from the synced tree (`go build -o /usr/local/sbin/vmobs-privd ./cmd/vmobs-privd`), install unit with uid/gid substitution, `mkdir -p /srv/vmobs/stage` owned by the service uid, `systemctl daemon-reload && systemctl enable --now vmobs-privd`, then verify: `systemctl is-active vmobs-privd` and socket exists.

- [ ] **Step 1: Write failing test** for main's flag parsing (extract `parseFlags([]string) (privdFlags, error)`; assert defaults and that missing `--allowed-uid` errors).
- [ ] **Step 2:** `go test ./cmd/vmobs-privd/ -v` — FAIL; implement main.go (parse → listen (remove stale socket first) → chown/chmod → `Serve`; SIGTERM cancels ctx, removes socket). Green locally; `scripts/check`.
- [ ] **Step 3:** Write the unit file and setup.sh + runbook edits. Runbook section: what privd is, how to upgrade it (re-run setup.sh), how to check health (`systemctl status vmobs-privd`, socket perms), and that agents never restart it directly.
- [ ] **Step 4: Commit** `feat(privd): daemon entrypoint, systemd unit, aibox03 install`
- [ ] **Step 5: HANDOFF — STOP and ask Doctor Biz** to run: `ssh -t harper@100.64.0.100 'cd vmobs-build && sudo sh scripts/aibox03/setup.sh'`. After he confirms, verify from here WITHOUT sudo: `ssh harper@100.64.0.100 'systemctl is-active vmobs-privd && ls -l /run/vmobs/privd.sock'`. Then run a live non-root smoke over the socket: `scripts/linux 'go test ./internal/privd/ -run TestPrivdLiveSmoke -v'` — write that test in this task: it connects to the real socket, sends `allocate_network` + `release_network` for id `privd-smoke` with CIDR `10.199.99.0/30` (private range clear of the host's tailscale 100.64/10 CGNAT space), asserts OK both ways (this exercises Task 3's root path end-to-end). Mark the test `//go:build linux` and skip when the socket is absent (honest skip naming setup.sh).

### Task 6: spool segment format — writer, reader, recovery

**Files:**
- Create: `internal/spool/segment.go`, `internal/spool/writer.go`, `internal/spool/reader.go`
- Test: `internal/spool/spool_test.go` (portable — real files, real fsync)

**Interfaces:**
- Consumes: `events.Envelope` (internal/events/envelope.go) marshaled as JSON record bodies.
- Produces: `spool.Writer` — `OpenWriter(dir string, cfg WriterCfg) (*Writer, error)`, `WriterCfg{VMID, InstanceID string; MaxSegmentBytes int64; MaxSpoolBytes int64}`, `(*Writer).Append(env *events.Envelope) error` (returns only after record + required metadata are durable — the §12.4 ack barrier), `(*Writer).Close() error`. `spool.ReadSegment(path string) (*SegmentIter, error)` with `Next() (*events.Envelope, error)` ending in `io.EOF`, `ErrCorruptRecord` for interior corruption, and truncated-tail tolerance; `spool.Recover(dir string) (RecoverReport, error)` where `RecoverReport{Segments []string; TruncatedTail bool; GapEmitted *events.Envelope}`.

Format (fixed here; documented in segment.go header):
- Segment file name: `seg-%016d.vmsp` (monotonic index).
- Header (JSON line, then `\n`): `{"magic":"vmsp","version":1,"vm_id":"...","instance_id":"..."}`.
- Record: `[len uint32 BE][crc32c uint32 BE][len bytes JSON envelope]`. Max record 256 KiB (§6.2 event frame limit).
- End marker: `len == 0xFFFFFFFF` written at clean close; a segment without one is "open or crashed".
- Durability: on segment create — fsync file AND its directory (§12.4 "Sync directory metadata when required"); on `Append` — write, fsync file, THEN return.
- `MaxSpoolBytes` (default from config `observation.max_runner_spool_bytes`, spec target 512 MiB): when a new `Append` would exceed it, return `ErrSpoolFull` — the caller (runner) must stop acking and emit the overflow health record; never drop silently (§12.5).

Recovery rules (§12.4 verbatim in the file header): tolerate an unacknowledged truncated trailing record (truncate it away); reject corrupt interior records — stop reading that segment at the corruption, report it; emit a recovery/gap record (kind `spool.recovery_gap`, registered Task 7).

- [ ] **Step 1: Write failing tests**: round-trip 3 envelopes through Writer→ReadSegment; crash simulation — write 2 records, then append 10 raw garbage bytes to the file, `Recover` reports TruncatedTail and iterating yields exactly 2; interior corruption — flip one byte inside record 1 of 3, iterator yields `ErrCorruptRecord` after 0 records; `ErrSpoolFull` at the configured bound; segment rotation at `MaxSegmentBytes`; end-marker present after `Close` and absent after simulated crash.
- [ ] **Step 2: Run** `go test ./internal/spool/ -v` — FAIL.
- [ ] **Step 3: Implement.** crc32c via `hash/crc32.MakeTable(crc32.Castagnoli)`.
- [ ] **Step 4: Run** green; `scripts/check`.
- [ ] **Step 5: Commit** `feat(spool): durable segment format with ack barrier and honest recovery`

### Task 7: spool importer + event kind registrations

**Files:**
- Create: `internal/spool/importer.go`
- Modify: `internal/events/registry.go`
- Test: `internal/spool/importer_test.go` (portable — real SQLite store)

**Interfaces:**
- Consumes: `store.Append` (dedup by `(source_instance_id, source_seq)`); Task 6 reader.
- Produces: `spool.Importer` — `NewImporter(st *store.Store, root string, interval time.Duration) *Importer`, `(*Importer).Run(ctx) error` (poll loop), `(*Importer).ImportOnce(ctx) (ImportStats, error)`; `ImportStats{Appended, Deduped, Pruned int}`. Cursor file per VM dir: `<root>/<vm_id>/cursor.json` `{"segment":"seg-0000000000000003.vmsp","record":41}` written AFTER the store batch commits (§12.4 step 4→5 ordering), tempfile+rename.

New registered kinds (all `Provenance: host_observed`, `Sensor: "runner"`, SchemaVersion 1, family `guest` / `vm` / `spool` per existing family conventions in the registry — read the file and match):
- `guest.channel_established` — semantics: runner completed the authenticated vsock handshake; data: `{"protocol_version":1,"capabilities_count":N}`.
- `guest.channel_lost` — semantics: control channel closed or ping window expired; data: `{"reason":"..."}`.
- `vm.vmm_exited` — semantics: the supervised VMM process is gone; data: `{"graceful":bool,"exit_observed_by":"pidfile_stat"}`.
- `spool.recovery_gap` — semantics: importer/reader detected unreadable spool records; caveats: "count of lost records is not claimed — an unknown interval is reported, not invented" (§12.5).

Prune protocol: a segment is deletable when it has an end marker AND the cursor points past it AND the store batch containing its last record committed. `ImportOnce` prunes then.

- [ ] **Step 1: Write failing tests** with a real `store.Open` on a temp DB: import 2 segments → all envelopes appear via the store's event queries; re-run `ImportOnce` → `Deduped == everything, Appended == 0` (at-least-once transport, deduplicated storage — the test title quotes §12.4); kill-between-batch-and-cursor simulation — delete cursor.json after import, re-import, assert dedup absorbs the replay; prune only after end-marker + cursor-past; registry test asserting the four kinds `LookupKind` correctly.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4:** green + `scripts/check`. 
- [ ] **Step 5: Commit** `feat(spool): controller importer with commit-then-cursor-then-prune ordering`

### Task 8: vmobs-runner — supervision, handshake, spool emission, control socket

**Files:**
- Create: `internal/runner/runner.go`, `internal/runner/ctl.go`, `internal/runner/state.go`
- Create: `cmd/vmobs-runner/main.go`
- Modify: `internal/guest/proto/messages.go` — add `KindShutdown = "shutdown"`, `KindShutdownAck = "shutdown_ack"`, `Shutdown{DeadlineS int}` (json tag `deadline_s`). The constants land here so the runner compiles; guestd's handler and the rootfs rebuild are Task 9.
- Test: `internal/runner/runner_test.go` (portable pieces), `internal/runner/runner_linux_test.go` (`//go:build linux`)

**Interfaces:**
- Consumes: `proto.DialHostVsock`, `proto.WriteControl/ReadControl`, `proto.Hello/HelloAck/CapabilityManifest`, ping/pong kinds (internal/guest/proto); `spool.OpenWriter` + `(*Writer).Append` (Task 6); event kinds from Task 7.
- Produces: the runner binary and its spawn contract, consumed verbatim by Task 10:

```
vmobs-runner --vm-id <id> --boot-id <uuid> --instance-id <uuid> \
  --uds <jail-root>/v.sock --token-file <state>/vms/<id>/token \
  --spool-dir <spool-root>/<id> --state-file <state>/vms/<id>/runner-state.json \
  --ctl-sock <state>/vms/<id>/runner.sock \
  --vmm-pid <pid> --vmm-starttime <ticks> --ping-interval 5s
```

Also produces `runner.State` read by the adapter (Task 10 polls it):

```go
// state.go — written tempfile+rename on every phase change and at each ping cycle.
type State struct {
	VMID          string `json:"vm_id"`
	BootID        string `json:"boot_id"`
	InstanceID    string `json:"instance_id"`
	RunnerPID     int    `json:"runner_pid"`
	VMMPID        int    `json:"vmm_pid"`
	VMMStartTime  string `json:"vmm_starttime"` // decimal ticks, from privd StartVMResp
	Phase         string `json:"phase"`         // starting | attached | degraded | vmm_exited | finalized
	UpdatedAtUnix int64  `json:"updated_at_unix"`
}
func ReadState(path string) (State, error)
```

Control socket (`ctl.go`): newline-delimited JSON over the unix socket, one command per connection — `{"cmd":"shutdown_guest","grace_s":20}` / `{"cmd":"finalize"}` answered by `{"ok":true}` or `{"ok":false,"error":"..."}`. No framing library; `json.NewDecoder(conn).Decode` + `json.NewEncoder(conn).Encode`. Socket mode 0600.

Runner loop (runner.go, `Run(ctx context.Context, cfg Config) error`):
1. Read token from `--token-file` (never argv — §15.3). Open spool writer.
2. Dial control vsock (port 10000) with bounded backoff; send `Hello{ProtocolVersion, VMID, BootID, SourceInstance: instanceID, AuthProof: token}`; on `HelloAck{Accepted:true}` send `get_capabilities`, read `capabilities`; append `guest.channel_established` to spool; phase → `attached`.
3. Ping every `--ping-interval`; 3 consecutive misses → append `guest.channel_lost` with reason `ping window expired`, phase → `degraded`, return to step 2 (redial).
4. In parallel (1s tick): verify VMM identity — `/proc/<pid>/stat` exists AND starttime field matches `--vmm-starttime`. Gone or mismatched → append `vm.vmm_exited` with `graceful` = whether a shutdown was requested this boot, phase → `vmm_exited`, close spool cleanly (end marker), phase → `finalized`, exit 0.
5. `shutdown_guest` command → `proto.WriteControl(conn, proto.KindShutdown, proto.Shutdown{DeadlineS: graceS})`, record shutdown-requested, reply once the guest acks or the write fails. `finalize` → close spool, phase → `finalized`, exit 0.

SourceSeq for spool envelopes: monotonic uint64 per instance, rendered as a decimal string in the envelope (decimal-string rule). Envelope timestamps: runner clock, `Provenance: host_observed`.

- [ ] **Step 1: Write failing portable tests**: `TestStateRoundTrip` (write/read, atomic rename — a reader looping during 100 writes never sees invalid JSON); `TestCtlProtocol` — serve the ctl socket in-process on a temp dir, send `shutdown_guest`, assert the injected shutdown func was called with grace 20 and the reply is `{"ok":true}`; unknown cmd → `{"ok":false}`.
- [ ] **Step 2: Run** `go test ./internal/runner/ -v` — FAIL.
- [ ] **Step 3: Write failing linux test** `TestRunnerAgainstRealGuestd` (`//go:build linux`, non-root): stand up a REAL `guest.NewAgent` + `ServeControl` on a unix socket in a temp dir (`proto.DialHostVsock` speaks CONNECT/OK over a UDS; copy the accept-side pattern from internal/guest's existing tests), run `runner.Run` as a goroutine with the fake VMM pid = a real spawned `sleep 300` child and its true starttime. Assert: state reaches `attached`; spool contains `guest.channel_established`; kill the sleep child → state reaches `finalized`, spool ends with `vm.vmm_exited` + end marker, `Run` returns nil.
- [ ] **Step 4: Run** `scripts/linux 'go test ./internal/runner/ -v'` — FAIL; implement runner.go/ctl.go/state.go + cmd/vmobs-runner/main.go (flag parse → `runner.Run`; extract `parseFlags` and unit-test it: `--vmm-starttime` must be decimal digits, all flags required).
- [ ] **Step 5: Run** portable + linux suites green; `scripts/check`.
- [ ] **Step 6: Commit** `feat(runner): per-VM supervisor with identity watch, guest handshake, durable spool`

### Task 9: guestd shutdown handler + reconnectable control loop + rootfs rebuild/re-pin

**Files:**
- Modify: `internal/guest/agent.go` (shutdown handler; verify/fix sequential-reconnect accept loop)
- Test: extend the existing agent control tests in `internal/guest/`
- On-host: rebuild `images/dist/rootfs.ext4`, re-pin `runtime.lock.json`

**Interfaces:**
- Consumes: existing `proto.WriteControl/ReadControl`, `guest.NewAgent`, `ServeControl`; `proto.KindShutdown`/`KindShutdownAck`/`Shutdown` (constants added in Task 8).
- Produces: guestd that answers `shutdown` and powers off; a control loop that accepts sequential reconnects; a rebuilt, re-pinned rootfs carrying both.

Guestd behavior: on `shutdown` (only on an authenticated connection — after hello accepted), reply `shutdown_ack`, then invoke the poweroff func. Make the poweroff func injectable on the agent for tests; production default execs `systemctl poweroff` as an argv array. Also required: after a control connection closes, `ServeControl` must accept the next connection and allow a fresh authenticated hello — runner redial (Task 8 step 3) and controller-restart adoption depend on it. Read the current accept loop; if it already serves sequential connections, add the regression test anyway.

- [ ] **Step 1: Write failing tests** in the existing guest test file style: (a) authenticated conn sends `shutdown` with deadline 10 → receives `shutdown_ack` and the injected poweroff func ran; (b) `shutdown` BEFORE hello → refused, poweroff NOT called; (c) reconnect — complete a hello, close the conn, dial again, hello again succeeds (accept loop still alive).
- [ ] **Step 2: Run** `go test ./internal/guest/... -v` — FAIL.
- [ ] **Step 3: Implement**; green locally AND `scripts/linux 'go test ./internal/guest/... -v'`; `scripts/check`.
- [ ] **Step 4: Commit** `feat(guest): shutdown verb and reconnectable control channel`
- [ ] **Step 5: Rebuild + re-pin on aibox03** (non-root — the rootfs build uses mke2fs -d, no mounts): follow the M0-documented flow in `docs/runbooks/aibox03.md` exactly — rebuild `images/dist/rootfs.ext4` on aibox03, verify the new guestd binary inside via the runbook's debugfs check, update the `runtime.lock.json` artifact hash, sync the lock to the host path the runbook names. DEVIATION TO RECORD (D9): guest kernel stays pinned at 6.1.186 (EOL 2026-09-02) through M1a; migrating the kernel series to a live LTS is its own pre-M2 task — note in PLAN.md at close-out.
- [ ] **Step 6: Rerun the M0 fixture as regression**: the documented M0 invocation (see the runbook / tests/integration) via `scripts/linux` — the new rootfs must still boot and handshake. Expected: PASS.
- [ ] **Step 7: Commit** `chore(images): rootfs with shutdown-capable guestd; re-pin runtime lock`

### Task 10: jailer adapter — the §5.3 launch transaction

**Files:**
- Create: `internal/jailer/adapter.go`, `internal/jailer/launch.go`, `internal/jailer/manifest.go`
- Test: `internal/jailer/launch_linux_test.go` (`//go:build linux`), `internal/jailer/manifest_test.go` (portable)

**Interfaces:**
- Consumes: `privd.Client` verbs via a package-local interface (the AT-005 seam — Task 13 injects failures through it):

```go
type privdClient interface {
	AllocateNetwork(ctx context.Context, req privd.AllocateNetworkReq) error
	ReleaseNetwork(ctx context.Context, req privd.ReleaseNetworkReq) error
	StartVM(ctx context.Context, req privd.StartVMReq) (privd.StartVMResp, error)
	SignalVM(ctx context.Context, req privd.SignalVMReq) error
	ReleaseVM(ctx context.Context, req privd.ReleaseVMReq) error
}
```

  plus `runner.ReadState` (Task 8), the runner spawn argv (Task 8), `network.NewAllocator/Next`, `lock.Load` for pinned digests, `guest.BootConfig`, `runtime.VMSpec`.
- Produces: `jailer.New(cfg Config, pc privdClient) (*Adapter, error)` where `Adapter` implements `runtime.Runtime`. Availability/Stop/ForceStop/Reconcile land in Task 11; this task lands Launch, with Pause/Resume returning a typed "pause not supported in M1a" error (honest — VMM pause capability work is later milestone scope, recorded as a deviation only if ACCEPTANCE demands it sooner). `Config{StateDir, StageRoot, JailBase, SpoolRoot, RunnerBin, RepoImagesDir, LockPath string; JailUIDBase, JailGID, MaxSlots int; CIDBase uint32; Allocator *network.Allocator; Preflight func(ctx context.Context, refresh bool) preflight.Report}`.

Manifest (`manifest.go`, portable logic):

```go
type Manifest struct {
	VMID      string   `json:"vm_id"`
	BootID    string   `json:"boot_id"`
	Slot      int      `json:"slot"`
	UID       int      `json:"uid"`      // JailUIDBase + Slot
	GID       int      `json:"gid"`
	CID       uint32   `json:"cid"`      // CIDBase + Slot
	CIDR      string   `json:"cidr"`
	VMMPID    int      `json:"vmm_pid,omitempty"`
	VMMStart  string   `json:"vmm_starttime,omitempty"`
	RunnerPID int      `json:"runner_pid,omitempty"`
	Stages    []string `json:"stages"` // appended AFTER each side effect completes: reserved, staged, network, vmm_started, runner_spawned, attached
}
```

Written to `<StateDir>/vms/<id>/manifest.json` (tempfile+rename) BEFORE the first side effect and updated after each — §5.3 step 4 verbatim: "persist a provisioning manifest before each external side effect so cleanup can target exactly the owned resources."

Launch sequence (launch.go), each stage bounded by ctx, all under the adapter's launch mutex (one transaction at a time; concurrent CreateVM calls queue — say so in a comment):
1. **Slot**: scan existing manifests, take the lowest free slot < MaxSlots; a manifest for this vm_id already holding a slot (stopped VM restarting) reuses it.
2. **Manifest** written with identities (uid = JailUIDBase+slot, gid = JailGID, cid = CIDBase+slot, cidr from `Allocator.Next()` — or the manifest's existing cidr on restart), stage `reserved`.
3. **Stage** under `<StageRoot>/<id>/`: copy vmlinux + rootfs.ext4 from `RepoImagesDir`, verifying SHA-256 against the loaded lock's pinned artifact digests (mismatch → fail, no side effects yet); generate a per-boot token (`crypto/rand`, 32 bytes, hex) → write `<StateDir>/vms/<id>/token` 0600 AND build config.ext4 containing `guest.BootConfig{Schema:"vmobs.guest_context.v1", VMID, BootID, CapabilityToken, ProtocolVersion}` via mke2fs -d (same tool and layout as the M0 fixture's config build — read tests/integration/fixture and mirror it; the jailer package owns its own copy, D5); create workspace.ext4 (`truncate` to `spec.WorkspaceDiskMiB`, `mke2fs -F -t ext4`); write fc-config.json mirroring the fixture's FCConfig shape (jailer-relative paths, vsock guest_cid + `v.sock`, drives: rootfs rw, config ro, workspace rw; vcpus/mem from spec). Stage `staged`.
4. **Network**: `pc.AllocateNetwork` with the manifest's vm_id + cidr. Stage `network`.
5. **VMM**: compute staged-file SHA-256s → `pc.StartVM{VMID, UID, GID, CID, StageDir, Files}` → record pid/starttime in the manifest. Stage `vmm_started`.
6. **Runner**: spawn Task 8's argv with `SysProcAttr{Setsid: true}`, stdout/stderr → `<StateDir>/vms/<id>/runner.log`; record RunnerPID. Stage `runner_spawned`.
7. **Attach wait**: poll `runner.ReadState` until `Phase == "attached"` (60s budget, 500ms interval — the fixture's readyTimeout/readyBackoff values). Stage `attached`; return nil. Timeout or runner exit → rollback.

Rollback (reverse dependency order, tolerate already-gone, never fuzzy-name): kill runner by recorded pid (SIGTERM, 2s, SIGKILL); `SignalVM{kill}` if `vmm_started`; `ReleaseVM`; `ReleaseNetwork` if `network`; remove the stage dir; remove `<StateDir>/vms/<id>/`. Return the original stage error wrapped `launch <id> failed at stage <name>: <cause>` — the operation record must surface which step failed (§5.3).

- [ ] **Step 1: Write failing portable tests** (`manifest_test.go`): manifest round-trip; slot allocation picks lowest free among {0,2} → 1; slots exhausted → typed error; stage append ordering preserved; restart reuse — an existing manifest for the vm_id keeps its slot and cidr.
- [ ] **Step 2: Run** `go test ./internal/jailer/ -v` — FAIL. Implement manifest.go; green.
- [ ] **Step 3: Write failing linux test** `TestLaunchTransactionAgainstFakePrivd` (`//go:build linux`, non-root): real `privd.NewServer` on a temp socket with a test-recording `OpsBackend` (StartVM returns a real spawned `sleep 300` pid + its true starttime); real guestd `ServeControl` listening at the UDS path where fc's v.sock would be; RunnerBin = the real runner built by the test (`go build -o` into a temp dir in `TestMain`). Drive `Adapter.Launch` with a full `runtime.VMSpec`; assert: manifest stages appear in order; digest tampering variant fails BEFORE the backend sees `allocate_network`; runner state reaches `attached`; spool gained `guest.channel_established`.
- [ ] **Step 4: Run** `scripts/linux 'go test ./internal/jailer/ -v'` — FAIL; implement adapter.go + launch.go; green. `scripts/check`.
- [ ] **Step 5: Commit** `feat(jailer): launch transaction with provisioning manifest and ordered rollback`

### Task 11: adapter Stop/ForceStop + doctor-gated Availability + real guest_channel check

**Files:**
- Modify: `internal/jailer/adapter.go` (Stop/ForceStop/Availability); Create: `internal/jailer/reconcile.go`
- Modify: `internal/preflight/preflight.go` (guest_channel real probe on Linux)
- Test: `internal/jailer/stop_linux_test.go`, extend `internal/preflight` tests

**Interfaces:**
- Consumes: runner ctl protocol + `runner.ReadState` (Task 8), privd signal/release verbs, `preflight.Report/Check` shapes, `runtime.UnavailableError{Reason string}`.
- Produces: complete `runtime.Runtime` on `*jailer.Adapter`; `(*Adapter).Reconcile(ctx context.Context) ([]Finding, error)` with `Finding{VMID string; Outcome string; Detail string}`, Outcome ∈ `adopted | vmm_gone | ambiguous` — consumed by Task 12's startup wiring.

`Stop(ctx, vmID, grace)`: read manifest + runner state. Runner alive and attached → ctl `shutdown_guest` with the grace; poll state until `vmm_exited`/`finalized` within grace → `forced=false`. Otherwise (or timeout): `SignalVM{term}`, 5s, `SignalVM{kill}` → `forced=true`. Then always: ctl `finalize` (tolerate a dead runner/socket), `ReleaseVM` (chroot removed), KEEP network + slot + manifest — a stopped VM can start again; the next Launch reuses the manifest's slot/cidr and `allocate_network` is idempotent for the same CIDR (Task 2). `ForceStop`: straight to `SignalVM{kill}` + the same teardown.

Full release (delete): read `internal/runtime/manager.go` first to see which runtime call its Delete path makes against the fake; implement the adapter so that path releases EVERYTHING — `ReleaseNetwork`, remove manifest + `<StateDir>/vms/<id>/` + stage dir. The spool dir stays for the importer; the importer prunes drained, segment-less VM dirs (Task 7 behavior).

`Availability(ctx)`: `cfg.Preflight(ctx, false)`; `Overall == "pass"` → nil; else the first Check with `Status == "fail"` becomes `runtime.UnavailableError{Reason: check.ID + ": " + check.Summary}` (AT-001: the refusal names the failed check; the manager already surfaces UnavailableError as the typed refusal).

`guest_channel` preflight (Linux): dial the configured privd socket with a 1s timeout (connect + close, no request) and stat the stage root for existence + writability. Pass with evidence lines; fail with remediation naming `scripts/aibox03/setup.sh`. Non-Linux stays `not_implemented`. Add `PrivdSocket, StageRoot string` to `preflight.Config`; empty values → fail with "not configured".

`Reconcile(ctx)`: for each `<StateDir>/vms/*/manifest.json` — runner state `attached` + runner pid alive + VMM identity (pid+starttime) matches → `adopted`. VMM identity gone → `vmm_gone`. Runner dead while VMM alive and identity matches → respawn the runner (new instance-id, same token/spool/state paths) and report `adopted`. Unreadable manifest or identity mismatch → `ambiguous`: touch NOTHING (§5.5 — never signal, never delete a quarantined VM).

- [ ] **Step 1: Write failing tests**: preflight — guest_channel passes against a live temp-socket listener, fails with remediation when absent (linux, non-root). Stop — extend Task 10's fake-privd harness: with the test guestd's injectable poweroff killing the fake-VMM sleep child, `Stop` with 10s grace returns `forced=false`, runner state `finalized`, backend saw NO `signal_vm`; with a guestd that ignores shutdown, `Stop` returns `forced=true` and the backend saw term then kill. ForceStop asserts kill + release. Reconcile — three manifest fixtures (adopted / vmm_gone / ambiguous) built from real spawned-then-killed sleep processes; assert Findings and that ambiguous touched nothing (no signals in backend, files intact).
- [ ] **Step 2: Run** `scripts/linux 'go test ./internal/jailer/ ./internal/preflight/ -v'` — FAIL.
- [ ] **Step 3: Implement**; green; `scripts/check`.
- [ ] **Step 4: Commit** `feat(jailer): doctor-gated availability, graceful stop, startup reconcile`

### Task 12: vmobsd wiring — runtime.mode, importer hook, NotifyVMMExit

**Files:**
- Modify: `internal/config/config.go` (+ tests), `internal/runtime/manager.go` (+ tests), `internal/spool/importer.go`, `cmd/vmobsd/main.go`
- Create: `cmd/vmobsd/runtime_linux.go`, `cmd/vmobsd/runtime_stub.go` (darwin stub)

**Interfaces:**
- Consumes: `jailer.New` (Task 10/11 Config), `spool.NewImporter` (Task 7), the pfFunc closure main.go already passes to `api.New`.
- Produces: config fields `Runtime.Mode string` (`"unavailable"` default | `"firecracker"`), `Runtime.JailUIDBase int` (default 20000), `Runtime.JailGID int` (default 36000), `Runtime.CIDBase int` (default 3); `(*runtime.Manager).NotifyVMMExit(ctx context.Context, vmID, reason string, graceful bool) error`; importer signature change to `NewImporter(st *store.Store, root string, interval time.Duration, onImported func(*events.Envelope)) *Importer` (update Task 7's tests in the same commit — pass nil there).

`NotifyVMMExit`: VM in `running`/`stopping` → transition to `stopped` (graceful) or `failed` (not) with the reason recorded, through the manager's EXISTING transition helpers — read manager.go first; do not invent a second state-write path (one source of truth). Already-terminal VM → no-op returning nil (importer replays are normal).

main.go serve wiring: `Mode == "firecracker"` is linux-only (`buildFirecrackerRuntime` lives in `runtime_linux.go`; the darwin stub returns a config error naming the field). It builds `network.NewAllocator` from existing host config, `privd.Client{SocketPath: cfg.Paths.PrivilegedSocket}`, `jailer.New(...)` with RunnerBin resolved beside the vmobsd binary (`os.Executable()` dir + `/vmobs-runner`; missing → startup error). Startup order: adapter `Reconcile` → map findings (`vmm_gone`/`ambiguous` → `mgr.NotifyVMMExit(vmID, "reconcile: "+detail, false)`) → existing `mgr.Reconcile` → importer goroutine (onImported routes `vm.vmm_exited` envelopes to `NotifyVMMExit`, graceful from the payload) → serve. `Mode == "unavailable"` keeps today's `runtime.ForHost` path unchanged.

- [ ] **Step 1: Write failing tests**: config — mode defaults to `unavailable`, `firecracker` accepted, anything else rejected naming the field; manager — `NotifyVMMExit` on a running VM (fake-runtime unit harness, existing helpers) flips to `failed` with the reason recorded; graceful=true flips to `stopped`; second call no-ops.
- [ ] **Step 2: Run** `go test ./internal/config/ ./internal/runtime/ -v` — FAIL.
- [ ] **Step 3: Implement** config + manager + importer hook + main wiring (+ `GOOS=linux` vet of the new files).
- [ ] **Step 4: Run** `scripts/check` AND `scripts/linux 'go test ./...'` — both green.
- [ ] **Step 5: Commit** `feat(vmobsd): firecracker runtime mode with reconcile-then-import startup`

### Task 13: AT-005 failure injection suite

**Files:**
- Create: `internal/jailer/inject_linux_test.go` (`//go:build linux`)

**Interfaces:**
- Consumes: Task 10's `privdClient` seam and the fake-privd harness (real `privd.NewServer` + recording backend + real runner binary + real guestd on a temp UDS).
- Produces: AT-005 evidence — a failure injected after every provisioning side effect; cleanup removes owned resources and only owned resources.

Decorator, defined in the test file (same shape for all five verbs):

```go
type failingPrivd struct {
	inner  privdClient
	failOn string
	calls  []string
}

func (f *failingPrivd) StartVM(ctx context.Context, req privd.StartVMReq) (privd.StartVMResp, error) {
	f.calls = append(f.calls, "start_vm")
	if f.failOn == "start_vm" {
		return privd.StartVMResp{}, &privd.RemoteError{Cause: "exec_failed", Message: "injected"}
	}
	return f.inner.StartVM(ctx, req)
}
```

Injection matrix — one subtest per point, each asserting FULL cleanup (no `<StateDir>/vms/<id>/`, no stage dir, backend saw release calls for exactly the stages that had completed, slot free afterwards) and that the error names the failed stage:
1. manifest write failure (state dir made read-only for the subtest)
2. staging digest mismatch (tampered source artifact)
3. `allocate_network` injected failure
4. `start_vm` injected failure (assert `release_network` seen after)
5. runner spawn failure (RunnerBin → missing path; assert `signal_vm kill` + `release_vm` + `release_network` seen)
6. attach timeout via wrong token (guestd refuses the hello — also proves a bad token can never reach `attached`)

Then the recovery assertion: after each rollback, a clean `Launch` of the SAME vm_id succeeds with no injected failure.

- [ ] **Step 1: Write the suite.** Any red is a real transaction bug in Tasks 10-11 — fix the product here, never the assertion.
- [ ] **Step 2: Run** `scripts/linux 'go test ./internal/jailer/ -run TestInject -v'` — drive to PASS.
- [ ] **Step 3:** `scripts/check` + full `scripts/linux 'go test ./...'`.
- [ ] **Step 4: Commit** `test(jailer): AT-005 failure injection after every provisioning side effect`

### Task 14: M1a gate on aibox03 — evidence, acceptance flips, close-out

**Files:**
- Create: `tests/integration/m1a_gate_test.go` (`//go:build linux`, guarded and evidence-captured exactly the way TestM0Boot is — read that file first and copy its guard + evidence-writer pattern)
- Modify: `docs/ACCEPTANCE.md`, `docs/VALIDATION.md`, `PLAN.md`
- Produces: `tests/integration/evidence/m1a-gate-aibox03.txt` (live capture)

**Interfaces:**
- Consumes: everything above; the installed privd from Task 5's handoff; the real HTTP API of a vmobsd the test starts with `runtime.mode: firecracker`, a temp DB, temp state/spool dirs, the real `/run/vmobs/privd.sock`, and a stage root UNDER `/srv/vmobs/stage/` (e.g. `/srv/vmobs/stage/m1a-gate/`, cleaned by the test) — the installed privd only accepts staging under its configured `--stage-root`, so a temp-dir stage root would be rejected.
- Produces: the M1a gate verdict + committed evidence.

Gate sequence (ordered subtests, each captured into the evidence file):
1. **Doctor pass**: `GET /host/status` overall `pass` — else the gate is honestly red; fix the host, not the test.
2. **AT-001 refusal**: a second vmobsd configured with `privileged_socket: /nonexistent/privd.sock` refuses `POST /vms` with the typed error naming `guest_channel`; shut that instance down after.
3. **Two real VMs**: create + start A and B via HTTP; both reach `running`; independence asserted — different uid/cid (read manifests), both `vmobs-<a>` and `vmobs-<b>` present in `ip netns list`, `guest.channel_established` event for each via the events API.
4. **AT-011**: graceful-stop A while B runs → A `stopped` with `forced=false` in its operation record, B still `running` with ping-driven events after A's stop time; delete A; B unaffected.
5. **AT-006 real path**: create a third VM, replay the same client_ref → same VM, no duplicate; changed payload + same client_ref → conflict.
6. **AT-009**: four VMs running simultaneously (1 vCPU / 512 MiB each), all with established channels; then stop/delete all.
7. **AT-018**: baseline capture (netns count, `veth-*` link count, jail dir entries, firecracker process count, state+stage dir entries) → 5 create/start/stop/delete cycles → recapture → assert return to baseline.
8. **AT-007 ordering**: for one VM, its `running` transition is not earlier than its `guest.channel_established` event (running only after the channel; seeding/baseline remain M4 — deviation recorded).

- [ ] **Step 1: Write the gate test** with live evidence capture per subtest.
- [ ] **Step 2: Run** via `scripts/linux` with the same guard env the M0 test uses. Iterate to PASS twice consecutively (M0's bar). Never weaken an assertion to pass; true deviations go to PLAN.md.
- [ ] **Step 3: Flip acceptance rows** in `docs/ACCEPTANCE.md` with evidence pointers: AT-001, AT-005, AT-006, AT-009, AT-011, AT-018 → TESTED_PASS; AT-007 → partial (guest-service gate tested; seeding/baseline M4). Run `uv run docs/validation/check.py`; append a dated revision to `docs/VALIDATION.md`.
- [ ] **Step 4: PLAN.md close-out**: L1a row done; session log entry; deviations D1–D9 recorded.
- [ ] **Step 5:** `scripts/check` + full `scripts/linux 'go test ./...'` green. Commit `feat(m1a): real runtime gate green on aibox03 — evidence and acceptance flips`.

---

## Explicitly out of scope (M1b plan, written after M1a lands)

Terminal data path (PTY vsock port 10002, `internal/terminal/`, xterm page), WebSocket upgrade + exact-Origin checks + terminal tickets (the P5 deferral), writer lease, replay buffer, minimal fleet page, AT-019–AT-030. The §18 M1 gate sentence ("no host shell proxy masquerading as a guest terminal; reconnect does not spawn a duplicate shell") closes with M1b; M1a's gate is the runtime half above.

