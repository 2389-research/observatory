# L0 — Real Host and Image Foundation (SPEC Milestone 0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Milestone 0 of the Linux track: doctor preflight, runtime version lock, reproducible guest kernel + root image, minimal vsock guest agent with capability probe, private-network plumbing, and a jailed boot fixture proving real KVM boot, vsock handshake, capability report, and independent disk ownership on aibox03.

**Architecture:** The portable core (P0–P5) stays untouched except for two seams: `/host/status` gains a preflight report and daemon startup verifies `runtime.lock.json`. New packages: `internal/guest/proto` (framing + handshake), `internal/guest` (guestd core), `internal/preflight` (doctor), `internal/lock` (runtime lock), `internal/network` (transit allocation). New binaries: `cmd/vmobs-guestd`. Image pipeline lives in `images/`; the boot fixture in `tests/integration`. Root operations on aibox03 go through a narrow, root-owned helper script with a NOPASSWD sudoers entry for exactly that path — a stand-in that M1's `vmobs-privd` replaces.

**Tech Stack:** Go 1.26+, `github.com/mdlayher/vsock` (guest AF_VSOCK listener), shell build scripts, docker as an unprivileged build sandbox (aibox03 only, never in any served path), `mkfs.ext4 -d` for rootless image assembly, SSH/rsync remote execution.

**Spec:** `docs/SPEC.md` — §18 Milestone 0 is the gate; §3.3 (privilege), §4 (doctor + runtime lock), §7 (guest image, vsock, framing), §10.1/10.3 (network baseline). `docs/ACCEPTANCE.md` rows AT-001..AT-004 (plus partial AT-009/AT-018 evidence).

## Global Constraints

Copied from SPEC/CLAUDE.md; every task's requirements include these.

- Evidence honesty is the product. Never fabricate counts, verdicts, coverage, or capability claims; a check that cannot run reports `not_implemented` or `fail` with evidence — never a silent pass. No silent software emulation for KVM (§4.1).
- The fake runtime and any test transport exist for unit tests only. Never wire a fake into a served mode; `vmobs-guestd` serves AF_VSOCK only.
- Acceptance evidence requires real Firecracker on Linux (aibox03). Fake-runtime results cannot satisfy real-KVM gates (ACCEPTANCE.md preamble).
- Counters that can exceed JS safe integers are decimal strings in JSON (§7.4 includes handshake cursors).
- Every API response is bounded; errors carry typed cause + remediation.
- No new event kinds in M0. Nothing emits unregistered kinds.
- Invoke approved binaries with argument arrays, not `sh -c` (§3.3). The root helper accepts typed verbs with validated arguments only — never arbitrary commands, paths, or rule text.
- Pinned dependencies and versions everywhere: exact Firecracker/jailer version + SHA256, kernel source + config hashes, base image digests (§3.1, §4.2). Never download an unpinned `latest` at run time; resolving and recording versions during implementation is sanctioned (§3.1).
- Privilege-bearing paths and their parents stay non-writable by unprivileged users (§3.3). The root helper is root-owned 0755; harper cannot edit it without the password path.
- TDD for every task. Tests use real components at seams we own (real files, real sockets, real SQLite). Contract fakes are allowed only at seams we do not own (Firecracker's CONNECT/OK socket protocol) and must be paired with the real fixture on aibox03.
- New hand-written source files start with 2-line `// ABOUTME:` (or `# ABOUTME:`) headers.
- Canonical gate: `scripts/check` locally; `scripts/linux 'go test ./...'` for Linux-only packages. Docs changes also need `uv run docs/validation/check.py` green.
- Conventional commit per component. Never push. Never bypass hooks.
- Go on the Mac needs `env -u GOROOT mise exec -- go ...`; `scripts/check` already handles this. On aibox03 plain `go` works.

## Ground truth (verified 2026-09-01)

- aibox03 = `harper@100.64.0.100`. Go 1.27.0 (mise), rsync, docker (harper in `docker` group). NOT installed: firecracker, jailer, jq. harper NOT in `kvm` group. `sudo` requires a password — nothing root-level runs non-interactively.
- `/dev/kvm` exists, `root:kvm` 0660. Kernel 6.8.0-138 (drifted from the 6.8.0-134 recorded in PLAN.md — doctor reads the tuple at runtime; recorded docs are never evidence).
- 32 CPUs, 63 GiB free on `/`, x86_64.
- The repo has no git remote. Code reaches aibox03 by rsync, not git push.

## Rulings (recorded here as architecture decisions; PLAN.md deviations log gets the durable copies at close-out)

- **L0-R1 (sync):** `scripts/linux` rsyncs the working tree to `aibox03:~/vmobs-build/` and runs a command there over SSH. No git remote is created; nothing is pushed anywhere.
- **L0-R2 (root boundary):** One-time root setup is a script Doctor Biz runs by hand (password sudo). Ongoing root operations (netns/TAP/nftables, jailer start/stop) go through `/usr/local/sbin/vmobs-root-helper` — root-owned, typed verbs, strict argument validation — with a sudoers NOPASSWD entry for exactly that path. This mirrors privd's philosophy (§3.3: typed requests, no arbitrary shell) and is replaced by `vmobs-privd` in M1. Honest caveat for the runbook: harper's existing `docker` group membership is already root-equivalent on this box, so the helper's marginal exposure is ~zero; the narrow shape is still right because it is the pattern the product ships.
- **L0-R3 (build sandbox):** Kernel and rootfs builds run inside docker containers on aibox03 (pinned base digests) because they need root-ish package installation the host should not carry. Docker is a build sandbox only; the artifacts are a plain `vmlinux` and ext4 files; no container runtime appears in any served path (§3.1's "no Docker socket exposed to the application or guest" governs the deployed service, not the build pipeline).
- **L0-R4 (guest userspace):** Ubuntu 24.04 base (pinned `ubuntu:24.04@sha256:...` digest resolved at implementation), systemd as the reaping init, `vmobs-guestd` as a systemd unit. "Ordinary Linux userspace" per §7.1; toolchain layering arrives with templates later.
- **L0-R5 (rootless imaging):** rootfs ext4 is built with `mkfs.ext4 -d <dir>` (no mounts, no root). Config disks likewise. Reproducibility means pinned inputs (base digest, apt snapshot timestamp, kernel source hash, config hash) plus recorded output digests, inventory, and retained build logs — not bit-identical outputs; timestamp variance is documented.
- **L0-R6 (vsock library):** `github.com/mdlayher/vsock` for the guest listener, pinned in go.mod. Same spirit as §3.1's "use cilium/ebpf rather than inventing a loader".
- **L0-R7 (auth proof):** The §7.4 handshake "authentication proof" is the per-boot capability token itself, delivered via the read-only config device (§7.3) and compared constant-time. There is no third party on a vsock link; an HMAC scheme would add ceremony without a threat it addresses. Guest root can read it — §7.3 already says to treat it that way.
- **L0-R8 (doctor freshness):** Cheap checks (<100ms total) re-run on demand; `GET /host/status` serves the latest report with `ran_at`. The expensive live-guest check (§4.1 item 8) is the fixture itself; its latest result is recorded, not re-run per request. Checks whose subject is not built yet report `not_implemented` — honest rows beat missing rows.
- **L0-R9 (lock absence vs mismatch):** A present-but-mismatched `runtime.lock.json` is fatal at daemon startup (AT-002: tampering evidence). An absent lock is degraded dev state: daemon runs, doctor `fc_binaries` fails, launches stay refused. macOS loopback dev keeps working without a lock.
- **L0-R10 (M0 network scope):** Private networking in M0 = per-VM namespace + TAP + veth with anti-spoof and default-deny (offline posture), transit subnets allocated with host-route overlap detection. No uplink routing, DNS, or policy profiles — that is M3. The fixture asserts isolation artifacts from the host; behavioral egress tests arrive with M3.
- **L0-R11 (socket access):** Fixture VMs run with gid = `vmobs-fixture` (setup creates it; harper joins it) and the helper sets umask 0002 before jailer, so the firecracker API/vsock sockets are group-writable and the unprivileged fixture can connect without chmod games.
- **L0-R12 (AT-001 linkage):** `runtime.ForHost` on every host keeps returning its honest UnavailableError (adapter arrives M1), but the reason string now appends the preflight overall status + first failing check ID when a report exists, so a refused launch names the failed check today. Full doctor-gated launch admission is M1 wiring.

## Execution notes for the controller

- Task order is the dependency order. Tasks 2–5 and the logic half of 7 are portable (build/test on macOS); Tasks 1, 6, 8 need aibox03; Task 8 additionally needs the one-time root setup done.
- **Harper handoff:** the moment Task 1 lands review, tell Doctor Biz to run the printed one-liner on aibox03 (it needs his password). Tasks 2–7 proceed while waiting; only Task 8 hard-blocks on it. Task 6 needs no root (docker group suffices).
- Every task that touches `docs/` runs `uv run docs/validation/check.py`; the dated `docs/VALIDATION.md` revision is folded into Task 9 once.
- Linux-only test files carry `//go:build linux`; KVM/root-dependent integration tests are additionally env-gated with `VMOBS_FIXTURE=1` so `go test ./...` stays green on any host.

---

### Task 1: Remote execution, host runbook, and the root boundary

**Files:**
- Create: `scripts/linux`
- Create: `scripts/aibox03/setup.sh`
- Create: `scripts/aibox03/vmobs-root-helper`
- Create: `scripts/aibox03/sudoers-vmobs`
- Create: `docs/runbooks/aibox03.md`
- Create: `runtime.lock.json` (firecracker/jailer section filled; kernel/image sections empty strings until Task 6)

**Interfaces:**
- Consumes: nothing from the repo; resolves the current stable Firecracker release + SHA256 from its GitHub releases page during implementation and pins it.
- Produces: `scripts/linux '<command>'` (used by every later task), root-helper verbs `net-setup <id> <cidr>`, `net-teardown <id>`, `jail-start <id> <uid> <gid> <cid>`, `jail-stop <id>` (used by Tasks 7–8), `runtime.lock.json` schema `vmobs.runtime_lock.v1` (used by Tasks 3–4, extended by Task 6), fixture directory contract `/srv/vmobs/fixture/<id>/staging/` (harper-writable) and `/srv/vmobs/jail/` (root-owned chroot base).

- [ ] **Step 1: Write `scripts/linux`**

```sh
#!/bin/sh
# ABOUTME: Runs a command on the Linux KVM host (aibox03) against a rsynced
# ABOUTME: copy of this working tree. Usage: scripts/linux 'go test ./...'
set -eu
HOST="${VMOBS_LINUX_HOST:-harper@100.64.0.100}"
DEST="${VMOBS_LINUX_DIR:-vmobs-build}"
[ $# -ge 1 ] || { echo "usage: scripts/linux '<command>'" >&2; exit 3; }
cd "$(dirname "$0")/.."
rsync -az --delete --exclude .git --exclude .superpowers \
  --filter=':- .gitignore' ./ "$HOST:$DEST/"
exec ssh "$HOST" "cd '$DEST' && $*"
```

Note: gitignored paths are excluded from transfer AND protected from `--delete`, so build outputs living under gitignored dirs on aibox03 (e.g. `images/dist/`) survive re-syncs.

- [ ] **Step 2: Verify it round-trips**

Run: `scripts/linux 'go version && go build ./...'`
Expected: prints `go1.27.x linux/amd64`, builds clean.

- [ ] **Step 3: Resolve and pin Firecracker**

On aibox03 (via `scripts/linux` or plain ssh): find the latest stable release tag on https://github.com/firecracker-microvm/firecracker/releases, download the x86_64 release tarball and its SHASUMS, verify, and record. Do NOT guess the version — read the releases page. Write `runtime.lock.json` at repo root:

```json
{
  "schema": "vmobs.runtime_lock.v1",
  "firecracker": {
    "version": "<resolved e.g. v1.x.y>",
    "release_url": "<exact tarball url>",
    "sha256": "<sha256 of firecracker binary>",
    "install_path": "/usr/local/bin/firecracker"
  },
  "jailer": {
    "sha256": "<sha256 of jailer binary>",
    "install_path": "/usr/local/bin/jailer"
  },
  "host_support": { "arch": "x86_64", "min_kernel": "<per the release's docs>" },
  "guest_kernel": { "version": "", "source_url": "", "source_sha256": "", "config_sha256": "", "vmlinux_sha256": "", "vmlinux_path": "images/dist/vmlinux" },
  "root_image": { "sha256": "", "path": "images/dist/rootfs.ext4", "base_image_ref": "", "apt_snapshot": "", "inventory": "images/dist/rootfs.inventory.txt" },
  "guestd": { "protocol_version": 1 }
}
```

The binary hashes come from the verified download, recorded exactly. `min_kernel` comes from the pinned release's documented host kernel support — read it, don't invent it.

- [ ] **Step 4: Write the root helper**

`scripts/aibox03/vmobs-root-helper` — POSIX sh, installed root-owned. Typed verbs only; every argument validated before use; argv arrays, no string-built shell. Full content:

```sh
#!/bin/sh
# ABOUTME: Narrow root helper for the M0 boot fixture on aibox03. Typed verbs
# ABOUTME: with strict validation; installed root-owned; replaced by vmobs-privd in M1.
set -eu

JAIL_BASE=/srv/vmobs/jail
STAGE_BASE=/srv/vmobs/fixture
RUN_BASE=/run/vmobs-fixture
FC_GROUP=vmobs-fixture

die() { echo "vmobs-root-helper: $*" >&2; exit 1; }

valid_id() {
  case "$1" in
    ''|*[!a-z0-9-]*) die "invalid id '$1' (want ^[a-z0-9-]{1,24}$)";;
  esac
  [ ${#1} -le 24 ] || die "id too long"
}

valid_uid() {
  case "$1" in ''|*[!0-9]*) die "invalid uid/gid '$1'";; esac
  [ "$1" -ge 10000 ] && [ "$1" -le 59999 ] || die "uid/gid out of range [10000,59999]"
}

valid_cid() {
  case "$1" in ''|*[!0-9]*) die "invalid cid '$1'";; esac
  [ "$1" -ge 3 ] && [ "$1" -le 65535 ] || die "cid out of range [3,65535]"
}

valid_cidr() {
  echo "$1" | grep -Eq '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/30$' \
    || die "invalid cidr '$1' (want a.b.c.d/30)"
}

cmd="${1:-}"; shift || true
case "$cmd" in
net-setup)
  id="$1"; cidr="$2"; valid_id "$id"; valid_cidr "$cidr"
  ns="vmobs-$id"
  ip netns add "$ns"
  ip netns exec "$ns" ip link set lo up
  ip netns exec "$ns" ip tuntap add dev tap0 mode tap
  ip netns exec "$ns" ip link set tap0 up
  ip link add "veth-$id" type veth peer name eth-up netns "$ns"
  ip link set "veth-$id" up
  ip netns exec "$ns" ip link set eth-up up
  # Default deny inside the namespace: no forwarding, drop all routed traffic.
  ip netns exec "$ns" nft -f - <<EOF
table inet vmobs {
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output  { type filter hook output  priority 0; policy accept; }
  chain input   { type filter hook input   priority 0; policy accept; }
}
EOF
  ;;
net-teardown)
  id="$1"; valid_id "$id"
  ip link del "veth-$id" 2>/dev/null || true
  ip netns del "vmobs-$id" 2>/dev/null || true
  ;;
jail-start)
  id="$1"; uid="$2"; gid="$3"; cid="$4"
  valid_id "$id"; valid_uid "$uid"; valid_uid "$gid"; valid_cid "$cid"
  stage="$STAGE_BASE/$id/staging"
  [ -d "$stage" ] || die "no staging dir $stage"
  [ -z "$(find "$stage" -type l)" ] || die "symlinks in staging refused"
  for f in vmlinux rootfs.ext4 config.ext4 fc-config.json; do
    [ -f "$stage/$f" ] || die "missing $stage/$f"
  done
  root="$JAIL_BASE/firecracker/$id/root"
  mkdir -p "$root"
  cp "$stage/vmlinux" "$stage/rootfs.ext4" "$stage/config.ext4" \
     "$stage/fc-config.json" "$root/"
  chown -R "$uid:$gid" "$JAIL_BASE/firecracker/$id"
  mkdir -p "$RUN_BASE"
  umask 0002
  jailer --id "$id" --exec-file /usr/local/bin/firecracker \
    --uid "$uid" --gid "$gid" \
    --chroot-base-dir "$JAIL_BASE" \
    --netns "/var/run/netns/vmobs-$id" \
    --daemonize \
    -- --config-file fc-config.json --api-sock api.sock
  ;;
jail-stop)
  id="$1"; valid_id "$id"
  pid="$(pgrep -f "firecracker --id $id " || true)"
  if [ -n "$pid" ]; then
    kill -TERM $pid 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 $pid 2>/dev/null || break; sleep 0.5
    done
    kill -KILL $pid 2>/dev/null || true
  fi
  rm -rf "$JAIL_BASE/firecracker/$id"
  ;;
*)
  die "unknown verb '$cmd' (net-setup|net-teardown|jail-start|jail-stop)"
  ;;
esac
```

The implementer MUST verify the jailer flag names and daemonize/pgrep process-title behavior against the pinned release's `jailer --help` on aibox03 and adjust — the plan's invocation is the shape, the release's help text is the authority. Same for the firecracker config-file schema in Task 8.

- [ ] **Step 5: Write sudoers fragment and setup script**

`scripts/aibox03/sudoers-vmobs`:

```
harper ALL=(root) NOPASSWD: /usr/local/sbin/vmobs-root-helper
```

`scripts/aibox03/setup.sh` (run once by Doctor Biz, with password sudo):

```sh
#!/bin/sh
# ABOUTME: One-time root setup for aibox03 as the vmobs L0 host. Run as:
# ABOUTME:   cd ~/vmobs-build && sudo sh scripts/aibox03/setup.sh
set -eu
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

# 1. Tools the pipeline needs on the host.
apt-get install -y --no-install-recommends jq e2fsprogs >/dev/null

# 2. KVM access + fixture group.
usermod -aG kvm harper
# Fixed gid 36000: the root helper validates gid in [10000,59999]; a --system
# group would land below 1000 and be rejected at jail-start.
if ! getent group vmobs-fixture >/dev/null; then
  getent group 36000 >/dev/null && { echo "gid 36000 taken; edit setup.sh" >&2; exit 1; }
  groupadd --gid 36000 vmobs-fixture
fi
usermod -aG vmobs-fixture harper

# 3. Pinned firecracker + jailer, hash-verified against runtime.lock.json.
lock="$repo/runtime.lock.json"
ver="$(jq -r .firecracker.version "$lock")"
url="$(jq -r .firecracker.release_url "$lock")"
want_fc="$(jq -r .firecracker.sha256 "$lock")"
want_j="$(jq -r .jailer.sha256 "$lock")"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$url" -o "$tmp/fc.tgz"
tar -xzf "$tmp/fc.tgz" -C "$tmp"
fc="$(find "$tmp" -name "firecracker-$ver-x86_64" -type f)"
j="$(find "$tmp" -name "jailer-$ver-x86_64" -type f)"
echo "$want_fc  $fc" | sha256sum -c - >/dev/null
echo "$want_j  $j"  | sha256sum -c - >/dev/null
install -o root -g root -m 0755 "$fc" /usr/local/bin/firecracker
install -o root -g root -m 0755 "$j" /usr/local/bin/jailer

# 4. Root helper + narrow sudoers.
install -o root -g root -m 0755 "$here/vmobs-root-helper" /usr/local/sbin/vmobs-root-helper
install -o root -g root -m 0440 "$here/sudoers-vmobs" /etc/sudoers.d/vmobs-fixture
visudo -c >/dev/null

# 5. Fixture directories.
install -d -o harper -g vmobs-fixture -m 0775 /srv/vmobs /srv/vmobs/fixture
install -d -o root -g root -m 0755 /srv/vmobs/jail

echo "setup complete: kvm+vmobs-fixture groups (re-login needed), firecracker $ver, helper+sudoers installed"
```

- [ ] **Step 6: Write the runbook**

`docs/runbooks/aibox03.md`: host facts, what setup.sh does and why each piece exists, the docker-group root-equivalence caveat from L0-R2 verbatim, how to re-run setup after a firecracker version bump, how `scripts/linux` works, and the fixture env vars (`VMOBS_FIXTURE=1`). Include the exact operator command:

```
scripts/linux 'true'   # sync first
ssh harper@100.64.0.100 'cd vmobs-build && sudo sh scripts/aibox03/setup.sh'
```

- [ ] **Step 7: Validate scripts and docs**

Run: `sh -n scripts/linux scripts/aibox03/setup.sh scripts/aibox03/vmobs-root-helper` (syntax), `scripts/check`, `uv run docs/validation/check.py`.
Expected: all green. The setup script itself is NOT run — that is Doctor Biz's handoff.

- [ ] **Step 8: Commit**

```bash
git add scripts/linux scripts/aibox03/ docs/runbooks/aibox03.md runtime.lock.json
git commit -m "feat(linux): remote exec script, aibox03 setup + narrow root helper, firecracker pin"
```

---

### Task 2: Guest channel framing and handshake protocol

**Files:**
- Create: `internal/guest/proto/frame.go`
- Create: `internal/guest/proto/frame_test.go`
- Create: `internal/guest/proto/messages.go`
- Create: `internal/guest/proto/messages_test.go`
- Create: `internal/guest/proto/hostdial.go`
- Create: `internal/guest/proto/hostdial_test.go`
- Create: `docs/guest-protocol.md`
- Create: `docs/schemas/guest-hello.schema.json`
- Create: `docs/schemas/guest-capability.schema.json`

**Interfaces:**
- Consumes: nothing.
- Produces (Tasks 5, 8 depend on these exact names):
  - `const ProtocolVersion = 1`
  - `const FrameControl byte = 0x01`, `FramePTY byte = 0x02`, `FrameArtifact byte = 0x03`
  - `const MaxControlFrame = 1 << 20`, `MaxBinaryFrame = 256 << 10`
  - `func WriteFrame(w io.Writer, typ byte, payload []byte) error`
  - `func ReadFrame(r io.Reader) (typ byte, payload []byte, err error)` — rejects oversized length BEFORE allocation, unknown type, short header.
  - `type Envelope struct { V int; Kind string; Data json.RawMessage }` (JSON: `v`, `kind`, `data`)
  - Kinds: `hello`, `hello_ack`, `get_capabilities`, `capabilities`, `ping`, `pong`, `error`
  - `type Hello struct { ProtocolVersion int; VMID, BootID, SourceInstance string; ResumeCursor string; AuthProof string }` (JSON snake_case; ResumeCursor is a decimal string, `"0"` initially)
  - `type HelloAck struct { Accepted bool; Reason string }`
  - `type CapabilityManifest struct { Schema string; KernelRelease string; Features []Feature }`, `type Feature struct { ID string; Present bool; Evidence string }` — Schema is `"vmobs.guest_capability.v1"`; feature IDs in M0: `btf`, `bpf_syscall`, `fanotify`, `fanotify_report_fid`, `cgroup_v2`, `devpts`, `vsock`, `virtio_net`, `virtio_blk`, `ext4`.
  - `func WriteControl(w io.Writer, kind string, data any) error`, `func ReadControl(r io.Reader) (Envelope, error)`
  - `func DialHostVsock(ctx context.Context, udsPath string, port uint32) (net.Conn, error)` — Firecracker host-side handshake: write `CONNECT <port>\n`, expect `OK <hostport>\n` (§7.3 [S3]).

- [ ] **Step 1: Write failing frame tests** — round-trip each type; oversized control (>1MiB) rejected with a length error before reading the body (feed a header claiming 100MiB over a real `net.Pipe`, assert error without the writer sending a body); unknown type 0x7F rejected; truncated header rejected.

```go
func TestReadFrameRejectsOversizeBeforeAllocation(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		hdr := []byte{FrameControl, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(hdr[1:], 100<<20)
		c1.Write(hdr) // no body ever sent
	}()
	_, _, err := ReadFrame(c2)
	if err == nil || !strings.Contains(err.Error(), "frame length") {
		t.Fatalf("want frame length error, got %v", err)
	}
}
```

- [ ] **Step 2: Run tests, verify FAIL** — `env -u GOROOT mise exec -- go test ./internal/guest/proto/`
- [ ] **Step 3: Implement frame.go** — 5-byte header `[type:1][len:4 big-endian]`; ReadFrame reads header with `io.ReadFull`, validates type ∈ {0x01,0x02,0x03} and len ≤ per-type max, then reads exactly len bytes.
- [ ] **Step 4: Write failing message + dial tests** — Envelope encode/decode; Hello JSON uses snake_case and carries `resume_cursor` as a string; DialHostVsock against a real unix-socket test server that speaks `CONNECT`/`OK` (this is Firecracker's seam, not ours — the real pairing happens in Task 8); server answering `ERR\n` or garbage → typed error.
- [ ] **Step 5: Implement messages.go + hostdial.go** — dial with a context deadline; read the OK line byte-at-a-time to a 64-byte cap (no buffering past the line: subsequent bytes belong to the application protocol).
- [ ] **Step 6: Write docs** — `docs/guest-protocol.md`: byte order (big-endian), maxima, frame types, control kinds, and the handshake sequence. Direction: guestd listens on vsock port 10000; the host initiates (CONNECT/OK on Firecracker's Unix socket, then the application protocol). The host authenticates to the guest: it minted the per-boot token into the config device, so it sends `hello` with the token as `auth_proof`; the guest compares constant-time and answers `hello_ack`. Then `get_capabilities` → `capabilities`, `ping` → `pong`. Deadlines: handshake 10s, read-idle 60s, write 10s. Two JSON schema files match the Go types.
- [ ] **Step 7: All green + docs check** — `scripts/check` and `uv run docs/validation/check.py`.
- [ ] **Step 8: Commit** — `git commit -m "feat(guest): vsock framing, handshake messages, host CONNECT dialer"`

---

### Task 3: Runtime lock verification

**Files:**
- Create: `internal/lock/lock.go`
- Create: `internal/lock/lock_test.go`
- Modify: `internal/config/config.go` (add `Runtime struct { LockFile string }`, default `"runtime.lock.json"`, under a `runtime:` YAML key; empty string allowed = explicitly no lock)
- Modify: `cmd/vmobsd/main.go` (startup verification per L0-R9)
- Test: `cmd/vmobsd/lock_startup_test.go`

**Interfaces:**
- Consumes: `runtime.lock.json` schema from Task 1.
- Produces (Task 4 depends on): 
  - `type Lock struct` mirroring the JSON schema exactly
  - `func Load(path string) (*Lock, error)` — unknown `schema` value is an error
  - `type Mismatch struct { Subject, Want, Got string }`
  - `func (l *Lock) VerifyBinaries() []Mismatch` — SHA256s `firecracker.install_path` and `jailer.install_path`; a missing file is a Mismatch with Got `"absent"`; empty `sha256` fields (not yet pinned) are skipped with a Mismatch NOT emitted but reported by `func (l *Lock) Unpinned() []string`
  - `func (l *Lock) VerifyArtifacts(repoRoot string) []Mismatch` — same for `guest_kernel.vmlinux_path` and `root_image.path` when their sha fields are non-empty

- [ ] **Step 1: Failing tests** — temp dir with two fake binaries; lock JSON pointing at them with correct hashes → no mismatches; flip one byte in the binary → exactly one Mismatch naming the subject (AT-002 at unit level); missing file → `"absent"`; unpinned kernel section → `Unpinned()` lists it, VerifyArtifacts empty.
- [ ] **Step 2: Verify FAIL, implement, verify PASS.**
- [ ] **Step 3: Startup wiring + test** — in `cmd/vmobsd`: if `cfg.Runtime.LockFile` non-empty AND the file exists → Load + VerifyBinaries; any Mismatch → daemon refuses to start with an error listing every mismatch (subject, want, got). File absent → log one line (`runtime lock absent; launches will be refused by preflight`) and continue. Test boots the real daemon `serve()` with a temp config naming a lock whose hash is wrong → startup error mentions the subject; and with no lock file → daemon serves normally.
- [ ] **Step 4: `scripts/check` green. Commit** — `git commit -m "feat(lock): runtime.lock.json verification; startup refuses hash mismatches"`

---

### Task 4: Preflight doctor

**Files:**
- Create: `internal/preflight/preflight.go` (types + runner)
- Create: `internal/preflight/checks.go` (portable checks)
- Create: `internal/preflight/checks_linux.go` (`//go:build linux`: KVM open + API version + tiny real-mode guest)
- Create: `internal/preflight/checks_other.go` (`//go:build !linux`: arch_kvm fails honestly with GOOS evidence)
- Create: `internal/preflight/preflight_test.go`, `internal/preflight/checks_linux_test.go`
- Modify: `internal/api/vms.go:466` (`handleHostStatus`): add `"preflight"` block to `/host/status`
- Modify: `internal/api/api.go`: `Server` gains a `Preflight func(ctx context.Context, refresh bool) preflight.Report` config hook (nil = block absent, honest for tests that don't wire it)
- Modify: `cmd/vmobsd/main.go`: construct the preflight runner with the loaded lock + config, wire into api.New, run once at startup
- Modify: `cmd/vmobs/main.go` + new `cmd/vmobs/doctor.go`: `vmobs doctor [--json]` rendering GET /host/status's preflight block (human table derived from the same data, §4.1)
- Modify: `internal/runtime/runtime.go`: UnavailableError reason appends preflight summary (L0-R12) — `ForHost` gains an optional `PreflightSummary func() string` hook; when set and non-empty its result is appended to the reason.
- Test: `cmd/vmobs/doctor_cli_test.go`, api host/status test additions

**Interfaces:**
- Consumes: `lock.Load/VerifyBinaries/Unpinned` (Task 3), `config.Config`.
- Produces:
  - `type Status string` — `"pass" | "fail" | "warn" | "not_implemented"`
  - `type Remediation struct { Cause, Action string; Params map[string]string }`
  - `type Check struct { ID string; Status Status; Summary string; Evidence []string; Remediation *Remediation }`
  - `type Report struct { RanAt time.Time; Arch, KernelRelease string; Overall Status; Checks []Check }` — Overall = fail if any check fails, else warn if any warns, else pass; `not_implemented` does not fail Overall but is listed.
  - `func New(cfg Config) *Runner` where `Config { Lock *lock.Lock; LockErr error; DataDir string; APIMode string; RequireAuth bool }`
  - `func (r *Runner) Run(ctx context.Context) Report` — cheap checks only; bounded <1s.
  - Check IDs (fixed, machine-readable): `arch_kvm`, `fc_binaries`, `kernel_tuple`, `cgroup_v2`, `net_prereqs`, `resources`, `dir_permissions`, `api_binding`, `guest_channel` (always `not_implemented` in M0 with Summary pointing at the fixture — flips in M1).

- [ ] **Step 1: Failing framework tests** — Overall aggregation truth table; JSON rendering field names (`ran_at`, `overall`, `checks[].id/status/summary/evidence/remediation`); every check present exactly once in every report regardless of status.
- [ ] **Step 2: Portable checks + tests** — `fc_binaries` from lock (nil lock → fail "no runtime lock", LockErr → fail with it, Unpinned non-empty → warn, mismatches → fail listing subjects); `resources` (MemAvailable via a `ProcRoot string` field default `/proc` — tests point at a tempdir with a real meminfo file; disk via `unix.Statfs` on DataDir; evidence carries numbers); `dir_permissions` (DataDir must exist, not world-writable — build a bad-perm tempdir in the test); `api_binding` (loopback+no-auth or https+auth = pass with evidence, anything else fail — reuse the config invariants); `kernel_tuple` (uname release vs `host_support.min_kernel`, string-compare major.minor numerically); `cgroup_v2` + `net_prereqs` read real paths (`/sys/fs/cgroup/cgroup.controllers`; `exec.LookPath` for `ip`, `nft`) — on macOS they fail/warn honestly; their pass-path asserts run on aibox03 in Step 5.
- [ ] **Step 3: Linux KVM check** — `checks_linux.go`: open `/dev/kvm` O_RDWR (ENOENT/EACCES → fail with remediation `run scripts/aibox03/setup.sh` / `re-login for kvm group`), `KVM_GET_API_VERSION` must be 12, `KVM_CREATE_VM` + `KVM_CREATE_VCPU` + run a minimal real-mode guest that executes `hlt` (a ~60-line canonical sequence with `golang.org/x/sys/unix`; memory via mmap; expect `KVM_EXIT_HLT`). This satisfies "run a real test guest" without silent emulation (§4.1). Evidence: api version, exit reason. `checks_other.go`: fail, evidence `GOOS=darwin: KVM requires Linux`.
- [ ] **Step 4: API + CLI wiring** — `/host/status` gains `"preflight": {…}` when the hook is wired (absent otherwise — never an empty fake block); `?refresh=1` re-runs; `vmobs doctor` renders a table (ID, STATUS, SUMMARY + evidence lines) from `--json`'s exact data; exit 1 when Overall = fail (a failed doctor is a structured API success but an operational failure — exit code carries the verdict, matching `vmobs`'s 0-on-success convention). Real-HTTP CLI test.
- [ ] **Step 5: Linux verification** — `scripts/linux 'go test ./internal/preflight/ ./internal/lock/'`. Expected TODAY (pre-setup): all portable tests pass; the KVM check unit test asserts BOTH branches honestly — if `/dev/kvm` opens, full sequence passes; if EACCES (no kvm group yet), the check must fail with the re-login remediation. Write the test to accept either real outcome and assert the report is honest about which occurred (no skip, no fake).
- [ ] **Step 6: L0-R12 linkage + test** — UnavailableError reason ends with `; preflight: fail (arch_kvm)` style suffix when the hook reports non-pass; existing AT-001 refusal tests still pass.
- [ ] **Step 7: `scripts/check` green. Commit** — `git commit -m "feat(preflight): doctor checks, /host/status preflight block, vmobs doctor"`

---

### Task 5: vmobs-guestd core

**Files:**
- Create: `cmd/vmobs-guestd/main.go`
- Create: `internal/guest/agent.go`, `internal/guest/agent_test.go`
- Create: `internal/guest/probe.go`, `internal/guest/probe_linux.go`, `internal/guest/probe_test.go`
- Create: `internal/guest/bootcfg.go`, `internal/guest/bootcfg_test.go`
- Modify: `go.mod` (add `github.com/mdlayher/vsock`, pinned)

**Interfaces:**
- Consumes: everything Task 2 produced.
- Produces (Task 6 bakes the binary; Task 8 talks to it):
  - `type BootConfig struct { Schema string; VMID, BootID string; CapabilityToken string; ProtocolVersion int }` — JSON schema value `"vmobs.guest_context.v1"`, file `context.json` at the config-device root. M0 carries only these fields; M4 extends the same file (additive).
  - `func LoadBootConfigDir(dir string) (*BootConfig, error)` (validation: all fields non-empty, version match); `func LoadBootConfig(device, mountpoint string) (*BootConfig, error)` (linux: mount ext4 read-only via `unix.Mount`, then Dir variant)
  - `func ProbeCapabilities() proto.CapabilityManifest` — feature probes: `btf` = `/sys/kernel/btf/vmlinux` exists; `bpf_syscall` + `fanotify` + `fanotify_report_fid` = feature-specific syscall probes behind `//go:build linux` (e.g. `fanotify_init(FAN_CLASS_NOTIF|FAN_REPORT_FID,…)` succeeding then closed); `cgroup_v2` = `/sys/fs/cgroup/cgroup.controllers` readable; `devpts` + `ext4` = `/proc/filesystems` lines; `vsock` = `/dev/vsock` exists; `virtio_net`/`virtio_blk` = `/sys/bus/virtio/drivers/virtio_net` / `virtio_blk` exist. Each Feature carries Evidence (the path or errno). Non-linux: every feature `Present: false`, evidence `GOOS`.
  - `type Agent struct`; `func NewAgent(cfg *BootConfig, manifest proto.CapabilityManifest) *Agent`; `func (a *Agent) ServeControl(ctx context.Context, ln net.Listener) error` — per-conn: 10s handshake deadline; first frame must be `hello` with matching ProtocolVersion and constant-time-equal AuthProof (`crypto/subtle`), else `hello_ack{accepted:false}` + close; then answer `get_capabilities` / `ping`; 60s idle read deadline; malformed frame → `error` envelope + close.

- [ ] **Step 1: Failing agent tests over real net.Pipe/unix listeners** — good token handshake → ack accepted, capabilities round-trip carries the manifest; wrong token → refused ack, connection closed, a second good connection still works; oversized frame → connection closed; protocol version mismatch → refused with reason.
- [ ] **Step 2: Implement agent.go, verify PASS.**
- [ ] **Step 3: Failing bootcfg tests** — tempdir with valid context.json → loads; missing field → error naming it; LoadBootConfig mount path is linux-only (tested by the fixture, not unit tests).
- [ ] **Step 4: Probe + tests** — on darwin asserts all-false-with-GOOS-evidence; on linux (`scripts/linux`) asserts the aibox03 host truthfully (btf/cgroup_v2/ext4 present there — but do NOT hardcode expectations that make the test lie elsewhere; assert Evidence non-empty and Present matches an independent stat of the same path done in the test).
- [ ] **Step 5: main.go** — flags `-config-dev` (default `/dev/vdb`), `-config-mount` (default `/run/vmobs/config`), `-control-port` (default 10000, §7.3). Sequence: mount+load config, probe, `vsock.ListenContextID`? No — guest listener: `vsock.Listen(port, nil)`. Serve until SIGTERM. Vsock is the ONLY served transport (no unix/tcp flags — unit tests use the Agent directly).
- [ ] **Step 6: Cross-compile proof** — `scripts/linux 'go build ./cmd/vmobs-guestd && go vet ./...'` and `scripts/check` locally (guestd main is linux-only via build tag; a darwin build of the repo must still succeed — put main.go behind `//go:build linux` with a stub main_other.go that exits 2 with "vmobs-guestd runs inside a Linux guest").
- [ ] **Step 7: Commit** — `git commit -m "feat(guestd): control-channel agent, capability probe, boot config device"`

---

### Task 6: Guest kernel and root image pipeline

**Files:**
- Create: `images/kernel/build.sh`, `images/kernel/vmobs.fragment`
- Create: `images/rootfs/build.sh`, `images/rootfs/pins.env`, `images/rootfs/guestd.service`
- Create: `images/build-all.sh`, `images/README.md`
- Modify: `runtime.lock.json` (fill `guest_kernel.*`, `root_image.*`)
- Modify: `.gitignore` (add `images/dist/`)

**Interfaces:**
- Consumes: `cmd/vmobs-guestd` (Task 5), lock schema (Task 1), docker on aibox03 (rootless for us — harper is in the docker group).
- Produces: `images/dist/vmlinux`, `images/dist/rootfs.ext4`, `images/dist/rootfs.inventory.txt`, `images/dist/logs/*.log` on aibox03; hashes recorded in `runtime.lock.json` (committed). Tasks 7–8 consume the artifacts by lock-recorded path.

- [ ] **Step 1: Kernel config fragment** — `images/kernel/vmobs.fragment` with the §7.1 facilities, each `CONFIG_…=y`: BPF (`CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT`, `CONFIG_DEBUG_INFO_BTF`, `CONFIG_KPROBES`, `CONFIG_TRACEPOINTS`, `CONFIG_PERF_EVENTS`), fanotify (`CONFIG_FANOTIFY`, `CONFIG_FANOTIFY_ACCESS_PERMISSIONS`), cgroups (`CONFIG_CGROUPS`, `CONFIG_CGROUP_BPF`, `CONFIG_MEMCG`, `CONFIG_CGROUP_PIDS`, `CONFIG_CPUSETS`, `CONFIG_CGROUP_SCHED`), PTY (`CONFIG_UNIX98_PTYS`, `CONFIG_DEVPTS_FS`... `DEVPTS` is not separately configurable on modern kernels — implementer verifies each symbol EXISTS in the chosen source before requiring it; a fragment symbol the kernel doesn't know is a silent no-op, which is exactly the failure §7.1 warns about), virtio (`CONFIG_VIRTIO`, `CONFIG_VIRTIO_MMIO`, `CONFIG_VIRTIO_NET`, `CONFIG_VIRTIO_BLK`, `CONFIG_VSOCKETS`, `CONFIG_VIRTIO_VSOCKETS`), filesystems (`CONFIG_EXT4_FS`, `CONFIG_TMPFS`, `CONFIG_PROC_FS`, `CONFIG_SYSFS`).
- [ ] **Step 2: Kernel build script** — `images/kernel/build.sh` runs on aibox03: pick the guest kernel version from the pinned Firecracker release's documented supported guest kernels (read the release's docs/CI resources — do not invent; firecracker publishes recommended guest configs per release), download source from kernel.org with sha256 verification, start from the release's recommended microvm guest config, merge the fragment via `scripts/kconfig/merge_config.sh`, `make olddefconfig`, then HARD-VERIFY: for every symbol in the fragment, `grep -q '^CONFIG_X=y' .config` or the build fails listing the missing ones (this is the §7.1 "verify required kernel facilities" step). Build `make -j$(nproc) vmlinux` inside a docker container (pinned `ubuntu:24.04@<digest>` + build-essential flex bison bc libelf-dev dwarves python3 — dwarves supplies pahole for BTF). Outputs: `images/dist/vmlinux`, sha256s of source tarball/config/vmlinux, log to `images/dist/logs/kernel.log`.
- [ ] **Step 3: Rootfs build script** — `images/rootfs/pins.env` holds `BASE_IMAGE_REF` (`ubuntu:24.04@sha256:<digest resolved at implementation>`) and `APT_SNAPSHOT` (a `snapshot.ubuntu.com` timestamp resolved at implementation). `build.sh`: `go build` vmobs-guestd (linux/amd64, CGO_ENABLED=0); docker run the pinned base, apt from the snapshot (`-o Acquire::Snapshots::URI` per Ubuntu 24.04 snapshot support — implementer verifies the exact apt option name on aibox03 rather than trusting this plan), install `systemd-sysv udev ca-certificates dbus`; copy in guestd + `guestd.service` (enabled via symlink), fstab (`/dev/vda / ext4 defaults 0 1`), hostname, empty machine-id; `docker export` the container; unpack to a dir; `mkfs.ext4 -d <dir> images/dist/rootfs.ext4 1G` (rootless); `dpkg -l` inventory into `rootfs.inventory.txt`; log retained. guestd.service:

```ini
[Unit]
Description=vmobs guest agent
After=local-fs.target
[Service]
ExecStart=/usr/local/bin/vmobs-guestd
Restart=on-failure
[Install]
WantedBy=multi-user.target
```

- [ ] **Step 4: build-all + lock update** — `images/build-all.sh` runs both, then writes the produced sha256s/versions/pins into `runtime.lock.json` via `jq` in place ON THE AIBOX03 COPY and prints the updated JSON; the implementer copies the values back into the committed `runtime.lock.json` (scp or paste — the repo copy is the source of truth and MUST match the artifacts; Task 8's fixture verifies via `lock.VerifyArtifacts` on aibox03).
- [ ] **Step 5: Run it** — `scripts/linux 'sh images/build-all.sh'` (docker + no root needed). Expected: both artifacts exist, inventory non-empty, fragment verification step passed in the log, lock updated + committed.
- [ ] **Step 6: Commit** — `git commit -m "feat(images): reproducible guest kernel + ubuntu rootfs pipeline, lock pins"`

---

### Task 7: Private-network baseline

**Files:**
- Create: `internal/network/alloc.go`, `internal/network/alloc_test.go`
- Create: `internal/network/names.go`, `internal/network/names_test.go`
- Test (linux, root-gated): `tests/integration/netns_test.go`

**Interfaces:**
- Consumes: root-helper `net-setup`/`net-teardown` (Task 1).
- Produces (Task 8 uses):
  - `type Allocator struct`; `func NewAllocator(hostRoutes []Route, pools []netip.Prefix) (*Allocator, error)` — pools default `[10.190.0.0/16, 172.28.0.0/16]`; construction FAILS if every pool overlaps host routes; overlapping pools are excluded with the exclusion recorded in `func (a *Allocator) Exclusions() []string` (§10.1: detect overlap with host LAN/VPN routes before allocation).
  - `type Route struct { Dst netip.Prefix }`; `func ParseIPRoutes(jsonOut []byte) ([]Route, error)` — parses `ip -json route` output (test fixture: real captured output from aibox03, including the tailscale 100.64/10 and docker routes).
  - `func (a *Allocator) Next() (netip.Prefix, error)` — sequential /30s, error when exhausted.
  - `func NamespaceName(id string) string` = `vmobs-<id>`; `func VethName(id string) string` = `veth-<id>` (must match the helper's derivations exactly — one naming source; the helper derives from id, these functions predict it for assertions).

- [ ] **Step 1: Failing alloc tests** — overlap exclusion (pool overlapping a fixture tailscale route is excluded and recorded); all-pools-overlap → error; /30 sequencing; exhaustion; ParseIPRoutes on the real captured `ip -json route` fixture from aibox03 (capture it during implementation: `scripts/linux 'ip -json route'` → testdata file).
- [ ] **Step 2: Implement, PASS, portable green.**
- [ ] **Step 3: Root-path integration test** — `tests/integration/netns_test.go` (`//go:build linux`, skip unless `VMOBS_FIXTURE=1`): `sudo /usr/local/sbin/vmobs-root-helper net-setup itest-net 10.190.0.0/30`, assert `/var/run/netns/vmobs-itest-net` exists, `ip netns exec` shows tap0 + nft table with forward-drop policy (read via `sudo …helper`? No — `ip netns list` and `/var/run/netns` stat need no root; rule-content assertion uses `sudo vmobs-root-helper` only if a read verb exists — it does not, and adding read verbs bloats the helper. Assert what harper can see without root: netns exists, veth-itest-net exists host-side with correct name, teardown removes both. Rule-content verification lands in M3 with real policy tests.) Then `net-teardown`, assert gone. This test SKIPS (with a printed reason) until Doctor Biz's setup lands — it must not fake a pass.
- [ ] **Step 4: `scripts/check` + `scripts/linux 'go test ./internal/network/'` green. Commit** — `git commit -m "feat(network): transit allocation with host-route overlap detection; netns fixture test"`

---

### Task 8: Jailed boot fixture — the M0 gate

**Files:**
- Create: `tests/integration/fixture/fixture.go` (helper package: PrepareVM, StartVM, StopVM, evidence capture)
- Create: `tests/integration/boot_test.go`
- Create: `tests/integration/README.md` (how to run; env vars; what evidence is captured where)

**Interfaces:**
- Consumes: proto (T2), lock (T3), guest BootConfig (T5), images (T6), allocator+names (T7), root helper (T1).
- Produces: the M0 gate evidence. `type VM struct { ID string; UID, GID int; CID uint32; Stage string; UDSPath string }`; `func PrepareVM(t *testing.T, repoRoot, id string, n int) *VM`; `func (v *VM) Start(t *testing.T)`; `func (v *VM) Stop(t *testing.T)`; `func (v *VM) DialControl(ctx context.Context) (net.Conn, error)`.

All of Task 8 is `//go:build linux` + `VMOBS_FIXTURE=1`-gated and runs via `scripts/linux 'VMOBS_FIXTURE=1 go test ./tests/integration/ -v -timeout 600s'`.

- [ ] **Step 1: PrepareVM** — uid/gid = 20000+n / the `vmobs-fixture` group's gid (resolve via `user.LookupGroup`); CID 3+n; build the per-VM config disk: tempdir with `context.json` (fresh boot UUID via `crypto/rand`-based UUID, 32-byte hex capability token) → `mkfs.ext4 -d` a 1MiB image; copy `images/dist/rootfs.ext4` + `vmlinux` (paths and hashes from `lock.Load` + `VerifyArtifacts` — a hash mismatch FAILS the test: never boot unverified artifacts); write `fc-config.json`:

```json
{
  "boot-source": { "kernel_image_path": "vmlinux", "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw" },
  "drives": [
    { "drive_id": "rootfs", "path_on_host": "rootfs.ext4", "is_root_device": true, "is_read_only": false },
    { "drive_id": "config", "path_on_host": "config.ext4", "is_root_device": false, "is_read_only": true }
  ],
  "machine-config": { "vcpu_count": 1, "mem_size_mib": 512 },
  "vsock": { "guest_cid": <CID>, "uds_path": "v.sock" },
  "network-interfaces": [ { "iface_id": "eth0", "host_dev_name": "tap0" } ]
}
```

(Implementer: validate this against the pinned release's config-file schema on aibox03 — `firecracker --help` / the release's docs in the downloaded tarball; the plan's field names are the shape, the release is the authority.) Stage everything to `/srv/vmobs/fixture/<id>/staging/`.

- [ ] **Step 2: Start/Stop** — `sudo /usr/local/sbin/vmobs-root-helper net-setup <id> <subnet>` (subnet from Allocator over live `ip -json route`), then `jail-start <id> <uid> <gid> <cid>`; UDSPath = `/srv/vmobs/jail/firecracker/<id>/root/v.sock`; readiness = retry `proto.DialHostVsock(ctx, UDSPath, 10000)` with 500ms backoff ≤ 60s. Stop = `jail-stop` + `net-teardown`, always via `t.Cleanup`.
- [ ] **Step 3: The gate test, four assertions in one boot pair** — boot `m0-a` and `m0-b` SIMULTANEOUSLY, then:
  1. **Real KVM boot + vsock handshake:** DialControl each; send `hello` (proof = that VM's token from its own context.json); assert `hello_ack.accepted` for the right VM and that VM A's token is REJECTED on VM B's socket (identity isolation).
  2. **Capability report:** `get_capabilities` → manifest asserts `btf`, `fanotify`, `vsock`, `virtio_blk`, `virtio_net`, `cgroup_v2`, `ext4` all `Present: true` with evidence — this proves the Task 6 fragment actually took effect end-to-end (§18 M0 "sensor capability report").
  3. **Independent disk ownership:** stat both chroot dirs from the host: `/srv/vmobs/jail/firecracker/<id>/root/rootfs.ext4` for A and B have different `st_uid` (20000 vs 20001), neither is harper/root-writable-by-others, distinct inodes; the two api.sock/v.sock files are owned by their own uid (AT-004 evidence: identity, approved disks, socket ownership from the host).
  4. **Independent teardown (AT-011/AT-018 seed):** stop A; B's control channel still answers `ping`; after stopping both, `/srv/vmobs/jail/firecracker/` and `/var/run/netns/` contain no `m0-*` entries (no leaks).
- [ ] **Step 4: Evidence capture** — the test writes a bounded evidence file `tests/integration/evidence/m0-boot-<hostname>.txt` (committed): lock hashes verified, firecracker version string (`/usr/local/bin/firecracker --version` output), per-VM uid/cid/netns, handshake transcript kinds (never the token), manifest JSON, ownership stat lines, teardown proof. Bounded ≤200 lines.
- [ ] **Step 5: Run the gate** — `scripts/linux 'VMOBS_FIXTURE=1 go test ./tests/integration/ -v -timeout 600s'` → PASS; commit evidence. Debugging note: serial console output lands in the jailer chroot (firecracker logs) — capture the log file path into evidence on failure. This task is the hard one; expect real iteration against firecracker's actual behavior.
- [ ] **Step 6: Commit** — `git commit -m "feat(fixture): jailed two-VM boot fixture — KVM, vsock handshake, capability report, disk ownership"`

---

### Task 9: Acceptance ledger, docs, and close-out

**Files:**
- Modify: `docs/ACCEPTANCE.md` (rows AT-001..AT-004 statuses per its own tracking conventions — read the file's status mechanism first and follow it)
- Modify: `docs/VALIDATION.md` (one dated revision covering all L0 docs: runbook, guest-protocol, schemas, images README, integration README)
- Modify: `PLAN.md` (phase table L0 row → done for M0 scope, L1=M1 next; copy rulings L0-R1..R12 into the deviations log dated; session log entry; kernel-drift note on the host section)
- Modify: `gotchas.md` (entries: scripts/linux usage + gitignore-filter behavior; sudo-needs-password boundary + root-helper path; mkfs.ext4 -d rootless imaging; fixture env gates)

- [ ] **Step 1: Acceptance statuses, honestly** — AT-001: TESTED_PASS only for what M0 demonstrates (doctor fails arch_kvm without KVM; launch refusal names preflight per L0-R12) with a note that doctor-gated admission completes in M1. AT-002: TESTED_PASS (startup rejects mutated hash — unit + daemon startup test). AT-003: remains SPECIFIED with a note (capability report exists; strict-observation refusal is M1/M2). AT-004: TESTED_PASS with the evidence file path. AT-009/AT-011/AT-018: note partial evidence from the fixture, statuses unchanged. Every claim links to a test name or evidence file.
- [ ] **Step 2: Run both gates end to end** — `scripts/check` AND `scripts/linux 'go test ./...'` AND `uv run docs/validation/check.py`.
- [ ] **Step 3: Commit** — `git commit -m "docs(l0): acceptance statuses, validation revision, plan + gotchas close-out"`

## Self-review notes (writing-plans checklist, run before saving)

- Spec coverage: §18 M0 deliverables → doctor (T4), version locking (T1+T3), image build (T6), guest capability probe (T5), private networking (T7), jailed boot fixture (T8), documented host setup (T1). Gate items → T8 assertions 1–3 + ownership. §4.1's nine checks → T4 IDs (item 5 partial as `net_prereqs`, item 8 as `guest_channel`/fixture — honest `not_implemented` rows). §7.4 framing/§7.3 CONNECT → T2. §7.1 config fragment + verification → T6. §10.1 overlap detection → T7.
- Known deferrals (recorded, not hidden): behavioral egress-deny tests (M3), doctor-gated launch admission (M1), strict-observation refusal (M1/M2), terminal handshake (M1), rule-content netns assertions (M3).
- Type consistency: proto names in T2 == consumers in T5/T8; lock fields in T1 == T3 struct == T6 jq paths == T8 verification; helper verbs in T1 == invocations in T7/T8; `vmobs-fixture` group in T1 setup == T8 gid resolution.
