# aibox03 — vmobs Linux KVM host

## Host facts

- **Address:** `harper@100.64.0.100` (Tailscale)
- **Hardware:** bare metal, x86_64, Intel VT-x (`kvm_intel` loaded)
- **OS:** Ubuntu 24.04.4 LTS, kernel 6.8.0-x-generic
- **Resources:** 32 vCPUs, 62 GiB RAM, ~60 GiB free on `/`
- **SSH:** key auth, `BatchMode` non-interactive
- **Go:** 1.27.0 via mise
- **Firecracker:** `v1.16.1` pinned in `runtime.lock.json`
- **KVM device:** `/dev/kvm` (root:kvm 0660); after `setup.sh`, harper is in the `kvm` group

## Env vars

| Var | Default | Purpose |
|-----|---------|---------|
| `VMOBS_LINUX_HOST` | `harper@100.64.0.100` | Override the SSH target for `scripts/linux` |
| `VMOBS_LINUX_DIR` | `vmobs-build` | Remote working-tree path on the host |
| `VMOBS_FIXTURE` | (unset) | Set to `1` inside tests that exercise the real fixture path |

## How `scripts/linux` works

`scripts/linux '<command>'` rsyncs the working tree to `$HOST:$DEST/` (excluding `.git` and `.superpowers`; gitignored paths are excluded from transfer AND shielded from `--delete`, so build outputs such as `images/dist/` survive re-syncs), then SSH-execs `<command>` inside the remote copy. Every task in the Linux track uses it for remote compilation and testing.

## One-time setup — `scripts/aibox03/setup.sh`

**This script requires password sudo and is run by the operator, not by any automation.**

```
scripts/linux 'true'   # sync first
ssh harper@100.64.0.100 'cd vmobs-build && sudo sh scripts/aibox03/setup.sh'
```

What it does, step by step:

1. **Installs host tools** — `jq` (used by setup.sh itself to parse `runtime.lock.json`) and `e2fsprogs` (for `mkfs.ext4` in Task 6 image builds).

2. **KVM and fixture group** — adds `harper` to the `kvm` group so the jailer can open `/dev/kvm` without root. Creates group `vmobs-fixture` at fixed GID 36000. The GID is fixed (not `--system`) because the root helper validates gid arguments in the range [10000, 59999]; a `--system` group would land below 1000 and be rejected at `jail-start`.

3. **Firecracker and jailer** — reads `runtime.lock.json` from the rsynced tree, downloads the pinned tarball, verifies both binary SHA-256 hashes, installs to `/usr/local/bin/`. The lock is the single source of truth; setup.sh cannot install a version other than what is recorded there.

4. **Root helper + sudoers** — installs `vmobs-root-helper` to `/usr/local/sbin/` (root-owned, 0755) and the sudoers fragment to `/etc/sudoers.d/vmobs-fixture`, granting `harper` passwordless sudo for exactly that path and nothing else. Runs `visudo -c` to verify the fragment before returning.

5. **Fixture directories** — creates `/srv/vmobs/fixture` (harper:vmobs-fixture 0775, harper-writable) and `/srv/vmobs/jail` (root:root 0755, root-only).

Re-login is required after setup.sh completes for group membership to take effect.

## Root-equivalence caveat (L0-R2)

harper's existing `docker` group membership is already root-equivalent on this box, so the helper's marginal exposure is approximately zero. The narrow helper shape is still right because it is the pattern the product ships. `vmobs-root-helper` is replaced by `vmobs-privd` in M1.

## `vmobs-root-helper` — verbs

The helper is invoked via `sudo vmobs-root-helper <verb> <args>`. All arguments are validated before use; argv arrays, no shell string construction.

| Verb | Args | Purpose |
|------|------|---------|
| `net-setup <id> <cidr>` | id: `[a-z0-9-]{1,24}`, cidr: `a.b.c.d/30` | Create a network namespace + veth pair + tap device + nftables default-deny |
| `net-teardown <id>` | id validated | Delete the veth pair and network namespace |
| `jail-start <id> <uid> <gid> <cid>` | uid/gid in [10000,59999], cid in [3,65535] | Copy staging artifacts into the jail chroot and invoke jailer/firecracker |
| `jail-stop <id>` | id validated | Send SIGTERM/SIGKILL via the jailer-written PID file; remove the jail directory |

`jail-stop` reads the PID from `$JAIL_BASE/firecracker/<id>/root/firecracker.pid`, which is where the jailer writes it when `--daemonize` is used (per the Firecracker/jailer v1.16.1 documentation). The process title is `firecracker --id=<id> ...` (using `=`, not space), so pgrep string matching is unreliable; the pid file is the authoritative source.

## Re-pinning Firecracker

When a new release is needed:

1. Resolve the new tag from the GitHub API: `curl -fsSL https://api.github.com/repos/firecracker-microvm/firecracker/releases/latest`.
2. Download the x86_64 tarball and its SHA256 file to a scratch dir on aibox03. Verify the tarball checksum.
3. Extract and compute `sha256sum` of the `firecracker-<ver>-x86_64` and `jailer-<ver>-x86_64` binaries.
4. Update `runtime.lock.json`: `firecracker.version`, `firecracker.release_url`, `firecracker.sha256`, `jailer.sha256`.
5. Check `docs/kernel-policy.md` in the new tagged source for the `min_kernel` host support table; update `host_support.min_kernel` if it changed.
6. Commit, then run `scripts/linux 'true'` to sync, then ask Doctor Biz to re-run `setup.sh`.
