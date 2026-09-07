# aibox03 — vmobs Linux KVM host

## Host facts

- **Address:** private; named by `VMOBS_LINUX_HOST` (see below). Reached over Tailscale.
- **Hardware:** bare metal, x86_64, Intel VT-x (`kvm_intel` loaded)
- **OS:** Ubuntu 24.04.4 LTS, kernel 6.8.0-x-generic
- **Resources:** 32 vCPUs, 62 GiB RAM, ~60 GiB free on `/`
- **SSH:** key auth, `BatchMode` non-interactive
- **Go:** 1.27.0 via mise
- **Firecracker:** `v1.16.1` pinned in `runtime.lock.json`
- **KVM device:** `/dev/kvm` (root:kvm 0660); after `setup.sh`, the operator is in the `kvm` group

## Env vars

| Var | Default | Purpose |
|-----|---------|---------|
| `VMOBS_LINUX_HOST` | none — required | SSH target for `scripts/linux`, e.g. `user@host`. The script exits 3 when it is unset. |
| `VMOBS_LINUX_DIR` | `vmobs-build` | Remote working-tree path on the host |
| `VMOBS_FIXTURE` | (unset) | Set to `1` inside tests that exercise the real fixture path |

## How `scripts/linux` works

`scripts/linux '<command>'` rsyncs the working tree to `$HOST:$DEST/` (excluding `.git` and `.superpowers`; gitignored paths are excluded from transfer AND shielded from `--delete`, so build outputs such as `images/dist/` survive re-syncs), then SSH-execs `<command>` inside the remote copy. Every task in the Linux track uses it for remote compilation and testing.

## One-time setup — `scripts/aibox03/setup.sh`

**This script requires password sudo and is run by the operator, not by any automation.**

```
scripts/linux 'true'                # sync first
ssh "$VMOBS_LINUX_HOST" 'cd vmobs-build && sudo sh scripts/aibox03/setup.sh'
```

Everything the script grants — group membership, the sudoers rule, the fixture
directory owner — names the **operator**: the user who invoked `sudo`, read from
`$SUDO_USER`. The script refuses to run when that is unset, so a bare root shell
cannot silently grant the wrong account.

What it does, step by step:

1. **Installs host tools** — `jq` (used by setup.sh itself to parse `runtime.lock.json`) and `e2fsprogs` (for `mkfs.ext4` in Task 6 image builds).

2. **KVM and fixture group** — adds the operator to the `kvm` group so the jailer can open `/dev/kvm` without root. Creates group `vmobs-fixture` at fixed GID 36000. The GID is fixed (not `--system`) because the root helper validates gid arguments in the range [10000, 59999]; a `--system` group would land below 1000 and be rejected at `jail-start`.

3. **Firecracker and jailer** — reads `runtime.lock.json` from the rsynced tree, downloads the pinned tarball, verifies both binary SHA-256 hashes, installs to `/usr/local/bin/`. The lock is the single source of truth; setup.sh cannot install a version other than what is recorded there.

4. **Root helper + sudoers** — installs `vmobs-root-helper` to `/usr/local/sbin/` (root-owned, 0755) and the sudoers fragment to `/etc/sudoers.d/vmobs-fixture`, granting the operator passwordless sudo for exactly that path and nothing else. The fragment on disk carries an `__OPERATOR__` placeholder; setup.sh substitutes the real name and runs `visudo -c` on the substituted copy before installing it.

5. **Fixture directories** — creates `/srv/vmobs/fixture` (operator:vmobs-fixture 0775, operator-writable) and `/srv/vmobs/jail` (root:root 0755, root-only).

Re-login is required after setup.sh completes for group membership to take effect.

## Root-equivalence caveat (L0-R2)

The operator's existing `docker` group membership is already root-equivalent on this box, so the helper's marginal exposure is approximately zero. The narrow helper shape is still right because it is the pattern the product ships. `vmobs-root-helper` is replaced by `vmobs-privd` in M1.

## `vmobs-root-helper` — verbs

The helper is invoked via `sudo vmobs-root-helper <verb> <args>`. All arguments are validated before use; argv arrays, no shell string construction.

| Verb | Args | Purpose |
|------|------|---------|
| `net-setup <id> <cidr>` | id: `[a-z0-9-]{1,24}`, cidr: `a.b.c.d/30` | Create a network namespace + veth pair + tap device + nftables default-deny |
| `net-teardown <id>` | id validated | Delete the veth pair and network namespace |
| `jail-start <id> <uid> <gid> <cid>` | uid/gid in [10000,59999], cid in [3,65535] | Copy staging artifacts into the jail chroot and invoke jailer/firecracker |
| `jail-stop <id>` | id validated | Send SIGTERM/SIGKILL via the jailer-written PID file; remove the jail directory |

After launching the jailer, `jail-start` waits (≤10s) for firecracker to bind `v.sock`, then reopens the chroot root dir to `0750`. Jailer chmods that dir to `0700` (uid-owned) during its own chroot prep, which locks the fixture group out of the socket path; the socket bind strictly follows jailer's prep, so re-chmodding after it appears cannot be raced back to `0700`. The socket itself is group-writable via the `umask 0002` set before the jailer runs.

`jail-stop` reads the PID from `$JAIL_BASE/firecracker/<id>/root/firecracker.pid`, which is where the jailer writes it when `--daemonize` is used (per the Firecracker/jailer v1.16.1 documentation). Matching on the process title instead would be unreliable: every path under the jail carries the VM id, so `pgrep -f <id>` also matches a runner dialing that jail's `v.sock`, and a pattern that pins the flag depends on jailer's exact argv spelling (v1.16.1 passes `--id` and the id as two separate elements). The pid file is the authoritative source.

## `vmobs-privd` — the M1 privilege daemon

`vmobs-privd` replaces the M0 root helper. It runs as root via systemd, listens on a unix socket at `/run/vmobs/privd.sock`, and serves typed verbs over the wire protocol in `internal/privd`. The socket is owned `root:<operator-gid>` mode `0660`; the server enforces peer-credential uid checks on every connection.

### What it does

Handles all root-required operations the non-root runner needs: `allocate_network`, `release_network`, `start_vm`, `signal_vm`, `release_vm`. The VM uid/gid range is `[10000, 60000)` — the same policy as the old root helper.

`paths.runtime` in the daemon config must be the parent of the unit's `--stage-root` and `--jail-base` — `/srv/vmobs` on aibox03 — because the daemon derives `<runtime>/stage` and `<runtime>/jail` from that one root: a mismatched stage root makes privd refuse `start_vm` with `stage_dir not under stage root`, and a mismatched jail base makes the runner dial a `v.sock` in a chroot privd never created.

### Install / upgrade

Re-running `setup.sh` is the full upgrade path:

```
scripts/linux 'true'   # sync the latest tree to the host
ssh -t "$VMOBS_LINUX_HOST" 'cd vmobs-build && sudo sh scripts/aibox03/setup.sh'
```

setup.sh builds `cmd/vmobs-privd` on aibox03, installs the binary to `/usr/local/sbin/vmobs-privd`, writes `/etc/systemd/system/vmobs-privd.service` (with the operator's uid/gid substituted from `$SUDO_UID`/`$SUDO_GID`), and restarts the unit. The build step resolves `go` from root's PATH first; if absent, it falls back to the operator's mise-managed go under `/home/$SUDO_USER/.local/share/mise/installs/go/`.

### Health check

```
# Unit status
systemctl status vmobs-privd

# Socket permissions (should be root:<operator-gid> 0660)
ls -l /run/vmobs/privd.sock

# Live smoke (run from aibox03 as the operator user)
scripts/linux 'go test ./internal/privd/ -run TestPrivdLiveSmoke -v'
```

### One instance, enforced

`vmobs-privd` takes an exclusive `flock` on `/run/vmobs/privd.sock.lock` and on
`/run/vmobs/privd/.privd.lock` before it removes the stale socket or binds, so a
second instance refuses to start rather than unlinking a live one's socket:

```
vmobs-privd: another vmobs-privd owns the socket /run/vmobs/privd.sock: \
  lock /run/vmobs/privd.sock.lock is already held by pid 1234: \
  resource temporarily unavailable
```

That message means the named pid is alive and serving — do not delete the lock
file to get past it. The hold belongs to the open file description, so the kernel
drops it the moment that process ends, however it ends; a lock file left on disk
with nothing holding it does not block anything. Both paths sit under
`RuntimeDirectory=vmobs vmobs/privd`, which systemd removes when the unit stops.

### Caution

Agents must never restart `vmobs-privd` directly (`systemctl restart vmobs-privd` requires root). If the daemon goes down, the operator re-runs setup.sh or manually restarts via `sudo systemctl restart vmobs-privd`.

## Re-pinning Firecracker

When a new release is needed:

1. Resolve the new tag from the GitHub API: `curl -fsSL https://api.github.com/repos/firecracker-microvm/firecracker/releases/latest`.
2. Download the x86_64 tarball and its SHA256 file to a scratch dir on aibox03. Verify the tarball checksum.
3. Extract and compute `sha256sum` of the `firecracker-<ver>-x86_64` and `jailer-<ver>-x86_64` binaries.
4. Update `runtime.lock.json`: `firecracker.version`, `firecracker.release_url`, `firecracker.sha256`, `jailer.sha256`.
5. Check `docs/kernel-policy.md` in the new tagged source for the `min_kernel` host support table; update `host_support.min_kernel` if it changed.
6. Commit, then run `scripts/linux 'true'` to sync, then ask Doctor Biz to re-run `setup.sh`.

## Rebuilding the guest rootfs

`images/dist/` is build output that lives only on aibox03 — `scripts/linux`
protects it from the rsync (`--filter='P images/dist/'`), so nothing in the repo
carries the image and nothing you do locally can overwrite it. The rebuild is
the one sanctioned write there.

The image embeds `vmobs-guestd` built from the tree at rebuild time, so a guestd
change reaches a VM only through a rebuild. Package set and base image are
pinned in `images/rootfs/pins.env`.

1. Check free disk on aibox03: the build wants headroom and the live gate needs
   about 21 GB. `df -h /`.
2. `scripts/linux 'bash images/rootfs/build.sh'`. Docker only, no sudo. Runs in
   a few minutes and logs to `images/dist/logs/rootfs.log`.
3. Verify from `images/dist/rootfs.inventory.txt`, not from the build's own
   chatter: the packages the terminal needs are `bash`, `procps` (`top`),
   `ncurses-base` (terminfo) and `vim-tiny`. `grep -E '^ii +(vim-tiny|bash|procps|ncurses-base) '`.
4. Confirm the image's guestd is the one you just built:
   `images/dist/rootfs-unpacked/usr/local/bin/vmobs-guestd -h` prints its flags,
   and the binary is a host-arch executable you can run safely — it parses flags
   before it touches a config device.
5. Re-pin `runtime.lock.json`: `root_image.sha256` from
   `images/dist/rootfs.pins` (`ROOTFS_SHA256`). Change `base_image_ref` and
   `apt_snapshot` too if `pins.env` moved.
6. Boot one VM through the fixture path and confirm it reaches `running`. A
   rootfs that does not boot is a blocker, not a footnote.
7. Commit the lock change. The image itself is never committed.
