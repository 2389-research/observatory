# aibox03 — vmobs Linux KVM host

## Host facts

- **Address:** private; named by `VMOBS_LINUX_HOST` (see below). Reached over Tailscale.
- **Hardware:** bare metal, x86_64, Intel VT-x (`kvm_intel` loaded)
- **OS:** Ubuntu 24.04.4 LTS, kernel 6.8.0-x-generic
- **Resources:** 32 vCPUs, 62 GiB RAM, ~60 GiB free on `/`
- **SSH:** key auth, `BatchMode` non-interactive
- **Go:** 1.27.0 via mise — used for host-side `go build` and unit tests. The
  appliance and the gate carry their own toolchain in the image.
- **Firecracker:** `v1.16.1` pinned in `runtime.lock.json`, installed in the image
- **KVM device:** `/dev/kvm` (root:kvm 0660), passed into the container with
  `--device`. The container names the host's kvm gid for itself; no host group
  edit is needed.

## Env vars

| Var | Default | Purpose |
|-----|---------|---------|
| `VMOBS_LINUX_HOST` | none — required | SSH target for `scripts/linux`, e.g. `user@host`. The script exits 3 when it is unset. |
| `VMOBS_LINUX_DIR` | `vmobs-build` | Remote working-tree path on the host |
| `VMOBS_FIXTURE` | (unset) | Set to `1` inside the gate container to enable the root-gated tests |

## How `scripts/linux` works

`scripts/linux '<command>'` rsyncs the working tree to `$HOST:$DEST/` (excluding `.git` and `.superpowers`; gitignored paths are excluded from transfer AND shielded from `--delete`, so build outputs such as `images/dist/` survive re-syncs), then SSH-execs `<command>` inside the remote copy. Every task in the Linux track uses it for remote compilation and testing.

## One-time setup

Two things, and only the first needs root:

```
ssh -t "$VMOBS_LINUX_HOST" 'cd vmobs-build && sudo sh deploy/install-apparmor.sh'
sudo usermod -aG docker "$USER"    # if not already; re-login to take effect
```

The AppArmor step is root because Docker takes a profile by *name* and asks the
kernel for one already loaded — there is no Docker API that loads a profile, so
no compose file or script can. It is the only privileged step in the whole
install, and `apparmor_parser -r` alone does not survive a reboot: the script
also writes the profile to `/etc/apparmor.d/`.

Nothing else is installed on this host. Firecracker, the jailer, `vmobs-privd`,
the guest kernel and the root image all live inside the appliance image, and the
acceptance gate builds its own throwaway container on top of that image. There is
no host installer, no sudoers fragment and no systemd unit — a host install would
put a second privd underneath the container and quietly answer for it.

## Running the appliance

```
scripts/linux 'true'                       # sync
ssh "$VMOBS_LINUX_HOST" 'cd vmobs-build && scripts/vmobs-container up'
```

`up` fetches the guest images, runs the host preflight, builds the image from the
checkout and starts the container. `docker compose up -d` does the same against
the published image instead. `scripts/vmobs-container status` reports container
state, image revision, whether privd's socket is bound, and whether the API
answers. `deploy/README.md` explains what the container is granted and why.

## Running the acceptance gate

```
scripts/linux 'scripts/vmobs-gate'
```

The gate builds a container on the appliance image, adds a Go toolchain and the
M0 fixture's root helper, provisions the fixture group and `/srv/vmobs` tree
inside it, builds `vmobs-privd` from the mounted source and runs it, then runs
the suite as the operator's own uid. `docker run --rm` throws all of it away. See
`tests/integration/README.md`.

The gate builds privd from source on every run rather than using the image's
copy, so a privd change is always the one under test.

## Root-equivalence caveat (L0-R2)

The operator's `docker` group membership is root-equivalent on this box. The
narrow privilege shapes below are still right because they are the pattern the
product ships to hosts where that is not true.

## `vmobs-root-helper` — the M0 fixture's verbs

`tests/integration/fixture/vmobs-root-helper` is test scaffolding, not product.
It exists for the M0 boot fixture, which predates privd; the gate container
installs it to `/usr/local/sbin/` and grants the test uid passwordless sudo for
exactly that path. It is never installed on a host and the product never execs
it — `internal/privd/netops.go` ports its network verbs into privd, command for
command.

| Verb | Args | Purpose |
|------|------|---------|
| `net-setup <id> <cidr>` | id: `[a-z0-9-]{1,24}`, cidr: `a.b.c.d/30` | Create a network namespace + veth pair + tap device + nftables default-deny |
| `net-teardown <id>` | id validated | Delete the veth pair and network namespace |
| `jail-start <id> <uid> <gid> <cid>` | uid/gid in [10000,59999], cid in [3,65535] | Copy staging artifacts into the jail chroot and invoke jailer/firecracker |
| `jail-stop <id>` | id validated | Send SIGTERM/SIGKILL via the jailer-written PID file; remove the jail directory |

The gid range matters: `vmobs-fixture` is created at a fixed gid 36000 because
the helper validates gid arguments in [10000, 59999]. A `--system` group would
land below 1000 and be rejected at `jail-start`.

After launching the jailer, `jail-start` waits (≤10s) for firecracker to bind `v.sock`, then reopens the chroot root dir to `0750`. Jailer chmods that dir to `0700` (uid-owned) during its own chroot prep, which locks the fixture group out of the socket path; the socket bind strictly follows jailer's prep, so re-chmodding after it appears cannot be raced back to `0700`. The socket itself is group-writable via the `umask 0002` set before the jailer runs.

`jail-stop` reads the PID from `$JAIL_BASE/firecracker/<id>/root/firecracker.pid`, which is where the jailer writes it when `--daemonize` is used (per the Firecracker/jailer v1.16.1 documentation). Matching on the process title instead would be unreliable: every path under the jail carries the VM id, so `pgrep -f <id>` also matches a runner dialing that jail's `v.sock`, and a pattern that pins the flag depends on jailer's exact argv spelling (v1.16.1 passes `--id` and the id as two separate elements). The pid file is the authoritative source.

## `vmobs-privd` — the privilege daemon

`vmobs-privd` is the product's answer to the root helper. It runs as root inside
the appliance container, started by `deploy/entrypoint.sh` before the daemon,
listens on a unix socket at `/run/vmobs/privd.sock`, and serves typed verbs over
the wire protocol in `internal/privd`. The socket is owned `root:<daemon gid>`
mode `0660`; the server enforces peer-credential uid checks on every connection.

`/run` is a container tmpfs, so that socket exists only inside the container. It
is not visible on the host and there is nothing on the host to point a client at.

### What it does

Handles all root-required operations the non-root runner needs: `allocate_network`, `release_network`, `start_vm`, `signal_vm`, `release_vm`. The VM uid/gid range is `[10000, 60000)` — the same policy as the old root helper.

`paths.runtime` in the daemon config must be the parent of privd's `--stage-root` and `--jail-base` — `/srv/vmobs` in the image — because the daemon derives `<runtime>/stage` and `<runtime>/jail` from that one root: a mismatched stage root makes privd refuse `start_vm` with `stage_dir not under stage root`, and a mismatched jail base makes the runner dial a `v.sock` in a chroot privd never created.

### Upgrade

A privd change reaches the host by rebuilding the image:

```
scripts/linux 'true'
ssh "$VMOBS_LINUX_HOST" 'cd vmobs-build && scripts/vmobs-container stop && scripts/vmobs-container up'
```

Or `docker compose pull && docker compose up -d` to take the published image.
Either way the running privd is replaced with the container, never underneath it.

### Health check

```
scripts/vmobs-container status         # unit state, revision, socket, API
scripts/vmobs-container logs           # privd's startup probe names any missing flag
scripts/vmobs-gate go test ./internal/privd/ -run TestPrivdLiveSmoke -v
```

The live smoke test needs a privd to talk to, and the gate container starts one.

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
with nothing holding it does not block anything. Both paths are on the container's
`/run` tmpfs, which the container's death takes with it.

### Caution

Do not restart privd inside a running container. The entrypoint ends the
container when either process exits, on purpose: a live daemon with a dead privd
serves an API that refuses every launch, which reads as a vmobs bug. Restart the
container instead.

## Re-pinning Firecracker

When a new release is needed:

1. Resolve the new tag from the GitHub API: `curl -fsSL https://api.github.com/repos/firecracker-microvm/firecracker/releases/latest`.
2. Download the x86_64 tarball and its SHA256 file to a scratch dir on aibox03. Verify the tarball checksum.
3. Extract and compute `sha256sum` of the `firecracker-<ver>-x86_64` and `jailer-<ver>-x86_64` binaries.
4. Update `runtime.lock.json`: `firecracker.version`, `firecracker.release_url`, `firecracker.sha256`, `jailer.sha256`.
5. Check `docs/kernel-policy.md` in the new tagged source for the `min_kernel` host support table; update `host_support.min_kernel` if it changed.
6. Commit, sync, and rebuild the image: `scripts/vmobs-container build`. The
   Dockerfile reads the lock and verifies both hashes, so a wrong hash fails the
   build rather than shipping.

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
6. Boot one VM through the gate's fixture path and confirm it reaches `running`.
   A rootfs that does not boot is a blocker, not a footnote.
7. Commit the lock change. The image itself is never committed.
