# Running vmobs in a container

`vmobs` launches Firecracker microVMs. That is a privileged job on any host, and
a container does not change it: the same three kernel gates apply, and the
container has to be given the same three things a bare-metal install has. This
directory holds the narrow profiles that grant exactly those and nothing more,
plus the image that carries the pinned binaries.

Everything here runs from a checkout:

    scripts/vmobs-container build
    scripts/vmobs-container start
    scripts/vmobs-container status
    scripts/vmobs-container logs -f
    scripts/vmobs-container stop

There is no installer. Nothing in `start` writes to the host outside Docker's
own storage; the single root step is installing the AppArmor profile, below, and
you run it yourself.

## Host prerequisites

| Requirement | Why | Check |
| --- | --- | --- |
| Linux with KVM | Firecracker is a KVM VMM | `test -c /dev/kvm` |
| `/dev/net/tun` | one tap device per VM | `test -c /dev/net/tun`, else `modprobe tun` |
| Docker with AppArmor enabled | the profile below has to load | `docker info \| grep apparmor` |
| x86-64 | the lock pins `firecracker-<ver>-x86_64` | `uname -m` |
| The guest kernel and root image | baked into the image | `ls images/dist/` |

`scripts/vmobs-container start` checks the first two and refuses with the fix
named. It does not check the rest, because Docker's own error is clearer.

### The guest images

`images/dist/vmlinux` and `images/dist/rootfs.ext4` are not in the checkout —
they are built, and their digests are pinned in `runtime.lock.json`:

    bash images/build-all.sh

That needs Docker and a kernel build toolchain, and it takes a while. The
appliance build copies both into the image and verifies all four pinned digests
(firecracker, jailer, kernel, root image) in the final stage, so a build that
succeeds cannot be shipping bytes nobody pinned.

### The AppArmor profile — the one root command

    sudo sh deploy/install-apparmor.sh

Once per host, and again whenever `deploy/apparmor/vmobs-jailer` changes.

It installs the profile to `/etc/apparmor.d/vmobs-jailer` and then loads it.
Both halves matter: `apparmor_parser` alone loads a profile into the running
kernel and leaves nothing on disk, so after a reboot the host has no
`vmobs-jailer` and `docker run --security-opt apparmor=vmobs-jailer` fails
outright. Installing it under `/etc/apparmor.d` is what makes the host load it
at boot.

`start` refuses before it runs anything if the profile is missing from
`/etc/apparmor.d` or differs from the copy in this repo, and names this script.
It compares those two files because what the kernel actually holds is not
readable without root: `/sys/kernel/security/apparmor/profiles` is `0444`
root-only. A stale profile is the failure worth catching — docker accepts any
loaded profile by name, so the container starts cleanly and the difference
surfaces minutes later as a denied mount in the middle of a launch.

The profile is Docker's own `docker-default` template with one substitution.
`docker-default` carries a blanket `deny mount,`, and an AppArmor `deny`
overrides every allow regardless of order, so no amount of capability grants
gets past it. In its place:

    umount,
    mount options=(rw, rslave) -> /,
    mount options=(rw, rprivate) -> /,
    mount options=(rw, rbind) /srv/vmobs/jail/** -> /srv/vmobs/jail/**,
    mount options=(rw, rshared) -> /run/netns/,
    mount options=(rw, bind) /run/netns/ -> /run/netns/,
    mount options=(rw, rbind) /run/netns/ -> /run/netns/,
    mount options=(rw, bind) -> /run/netns/*,
    mount fstype=sysfs -> /sys/,
    pivot_root /srv/vmobs/jail/firecracker/*/root/,

Every other mount stays denied. The list grew from three rules to these because
it was first traced from the jailer alone, and the container runs more than the
jailer: privd's own exec makes `/` rprivate, and `ip netns add` and `ip netns
exec` account for the five `/run/netns` and `/sys` rules between them. Each one
was added against a measured denial, recorded in
`docs/design/container-boundary.md` §10 and pinned by `tests/deploy/profiles_test.go`.

## What `start` passes, and why

    --init                     reap the daemonized VMMs
    --network host             the API binds loopback; see below
    --cap-add SYS_ADMIN        setns, and the jailer's mounts
    --cap-add NET_ADMIN        tap and veth
    --device /dev/kvm          the VMM
    --device /dev/net/tun      the tap devices
    --security-opt apparmor=vmobs-jailer
    --security-opt seccomp=deploy/seccomp/vmobs-jailer.json
    --tmpfs /run               privd's ledger lives for one privd
    -v vmobs-state:/var/lib/vmobs
    -v vmobs-runtime:/srv/vmobs

The three gates, in the order the kernel applies them, are measured in
`docs/design/container-boundary.md` §5. Short version:

- **Capabilities.** `CAP_SYS_ADMIN` for `setns` and the jailer's mount work,
  `CAP_NET_ADMIN` plus `/dev/net/tun` for the tap and veth pair.
- **AppArmor.** `docker-default` denies `mount` outright; the profile above
  replaces that with the three rules the jailer needs.
- **Seccomp.** Docker's default profile does not list `pivot_root` in any allow
  group, so it returns EPERM even with `CAP_SYS_ADMIN`.
  `deploy/seccomp/vmobs-jailer.json` is Docker's default with `pivot_root`
  added to the group already gated on `CAP_SYS_ADMIN` — the group that carries
  `mount`, `setns`, `unshare` and `move_mount`. Nothing else differs.

`vmobs-privd` measures all three at startup, in a throwaway mount and network
namespace, before it binds its socket. A container missing one of these flags
dies immediately naming the flag, instead of failing four stages into a launch
after admission, network allocation and staging — which reads like a bug in
vmobs and is not one.

### `/dev/kvm`, and the `--group-add` that is not here

The container sees the node as `crw-rw---- root:<kvm gid>`, so the obvious flag
is `--group-add <kvm gid>`. It is not in the run line, for two separate reasons.

Firecracker does not need it. The jailer `mknod`s its own `dev/kvm` inside the
chroot while it is still root, chowns it to the jail uid, and only then drops
privilege — so the VMM opens a node it owns, holding no supplementary groups at
all. The host's `kvm` group never enters the picture.

`vmobsd` does need the group, for the `arch_kvm` preflight that opens the
container's node before any VM exists — and `--group-add` cannot deliver it.
The entrypoint drops to the `vmobs` user with `setpriv --init-groups`, which
rebuilds the supplementary set from `/etc/group` and discards whatever docker
granted. So `deploy/entrypoint.sh` reads the gid off the device node it was
given and adds `vmobs` to that group inside the container, where the rebuild
finds it. The gid differs between hosts; nothing hardcodes it.

Measured in `docs/design/container-boundary.md` §10.

### `--init`

The jailer daemonizes each Firecracker, so every VMM reparents to PID 1. With no
reaper they stay as zombies, and a zombie answers `kill(pid, 0)` — the runtime's
liveness check would call a dead VM alive.

### `--network host`, and what it costs

`server.mode: loopback_only` means the API binds `127.0.0.1` and is reachable
only from this host; `config.Validate` refuses a non-loopback bind in that mode,
and refuses to serve beyond loopback without TLS and authentication. Publishing
a port from a bridge network would put an unauthenticated API on the host's
external interfaces, so the container shares the host's network namespace
instead and the mode's promise stays literally true.

The cost, stated plainly: each VM's `veth-<id>` and its network namespace are
created in the host's network namespace, not in one of the container's own. They
are the same interfaces a bare-metal install creates, cleaned up by the same
stop path, but `docker rm` is not what removes them — a VM deleted through the
API is. Stopping the container with VMs still running leaves their interfaces
behind; delete the VMs first.

## Two processes in one container

`vmobs-privd` runs as root and holds the capabilities that launch a VM.
`vmobsd` — the process that talks to the network — runs as uid 2389 and has
none of them. That split is the product's security boundary, so the entrypoint
starts both rather than collapsing them to satisfy a one-process-per-container
convention.

`deploy/entrypoint.sh` exits as soon as either one does. A live daemon with a
dead privd serves an API that refuses every launch.

## State

Two volumes, and they hold different things:

- `vmobs-state` → `/var/lib/vmobs`: the SQLite database, artifacts, the
  credential store. This is the data worth keeping.
- `vmobs-runtime` → `/srv/vmobs`: staging directories and the jailer's chroots.
  Scratch, recreated per VM.

`/run` is a tmpfs on purpose. privd's ledger records which jail uid, guest CID
and subnet each VM holds, and its lifetime is one privd instance — the same
thing systemd's `RuntimeDirectory=` gives it on bare metal. An entry that
outlived its privd would hold a slot no VM is using and the next launch would be
refused as a collision, so the entrypoint clears it at start too.

`stop` keeps both volumes. To discard them:

    docker volume rm vmobs-state vmobs-runtime

## Authentication

The shipped config runs with `require_authentication: false`, which is legal
only because the API is loopback-bound: the boundary is the host ACL. To require
a credential, mount a config with `auth.require_authentication: true` and mint
the first operator:

    scripts/vmobs-container init-auth -username local_operator -password-stdin

## Your own config

The image never rewrites `/etc/vmobs/config.yaml`. Mount yours over it:

    docker run ... -v /path/to/config.yaml:/etc/vmobs/config.yaml:ro ...

Keep the paths: `/opt/vmobs/runtime.lock.json`, `/run/vmobs/privd.sock`,
`/var/lib/vmobs`, `/srv/vmobs`, `/etc/vmobs/templates` are where the image puts
things.

## Provenance

The image records the revision it was built from at `/opt/vmobs/SOURCE_REVISION`
and in the `org.opencontainers.image.revision` label; `status` prints it. A
build from a dirty tree is tagged and labelled `-dirty`, because an image built
from uncommitted work must not claim a commit.

Both base images are pinned by digest. The runtime base is the same Ubuntu
digest `runtime.lock.json` pins for the guest root image.

## When it does not work

`scripts/vmobs-container logs` first — privd's probe failure names the missing
flag. Then:

| Symptom | Cause |
| --- | --- |
| `profile "vmobs-jailer" not found` | load the profile: `sudo apparmor_parser -r -W deploy/apparmor/vmobs-jailer` |
| probe fails at `pivot_root` with EPERM | the seccomp profile is not being passed |
| probe fails at any step with EACCES | the AppArmor profile is not being applied |
| probe fails at `tap_create` with ENOENT | `--device /dev/net/tun` missing, or the module is not loaded |
| probe fails with EPERM elsewhere | `--cap-add SYS_ADMIN` missing |
| launches fail as a slot collision | a stale ledger; `/run` must be a tmpfs |
