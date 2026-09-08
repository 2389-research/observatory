# Running vmobs in a container

`vmobs` launches Firecracker microVMs. That is a privileged job on any host, and
a container does not change it: the same three kernel gates apply, and the
container has to be given the same three things a bare-metal install has. This
directory holds the narrow profiles that grant exactly those and nothing more,
plus the image that carries the pinned binaries.

On a host with the prerequisites below:

    docker compose up -d

`compose.yaml` at the repository root carries the runtime boundary and a
short-lived `apparmor` service. That service loads the bundled profile into the
shared host kernel; the appliance depends on its successful completion. Docker
then applies that profile by name to the appliance.

`scripts/vmobs-container up` does the same thing with checks in front of it. It
downloads the guest images, tests `/dev/kvm` and `/dev/net/tun`, builds from the
checkout, and uses the same Compose loader. Prefer it for local builds; Compose
uses the published appliance image.

Afterwards, either way:

    scripts/vmobs-container status
    scripts/vmobs-container logs -f
    scripts/vmobs-container stop

`compose.yaml` and the script start the same container under the same name and
the same volumes, and `tests/deploy/compose_test.go` fails if the two ever grant
different things. `build` and `start` are still there as separate verbs; `up` is
the two of them with the prerequisite checks moved to the front, where a missing
one costs you seconds instead of a finished image.

No host packages, systemd units, sudoers entries or `/etc/apparmor.d` files are
installed. The loader does change shared-kernel AppArmor policy, and the runtime
creates host network interfaces as described below.

### Starting without the profile

`VMOBS_APPARMOR_PROFILE=unconfined` is an explicit development-only override.
The wrappers skip policy loading for this override. The supported default
loads `vmobs-jailer`; the loader does not manage arbitrary profile names.

It is worth being plain about what that costs. This container holds
`CAP_SYS_ADMIN` and a seccomp profile that deliberately permits `mount`,
`pivot_root`, `setns` and `unshare`, because the jailer needs all four. AppArmor
is the only remaining layer that bounds *where* those mounts can land.
`docs/design/container-boundary.md` §9 asked whether a container with
`CAP_SYS_ADMIN` and no mount confinement is a boundary worth having, and the
answer that got built was the narrow profiles. Use `unconfined` to get a look at
the thing; do not run anything you care about behind it.

## Host prerequisites

| Requirement | Why | Check |
| --- | --- | --- |
| Linux with KVM | Firecracker is a KVM VMM | `test -c /dev/kvm` |
| `/dev/net/tun` | one tap device per VM | `test -c /dev/net/tun`, else `modprobe tun` |
| Docker with Compose and AppArmor enabled | Compose loads the profile before starting the appliance | `docker compose version` and `docker info \| grep apparmor` |
| x86-64 | the lock pins `firecracker-<ver>-x86_64` | `uname -m` |
| The guest kernel and root image | baked into the image | `ls images/dist/` |

`scripts/vmobs-container up` checks the devices before building. Policy loading
must then succeed before the confined appliance starts. For a failed Compose
startup, inspect `docker compose logs apparmor`; wrappers print loader failures
in their command output.

### The guest images

`images/dist/vmlinux` and `images/dist/rootfs.ext4` are not in the checkout.
`runtime.lock.json` pins their sha256s and, once they have been published, the
URLs to fetch them from:

    scripts/fetch-guest-images

`up` runs that for you. It downloads each artifact, checks it against its pin,
and refuses to leave an unverified file behind. A file already on disk that
matches its pin is left alone, so re-running it costs one hash.

If nothing has been published yet, the lock names no URL and the fetch says so,
pointing at the source build:

    bash images/build-all.sh

That compiles the guest kernel in a pinned container and debootstraps the root
image. It needs Docker, and it takes a while. It checks what it produced against
the pins in `runtime.lock.json` and fails if they disagree — the lock is an
input, not a build output. To move the pins deliberately, `--repin` rewrites them
and you commit the result.

Whoever has write access to the repository publishes a built set once:

    scripts/publish-guest-images --tag guest-images-6.1.186

That uploads both artifacts to a GitHub release, refuses if they do not match the
digests the lock pins, and writes the resulting download URLs back into
`runtime.lock.json` for you to commit. After that nobody else compiles a kernel.

The appliance build copies both into the image and verifies all four pinned
digests (firecracker, jailer, kernel, root image) in the final stage, so a build
that succeeds cannot be shipping bytes nobody pinned.

### The AppArmor loader

The approved design uses the same appliance image for `apparmor` and `vmobs`.
The image contains the parser and the profile from `deploy/apparmor/vmobs-jailer`.
The setup service invokes `apparmor_parser --replace --skip-cache` directly on that
bundled profile. It replaces policy in the running kernel without writing host
configuration or parser cache files.

The setup service drops all capabilities and adds only `MAC_ADMIN`. It runs
with `apparmor=unconfined`, no network, a read-only image filesystem, and a
read-write bind of `/sys/kernel/security`. It has no Docker socket or host root
mount. That authority belongs only to the short-lived loader: the appliance
keeps its narrow AppArmor and seccomp profiles and existing capabilities.

Use `docker compose up -d` for startup, including after a host reboot. The
design reloads the bundled policy before the appliance starts, even when the
kernel has lost the profile. `docker start` and `docker restart` do not run
Compose dependencies and cannot reload it. The loader's capability boundary
and repeated-start behavior require the Linux measurements recorded in
`docs/design/container-boundary.md`; this section describes the approved design.

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

    --network host             the API binds loopback; see below
    --pid host                 recover VMM ownership across container restarts
    --cap-add SYS_ADMIN        setns, and the jailer's mounts
    --cap-add NET_ADMIN        tap and veth
    --device /dev/kvm          the VMM
    --device /dev/net/tun      the tap devices
    --security-opt apparmor=vmobs-jailer
    --security-opt seccomp=deploy/seccomp/vmobs-jailer.json
    --tmpfs /run               ephemeral sockets and network-namespace mounts
    -v vmobs-state:/var/lib/vmobs
    -v vmobs-runtime:/srv/vmobs # chroots, staging and privd's durable ledger

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

### `--pid host`

The jailer daemonizes each Firecracker. Sharing the host PID namespace lets the
host's PID 1 reap those VMMs and lets a replacement privd inspect the same
process identities after a container restart. Compose and the development
wrappers therefore use host PID visibility and do not add a container init
process.

This expands the container's view: processes elsewhere on the host become
visible by PID. It does not change the appliance's AppArmor profile, seccomp
profile, capabilities or device grants. privd still authorizes signaling from
its root-owned ledger; visibility alone grants no VM ownership.

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
- `vmobs-runtime` → `/srv/vmobs`: staging directories, jailer chroots and
  privd's root-owned ledger at `/srv/vmobs/privd`. The ledger directory is mode
  `0700` and survives container restarts with the resources it authorizes.

Each VM ledger record binds the VM allocation to the host kernel boot and PID
namespace in which its VMM was created. A replacement privd may signal a
recorded PID only when those identities still match. A host reboot makes the
record stale without risking a signal to an unrelated process; unreadable or
ambiguous ownership fails closed and keeps the allocation reserved for
operator review.

The durable ledger prevents future restart loss. It does not import legacy
chroots whose old `/run` ledger has already disappeared, because their files
cannot establish trusted process ownership. Resolve those unknown resources
before reusing their allocations; do not create ledger records from manifests
or jail pidfiles.

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
| `profile "vmobs-jailer" not found` | inspect `docker compose logs apparmor`, check the AppArmor-enabled host prerequisites, then retry `docker compose up -d` |
| probe fails at `pivot_root` with EPERM | the seccomp profile is not being passed |
| probe fails at any step with EACCES | the AppArmor profile is not being applied |
| probe fails at `tap_create` with ENOENT | `--device /dev/net/tun` missing, or the module is not loaded |
| probe fails with EPERM elsewhere | `--cap-add SYS_ADMIN` missing |
| launches fail as a slot collision | inspect `/srv/vmobs/privd`; do not delete a record while its resources may exist |
