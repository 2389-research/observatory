<!-- ABOUTME: Every privileged operation v2's launch chain performs, what each needs from the kernel, -->
<!-- ABOUTME: and the measured delta against Docker's defaults. A review artifact, not a shipping profile. -->

# Container Boundary: what v2's chain asks of the kernel

## 0. What this is

Kata `q4b2` asks whether `vmobs` can run inside a container, and says the
answer waits on a device/cgroup/security review with Doctor Biz. This is the
document that review needs and did not exist: the privileged surface named
operation by operation, each requirement traced to v2's own code or measured
on aibox03, set against what Docker actually grants.

Nothing in sections 1-9 is a decision. When they were written there was no
Dockerfile, no compose file and no shipping profile, deliberately — the kata
says diagnostic permissions must not be promoted into shipping configuration
without review, and a document is the thing that gets reviewed.

The review chose option 4 (§8), and §10 records what the build measured. Where
§10 and an earlier section disagree, §10 is what a machine did and the earlier
section is what someone expected it to do; §10 wins and says so.

The Compose loader design in §11 supersedes §10's final host-installer remedy.
The earlier measurements remain evidence of the runtime boundary, not evidence
that the loader has passed its separate Linux checks.

## 1. Method, and why it is the part that matters

v1 has a plan doc with container measurements
(`../observatory/docs/superpowers/plans/2026-09-05-docker-runtime.md`). Its
numbers are real and they are **not transferable**. v1 ran Firecracker
directly; v2 runs it under the jailer, inside a per-VM network namespace,
behind a privileged daemon. v1's own doc says its passing test "did not
validate guest authentication, jailer isolation, TAP/network namespaces, the
helper, restart recovery, or AT-002", and that "neither NET_ADMIN nor
`/dev/net/tun` was added here". Those are exactly the halves v2 depends on.

So every requirement below is read out of v2's code (cited by file and line)
or measured on aibox03 (2026-09-06, Docker 27.2.1, kernel 6.8.0-138-generic,
Ubuntu 24.04.4, cgroup v2, AppArmor enabled, jailer/Firecracker v1.16.1).
Requirements inherited from v1 and not checked here are marked as such, and
two of them turned out to be wrong — see §6.

Every probe ran `--rm --network none` in a throwaway container from a
throwaway image, both removed afterwards; each run reports that it left no
containers behind and the probe images were deleted. Nothing was installed on
the host and no host namespace, cgroup or device was modified.

## 2. The privileged surface

privd serves five verbs, each executed as root. This is what each one does.

| Verb | Operation | Kernel facility | Needs |
|---|---|---|---|
| `allocate_network` | `ip netns add vmobs-<id>` | new net namespace + bind-mount at `/run/netns/<name>` | `CAP_SYS_ADMIN` (for the mount, not the namespace) |
| | `ip netns exec … ip tuntap add dev tap0 mode tap` | `/dev/net/tun` + `TUNSETIFF` | `CAP_NET_ADMIN` + the tun device node |
| | `ip link add veth-<id> type veth peer name eth-up netns …` | rtnetlink `RTM_NEWLINK` | `CAP_NET_ADMIN` |
| | `ip netns exec … nft -f -` (default-deny table) | nfnetlink | `CAP_NET_ADMIN` |
| `release_network` | `ip link del`, `ip netns del` | as above + unmount | `CAP_NET_ADMIN`, `CAP_SYS_ADMIN` |
| `start_vm` | `jailer --netns /var/run/netns/vmobs-<id>` | `setns(CLONE_NEWNET)` | `CAP_SYS_ADMIN` |
| | jailer mount propagation | `mount --make-slave /` | `CAP_SYS_ADMIN` **and** an AppArmor mount exception |
| | jailer chroot | `pivot_root(2)` | `CAP_SYS_ADMIN` **and** a seccomp exception |
| | jailer drops privilege | `setuid`/`setgid` to the jail uid | `CAP_SETUID`, `CAP_SETGID` |
| | firecracker | `/dev/kvm` | a kvm node the **jailed** uid owns — the jailer makes its own inside the chroot (§10) |
| `signal_vm` | `pidfd_open` + `kill` across a uid boundary | — | `CAP_KILL` |
| `release_vm` | `RemoveAll` of the jail dir | — | root in the mount namespace |

Sources: `internal/privd/netops.go:203-212` (the verb sequence verbatim),
`internal/privd/vmops.go:310-323` (the jailer argv),
`internal/privd/vmops.go:659-697` (signal and release),
the `net-setup` and `jail-start` verbs of
`tests/integration/fixture/vmobs-root-helper` (the same sequence in the
sudo-gated M0 helper).

**The guest channel needs no device.** `internal/runner/runner.go:52` and
`:226` dial a **unix socket** — `<JailBase>/firecracker/<id>/root/v.sock` —
not `/dev/vhost-vsock`. Firecracker implements virtio-vsock in userspace over
a UDS. `/dev/vhost-vsock` exists on aibox03 and v2 never opens it. A container
profile that passes it through would be granting a device for nothing.

## 3. What Docker grants by default

Measured inside a default container on aibox03:

```
CapPrm/CapEff/CapBnd: 00000000a80425fb
/sys/fs/cgroup:       ro,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot (cgroup2)
Seccomp:              2   (SECCOMP_MODE_FILTER — the default profile is loaded)
/dev/kvm:             absent
/dev/net/tun:         absent
```

Decoding the mask gives 14 capabilities: CHOWN, DAC_OVERRIDE, FOWNER, FSETID,
KILL, SETGID, SETUID, SETPCAP, NET_BIND_SERVICE, NET_RAW, SYS_CHROOT, MKNOD,
AUDIT_WRITE, SETFCAP.

Against §2 that lands well: `CAP_SETUID`, `CAP_SETGID` and `CAP_KILL` — what
the jailer's privilege drop and `signal_vm` need — are already granted.
`CAP_NET_ADMIN` and `CAP_SYS_ADMIN` are withheld, and both devices are absent.

## 4. The measured matrix

Each cell is one command from §2 run in a container. `netns` is `ip netns
add`; `tap` is `ip tuntap add … mode tap`; `veth` is the veth pair; `nft` is
the helper's exact default-deny ruleset; `jailer` is v2's argv from
`vmops.go:313-323` with `--netns` pointed at the container's own namespace so
the network half is not the variable, and firecracker asked for `--version` so
that reaching exec is unambiguous.

| Profile | netns | tap | veth | nft | jailer |
|---|---|---|---|---|---|
| **A** default | ✗ EPERM | ✗ ENOENT | ✗ EPERM | ✗ EPERM | — |
| **F** default + `/dev/kvm` | — | — | — | — | ✗ `SetNetNs` EPERM |
| **B** `+NET_ADMIN +/dev/net/tun` | ✗ EPERM | ✓ | ✓ | ✓ | — |
| **C** B `+SYS_ADMIN` | ✗ EACCES | ✓ | ✓ | ✓ | ✗ `MountPropagationSlave` EACCES |
| **G** C + `seccomp=unconfined` | — | — | — | — | ✗ `MountPropagationSlave` EACCES |
| **D** C + `apparmor=unconfined` | ✓ | ✓ | ✓ | ✓ | ✗ `PivotRoot` EPERM |
| **H** C + both unconfined | ✓ | ✓ | ✓ | ✓ | **✓ exit 0, `Firecracker v1.16.1`** |
| **I** `--privileged` | ✓ | ✓ | ✓ | ✓ | ✓ exit 0 |

Profile H is the narrowest measured profile that runs v2's real jailer to
completion, and it matches `--privileged` on every cell.

## 5. The three gates, in the order the kernel applies them

The matrix isolates each gate because the jailer fails at a different step in
each profile, and the step names the gate.

1. **Capabilities.** Profile F, default caps, dies at `SetNetNs` — joining a
   namespace needs `CAP_SYS_ADMIN`. Profile B shows the network verbs are a
   separate axis: `CAP_NET_ADMIN` plus `/dev/net/tun` buys tap, veth and nft,
   and buys nothing toward `ip netns add`, which fails on its bind-mount.
2. **AppArmor.** Profile G lifts seccomp entirely and still dies at
   `mount --make-slave` with EACCES. `docker-default`'s blanket mount denial
   is the cause, and no capability defeats it. This is the same wall v1
   measured against systemd, reached here by a different road.
3. **Seccomp.** Profile D lifts AppArmor and dies at `pivot_root` with EPERM
   while seccomp is loaded; profile H lifts seccomp and the same call
   succeeds. Docker's default seccomp profile blocks `pivot_root`, so **the
   jailer cannot run under it at any capability level.**

Neither exception alone is sufficient. That is the finding: v1's passing
container profile needed one exception; v2's chain needs two, and the second
one is invisible until you run the jailer, which v1 never did.

## 6. Two inherited assumptions that are wrong for v2

Both would have gone into this document unchallenged if v1's numbers had been
copied instead of re-measured.

- **The cgroup mount is not a blocker.** `/sys/fs/cgroup` is read-only in
  every profile including H, and the jailer exits 0 anyway, creating no cgroup
  directory. With v2's argv — `--cgroup-version 2` and no `--cgroup` or
  `--parent-cgroup` (`vmops.go:319`) — no cgroup write is attempted. v1's
  blocker was systemd needing `/init.scope`, and v2 runs no systemd in the
  container. **This changes if anyone adds `--cgroup` limits later**, which is
  a plausible thing to want; it would reintroduce the requirement and should
  be treated as a boundary change, not a tuning change.
- **`/dev/vhost-vsock` is not needed.** See §2.

## 7. What has not been measured

Naming these because a profile that boots `--version` is not a profile that
boots a VM, and the difference is where the remaining risk lives.

Six of the eight items this section carried before the build are now measured
and have moved to §10, one of them with the opposite answer to the one
predicted here. Getting there took five AppArmor denials, all of one family:
the profile was traced from the jailer, and the container runs more than the
jailer. What is left:

- **The acceptance gate.** AT-002 and the live integration suite have never
  run in a container against v2. §10's VMs were driven through the API by
  hand — the gate's shape, not the gate.
- **Restart recovery acceptance.** The durable-ledger and host-PID design is
  chosen, but its live regression has not yet passed. §10 retains the historical
  tmpfs-ledger failure that made this requirement concrete.

## 8. The options, with what each costs

1. **Host-only, as today.** No container. The privileged surface stays behind
   privd and the sudo-gated helper, both of which already exist and are
   already reviewed. Costs nothing; buys nothing.
2. **`--privileged`.** Works (profile I). Grants every capability, all
   devices, no AppArmor, no seccomp. The container is the host with extra
   steps, and v2's whole isolation story is jailer-plus-netns *inside* that
   boundary, so this trades away the outer boundary entirely.
3. **Profile H — two caps, two devices, two exceptions.** Measured working.
   Materially narrower than `--privileged` on capabilities and devices, and
   identical to it on AppArmor and seccomp, which are the two that matter
   most. Honest summary: this narrows the blast radius, it does not contain it.
4. **Profile H with a narrow seccomp profile** (default + `pivot_root`) and a
   per-container AppArmor profile (default + the mounts the jailer makes).
   This is the only option that keeps a real confinement story, and it is the
   only one not yet measured. v1 already built a per-container AppArmor
   exception for its own case, so the shape is known to work.
5. **Drop the per-VM netns.** Run every tap in the container's own namespace
   and the container needs no `CAP_SYS_ADMIN` for networking at all — profile
   B territory. It also deletes the isolation between VMs that the per-VM
   netns exists to provide, which SPEC treats as load-bearing. Named for
   completeness; recommending it would be trading a real security property
   for a packaging convenience.

## 9. What the review has to decide

One question, and it is not a packaging question: **is a container that has
`CAP_SYS_ADMIN`, no AppArmor mount confinement and no seccomp filter a
boundary worth having?** If yes, option 4 is the version to build and the
narrow profiles are the work. If no, option 1 stands and `q4b2`'s
implementation half should close as declined rather than sit open.

The review answered yes and option 4 was built; §10 is the record. The
secondary decision this section named — measure the `/dev/kvm` group question
before writing a profile down — is settled, and the measurement inverted its
premise rather than confirming it. What takes its place is the first item in
§7: the AppArmor profile exists, ships, and has never run.

## 10. Measured in the build: 2026-09-06

Option 4, built and run on aibox03 against image `vmobs:fc56f1f-dirty` —
revision `fc56f1f9a9ecbe9ba0d339dba0af80c3b3f09d71` plus the working tree that
became commits `c494189` and `e57e3b7`. Everything below used
`deploy/seccomp/vmobs-jailer.json` and `apparmor=unconfined`; see §7 for why
the AppArmor half is still owed.

### `/dev/kvm` needs no group at all

§7 predicted `--group-add 108` and named the wrong layer. Three facts, read off
a running VM:

```
the container's node:  crw-rw---- 0:108      /dev/kvm
the jail's node:       crw------- 20000:36000  <jail>/root/dev/kvm
firecracker:           Uid: 20000  Gid: 36000  Groups: (none)
```

The jailer never hands the host's device to the jailed process. While it is
still root it `mknod`s its own `dev/kvm` inside the chroot and chowns it to the
jail uid — likewise `dev/net/tun`, `dev/urandom` and `dev/userfaultfd` — and
only then drops privilege. Firecracker opens it as its owner, holding no
supplementary groups whatsoever. The host's `kvm` gid never reaches it, so
`--group-add` would have been answering a question nobody asked.

The gid does matter one layer out, for vmobsd's own `arch_kvm` preflight, which
opens the container's node before any VM exists. `--group-add` cannot deliver
it there either: the entrypoint drops to the `vmobs` user with
`setpriv --init-groups`, which rebuilds the supplementary set from `/etc/group`
and discards whatever docker granted. So `deploy/entrypoint.sh` reads the gid
off the device node it was given and adds `vmobs` to that group *inside* the
container, where the rebuild can find it.

### A real boot, and a clean teardown

Two VMs at the m1a gate's shape — 1 vCPU, 512 MiB, 4096 MiB root, 64 MiB
workspace, template `standard` — created through the container's API:

| | VM P | VM Q |
|---|---|---|
| reached `running` | 7 s | 7 s |
| jail uid | 20000 | 20001 |
| guest CID | 3 | 4 |
| subnet | `10.190.0.0/30` | `10.190.0.4/30` |
| telemetry at 45 s | `healthy`, 8 events | `healthy`, 7 events |
| stopped, then deleted | 1 s, 1 s | 1 s, 1 s |

Both emitted `guest.channel_established` and reported a guestd uptime, so the
guest agent authenticated over `v.sock` inside the jail — the boundary's
narrowest path, and the one §7 doubted hardest. Both rings were clean:
capacity 1024, `dropped "0"`, queued 0.

After the deletes: no firecracker, no runner, no netns, no jail directory, no
stage directory, no ledger file, every reservation zero, and the host's veth
and tap counts back where the run found them. The host's own `vmobs-privd`
stayed `active` throughout and the host's `/srv/vmobs` was never touched — the
container builds its whole tree on its own volume.

### The fresh install found a bug the host had been hiding

This was v2's first clean-slate install, and it caught one. privd created
`<jail-base>/firecracker` with `MkdirAll(…, 0o750)` under its pinned `0002`
umask, giving a `root:root` directory that the unprivileged daemon — which
dials `v.sock` beneath it and stats the chroot to tear it down — could not
traverse. Every launch timed out at stage `attached` naming nothing, and every
delete returned 500. On aibox03's host the directory was already 0755 from the
M0 root helper, and `MkdirAll` leaves an existing directory's mode alone, so
the defect had never had a surface to appear on. Fixed in `c494189`, as
`privd.EnsureJailBase`, called at startup as well as from the launch path:
teardown reaches through that directory and creates nothing, so a repair that
only ran while starting a VM would leave an install unable to delete the VMs it
inherited and unable to launch its way out of holding their capacity.

### Historical: a container restart stranded every VM it was running

This measurement predates the durable-ledger and host-PID design. It remains as
evidence of the failure that design must fix, not as current operating guidance.
Measured on purpose after hitting it by accident: one VM `running`, then
`scripts/vmobs-container stop` and `start`.

- **Every VMM dies.** The container has its own PID namespace, so the jailer's
  daemonized firecracker goes with it. Zero survived.
- **privd's ledger is empty.** It lives on `--tmpfs /run`, which the restart
  discards.
- **Reconcile marks the VM `failed`.** Correct — it is gone.
- **The 1.7 GB chroot survives on the runtime volume and can no longer be
  reclaimed.** `RealOps.ReleaseVM` is the only code that removes it and is
  reachable only through a live ledger entry, so `DELETE` returns 500,
  `runtime_operation_failed`, *"stopped, but its jail chroot could not be
  reclaimed: privd: not_found: vm not in ledger"*. The row parks in `deleting`
  for good, still holding the disk it reserved — and that reservation is what
  refuses the next launch.

This is not a containerization defect. The host install has it too, across a
privd restart or a reboot; the container just reaches it in one command instead
of one outage. It is filed as kata `7p8m` rather than fixed here, because the
fix changes privd's release contract and nine tests pin that contract
(`internal/jailer/release_orphan_linux_test.go`) — including the rule that
`not_found` is an ordinary answer when nothing survives, which is exactly the
answer that goes wrong when something does.

### The narrow seccomp profile is sufficient

§6 measured only `seccomp=unconfined`, and §7 called the narrow form — Docker's
default profile plus `pivot_root` — "very likely sufficient" while refusing to
write that down as a measurement. Every run above used the narrow profile and
booted. It is a measurement now.

### The shipped AppArmor profile denied privd its own startup

Loading `deploy/apparmor/vmobs-jailer` and starting the container broke privd
before it bound its socket. The controlled form: one image, one seccomp
profile, one variable changed — `apparmor=unconfined` to
`apparmor=vmobs-jailer`. Unconfined booted VMs; confined never got a socket.

What privd reported was an exec failure:

    jail probe: could not enter a private mount namespace: fork/exec
    /usr/local/bin/vmobs-privd: permission denied

That message names no mount, and the remediation it carries tells the operator
to load the AppArmor profile — the profile that had just denied it. The kernel
was the only place the truth was written:

    apparmor="DENIED" operation="mount" class="mount" info="failed flags match"
    error=-13 profile="vmobs-jailer" name="/" pid=103968 comm="vmobs-privd"
    flags="rw, rprivate"

The profile was derived by tracing `jailer`, which marks `/` **rslave**
(`MS_REC|MS_SLAVE`) and nothing stricter. privd's jail probe forks a child with
`CLONE_NEWNS`, and Go's own `syscall/exec_linux.go` marks `/` **rprivate** in
that child before `execve` — a second, stricter propagation change on the same
mount point, made by the runtime rather than by any code in this repository.
Tracing the jailer could not have found it, because the jailer never makes it.

Two things this measures beyond the one missing rule:

- **A profile derived from tracing one program confines every program that
  runs under it.** The container's profile is the container's, not the
  jailer's. Anything the Go runtime does on its own behalf — here, one mount —
  has to be in the profile or it is denied.
- **An EACCES inside a forked child arrives as an exec failure.** The syscall
  that was refused happens between `fork` and `execve`, so the parent sees only
  `permission denied` on the exec. Nothing short of the kernel audit log says
  which operation was actually refused, which is why §1's method — read the
  kernel, not the error string — is the part that matters.

The rule went into the profile with the reasoning beside it, and
`tests/deploy/profiles_test.go` fails if it is removed. The fixed profile was
loaded on aibox03 at 2026-09-07 00:40:03 UTC (`apparmor="STATUS"
operation="profile_replace" name="vmobs-jailer"`).

### Three more denials, and what the probe was really measuring

The container restarted under the amended profile and exited again. The kernel
named the next one:

    apparmor="DENIED" operation="mount" class="mount" info="failed mntpnt match"
    error=-13 profile="vmobs-jailer" name="/tmp/vmobs-jailprobe-1810112568/netns"
    pid=232429 comm="vmobs-privd" srcname="/" flags="rw, bind"

`ip netns add` names a network namespace by bind-mounting `/proc/self/ns/net`
onto a file. privd runs that verb for every launch. The jailer runs it never,
so the trace found it never — the same root cause as the `rprivate` rule,
arriving at a different syscall.

The obvious fix was a rule for `/tmp/vmobs-jailprobe-*/netns`, and it was
wrong. It shipped, and the next restart produced this:

    apparmor="DENIED" operation="mount" class="mount" info="failed mntpnt match"
    error=-13 profile="vmobs-jailer" name="/tmp/vmobs-jailprobe-4208701220/"
    srcname="/tmp/vmobs-jailprobe-4208701220/" flags="rw, rbind"

That is the probe's own `pivot_root` step, self-binding its scratch directory
the way the jailer self-binds a chroot — in `/tmp`, where the profile grants
nothing, because the rules name `/srv/vmobs/jail/**`.

**A probe that runs somewhere convenient measures a grant nothing uses.** Two
of the three denials so far were the probe being denied paths production never
touches, and the reverse error was worse than the noise: a probe passing in
`/tmp` says nothing about whether `/srv/vmobs/jail` is permitted, so a profile
with a typo in the jail path would clear startup and fail every launch, from
inside the jailer, after a VM's worth of admission and staging.

The probe now stages at `<jail base>/firecracker/jailprobe-*/root` — the shape
the `pivot_root` rule names — and needs no rules of its own. The same argument
applied to the netns step, which had reimplemented `ip netns add` as a single
bind. It now runs the command. That change measured something a
reimplementation could not:

    apparmor="DENIED" operation="mount" class="mount" info="failed mntpnt match"
    error=-13 profile="vmobs-jailer" name="/run/netns/" comm="ip"
    flags="rw, rshared"

iproute2 marks `/run/netns` shared before it binds anything, and `MS_SHARED`
needs a mount point, so on the plain directory inside the `/run` tmpfs it gets
`EINVAL` and binds the directory onto itself to make one. Three mounts for one
verb. The hand-written version made one of them, would have passed the probe,
and every launch would have failed at network allocation.

**Run the verb; do not model it.** A probe that reimplements what production
calls measures the author's belief about the command. Where the real thing can
be run — and here it could, in a throwaway namespace, at a cost of one exec —
run it.

What this cost is worth recording too. Each missing rule took a full image
rebuild and container restart to find, because the probe returned at its first
failing step. It now runs every step and names a remedy for each, so a host
with three gaps learns about three. A step whose prerequisite failed is
reported inconclusive rather than run: `pivot_root(2)` after a failed
`mount_propagation_slave` raises an `EINVAL` about propagation, and `ip netns
exec` on a namespace that was never created reports only that it is missing.
Either, recorded as its own failure, names the wrong problem. And the remedy
for a step with no errno — a step that runs a command has an exit status and
nothing else — now sends the operator to `journalctl -k` first, which is the
only place an AppArmor denial is ever written.

### The fifth denial, and the first one the probe caught

With the four rules above loaded, privd started, the API came up, preflight
passed, and the first VM launched under the profile failed at network
allocation:

    apparmor="DENIED" operation="mount" class="mount" info="failed mntpnt match"
    error=-13 profile="vmobs-jailer" name="/sys/" comm="ip" fstype="sysfs"
    srcname="vmobs-<vm id>"

`ip netns exec` does not merely `setns`. It replaces `/sys` with a sysfs
instance describing the namespace it entered, so that `/sys/class/net` shows
that namespace's interfaces rather than the caller's. privd runs every network
setup command that way, and no amount of `ip netns add` reaches it: the add's
three mounts were granted and every launch still failed. The rule constrains
the filesystem type and the mount point, because the source is the namespace's
name and not a path:

    mount fstype=sysfs -> /sys/,

Then the same lesson a fourth time — run the verb — produced the first
denial this document did not have to spend a launch on. A fifth probe step
runs `ip netns exec <ns> true`, and on the host with the old profile still
loaded privd refused to serve, in under a second, saying which step and why:

    vmobs-privd: jail probe: 1 of 5 steps failed
      netns_exec: ip netns exec vmobs-jailprobe-42 true: exit status 255:
                  mount of /sys failed: Permission denied

Four of five steps passed; the report named the one that did not. The same
defect, found the previous way, had cost an image rebuild, a container restart,
admission, staging and a launch. **A startup probe is worth exactly the
production verbs it runs** — the four denials the earlier probe missed were all
operations it did not perform.

### A VM boots, and a terminal opens, under the loaded profile

With all ten rules loaded, a VM booted under the profile. It was created
through the web UI at 01:36:02 and reached `running / running / healthy`:

    container AppArmorProfile: vmobs-jailer
    /proc/<firecracker pid>/attr/current: vmobs-jailer (enforce)
    AppArmor denials since container start: 0
    events: guest.channel_established (host_observed),
            guest.sensor_health (guest_reported)

The VMM itself runs under the profile — not merely the container that spawned
it — and the guest agent answered over vsock, so the confined chain runs end to
end. That was the last thing §7 named about the mount boundary.

A terminal opened on a later VM under the same profile, and this is the round
trip in full: `POST /vms/<id>/terminals` allocated a PTY at guest pid 730, the
WebSocket upgrade returned `101`, the stream's first message was
`{"type":"attached","writer":true}`, and typing `echo <marker>` produced the
marker back followed by a fresh prompt. PTY bytes cross the vsock, through the
jailed VMM, under confinement.

Opening it required a fix. `cmd/vmobsd/main.go` built its `api.AuthConfig` with
`PublicOrigin` set only on the branch where authentication is enabled, and the
appliance ships with `require_authentication: false`. `PublicOrigin` is not an
authentication field: the WebSocket origin gate compares it on every upgrade,
and an empty one matches nothing. Every terminal in the shipped configuration
was refused with `403 public_origin_unset`, while `/etc/vmobs/config.yaml` set
a public origin two lines above the listen address. Every API test builds its
`AuthConfig` by hand, so the suite never saw the daemon's own construction of
it; the fix extracts that into `authConfig()` with a test on the auth-off path.

The gate still bites. With the fix in place, `Origin: http://localhost:8787`
and `Origin: http://evil.example` are both refused `403 origin_rejected`
against a `public_origin` of `http://127.0.0.1:8787`. What changed is that the
configured origin now passes.

### Historical: a restart could strand a VM permanently, and did

This section records the old tmpfs-ledger design and is superseded by the
recovery design below. §10's earlier note that a container restart strands every
VM it was running described the shape. This is the measured case, and it was
worse than the note said: the strand could not be cleared by any API call at all.

privd's ledger is on `--tmpfs /run`, so a restart empties it while the jail
chroots on the `vmobs-runtime` volume survive. `Manager.Delete` force-stops
first, and the force-stop asked `release_vm` for a VM the new ledger had never
heard of. privd answered its ordinary typed `not_found`, and the stop path
reported that as an `ErrCleanupPending` — a cleanup debt. Delete treats a debt
as a failed force-stop, correctly, because a `deleted` row promises every
resource is gone. So the row sat at `failed`, its 5120 MiB reservation held,
`free_disk` at `-2536`, and every retry produced:

    HTTP 500  ... stopped, but its jail chroot could not be reclaimed:
    privd: not_found: vm not in ledger

`doRelease` had always run that answer through `ignoreNotFound` and taken its
verdict from the filesystem. The force-stop path did neither. Both now share
`chrootDebt`, which asks the filesystem — because `not_found` cannot simply be
ignored either: a lost ledger is precisely the state where the chroot *does*
survive. When it does, the debt now names the directory instead of repeating
privd's answer, which is the difference between a leak an operator can find and
one they cannot.

The measured system still had this limitation: a chroot whose ledger entry was
gone was unreclaimable by any privileged call. Clearing this case required
manual directory removal. The chosen successor design avoids that state by
keeping the root-owned ledger at `/srv/vmobs/privd` on the runtime volume.

Compose and the development wrappers also join the host PID namespace. Each VM
record captures the host kernel boot identity and PID namespace identity, so a
replacement privd can distinguish its VMM from PID reuse. A mismatch or
unreadable record fails closed; it never authorizes a signal. This increases
host process visibility inside the appliance. AppArmor, seccomp, capabilities
and device grants are unchanged. The design requires no host install step and
adds no supervisor. Its live recovery gate is still pending, so this document
does not claim the restart defect fixed or measured green.

Nor does the new ledger auto-import the legacy chroots described above. Once an
old ephemeral record is gone, a manifest or jail pidfile cannot recreate trusted
root signaling authority. Those preexisting resources remain unknown and fail
closed until an operator resolves them; the design prevents the same loss for
records created after it ships.

### The profile was never installed, only loaded

Every load of the profile on this host was `apparmor_parser -r` against the
checkout, which loads into the running kernel and leaves nothing behind:
`/etc/apparmor.d/vmobs-jailer` did not exist. The profile therefore died at
every reboot, and `docker run --security-opt apparmor=vmobs-jailer` would have
refused to start the appliance until someone reran the command by hand.

The initial remedy was a host installer that copied the profile into
`/etc/apparmor.d` and loaded it, with `start` refusing when that copy was missing
or differed from the repo's. That remedy is superseded by §11; no host installer
ships now. The comparison was between those two files because
what the kernel holds is not readable without root — `/sys/kernel/security/apparmor/profiles`
is `0444` root-only — and the refusal says which two it compared. A stale
profile is the case worth catching: docker accepts any loaded profile by name,
so the container starts clean and the mismatch surfaces minutes later as a
denied mount in the middle of a launch. Four of this document's five denials
were found that way.

## 11. Compose policy loader (2026-09-07)

Doctor Biz approved a short-lived Compose service with policy-management
authority so installation is `docker compose up -d`. Docker still selects the
runtime profile by name. A helper can load that name into the shared kernel
before Docker starts the appliance; the earlier conclusion that Compose could
not arrange this was too broad.

The `apparmor` service uses the same appliance image as `vmobs`, containing the
parser and bundled profile. It invokes `apparmor_parser --replace --skip-cache`
directly, with all capabilities dropped except `MAC_ADMIN`,
`apparmor=unconfined` on the loader only, no network, a read-only image
filesystem, and a read-write securityfs bind. It receives no Docker socket or
host root mount. No host packages, configuration files, systemd units or sudoers
entries are installed. Loading policy still changes the shared host kernel and
can affect other processes using the same profile name.

The appliance depends on the loader's successful completion and retains its
existing AppArmor/seccomp profiles, capabilities, devices, uid split and named
volumes. The developer wrappers and integration gate use this same loader for
the supported default `vmobs-jailer` profile. The explicit `unconfined` override
remains for development only; the loader does not manage arbitrary profiles.

The startup command after a host reboot is also `docker compose up -d`, which
must reload the bundled policy before the appliance starts. Plain `docker
start` or `docker restart` cannot run that dependency. No claim of automatic
boot-time loading is made.

Measured on aibox03 with Docker 27.2.1, Compose 2.29.2 and AppArmor parser 4.0.1:
the loader needs only `MAC_ADMIN`; removing it refuses policy replacement.
A separate container reported the probe profile in enforce mode.

`TestComposeLive` then passed against the built appliance image. Starting from
an absent policy and fresh volumes, an invalid parser input blocked appliance
startup. Correcting that input started the appliance under `vmobs-jailer
(enforce)`, with a passing preflight, and a real VM reached `running` then
`deleted`. Stopping the appliance and unloading its unused policy simulated
the kernel state after reboot. A later `compose up -d` reloaded it despite the
previous setup container's successful exit; a further `up` also succeeded.
The host's `/etc/apparmor.d/vmobs-jailer` remained absent throughout. No host
reboot was performed. The test owns and removes its named containers and volumes.
