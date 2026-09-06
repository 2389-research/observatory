<!-- ABOUTME: Every privileged operation v2's launch chain performs, what each needs from the kernel, -->
<!-- ABOUTME: and the measured delta against Docker's defaults. A review artifact, not a shipping profile. -->

# Container Boundary: what v2's chain asks of the kernel

## 0. What this is

Kata `q4b2` asks whether `vmobs` can run inside a container, and says the
answer waits on a device/cgroup/security review with Doctor Biz. This is the
document that review needs and did not exist: the privileged surface named
operation by operation, each requirement traced to v2's own code or measured
on aibox03, set against what Docker actually grants.

Nothing here is a decision. There is no Dockerfile, no compose file and no
shipping profile in this pass, deliberately — the kata says diagnostic
permissions must not be promoted into shipping configuration without review,
and a document is the thing that gets reviewed.

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
| | firecracker | `/dev/kvm` | the kvm device node, openable by the **jailed** uid |
| `signal_vm` | `pidfd_open` + `kill` across a uid boundary | — | `CAP_KILL` |
| `release_vm` | `RemoveAll` of the jail dir | — | root in the mount namespace |

Sources: `internal/privd/netops.go:203-212` (the verb sequence verbatim),
`internal/privd/vmops.go:310-323` (the jailer argv),
`internal/privd/vmops.go:659-697` (signal and release),
`scripts/aibox03/vmobs-root-helper:39-141` (the same sequence in the
sudo-gated helper).

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

- **`/dev/kvm` ownership across the privilege drop.** In-container the node
  appears as `crw-rw---- root:108`, gid 108 being the host's `kvm` group. The
  jailer setuids to the jail uid (36000-based) before exec'ing firecracker, so
  the *jailed* uid must be able to open it — container root's `DAC_OVERRIDE`
  does not help a process that has already dropped to 36000. Untested; likely
  needs `--group-add 108` or equivalent, and it is the next thing that breaks.
- **A real boot.** No profile here started a VM: no kernel, no rootfs, no
  guest, no `v.sock`, no guest authentication, no telemetry.
- **Restart recovery and reconciliation**, which read `/proc` for jailed VMMs
  across a container restart, where PID namespaces change the picture.
- **The acceptance gate.** AT-002 and the live integration suite have never
  run in a container against v2.
- **A narrow seccomp profile.** Only `seccomp=unconfined` was measured. The
  narrow form — Docker's default profile plus `pivot_root` — is a small JSON
  file and is very likely sufficient, but "very likely" is not a measurement
  and should not be written into a profile as though it were.

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

A secondary decision, if option 4 proceeds: the `/dev/kvm` group question in
§7 needs measuring before any profile is written down, because it is the
difference between a profile that runs `jailer --version` and one that boots.
