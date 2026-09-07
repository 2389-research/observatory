# Integration tests

## What is here

- `netns_test.go` — Task 7: network namespace setup/teardown via the root helper.
- `boot_test.go` — Task 8 (M0 gate): jailed two-VM boot, vsock handshake, capability report, disk ownership, teardown.
- `m1a_gate_test.go`, `m1b_gate_test.go`, `m2a_gate_test.go` — the milestone gates.
- `fixture/` — Helper package for building and managing fixture VMs, plus the
  narrow root helper the M0 network tests exec through `sudo`.
- `evidence/` — Evidence files written by the gate test when it runs (committed; never fabricated).

## How to run

```sh
scripts/vmobs-gate                                              # the whole suite
scripts/vmobs-gate go test ./tests/integration/ -run TestM1aGate -v
```

That builds a throwaway image on top of the appliance image and runs the suite
inside it under the same capabilities, devices, seccomp profile and AppArmor
profile the appliance runs under — `docs/design/container-boundary.md` §5. A gate
holding privileges no user has would prove nothing about what users can do, so
`tests/deploy/gate_test.go` fails if the two ever drift apart.

Nothing is installed on the host. The container creates the `vmobs-fixture`
group, the root helper's sudoers grant and the `/srv/vmobs` tree for itself, and
`docker run --rm` throws all of it away.

### Host prerequisites

The same ones anybody installing vmobs already has:

- Docker, and a user in the `docker` group
- `/dev/kvm` and `/dev/net/tun`
- The AppArmor profile loaded: `sudo sh deploy/install-apparmor.sh`

On a host with no AppArmor at all, `VMOBS_APPARMOR_PROFILE=unconfined` runs the
suite without it. That is a weaker boundary than the appliance ships, so say so
in anything you claim from such a run.

### Running on a remote Linux host

`scripts/linux` rsyncs this tree to `$VMOBS_LINUX_HOST` and runs a command there:

```sh
scripts/linux 'scripts/vmobs-gate'
```

It carries the revision across, because the copy it sends arrives without `.git`
and a gate that cannot name its source publishes no evidence.

## Environment variables

| Variable | Effect |
|---|---|
| `VMOBS_FIXTURE=1` | Enable root-gated tests. Set by the gate container; without it every integration test skips. |
| `VMOBS_SOURCE_REVISION` | The 40-character commit the tree under test came from. `scripts/linux` sets it, because the copy it rsyncs to the host arrives without `.git`. Without it a gate records no evidence and says why. |
| `VMOBS_SOURCE_DIRTY=1` | The tree under test differs from that commit. `scripts/linux` sets it from `git status --porcelain`. |
| `VMOBS_EVIDENCE_ROOT` | Where execution records are published. `scripts/vmobs-gate` sets it to a mounted host directory, because a `--rm` container deletes its own filesystem the moment the run finishes. |
| `VMOBS_GATE_EVIDENCE_DIR` | The host side of that mount. Default `${TMPDIR:-/tmp}/vmobs-evidence` — outside the checkout, because `scripts/linux` rsyncs with `--delete`. |
| `VMOBS_IMAGE` | The appliance image the gate builds on. Default is the published one, so a plain run tests the artifacts a stranger installs. |

## Evidence

When the gate runs successfully, it writes:

```
tests/integration/evidence/m0-boot-<hostname>.txt
```

The evidence file is bounded (≤200 lines) and contains:

- Lock artifact hashes verified against `runtime.lock.json`
- Firecracker version string (`/usr/local/bin/firecracker --version`)
- Per-VM uid/gid/cid/netns identity
- Handshake transcript (message kinds only — never the token)
- Capability manifests for both VMs
- Host-stat ownership lines for rootfs.ext4 in each chroot
- Teardown proof (no m0-* entries remain in jail or netns)

**The evidence file is only written when the gate actually runs.** Fabricated
evidence is the one unforgivable defect in this codebase.

### Execution records

Alongside the transcript, a real-host gate publishes one machine-readable record
per acceptance row it exercises (`internal/evidence`, wired by
`evidence_record_test.go`). Each record binds that row's outcome to the commit,
the sha256 of every binary that ran, the runtime-lock digest, the pinned guest
artifacts the lock names, the host's identity and preflight verdict, and the
digest of the transcript the subtest wrote. A record is written once under a
name that cannot be reused.

Records land in the directory `scripts/vmobs-gate` mounts — by default
`/tmp/vmobs-evidence` on the host that ran it. To bring a remote run's records
back:

```sh
scripts/linux 'tar -C /tmp/vmobs-evidence -czf - . | base64 -w0' | tail -1 | base64 -d | tar -xzf - -C <dest>
```

The gate's transcript ends with the ID and result of every record it published,
so a run can be matched to its records without guessing.

## Debugging tips

If a VM fails to boot:

1. Serial console output is Firecracker's log, which lands in the jailer chroot.
   That chroot is inside the gate container, which `--rm` deletes — so to keep it,
   run the suite with a shell instead and poke around before exiting:
   ```sh
   scripts/vmobs-gate sh -c 'go test ./tests/integration/ -run TestM0Boot -v; ls /srv/vmobs/jail/firecracker/*/root/'
   ```
2. The vsock readiness timeout is 60 seconds. If the guest never answers, the
   kernel panic log is in the Firecracker log file inside the chroot.
3. `scripts/linux 'dmesg | tail -40'` checks for KVM or kernel errors on the host.
   KVM errors surface on the host, not in the container.
4. `scripts/vmobs-gate getent group vmobs-fixture` shows the gid the container
   made, which must match the one the root helper accepts.
