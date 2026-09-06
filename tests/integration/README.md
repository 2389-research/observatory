# Integration tests

## What is here

- `netns_test.go` — Task 7: network namespace setup/teardown via the root helper.
- `boot_test.go` — Task 8 (M0 gate): jailed two-VM boot, vsock handshake, capability report, disk ownership, teardown.
- `fixture/` — Helper package for building and managing fixture VMs.
- `evidence/` — Evidence files written by the gate test when it runs (committed; never fabricated).

## Prerequisites

All of these are installed by `scripts/aibox03/setup.sh` (run once by the host operator with password sudo):

- `/usr/local/sbin/vmobs-root-helper` — the narrow root helper
- `/srv/vmobs/` — the directory tree used by the helper
- `/usr/local/bin/firecracker` and `/usr/local/bin/jailer`
- The `vmobs-fixture` group and `harper` added to it and the `kvm` group

Until `scripts/aibox03/setup.sh` has been run, tests skip with a message naming the script.

## Environment variables

| Variable | Effect |
|---|---|
| `VMOBS_FIXTURE=1` | Enable root-gated tests. Without this, all integration tests skip. |
| `VMOBS_SOURCE_REVISION` | The 40-character commit the tree under test came from. `scripts/linux` sets it, because the copy it rsyncs to the host arrives without `.git`. Without it a gate records no evidence and says why. |
| `VMOBS_SOURCE_DIRTY=1` | The tree under test differs from that commit. `scripts/linux` sets it from `git status --porcelain`. |
| `VMOBS_EVIDENCE_ROOT` | Where execution records are published. Default `<tmpdir>/vmobs-evidence` — deliberately outside the repository, because `scripts/linux` rsyncs with `--delete`. |

## How to run

Remote execution via the rsync bridge:

```sh
# Skip gate (fast; safe to run any time):
scripts/linux 'go test ./tests/integration/ -v'

# Honest skip after setup.sh is installed:
scripts/linux 'env VMOBS_FIXTURE=1 go test ./tests/integration/ -v'

# Full M0 gate run (requires setup.sh to have been run on aibox03):
scripts/linux 'env VMOBS_FIXTURE=1 go test ./tests/integration/ -v -timeout 600s'
```

The remote login shell is fish, where a bare `VAR=value command` prefix is a
syntax error. Pass environment through `env`, as above.

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

**The evidence file is only written when the gate actually runs.** No placeholder exists before setup.sh lands. Fabricated evidence is the one unforgivable defect in this codebase.

### Execution records

Alongside the transcript, a real-host gate publishes one machine-readable record
per acceptance row it exercises (`internal/evidence`, wired by
`evidence_record_test.go`). Each record binds that row's outcome to the commit,
the sha256 of every binary that ran, the runtime-lock digest, the pinned guest
artifacts the lock names, the host's identity and preflight verdict, and the
digest of the transcript the subtest wrote. A record is written once under a
name that cannot be reused.

Records land in `$VMOBS_EVIDENCE_ROOT` (default `<tmpdir>/vmobs-evidence`), so
they survive the next `scripts/linux` rsync. To bring a run's records back:

```sh
scripts/linux 'tar -C /tmp/vmobs-evidence -czf - . | base64 -w0' | tail -1 | base64 -d | tar -xzf - -C <dest>
```

The gate's transcript ends with the ID and result of every record it published,
so a run can be matched to its records without guessing.

## Debugging tips

If a VM fails to boot:

1. Serial console output is Firecracker's log, which lands in the jailer chroot. After a failed run, check:
   ```
   /srv/vmobs/jail/firecracker/<id>/root/
   ```
2. The vsock readiness timeout is 60 seconds. If the guest never answers, the kernel panic log is in the Firecracker log file inside the chroot.
3. Run `scripts/linux 'dmesg | tail -40'` to check for KVM or kernel errors on the host.
4. Verify `vmobs-fixture` group gid matches what the helper expects: `getent group vmobs-fixture`.
