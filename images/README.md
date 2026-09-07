# Guest image pipeline

Builds two artifacts consumed by the Firecracker microVM runtime:

- `images/dist/vmlinux` — guest Linux kernel (6.1 series)
- `images/dist/rootfs.ext4` — Ubuntu 24.04 root filesystem with vmobs-guestd

## Running

All scripts run **on aibox03** (the Linux KVM host). No root or sudo is needed — docker is rootless for `harper`.

```
# Full build (kernel + rootfs), checked against runtime.lock.json:
bash images/build-all.sh

# Same, but taking the build's digests as the new pins:
bash images/build-all.sh --repin

# Individual stages:
bash images/kernel/build.sh
bash images/rootfs/build.sh
```

Most installs never run any of this. `scripts/fetch-guest-images` downloads the
published artifacts and verifies them against the same pins; building from source
is for moving the pins, or for a set nobody has published yet.

`runtime.lock.json` is an input here: `images/lock-pins.sh` compares what the
build produced against it and fails on a disagreement, so an ordinary build
leaves the checkout clean. `--repin` is how you move the pins on purpose — commit
the lock afterwards, and republish with `scripts/publish-guest-images`.

Scripts are idempotent: re-running cleans their own staging and produces fresh artifacts. The kernel tarball is cached at `/tmp/vmobs-kernel-src/` to avoid redundant downloads.

## What gets produced

| Artifact | Location on aibox03 | Committed? |
|---|---|---|
| `vmlinux` | `images/dist/vmlinux` | No (gitignored) |
| `rootfs.ext4` | `images/dist/rootfs.ext4` | No (gitignored) |
| `rootfs.inventory.txt` | `images/dist/rootfs.inventory.txt` | No (gitignored) |
| Build logs | `images/dist/logs/*.log` | No (gitignored) |

Artifact sha256s and paths are committed in `runtime.lock.json` (`guest_kernel.*`, `root_image.*`).

## Pins explained

### Docker base image

`images/rootfs/pins.env` holds the exact `ubuntu@sha256:<digest>` used for both the rootfs build container and the kernel build container. Resolved once on aibox03 via:

```
docker pull ubuntu:24.04
docker inspect --format '{{index .RepoDigests 0}}' ubuntu:24.04
```

Re-pinning: run the above two commands on the target host, update `BASE_IMAGE_REF` in `pins.env`, commit, and re-run the build.

### APT snapshot

`APT_SNAPSHOT` in `pins.env` is a `snapshot.ubuntu.com` timestamp (format `YYYYMMDDTHHMMSSZ`). The rootfs build installs packages at that frozen point. Invocation:

```
apt-get -S <snapshot-timestamp> install ...
```

`ca-certificates` is installed first via the live archive (needed to reach `snapshot.ubuntu.com` over TLS) — this is an acceptable deviation because the TLS certificate infrastructure is not part of the guest software stack; only `ca-certificates` itself comes from the live archive before we switch to the snapshot. The deviation is bounded to the software stack, not to the artifact: that step is unpinned, so `rootfs.ext4`'s sha256 can still move between builds (reproducibility caveat 5 below).

### Kernel source

Linux 6.1.186 from `cdn.kernel.org`. The sha256 is verified before extraction. The base kernel config comes from the Firecracker v1.16.1 CI config for x86_64 6.1 (`resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config`).

## Kernel version rationale

Firecracker v1.16.1's `docs/kernel-policy.md` lists two supported guest kernel series: v5.10 (EOL 2024-01-31) and v6.1 (EOL 2026-09-02). We chose **v6.1** as the newest supported series. The exact version (6.1.186) is the latest stable release from kernel.org at implementation time (2026-08-28 release date).

**Note on Amazon Linux kernels:** Firecracker's own CI uses Amazon Linux-patched kernels. The repo's guest configs were generated against those patched trees and may reference symbols that differ from mainline 6.1. We use the mainline tarball with the Firecracker base config; the fragment hard-verify step catches any symbol discrepancy before the build proceeds.

## Fragment verification

After `olddefconfig`, `images/kernel/build.sh` checks every symbol in `images/kernel/vmobs.fragment`:

```
for sym in fragment:
    grep '^CONFIG_SYM=y' .config || BUILD FAILS
```

Two brief spec symbols were excluded from the fragment:

| Symbol | Why excluded |
|---|---|
| `CONFIG_DEVPTS_FS` | Not a Kconfig symbol in mainline 6.1. PTY support provided by `CONFIG_UNIX98_PTYS=y` (which implicitly enables devpts). `fs/Kconfig` has no `DEVPTS_FS` entry in this tree. |
| `CONFIG_TRACEPOINTS` | Prompt-less bool in `init/Kconfig` — selected automatically by tracing infrastructure. Cannot be set in a fragment (olddefconfig treats it as read-only). |

## Build toolchain note

The C toolchain (gcc, binutils) comes from the pinned `ubuntu:24.04` container's live apt (install happens inside the container run, not the snapshot). The toolchain influences compiler metadata in `vmlinux` but not the kernel source or config — reproducibility of the ELF binary is not claimed; the sha256 pins the specific artifact built at implementation time.

## Reproducibility caveats

1. **Docker image digest**: pinned in `pins.env`. A different digest produces a different toolchain and a different `vmlinux` sha256.
2. **APT snapshot**: rootfs packages are frozen at `APT_SNAPSHOT`. A newer snapshot will produce different package versions and a different `rootfs.ext4` sha256.
3. **Kernel sha256**: kernel.org source tarball sha256 is pinned in `runtime.lock.json`. The tarball is immutable for a given version.
4. **Build toolchain** (kernel only): not pinned beyond the docker image digest. Same image, same gcc version; different image, potentially different output.
5. **Live apt bootstrap** (rootfs only): `images/rootfs/build.sh:88-90` runs a live `apt-get update` and installs `ca-certificates` before switching to the pinned apt snapshot, because reaching `snapshot.ubuntu.com` needs TLS first. That step is not pinned, so `rootfs.ext4`'s sha256 can move between builds for reasons unrelated to any input we control. Not fixed in this rebuild; fixing the bootstrap is M1b work.
