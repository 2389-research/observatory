#!/bin/bash
# ABOUTME: Builds the vmobs guest kernel (Linux 6.1.186) inside a pinned ubuntu:24.04
# ABOUTME: docker container; hard-verifies every fragment symbol; outputs images/dist/vmlinux.
set -euo pipefail

# ---------------------------------------------------------------------------
# Paths — run from anywhere inside the repo; resolve script dir as repo root
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DIST_DIR="$REPO_ROOT/images/dist"
LOG_DIR="$DIST_DIR/logs"
LOG="$LOG_DIR/kernel.log"

mkdir -p "$DIST_DIR" "$LOG_DIR"

# Redirect everything to log and stdout
exec > >(tee -a "$LOG") 2>&1

echo "[kernel/build.sh] started $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[kernel/build.sh] repo root: $REPO_ROOT"

# ---------------------------------------------------------------------------
# Pins — never guess, always verify
# ---------------------------------------------------------------------------
KERNEL_VERSION="6.1.186"
KERNEL_TARBALL="linux-${KERNEL_VERSION}.tar.xz"
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/${KERNEL_TARBALL}"
KERNEL_SHA256="eeedc32bbf2448205aff50ee2760a4d87172cf8f8279c1e5930069ad36f6236e"

# Firecracker x86_64 6.1 guest base config (v1.16.1 tag)
FC_CONFIG_URL="https://raw.githubusercontent.com/firecracker-microvm/firecracker/v1.16.1/resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config"

# Pinned Ubuntu 24.04 docker image — digest resolved once at implementation time
# (docker pull ubuntu:24.04 && docker inspect --format '{{index .RepoDigests 0}}' ubuntu:24.04)
PINS_ENV="$SCRIPT_DIR/../rootfs/pins.env"
if [ ! -f "$PINS_ENV" ]; then
    echo "[kernel/build.sh] ERROR: pins.env not found at $PINS_ENV — run rootfs/build.sh first or create pins.env" >&2
    exit 1
fi
# shellcheck source=images/rootfs/pins.env
. "$PINS_ENV"
# BASE_IMAGE_REF is now set from pins.env

FRAGMENT="$SCRIPT_DIR/vmobs.fragment"

# ---------------------------------------------------------------------------
# Download kernel source (idempotent — skip if sha256 already matches)
# ---------------------------------------------------------------------------
SRCDIR="/tmp/vmobs-kernel-src"
TARBALL_PATH="$SRCDIR/${KERNEL_TARBALL}"

mkdir -p "$SRCDIR"

if [ -f "$TARBALL_PATH" ]; then
    echo "[kernel/build.sh] verifying cached tarball..."
    CACHED_SHA=$(sha256sum "$TARBALL_PATH" | awk '{print $1}')
    if [ "$CACHED_SHA" = "$KERNEL_SHA256" ]; then
        echo "[kernel/build.sh] cached tarball sha256 OK: $CACHED_SHA"
    else
        echo "[kernel/build.sh] cached tarball sha256 MISMATCH (got $CACHED_SHA), re-downloading"
        rm -f "$TARBALL_PATH"
    fi
fi

if [ ! -f "$TARBALL_PATH" ]; then
    echo "[kernel/build.sh] downloading $KERNEL_URL ..."
    curl -fL --progress-bar -o "$TARBALL_PATH" "$KERNEL_URL"
    echo "[kernel/build.sh] verifying download sha256..."
    DOWNLOADED_SHA=$(sha256sum "$TARBALL_PATH" | awk '{print $1}')
    if [ "$DOWNLOADED_SHA" != "$KERNEL_SHA256" ]; then
        echo "[kernel/build.sh] ERROR: tarball sha256 mismatch!" >&2
        echo "  expected: $KERNEL_SHA256" >&2
        echo "  got:      $DOWNLOADED_SHA" >&2
        rm -f "$TARBALL_PATH"
        exit 1
    fi
    echo "[kernel/build.sh] tarball sha256 verified: $DOWNLOADED_SHA"
fi

# ---------------------------------------------------------------------------
# Download Firecracker base config
# ---------------------------------------------------------------------------
FC_CONFIG_PATH="$SRCDIR/microvm-kernel-ci-x86_64-6.1.config"
echo "[kernel/build.sh] downloading Firecracker base config..."
curl -fsSL -o "$FC_CONFIG_PATH" "$FC_CONFIG_URL"
FC_CONFIG_SHA256=$(sha256sum "$FC_CONFIG_PATH" | awk '{print $1}')
echo "[kernel/build.sh] base config sha256: $FC_CONFIG_SHA256"

# ---------------------------------------------------------------------------
# Extract source (idempotent — skip if already extracted)
# ---------------------------------------------------------------------------
KDIR="$SRCDIR/linux-${KERNEL_VERSION}"
if [ -d "$KDIR" ]; then
    echo "[kernel/build.sh] source dir exists, skipping extract"
else
    echo "[kernel/build.sh] extracting tarball (this takes a minute)..."
    tar -xJf "$TARBALL_PATH" -C "$SRCDIR"
    echo "[kernel/build.sh] extracted to $KDIR"
fi

# ---------------------------------------------------------------------------
# Build inside pinned docker container
# ---------------------------------------------------------------------------
echo "[kernel/build.sh] pulling base image: $BASE_IMAGE_REF"
docker pull --quiet "$BASE_IMAGE_REF"

echo "[kernel/build.sh] starting kernel build in docker..."

docker run --rm \
    -v "$KDIR":/build/linux \
    -v "$FC_CONFIG_PATH":/build/fc.config:ro \
    -v "$FRAGMENT":/build/vmobs.fragment:ro \
    -v "$DIST_DIR":/build/dist \
    -w /build/linux \
    "$BASE_IMAGE_REF" \
    bash -euo pipefail -c '
set -euo pipefail

echo "[docker] installing build deps..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    build-essential flex bison bc libelf-dev dwarves python3 libssl-dev \
    2>&1 | tail -5

echo "[docker] copying Firecracker base config..."
cp /build/fc.config /build/linux/.config

echo "[docker] merging fragment via merge_config.sh..."
# scripts/kconfig/merge_config.sh merges additional config fragments
# It expects to be run from the kernel source root
bash scripts/kconfig/merge_config.sh -m /build/linux/.config /build/vmobs.fragment

echo "[docker] running make olddefconfig..."
make olddefconfig

echo "[docker] hard-verifying fragment symbols..."
FRAGMENT=/build/vmobs.fragment
FAILED=0
while IFS= read -r line; do
    # Skip comments and blank lines
    case "$line" in
        ""|\#*) continue ;;
    esac
    # Extract symbol name: CONFIG_FOO=y -> CONFIG_FOO
    sym="${line%%=*}"
    if grep -q "^${sym}=y" .config; then
        echo "[verify] OK: $sym"
    else
        echo "[verify] MISSING: $sym  (not =y in .config after olddefconfig)" >&2
        FAILED=$((FAILED + 1))
    fi
done < /build/vmobs.fragment
if [ "$FAILED" -gt 0 ]; then
    echo "[verify] HARD-VERIFY FAILED: $FAILED symbol(s) missing — see above" >&2
    exit 1
fi
echo "[verify] all fragment symbols verified OK"

echo "[docker] computing post-merge .config sha256..."
CONFIG_SHA256=$(sha256sum .config | awk "{print \$1}")
echo "[docker] config sha256: $CONFIG_SHA256"

echo "[docker] building vmlinux with $(nproc) jobs..."
make -j"$(nproc)" vmlinux

echo "[docker] copying output artifacts..."
cp vmlinux /build/dist/vmlinux
cp .config /build/dist/kernel.config

echo "[docker] vmlinux sha256: $(sha256sum /build/dist/vmlinux | awk "{print \$1}")"
echo "[docker] config sha256: $CONFIG_SHA256"
echo "$CONFIG_SHA256" > /build/dist/kernel.config.sha256
'

# ---------------------------------------------------------------------------
# Record sha256 sums back on the host (for lock update)
# ---------------------------------------------------------------------------
VMLINUX_SHA256=$(sha256sum "$DIST_DIR/vmlinux" | awk '{print $1}')
CONFIG_SHA256=$(cat "$DIST_DIR/kernel.config.sha256")

echo "[kernel/build.sh] === BUILD COMPLETE ==="
echo "[kernel/build.sh] kernel version: $KERNEL_VERSION"
echo "[kernel/build.sh] source sha256:  $KERNEL_SHA256"
echo "[kernel/build.sh] config sha256:  $CONFIG_SHA256"
echo "[kernel/build.sh] vmlinux sha256: $VMLINUX_SHA256"
echo "[kernel/build.sh] vmlinux size:   $(du -sh "$DIST_DIR/vmlinux" | cut -f1)"
echo "[kernel/build.sh] log: $LOG"

# Write out values for build-all.sh to pick up
cat > "$DIST_DIR/kernel.pins" <<EOF
KERNEL_VERSION=${KERNEL_VERSION}
KERNEL_URL=${KERNEL_URL}
KERNEL_SHA256=${KERNEL_SHA256}
CONFIG_SHA256=${CONFIG_SHA256}
VMLINUX_SHA256=${VMLINUX_SHA256}
EOF

echo "[kernel/build.sh] pins written to $DIST_DIR/kernel.pins"
