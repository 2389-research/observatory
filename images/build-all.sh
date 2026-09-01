#!/bin/bash
# ABOUTME: Orchestrates the full guest image pipeline: kernel build + rootfs build, then
# ABOUTME: updates runtime.lock.json in-place with computed sha256s and artifact paths.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$REPO_ROOT/images/dist"
LOCK_FILE="$REPO_ROOT/runtime.lock.json"
LOG_DIR="$DIST_DIR/logs"

mkdir -p "$DIST_DIR" "$LOG_DIR"

echo "[build-all] started $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[build-all] repo root: $REPO_ROOT"

# ---------------------------------------------------------------------------
# Step 1: Kernel
# ---------------------------------------------------------------------------
echo "[build-all] === STEP 1: kernel build ==="
bash "$SCRIPT_DIR/kernel/build.sh"

# ---------------------------------------------------------------------------
# Step 2: Rootfs
# ---------------------------------------------------------------------------
echo "[build-all] === STEP 2: rootfs build ==="
bash "$SCRIPT_DIR/rootfs/build.sh"

# ---------------------------------------------------------------------------
# Step 3: Load computed pins
# ---------------------------------------------------------------------------
echo "[build-all] loading pins..."
# shellcheck source=images/dist/kernel.pins
. "$DIST_DIR/kernel.pins"
# shellcheck source=images/dist/rootfs.pins
. "$DIST_DIR/rootfs.pins"

# Verify artifacts exist
if [ ! -f "$DIST_DIR/vmlinux" ]; then
    echo "[build-all] ERROR: vmlinux not found in $DIST_DIR" >&2
    exit 1
fi
if [ ! -f "$DIST_DIR/rootfs.ext4" ]; then
    echo "[build-all] ERROR: rootfs.ext4 not found in $DIST_DIR" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 4: Update runtime.lock.json via jq
# ---------------------------------------------------------------------------
echo "[build-all] updating $LOCK_FILE ..."

# jq in-place update: set all guest_kernel.* and root_image.* fields
TMP_LOCK="${LOCK_FILE}.tmp.$$"
jq \
    --arg version "$KERNEL_VERSION" \
    --arg url "$KERNEL_URL" \
    --arg src_sha256 "$KERNEL_SHA256" \
    --arg cfg_sha256 "$CONFIG_SHA256" \
    --arg vmlinux_sha256 "$VMLINUX_SHA256" \
    --arg rootfs_sha256 "$ROOTFS_SHA256" \
    --arg base_image_ref "$BASE_IMAGE_REF" \
    --arg apt_snapshot "$APT_SNAPSHOT" \
    '.guest_kernel.version = $version |
     .guest_kernel.source_url = $url |
     .guest_kernel.source_sha256 = $src_sha256 |
     .guest_kernel.config_sha256 = $cfg_sha256 |
     .guest_kernel.vmlinux_sha256 = $vmlinux_sha256 |
     .root_image.sha256 = $rootfs_sha256 |
     .root_image.base_image_ref = $base_image_ref |
     .root_image.apt_snapshot = $apt_snapshot' \
    "$LOCK_FILE" > "$TMP_LOCK"

mv "$TMP_LOCK" "$LOCK_FILE"

echo "[build-all] runtime.lock.json updated"

# ---------------------------------------------------------------------------
# Step 5: Print summary
# ---------------------------------------------------------------------------
echo ""
echo "[build-all] === BUILD COMPLETE ==="
echo "[build-all] kernel version:    $KERNEL_VERSION"
echo "[build-all] source sha256:     $KERNEL_SHA256"
echo "[build-all] config sha256:     $CONFIG_SHA256"
echo "[build-all] vmlinux sha256:    $VMLINUX_SHA256"
echo "[build-all] rootfs sha256:     $ROOTFS_SHA256"
echo "[build-all] base image:        $BASE_IMAGE_REF"
echo "[build-all] apt snapshot:      $APT_SNAPSHOT"
echo ""
echo "[build-all] Updated lock:"
cat "$LOCK_FILE"
