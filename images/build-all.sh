#!/bin/bash
# ABOUTME: Orchestrates the full guest image pipeline: kernel build + rootfs build, then
# ABOUTME: checks the computed sha256s against the pins in runtime.lock.json.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$REPO_ROOT/images/dist"
LOCK_FILE="$REPO_ROOT/runtime.lock.json"
LOG_DIR="$DIST_DIR/logs"
REPIN=()

while [ $# -gt 0 ]; do
    case "$1" in
        --repin) REPIN=(--repin); shift ;;
        -h|--help)
            echo "usage: images/build-all.sh [--repin]"
            echo ""
            echo "Builds the guest kernel and root image, then checks the result against"
            echo "the pins in runtime.lock.json. --repin rewrites those pins instead, for"
            echo "a deliberate kernel or snapshot bump; commit the lock afterwards."
            exit 0 ;;
        *) echo "[build-all] unknown argument: $1" >&2; exit 2 ;;
    esac
done

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
# Step 3: Check the build against runtime.lock.json
# ---------------------------------------------------------------------------
echo "[build-all] === STEP 3: pins ==="
bash "$SCRIPT_DIR/lock-pins.sh" --dist "$DIST_DIR" --lock "$LOCK_FILE" "${REPIN[@]+"${REPIN[@]}"}"

# ---------------------------------------------------------------------------
# Step 4: Print summary
# ---------------------------------------------------------------------------
# shellcheck source=images/dist/kernel.pins
. "$DIST_DIR/kernel.pins"
# shellcheck source=images/dist/rootfs.pins
. "$DIST_DIR/rootfs.pins"

echo ""
echo "[build-all] === BUILD COMPLETE ==="
echo "[build-all] kernel version:    $KERNEL_VERSION"
echo "[build-all] source sha256:     $KERNEL_SHA256"
echo "[build-all] config sha256:     $CONFIG_SHA256"
echo "[build-all] vmlinux sha256:    $VMLINUX_SHA256"
echo "[build-all] rootfs sha256:     $ROOTFS_SHA256"
echo "[build-all] base image:        $BASE_IMAGE_REF"
echo "[build-all] apt snapshot:      $APT_SNAPSHOT"
