#!/bin/bash
# ABOUTME: Compares the digests a guest image build produced against the pins in
# ABOUTME: runtime.lock.json, and only rewrites the lock when asked to --repin.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$REPO_ROOT/images/dist"
LOCK_FILE="$REPO_ROOT/runtime.lock.json"
REPIN=0

usage() {
    cat <<'USAGE'
usage: images/lock-pins.sh [--repin] [--dist DIR] [--lock PATH]

Reads the digests images/kernel/build.sh and images/rootfs/build.sh wrote to
kernel.pins and rootfs.pins, and compares them against runtime.lock.json.

  (default)   verify only; a disagreement is an error and the lock is not touched
  --repin     take the build's digests as the new pins and rewrite the lock

runtime.lock.json is an input to every install: it names the artifacts a host is
allowed to boot. A build that rewrites it turns a stranger's first command into
an uncommitted change. Repin deliberately, when you mean to move the pins.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --repin) REPIN=1; shift ;;
        --dist) DIST_DIR="$2"; shift 2 ;;
        --lock) LOCK_FILE="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[lock-pins] unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

command -v jq >/dev/null 2>&1 || {
    echo "[lock-pins] ERROR: jq is required" >&2
    exit 1
}

for pins in kernel.pins rootfs.pins; do
    if [ ! -f "$DIST_DIR/$pins" ]; then
        echo "[lock-pins] ERROR: $DIST_DIR/$pins not found — run images/build-all.sh first" >&2
        exit 1
    fi
done

# shellcheck source=images/dist/kernel.pins
. "$DIST_DIR/kernel.pins"
# shellcheck source=images/dist/rootfs.pins
. "$DIST_DIR/rootfs.pins"

# Pins describe artifacts. Digests with no file behind them would verify clean
# and leave the lock pointing at nothing.
for artifact in vmlinux rootfs.ext4; do
    if [ ! -f "$DIST_DIR/$artifact" ]; then
        echo "[lock-pins] ERROR: $artifact not found in $DIST_DIR — the build did not finish" >&2
        exit 1
    fi
done

if [ "$REPIN" -eq 0 ]; then
    mismatches=0
    check() {
        # $1 lock path, $2 built value, $3 label
        want=$(jq -r "$1 // \"\"" "$LOCK_FILE")
        if [ "$want" != "$2" ]; then
            echo "[lock-pins] MISMATCH $3" >&2
            echo "               lock: $want" >&2
            echo "              built: $2" >&2
            mismatches=$((mismatches + 1))
        fi
    }
    check '.guest_kernel.version' "$KERNEL_VERSION" 'guest_kernel.version'
    check '.guest_kernel.source_url' "$KERNEL_URL" 'guest_kernel.source_url'
    check '.guest_kernel.source_sha256' "$KERNEL_SHA256" 'guest_kernel.source_sha256'
    check '.guest_kernel.config_sha256' "$CONFIG_SHA256" 'guest_kernel.config_sha256'
    check '.guest_kernel.vmlinux_sha256' "$VMLINUX_SHA256" 'guest_kernel.vmlinux_sha256'
    check '.root_image.sha256' "$ROOTFS_SHA256" 'root_image.sha256'
    check '.root_image.base_image_ref' "$BASE_IMAGE_REF" 'root_image.base_image_ref'
    check '.root_image.apt_snapshot' "$APT_SNAPSHOT" 'root_image.apt_snapshot'

    if [ "$mismatches" -ne 0 ]; then
        echo "" >&2
        echo "[lock-pins] $mismatches pin(s) disagree with $LOCK_FILE." >&2
        echo "[lock-pins] If this build is the new truth, rerun with --repin and commit the lock." >&2
        exit 1
    fi
    echo "[lock-pins] build matches $LOCK_FILE"
    exit 0
fi

echo "[lock-pins] --repin: rewriting $LOCK_FILE from the build"
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

echo "[lock-pins] $LOCK_FILE repinned — commit it, and republish the artifacts:"
echo "               scripts/publish-guest-images"
