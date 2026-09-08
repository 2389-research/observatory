#!/bin/bash
# ABOUTME: Builds a minimal Ubuntu 24.04 root filesystem image (rootfs.ext4) with
# ABOUTME: vmobs-guestd pre-installed; uses pinned docker image and apt snapshot for reproducibility.
set -euo pipefail

# ---------------------------------------------------------------------------
# Paths — run from anywhere inside the repo
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DIST_DIR="$REPO_ROOT/images/dist"
LOG_DIR="$DIST_DIR/logs"
LOG="$LOG_DIR/rootfs.log"

mkdir -p "$DIST_DIR" "$LOG_DIR"

# Redirect everything to log and stdout
exec > >(tee -a "$LOG") 2>&1

echo "[rootfs/build.sh] started $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[rootfs/build.sh] repo root: $REPO_ROOT"

# ---------------------------------------------------------------------------
# Load pins
# ---------------------------------------------------------------------------
PINS_ENV="$SCRIPT_DIR/pins.env"
# shellcheck source=images/rootfs/pins.env
. "$PINS_ENV"
# BASE_IMAGE_REF and APT_SNAPSHOT now set

echo "[rootfs/build.sh] base image: $BASE_IMAGE_REF"
echo "[rootfs/build.sh] apt snapshot: $APT_SNAPSHOT"

# ---------------------------------------------------------------------------
# Build vmobs-guestd (linux/amd64, no cgo) from repo tree on this host.
# Runs on aibox03 (linux/amd64) where go is available.
# ---------------------------------------------------------------------------
GUESTD_STAGING="$DIST_DIR/rootfs-staging"
GUESTD_BIN="$GUESTD_STAGING/usr/local/bin/vmobs-guestd"

echo "[rootfs/build.sh] building vmobs-guestd..."
mkdir -p "$(dirname "$GUESTD_BIN")"
(
    cd "$REPO_ROOT"
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
        -o "$GUESTD_BIN" \
        ./cmd/vmobs-guestd
)
echo "[rootfs/build.sh] guestd sha256: $(sha256sum "$GUESTD_BIN" | awk '{print $1}')"

# ---------------------------------------------------------------------------
# Pull base image
# ---------------------------------------------------------------------------
echo "[rootfs/build.sh] pulling $BASE_IMAGE_REF ..."
docker pull --quiet "$BASE_IMAGE_REF"

# ---------------------------------------------------------------------------
# Build rootfs in a named docker container (no --rm, so we can export it)
# ---------------------------------------------------------------------------
CONTAINER_NAME="vmobs-rootfs-$$"
UNPACK_DIR="$DIST_DIR/rootfs-unpacked"
ROOTFS_OUT="$DIST_DIR/rootfs.ext4"
INVENTORY_OUT="$DIST_DIR/rootfs.inventory.txt"

# Clean up any leftover container from a previous failed run
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

# Remove the previous inventory so the post-run emptiness check cannot pass
# on a stale file if the container script dies early.
rm -f "$INVENTORY_OUT"

echo "[rootfs/build.sh] starting rootfs container: $CONTAINER_NAME"

# Run without --rm so we can docker export after completion.
# Mount $DIST_DIR so the container can write the inventory directly.
# QUOTING: the container script below is ONE host-side double-quoted string.
# ${VARS} expand on the host even inside inner single quotes. A raw " inside
# the script terminates the string and silently truncates the script — use
# single quotes or \" only.
docker run --name "$CONTAINER_NAME" \
    -v "$SCRIPT_DIR/guestd.service":/build/guestd.service:ro \
    -v "$GUESTD_BIN":/build/vmobs-guestd:ro \
    -v "$DIST_DIR":/build/dist \
    "$BASE_IMAGE_REF" \
    bash -euo pipefail -c "
set -euo pipefail

echo '[rootfs] installing ca-certificates (live apt — needed for snapshot TLS)...'
apt-get update -qq
apt-get install -y --no-install-recommends ca-certificates 2>&1 | tail -3

echo '[rootfs] updating package index from snapshot ${APT_SNAPSHOT} ...'
apt-get -S ${APT_SNAPSHOT} update -qq

echo '[rootfs] installing packages from snapshot...'
apt-get -S ${APT_SNAPSHOT} install -y --no-install-recommends \
    systemd-sysv udev dbus \
    vim-tiny \
    2>&1 | tail -8

echo '[rootfs] copying vmobs-guestd...'
cp /build/vmobs-guestd /usr/local/bin/vmobs-guestd
chmod 755 /usr/local/bin/vmobs-guestd

echo '[rootfs] installing guestd.service...'
install -Dm644 /build/guestd.service /etc/systemd/system/guestd.service
mkdir -p /etc/systemd/system/multi-user.target.wants
ln -sf /etc/systemd/system/guestd.service \
    /etc/systemd/system/multi-user.target.wants/guestd.service

echo '[rootfs] writing fstab...'
mkdir -p /workspace
printf '/dev/vda / ext4 defaults 0 1\n/dev/vdc /workspace ext4 defaults 0 2\n' > /etc/fstab

echo '[rootfs] writing hostname...'
echo 'vmobs-guest' > /etc/hostname

echo '[rootfs] clearing machine-id (generated on first boot)...'
truncate -s 0 /etc/machine-id 2>/dev/null || true
truncate -s 0 /var/lib/dbus/machine-id 2>/dev/null || true

echo '[rootfs] recording package inventory...'
dpkg -l > /build/dist/rootfs.inventory.txt
echo \"[rootfs] inventory: \$(wc -l < /build/dist/rootfs.inventory.txt) lines\"
"

echo "[rootfs/build.sh] container finished. exporting filesystem..."
rm -rf "$UNPACK_DIR"
mkdir -p "$UNPACK_DIR"
docker export "$CONTAINER_NAME" | tar -xf - -C "$UNPACK_DIR"
echo "[rootfs/build.sh] export complete."

echo "[rootfs/build.sh] removing container..."
docker rm -f "$CONTAINER_NAME"

# Verify inventory
if [ ! -s "$INVENTORY_OUT" ]; then
    echo "[rootfs/build.sh] ERROR: inventory file is empty — build may have failed" >&2
    exit 1
fi
echo "[rootfs/build.sh] inventory: $(wc -l < "$INVENTORY_OUT") lines → $INVENTORY_OUT"

# The image's whole purpose is shipping guestd; refuse to mkfs without it.
if [ ! -x "$UNPACK_DIR/usr/local/bin/vmobs-guestd" ]; then
    echo "[rootfs/build.sh] ERROR: vmobs-guestd missing from unpacked tree — container script did not complete" >&2
    exit 1
fi
if [ ! -f "$UNPACK_DIR/etc/systemd/system/guestd.service" ]; then
    echo "[rootfs/build.sh] ERROR: guestd.service missing from unpacked tree" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Build ext4 image — exactly 1G; fail loudly if tree doesn't fit
# ---------------------------------------------------------------------------
echo "[rootfs/build.sh] building rootfs.ext4 (1G)..."
rm -f "$ROOTFS_OUT"

# mkfs.ext4 -d <dir> populates the image from a directory tree (no root needed)
if ! mkfs.ext4 -d "$UNPACK_DIR" -L vmobs-root "$ROOTFS_OUT" 1G; then
    echo "[rootfs/build.sh] ERROR: mkfs.ext4 failed — tree may be too large for 1G" >&2
    exit 1
fi

echo "[rootfs/build.sh] ext4 file size: $(du -sh "$ROOTFS_OUT" | cut -f1)"

# ---------------------------------------------------------------------------
# Compute sha256 and write pins
# ---------------------------------------------------------------------------
ROOTFS_SHA256=$(sha256sum "$ROOTFS_OUT" | awk '{print $1}')

echo "[rootfs/build.sh] === ROOTFS BUILD COMPLETE ==="
echo "[rootfs/build.sh] rootfs sha256: $ROOTFS_SHA256"
echo "[rootfs/build.sh] rootfs size:   $(du -sh "$ROOTFS_OUT" | cut -f1)"
echo "[rootfs/build.sh] inventory:     $INVENTORY_OUT"
echo "[rootfs/build.sh] log:           $LOG"

cat > "$DIST_DIR/rootfs.pins" <<EOF
ROOTFS_SHA256=${ROOTFS_SHA256}
BASE_IMAGE_REF=${BASE_IMAGE_REF}
APT_SNAPSHOT=${APT_SNAPSHOT}
EOF

echo "[rootfs/build.sh] pins written to $DIST_DIR/rootfs.pins"
