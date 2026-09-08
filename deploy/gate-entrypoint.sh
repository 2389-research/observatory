#!/bin/bash
# ABOUTME: Gate container entrypoint: builds and starts vmobs-privd, then runs the
# ABOUTME: acceptance gate as the operator's own uid against the mounted checkout.
#
# Everything the old host installer did to a machine, done here to a container
# that `docker run --rm` throws away: the fixture group, the root helper's
# sudoers grant, the /srv/vmobs tree, and privd itself. Nothing survives the run,
# and no operator machine is touched.
#
# The gate runs as the uid that owns the bind-mounted checkout rather than as
# root. It writes evidence into the checkout, so a different uid could not; and
# privd's --allowed-uid is a real check that the gate should be passing honestly
# rather than sidestepping by running as root.
set -euo pipefail

SRC="${VMOBS_GATE_SRC:-/src}"
SOCKET=/run/vmobs/privd.sock
LEDGER=/run/vmobs/privd
BUILD_DIR=/run/vmobs-gate-build
UID_WANTED="${VMOBS_GATE_UID:?VMOBS_GATE_UID not set; scripts/vmobs-gate supplies it}"
GID_WANTED="${VMOBS_GATE_GID:?VMOBS_GATE_GID not set; scripts/vmobs-gate supplies it}"

log() { printf '%s vmobs-gate: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

if [ "$(id -u)" -ne 0 ]; then
    log "must start as root: the gate's privd holds the capabilities that launch a VM" >&2
    exit 1
fi
if [ "$UID_WANTED" -eq 0 ]; then
    log "refusing to run the gate as root: privd's --allowed-uid check would never be exercised" >&2
    exit 1
fi
if [ ! -d "$SRC" ]; then
    log "no checkout at $SRC; scripts/vmobs-gate bind-mounts one there" >&2
    exit 1
fi

# The operator's identity, recreated inside the container so the bind-mounted
# checkout stays writable and `sudo` has a user to grant to. The base image
# already ships a uid 1000, which is the commonest operator uid there is, so
# reuse whatever is already there rather than failing on the collision.
if ! getent group "$GID_WANTED" >/dev/null; then
    groupadd --gid "$GID_WANTED" gate
fi
gate_group="$(getent group "$GID_WANTED" | cut -d: -f1)"
if ! getent passwd "$UID_WANTED" >/dev/null; then
    useradd --uid "$UID_WANTED" --gid "$GID_WANTED" --no-create-home \
        --home-dir "$SRC" --shell /bin/bash gate
fi
gate_user="$(getent passwd "$UID_WANTED" | cut -d: -f1)"
log "gate runs as $gate_user:$gate_group ($UID_WANTED:$GID_WANTED)"

# The fixture group exists in the appliance image at the fixed gid 36000 that the
# root helper's [10000,59999] range requires; the operator has to be in it to
# traverse each VM's v.sock.
usermod -aG vmobs-fixture "$gate_user"

# The one sudo grant the M0 boot fixture needs, scoped to a single binary with no
# arguments of the caller's choosing beyond the helper's own verbs.
printf '%s ALL=(root) NOPASSWD: /usr/local/sbin/vmobs-root-helper\n' "$gate_user" \
    > /etc/sudoers.d/vmobs-fixture
chmod 0440 /etc/sudoers.d/vmobs-fixture
visudo -cf /etc/sudoers.d/vmobs-fixture >/dev/null

# Same reasoning as deploy/entrypoint.sh: /dev/kvm keeps the host's gid inside
# the container and that gid has no name here, so setpriv --init-groups has
# nothing to pick up. Without this the arch_kvm preflight fails and takes every
# launch with it.
if [ -c /dev/kvm ]; then
    kvm_gid="$(stat -c %g /dev/kvm)"
    kvm_group="$(getent group "$kvm_gid" | cut -d: -f1 || true)"
    if [ -z "$kvm_group" ]; then
        kvm_group=host-kvm
        groupadd --gid "$kvm_gid" "$kvm_group"
    fi
    usermod -aG "$kvm_group" "$gate_user"
else
    log "/dev/kvm is absent; the arch_kvm preflight will fail and every launch with it" >&2
fi

# The /srv/vmobs layout the gate asserts against. The appliance image creates
# stage and jail; fixture is the M0 boot fixture's staging area, and both it and
# stage belong to the operator because the daemon and the fixture write there.
rm -rf "$LEDGER"
install -d -o root -g root -m 0755 /run/vmobs "$LEDGER"
install -d -o root -g root -m 0755 /srv/vmobs /srv/vmobs/jail
install -d -o "$UID_WANTED" -g "$GID_WANTED" -m 0755 /srv/vmobs/stage
install -d -o "$UID_WANTED" -g vmobs-fixture -m 0775 /srv/vmobs/fixture
install -d -o "$UID_WANTED" -g "$GID_WANTED" -m 0755 "${GOCACHE:-/gocache}"

# privd comes from the checkout under test, not from the appliance image. A gate
# that ran the image's privd would report on whatever was compiled weeks ago --
# every privd change would look verified while never having been run.
#
# It builds as the gate uid, not as root. The build cache is a named volume
# shared with the test run that follows, and a root-written cache entry is one
# the gate user cannot overwrite -- `go test` then dies at setup with a bare
# "permission denied" naming a hash, which says nothing about who wrote it.
log "building vmobs-privd from $SRC"
install -d -o "$UID_WANTED" -g "$GID_WANTED" -m 0700 "$BUILD_DIR"
setpriv --reuid "$UID_WANTED" --regid "$GID_WANTED" --init-groups \
    env HOME="$SRC" sh -c 'cd "$0" && exec go build -o "$1"/vmobs-privd ./cmd/vmobs-privd' \
    "$SRC" "$BUILD_DIR"
install -o root -g root -m 0755 "$BUILD_DIR/vmobs-privd" /usr/local/sbin/vmobs-privd

log "starting vmobs-privd"
/usr/local/sbin/vmobs-privd \
    --socket "$SOCKET" \
    --ledger-dir "$LEDGER" \
    --allowed-uid "$UID_WANTED" \
    --allowed-gid "$GID_WANTED" \
    --stage-root /srv/vmobs/stage \
    --jail-base /srv/vmobs/jail \
    --firecracker /usr/local/bin/firecracker \
    --jailer /usr/local/bin/jailer &
privd_pid=$!

for _ in $(seq 1 100); do
    [ -S "$SOCKET" ] && break
    if ! kill -0 "$privd_pid" 2>/dev/null; then
        wait "$privd_pid" || true
        log "vmobs-privd exited before it bound $SOCKET; see the lines above for the reason" >&2
        exit 1
    fi
    sleep 0.1
done
if [ ! -S "$SOCKET" ]; then
    log "vmobs-privd did not bind $SOCKET within 10s" >&2
    kill "$privd_pid" 2>/dev/null || true
    exit 1
fi

# VMOBS_FIXTURE=1 is the gate's own guard, and inside this container the fixture
# genuinely is present -- privd is up, the tree is staged, the helper is granted.
# The capability bounding set is deliberately left alone: the M0 boot fixture
# reaches root through sudo, and a root with no capabilities cannot run `ip netns
# add`.
log "running: $*"
set +e
setpriv --reuid "$UID_WANTED" --regid "$GID_WANTED" --init-groups \
    env HOME="$SRC" VMOBS_FIXTURE=1 \
    sh -c 'cd "$0" || exit 1; exec "$@"' "$SRC" "$@"
status=$?
set -e

log "gate exited with status $status; stopping vmobs-privd"
kill -TERM "$privd_pid" 2>/dev/null || true
wait "$privd_pid" 2>/dev/null || true
exit "$status"
