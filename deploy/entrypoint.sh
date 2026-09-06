#!/bin/bash
# ABOUTME: Container entrypoint: starts vmobs-privd as root, then vmobsd as the
# ABOUTME: vmobs user, and exits as soon as either of them does.
#
# Two processes, one container, because that is the privilege split the product
# is built around: privd holds the capabilities that launch a VM, and the
# control-plane daemon that talks to the network never has them. Collapsing them
# into one process to satisfy a container convention would throw away the
# boundary.
set -euo pipefail

CONFIG="${VMOBS_CONFIG:-/etc/vmobs/config.yaml}"
SOCKET=/run/vmobs/privd.sock
LEDGER=/run/vmobs/privd
VMOBS_UID=2389
VMOBS_GID=2389

log() { printf '%s vmobs-entrypoint: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

if [ "$(id -u)" -ne 0 ]; then
    log "must start as root: vmobs-privd holds the capabilities that launch a VM" >&2
    exit 1
fi

# privd's ledger is runtime state whose lifetime is one privd instance -- the
# same thing systemd's RuntimeDirectory= gives it on a bare-metal host. An entry
# that outlived its privd holds a jail uid, a guest CID and a subnet that no VM
# is using, and the next launch is refused as a collision.
rm -rf "$LEDGER"
install -d -o root -g root -m 0755 /run/vmobs "$LEDGER"

# Volumes mounted over these are empty on first use; a bind mount is empty every
# time. Create what is missing without touching what is already there, so a
# restart never rewrites a live state directory's ownership.
[ -d /var/lib/vmobs ] || install -d -o "$VMOBS_UID" -g "$VMOBS_GID" -m 0755 /var/lib/vmobs
[ -d /srv/vmobs/stage ] || install -d -o "$VMOBS_UID" -g "$VMOBS_GID" -m 0755 /srv/vmobs/stage
[ -d /srv/vmobs/jail ] || install -d -o root -g root -m 0755 /srv/vmobs/jail

# The probe inside privd measures the jailer's privileged operations before it
# serves, so a container missing a flag dies here with the flag named.
log "starting vmobs-privd"
/usr/local/sbin/vmobs-privd \
    --socket "$SOCKET" \
    --ledger-dir "$LEDGER" \
    --allowed-uid "$VMOBS_UID" \
    --allowed-gid "$VMOBS_GID" \
    --stage-root /srv/vmobs/stage \
    --jail-base /srv/vmobs/jail \
    --firecracker /usr/local/bin/firecracker \
    --jailer /usr/local/bin/jailer &
privd_pid=$!

# Wait for the socket rather than sleeping: the daemon's guest_channel preflight
# dials it, and a daemon that starts first reports a false failure.
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

# init-auth is a one-shot: it mints the first operator credential into the
# credential store and exits. It runs only when asked, because a config with
# require_authentication: false has nothing to mint against.
if [ "${1:-}" = "init-auth" ]; then
    shift
    log "minting the initial operator credential"
    exec setpriv --reuid "$VMOBS_UID" --regid "$VMOBS_GID" --init-groups -- \
        /usr/local/bin/vmobsd init-auth -config "$CONFIG" "$@"
fi

log "starting vmobsd as uid $VMOBS_UID"
setpriv --reuid "$VMOBS_UID" --regid "$VMOBS_GID" --init-groups -- \
    /usr/local/bin/vmobsd -config "$CONFIG" &
vmobsd_pid=$!

# Either process ending ends the container. A live daemon with a dead privd
# serves an API that refuses every launch, which reads as a vmobs bug; a live
# privd with a dead daemon serves nothing at all.
shutdown() {
    trap - TERM INT
    log "stopping"
    kill -TERM "$vmobsd_pid" "$privd_pid" 2>/dev/null || true
    wait "$vmobsd_pid" 2>/dev/null || true
    wait "$privd_pid" 2>/dev/null || true
}
trap 'shutdown; exit 0' TERM INT

set +e
wait -n "$privd_pid" "$vmobsd_pid"
first_status=$?
set -e
if kill -0 "$vmobsd_pid" 2>/dev/null; then
    log "vmobs-privd exited with status $first_status; stopping vmobsd"
else
    log "vmobsd exited with status $first_status; stopping vmobs-privd"
fi
shutdown
exit "$first_status"
