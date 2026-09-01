#!/bin/sh
# ABOUTME: One-time root setup for aibox03 as the vmobs L0 host. Run as:
# ABOUTME:   cd ~/vmobs-build && sudo sh scripts/aibox03/setup.sh
set -eu
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

# 1. Tools the pipeline needs on the host.
apt-get install -y --no-install-recommends jq e2fsprogs >/dev/null

# 2. KVM access + fixture group.
usermod -aG kvm harper
# Fixed gid 36000: the root helper validates gid in [10000,59999]; a --system
# group would land below 1000 and be rejected at jail-start.
if ! getent group vmobs-fixture >/dev/null; then
  getent group 36000 >/dev/null && { echo "gid 36000 taken; edit setup.sh" >&2; exit 1; }
  groupadd --gid 36000 vmobs-fixture
fi
usermod -aG vmobs-fixture harper

# 3. Pinned firecracker + jailer, hash-verified against runtime.lock.json.
lock="$repo/runtime.lock.json"
ver="$(jq -r .firecracker.version "$lock")"
url="$(jq -r .firecracker.release_url "$lock")"
want_fc="$(jq -r .firecracker.sha256 "$lock")"
want_j="$(jq -r .jailer.sha256 "$lock")"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$url" -o "$tmp/fc.tgz"
tar -xzf "$tmp/fc.tgz" -C "$tmp"
fc="$(find "$tmp" -name "firecracker-$ver-x86_64" -type f)"
j="$(find "$tmp" -name "jailer-$ver-x86_64" -type f)"
echo "$want_fc  $fc" | sha256sum -c - >/dev/null
echo "$want_j  $j"  | sha256sum -c - >/dev/null
install -o root -g root -m 0755 "$fc" /usr/local/bin/firecracker
install -o root -g root -m 0755 "$j" /usr/local/bin/jailer

# 4. Root helper + narrow sudoers.
install -o root -g root -m 0755 "$here/vmobs-root-helper" /usr/local/sbin/vmobs-root-helper
visudo -cf "$here/sudoers-vmobs" >/dev/null || { echo "sudoers fragment invalid" >&2; exit 1; }
install -o root -g root -m 0440 "$here/sudoers-vmobs" /etc/sudoers.d/vmobs-fixture

# 5. Fixture directories.
install -d -o harper -g vmobs-fixture -m 0775 /srv/vmobs /srv/vmobs/fixture
install -d -o root -g root -m 0755 /srv/vmobs/jail

# 6. vmobs-privd daemon.
go_bin="$(command -v go || true)"
if [ -z "$go_bin" ] && [ -n "${SUDO_USER:-}" ]; then
  go_bin="$(ls -d "/home/$SUDO_USER/.local/share/mise/installs/go/"[0-9]*.[0-9]*.[0-9]*/bin/go 2>/dev/null | sort -V | tail -1 || true)"
fi
[ -n "$go_bin" ] || { echo "go not found in PATH or operator mise installs; add go to PATH" >&2; exit 1; }
"$go_bin" build -o /usr/local/sbin/vmobs-privd "$repo/cmd/vmobs-privd"

# Substitute the invoking user's uid/gid into the unit before installing.
# setup.sh is run via `sudo sh`, so SUDO_UID/SUDO_GID carry the real operator identity.
: "${SUDO_UID:?SUDO_UID not set; run via sudo sh setup.sh}"
: "${SUDO_GID:?SUDO_GID not set; run via sudo sh setup.sh}"
sed \
  -e "s/__ALLOWED_UID__/$SUDO_UID/g" \
  -e "s/__ALLOWED_GID__/$SUDO_GID/g" \
  "$here/vmobs-privd.service" \
  > /etc/systemd/system/vmobs-privd.service

# stage directory owned by the operator user so vmobsd can drop artifacts there.
install -d -o "$SUDO_UID" -g "$SUDO_GID" -m 0755 /srv/vmobs/stage

systemctl daemon-reload
systemctl enable --now vmobs-privd

# Verify the unit came up and the socket exists.
systemctl is-active vmobs-privd || { echo "vmobs-privd failed to start; check: journalctl -u vmobs-privd" >&2; exit 1; }
[ -S /run/vmobs/privd.sock ] || { echo "privd.sock absent after start" >&2; exit 1; }

echo "setup complete: kvm+vmobs-fixture groups (re-login needed), firecracker $ver, helper+sudoers installed, vmobs-privd running"
