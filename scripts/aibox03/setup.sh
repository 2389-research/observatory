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

echo "setup complete: kvm+vmobs-fixture groups (re-login needed), firecracker $ver, helper+sudoers installed"
