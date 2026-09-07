#!/bin/sh
# ABOUTME: Install and load the vmobs-jailer AppArmor profile. Run as root:
# ABOUTME:   sudo sh deploy/install-apparmor.sh
#
# This is the one root step the appliance needs, and it is deliberately its own
# script rather than something scripts/vmobs-container does for you: loading a
# kernel security profile is not a side effect an ordinary start should have.
#
# It does two things, and the second is the one that is easy to skip.
# apparmor_parser loads a profile into the running kernel and leaves nothing on
# disk, so a profile loaded straight out of the checkout is gone after a reboot
# and `docker run --security-opt apparmor=vmobs-jailer` then fails outright.
# Installing it under /etc/apparmor.d is what makes the host load it at boot.
#
# Run it again whenever deploy/apparmor/vmobs-jailer changes. scripts/vmobs-container
# compares the two copies before it starts anything and names this script when
# they differ.
set -eu

cd "$(dirname "$0")/.."
REPO="$(pwd)"

NAME="${VMOBS_APPARMOR_PROFILE:-vmobs-jailer}"
SRC="$REPO/deploy/apparmor/$NAME"
DEST="/etc/apparmor.d/$NAME"

die() { printf 'install-apparmor: %s\n' "$*" >&2; exit 1; }

[ -f "$SRC" ] || die "missing $SRC"
[ "$(id -u)" = 0 ] || die "must run as root: sudo sh deploy/install-apparmor.sh"
[ -r /sys/module/apparmor/parameters/enabled ] && [ "$(cat /sys/module/apparmor/parameters/enabled)" = "Y" ] ||
    die "AppArmor is not enabled on this host (/sys/module/apparmor/parameters/enabled is not Y).
  Enable it, or accept the weaker boundary and start with:
    VMOBS_APPARMOR_PROFILE=unconfined scripts/vmobs-container start"
command -v apparmor_parser >/dev/null 2>&1 || die "apparmor_parser is not on PATH; install the apparmor package"

# Install before loading: loading first would parse whatever copy was already
# there, and report success for the profile the operator was trying to replace.
install -o root -g root -m 0644 "$SRC" "$DEST"
apparmor_parser -r -W "$DEST"

printf 'installed and loaded %s (%s)\n' "$NAME" "$DEST"
printf 'it now loads at boot; run this again whenever deploy/apparmor/%s changes\n' "$NAME"
