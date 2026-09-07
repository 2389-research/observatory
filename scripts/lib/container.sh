# ABOUTME: Shared boundary logic for the scripts that run vmobs in a container:
# ABOUTME: docker checks, revision/tag derivation, and the host preflight.
#
# Sourced, never executed. The caller sets REPO to the repository root and PROG
# to its own name so failures say which script refused. scripts/vmobs-container
# runs the appliance and scripts/vmobs-gate runs the acceptance gate; both have
# to hand docker the same capabilities, devices and profiles, so the checks in
# front of them live here rather than in two copies that drift.

: "${REPO:?scripts/lib/container.sh: set REPO before sourcing}"
PROG="${PROG:-vmobs}"

APPARMOR_PROFILE="${VMOBS_APPARMOR_PROFILE:-vmobs-jailer}"
SECCOMP_PROFILE="$REPO/deploy/seccomp/vmobs-jailer.json"

die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }
note() { printf '%s\n' "$*"; }

need_docker() {
    command -v docker >/dev/null 2>&1 || die "docker is not on PATH; see deploy/README.md"
    docker info >/dev/null 2>&1 || die "cannot talk to the docker daemon; is it running, and is this user in the docker group?"
}

# revision_for prints the commit this image is being built from, with "-dirty"
# appended when the tree it was built from had uncommitted changes.
#
# The environment is asked before git, and that order is the point: this script
# runs on the Linux host against a tree rsynced without .git (scripts/linux),
# where git can answer nothing. That wrapper carries the answer across in
# VMOBS_SOURCE_REVISION and VMOBS_SOURCE_DIRTY, the same pair the integration
# gate binds its evidence to. With neither source the revision is "unknown" --
# said out loud in the image, never guessed.
revision_for() {
    if [ -n "${VMOBS_SOURCE_REVISION:-}" ]; then
        if [ "${VMOBS_SOURCE_DIRTY:-0}" = "1" ]; then
            echo "$VMOBS_SOURCE_REVISION-dirty"
        else
            echo "$VMOBS_SOURCE_REVISION"
        fi
        return
    fi
    if git -C "$REPO" rev-parse HEAD >/dev/null 2>&1; then
        rev="$(git -C "$REPO" rev-parse HEAD)"
        if [ -n "$(git -C "$REPO" status --porcelain)" ]; then
            echo "$rev-dirty"
        else
            echo "$rev"
        fi
        return
    fi
    echo "unknown"
}

# tag_for prints the image tag: the short revision, "-dirty" when the tree was
# modified, and "local" when nothing can say what the tree is.
tag_for() {
    image="$1"
    rev="$(revision_for)"
    case "$rev" in
        unknown) echo "$image:local" ;;
        *-dirty) echo "$image:$(printf '%s' "${rev%-dirty}" | cut -c1-7)-dirty" ;;
        *)       echo "$image:$(printf '%s' "$rev" | cut -c1-7)" ;;
    esac
}

# require_guest_images fails before the docker build rather than 500 layers in.
# The guest kernel and root image are not in the checkout: they are downloaded
# against the digests in runtime.lock.json, or built from source when nothing has
# been published. `up` does that step; `build` names it rather than doing it
# behind your back.
require_guest_images() {
    for rel in images/dist/vmlinux images/dist/rootfs.ext4; do
        [ -f "$REPO/$rel" ] || die "missing $rel — get the guest images first:
    scripts/fetch-guest-images
  That downloads them and checks each against its pin in runtime.lock.json. If
  nothing has been published it says so and names images/build-all.sh, which
  compiles the guest kernel from source and takes a while."
    done
}

# preflight_host checks what docker cannot report clearly on its own. Each
# failure names the one thing to change; none of them is fixed silently.
preflight_host() {
    [ -c /dev/kvm ] || die "/dev/kvm is missing — this host cannot run VMs.
  Check that KVM is enabled in firmware and the kvm module is loaded (lsmod | grep kvm)."
    [ -c /dev/net/tun ] || die "/dev/net/tun is missing — load the tun module (modprobe tun)."
    [ -f "$SECCOMP_PROFILE" ] || die "missing $SECCOMP_PROFILE"
    # "unconfined" is docker's own reserved value for "no profile", so it names
    # no file and the file check cannot pass for it. It is how the container comes
    # up on a host where the profile has not been loaded yet -- loading it is root
    # work, and root work is a step an operator takes deliberately. It drops the
    # mount confinement, so cmd_start says so out loud rather than letting a
    # weaker boundary pass quietly for the shipped one.
    case "$APPARMOR_PROFILE" in
        unconfined) ;;
        *) preflight_apparmor ;;
    esac
}

# preflight_apparmor checks the two things docker's own error cannot separate:
# a host with no AppArmor at all, and a host whose loaded profile is older than
# the repo's.
#
# What the kernel actually holds is not readable here --
# /sys/kernel/security/apparmor/profiles is 0444 root-only -- so the comparison
# is against /etc/apparmor.d/<name>, the copy the host loads at boot. That is
# the honest check, and it catches the failure that costs the most: docker
# accepts any loaded profile by name, so a stale one starts cleanly and then
# denies a mount in the middle of a launch, minutes later and nowhere near the
# cause.
preflight_apparmor() {
    src="$REPO/deploy/apparmor/$APPARMOR_PROFILE"
    dest="/etc/apparmor.d/$APPARMOR_PROFILE"
    [ -f "$src" ] || die "missing deploy/apparmor/$APPARMOR_PROFILE"

    enabled=""
    [ -r /sys/module/apparmor/parameters/enabled ] && enabled="$(cat /sys/module/apparmor/parameters/enabled)"
    if [ "$enabled" != "Y" ]; then
        die "this host has no AppArmor enabled, so the profile cannot load.
  Enable AppArmor, or accept the weaker boundary and start with:
    VMOBS_APPARMOR_PROFILE=unconfined $PROG start
  (that drops the mount confinement; seccomp and the capabilities still apply.)"
    fi

    if [ ! -f "$dest" ]; then
        die "$APPARMOR_PROFILE is not installed at $dest, so this host does not load it at boot.
  Install and load it once, as root:
    sudo sh deploy/install-apparmor.sh"
    fi
    if ! cmp -s "$src" "$dest"; then
        die "the profile installed at $dest differs from deploy/apparmor/$APPARMOR_PROFILE.
  docker would accept the installed one by name and the difference would surface
  later, as a denied mount in the middle of a launch. Reload it, as root:
    sudo sh deploy/install-apparmor.sh"
    fi
}

