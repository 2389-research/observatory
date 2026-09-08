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
    # Preserve the explicit development override; the default always loads the
    # bundled policy before starting a confined container.
    case "$APPARMOR_PROFILE" in
        unconfined) ;;
        *) preflight_apparmor ;;
    esac
}

# preflight_apparmor distinguishes a missing host facility from an unloaded
# policy. The Compose loader replaces policy from the selected image at startup.
preflight_apparmor() {
    enabled=""
    [ -r /sys/module/apparmor/parameters/enabled ] && enabled="$(cat /sys/module/apparmor/parameters/enabled)"
    if [ "$enabled" != "Y" ]; then
        die "this host has no AppArmor enabled, so the profile cannot load.
  Enable AppArmor, or accept the weaker boundary and start with:
    VMOBS_APPARMOR_PROFILE=unconfined $PROG start
  (that drops the mount confinement; seccomp and the capabilities still apply.)"
    fi
}

# load_apparmor uses the exact Compose setup service with the caller's image.
# A failed loader stops startup; there is no host profile installation to repair.
load_apparmor() {
    [ "$APPARMOR_PROFILE" != unconfined ] || return 0
    note "loading AppArmor policy from $1"
    VMOBS_IMAGE="$1" docker compose -f "$REPO/compose.yaml" run --rm --no-deps apparmor \
        || die "AppArmor policy loading failed; the container was not started. See the Compose loader output above."
}
