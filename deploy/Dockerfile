# ABOUTME: The vmobs appliance image: control-plane daemon, privilege daemon, runner,
# ABOUTME: pinned firecracker/jailer and the pinned guest kernel and root image.
#
# Every artifact in this image is pinned. The two base images are pinned by
# digest; firecracker and the jailer are downloaded and checked against
# runtime.lock.json; the guest kernel and root image are copied from the build
# context and checked against the same lock. A digest that moves fails the build
# rather than shipping something nobody chose.
#
# Build it through scripts/vmobs-container, which supplies the guest artifacts and
# the source revision. See deploy/README.md for the host prerequisites and the
# security profiles this image expects to run under.

# Resolved with: docker pull <tag> && docker inspect --format '{{index .RepoDigests 0}}' <tag>
# (aibox03, docker 27.2.1, 2026-09-06). The runtime base is the same digest
# runtime.lock.json pins for the guest root image: one Ubuntu, two roles.
ARG GO_IMAGE=golang@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36
ARG RUNTIME_IMAGE=ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517

# ---------------------------------------------------------------------------
# Stage 1: the Go binaries.
# ---------------------------------------------------------------------------
FROM ${GO_IMAGE} AS build
WORKDIR /src

# Modules first so a source-only change does not refetch them.
COPY go.mod go.sum ./
RUN go mod download

# Only what the three binaries compile from. web/ carries dist/, which
# web/embed.go embeds; the guest images and the docs never enter this stage.
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY web/ ./web/

# CGO off: modernc.org/sqlite is pure Go, so the binaries are static and the
# runtime stage needs no toolchain. -buildvcs=false because the build context
# carries no .git; the revision arrives as a build argument instead and is
# recorded in the image below.
RUN mkdir -p /out \
 && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/vmobsd ./cmd/vmobsd \
 && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/vmobs-runner ./cmd/vmobs-runner \
 && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/vmobs-privd ./cmd/vmobs-privd

# ---------------------------------------------------------------------------
# Stage 2: firecracker and the jailer, verified against the lock.
# ---------------------------------------------------------------------------
FROM ${RUNTIME_IMAGE} AS firecracker
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends ca-certificates curl jq \
 && rm -rf /var/lib/apt/lists/*
COPY runtime.lock.json /lock/runtime.lock.json
RUN set -eu; \
    ver="$(jq -r .firecracker.version /lock/runtime.lock.json)"; \
    url="$(jq -r .firecracker.release_url /lock/runtime.lock.json)"; \
    want_fc="$(jq -r .firecracker.sha256 /lock/runtime.lock.json)"; \
    want_j="$(jq -r .jailer.sha256 /lock/runtime.lock.json)"; \
    curl -fsSL "$url" -o /tmp/fc.tgz; \
    tar -xzf /tmp/fc.tgz -C /tmp; \
    fc="$(find /tmp -name "firecracker-$ver-x86_64" -type f)"; \
    j="$(find /tmp -name "jailer-$ver-x86_64" -type f)"; \
    echo "$want_fc  $fc" | sha256sum -c -; \
    echo "$want_j  $j"  | sha256sum -c -; \
    install -D -m 0755 "$fc" /out/firecracker; \
    install -D -m 0755 "$j"  /out/jailer

# ---------------------------------------------------------------------------
# Stage 3: the appliance.
# ---------------------------------------------------------------------------
FROM ${RUNTIME_IMAGE}

# iproute2 and nftables are the network verbs privd runs; e2fsprogs is mkfs.ext4,
# which the daemon runs to build each VM's config and workspace disks; jq reads
# the lock in the entrypoint. util-linux (setpriv) ships in the base image.
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends \
      iproute2 nftables e2fsprogs jq ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# The daemon's identity. Fixed ids so a state volume written by one build is
# readable by the next. 2389 sits below the jail uid range the root helper
# accepts ([10000,59999]), so it can never collide with a VM's uid. The
# vmobs-fixture group is gid 36000 because firecracker binds each VM's v.sock as
# that group and the daemon has to traverse it. The gid is fixed rather than
# allocated because the root helper the M0 fixture drives rejects a gid outside
# [10000,59999], and a --system group would land below 1000.
RUN groupadd --gid 36000 vmobs-fixture \
 && groupadd --gid 2389 vmobs \
 && useradd --uid 2389 --gid 2389 --groups vmobs-fixture --home-dir /var/lib/vmobs \
      --no-create-home --shell /usr/sbin/nologin vmobs

COPY --from=build /out/vmobsd /usr/local/bin/vmobsd
COPY --from=build /out/vmobs-runner /usr/local/bin/vmobs-runner
COPY --from=build /out/vmobs-privd /usr/local/sbin/vmobs-privd
COPY --from=firecracker /out/firecracker /usr/local/bin/firecracker
COPY --from=firecracker /out/jailer /usr/local/bin/jailer

# The lock's artifact paths are relative to the lock file's own directory
# (config.Runtime.ArtifactRoot), so the guest kernel and root image go beneath
# /opt/vmobs exactly as they sit in a checkout.
COPY runtime.lock.json /opt/vmobs/runtime.lock.json
COPY images/dist/vmlinux /opt/vmobs/images/dist/vmlinux
COPY images/dist/rootfs.ext4 /opt/vmobs/images/dist/rootfs.ext4

COPY deploy/config.yaml /etc/vmobs/config.yaml
COPY deploy/templates/ /etc/vmobs/templates/
COPY deploy/entrypoint.sh /usr/local/bin/vmobs-entrypoint

# Every pinned artifact, checked once, in the image that will use it. A build
# that gets this far cannot be serving bytes nobody pinned.
RUN set -eu; \
    lock=/opt/vmobs/runtime.lock.json; \
    check() { echo "$1  $2" | sha256sum -c -; }; \
    check "$(jq -r .firecracker.sha256 $lock)" /usr/local/bin/firecracker; \
    check "$(jq -r .jailer.sha256 $lock)" /usr/local/bin/jailer; \
    check "$(jq -r .guest_kernel.vmlinux_sha256 $lock)" "/opt/vmobs/$(jq -r .guest_kernel.vmlinux_path $lock)"; \
    check "$(jq -r .root_image.sha256 $lock)" "/opt/vmobs/$(jq -r .root_image.path $lock)"; \
    chmod 0755 /usr/local/bin/vmobs-entrypoint

# 0755 and root-owned: internal/lock's trusted-path walk refuses an artifact
# whose directory is world-writable, and refuses to follow a symlink into it.
RUN chown -R root:root /opt/vmobs /etc/vmobs \
 && chmod -R go-w /opt/vmobs /etc/vmobs

# The daemon's state and the jailer's chroots. Declared so a run without volumes
# still works (into the container's own layer) and a run with them mounts over
# these, ownership intact.
RUN install -d -o vmobs -g vmobs -m 0755 /var/lib/vmobs \
 && install -d -o root  -g root  -m 0755 /srv/vmobs \
 && install -d -o vmobs -g vmobs -m 0755 /srv/vmobs/stage \
 && install -d -o root  -g root  -m 0755 /srv/vmobs/jail \
 && install -d -o root  -g root  -m 0755 /run/vmobs

VOLUME ["/var/lib/vmobs", "/srv/vmobs"]

ARG SOURCE_REVISION=unknown
RUN printf '%s\n' "$SOURCE_REVISION" > /opt/vmobs/SOURCE_REVISION
LABEL org.opencontainers.image.title="vmobs appliance" \
      org.opencontainers.image.source="https://github.com/2389-research/observatory" \
      org.opencontainers.image.revision="${SOURCE_REVISION}"

# Root, because vmobs-privd is the process that holds the privileges. It drops to
# the vmobs user for the control-plane daemon itself; see deploy/entrypoint.sh.
ENTRYPOINT ["/usr/local/bin/vmobs-entrypoint"]
