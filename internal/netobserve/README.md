This package decodes IPv4 Linux conntrack and NFLOG datagrams and bounds one
collector's flow/sequence history. On Linux, `OpenConntrack` opens and subscribes
a current-namespace socket and requests the initial snapshot with NET_ADMIN;
`OpenNFLog` binds an explicit nonzero current-namespace group, limits packet copies
to 128 bytes and enables local sequence reporting. It does not configure policy,
resolve DNS, write events or provide an integrated live collector.

`OpenNFLog` caps setup at two seconds, validates the kernel ACK for group binding
and configuration, refuses an owned group, and closes the socket after any setup
failure. Closing the caller-owned descriptor releases its group. Namespace and
group allocation still belong to privd. Live readers must validate kernel sender
identity and `MSG_TRUNC`, match each NFLOG record to the immutable returned group,
and correlate conntrack dump replies with their request sequence before passing
`snapshot=true`. Feed one complete datagram to `ParseConntrack` or `ParseNFLog`.
If traffic queues a packet before the NFLOG setup ACK, acquisition fails and
closes the socket; recovery must report unknown loss or quiesce the source before
retrying rather than claim a healthy handoff.
Empty ACK/NOOP/DONE replies produce no observation; malformed data, kernel errors,
overrun and interrupted dumps return explicit errors. Parsers reject datagrams
above 1 MiB. Call `Tracker.ReadError` for receive or decode failures.

Create one `Tracker` per immutable `Scope`; serialize access. `Generation` names
the owned network allocation/acquisition, `BootID` is the guest boot, and
`HostBootID` is the kernel boot. Use a new tracker on socket/source replacement,
with an explicit restart/loss record in the durable event layer. Never recover
past starts from a conntrack dump. `Expire` and eviction discard local history;
they do not claim a kernel flow ended. `StartObserved` means this collector saw
NEW, not that TCP established. Flow ID reuse is separated by original tuple and
zone. Missing identity leaves the observation uncorrelated.

NFLOG is not itself a denial verdict. Bind its group/prefix to an installed
policy rule before publishing `policy.denial`. The parser retains no raw packet
bytes. Short copies, malformed packets and noninitial fragments preserve unknown
transport fields. `CapturedLength` is the copied size; `OriginalLength` is the
IPv4 header's stated length when available. Neither is an aggregate firewall
counter. Track aggregate policy counters independently from retained log records.
Only local NFLOG sequence gaps yield measured missing-record counts; global
sequence may span other groups. Sequence reset/duplicate, kernel overrun and
read failures report unknown loss size. State eviction/expiration counts refer
to forgotten tracking entries, not missing packets.

Numeric pointers distinguish absent evidence from zero. These structs are an
internal API, not a browser JSON schema: encode 64-bit counters/timestamps as
decimal strings at the durable event boundary. Persist normalized observations
through the existing runner writer/importer. Keep health/loss capacity reserved
outside noisy flow queues and propagate spool failures into coverage.

Fixtures are explicitly encoded Linux UAPI messages, not captured real-kernel
acceptance evidence. Definitions:

- https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/netfilter/nfnetlink_conntrack.h
- https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/netfilter/nfnetlink_log.h
- https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/netfilter/nfnetlink.h
- https://docs.kernel.org/netlink/specs/conntrack.html

Run `go test -race ./internal/netobserve`, `go vet ./internal/netobserve` and
`golangci-lint run ./internal/netobserve/...` for package checks. The repository's
`scripts/check` and real confined Linux/KVM acceptance remain required for the
integrated collector.
