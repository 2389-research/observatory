# Guest Channel Protocol

Version 1. Describes the wire format, message types, and handshake sequence for the vsock channel between the Observatory host and a running guest (`guestd`).

## Wire framing

Every message is a frame. A frame begins with a 5-byte header:

```
[type:1 byte][length:4 bytes big-endian]
```

The length field is the byte count of the payload that follows. Length validation happens before allocation; a hostile large length value is rejected without allocating a buffer.

### Frame types

| Byte | Name     | Max payload |
|------|----------|-------------|
| 0x01 | Control  | 1 MiB       |
| 0x02 | PTY      | 256 KiB     |
| 0x03 | Artifact | 256 KiB     |

Unknown type bytes are rejected.

## Control frames

A Control frame carries a JSON `Envelope`:

```json
{"v": 1, "kind": "hello", "data": {...}}
```

`v` is the protocol version (currently `1`). `kind` names the message type. `data` holds the kind-specific payload.

### Message kinds

| Kind              | Direction      | Purpose                          |
|-------------------|----------------|----------------------------------|
| `hello`           | host → guest   | Establish identity, provide auth proof |
| `hello_ack`       | guest → host   | Accept or reject the hello       |
| `get_capabilities`| host → guest   | Request capability manifest      |
| `capabilities`    | guest → host   | Report kernel features           |
| `ping`            | either         | Liveness check                   |
| `pong`            | either         | Liveness reply                   |
| `error`           | either         | Typed error response             |

## Handshake sequence

```
host                           Firecracker            guest (guestd)
  |                               |                       |
  |-- connect to UDS socket ----→ |                       |
  |-- "CONNECT 10000\n" --------→ |                       |
  |←- "OK <hostport>\n" -------- |                       |
  |                               |--- vsock connect ----→|
  |                                                       |
  |-- hello (FrameControl) ----------------------------→ |
  |←- hello_ack (accepted: true) ----------------------- |
  |-- get_capabilities --------------------------------→ |
  |←- capabilities ------------------------------------ |
  |-- ping -------------------------------------------→ |
  |←- pong ------------------------------------------- |
  |                    (application protocol)             |
```

### Host CONNECT step (§7.3 [S3])

The host dials Firecracker's Unix domain socket and sends:

```
CONNECT <port>\n
```

Firecracker replies:

```
OK <hostport>\n
```

The host reads the OK line one byte at a time to a 64-byte cap. No buffered reader wraps the connection at this point; bytes after the newline belong to the application protocol and must not be consumed.

On any response other than an `OK`-prefixed line, the connection is closed and the dial returns an error.

### Hello (host → guest)

```json
{
  "protocol_version": 1,
  "vm_id": "<uuid>",
  "boot_id": "<uuid>",
  "source_instance": "<uuid>",
  "resume_cursor": "0",
  "auth_proof": "<per-boot token>"
}
```

`resume_cursor` is a decimal string (counter may exceed JS safe integer range).

`auth_proof` is the per-boot token the host minted into the config device. The guest compares it constant-time and answers `hello_ack`.

### Hello ack (guest → host)

```json
{"accepted": true}
```

Or, on rejection:

```json
{"accepted": false, "reason": "auth_proof mismatch"}
```

### Capabilities (guest → host)

```json
{
  "schema": "vmobs.guest_capability.v1",
  "kernel_release": "6.8.0-134-generic",
  "features": [
    {"id": "btf",                    "present": true,  "evidence": "/sys/kernel/btf/vmlinux"},
    {"id": "bpf_syscall",            "present": true,  "evidence": ""},
    {"id": "fanotify",               "present": true,  "evidence": ""},
    {"id": "fanotify_report_fid",    "present": true,  "evidence": ""},
    {"id": "cgroup_v2",              "present": true,  "evidence": "/sys/fs/cgroup/cgroup.controllers"},
    {"id": "devpts",                 "present": true,  "evidence": ""},
    {"id": "vsock",                  "present": true,  "evidence": ""},
    {"id": "virtio_net",             "present": true,  "evidence": ""},
    {"id": "virtio_blk",             "present": true,  "evidence": ""},
    {"id": "ext4",                   "present": true,  "evidence": ""}
  ]
}
```

M0 feature IDs: `btf`, `bpf_syscall`, `fanotify`, `fanotify_report_fid`, `cgroup_v2`, `devpts`, `vsock`, `virtio_net`, `virtio_blk`, `ext4`.

## Deadlines

| Phase             | Deadline |
|-------------------|----------|
| Full handshake    | 10 s     |
| Read idle         | 60 s     |
| Write             | 10 s     |

## Schema references

- `docs/schemas/guest-hello.schema.json` — `Hello` message
- `docs/schemas/guest-capability.schema.json` — `CapabilityManifest` message
