# Credential lifetime and durable publication

Token lifetimes use one maximum: `auth.MaxTokenTTLMinutes`, currently
153722867 minutes, the largest whole-minute duration that fits Go's signed
64-bit nanosecond duration. The API and CLI validate integers before multiplying.
Omitted and zero values remain permanent. Negative and larger positive values
fail before minting: HTTP 400 with `validation_failed / ttl_invalid`, or a CLI
usage error. JSON integers outside int64 fail as `malformed_request /
body_invalid`. Direct store calls also reject negative durations and durations
above that same whole-minute maximum; shorter positive durations remain valid.

Credentials publish through `internal/durable.WriteFile`: write a private
temporary file, sync its bytes and mode, close it, rename it, then sync its
directory. Initial credential directories use `durable.MkdirAll` to sync newly
created directory entries. Every directory call repeats ancestor barriers,
including ancestors already visible after a failed call in another process.
An ancestor that cannot be opened or synced prevents acknowledgement; a retry
must repair that failure rather than infer durability from existence.
Credential files remain 0600; the credential
directory remains 0700.

A failed barrier means the operation was not acknowledged. In particular, a
post-rename directory failure can leave a new token or revocation visible even
though the caller received an error. Mint returns no secret in that case; the
operator can list and revoke the resulting unusable token record. Revocation
retries always republish the recorded state with all barriers, including when
`RevokedAt` is already present. Reopening the store cannot turn an unsettled
visible revocation into a successful acknowledgement.

The tests exercise actual permission failures using a 0300 directory, where
write and rename succeed but opening the directory for its barrier fails.
Those tests skip when running as root because root bypasses the permission
check. HTTP tests verify storage failure responses on both the first revocation
and retry, followed by success after restoring permissions and rejection of
the revoked credential.

Subprocess tests kill the process after acknowledged operator initialization,
mint and revocation, then reopen and check passwords, token validity and private
permissions. These establish survival of a process crash. They do not establish
power-loss behavior: the kernel's page cache survives a process kill. The
durability guarantee relies on the filesystem and storage honoring sync
barriers; tmpfs cannot preserve credentials across reboot.

The store still assumes one service owns its credential directory. Its mutex
serializes token mutation within that store instance; cross-process writers
remain outside the supported model.
