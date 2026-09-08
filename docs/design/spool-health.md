# Spool import health

The daemon keeps one current diagnostic record per spool directory it sees, plus
one for reading the root directory. These records describe this process's own
attempts. Restart reports `unknown` until a cycle runs; a successful empty cycle
reports `healthy` and updates `last_success_at`. Directories removed from the
root leave the live map after the next successful directory walk.

`GET /api/v1/telemetry/import` returns the root record.
`GET /api/v1/vms/{id}/telemetry/import` returns an owner-scoped VM record. Both
are fixed-size responses with `state`, `last_error`, `consecutive_failures`,
`last_success_at`, and `next_retry_at`. Errors stop at 512 Unicode characters;
counters are saturating decimal strings. An absent success timestamp means no
successful cycle has been observed, not a timestamp of zero. The route table
publishes both endpoints under the `telemetry_import` feature.

A failed root read or VM import degrades the existing VM `telemetry_health`
response even when the guest's most recent heartbeat is fresh. Sensor counts
still come from the heartbeat. The root record describes directory discovery,
not an aggregate assertion that every VM imported successfully.

The engine binds its configured trigger, duplicate-collapse and queue limits to
the importer. With the trigger enabled, the first failure in an episode raises
existing `telemetry_degraded` attention
with the diagnostic endpoint and an instruction to inspect spool permissions,
cursor, or storage availability. Further retries update the live record without
raising more events. Successful import resets the episode. Attention remains
historical evidence until the operator acknowledges it; recovery does not
pretend the operator acknowledged a fault. Queue overflow counts as delivery,
so a full queue does not produce a new overflow event every retry. If SQLite
itself is unavailable, the live diagnostic remains readable and attention is
retried after storage returns. No new event kind is emitted.

The background loop backs off each failed VM independently, doubling its poll
interval up to one minute. Healthy VMs continue on the normal poll interval.
Root discovery failures use the same cap. An explicit `ImportOnce` always
attempts work; it returns an error for any failed VM while preserving totals for
records that did commit. Context cancellation does not start or increment an
incident.

Store and cursor failures stop the affected VM before later segments can move
its cursor past missing evidence. Recovery-handled corruption retains its
existing gap evidence behavior. The ordering remains store commit, cursor
write, then prune. Retry deduplicates already committed records. This change
does not claim to make filesystem calls interruptible or persist live retry
counters across daemon restarts.

Portable tests use actual spool files, SQLite, and HTTP. They cover mixed and
all-VM failures, repeated failures, empty success, recovery, attention
coalescing, capped retries, a closed store, and a failed cursor write followed by
replay. Service tests verify that a fresh guest heartbeat cannot hide an import
failure. These tests make no Linux/KVM outage-reproduction claim.
