# Spool import health

The daemon keeps one current diagnostic record per spool directory it sees, plus
one for reading the root directory. These records describe this process's own
attempts. Restart reports `unknown` until a cycle runs; a successful empty cycle
reports `healthy` and updates `last_success_at`. Directories removed from the
root leave the live map after the next successful directory walk.

`GET /api/v1/telemetry/import` returns the root record.
`GET /api/v1/vms/{id}/telemetry/import` returns an owner-scoped VM record. Both
are fixed-size responses with `state`, `last_error`, `consecutive_failures`,
`last_success_at`, and `next_retry_at`; the VM record adds `writer`, the health
of that VM's spool writer (below). Errors stop at 512 Unicode characters;
counters are saturating decimal strings. An absent success timestamp means no
successful cycle has been observed, not a timestamp of zero. The route table
publishes both endpoints under the `telemetry_import` feature.

A failed root read or VM import degrades the existing VM `telemetry_health`
response even when the guest's most recent heartbeat is fresh, and so does a
spool writer that reads `failing`. Sensor counts
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
retried after storage returns. Import and writer health raise only this
attention and emit no event kind of their own; the loss a failing writer causes
is recorded as `telemetry.loss` (below).

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

## Spool writer health

The runner's spool writer keeps its health in `writer.status` in the VM's spool
directory. The file is exactly 4096 bytes: the body's length and its CRC-32C,
each a big-endian uint32, then a JSON body of at most 4088 bytes, then zeros.
When the body would be longer, the writer halves `cause` and `last_error` by
characters until it fits, and writes nothing if it does not fit with both
empty. Recovery and the spool quota look only at `.vmsp` files, so they never
touch it.

Each new writer zeroes the file and fsyncs it before it creates its first
segment, then writes `healthy` under its own instance id once that segment
exists, so a writer that cannot create its first segment leaves a file that
reads `unknown`. Every
refused append rewrites the file as `failing`, a loss record that lands
rewrites it as `healthy`, and `Close` writes the final status: `healthy`
unless the outage is still open after `Close` tried to record it. Each update
overwrites all 4096 bytes in place without an fsync, and the writer ignores
its errors: the status is advisory, and the `telemetry.loss` record is the
durable evidence.

The VM record's `writer` holds `state`, `since`, `cause`, `last_error`,
`runner_records_refused`, `guest_pushes_refused`, `updated_at`, and
`instance_id`. Times are UTC event timestamps; counts are decimal strings.

- `healthy`: the writer refuses nothing. `since` is when it opened or last
  recorded a loss, both counts are `"0"`, and `cause` and `last_error` are
  empty.
- `failing`: the writer has an open outage. It refuses every record it cannot
  make durable and tries again on each append. `since`, `cause` (the first
  refusal's error) and the counts describe the outage; `last_error` is the
  newest refusal's error, up to 512 characters.
- `unknown`: there is no status file, or no intact frame in it: a short file,
  a zero or impossible length, a bad checksum, bad JSON, or a state the writer
  never writes. A read that races an overwrite reads `unknown` too. Every other
  field is empty, and `unknown` degrades nothing.

The importer reads each VM directory's status on every cycle that lists the
spool root, including cycles in which that VM's import is backing off, so an
outage shows on the next cycle. `writer` is the last status read, or
`unknown` before the first; a directory that leaves the root drops its entry,
and the root record has no `writer`. With the `telemetry_degraded` trigger
enabled, the first `failing` read of an outage raises attention with the VM's
diagnostic endpoint as evidence and a suggestion to free space or repair
permissions on the spool filesystem. The importer tells outages apart by
`since`: a failed raise is retried next cycle, a new `since` raises again, a
`healthy` read ends the outage, and an `unknown` read changes nothing. With
duplicate collapse on, a writer outage and an import failure on one VM fold
into one open item, which keeps the summary of whichever raised first.

The first append that succeeds after refusals writes the outage's
`telemetry.loss` record ahead of its own record, and `Close` writes one when
an outage is still open. Its data holds `cause`, `interval_start`,
`interval_end`, `runner_records_refused` and `guest_pushes_refused` (decimal
strings), and `guest_events_lost`: `"0"`, or `"unknown"` once any guest push
was refused. The caveats below follow `internal/events/registry.go`'s entry
for `telemetry.loss`:

1. An unknown-span loss must not be summed as zero events lost.
2. `guest_pushes_refused` counts refused push attempts. The guest re-sends
   what it never saw acknowledged, so one event can be refused more than once
   and still arrive.
3. `guest_events_lost` is `"unknown"` whenever a guest push was refused: the
   guest's bounded ring may have overwritten events it held, and its
   heartbeat's dropped counter reports how many.
4. `runner_records_refused` is an upper bound: a record whose fsync failed may
   still reach the store when the writer could not trim it from the segment,
   or when the importer read it first.
5. A loss record whose fsync failed may still reach the store while its outage
   stays open, so `telemetry.loss` records from one `source_instance_id` that
   share an `interval_start` describe one outage. The one with the highest
   `source_seq` counts every refusal the others count, and has the latest
   `interval_end` unless the clock stepped back. They must not be summed.
6. `interval_start` and `interval_end` are wall-clock readings: a clock step
   during the outage skews the interval and can put `interval_end` before
   `interval_start`. The record keeps both as the clock read them.
7. The counts describe what the runner's spool refused, not loss elsewhere in
   the pipeline.

Writer health has known limits. On a copy-on-write filesystem such as APFS,
btrfs or ZFS, an overwrite in place needs new blocks, so on a full disk the status
overwrite can fail, and so can a segment's end-marker write. The file then
keeps an older status and can read `healthy` while the writer refuses records.
A loss the old writer could not record at `Close` survives only in
`runner.log` once the next writer resets the status file. Two runners that
share a spool directory across a stop and start both write the file, which
shows whichever wrote last; `instance_id` tells them apart.

## Tests

Portable tests use actual spool files, SQLite, and HTTP. They cover mixed and
all-VM failures, repeated failures, empty success, recovery, attention
coalescing, capped retries, a closed store, and a failed cursor write followed by
replay. Service tests verify that a fresh guest heartbeat cannot hide an import
failure. Writer health tests cover a missing, short, zeroed or corrupt status
file, the file's size after each update, halving an overlong cause, a writer
that fails to open, one attention per outage, and a status that stays current
while the import backs off. These tests make no Linux/KVM outage-reproduction
claim.
