# Kata 19g4: spool writer recovery implementation plan

> **For agentic workers:** Execute with subagent-driven-development, one task at a time, in the order below. Each `### Task N` section is that task's entire brief; read the code it names before changing it. The SDD workspace's constraints.md travels with every dispatch.

**Goal:** A runner whose spool write fails keeps refusing what it cannot make durable, resumes by itself once the filesystem accepts writes, records the gap as a `telemetry.loss` event, and tells the operator while the failure lasts. The branch also fixes a new boot reusing segment names the import cursor has passed (losing its first records) and the importer's Recover truncating or rejecting the segment the writer is appending to.

**Architecture:** All state stays in the VM's spool dir, shared by the runner and vmobsd. The writer abandons a damaged segment instead of itself: the next append opens the next segment, whose first record is a `telemetry.loss` describing the refusals. A preallocated `writer.status` file carries the writer's health to the importer, which serves it on the existing `/telemetry/import` records and raises `telemetry_degraded` attention.

**Tech stack:** Go, SQLite (the store), real files and HTTP in tests; hdiutil (darwin) or tmpfs (Linux, root) for the full-disk test.

**Kata:** 19g4 (P1). Done when "a test on a real filesystem that runs out of space poisons the writer, frees the space, and sees the next append land in a new segment behind an explicit loss record; the importer imports both segments; and an operator can read the cause from the API while it persists."

## Why

On aibox03 the root LV filled at 2026-09-20 02:08 UTC and had space again by 05:26. The importer recovered. The runner of the one live VM, werwwrewer (`99da283e`, boot `4637c97a`), did not: `spool.Writer` set a sticky `poison` on the ENOSPC, and every append since has failed with the original error. The store has recorded nothing since event 96952, while guestd keeps heartbeating. The operator sees `telemetry_health: degraded` and an attention that names the importer's cursor write, the one failure that recovered. The cause that persists lives only in `runner.log` inside the container.

The poison's comment gives its reason: after a failed fsync the kernel may drop dirty pages and clear the error, so a later fsync on the same file can succeed although earlier bytes never reached disk. That reason condemns the file, not the writer. A new segment has no such history.

Checking the fix turned up two more ways the same code loses events:

- A new boot after a prune reuses segment names the import cursor has passed, and the importer skips the new boot's first records as already committed. A throwaway probe measured it: boot A wrote 3 records, boot B wrote 4, and the store kept 1 of B's.
- The importer's `Recover` truncates any segment with a torn tail and fails on any header it cannot read, the newest segment included, and the runner may be writing that segment at that moment.

## Spec authority

- SPEC §12.4 (docs/SPEC.md:707): "Segment files have a versioned header, bounded records, checksums and an end marker. Recovery tolerates an unacknowledged truncated trailing record, rejects corrupt interior records, and emits a recovery/gap record. Sync directory metadata when required to make a newly created segment durable. Do not acknowledge merely because bytes reached an in-memory channel."
- SPEC §12.5 (:713): "Report measured drops where possible and unknown intervals otherwise. Do not invent a numerical drop count for an unobservable crash interval."
- SPEC §12.5 (:715): "Default overflow policy is `degrade`: preserve host safety and control responsiveness, emit an explicit loss interval, and continue according to configured capture priorities. Lifecycle/security/health records have a separately reserved path so an event flood cannot hide its own loss indefinitely."
- SPEC §12.5 (:719): "On low host disk: reject new launches, close optional content capture, preserve reserved health/control space, then stop/pause affected runs according to policy before general filesystem exhaustion. Do not silently disable persistence while continuing to acknowledge durable events."
- SPEC failure table (:1018): "Spool/disk fills | Stop acknowledging undurable data; preserve control/health reserve; degrade or stop per policy."
- The branch feeds these acceptance rows and closes none of them:
  - AT-017 (R-09): "Fill a workspace and event spool. Guest/storage-specific failure does not exhaust the host system filesystem or another VM's disk."
  - AT-045 (R-05, R-12): "Overflow fanotify and eBPF queues deliberately. Loss health records and visible degraded coverage appear, with unknown counts represented as unknown."
  - AT-073 (R-04, R-09): "Saturate one VM's spool/index stream while others run. Fair ingestion and bounded memory hold; every loss/truncation policy is visible."

## Global constraints

- Work in the main checkout on branch `fix/19g4-spool-writer-recovery`. No worktree. Never switch branches. Never push.
- Run Go as `env -u GOROOT mise exec -- go …`. Before reporting DONE, run the gate `env -u GOROOT mise exec -- scripts/check` and quote its last lines in the report.
- TDD: write the test first, run it, and capture the RED failure text (the failing assertion's message) for the report. Then make it pass.
- Tests use real files, real SQLite, real HTTP and real failures (closed fds, read-only dirs, a quota, a real full filesystem). No mocks. Never wire the fake runtime into anything served.
- Counters that can exceed JS safe integers are decimal strings in JSON. "unknown" beats a guessed number.
- New hand-written files start with two `// ABOUTME: ` lines that say what the file does.
- Match the surrounding style. Comments say what and why, never what changed or how it used to work.
- Only a `--- PASS` line is evidence. A skipped test proves nothing; say so when yours skipped.
- Do not touch aibox03, docker, any deploy or any remote. Never read or print token files.
- Commit your own task: run `git status`, `git add` the files by path (never `-A`), and commit with the message the task gives. Never `--no-verify`; when a hook fails, fix the cause and commit again.
- Never edit PLAN.md, gotchas.md or anything under docs/superpowers/plans/.
- Write the full report to the path the dispatch gives. Return only: status, commit hashes, a one-line test summary, and concerns.

## Known limitations (katas to file after the branch)

1. A segment without an end marker that is no longer the newest is never pruned, and the importer counts its records again every cycle. A runner crash, a failed retire or a respawned runner leaves one behind.
2. The importer stops a VM's import for good on a seq/payload conflict for a real record; only gap envelopes treat `ErrIntegrityFailure` as a duplicate. Task 3 removes one way to reach it.
3. A recovery-gap envelope's `SourceSeq` is the segment's position in the sorted list, so a prune shifts it. Changing it needs a new dedup namespace.
4. Runner lifecycle and health records share the quota with guest pushes; SPEC §12.5 asks for a reserved path. Only the loss record is exempt.
5. On copy-on-write filesystems (APFS, btrfs, ZFS) the `writer.status` overwrite and the end-marker write can fail on a full disk.
6. A loss frame whose fsync failed can still reach the store, leaving two `telemetry.loss` records with the same `interval_start`; the later one covers the earlier.
7. A guest push near the 64 KiB payload limit may pass the 256 KiB frame limit once JSON escapes `<`, `>` and `&` as six bytes each. The runner would then refuse it on every resend and the stream would stall. Unverified: check before filing.
8. A loss the old writer could not record at Close survives only in `runner.log` once the next writer resets `writer.status`.
9. Two runners sharing a spool dir during a stop/start overlap: unverified.
10. On filesystems that keep small files inline (ext4 `inline_data`), an outage could leave header-only segments behind.
11. Linux ENOSPC evidence (tmpfs, as root) waits for approval to run on a Linux host.

## Rulings

- Ruling: the main checkout, no worktree — Doctor Biz's standing rule for day-to-day work — a stray edit lands in the working tree, where `git status` shows it.
- Ruling: merge a green branch to main without asking; push only with approval — a push to main publishes `:latest` — none; both are standing instructions.
- Ruling: the cross-boot fix goes in this branch (Task 1) — it loses events on every boot after a prune, and Task 2 rewrites the same function — a larger branch to review.
- Ruling: a resend reuses the refused envelope (Task 3) — without it, Task 2's fsync-failure path can stall a VM's import on a seq/payload conflict — one more task.
- Ruling: the Recover race folds into Task 4 — Task 2 makes segment creation routine, which makes the race common — none.
- Ruling: the writer's attention uses `telemetry_degraded` — the class already exists and the operator already acts on it — a separate class would be easier to filter.
- Ruling: the writer's health goes on the existing `/telemetry/import` records — one place to look, no new route — a crowded record.
- Ruling: a marshal error or an oversize record is not an outage — it rejects one record for its content, and the spool is fine — such a record leaves no loss record (the caller still sees the error).
- Ruling: the importer reads only pattern-named segments (`seg-` + 16 digits + `.vmsp`) — the writer makes no other name, and Task 2's tests use a `ballast.vmsp` to fill the quota — a hand-made segment with another name is never imported.
- Ruling: fixtures that planted a header-less "broken" segment are replanted as `seg-0000000000000000.vmsp` holding `broken\n` — after Task 4 a header without a newline is a creation in progress, and only a complete but unparseable line is corruption — none.
- Ruling: an invalid cursor fails OpenWriter — loud beats a silent name reuse — a VM whose `cursor.json` is corrupt cannot start until someone repairs or removes it.
- Ruling: a failed advance marks the current segment damaged — the writer then never appends to a segment that may have a higher-numbered sibling, which Task 4's Recover treats as finished and may truncate — one extra segment creation per outage.
- Ruling: a non-newest segment with an incomplete header is removed — no writer will ever finish it — a second writer on the same dir (limitation 9) could lose a creation in progress.
- Ruling: no aibox03; darwin hdiutil is the full-disk evidence and Linux waits — aibox03 runs a live user VM and root work there needs approval — the Linux path compiles but is unproven.
- Ruling: Task 6 lives in `internal/api` — the Done-when's last clause is read over real HTTP — a test that crosses four packages.
- Ruling: `boundRunes` is shared with health.go — one source for the 512-rune bound — none.
- Ruling: models — T1 sonnet, T2 opus, T3 sonnet, T4 sonnet, T5 opus, T6 sonnet; reviewers opus for T2 and T5, sonnet otherwise; the final review on opus.

## Session state

- 2026-09-23: plan written at f1bf1f2; no task started.

### Task 1: Never reuse a segment name the import cursor has passed

**Context.** The importer (`importVM` in `internal/spool/importer.go`) classifies each segment by comparing its file name with the cursor's `segment`, in string order. A name below the cursor is PAST: its records count as committed, and a closed one is pruned. The cursor's own name is CURRENT: import resumes at `record+1`. A name above is FUTURE: import starts at 0. The importer writes `cursor.json` after each record commits and prunes a closed segment once it has read it to the end, so the cursor goes on naming a segment that is gone from disk.

`nextSegmentIndex` (`internal/spool/writer.go`) picks a new writer's first index from the directory listing alone. A new boot (a new runner and writer on the same spool dir) after a prune finds an empty directory and starts again at `seg-0000000000000000.vmsp`:

- When the cursor names `seg-0000000000000000.vmsp`, the new segment is CURRENT, and its first `record+1` records are skipped as already committed although they are new events. A throwaway probe measured it: boot A wrote 3 records, boot B wrote 4; B's import returned `{Appended:1 Deduped:3 Pruned:1}` and the store kept 1 of B's 4.
- When boot A rotated to `seg-0000000000000002.vmsp` before the prune, B's `seg-0000000000000000.vmsp` sorts below the cursor, so it is PAST: every record is skipped and the segment is pruned unread.
- A stray name that sorts last (`zz-stray.vmsp`) makes `fmt.Sscanf` fail and resets the index to 0.

The runner and vmobsd (the importer) run as the same uid and share the spool dir `<state>/spool/<vmid>`, which holds `cursor.json`.

**Files**

- Modify: `internal/spool/writer.go`, `internal/spool/importer.go`
- Create: `internal/spool/segment_index_test.go` (package `spool_test`), `internal/spool/segment_name_test.go` (package `spool`)

**Change**

1. Add, beside the segment code in `writer.go`:
   - `parseSegmentName(name string) (uint64, bool)`: true only for exactly `seg-` + 16 ASCII digits + `.vmsp` (25 bytes). Check the length, prefix, suffix and each digit byte by hand, then `strconv.ParseUint`. Do not use `fmt.Sscanf`, which accepts a sign and leading spaces.
   - `segmentName(idx uint64) string`, returning `fmt.Sprintf("seg-%016d.vmsp", idx)`. `openSegment` uses it.
   - A constant for the highest index, 9999999999999999. `openSegment` refuses a higher index with `fmt.Errorf("spool: segment index %d exceeds the 16-digit name space", idx)` before creating anything: a 17-digit name would sort before every 16-digit name and be pruned as PAST.
2. Move `(*Importer).loadCursor` to a package function `readCursor(vmDir string) (cursor, error)` with the same behavior and error text. `importVM` calls it.
3. Rewrite `nextSegmentIndex(dir)`:
   1. List `dir` first; a missing dir is empty. Take the highest index among entries that are not directories and whose names `parseSegmentName` accepts. Ignore every other name.
   2. Then call `readCursor(dir)`. An error returns `fmt.Errorf("read import cursor: %w", err)`. A cursor whose `Segment` is non-empty and not a segment name returns `fmt.Errorf("import cursor names %q, which is not a segment name", c.Segment)`. A valid cursor's index joins the maximum.
   3. Return the maximum plus one, or 0 when neither the listing nor the cursor names a segment.
   4. Say in a comment why the listing comes before the cursor: the importer commits, then writes the cursor, then prunes. A segment missing from the earlier listing was pruned after the cursor named it, so the cursor read afterwards names it. Read in the other order, a prune between the two reads could hide the segment from both.
4. `OpenWriter` keeps its wrapper `spool: scan dir for next segment index: %w` and creates no file when `nextSegmentIndex` fails.

Tests that turn `cursor.json` into a directory (`internal/spool/import_health_test.go`) open no writer afterwards, so this change should not touch them. If one fails, stop and report; do not loosen `readCursor`.

**Tests** (RED first; capture each failure message)

In `segment_index_test.go`, use `openTestStore`, `makeSpoolEnvelope` and `countEvents` from `importer_test.go`, and import with `spool.NewImporter(st, root, time.Second, nil).ImportOnce(ctx)`. Each boot uses its own lowercase-UUID instance id in its envelopes.

- `TestNewBootAfterPruneImportsEveryRecord`: boot A opens a writer on `root/<vm>`, appends 3 records and closes. Import, and assert `seg-0000000000000000.vmsp` was pruned. Boot B opens a new writer on the same dir, appends 4 records and closes. Before importing, assert B's segment is `seg-0000000000000001.vmsp`. Import; `countEvents` for B's instance is 4. RED today: 1.
- `TestNewBootAfterRotatedPruneImportsEveryRecord`: boot A's `MaxSegmentBytes` is small enough that its records span exactly three segments; assert the listing shows `seg-…0000` through `seg-…0002` before importing rather than trusting arithmetic. Import (all three are pruned). Boot B's first segment is `seg-0000000000000003.vmsp`, and all 4 of its records import. RED today: 0.
- `TestStraySpoolFileDoesNotResetSegmentIndex`: plant files named `seg-0000000000000004.vmsp` and `zz-stray.vmsp`; the new writer creates `seg-0000000000000005.vmsp`. RED today: `seg-0000000000000000.vmsp`.
- `TestInvalidCursorFailsOpenWriter`: `cursor.json` holds `not json`. OpenWriter fails with an error containing `read import cursor`, and no `.vmsp` file exists afterwards.
- `TestCursorNamingANonSegmentFailsOpenWriter`: `cursor.json` holds `{"segment":"notes.txt","record":0}`. The error contains `import cursor names "notes.txt"`, and no `.vmsp` file is created.
- `TestSegmentIndexCeiling`: plant `seg-9999999999999999.vmsp`. OpenWriter fails with the 16-digit error and creates no other `.vmsp` file.

In `segment_name_test.go`, `TestParseSegmentName` is a table:

- accepts `seg-0000000000000000.vmsp` (0), `seg-0000000000000042.vmsp` (42) and `seg-9999999999999999.vmsp` (9999999999999999), and `segmentName` of each index returns the same name;
- rejects `seg-000000000000001.vmsp` (15 digits), `seg-00000000000000001.vmsp` (17 digits), `seg-000000000000000a.vmsp`, `seg-+000000000000001.vmsp`, `seg- 000000000000001.vmsp`, `seg-0000000000000001.vmsp.tmp`, `bad.vmsp`, `SEG-0000000000000001.vmsp` and the empty string.

**Commit:** `fix(spool): never reuse a segment name the import cursor has passed`

### Task 2: The writer abandons a damaged segment, not itself, and records the loss

**Context.** `Writer` (`internal/spool/writer.go`) sets a sticky `poison` on the first failed write or fsync, and every later `Append` returns it. Its comment gives the reason: after a failed fsync the kernel may drop dirty pages and clear the error, so a later fsync on the same file can succeed although earlier bytes never reached disk. That reason condemns the file, not the writer; a new segment has no such history. On aibox03 one ENOSPC on 2026-09-20 silenced a live VM's runner for the rest of its boot, although space came back three hours later.

SPEC §12.5: "Default overflow policy is `degrade`: preserve host safety and control responsiveness, emit an explicit loss interval, and continue according to configured capture priorities." And: "Do not invent a numerical drop count for an unobservable crash interval."

The runner never acks a record the spool refused: `serveTelemetry` (`internal/runner/telemetry.go`) returns on a spool error, and the guest keeps unacked events in its bounded ring and resends them on the next connection. So the writer must refuse what it cannot make durable, try again on every `Append`, and once an `Append` succeeds, first write a `telemetry.loss` record that describes what it refused.

**Files**

- Modify: `internal/spool/writer.go` (put `Outage` there or in a new `internal/spool/outage.go`).
- Modify: `internal/spool/segment.go`. The package doc drops its "Task 7" and "Task 8" references. `ErrSpoolFull`'s doc says the writer counts the refusal and records it in a `telemetry.loss` once an append succeeds, so the caller's only duty is to withhold the ack.
- Modify: `internal/spool/health.go`, so `record()` bounds `LastError` with the shared helper below.
- Modify: `internal/events/registry.go`, adding the `telemetry.loss` caveats below.
- Modify: `internal/runner/runner.go`: the `LossRecord` closure, and the comment on `appendChannelEstablished`, which still describes the poison.
- Modify: every `spool.WriterCfg{` literal in `internal/spool/spool_test.go`, `internal/spool/importer_test.go` and `internal/spool/segment_index_test.go` (`git grep -n 'WriterCfg{'` finds them all), through a helper in `spool_test.go`: `lossRecordFor(vmID string) func(spool.Outage) *events.Envelope`. It builds `telemetry.loss`, `events.HostObserved`, Sensor `"runner"`, the given VMID, a fixed lowercase-UUID `SourceInstanceID`, a `SourceSeq` from a package-level atomic counter (decimal string, starting at 1), not-applicable quality, and `Data: o.Data()`.
- Modify: `internal/runner/telemetry_test.go` (the runner test below).
- Delete: `internal/spool/writer_poison_test.go`. Its behavior is gone; its closed-fd technique moves to the new tests.
- Create: `internal/spool/writer_recovery_test.go` (package `spool`, white-box).

**API**

```go
// Outage describes an interval in which the writer refused records.
type Outage struct {
	Since, Until         time.Time
	Cause                string // the first refusal's error, bounded to 512 runes
	RunnerRecordsRefused uint64 // refused envelopes whose Provenance is not guest_reported
	GuestPushesRefused   uint64 // refused envelopes whose Provenance is guest_reported
}

// Data returns the telemetry.loss payload.
func (o Outage) Data() map[string]any
```

`Data` returns string values only:

- `"cause"`: `o.Cause`
- `"interval_start"` and `"interval_end"`: `o.Since` and `o.Until` in UTC, formatted with `events.TimestampLayout`
- `"runner_records_refused"` and `"guest_pushes_refused"`: decimal strings
- `"guest_events_lost"`: `"0"` when `GuestPushesRefused` is 0, else `"unknown"`. The guest's bounded ring may have overwritten events while the runner refused them, and SPEC §12.5 forbids inventing a count.

`WriterCfg` gains a required field:

```go
// LossRecord builds the telemetry.loss envelope for an outage. The writer
// calls it while holding its lock, so it must not call the Writer.
LossRecord func(Outage) *events.Envelope
```

`OpenWriter` fails with `spool: WriterCfg.LossRecord is required` when it is nil, after the `MaxSegmentBytes` check and before touching the directory.

**Writer state.** Replace `poison` with:

- `damaged bool`: the current segment may hold bytes that failed to become durable, and nothing more will be written to it;
- `outage *Outage`: open while refusals are unrecorded;
- `closed bool`.

Invariant: `damaged` implies an open outage.

**Append(env)**, in order:

1. When closed, return `spool: append after close`. Not counted.
2. `json.Marshal` and the 256 KiB frame check keep their error texts. Not counted: they reject one record for its content, and the spool is fine.
3. A `spoolTotalBytes` error is a refusal (`spool: measure spool size: %w`). When `totalNow + recordFrame > maxSpool`, refuse with `ErrSpoolFull`. The quota counts the record's frame only; the loss frame is exempt, so a full quota can still record its own loss (the reserved path of §12.5).
4. When an outage is open, copy it, set `Until` to now, and call `cfg.LossRecord` with the copy. Frame its envelope exactly like a record. A nil envelope is a refusal (`spool: LossRecord returned nil`), a marshal failure is a refusal (`spool: marshal loss record: %w`), and a body over the frame limit is a refusal (`spool: loss record body %d bytes exceeds 256 KiB frame limit`).
5. When `damaged`, or when `segBytes + lossFrame + recordFrame > MaxSegmentBytes`, call `advance()`. Its error is a refusal, and it also calls `damage()`, so the writer never again writes to a segment that a failed create may have left a higher-numbered file beside.
6. When a loss frame was built, write it and fsync. On failure call `damage()` and refuse (`spool: write loss record: %w`, `spool: fsync after loss record: %w`). On success add its size to `segBytes` and clear the outage.
7. Write the record's frame and fsync. On failure call `damage()` and refuse (`spool: write record: %w`, `spool: fsync after record: %w`); this opens a new outage when step 6 cleared the old one. On success add its size to `segBytes` and return nil.

**refuse(env, err) error.** Open the outage when none is open: `Since` is now, and `Cause` is the error text bounded to 512 runes. Count `GuestPushesRefused` when `env.Provenance == events.GuestReported`, else `RunnerRecordsRefused`, saturating at the maximum `uint64`. Return `err` unchanged, so `errors.Is(err, ErrSpoolFull)` and `errors.Is(err, syscall.ENOSPC)` keep working. Each failed `Append` counts exactly once.

**boundRunes.** One helper, `boundRunes(s string, n int) string`, which keeps the first `n` runes, and one constant for 512. `refuse` and health.go's `record()` both use them.

**damage().** Set `damaged`, then, best effort, `f.Truncate(segBytes)` and `f.Sync()`, ignoring both errors. The segment is abandoned either way, and `retireSegment` trims it again.

**advance().**

1. Increment `segIdx` first. That burns the index, so a failed attempt never retries a name that may exist on disk.
2. Call `createSegment()` (rename `openSegment`). It keeps today's error texts, and on any failure after the `O_EXCL` create it closes and removes its file.
3. Only on success: keep the old file and its `segBytes`, switch to the new segment, clear `damaged`, then call `retireSegment(old, oldSize)` and ignore its error. The old segment's records are already durable; a missing marker only makes recovery read it as crashed.

Normal rotation uses `advance()` too.

**retireSegment(f \*os.File, size int64) error.** It works on any file, damaged or not:

1. `f.Truncate(size)`, or `spool: trim segment before end marker: %w`;
2. `f.WriteAt(marker, size)`, or `spool: write end marker: %w`;
3. `f.Sync()`, or `spool: fsync end marker: %w`.

Stop at the first failure. Always close `f`. Return the first error, or the `Close` error unwrapped when all three steps succeeded. The trim matters because a damaged segment may hold a partial or unsynced frame past `size`, and the marker must follow the last durable record.

**Close().**

- A second call returns nil. Set `closed`.
- When an outage is open, try once to write its loss frame on its own (`Until` is now), advancing first when `damaged` or when the frame does not fit. Success clears the outage.
- Retire the current segment with `retireSegment(f, segBytes)`. After a failed advance this is still the damaged segment, and the retire trims it.
- When the outage is still open, return `fmt.Errorf("spool: loss since %s not recorded: %d runner records and %d guest pushes refused; first cause: %s", ...)`, with `Since` formatted by `events.TimestampLayout`, joined by `errors.Join` with any retire error. Otherwise return the retire error. The runner already logs a Close error to its stderr, which is `runner.log`.

**Runner.** In `internal/runner/runner.go`:

```go
LossRecord: func(o spool.Outage) *events.Envelope {
	return r.newEnvelope("telemetry.loss", o.Data())
},
```

`newEnvelope` takes the next seq from an atomic counter and takes no lock, so the writer may call it under its own lock. Rewrite the comment on `appendChannelEstablished` to say the writer records refused appends as a `telemetry.loss` once an append succeeds.

**Registry.** Add these caveats to `telemetry.loss` in `internal/events/registry.go`, verbatim, and keep the existing one:

- `guest_pushes_refused counts refused push attempts; the guest re-sends what it never saw acknowledged, so one event can be refused more than once and still arrive`
- `guest_events_lost is "unknown" whenever a guest push was refused: the guest's bounded ring may have overwritten events it held, and its heartbeat's dropped counter reports how many`
- `runner_records_refused is an upper bound: a record whose fsync failed may still reach the store when the writer could not trim it from the segment, or when the importer read it first`
- `the counts describe what the runner's spool refused, not loss elsewhere in the pipeline`

**Tests** (RED first where the behavior is new; real files throughout)

In `writer_recovery_test.go` (package `spool`), with a local `LossRecord` helper and envelopes of both provenances:

- A write failure moves the writer to a new segment. Append 2 records, then close `w.f` behind the writer's back (the trick `writer_poison_test.go` uses) and append a guest record: it fails, and the outage counts 1 guest push and 0 runner records. Append a runner record: it succeeds and lands in `seg-0000000000000001.vmsp`, which reads back as exactly [`telemetry.loss`, the record]. The loss data carries `guest_pushes_refused` `"1"`, `runner_records_refused` `"0"`, `guest_events_lost` `"unknown"`, a cause that names the failed write, and `interval_start` at or before `interval_end`. `seg-0000000000000000.vmsp` still holds its 2 records and has no end marker, because the retire could not use the closed fd.
- A quota outage recovers in the same segment. Set a small `MaxSpoolBytes` and create a sparse `ballast.vmsp` (a non-pattern name, which `spoolTotalBytes` still counts) that fills the quota. Two guest appends and one runner append each fail with `errors.Is(err, ErrSpoolFull)`. Remove the ballast; the next append lands in the same segment as [loss, record], with counts guest 2 and runner 1 and a cause containing `spool full`.
- Advances burn indices until the dir is writable (skip as root). A closed-fd refusal, then `chmod 0500` on the dir, then two more refused appends (each advance fails). After `chmod 0700`, the next append lands in `seg-0000000000000003.vmsp` as [loss, record], with counts that match all three refusals by provenance. Restore the mode in `t.Cleanup`.
- Close records an open outage. With the ballast still in place, `Close` writes the loss frame (exempt from the quota) and returns nil; the segment ends [loss, end marker].
- Close reports a loss it could not record (skip as root). Closed fd plus a `0500` dir, one refused append, then `Close` returns an error containing `not recorded`.
- An oversize record and a record whose `Data` cannot marshal each fail and open no outage; the next append has no loss record in front of it.
- Counts saturate at the maximum `uint64` (white-box).
- `Outage.Data` returns exact strings for fixed times and counts, including `guest_events_lost` `"0"` when no guest push was refused.
- A nil `LossRecord` fails `OpenWriter`, which creates no `.vmsp` file.
- An append after `Close` fails and opens no outage.
- Rotation retires the full segment: with a small `MaxSegmentBytes`, the first segment ends in the end marker and reads cleanly.
- `retireSegment` trims junk: write a header, one record and some junk bytes to a file, call `retireSegment(f, size)` with the size after the record, and assert the file is `size+4` bytes and reads back as the record then EOF.

In `internal/runner/telemetry_test.go` (package `runner_test`), `TestRunnerRecordsLossAfterSpoolRecovers`, built like `TestRunnerNeverAcksWhatItCouldNotSpool` (a served-connection counter; later connections are handled explicitly):

1. Connection 1 pushes seq 1 and reads its ack. It creates a 512 MiB sparse `ballast.vmsp` in the spool dir (`os.Create`, then `Truncate(512 << 20)`), which puts the spool over `DefaultMaxSpoolBytes`. It pushes seq 2; the runner refuses it and closes the connection (`proto.ReadControl` returns an error). Then it removes the ballast.
2. Connection 2 resends seq 2 and reads its ack.
3. Assert, reading the spool: a `telemetry.loss` envelope that is `host_observed`, has Sensor `"runner"`, `SourceInstanceID` `telInstance`, VMID `telVMID` and BootID `telBootID`, `guest_pushes_refused` at least 1, `guest_events_lost` `"unknown"`, and a cause containing `spool full`. It comes before seq 2's envelope in spool order.

The harness's `spooled()` globs only `seg-*.vmsp`, so it never reads the ballast.

The report must say plainly that the fsync-failure path shares its code with the write-failure path, but no test induces an fsync failure on a real filesystem.

**Commit:** `fix(spool): abandon a damaged segment, not the writer, and record the loss`

### Task 3: A resent push reuses the envelope it was refused with

**Context.** The runner wraps each guest push in an envelope in `newGuestEnvelope` (`internal/runner/telemetry.go`), stamping `HostReceivedAt: time.Now().UTC()`. After a write whose fsync failed, the spool writer refuses the record, so the runner withholds the ack. The record may still reach the store, because the importer can read the frame before the writer trims it. The guest resends every unacked push on its next connection. A fresh envelope for the resend carries a new `HostReceivedAt`, so its payload differs from the stored one under the same (`source_instance_id`, `source_seq`). The store answers with a seq/payload conflict (`store.ErrIntegrityFailure`), and `importVM` fails that VM's import on every cycle from then on.

The guest's ring stamps each event when it is pushed into the ring, so a resend is byte-identical on the wire. The runner can make the envelope identical as well.

**Files**

- Modify: `internal/runner/telemetry.go`, `internal/runner/telemetry_test.go`

**Change**

1. Remember one refused push: its stream ID, the `proto.TelemetryPush`, and the envelope built for it. The telemetry goroutine owns this memory and passes it along the way it passes the `spooled` map; no lock.
2. In `spoolTelemetryPush`, reuse the remembered envelope when the new push has the same stream and `Seq`, the same `Kind`, `GuestWallAt` and `GuestMonotonicNS`, and `bytes.Equal` `Data`. Otherwise build a fresh envelope as today. Remember whichever envelope the spool refuses; forget it when its append succeeds.
3. One is enough: `serveTelemetry` returns after the first refusal and acks are cumulative, so the refused push is always the first one the guest resends.
4. Rewrite the doc of `spoolTelemetryPush`: its last sentence leaves resend bytes to the store; say instead why the runner reuses the refused envelope.

**Test** (RED first): `TestRunnerResendReusesTheRefusedEnvelope`, built like `TestRunnerNeverAcksWhatItCouldNotSpool`:

1. Build one `proto.TelemetryPush` value for seq 2 and send it with `proto.WriteControl(conn, proto.KindTelemetryPush, push)` both times. `writeFakePush` restamps `GuestWallAt` on every call, which would defeat the test.
2. Connection 1 pushes seq 1 and reads its ack, creates the 512 MiB sparse `ballast.vmsp` in the spool dir (as in `TestRunnerRecordsLossAfterSpoolRecovers`), pushes seq 2, and sees the runner close the connection. It records `T2 := time.Now()` and removes the ballast.
3. Connection 2 (served count 2, the same `fakeEpoch` in its hello reply) waits until at least one second after `T2`, so microsecond truncation cannot flip the comparison, then resends the identical seq-2 push and reads its ack.
4. Assert: seq 2's spooled envelope has a `HostReceivedAt` before `T2`; a `telemetry.loss` with `guest_pushes_refused` at least 1 comes before it in spool order; and seq 2 appears exactly once in the spool.

RED today: `HostReceivedAt` falls after `T2`.

**Commit:** `fix(runner): resend a refused push with the envelope it was refused with`

### Task 4: Recover never mutates or rejects the newest segment

**Context.** The importer (vmobsd) calls `Recover(vmDir)` (`internal/spool/reader.go`) at the start of every cycle for every VM, while that VM's runner, another process, may be appending to its newest segment. Today `Recover`:

- opens every `.vmsp` file read-write and truncates any segment whose last record looks torn, the newest included, where the torn record may be a write in flight. The writer then writes at its own file offset, past the truncation point, leaving a hole of zeros that reads as a corrupt record, and every later record in that segment is lost to the importer;
- fails the whole VM's import on a header it cannot read, including a segment whose creation is under way (the file exists, its header is not written yet): `read header: EOF`. The writer now opens a segment after every outage (Task 2), so the race matters more;
- treats every `.vmsp` name as a segment, including names the writer never makes. Task 2's tests fill the quota with a `ballast.vmsp`.

The writer writes a segment's header with a single `write()` at offset 0 of an empty file. A reader sees either a header with no newline yet or the complete line. So a header without a newline is a creation under way or a torn creation, never corruption. A complete line that does not parse, or a wrong magic, is real corruption.

**Files**

- Modify: `internal/spool/reader.go`, `internal/spool/importer.go`, `internal/spool/spool_test.go`, `internal/spool/importer_test.go`, `internal/situation/import_health_test.go`, `internal/api/import_health_test.go`
- Tests may go in a new `internal/spool/recover_test.go` (package `spool_test`) or beside `TestCrashSimulation`.

**Change**

1. `Recover` and `importVM` consider only names `parseSegmentName` accepts (Task 1). Other `.vmsp` files are never read, truncated, removed or treated as newest. `spoolTotalBytes` in `writer.go` keeps counting every `.vmsp` file: the quota protects the disk, whatever the name.
2. Order segments by parsed index. The newest is the highest index in the listing.
3. A segment whose header has no newline (a 0-byte file included):
   - the newest: skip it, because its creation may be under way;
   - any other: remove it, because no writer will ever finish it (the writer appends only to the newest segment it created, and after any failure it moves on to a new one). A removal error fails the VM's recovery.
   - Either way it is left out of `report.Segments`.
4. Truncate a torn tail only on a segment that is not the newest. Open the newest read-only and never truncate it; reading simply stops at its torn tail, as `ReadSegment` already does. Count interior corruption on every segment, the newest included.
5. A complete header line that does not parse, and a wrong magic, stay hard errors on every segment, the newest included.
6. The gap envelope's `SourceSeq` stays the segment's position in the returned list. That is a known limitation; do not change it here.
7. Update the `recoverSegment` doc, which still mentions "importer, Task 7".

**Tests** (RED first where the behavior is new)

- Change `TestCrashSimulation` (`internal/spool/spool_test.go`). Its only segment is the newest, so `Recover` leaves it alone: `TruncatedTail` is false, the size is unchanged, and the 2 records still read back. Then open a second writer on the same dir, which creates `seg-0000000000000001.vmsp`. Now `Recover` truncates the garbage from `seg-0000000000000000.vmsp`, reports `TruncatedTail` true, and the file's size equals its size before the garbage.
- An empty newest segment. A closed `seg-0000000000000000.vmsp` with records beside an empty `seg-0000000000000001.vmsp`: `Recover` returns `report.Segments` equal to the first path only, the empty file still exists, and `ImportOnce` imports the first segment's records. RED today: `read header: EOF`.
- A torn creation below the newest. Valid `seg-…0000`, `seg-…0001` holding a partial header with no newline, and valid `seg-…0002`: `Recover` removes `seg-…0001` and reports the other two.
- Non-pattern files. `bad.vmsp` and `zz.vmsp` holding garbage beside a valid `seg-…0000`: `Recover` reports only the segment, both files remain on disk, and the import succeeds.
- A newest segment holding a complete but unparseable header line is still a hard error.

Replant these fixtures. Each planted `broken` with no newline, which after this change reads as a creation under way (or, for `bad.vmsp`, an ignored name) instead of the failure its test needs:

- `internal/api/import_health_test.go:132-133`: `seg-0000000000000000.vmsp` holding `broken\n`
- `internal/situation/import_health_test.go:29`: `seg-0000000000000000.vmsp` holding `broken\n`
- `internal/situation/import_health_test.go:61`: rename `bad.vmsp` to `seg-0000000000000000.vmsp`, holding `broken\n`
- `internal/spool/importer_test.go:780`: `seg-0000000000000000.vmsp` holding `broken\n`

Run `git grep -n vmsp -- '*_test.go'` for any other fixture that plants raw segment bytes, and say in the report what you found.

**Commit:** `fix(spool): never truncate or reject the segment the writer is appending to`

### Task 5: The operator sees the writer's failure while it lasts

**Context.** vmobsd serves per-VM import health at `GET /api/v1/vms/{id}/telemetry/import` (`internal/api/import_health.go`, then `Engine.ImporterStatus`, then `Importer.Status` in `internal/spool/health.go`), and it raises `telemetry_degraded` attention through `SetFailureReporter` (`internal/situation/import_health.go`). The writer runs in another process, the runner. Its refusals reach the store only as a `telemetry.loss` after recovery, so while the disk stays full the operator sees nothing that names the cause. On aibox03 the one attention named the importer's cursor write, the failure that had recovered. The runner and vmobsd share the VM's spool dir and uid, so the writer's health travels through a file there.

`docs/design/spool-health.md` describes the import status records.

**Files**

- Create: `internal/spool/status.go` and its tests
- Modify: `internal/spool/writer.go`, `internal/spool/health.go`, `internal/spool/importer.go`, `internal/situation/import_health.go`, `internal/situation/telemetry_health.go`, `docs/design/spool-health.md`, and the tests that cover them, including `internal/api/import_health_test.go`

**The status file.**

- `writer.status` in the spool dir, exactly 4096 bytes and really allocated. `OpenWriter` opens it `O_RDWR|O_CREATE`, mode `0600`, writes all 4096 bytes (the frame plus explicit zero padding) at offset 0, and fsyncs. It needs no directory fsync: a missing file reads as unknown.
- Allocating the bytes up front means every later update overwrites blocks the file already owns, which still works on a full disk on filesystems that do not copy on write (ext4, xfs, HFS+).
- `OpenWriter`'s order becomes: validate the config, find the next index (Task 1), prepare the status (`spool: prepare writer status: %w`), create the first segment. Close the status fd when the segment's creation fails.
- Each new writer resets the file to healthy with its own instance id.
- The writer keeps the fd open. An update writes all 4096 bytes at offset 0 with `WriteAt`, without fsync, and ignores errors: the status is advisory, and the loss record is the durable evidence.
- Frame: `[len uint32 BE][crc32c uint32 BE][JSON body][zero padding to 4096]`, with the body at most 4088 bytes. When the marshaled body is longer, halve the rune length of `cause` and `last_error` and try again until it fits.
- A reader that finds the file missing or short, a zero or impossible length, a bad CRC or bad JSON returns state `unknown`. A torn read of an in-place overwrite therefore reads as unknown, never as a wrong answer.

**WriterHealth.**

```go
type WriterHealth struct {
	State                string `json:"state"` // healthy | failing | unknown
	Since                string `json:"since"`
	Cause                string `json:"cause"`
	LastError            string `json:"last_error"`
	RunnerRecordsRefused string `json:"runner_records_refused"`
	GuestPushesRefused   string `json:"guest_pushes_refused"`
	UpdatedAt            string `json:"updated_at"`
	InstanceID           string `json:"instance_id"`
}
```

- healthy: `Since` is when this writer opened or last recorded a loss; both counts are `"0"`; `Cause` and `LastError` are empty.
- failing: `Since`, `Cause` and the counts come from the open outage, as decimal strings; `LastError` is the latest refusal's error, bounded to 512 runes with the shared helper.
- unknown: every other field is empty.
- Times are UTC in `events.TimestampLayout`.

**Writer.** Write the status on every counted refusal (failing) and when a loss record lands (healthy, `Since` now). `Close` writes a final status (healthy when no outage is open, failing otherwise) and closes the fd.

**Importer.**

- Every cycle, for every VM dir, read its `writer.status` before the backoff `continue` in `importOnce`, so a VM whose import is backing off still shows its writer's state. Keep the results in their own map under `imp.mu`, and delete entries for dirs that vanished, as the import health map does.
- `ImportStatus` gains `Writer *WriterHealth` with tag `json:"writer,omitempty"`. `Status(vmID)` sets it for a non-empty `vmID`: the last value read, or a `WriterHealth` with state `unknown` when none was. The root status (`vmID == ""`) leaves it nil.
- `SetWriterFailureReporter(report func(context.Context, string, WriterHealth) error)` takes `cycleMu`, like `SetFailureReporter`. The importer calls the reporter under `cycleMu` and outside `imp.mu` when a VM's writer reads failing and its `Since` differs from the `Since` last reported for that VM. A nil return records that `Since`; a healthy read clears it; an unknown read changes nothing. So each outage raises one attention, and a new outage raises another.

**Situation.**

- Add `reportWriterFailure(ctx, id string, h spool.WriterHealth) error` to `internal/situation/import_health.go`, mirroring `reportImportFailure`: return nil when the `telemetry_degraded` trigger is off; otherwise raise attention with `TriggerClass` `"telemetry_degraded"`, `store.SeverityNeedsDecision`, `VMID` set, `Summary` `fmt.Sprintf("runner spool writer failing since %s: %s", h.Since, h.Cause)`, `SystemAction` `"refusing records the spool cannot make durable; the runner retries on every append and writes a telemetry.loss record once an append succeeds"`, the evidence link `/api/v1/vms/<id>/telemetry/import`, one suggested action `inspect_spool_import` with `Params` `{"url": link}` and `Rationale` `"Free space or repair permissions on the spool filesystem; the writer resumes on its next append and records the loss."`, and `Collapse` and `QueueMax` from the engine config. Wire it in `SetImporter` beside `SetFailureReporter`.
- `VMTelemetryHealth` (`internal/situation/telemetry_health.go`) also reports degraded when the VM's import status has a `Writer` whose state is `failing`.

**Docs.** In `docs/design/spool-health.md`: describe the writer health (the file, its fields, what failing means); list the `telemetry.loss` fields from Task 2 and their caveats; replace "No new event kind is emitted", which is no longer true; and state that on copy-on-write filesystems the status overwrite can fail on a full disk. Find any other doc or contract test that lists the import status fields (`git grep -n next_retry_at`) and add `writer`.

**Tests** (real files, real SQLite, real HTTP)

- Status file: healthy and failing values round-trip; a missing file, a short file, a zeroed file and a file with a flipped CRC byte each read as unknown; the file is exactly 4096 bytes after open and after updates; an overlong cause is halved until it fits, and the result still round-trips.
- Writer: a refusal writes failing with the right counts, cause and last error; the loss record's landing writes healthy with a new `Since`; `Close` writes the final status; a new writer on the same dir resets to healthy with its own instance id.
- Importer: `Status(vm).Writer` follows the file each cycle, including for a VM whose import is failing and backing off under `Run`'s schedule; a vanished dir drops its entry; the root status has no writer.
- Reporter: one call per outage across several cycles with the same `Since`, another for a new `Since`, none for unknown.
- Situation: with `telemetry_degraded` on, a failing writer raises one attention with the summary and link above, and `VMTelemetryHealth` reads degraded.
- API: `GET /api/v1/vms/{id}/telemetry/import` over a real `httptest` server built with `api.New(st, eng, nil, api.AuthConfig{}, nil, nil)` returns `writer` with state `failing` and the cause. Seed the VM as `TestHTTPVMImportFailureHealthAndUnknownVM` does.

**Commit:** `feat(spool): report the writer's health on the import status and attention`

### Task 6: Prove recovery from a real full disk, end to end

**Context.** Kata 19g4 is done when "a test on a real filesystem that runs out of space poisons the writer, frees the space, and sees the next append land in a new segment behind an explicit loss record; the importer imports both segments; and an operator can read the cause from the API while it persists." The earlier tasks built the parts:

- the writer refuses and recovers, recording a `telemetry.loss` (`internal/spool/writer.go`);
- `Recover` leaves the newest segment alone;
- `writer.status` reaches `GET /api/v1/vms/{id}/telemetry/import` as the `writer` field and raises `telemetry_degraded` attention.

This test proves them together on a filesystem that really returns ENOSPC.

**Files**

- Create: `internal/api/spool_full_disk_test.go` (package `api_test`)
- Create: `internal/api/smallfs_darwin_test.go`, `internal/api/smallfs_linux_test.go`, and `internal/api/smallfs_other_test.go` (`//go:build !darwin && !linux`). Each provides `smallFilesystem(t *testing.T) string`, which returns the mount point of a fresh 8 MiB filesystem:
  - darwin: `hdiutil create -size 8m -fs HFS+ -volname vmobs-enospc <tmp>/img.dmg`, create `<tmp>/mnt`, then `hdiutil attach -nobrowse -noverify -noautoopen -mountpoint <tmp>/mnt <tmp>/img.dmg`. Register `hdiutil detach -force <tmp>/mnt` with `t.Cleanup` after creating the temp dir, so the detach runs first. Skip only when `hdiutil` is not on PATH; any other failure fails the test with the command's output. These commands were checked by hand on this Mac as a regular user. HFS+ does not copy on write, so an in-place overwrite still works on a full volume.
  - linux: when the euid is 0, `syscall.Mount("tmpfs", mnt, "tmpfs", 0, "size=8m")`, and unmount in `t.Cleanup`. Skip when not root. On EPERM, skip with a message naming CAP_SYS_ADMIN. Any other error fails the test.
  - other: skip.

**Layout.** Seed a real VM and boot as `TestHTTPVMImportFailureHealthAndUnknownVM` (`internal/api/import_health_test.go`) does, with the store under `t.TempDir()`, not on the small filesystem. The spool dir is `<mnt>/spool/<vmid>` and the importer root is `<mnt>/spool`. Build the engine with `situation.Config{Triggers: map[string]bool{"telemetry_degraded": true}, QueueMaxItems: 10, CollapseDuplicates: true}`, call `eng.SetImporter(imp)`, and serve `api.New(st, eng, nil, api.AuthConfig{}, nil, nil)` from `httptest`.

Open the writer with `MaxSegmentBytes` of 64 KiB and the default quota (the filesystem fills long before 512 MiB). Its `LossRecord` builds a `telemetry.loss` the way the runner does: `host_observed`, Sensor `"runner"`, the seeded VM and boot, a fixed lowercase-UUID instance id, and an incrementing seq. Records alternate between `guest.sensor_health` (guest_reported; copy the data from the existing API test) and `guest.channel_established` (host_observed), each with its own instance id and seq.

**Steps**

1. Append a few records of each kind and import. They are in the store.
2. Fill the filesystem with ballast files at `<mnt>/ballast-<n>.bin`, outside the spool dir and without a `.vmsp` name, in falling sizes (1 MiB, then 64 KiB, then 4 KiB) until each size fails with ENOSPC.
3. Append until an append fails with `errors.Is(err, syscall.ENOSPC)`, in a bounded loop that fails the test if ENOSPC never comes. Appends that succeed on the way are acknowledged records.
4. Make several more appends of both provenances; each must fail. Count every refusal by provenance, the first ENOSPC included. No segment may hold a refused record: read every pattern-named segment and check. Log the segments present, and say in the report whether any header-only segment appeared.
5. Run `ImportOnce` without asserting its error; the importer's own cursor write may fail on the full filesystem, as it did on aibox03. Then `GET /api/v1/vms/<id>/telemetry/import` returns `writer.state` `failing`, a `writer.cause` containing `no space left on device`, and counts equal to the refusals so far. `imp.Status(vmID).Writer` agrees, and exactly one open attention's summary starts with `runner spool writer failing since`. (The importer's own failure may raise a second attention; do not count it.)
6. Remove the ballast files.
7. Append one record. It succeeds and lands in a new segment, the newest, holding exactly [`telemetry.loss`, the record]. The segment that failed now ends with an end marker.
8. `ImportOnce` returns nil. The importer has imported both segments:
   - every acknowledged record is in the store;
   - no refused record is; step 4 found none in any segment, and this checks the store as well;
   - the loss record's `runner_records_refused` and `guest_pushes_refused` equal the refusals by provenance, `guest_events_lost` is `"unknown"`, the cause contains `no space left on device`, and `interval_start` is at or before `interval_end`;
   - the segment that failed has been pruned.
9. The API now returns `writer.state` `healthy`.

Close the writer before the cleanup detaches the volume.

Check that the Linux file compiles: `GOOS=linux env -u GOROOT mise exec -- go vet ./internal/api/`. Run the test with `-count=1 -v -run <name> ./internal/api/`, and quote its `--- PASS` line, the platform and the filesystem in the report.

**Commit:** `test(api): prove recovery from a real full disk end to end`
