# Cleanup retries while the controller runs

Startup reconciliation repairs interrupted operation records and uses the host
scan performed before manager construction. It remains synchronous, before HTTP
readiness. The periodic cleanup controller never calls it.

After startup, the manager schedules a cleanup pass 30 seconds after the previous
pass finishes. Each pass visits at most 16 rows, in row-ID order, under one
30-second context. A cursor carries progress to the next pass and wraps at the
end. This fixed delay bounds retry pressure without an unbounded per-VM backoff
map. Large backlogs take multiple passes; the delay is not a per-VM deadline.

The candidates are `stopping`, `deleting`, and `failed` VMs, plus stopped VMs
with a durable cleanup-debt marker. Failed VMs whose
reservations have already been fully released need no host calls. The controller
rereads each candidate after claiming it. Public actions, deletes, exit notices,
queued launches and batch stop waves hold lifecycle claims. They retain their
existing concurrency with one another; a retry requires exclusive ownership.
A foreground caller cancels an existing retry, waits for its bounded call to
return, and reads the VM again. A late successful host result after cancellation
cannot settle the VM or spend the caller's revision.

Every attempt obtains fresh evidence through the runtime's `ForceStop` and
`Release` contracts. Saved startup adoption and ambiguity findings are never
reused. An unavailable adapter does not prove release. The jailer must resolve
pending launch identity and acquire its cancellable lifecycle lock before
observing or releasing host resources, including launches whose caller has
already received `ErrLaunchPending`.

A stopping VM reaches stopped only after force-stop completes. Disk reservations
remain for restart. A stopping VM whose desired state is deleted continues
through stopped and deleting after full release succeeds. Deleting VMs become
deleted only after full release. Failed VMs retain their failure evidence while
successful full cleanup releases their remaining reservations. No retry changes
operation outcomes. Failed host calls append `vm.cleanup_failed`, including the
host reason and the manual DELETE remedy. Manual DELETE remains available.

The idle timer does not count as active manager work. Its callback enrolls through
the shutdown gate; closing stops the timer, cancels any active pass, and drains
its storage users. There is no recovery work moved behind HTTP readiness.

Normal stop calls can settle at stopped with `ErrCleanupPending` for jail
cleanup. Recording that failure also writes a `cleanup_debt` marker in the same
SQLite transaction. The marker contains only the VM ID; the existing failure
event carries its reason. A stopped retry calls `ForceStop` without `Release`,
then clears the marker after fresh success. Stage files, network allocation and
disk reservations remain available for restart. A transition away from stopped
supersedes its marker. Ordinary stopped VMs cause no host retry calls.

Schema migration 10 seeds markers for currently stopped VMs with historical
stopped cleanup failures. Older versions recorded no settlement witness, so this
is conservative: an already-clean VM may receive one harmless, idempotent
force-stop. Fresh proof clears that marker. The retry rereads markers under its
claim, since a foreground action may have settled debt after the page was read.

Portable coverage uses real SQLite and the owned runtime boundary to exercise
recovery, paging, concurrent lifecycle work, stale results, scheduling and
shutdown. Linux acceptance must also force a real host cleanup failure, remove
its cause while the same manager remains alive, and observe cleanup and safe
slot reuse. Portable tests alone do not establish that host behavior.
