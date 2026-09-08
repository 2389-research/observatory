# Disk capacity after restart and reclamation

Kata `n0vw` fixes a startup sample that continued to charge deleted VM disks.
Admission and host capacity now use the same live filesystem calculation:

```
free for a request = filesystem available - inspection scratch
                    - (outstanding disk reservations - allocated guest disks)
```

SQLite remains the reservation authority. The admission transaction reads both
aggregate reservations and their VM owners. Host capacity uses the same writer
transaction. The runtime observer tries the jailer's existing lifecycle mutex
before reading each reserved VM's canonical jail `rootfs.ext4` and
`workspace.ext4`, followed by filesystem availability. Launch, rollback, stop
and release hold that mutex too. If lifecycle work holds it, observation returns
current filesystem availability with zero allocated-disk credit. That keeps all
reservation debt and avoids waiting for a launch while holding SQLite's writer.
Adapter work under the lifecycle mutex must never acquire the writer.

Before granting allocated-block credit, the observer also asks privd for its
settled network inventory, with a 100-millisecond deadline. That inventory holds
the privileged execution lock and refuses any busy, pending or unknown mutation,
including interrupted starts and releases. A lost socket reply can leave privd
working after the adapter releases its mutex, so the local mutex alone cannot
prove images will remain allocated through the free-space sample. Missing,
failed or timed-out inventory returns zero credit. After a settled inventory,
the held adapter mutex prevents this controller from issuing another mutation
until sampling finishes. This assumes one controller owns the managed image
lifecycle; other privileged clients must not mutate its images concurrently.

Only allocated blocks receive credit, rounded down to MiB and capped at each
VM's reservation. Sparse lengths, missing files and pending creates receive no
credit for unwritten space. Unreserved files and retained stage copies receive
no credit. Existing allocations therefore do not pay twice, while outstanding
promises remain charged. A restart needs no persisted observation or derived
allocation ledger. A delete becomes visible on the next request.

A missing image means zero credit. Failed observation, symlinks, shared hardlinks,
or an image on an unconfigured filesystem refuse admission. The observer uses configured
paths and SQLite VM IDs, never manifest-supplied paths or privileged ownership
claims. State, staging and jail paths may reside on separate filesystems. The observer
samples each distinct filesystem, credits image blocks only on their own
filesystem, and uses the smallest free-plus-credit result. Missing runtime
directories use their nearest existing parent's filesystem. Each filesystem must
conservatively cover all outstanding promises, even where it holds only metadata;
this can refuse capacity earlier on a small separate state volume. The inspection
scratch reserve is unchanged, including when current
free space falls below it. In that case capacity may report negative headroom.

The serialization protects Observatory's own image lifecycle. Guest writes can
allocate more host blocks between the image sample and the final free-space
sample; that makes admission more conservative. Guests cannot truncate or punch
holes in their host image files. External tools must not mutate those managed
files concurrently. Other host writers can still consume free space after an
observation; this is admission accounting, not a filesystem quota.

Current staging already keeps additional copies and boot artifacts beyond the
root-plus-workspace reservation. This change neither credits those copies nor
adds a reservation for future staging overhead. Low-headroom acceptance must
leave space for that existing launch footprint. Busy lifecycle work can cause a
temporary conservative admission refusal because existing images receive no
credit until observation can take the mutex.

Local verification covers real files with sparse and allocated extents, image
reclamation and symlink refusal; real SQLite owner snapshots; policy scratch,
pending debt and observation failure; and concurrent manager creates competing
for one disk reservation. Real Linux/KVM restart, delete and successor admission
remain a separate required acceptance run.
