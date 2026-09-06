# Execution records

One record per acceptance row a real-host gate exercised, named by its execution
ID and never rewritten. Each `<id>.json` binds that row's outcome to the commit,
the binary digests, the runtime lock and the pinned guest artifacts behind it;
the matching `<id>.txt` is the transcript that row produced, bound by digest.

Read them with `internal/evidence`: `Load` validates every record and reports
one it cannot trust, `Verify` re-hashes the artifacts, and `Status` answers what
the latest executed real-host run found for one row. `ls` is not the reader —
the filenames are opaque on purpose.

These are published outside the repository first (see `../../README.md`) and
copied in; the gate transcript names the IDs it published.
