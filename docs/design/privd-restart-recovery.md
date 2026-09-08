# Privd restart recovery — Kata 7p8m

Status: implemented and verified with real Docker Compose restart recovery.

## Measured failure

On 2026-09-07, the extended `TestComposeLive` ran on aibox03 against published
image `ghcr.io/2389-research/observatory:a6a1394`. A real VM reached running;
`docker compose restart vmobs` ended it; its chroot, stage and manifest survived.
Forced DELETE returned `runtime_operation_failed`: the jail chroot survived
release. The test failed in 13.68 seconds at the cleanup assertion. Successor
assertions were not reached. Evidence: `/tmp/vmobs-restart-red.log` locally and
on aibox03. Disposable containers and volumes were removed; the original
appliance was restarted and its API answered with no VMs.

The result above is the historical red case that established the requirement.
It predates the durable-ledger design in this document and is not the behavior
the new design intends to ship.

## Ownership constraint

The failed build's entrypoint deleted `/run/vmobs/privd`; that ledger was also
on tmpfs.
`handleReleaseVM` needs a ledger entry before it calls `RealOps.ReleaseVM`.
The persistent jail outlives the only privileged cleanup record.

Persisting the root-owned ledger was insufficient by itself while the appliance
used a private PID namespace, because a replacement container saw different PID
identities. A namespace mismatch alone does not prove an old process died.
Importing the daemon-owned manifest or guest-owned jail pidfile would turn
untrusted data into root signaling authority. Cleanup stays VM-ID-scoped and
refuses a live recorded process. Reservations remain held until cleanup succeeds.

## Chosen design

privd keeps its root-owned ledger at `/srv/vmobs/privd`, on the same persistent
runtime volume as the resources it authorizes. The directory is mode `0700`.
The entrypoint creates it when absent and does not clear it on restart. No host
installer or new supervisor is required; deployment remains Docker Compose.

Compose and the development wrappers use the host PID namespace. A replacement
privd therefore sees the same PIDs as its predecessor, while the host's PID 1
reaps daemonized VMMs. Each VM record captures the host kernel boot identity and
the VMM's PID namespace identity. privd may signal the recorded process only
when both identities match the trusted record. After a host reboot, a stale PID
cannot authorize signaling an unrelated process. Missing, unreadable or
ambiguous identity evidence fails closed and keeps the reservation until cleanup
can be proved.

Host PID visibility is a real security cost: the appliance can enumerate host
processes. The chosen design accepts that cost to make process ownership stable
across container restarts. AppArmor, seccomp, capabilities and device grants
remain unchanged, and a PID visible in the namespace is not authority by itself.

The daemon-owned manifest and guest-owned jail pidfile remain untrusted for root
signaling. Unknown VM IDs cannot pass through `release_vm`, and a mismatched
namespace does not by itself prove that a process is safe to kill.

This design prevents future ledger loss; it cannot recover trusted ownership
for a legacy chroot whose ephemeral ledger disappeared before the change. privd
does not auto-import those resources from manifests or jail pidfiles. They stay
unknown and fail closed until an operator resolves them.

## Next verification

The live regression must pass with released slot reuse and predecessor DELETE
retry without killing its successor. Unit tests recreate the server around a
durable ledger and use real child processes with synthetic old-boot and
different-namespace records. They do not perform a host reboot or restart a live
privd independently. Existing fake-ledger adapter tests cover call ordering but
cannot prove the privileged recovery boundary.

This change does not add generation fields to the privileged protocol. The
successor test uses a distinct VM ID, so it does not establish stale-request
semantics across new boots of the same VM. The separate `bm7v` work covers
uncertain mutation outcomes, including a crash between VMM spawn and durable
publication of its ownership record.

## Verification result — 2026-09-07

The final candidate image passed `TestComposeLive` on aibox03 in 27.23 seconds:
the VMM ran, Docker restarted the appliance, DELETE reclaimed chroot/stage/
manifest, reservations returned to baseline, and a successor reused the slot,
UID and CID. Repeating predecessor DELETE preserved the successor's exact live
PID/starttime. Policy loader refusal, profile-loss recovery and repeated Compose
up also passed. The ledger remained unchanged across restart and unreadable to
the unprivileged daemon. Evidence: `/tmp/vmobs-restart-final-live.log`.

All ten local `scripts/check` gates and the Linux Go suite passed. Recovery tests
use actual child processes and disk records to exercise old boot/namespace
refusal, incomplete ownership, and release after process death. No actual host
reboot was performed. Independent review found no remaining blockers.

Near the host disk reserve, a separate capacity snapshot issue can refuse the
successor even after deletion releases all reservations. Kata `n0vw` records
that observed failure; the passing run had ample disk space. This fix does not
change admission policy or weaken its reserve.
