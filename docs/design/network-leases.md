# Network lease reclamation

A VM's provisioning manifest and privd's authoritative ledger record its transit
prefix. The allocator caches their combined claims in memory when the controller
starts and before launch. It has no separate durable lease file. Acquisition is atomic and
idempotent by VM ID; a freed prefix can serve a later VM.

A route is exempt from pool overlap checks only when its exact /30 and host
veth agree with a validated manifest and privd's matching claim, and it has no gateway. Manifest VM IDs
must agree with their directory names. A veth-like name alone proves nothing.
Foreign and VPN routes still exclude overlapping pools. Privd-only claims also
reserve prefixes even when no host route remains. Unknown privileged outcomes
or a manifest/privd disagreement refuse new allocation. Unmanifested orphan
routes remain conservative exclusions.

Unreadable or conflicting manifests refuse launch. The adapter remains usable
for reconciliation and deletion so an operator can resolve the corrupt record.
A controller that cannot validate its lease inventory grants no owned-route
exemptions. If all pools overlap routes, the allocator still supports recovery
and release but cannot allocate a fresh prefix. Surviving leases outside today's
usable pools retain their identity.

Release returns a prefix only after privd releases both VM and network ownership,
the jail chroot is absent, and staging and manifest removal finish their durable
barriers. Failed launch rollback uses that same release path. A failed or
ambiguous teardown retains the manifest and in-memory lease for retry. A retry
of an already removed tree repeats the directory barrier on its nearest
surviving ancestor: visible absence after a failed fsync is not a settled release.
Inventory reconstruction also syncs that directory before interpreting absent
manifests as reusable identities, including after a controller restart.

Tests cover small-pool reuse and exhaustion, concurrent owner acquisition,
controller restoration, exact route ownership, failed launch, surviving chroot
debt, and directory-barrier retries. Local tests do not prove power-loss
behavior or real Linux network teardown; the Linux/Firecracker acceptance gate
must supply that evidence before this kata is closed.
