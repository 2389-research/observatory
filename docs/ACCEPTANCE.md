# Firecracker Observatory — Acceptance and Evidence Plan

This file is part of `SPEC.md`. Every row starts **SPECIFIED / NOT RUN**. These are tests to implement, not claims of successful execution.

## Evidence rules

For each test, record: stable test ID; linked requirement; exact procedure/fixture revision; expected and actual result; status; host hardware and nested/bare-metal context; runtime-lock digest; relevant event/artifact IDs; logs; defects; and the command that reproduces the result.

Use statuses `SPECIFIED`, `TESTED_PASS`, `TESTED_FAIL`, `BLOCKED`, and `VERIFIED`. `VERIFIED` requires rerunning after any relevant fix. A skipped test is not a pass. A UI screenshot is not proof of host isolation. Fake-runtime results must be explicitly labeled and cannot satisfy real-KVM gates.

Use a dedicated controlled network fixture for deterministic HTTP, HTTPS, DNS, pinned certificates, streaming, redirects and failure responses. Fixture-network exceptions must be confined to the isolated test installation and never silently added to production policies. Internet smoke tests are supplementary, not the sole evidence.

## A. Host, images and provisioning

| Test | Requirement | Procedure and required result |
|---|---|---|
| AT-001 | R-01, R-11 | Run doctor without usable KVM. Launch is rejected with the failed check; no silent emulation or half-created VM. |
| AT-002 | R-01, R-11 | Change a runtime/image hash or make a privileged path writable by an ordinary account. Startup rejects the unsafe configuration. |
| AT-003 | R-05, R-12 | Boot a guest missing a required sensor feature. Report the exact missing capability and refuse strict-observation launch. No false healthy state. |
| AT-004 | R-01, R-11 | Boot a real jailed VM; inspect actual identity, cgroup, namespace, approved disks and socket ownership. Capture evidence from the host. |
| AT-005 | R-01, R-10 | Inject a failure after every provisioning side effect. Cleanup removes only owned resources and releases reservations or reports a retryable cleanup backlog. |
| AT-006 | R-01, R-10 | Retry the same create request across a timeout. Exactly the original VM/operation is returned; a changed payload with the same key conflicts. |
| AT-007 | R-01, R-05 | Verify user jobs cannot start before guestd readiness, workspace seeding, baseline creation and required sensor checks. |
| AT-008 | R-11 | Supply malicious seed archives: traversal, symlink/hardlink escape, device entries, huge expansion and too many files. Reject safely inside the preparation sandbox. |

## B. Multiple VMs and resource limits

| Test | Requirement | Procedure and required result |
|---|---|---|
| AT-009 | R-02 | Launch four admitted VMs simultaneously. Each has a distinct VM/boot identity, network allocation, writable disk set, terminal session and event binding. |
| AT-010 | R-02, R-11 | Write identical pathnames with different contents in two VMs. Reads, final hashes and exports show no shared writable state. |
| AT-011 | R-01, R-02 | Stop and delete one VM while others run commands and stream logs. No unrelated VM, terminal or network worker is interrupted. |
| AT-012 | R-02, R-09 | Submit simultaneous creates that exceed remaining RAM. Transactional admission does not over-reserve or start unaccounted VMs. |
| AT-013 | R-02, R-09 | Pause a VM and launch another request. Paused memory remains reserved; no false capacity is advertised. |
| AT-014 | R-02 | Test atomic-reservation batch rejection and a post-reservation boot failure. Per-VM results and configured keep/stop-successful behavior are correct. |
| AT-015 | R-02 | Retry a partially completed batch with its original key. The original member IDs/results return; no duplicate batch appears. |
| AT-016 | R-09 | Exhaust CPU, guest process count, guest RAM, terminal sessions and network concurrency in one VM. Limits activate and other VMs/control plane remain usable. |
| AT-017 | R-09 | Fill a workspace and event spool. Guest/storage-specific failure does not exhaust the host system filesystem or another VM's disk. |
| AT-018 | R-09, R-10 | Repeat create/start/stop/delete cycles and compare owned namespaces, cgroups, images, sockets and reservation counts with the documented idle baseline. No growing leaks. |

## C. Browser terminal

| Test | Requirement | Procedure and required result |
|---|---|---|
| AT-019 | R-03 | Run `tty`, shell job control and a foreground process in the browser. It is a real guest PTY, not a host shell or pipes-only imitation. |
| AT-020 | R-03 | Run installed `vi` and a full-screen process viewer; resize repeatedly; type UTF-8; use color, alternate screen and bracketed paste. Output and dimensions remain correct. |
| AT-021 | R-03 | Send Ctrl-C, Ctrl-D, suspend/resume and foreground/background job commands. Correct guest terminal/process-group behavior occurs. |
| AT-022 | R-03, R-10 | Disconnect/reload the browser and reattach by session ID. The same shell remains, commands do not rerun, and available output replays once. |
| AT-023 | R-03, R-12 | Overflow the retained terminal window while detached. Reattach shows a replay gap/reset rather than claiming an exact historical screen. |
| AT-024 | R-03, R-11 | Attach two browsers to one session. Only the lease owner can input/resize; transfer invalidates the old writer immediately. |
| AT-025 | R-03 | Open independent sessions in the same VM. Cwd, shell state, dimensions and exit state do not leak between PTYs. |
| AT-026 | R-03, R-12 | Duplicate terminal input frames and simulate an ambiguous broker restart. Accepted frame retries do not duplicate typing; ambiguous input is not blindly resent. |
| AT-027 | R-03, R-09 | Flood PTY output with a deliberately slow browser. Memory stays bounded, lost ranges are declared, and telemetry/control are not starved. |
| AT-028 | R-03, R-10 | Pause, resume, reboot and stop the VM while attached. The UI distinguishes these states; an old session cannot attach to a new boot. |
| AT-029 | R-03, R-11 | Emit HTML, malicious titles/links, OSC clipboard sequences and download-like control sequences. No DOM execution, automatic clipboard write or automatic download occurs. |
| AT-030 | R-03, R-11 | Attempt unauthenticated, wrong-Origin, wrong-owner and expired-session WebSocket upgrades. Deny each without reaching a guest PTY. |

## D. Structured execution and process events

| Test | Requirement | Procedure and required result |
|---|---|---|
| AT-031 | R-13 | Execute argv with stdout and stderr interleaving. Return separate cursorable streams, a stable exec ID, exact exit code/signal and correct limits. |
| AT-032 | R-13 | Pass shell metacharacters as ordinary argv. They remain arguments unless the caller explicitly selected a shell executable. No host shell runs. |
| AT-033 | R-13, R-10 | Retry an exec creation after connection loss. Query the original exec ID; do not execute a second copy. |
| AT-034 | R-13, R-09 | Cancel/timeout an exec that spawned descendants. All tracked guest job processes terminate; a detached child cannot survive by only orphaning its parent. |
| AT-035 | R-05 | Run a rapid short-lived process tree with forks and successful exec transitions. Sensor events preserve identities/parentage even when later `/proc` lookup is impossible. |
| AT-036 | R-05, R-12 | Attempt a nonexistent executable and an exec denied by permissions. Distinguish attempt/failure from successful execution. |
| AT-037 | R-05, R-12 | Force PID reuse and multiple execs in one PID. Process keys and exec generations remain distinct and historical rows are not overwritten. |
| AT-038 | R-05, R-12 | Use long argv and unavailable cwd/path data. Truncation/capture-failure fields are visible; missing data is not invented. |
| AT-039 | R-05, R-12 | Run shell builtins and interpreted in-process operations. The product does not claim they are all separately captured execs or a complete command transcript. |

## E. Filesystem events and final state

| Test | Requirement | Procedure and required result |
|---|---|---|
| AT-040 | R-05 | Execute deterministic create/write/close/rename/unlink/chmod operations on root and workspace. Supported events have correct scope and appropriate process/path evidence. |
| AT-041 | R-05, R-12 | Open a file writable and close without changing bytes. `fs.close_write` appears where supported; no unsupported `content_changed` assertion is made. |
| AT-042 | R-05, R-08, R-12 | Modify a persisted file via shared mmap and flush it. The final diff finds the change; notification coverage does not falsely claim a complete write history. |
| AT-043 | R-05, R-12 | Exercise rapid rename/unlink, hard links, non-UTF-8 names and bind-mount access. Preserve byte names/identities and mark unresolved/inferred paths honestly. |
| AT-044 | R-05, R-12 | Create a new mount or use an unsupported filesystem. Coverage reports the newly monitored scope or an explicit exclusion/gap. |
| AT-045 | R-05, R-12 | Overflow fanotify and eBPF queues deliberately. Loss health records and visible degraded coverage appear, with unknown counts represented as unknown. |
| AT-046 | R-05, R-09 | Trigger collector housekeeping, hashing and dependency-cache churn. No unbounded self-observation loop; UI noise filters do not silently erase supported captured evidence. |
| AT-047 | R-08 | Change content while preserving mtime; create/delete/type-change/symlink/hard-link/metadata-only cases. Final manifest/diff classifies them correctly without relying on mtime equality. |
| AT-048 | R-08, R-12 | Create then delete a file between baseline and final capture; modify tmpfs. Final diff scope is honest and does not claim to include vanished intermediate versions. |
| AT-049 | R-08, R-11 | Inspect a normal captured disk set. Verify no inspected filesystem is mounted in the host kernel and the inspector boots its own image without network access. |
| AT-050 | R-08, R-11 | Supply corrupted/hostile filesystem images, huge filenames/manifests and special-file trees. Inspector time/memory/output limits hold; no captured code executes. |
| AT-051 | R-08, R-12 | Force-stop during filesystem activity. Preserve the original disk digest; recovery, if needed, occurs only on a copy and the diff is labeled recovered/incomplete. |
| AT-052 | R-08, R-14 | Compare displayed before/after previews with actual retained artifacts and hashes. Missing/truncated historical content is not reconstructed from a current file. |

## F. Networking and interception

| Test | Requirement | Procedure and required result |
|---|---|---|
| AT-053 | R-06 | Test offline, transport and inspection profiles against controlled services. Allowed paths work and denied paths have correct outcomes/coverage indicators. |
| AT-054 | R-06, R-11 | Attempt cross-VM traffic, address/MAC spoofing, host API access, LAN/loopback/link-local/metadata access. Host enforcement blocks the prohibited paths. |
| AT-055 | R-06, R-11 | Re-enable IPv6 in a root-enabled guest and attempt IPv6 egress. Host boundary still drops it under the V1 IPv4-only policy. |
| AT-056 | R-06, R-11 | Change guest routes/DNS, unset proxy variables, connect directly to public IPs, use UDP/443 or alternate DNS in inspection mode. No silent bypass. |
| AT-057 | R-06 | Compare controlled flow tuples/counters and DNS records with fixture truth. Distinguish attempted/completed connections and DNS query evidence from request identity. |
| AT-058 | R-06, R-12 | Reuse network tuples, use UDP and connect through the proxy. Exact associations stay exact; ambiguous guest process attribution is shown as unknown/inferred. |
| AT-059 | R-06, R-11 | Test DNS rebinding, redirects to private addresses, mismatched CONNECT/Host authority, literals and unauthorized ports. Validate the actual upstream destination and deny bypasses. |
| AT-060 | R-06, R-12 | Exceed denial-log rate limits or drop packet/conntrack observations. Counters, sampling and gap metadata remain visible; missing individual records are not fabricated. |
| AT-061 | R-07 | Intercept controlled HTTPS using the per-VM CA with template curl/Python/Node/Git/package-manager clients. Verify upstream validation remains enabled. |
| AT-062 | R-07, R-12 | Use a pinned-certificate client or incompatible trust store. Show inspection failure or explicit passthrough status; never claim body visibility. |
| AT-063 | R-07, R-09 | Stream SSE/model-like responses, large package bodies, HTTP/2 multiplexed requests and WebSocket upgrades. Bounded records appear before close; no indefinite whole-body buffering. |
| AT-064 | R-06, R-07, R-10 | Kill proxy, resolver and flow workers separately. Policy stays installed; inspection has no direct fail-open fallback; required observation policy reacts as specified. |
| AT-065 | R-06, R-11 | Attempt to use another VM's proxy listener/CA identity. Connections and records cannot acquire another VM's network authority or log binding. |

## G. Durability, replay and crash behavior

| Test | Requirement | Procedure and required result |
|---|---|---|
| AT-066 | R-04, R-10 | Kill the controller after runner fsync/guest ACK but before database indexing. Restart indexes every acknowledged event once through deduplication. |
| AT-067 | R-04, R-10 | Kill after database commit but before spool-prune acknowledgment. Replay does not duplicate canonical event rows. |
| AT-068 | R-04, R-10 | Crash mid-record/segment creation before durable ACK. Recover an unacknowledged tail safely; corrupt interior data is flagged, not silently ignored. |
| AT-069 | R-04, R-11 | Replay a source sequence with different payload or spoof VM/provenance fields. Reject/quarantine contradiction; guest data cannot overwrite authoritative metadata. |
| AT-070 | R-04, R-12 | Reset guest wall clock, restart a collector and delay buffered streams. Source ordering, boot/source identity and host capture/ingestion times remain distinct. |
| AT-071 | R-04 | Publish events exactly while subscribing/reconnecting. Cursor-based replay/live delivery has no unreported gap or duplicate UI rows. |
| AT-072 | R-04, R-12 | Request a retained cursor and an expired cursor. Replay the former; return explicit expiry/earliest cursor for the latter. |
| AT-073 | R-04, R-09 | Saturate one VM's spool/index stream while others run. Fair ingestion and bounded memory hold; every loss/truncation policy is visible. |
| AT-074 | R-10, R-12 | Kill guestd in both privilege profiles. Host indicates degraded/unavailable health and maintains egress enforcement; strict mode pauses/stops within its documented detection bound. |
| AT-075 | R-10 | Kill/restart runner and controller independently. Reconcile the actual owned VMM using identity/cgroup evidence, and never signal a PID-reused unrelated process. |
| AT-076 | R-01, R-10 | Race start/stop/pause/delete and cancel during provisioning. Valid transitions serialize; reservations and resource ownership remain correct. |
| AT-077 | R-10, R-14 | Simulate host reboot/power interruption on the test host. Reconcile interrupted runs and retained data; state the durability boundary and any unacknowledged unknown interval. |
| AT-078 | R-10, R-14 | Back up and restore metadata/artifacts to a separate test installation. Verify canonical event counts, artifact digests, retention metadata and no accidental live-VM resurrection. |

## H. Security, UI, export and load

| Test | Requirement | Procedure and required result |
|---|---|---|
| AT-079 | R-11 | Attempt cross-owner API/terminal/artifact access, CSRF mutations, forged proxy identity headers and unauthorized helper RPC. Deny without host side effects. |
| AT-080 | R-11 | Submit host path traversal, symlink substitutions, executable-path injection and arbitrary nft/shell fragments through exposed inputs. Helper rejects them; no generic host exec exists. |
| AT-081 | R-11, R-14 | Inject known canary secrets into headers, query strings, argv, structured bodies and error paths. Search spools, DB, debug/proxy logs and default exports; prohibited plaintext is absent. |
| AT-082 | R-11, R-12 | Enable sensitive body/terminal/pcap/disk capture explicitly. UI/ACL/retention labels are correct and do not falsely promise complete redaction or erasure. |
| AT-083 | R-04, R-11 | Render malicious filenames, URLs, bidi text and JSON fields in every UI view. They remain escaped data; no injected markup, script or misleading hidden action. |
| AT-084 | R-02, R-03, R-04 | Complete the real user workflow: batch launch, correct terminal selection, side-by-side events, filter, pause scrolling, stop one VM and inspect others. Keyboard/refresh/error states work. |
| AT-085 | R-14 | Export a complete bounded run with a known gap, redaction and incomplete preview. Export includes the same coverage, consistency, policy/runtime-lock and digest metadata shown in UI. |
| AT-086 | R-09 | On the documented reference host, measure four-VM workloads, terminal p95 echo, event p95 latency, steady metadata load and burst behavior. Publish measurements; do not mark targets met without data. |
| AT-087 | R-09, R-10 | Exhaust optional capture quota and then approach the host reserve threshold. New launches stop; durable ACK semantics hold; health/control remain usable. |
| AT-088 | R-01, R-11 | Trigger authenticated host emergency stop while guest control is unresponsive. Owned VM uplinks/processes are stopped without touching unrelated host workloads. |

## Traceability and release gate

Every requirement R-01 through R-14 is represented above. The builder must add tests when implementation choices introduce new behavior, not replace this matrix with a handful of happy-path checks.

V1 mandatory gate: all 88 rows are implemented and run in their relevant environment, with every failure or blockage explicitly reported. Any scoped exception requires a documented product limitation and must not contradict the core requirements. Memory snapshot/restore is not part of these 88 V1 rows.
