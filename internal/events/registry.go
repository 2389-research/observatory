// ABOUTME: The event-kind registry: the single implementation-side table that
// ABOUTME: /meta/event-kinds serves and ingress enforces (P-07, SPEC §12.2, §17).
package events

import "sort"

// KindInfo describes one registered event kind, including the semantic caveats
// an operator needs to interpret it honestly.
type KindInfo struct {
	Kind          string     `json:"kind"`
	Family        string     `json:"family"`
	SchemaVersion int        `json:"schema_version"`
	Provenance    Provenance `json:"provenance"`
	Semantics     string     `json:"semantics"`
	Caveats       []string   `json:"caveats,omitempty"`
}

// registry grows only alongside the code that emits each kind. Ingress rejects
// kinds absent from this table (SPEC §17: unregistered event kind).
var registry = []KindInfo{
	{
		Kind:          "fs.modify",
		Family:        "fs",
		SchemaVersion: 1,
		Provenance:    GuestReported,
		Semantics:     "A modification notification was observed for a file in the monitored guest filesystem scope.",
		Caveats: []string{
			"fanotify can lose events on queue overflow; a quiet stream is not proof of no writes",
			"mmap/msync/munmap writes do not generate this notification",
			"a notification is not a content diff; fs.content_changed requires actual comparison",
			"paths are not stable identities: rename, unlink and hard links can defeat late resolution",
		},
	},
	{
		Kind:          "telemetry.loss",
		Family:        "telemetry",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "An explicit loss interval: events were dropped, with a measured count or an unknown span.",
		Caveats: []string{
			"an unknown-span loss must not be summed as zero events lost",
		},
	},
	{
		Kind:          "telemetry.integrity_failure",
		Family:        "telemetry",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "Trusted ingress refused something a producer sent, and recorded the refusal rather than silently accepting or silently dropping it. data.failure names which: seq_payload_conflict (a key resent with different payload bytes), stream_scope_rebind (a stream reassigned to another scope), guest_provenance_claim (a guest reported a host_observed kind), unexpected_frame or malformed_push (a frame the channel's contract refuses).",
		Caveats: []string{
			"the refused event is not stored; this record is the only trace of it",
			"one failure per refusal, not per producer: a producer repeating the same violation produces one of these each time",
		},
	},
	{
		Kind:          "telemetry.unregistered_kind",
		Family:        "telemetry",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "Ingress rejected an event whose kind is not in this registry; the original kind and source are recorded in data.",
	},
	{
		Kind:          "attention.raised",
		Family:        "attention",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "A deterministic trigger raised an attention item; data carries the item fields. The event is host-wide; VM linkage lives in data and on the queue item.",
		Caveats: []string{
			"raised only by the in-process trigger engine, never by API clients",
			"duplicates of an open item collapse on the queue with counts; each raise is still its own event",
		},
	},
	{
		Kind:          "attention.queue_overflow",
		Family:        "attention",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "The bounded attention queue refused a non-critical item; data records the refused trigger class and scope. Critical items are never refused.",
	},
	{
		Kind:          "annotation.created",
		Family:        "annotation",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "An operator annotation was recorded against an entity ref; data carries the annotation. Annotations are immutable once created.",
		Caveats: []string{
			"text is stored post-redaction; the original input is not retained",
		},
	},
	{
		Kind:          "vm.created",
		Family:        "vm",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "A VM record was created and its resources reserved. Data carries vm_id, name, template_id, template_digest, operation_id, owner, and resources.",
		Caveats: []string{
			"creation precedes boot; the VM is in provisioning state and is not yet running",
		},
	},
	{
		Kind:          "vm.state_changed",
		Family:        "vm",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "An observed lifecycle state transition. Data carries vm_id, from, to, reason, operation_id, and revision as a decimal string.",
		Caveats: []string{
			"failed state carries failure_stage and failure_reason for the last completed stage",
			"paused VMs retain memory and disk reservations; freed compute is only on stopped",
		},
	},
	{
		Kind:          "vm.cleanup_failed",
		Family:        "vm",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "A cleanup the controller retried did not complete; the VM's host resources are still owned. Data carries vm_id, the state the row is retained in, and reason.",
		Caveats: []string{
			"a row held at stopping or deleting is retried at every controller start; a stopped row's outstanding cleanup is retried by the next delete",
			"reason is the runtime's own error text, redacted per SPEC §15.3",
		},
	},
	{
		Kind:          "vm.reconcile_ambiguous",
		Family:        "vm",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "A startup scan looked at this VM's host state and could not classify it, so its row was left exactly as found. Data carries vm_id, the state the row is held in, and detail.",
		Caveats: []string{
			"the row is not a claim about the VM: it is the state the last controller left, held because nothing since has observed otherwise",
			"detail is the runtime's own account of what it could not tell, redacted per SPEC §15.3",
		},
	},
	{
		Kind:          "vm.deleted",
		Family:        "vm",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "VM compute resources were deleted. Retained history and artifacts are not purged by deletion (SPEC §5.4). Data carries vm_id and operation_id.",
	},
	{
		Kind:          "operation.state_changed",
		Family:        "operation",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "Operation progress event. Data carries operation_id, kind, vm_id (nullable), phase, state, attempt, and error {cause, message} when failed. Terminal states are succeeded and failed.",
	},
	{
		Kind:          "run.created",
		Family:        "run",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "A declarative run was created and bound to a VM. Data carries run_id, vm_id, goal, success_criteria, on_completion, progress_events, and the initial phase.",
		Caveats: []string{
			"creation is not evaluation; the outcome exists only in the terminal run.state_changed",
		},
	},
	{
		Kind:          "run.state_changed",
		Family:        "run",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "A run phase transition. Data carries run_id, vm_id, from, to, and on terminal transitions outcome fields (evaluated_by, reason).",
		Caveats: []string{
			"terminal outcome stands even if a later report generation fails",
		},
	},
	{
		Kind:          "run.progress",
		Family:        "run",
		SchemaVersion: 1,
		Provenance:    GuestReported,
		Semantics:     "Bounded structured progress submitted by the guest workload. Data carries run_id, vm_id, seq, and the payload.",
		Caveats: []string{
			"guest-supplied content: tamperable in developer_root and not verified by the host",
			"seq orders submissions within one run",
		},
	},
	{
		Kind:          "run.result_recorded",
		Family:        "run",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "Trusted ingress recorded a guest-submitted final result. Data carries run_id, vm_id, status, and size_bytes; the full result is served on the run resource.",
		Caveats: []string{
			"the event is host_observed (the recording); the result content itself is guest-supplied and labeled guest_reported where served",
		},
	},
	{
		Kind:          "run.submission_rejected",
		Family:        "run",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "Ingress refused an oversized or malformed guest submission. Data carries run_id, vm_id, submission (progress|result), reason, and size_bytes.",
		Caveats: []string{
			"rejection is bounded and durable; the refused payload is not retained",
		},
	},
	// auth.* family: operator session and token lifecycle events (P5, §15.1).
	// All are host_observed — trusted ingress assigns provenance; no guest path exists.
	{
		Kind:          "auth.session_created",
		Family:        "auth",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "Operator login established a browser session",
	},
	{
		Kind:          "auth.session_ended",
		Family:        "auth",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "Operator logout ended a session",
		Caveats: []string{
			"expiry is lazy and does not emit this event; only explicit logout fires session_ended",
		},
	},
	{
		Kind:          "auth.login_failed",
		Family:        "auth",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "A login attempt failed",
		Caveats: []string{
			"serialized and delayed at ingress so volume is bounded",
			"username in data is bounded to 64 bytes",
		},
	},
	{
		Kind:          "auth.token_created",
		Family:        "auth",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "A CLI token was minted",
		Caveats: []string{
			"data carries token id and name, never the secret",
		},
	},
	{
		Kind:          "auth.token_revoked",
		Family:        "auth",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "A CLI token was revoked",
	},
	// guest.* family: events about the vsock control channel between the host
	// runner and the guest agent (L1a, §7.4). All are host_observed — the host
	// is the authoritative observer of the channel state.
	{
		Kind:          "guest.channel_established",
		Family:        "guest",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "Runner completed the authenticated vsock handshake with the guest agent.",
		Caveats: []string{
			"established does not imply the guest workload is running; it only proves the channel is ready",
		},
	},
	{
		Kind:          "guest.channel_lost",
		Family:        "guest",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "The vsock control channel closed or a ping window expired.",
		Caveats: []string{
			"channel loss does not imply guest crash; the VMM may still be running",
		},
	},
	// guest.sensor_health: the guest agent's own periodic report on its sensors
	// (M2a, §138–§139). The one guest_reported kind on the telemetry channel in
	// this slice; every later sensor registers into its sensors array.
	{
		Kind:          "guest.sensor_health",
		Family:        "guest",
		SchemaVersion: 1,
		Provenance:    GuestReported,
		Semantics:     "The guest agent reported its own liveness, its bounded ring's drop count, and the state of each sensor it has registered.",
		Caveats: []string{
			"a heartbeat proves the guest agent is alive; it proves nothing about what any sensor observed",
			"an empty sensors array means no sensor is registered, not that no activity occurred",
			"drop counts are the guest's own measurement of its ring; loss elsewhere in the path is not counted here",
			"the absence of heartbeats is not itself an event — staleness is derived by comparing the newest one against the host clock",
		},
	},
	// vm.vmm_exited: host runner observed the supervised VMM process exit (L1a).
	{
		Kind:          "vm.vmm_exited",
		Family:        "vm",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "The supervised VMM process is gone as observed by the runner.",
		Caveats: []string{
			"exit does not distinguish clean shutdown from crash; the graceful field reports the runner's assessment",
		},
	},
	// spool.recovery_gap: importer detected unreadable spool records (L1a, §12.5).
	{
		Kind:          "spool.recovery_gap",
		Family:        "spool",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "Importer or reader detected unreadable spool records; an unknown interval is reported, not an invented count.",
		Caveats: []string{
			"count of lost records is not claimed — an unknown interval is reported, not invented",
		},
	},
	// net.flow, dns, and policy families: reserved for the network inspection
	// subsystem (L1). Registered now so run-report reproduce_queries are valid
	// today (zero counts are honest); actual ingress awaits the network emitter.
	{
		Kind:          "net.flow.observed",
		Family:        "net.flow",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "A network flow was observed for the VM. Reserved for the network inspection subsystem; not yet emitted in this build.",
		Caveats: []string{
			"not emitted in the portable core; queries return zero results until the network subsystem lands",
		},
	},
	{
		Kind:          "dns.query",
		Family:        "dns",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "A DNS query was observed for the VM. Reserved for the network inspection subsystem; not yet emitted in this build.",
		Caveats: []string{
			"not emitted in the portable core; queries return zero results until the network subsystem lands",
		},
	},
	{
		Kind:          "policy.denial",
		Family:        "policy",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "A network policy denial was observed for the VM. Reserved for the network inspection subsystem; not yet emitted in this build.",
		Caveats: []string{
			"not emitted in the portable core; queries return zero results until the network subsystem lands",
		},
	},
	{
		Kind:          "terminal.session_opened",
		Family:        "terminal",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "The host opened an interactive terminal session on a VM: session_id, vm_id, boot_id, owner, rows, cols and argv. The host mints the session id and asks the guest for the PTY, so this records the request the host made.",
		Caveats: []string{
			"the session is bound to boot_id; after a reboot the same session id is stale, not resumable",
			"argv is what the host asked for, not proof of what the guest executed",
		},
	},
	{
		Kind:          "terminal.session_closed",
		Family:        "terminal",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "An interactive terminal session ended: session_id, vm_id, reason, optional exit_code and signal, and the output_bytes, input_bytes and dropped_bytes counts for the session.",
		Caveats: []string{
			"output_bytes, input_bytes and dropped_bytes are decimal strings: a busy shell passes 2^53 bytes in days",
			"a session the host never saw close — a VMM that vanished — has no event here; absence is not proof it is still open",
			"exit_code and signal are absent unless the guest reported them",
		},
	},
	{
		Kind:          "terminal.output_dropped",
		Family:        "terminal",
		SchemaVersion: 1,
		Provenance:    HostObserved,
		Semantics:     "The guest's replay ring overwrote output nobody had read yet, losing the byte range from_offset to to_offset on that session's stream.",
		Caveats: []string{
			"from_offset and to_offset are decimal strings",
			"the range names bytes that are gone; it is a loss report, not a recoverable pointer",
			"the PTY was never blocked to prevent this: §8.3 chooses a live shell over a complete transcript",
		},
	},
}

var registryByKind = func() map[string]KindInfo {
	m := make(map[string]KindInfo, len(registry))
	for _, k := range registry {
		m[k.Kind] = k
	}
	return m
}()

// Kinds returns the registered kinds sorted by kind name.
func Kinds() []KindInfo {
	out := make([]KindInfo, len(registry))
	copy(out, registry)
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}

// LookupKind returns the registry entry for kind.
func LookupKind(kind string) (KindInfo, bool) {
	info, ok := registryByKind[kind]
	return info, ok
}

// KindsByFamily returns the kind strings for all registered kinds whose Family
// matches family. Returns nil (not an empty slice) when the family has no
// registered kinds — the caller should treat nil as an unknown family.
func KindsByFamily(family string) []string {
	var out []string
	for _, k := range registry {
		if k.Family == family {
			out = append(out, k.Kind)
		}
	}
	return out
}

// Families returns all distinct family names in the registry, sorted
// alphabetically. The order is deterministic regardless of registry slice order.
func Families() []string {
	seen := make(map[string]struct{}, len(registry))
	for _, k := range registry {
		seen[k.Family] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}
