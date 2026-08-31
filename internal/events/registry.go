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
		Semantics:     "A producer resent a (source_instance_id, source_seq) key with different payload bytes: protocol-integrity failure, recorded, not silently updated.",
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
