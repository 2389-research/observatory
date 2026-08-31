// ABOUTME: Report schema types mirroring docs/schemas/run-report.schema.json.
// ABOUTME: additionalProperties:false means no extra fields; omitempty on schema-optional only.
package report

// Options controls report generation tuning knobs.
type Options struct {
	// TailMaxBytes caps stdout/stderr tail captures when execs exist.
	// Unused until exec subsystem lands, but part of the contract.
	TailMaxBytes int64
}

// Report is the top-level run report structure. Field order matches the schema
// so json.Marshal produces canonical output deterministically.
type Report struct {
	SchemaVersion     int              `json:"schema_version"`
	RunID             string           `json:"run_id"`
	VMID              string           `json:"vm_id"`
	BootIDs           []string         `json:"boot_ids"`
	Goal              string           `json:"goal"`
	SuccessCriteria   string           `json:"success_criteria"`
	Outcome           OutcomeBlock     `json:"outcome"`
	Timing            TimingBlock      `json:"timing"`
	Execs             []ExecBlock      `json:"execs"`
	EventRollup       []EventRollupRow `json:"event_rollup"`
	Coverage          CoverageBlock    `json:"coverage"`
	NetworkSummary    NetworkBlock     `json:"network_summary"`
	FilesystemSummary FilesystemBlock  `json:"filesystem_summary"`
	Artifacts         []ArtifactBlock  `json:"artifacts"`
	Attention         []AttentionRow   `json:"attention"`
	Quality           QualityBlock     `json:"quality"`
	Links             LinksBlock       `json:"links"`
}

// OutcomeBlock records the terminal outcome of the run.
type OutcomeBlock struct {
	Status        string   `json:"status"`
	EvaluatedBy   string   `json:"evaluated_by"`
	Reason        string   `json:"reason,omitempty"`
	EvidenceLinks []string `json:"evidence_links"`
}

// TimingBlock records the run's lifecycle timestamps.
type TimingBlock struct {
	CreatedAt   string  `json:"created_at"`
	StartedAt   *string `json:"started_at,omitempty"`
	ConcludedAt string  `json:"concluded_at"`
}

// Counted is the schema's counted object: a count with its reproduce_query.
type Counted struct {
	Count          int64  `json:"count"`
	ReproduceQuery string `json:"reproduce_query"`
}

// ExecBlock describes one exec's result (placeholder — no execs in portable core).
type ExecBlock struct {
	ExecID      string       `json:"exec_id"`
	ArgvPreview string       `json:"argv_preview"`
	Result      ExecResult   `json:"result"`
	Stdout      StreamDigest `json:"stdout"`
	Stderr      StreamDigest `json:"stderr"`
}

// ExecResult is the execution outcome summary.
type ExecResult struct {
	Kind       string `json:"kind"`
	ExitCode   *int   `json:"exit_code,omitempty"`
	Signal     string `json:"signal,omitempty"`
	DurationMS *int64 `json:"duration_ms,omitempty"`
}

// StreamDigest is the stream capture summary.
type StreamDigest struct {
	Bytes          int64  `json:"bytes"`
	Truncated      bool   `json:"truncated"`
	Digest         string `json:"digest,omitempty"`
	Tail           string `json:"tail,omitempty"`
	FullOutputLink string `json:"full_output_link,omitempty"`
}

// EventRollupRow is one family's count in the event rollup.
type EventRollupRow struct {
	Family         string `json:"family"`
	Count          int64  `json:"count"`
	ReproduceQuery string `json:"reproduce_query"`
}

// CoverageBlock describes telemetry health and known gaps.
type CoverageBlock struct {
	TelemetryHealthFinal string        `json:"telemetry_health_final"`
	Gaps                 []CoverageGap `json:"gaps"`
}

// CoverageGap describes one known gap in observability.
type CoverageGap struct {
	Kind         string `json:"kind"`
	Detail       string `json:"detail,omitempty"`
	EvidenceLink string `json:"evidence_link"`
}

// NetworkBlock summarizes network activity counts.
type NetworkBlock struct {
	Profile       string  `json:"profile"`
	Flows         Counted `json:"flows"`
	DNSQueries    Counted `json:"dns_queries"`
	PolicyDenials Counted `json:"policy_denials"`
}

// FilesystemBlock summarizes filesystem activity.
type FilesystemBlock struct {
	LiveMutationEvents Counted   `json:"live_mutation_events"`
	FinalDiff          FinalDiff `json:"final_diff"`
}

// FinalDiff describes the final filesystem diff status.
type FinalDiff struct {
	Status   string `json:"status"`
	Added    *int64 `json:"added,omitempty"`
	Modified *int64 `json:"modified,omitempty"`
	Deleted  *int64 `json:"deleted,omitempty"`
	Link     string `json:"link,omitempty"`
}

// ArtifactBlock describes one stored artifact (none in portable core).
type ArtifactBlock struct {
	ArtifactID string `json:"artifact_id"`
	MediaType  string `json:"media_type"`
	ByteSize   int64  `json:"byte_size"`
	Digest     string `json:"digest"`
	Label      string `json:"label,omitempty"`
}

// AttentionRow is a minimal attention reference in the report.
type AttentionRow struct {
	AttentionID string `json:"attention_id"`
	Kind        string `json:"kind"`
	Severity    string `json:"severity"`
	Acked       bool   `json:"acked"`
	Link        string `json:"link,omitempty"`
}

// QualityBlock records report quality flags.
type QualityBlock struct {
	Truncated bool     `json:"truncated"`
	Redacted  bool     `json:"redacted"`
	Notes     []string `json:"notes,omitempty"`
}

// LinksBlock is the standard link set on a report.
type LinksBlock struct {
	Run    string `json:"run"`
	VM     string `json:"vm"`
	Events string `json:"events"`
	Export string `json:"export,omitempty"`
}
