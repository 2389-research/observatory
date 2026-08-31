// ABOUTME: Host configuration contract from docs/examples/host-config.yaml,
// ABOUTME: parsed strictly. Phase 1 enforces only what this build acts on.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config mirrors the full host-config contract. Sections this build does not
// yet act on still parse, so a complete production config is valid from day one.
type Config struct {
	ConfigVersion      int                `yaml:"config_version"`
	Server             Server             `yaml:"server"`
	Auth               Auth               `yaml:"auth"`
	Paths              Paths              `yaml:"paths"`
	Admission          Admission          `yaml:"admission"`
	VMDefaults         VMDefaults         `yaml:"vm_defaults"`
	Network            Network            `yaml:"network"`
	Observation        Observation        `yaml:"observation"`
	Terminal           Terminal           `yaml:"terminal"`
	Capture            Capture            `yaml:"capture"`
	AgentInterface     AgentInterface     `yaml:"agent_interface"`
	Storage            Storage            `yaml:"storage"`
	PerformanceTargets PerformanceTargets `yaml:"performance_targets"`
}

type Server struct {
	Listen                 string `yaml:"listen"`
	PublicOrigin           string `yaml:"public_origin"`
	Mode                   string `yaml:"mode"`
	TrustForwardedIdentity bool   `yaml:"trust_forwarded_identity"`
}

type Auth struct {
	Mode                  string `yaml:"mode"`
	RequireAuthentication bool   `yaml:"require_authentication"`
	CredentialStore       string `yaml:"credential_store"`
	CSRFProtection        bool   `yaml:"csrf_protection"`
	SessionCookieHTTPOnly bool   `yaml:"session_cookie_http_only"`
	SessionCookieSameSite string `yaml:"session_cookie_same_site"`
	SessionCookieSecure   bool   `yaml:"session_cookie_secure"`
}

type Paths struct {
	State             string `yaml:"state"`
	Runtime           string `yaml:"runtime"`
	ApprovedTemplates string `yaml:"approved_templates"`
	RuntimeLock       string `yaml:"runtime_lock"`
	PrivilegedSocket  string `yaml:"privileged_socket"`
}

type Admission struct {
	AllowMemoryOvercommit       bool    `yaml:"allow_memory_overcommit"`
	CPUOvercommitRatio          float64 `yaml:"cpu_overcommit_ratio"`
	ReserveHostCPUCores         int     `yaml:"reserve_host_cpu_cores"`
	ReserveHostMemoryMinMiB     int64   `yaml:"reserve_host_memory_min_mib"`
	ReserveHostMemoryFraction   float64 `yaml:"reserve_host_memory_fraction"`
	ReservePerVMHostOverheadMiB int64   `yaml:"reserve_per_vm_host_overhead_mib"`
	ReserveInspectionSlots      int     `yaml:"reserve_inspection_slots"`
	ReserveInspectorMemoryMiB   int64   `yaml:"reserve_inspector_memory_mib"`
	ReserveInspectorCPUCores    int     `yaml:"reserve_inspector_cpu_cores"`
	ReserveInspectorScratchMiB  int64   `yaml:"reserve_inspector_scratch_mib"`
	MaxParallelProvisions       int     `yaml:"max_parallel_provisions"`
	MaxBatchSize                int     `yaml:"max_batch_size"`
	DefaultBatchReservation     string  `yaml:"default_batch_reservation"`
	DefaultBatchOnFailure       string  `yaml:"default_batch_on_failure"`
}

type VMDefaults struct {
	VCPUCount           int    `yaml:"vcpu_count"`
	MemoryMiB           int64  `yaml:"memory_mib"`
	RootDiskMiB         int64  `yaml:"root_disk_mib"`
	WorkspaceDiskMiB    int64  `yaml:"workspace_disk_mib"`
	GuestPrivilege      string `yaml:"guest_privilege"`
	NetworkProfile      string `yaml:"network_profile"`
	NetworkPolicyID     string `yaml:"network_policy_id"`
	DiskAllocation      string `yaml:"disk_allocation"`
	MaxTerminalSessions int    `yaml:"max_terminal_sessions"`
	StopGraceSeconds    int    `yaml:"stop_grace_seconds"`
}

type Network struct {
	IPv4OnlyGuestBoundary             bool   `yaml:"ipv4_only_guest_boundary"`
	DropGuestIPv6OnHost               bool   `yaml:"drop_guest_ipv6_on_host"`
	DenyCrossVM                       bool   `yaml:"deny_cross_vm"`
	DenyHostAndSpecialUseDestinations bool   `yaml:"deny_host_and_special_use_destinations"`
	PolicyDirectory                   string `yaml:"policy_directory"`
	ProxyPerVM                        bool   `yaml:"proxy_per_vm"`
	ProxyCAPerVM                      bool   `yaml:"proxy_ca_per_vm"`
	ProxyUpstreamTLSVerify            bool   `yaml:"proxy_upstream_tls_verify"`
	ProxyFailure                      string `yaml:"proxy_failure"`
	RawPcapDefault                    bool   `yaml:"raw_pcap_default"`
}

type Observation struct {
	FilesystemReadsDefault    bool   `yaml:"filesystem_reads_default"`
	RequiredByDefault         bool   `yaml:"required_by_default"`
	FailureActionDefault      string `yaml:"failure_action_default"`
	HeartbeatIntervalSeconds  int    `yaml:"heartbeat_interval_seconds"`
	HeartbeatTimeoutSeconds   int    `yaml:"heartbeat_timeout_seconds"`
	MaxFrameBytes             int64  `yaml:"max_frame_bytes"`
	MaxGuestPendingBytes      int64  `yaml:"max_guest_pending_bytes"`
	MaxRunnerSpoolBytes       int64  `yaml:"max_runner_spool_bytes"`
	HostEmergencyReserveBytes int64  `yaml:"host_emergency_reserve_bytes"`
	SpoolAckBarrier           string `yaml:"spool_ack_barrier"`
	SourceDeduplication       string `yaml:"source_deduplication"`
}

type Terminal struct {
	MaxReplayBytesPerSession int64 `yaml:"max_replay_bytes_per_session"`
	MaxWireChunkBytes        int64 `yaml:"max_wire_chunk_bytes"`
	MaxInflightBrowserBytes  int64 `yaml:"max_inflight_browser_bytes"`
	WriterLeaseSeconds       int   `yaml:"writer_lease_seconds"`
	RecordInput              bool  `yaml:"record_input"`
	PersistOutputDefault     bool  `yaml:"persist_output_default"`
	AutomaticClipboardWrite  bool  `yaml:"automatic_clipboard_write"`
	AutomaticDownload        bool  `yaml:"automatic_download"`
}

type Capture struct {
	HTTPHeadersDefault           string `yaml:"http_headers_default"`
	HTTPBodiesDefault            string `yaml:"http_bodies_default"`
	MaxHeaderBytes               int64  `yaml:"max_header_bytes"`
	MaxBodyPreviewBytes          int64  `yaml:"max_body_preview_bytes"`
	MaxFilePreviewBytes          int64  `yaml:"max_file_preview_bytes"`
	RedactBeforePersistence      bool   `yaml:"redact_before_persistence"`
	AllowUnredactedProxyFlowDump bool   `yaml:"allow_unredacted_proxy_flow_dump"`
}

type AgentInterface struct {
	SituationMaxResponseBytes   int64           `yaml:"situation_max_response_bytes"`
	AttentionQueueMaxItems      int             `yaml:"attention_queue_max_items"`
	AttentionCollapseDuplicates bool            `yaml:"attention_collapse_duplicates"`
	AttentionTriggers           map[string]bool `yaml:"attention_triggers"`
	RunGoalMaxBytes             int64           `yaml:"run_goal_max_bytes"`
	GuestResultMaxBytes         int64           `yaml:"guest_result_max_bytes"`
	ReportTailMaxBytes          int64           `yaml:"report_tail_max_bytes"`
	// AttentionNotifyHook is host-config only by design; it must never be
	// settable through the API (that would be a host exec primitive).
	AttentionNotifyHook *string `yaml:"attention_notify_hook"`
}

type Storage struct {
	Database                                   string `yaml:"database"`
	SQLiteJournalMode                          string `yaml:"sqlite_journal_mode"`
	SQLiteSynchronous                          string `yaml:"sqlite_synchronous"`
	LogicalWriters                             int    `yaml:"logical_writers"`
	EventRetentionDays                         int    `yaml:"event_retention_days"`
	ArtifactRetentionDays                      int    `yaml:"artifact_retention_days"`
	RawDiskExportRequiresSeparateAuthorization bool   `yaml:"raw_disk_export_requires_separate_authorization"`
	UntrustedHostKernelMounts                  string `yaml:"untrusted_host_kernel_mounts"`
}

type PerformanceTargets struct {
	ReferenceConcurrentVMs        int `yaml:"reference_concurrent_vms"`
	TerminalEchoP95Ms             int `yaml:"terminal_echo_p95_ms"`
	EventVisibilityP95Ms          int `yaml:"event_visibility_p95_ms"`
	SteadyMetadataEventsPerSecond int `yaml:"steady_metadata_events_per_second"`
}

// Load parses path strictly (unknown fields are config typos, not extensions)
// and validates the constraints this build enforces.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &cfg, nil
}

// Validate enforces the constraints phase 1 acts on. Fields the build ignores
// are not judged here; inventing checks for unbuilt behavior would lie about
// coverage.
func (c *Config) Validate() error {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	if c.ConfigVersion != 1 {
		add("config_version must be 1, got %d", c.ConfigVersion)
	}
	if c.Server.Mode != "loopback_only" {
		add("server.mode %q is not supported: only loopback_only until the authentication boundary is built", c.Server.Mode)
	}
	if err := requireLoopback(c.Server.Listen); err != nil {
		add("server.listen: %v", err)
	}
	if c.Storage.Database == "" {
		add("storage.database is required")
	}
	if c.Storage.SQLiteJournalMode != "WAL" {
		add("storage.sqlite_journal_mode must be WAL (this build only implements WAL), got %q", c.Storage.SQLiteJournalMode)
	}
	if c.Storage.SQLiteSynchronous != "FULL" {
		add("storage.sqlite_synchronous must be FULL (this build only implements FULL), got %q", c.Storage.SQLiteSynchronous)
	}
	if c.Storage.LogicalWriters != 1 {
		add("storage.logical_writers must be 1: the store has exactly one logical writer, got %d", c.Storage.LogicalWriters)
	}

	if len(problems) > 0 {
		return errors.New("config invalid: " + strings.Join(problems, "; "))
	}
	return nil
}

// requireLoopback accepts only an explicit loopback IP with port. Hostnames
// (even localhost) are refused: what resolves is not what was audited.
func requireLoopback(listen string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("%q is not host:port: %v", listen, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%q is not an IP address; use an explicit loopback IP such as 127.0.0.1", host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("%s is not a loopback address; the API binds loopback-only until the authentication boundary is built", ip)
	}
	return nil
}
