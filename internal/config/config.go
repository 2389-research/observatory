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
	Runtime            Runtime            `yaml:"runtime"`
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

// Runtime holds runtime verification settings. The zero value (no runtime:
// section in YAML) applies defaults in Load.
type Runtime struct {
	// LockFile is the path to runtime.lock.json. Default: "runtime.lock.json"
	// (relative to wherever the daemon is invoked). Empty string disables lock
	// verification entirely (useful for integration environments).
	LockFile string `yaml:"lock_file"`

	// Mode selects the VM runtime. "unavailable" (default) keeps the existing
	// ForHost path. "firecracker" wires the real adapter on Linux; the darwin
	// stub returns a config error. Future modes would land here.
	Mode string `yaml:"mode"`

	// JailUIDBase is the first UID assigned to a jailed VM (slot 0 = JailUIDBase,
	// slot 1 = JailUIDBase+1, …). Default: 20000.
	JailUIDBase int `yaml:"jail_uid_base"`

	// JailGID is the shared group ID for all jailed VM processes. Default: 36000.
	JailGID int `yaml:"jail_gid"`

	// CIDBase is the base vsock CID (slot 0 = CIDBase, slot 1 = CIDBase+1, …).
	// Default: 3 (CIDs 0–2 are reserved by the vsock spec).
	CIDBase int `yaml:"cid_base"`
}

type Server struct {
	Listen                 string `yaml:"listen"`
	PublicOrigin           string `yaml:"public_origin"`
	Mode                   string `yaml:"mode"`
	TrustForwardedIdentity bool   `yaml:"trust_forwarded_identity"`
	// TLSCertFile and TLSKeyFile are required in mode: https; must be empty in loopback_only.
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
}

type Auth struct {
	Mode                  string `yaml:"mode"`
	RequireAuthentication bool   `yaml:"require_authentication"`
	CredentialStore       string `yaml:"credential_store"`
	CSRFProtection        bool   `yaml:"csrf_protection"`
	SessionCookieHTTPOnly bool   `yaml:"session_cookie_http_only"`
	SessionCookieSameSite string `yaml:"session_cookie_same_site"`
	SessionCookieSecure   bool   `yaml:"session_cookie_secure"`
	// SessionTTLMinutes is the absolute browser-session lifetime in minutes.
	// 0 in YAML → default 720 applied in Load.
	SessionTTLMinutes int `yaml:"session_ttl_minutes"`
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

// defaults holds the pre-decode values for fields whose zero value is
// ambiguous: an absent YAML key leaves these intact, while an explicit YAML
// value overwrites them. Fields with unambiguous zero values (bool, int 0)
// stay in post-decode logic below.
func defaults() Config {
	return Config{
		Runtime: Runtime{
			// Empty string means "explicitly no lock". An absent runtime:
			// lock_file key leaves this default; lock_file: "" overwrites it.
			LockFile: "runtime.lock.json",
			Mode:     "unavailable",
			// Defaults match L0's fixture UID/GID assignment (SPEC §10.1, L0-R11).
			JailUIDBase: 20000,
			JailGID:     36000,
			// CIDs 0–2 are reserved by the vsock spec; base at 3.
			CIDBase: 3,
		},
	}
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
	cfg := defaults()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.Auth.SessionTTLMinutes == 0 {
		cfg.Auth.SessionTTLMinutes = 720
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &cfg, nil
}

// AuthEnabled reports whether caller authentication is required.
func (c *Config) AuthEnabled() bool {
	return c.Auth.RequireAuthentication
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
	switch c.Server.Mode {
	case "loopback_only":
		if err := requireLoopback(c.Server.Listen); err != nil {
			add("server.listen: %v", err)
		}
		if c.Server.TLSCertFile != "" || c.Server.TLSKeyFile != "" {
			add("tls_cert_file/tls_key_file are set but server.mode is loopback_only; a cert nothing serves is a config lie")
		}
		// require_authentication: false is legal here and only here —
		// loopback + host ACLs, the P1–P4 trust model, kept for dev.
	case "https":
		if c.Server.TLSCertFile == "" {
			add("server.mode https requires tls_cert_file")
		}
		if c.Server.TLSKeyFile == "" {
			add("server.mode https requires tls_key_file")
		}
		if !c.Auth.RequireAuthentication {
			add("server.mode https requires auth.require_authentication: true")
		}
		if !c.Auth.SessionCookieSecure {
			add("server.mode https requires auth.session_cookie_secure: true")
		}
		if !strings.HasPrefix(c.Server.PublicOrigin, "https://") {
			add("server.mode https requires an https:// public_origin, got %q", c.Server.PublicOrigin)
		}
	default:
		add("server.mode %q is not supported: loopback_only or https", c.Server.Mode)
	}
	if c.Server.TrustForwardedIdentity {
		add("server.trust_forwarded_identity is not built in this version; only direct local_operator auth exists")
	}
	if c.Auth.RequireAuthentication {
		if c.Auth.Mode != "local_operator" {
			add("auth.mode %q is not built: only local_operator", c.Auth.Mode)
		}
		if c.Auth.CredentialStore == "" {
			add("auth.credential_store is required when require_authentication is true")
		}
		if !c.Auth.CSRFProtection {
			add("auth.csrf_protection cannot be disabled while authentication is enabled")
		}
		if !c.Auth.SessionCookieHTTPOnly {
			add("auth.session_cookie_http_only cannot be disabled while authentication is enabled")
		}
		if ss := c.Auth.SessionCookieSameSite; ss != "strict" && ss != "lax" {
			add("auth.session_cookie_same_site must be strict or lax, got %q", ss)
		}
	}
	if c.Auth.SessionTTLMinutes < 0 {
		add("auth.session_ttl_minutes must be >= 0, got %d", c.Auth.SessionTTLMinutes)
	}
	switch c.Runtime.Mode {
	case "unavailable", "firecracker":
		// valid
	default:
		add("runtime.mode %q is not supported: unavailable or firecracker", c.Runtime.Mode)
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
		return fmt.Errorf("%s is not a loopback address; loopback_only mode always binds loopback — use server.mode https to serve beyond this host", ip)
	}
	return nil
}
