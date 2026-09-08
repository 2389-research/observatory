// ABOUTME: TypeScript mirrors of the /api/v1 wire shapes the fleet page reads.
// ABOUTME: Counters that can outgrow Number.MAX_SAFE_INTEGER stay strings, always.
export interface Capacity {
  usable_memory_mib: number
  reserved_memory_mib: number
  free_memory_mib: number
  usable_vcpu: number
  reserved_vcpu: number
  free_vcpu: number
  usable_disk_mib: number
  reserved_disk_mib: number
  free_disk_mib: number
  active_vms: number
}

/** What the host charges and caps when admitting a VM. */
export interface Admission {
  allow_memory_overcommit: boolean
  cpu_overcommit_ratio: number
  reserve_per_vm_host_overhead_mib: number
  max_parallel_provisions: number
  max_batch_size: number
}

/** What a create request gets for every field it leaves out. */
export interface VMDefaults {
  vcpu_count: number
  memory_mib: number
  root_disk_mib: number
  workspace_disk_mib: number
  guest_privilege: string
  network_profile: string
  network_policy_id: string
  max_terminal_sessions: number
  stop_grace_seconds: number
}

export interface HostStatus {
  capacity: Capacity
  runtime: { available: boolean; reason: string }
  vms: Record<string, number>
  admission: Admission
  vm_defaults: VMDefaults
  preflight?: unknown
}

export interface Template {
  template_id: string
  description: string
  digest: string
  guest_privilege_profiles: string[]
  sensors: string[]
  protocol_versions: Record<string, string>
}

export interface TemplateList {
  templates: Template[]
}

export interface VMResources {
  vcpu_count: number
  memory_mib: number
  root_disk_mib: number
  workspace_disk_mib: number
}

export interface VMFailure {
  stage: string
  reason: string
}

export interface VM {
  vm_id: string
  name: string
  owner: string
  template_id: string
  template_digest: string
  desired_state: string
  observed_state: string
  /**
   * The second health dimension (SPEC §133): how well this VM is being
   * observed, which is a separate question from what it is doing. A VM can be
   * running with degraded telemetry, and §138 forbids showing only one.
   * One of: starting, healthy, degraded, unavailable.
   */
  telemetry_health: string
  /** Decimal string: may exceed Number.MAX_SAFE_INTEGER. Never parse it. */
  revision: string
  resources: VMResources
  network_profile: string
  network_policy_id: string
  labels: Record<string, string> | null
  failure?: VMFailure
  created_at: string
  updated_at: string
  links: Record<string, string>
}

export interface VMList {
  vms: VM[]
  next_after: string
}

export interface Attention {
  attention_id: string
  cursor: string
  severity: string
  kind: string
  vm_id?: string
  run_id?: string
  summary: string
  system_action: string
  /** Decimal string, same rule as VM.revision. */
  count: string
  acked: boolean
  evidence_links: string[]
}

export interface AttentionList {
  items: Attention[]
  next_after?: string
}

export interface Meta {
  service: string
  version: string
  api_version: string
  features: Record<string, boolean>
}

/** The typed error envelope every non-2xx response carries (SPEC P-06). */
export interface ApiError {
  code: string
  message: string
  cause: string
  retryable: boolean
  remediation?: { action: string; rationale: string }[]
}

/** One member's outcome inside a batch reply (SPEC §6.3). */
export interface BatchMember {
  position: number
  name: string
  vm?: VM
  operation?: Operation
  /** The daemon's refusal for this member alone. The wire carries no per-member remediation. */
  refusal?: { cause: string; message: string }
}

export interface Operation {
  operation_id: string
  kind: string
  vm_id?: string
  phase: string
  /** `running` while in flight; `succeeded` and `failed` are terminal. */
  state: string
  error?: { cause: string; message: string }
  attempt: number
  created_at: string
  updated_at: string
}

export interface Batch {
  batch_id: string
  owner: string
  idempotency_key?: string
  reservation_mode: string
  on_failure: string
  created_at: string
  updated_at: string
  links: Record<string, string>
}

export interface BatchReply {
  batch: Batch
  operation?: Operation
  members: BatchMember[]
  is_replay?: boolean
}

/**
 * One event as GET /events returns it. Only the fields this UI reads are named;
 * the wire envelope carries more (SPEC §12.1).
 *
 * Store-synthesized events — `vm.*`, `operation.*`, `run.*` — ride the host-wide
 * stream with a null envelope `vm_id` and name their VM inside `data`, so a
 * reader that wants the VM must look in both places.
 */
export interface EventEnvelope {
  process_key?: string
  boot_id?: string | null
  guest_wall_at?: string | null
  quality?: Record<string, unknown>
  event_id: string
  kind: string
  vm_id: string | null
  provenance: string
  host_received_at: string
  data: Record<string, unknown>
}

export interface EventPage {
  events: EventEnvelope[]
  /** Resume cursor: the highest event_id on this page. */
  next_after: string
  /** How far the store goes, so an empty page reads as quiet, not as a gap. */
  latest_event_id: string
}

/**
 * One terminal session, as POST and GET /vms/{id}/terminals return it (§8.2).
 * `state` is `open` or `closed`.
 */
export interface TerminalSession {
  session_id: string
  vm_id: string
  /** The boot this session belongs to. A reboot makes the session stale. */
  boot_id: string
  owner: string
  state: string
  rows: number
  cols: number
  argv: string[]
  pid: number
  created_at: string
  /** Decimal strings: byte counters outgrow Number.MAX_SAFE_INTEGER. */
  output_bytes: string
  input_bytes: string
  /** The connection holding the writer lease, or empty when nobody holds it. */
  writer_holder: string
  writer_available: boolean
  closed_at?: string
  reason?: string
  exit_code?: number
  signal?: string
  links: Record<string, string>
}

export interface TerminalSessionList {
  terminals: TerminalSession[]
  next_after: string
  limit: number
}

/** Capture health is separate from channel liveness and uses nullable unknown counters. */
export interface CollectorCoverage {
  id: string
  state: string
  enabled: boolean
  event_classes: string[]
  scope: string[]
  exclusions: string[]
  limitations: string[]
  observed_dropped: string | null
  unknown_loss_intervals: number | null
  last_event_at?: string
  last_success_at?: string
  capture_mode?: string
  reason?: string
  source: string
  provenance: string
}
export interface CaptureCoverage {
  vm_id: string
  boot_id?: string
  channel: {
    state: string
    observed_dropped: string | null
    reason?: string
    last_heartbeat_at?: string
    last_success_at?: string
  }
  collectors: CollectorCoverage[]
  gaps: string[]
}
