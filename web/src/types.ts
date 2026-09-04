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
  kernel_image: string
  root_image: string
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
