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

export interface HostStatus {
  capacity: Capacity
  runtime: { available: boolean; reason: string }
  vms: Record<string, number>
  preflight?: unknown
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
