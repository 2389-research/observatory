// ABOUTME: The API-shaped fixtures every web test reads, in one place.
// ABOUTME: A second copy would drift, and a drifted fixture hides a real wire change.
import type { EventEnvelope, HostStatus, Template, VM } from '../types'

export const testHost: HostStatus = {
  capacity: {
    usable_memory_mib: 8192,
    reserved_memory_mib: 1024,
    free_memory_mib: 2048,
    usable_vcpu: 8,
    reserved_vcpu: 2,
    free_vcpu: 6,
    usable_disk_mib: 100000,
    reserved_disk_mib: 5000,
    free_disk_mib: 20000,
    active_vms: 1,
  },
  runtime: { available: true, reason: '' },
  vms: { running: 1 },
  admission: {
    allow_memory_overcommit: false,
    cpu_overcommit_ratio: 4,
    reserve_per_vm_host_overhead_mib: 768,
    max_parallel_provisions: 2,
    max_batch_size: 8,
  },
  vm_defaults: {
    vcpu_count: 1,
    memory_mib: 512,
    root_disk_mib: 4096,
    workspace_disk_mib: 8192,
    guest_privilege: 'unprivileged',
    network_profile: 'transport',
    network_policy_id: '',
    max_terminal_sessions: 2,
    stop_grace_seconds: 30,
  },
}

export const testTemplates: Template[] = [
  {
    template_id: 'standard',
    description: 'Demo VM template',
    digest: 'sha256:abc',
    kernel_image: '/srv/vmobs/images/vmlinux',
    root_image: '/srv/vmobs/images/rootfs.img',
    guest_privilege_profiles: ['unprivileged'],
    sensors: ['fanotify'],
    protocol_versions: { guestd: '1' },
  },
]

export function testVM(overrides: Partial<VM> = {}): VM {
  return {
    vm_id: 'vm-1',
    name: 'worker-1',
    owner: 'local_operator',
    template_id: 'standard',
    template_digest: 'sha256:abc',
    desired_state: 'running',
    observed_state: 'running',
    revision: '3',
    resources: { vcpu_count: 1, memory_mib: 512, root_disk_mib: 4096, workspace_disk_mib: 8192 },
    network_profile: 'transport',
    network_policy_id: '',
    labels: null,
    created_at: '2026-09-04T10:00:00Z',
    updated_at: '2026-09-04T10:00:05Z',
    links: { self: '/api/v1/vms/vm-1' },
    ...overrides,
  }
}

/**
 * One `operation.state_changed` event, shaped the way the daemon emits it: the
 * envelope's vm_id is null and the VM is named inside `data` (internal/store).
 */
export function testOperationEvent(
  o: {
    event_id?: string
    operation_id?: string
    kind?: string
    vm_id?: string
    phase?: string
    state?: string
    attempt?: number
    error?: { cause: string; message: string }
    host_received_at?: string
  } = {},
): EventEnvelope {
  return {
    event_id: o.event_id ?? '1',
    kind: 'operation.state_changed',
    vm_id: null,
    provenance: 'host_observed',
    host_received_at: o.host_received_at ?? '2026-09-04T10:00:00Z',
    data: {
      operation_id: o.operation_id ?? 'op-000001',
      kind: o.kind ?? 'vm.create',
      vm_id: o.vm_id ?? 'vm-1',
      phase: o.phase ?? 'running',
      state: o.state ?? 'running',
      attempt: o.attempt ?? 1,
      ...(o.error ? { error: o.error } : {}),
    },
  }
}
