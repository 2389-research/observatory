// ABOUTME: The API-shaped fixtures every web test reads, in one place.
// ABOUTME: A second copy would drift, and a drifted fixture hides a real wire change.
import type { HostStatus, Template, VM } from '../types'

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
