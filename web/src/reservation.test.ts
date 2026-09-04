// ABOUTME: The preview restates the host's published overhead, at one VM and at four.
import { describe, it, expect } from 'vitest'
import { reservationFor } from './reservation'
import type { HostStatus, VMResources } from './types'

const host: HostStatus = {
  capacity: {
    usable_memory_mib: 8192,
    reserved_memory_mib: 1024,
    free_memory_mib: 6000,
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

const res: VMResources = {
  vcpu_count: 1,
  memory_mib: 512,
  root_disk_mib: 2048,
  workspace_disk_mib: 1024,
}

describe('reservationFor', () => {
  it('charges the published per-VM overhead once per VM', () => {
    expect(reservationFor(res, host, 1).memory.requested).toBe(1280)
    expect(reservationFor(res, host, 4).memory.requested).toBe(5120)
  })

  it('counts disk as root plus workspace, per VM', () => {
    expect(reservationFor(res, host, 1).disk.requested).toBe(3072)
    expect(reservationFor(res, host, 4).disk.requested).toBe(12288)
  })

  it('counts vCPU without an overhead the host does not charge', () => {
    expect(reservationFor(res, host, 4).vcpu.requested).toBe(4)
  })

  it('reads free capacity from the host, never from a total it computes', () => {
    const r = reservationFor(res, host, 1)
    expect(r.memory.free).toBe(host.capacity.free_memory_mib)
    expect(r.vcpu.free).toBe(host.capacity.free_vcpu)
    expect(r.disk.free).toBe(host.capacity.free_disk_mib)
  })

  it('marks the line that exceeds free capacity, and only that line', () => {
    const r = reservationFor(res, host, 8) // 8 × 1280 = 10240 memory, 8 vCPU, 24576 disk
    expect(r.memory.over).toBe(true)
    expect(r.vcpu.over).toBe(true)
    expect(r.disk.over).toBe(true)
    expect(r.over).toBe(true)

    const fits = reservationFor(res, host, 1)
    expect(fits.over).toBe(false)
  })
})
