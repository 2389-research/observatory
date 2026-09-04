// ABOUTME: Reservation preview arithmetic: what a launch would charge the host.
// ABOUTME: Every input is a number GET /host/status served; nothing here is a private constant.
import type { HostStatus, VMResources } from './types'

/** One resource line of the preview: what is asked against what is free. */
export interface ReservationLine {
  resource: 'memory' | 'vcpu' | 'disk'
  unit: string
  requested: number
  free: number
  over: boolean
}

export interface Reservation {
  memory: ReservationLine
  vcpu: ReservationLine
  disk: ReservationLine
  /** True when any line exceeds what the host has free. */
  over: boolean
}

/**
 * What launching `count` VMs of these resources would reserve.
 *
 * Memory charges the host's published per-VM overhead on top of the guest's
 * own memory, because that is what the daemon's admission check charges. A
 * browser that charged a different number would draw a preview the host does
 * not honour (SPEC §13, AT-101).
 *
 * This is a warning, not a gate: the daemon decides admission, and its typed
 * refusal is the answer the operator sees.
 */
export function reservationFor(res: VMResources, host: HostStatus, count = 1): Reservation {
  return reservationForAll(new Array<VMResources>(count).fill(res), host)
}

/**
 * The same arithmetic for a batch whose members differ from each other.
 *
 * A batch preview sums its members rather than multiplying one of them: the
 * form lets each member carry its own size, and a multiplied preview would
 * quietly describe a batch nobody asked for.
 */
export function reservationForAll(all: VMResources[], host: HostStatus): Reservation {
  const cap = host.capacity
  const overhead = host.admission.reserve_per_vm_host_overhead_mib
  const sum = (of: (r: VMResources) => number) => all.reduce((total, r) => total + of(r), 0)

  const line = (
    resource: ReservationLine['resource'],
    unit: string,
    requested: number,
    free: number,
  ): ReservationLine => ({ resource, unit, requested, free, over: requested > free })

  const memory = line('memory', 'MiB', sum((r) => r.memory_mib + overhead), cap.free_memory_mib)
  const vcpu = line('vcpu', 'vCPU', sum((r) => r.vcpu_count), cap.free_vcpu)
  const disk = line('disk', 'MiB', sum((r) => r.root_disk_mib + r.workspace_disk_mib), cap.free_disk_mib)

  return { memory, vcpu, disk, over: memory.over || vcpu.over || disk.over }
}
