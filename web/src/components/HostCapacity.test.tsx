// ABOUTME: Tests for the host capacity panel: reservations, free headroom, runtime health.
// ABOUTME: A degraded runtime must be visible on the landing page, not buried in a field.
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { HostCapacity } from './HostCapacity'
import type { HostStatus } from '../types'

const status = (over: Partial<HostStatus> = {}): HostStatus => ({
  capacity: {
    usable_memory_mib: 60000,
    reserved_memory_mib: 4096,
    free_memory_mib: 55904,
    usable_vcpu: 16,
    reserved_vcpu: 4,
    free_vcpu: 12,
    usable_disk_mib: 23339,
    reserved_disk_mib: 8320,
    free_disk_mib: 15019,
    active_vms: 2,
  },
  runtime: { available: true, reason: '' },
  vms: { running: 2, stopped: 1 },
  ...over,
})

describe('HostCapacity', () => {
  it('reports reserved against usable for each resource', () => {
    render(<HostCapacity status={status()} />)
    expect(screen.getByText('4096 / 60000 MiB')).toBeInTheDocument()
    expect(screen.getByText('4 / 16 vCPU')).toBeInTheDocument()
    expect(screen.getByText('8320 / 23339 MiB')).toBeInTheDocument()
  })

  it('shows how much room is left for the next VM', () => {
    render(<HostCapacity status={status()} />)
    expect(screen.getByText(/55904 MiB free/)).toBeInTheDocument()
    expect(screen.getByText(/15019 MiB free/)).toBeInTheDocument()
  })

  it('raises the runtime reason when Firecracker is unavailable', () => {
    render(
      <HostCapacity
        status={status({ runtime: { available: false, reason: 'kvm_unavailable' } })}
      />,
    )
    expect(screen.getByRole('alert')).toHaveTextContent('kvm_unavailable')
  })

  it('shows no alert when the runtime is available', () => {
    render(<HostCapacity status={status()} />)
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('breaks the fleet down by observed state', () => {
    render(<HostCapacity status={status()} />)
    expect(screen.getByText('running')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
    expect(screen.getByText('stopped')).toBeInTheDocument()
  })

  it('handles an idle host without inventing a state breakdown', () => {
    render(<HostCapacity status={status({ vms: {}, capacity: { ...status().capacity, active_vms: 0 } })} />)
    expect(screen.getByText(/no vms/i)).toBeInTheDocument()
  })
})
