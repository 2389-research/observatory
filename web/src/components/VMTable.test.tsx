// ABOUTME: Tests for the fleet VM table: honest gaps, exact counters, inert strings.
// ABOUTME: SPEC §13.1 names columns this build cannot measure; they must say so.
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { VMTable } from './VMTable'
import type { VM } from '../types'

const vm = (over: Partial<VM> = {}): VM => ({
  vm_id: '7f3a9c21-0000-4000-8000-000000000001',
  name: 'agent-03',
  owner: 'local_operator',
  template_id: 'python-dev',
  template_digest: 'sha256:abcdef0123456789',
  desired_state: 'running',
  observed_state: 'running',
  revision: '7',
  resources: { vcpu_count: 2, memory_mib: 2048, root_disk_mib: 4096, workspace_disk_mib: 64 },
  network_profile: 'http_inspect',
  network_policy_id: '',
  labels: null,
  created_at: new Date(Date.now() - 3600_000).toISOString(),
  updated_at: new Date().toISOString(),
  links: {},
  ...over,
})

describe('VMTable', () => {
  it('renders one row per VM with its name and template', () => {
    render(<VMTable vms={[vm(), vm({ vm_id: 'other', name: 'agent-04' })]} />)
    expect(screen.getByText('agent-03')).toBeInTheDocument()
    expect(screen.getByText('agent-04')).toBeInTheDocument()
    expect(screen.getAllByText('python-dev')).toHaveLength(2)
  })

  it('shows observed state, and flags a desired state that disagrees', () => {
    render(<VMTable vms={[vm({ desired_state: 'running', observed_state: 'stopping' })]} />)
    expect(screen.getByText('stopping')).toBeInTheDocument()
    expect(screen.getByText(/want running/i)).toBeInTheDocument()
  })

  it('does not flag desired state when it agrees with observed', () => {
    render(<VMTable vms={[vm()]} />)
    expect(screen.queryByText(/want running/i)).not.toBeInTheDocument()
  })

  it('says telemetry health and live usage are not measured, rather than showing zero', () => {
    render(<VMTable vms={[vm()]} />)
    const notMeasured = screen.getAllByText('not measured')
    expect(notMeasured.length).toBeGreaterThanOrEqual(2)
    expect(screen.queryByText('0%')).not.toBeInTheDocument()
  })

  it('renders allocation from the resources block', () => {
    render(<VMTable vms={[vm()]} />)
    expect(screen.getByText('2 vCPU')).toBeInTheDocument()
    expect(screen.getByText('2048 MiB')).toBeInTheDocument()
  })

  it('renders a revision past MAX_SAFE_INTEGER exactly', () => {
    const huge = '9007199254740993'
    render(<VMTable vms={[vm({ revision: huge })]} />)
    expect(screen.getByText(`rev ${huge}`)).toBeInTheDocument()
  })

  it('neutralizes bidi control characters in a name instead of letting them reorder the row', () => {
    render(<VMTable vms={[vm({ name: 'safe‮gnp.exe' })]} />)
    const cell = screen.getByTestId('vm-name')
    expect(cell.textContent).not.toContain('‮')
    expect(cell.textContent).toContain('U+202E')
  })

  it('shows the failure cause when a VM carries one', () => {
    render(<VMTable vms={[vm({ observed_state: 'failed', failure: { stage: 'stage', reason: 'artifact hash mismatch' } })]} />)
    expect(screen.getByText(/artifact hash mismatch/)).toBeInTheDocument()
  })

  it('says so plainly when the fleet is empty', () => {
    render(<VMTable vms={[]} />)
    expect(screen.getByText(/no vms/i)).toBeInTheDocument()
  })
})
