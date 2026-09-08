// ABOUTME: Tests for the fleet VM table: honest gaps, exact counters, inert strings.
// ABOUTME: SPEC §13.1 names columns this build cannot measure; they must say so.
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { VMTable } from './VMTable'
import type { FleetControls } from './BulkActions'
import type { VM } from '../types'

/** The table always has controls; these tests are about what it renders, not what it does. */
const inert: FleetControls = {
  selected: new Set(),
  toggle: () => {},
  toggleAll: () => {},
  results: {},
  run: async () => {},
  retry: async () => {},
  pendingDelete: [],
  askDelete: () => {},
  cancelDelete: () => {},
  confirmDelete: async () => {},
  busy: false,
}

const vm = (over: Partial<VM> = {}): VM => ({
  vm_id: '7f3a9c21-0000-4000-8000-000000000001',
  name: 'agent-03',
  owner: 'local_operator',
  template_id: 'python-dev',
  template_digest: 'sha256:abcdef0123456789',
  desired_state: 'running',
  observed_state: 'running',
  telemetry_health: 'healthy',
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
    render(<VMTable vms={[vm(), vm({ vm_id: 'other', name: 'agent-04' })]} controls={inert} />)
    expect(screen.getByText('agent-03')).toBeInTheDocument()
    expect(screen.getByText('agent-04')).toBeInTheDocument()
    expect(screen.getAllByText('python-dev')).toHaveLength(2)
  })

  it('shows observed state, and flags a desired state that disagrees', () => {
    render(<VMTable vms={[vm({ desired_state: 'running', observed_state: 'stopping' })]} controls={inert} />)
    expect(screen.getByText('stopping')).toBeInTheDocument()
    expect(screen.getByText(/want running/i)).toBeInTheDocument()
  })

  it('does not flag desired state when it agrees with observed', () => {
    render(<VMTable vms={[vm()]} controls={inert} />)
    expect(screen.queryByText(/want running/i)).not.toBeInTheDocument()
  })

  it('says live usage is not measured, rather than showing zero', () => {
    render(<VMTable vms={[vm()]} controls={inert} />)
    expect(screen.getAllByText('not measured').length).toBeGreaterThanOrEqual(1)
    expect(screen.queryByText('0%')).not.toBeInTheDocument()
  })

  // Capture is read independently; the legacy telemetry summary cannot answer
  // whether a specific filesystem or network collector is available.
  it('checks capture independently of the legacy telemetry summary', () => {
    render(
      <VMTable
        vms={[vm({ observed_state: 'running', telemetry_health: 'unavailable' })]}
        controls={inert}
      />,
    )
    expect(screen.getByTestId('vm-telemetry')).toHaveTextContent('Files checking')
    expect(screen.getByTestId('vm-telemetry')).not.toHaveTextContent('Files unavailable')
    expect(screen.getByText('running')).toBeInTheDocument()
  })

  it('renders allocation from the resources block', () => {
    render(<VMTable vms={[vm()]} controls={inert} />)
    expect(screen.getByText('2 vCPU')).toBeInTheDocument()
    expect(screen.getByText('2048 MiB')).toBeInTheDocument()
  })

  it('renders a revision past MAX_SAFE_INTEGER exactly', () => {
    const huge = '9007199254740993'
    render(<VMTable vms={[vm({ revision: huge })]} controls={inert} />)
    expect(screen.getByText(`rev ${huge}`)).toBeInTheDocument()
  })

  it('neutralizes bidi control characters in a name instead of letting them reorder the row', () => {
    render(<VMTable vms={[vm({ name: 'safe‮gnp.exe' })]} controls={inert} />)
    const cell = screen.getByTestId('vm-name')
    expect(cell.textContent).not.toContain('‮')
    expect(cell.textContent).toContain('U+202E')
  })

  it('shows the failure cause when a VM carries one', () => {
    render(<VMTable vms={[vm({ observed_state: 'failed', failure: { stage: 'stage', reason: 'artifact hash mismatch' } })]} controls={inert} />)
    expect(screen.getByText(/artifact hash mismatch/)).toBeInTheDocument()
  })

  it('says so plainly when the fleet is empty', () => {
    render(<VMTable vms={[]} controls={inert} />)
    expect(screen.getByText(/no vms/i)).toBeInTheDocument()
  })
})
