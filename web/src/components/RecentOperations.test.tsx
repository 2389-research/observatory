// ABOUTME: Tests for the recent-operations panel: it renders the daemon's own
// ABOUTME: operation events, so another browser's launches show up here too.
import { describe, it, expect } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { RecentOperations } from './RecentOperations'
import { testOperationEvent } from '../test/fixtures'

describe('RecentOperations', () => {
  it('shows the operation id, its kind and its outcome', () => {
    render(
      <RecentOperations
        events={[
          testOperationEvent({ event_id: '9', operation_id: 'op-000009', kind: 'vm.create', state: 'succeeded' }),
        ]}
      />,
    )
    const row = screen.getByTestId('operation-op-000009')
    expect(row).toHaveTextContent('op-000009')
    expect(row).toHaveTextContent('vm.create')
    expect(row).toHaveTextContent('succeeded')
  })

  it('lists the newest operation first', () => {
    render(
      <RecentOperations
        events={[
          testOperationEvent({ event_id: '1', operation_id: 'op-000001' }),
          testOperationEvent({ event_id: '2', operation_id: 'op-000002' }),
        ]}
      />,
    )
    const rows = screen.getAllByTestId(/^operation-/)
    expect(rows[0]).toHaveTextContent('op-000002')
  })

  it('shows one row per operation, at its latest phase — not one row per event', () => {
    render(
      <RecentOperations
        events={[
          testOperationEvent({ event_id: '1', operation_id: 'op-000001', phase: 'admitted', state: 'running' }),
          testOperationEvent({ event_id: '2', operation_id: 'op-000001', phase: 'running', state: 'succeeded' }),
        ]}
      />,
    )
    const rows = screen.getAllByTestId(/^operation-/)
    expect(rows).toHaveLength(1)
    expect(rows[0]).toHaveTextContent('succeeded')
  })

  it('renders a failure with the cause the daemon gave, never a bare "failed"', () => {
    render(
      <RecentOperations
        events={[
          testOperationEvent({
            operation_id: 'op-000004',
            state: 'failed',
            error: { cause: 'jailer_spawn_failed', message: 'firecracker exited before the api socket appeared' },
          }),
        ]}
      />,
    )
    const row = screen.getByTestId('operation-op-000004')
    expect(row).toHaveTextContent('jailer_spawn_failed')
    expect(row).toHaveTextContent('firecracker exited before the api socket appeared')
  })

  it('says the stream is quiet rather than looking broken', () => {
    render(<RecentOperations events={[]} />)
    expect(screen.getByText(/no operations/i)).toBeInTheDocument()
  })

  it('names the VM an operation acted on, when the event carries one', () => {
    render(
      <RecentOperations
        events={[testOperationEvent({ operation_id: 'op-000007', vm_id: '7f3a9c21-0000-4000-8000-000000000001' })]}
      />,
    )
    expect(within(screen.getByTestId('operation-op-000007')).getByText(/7f3a9c21/)).toBeInTheDocument()
  })
})
