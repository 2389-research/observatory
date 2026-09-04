// ABOUTME: One row per batch member with its own verdict — and no member name
// ABOUTME: reaches the page still able to reorder the row around it (13.3).
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { BatchProgress } from './BatchProgress'
import type { BatchReply } from '../types'

const RLO = String.fromCodePoint(0x202e)

const reply = (members: BatchReply['members']): BatchReply => ({
  batch: {
    batch_id: 'batch-000001',
    owner: 'local_operator',
    reservation_mode: 'atomic_reservation',
    on_failure: 'keep_successful',
    created_at: '2026-09-04T12:00:00Z',
    updated_at: '2026-09-04T12:00:00Z',
    links: {},
  },
  members,
})

describe('BatchProgress', () => {
  it('names each member and its own outcome', () => {
    render(
      <BatchProgress
        polling={false}
        reply={reply([
          { position: 0, name: 'worker-1', operation: { operation_id: 'op-000001', kind: 'create_vm', phase: 'done', state: 'succeeded', attempt: 1, created_at: '', updated_at: '' } },
          { position: 1, name: 'worker-2', refusal: { cause: 'admission_refused', message: 'no room' } },
        ])}
      />,
    )
    expect(screen.getByTestId('member-row-0')).toHaveTextContent('worker-1')
    const refused = screen.getByTestId('member-row-1')
    expect(refused).toHaveTextContent('worker-2')
    expect(refused).toHaveTextContent('admission_refused')
    expect(refused).toHaveTextContent('no room')
  })

  it('neutralizes a hostile member name and the refusal that quotes it', () => {
    render(
      <BatchProgress
        polling={false}
        reply={reply([
          { position: 0, name: `invoice${RLO}gnp.exe`, refusal: { cause: 'name_invalid', message: `${RLO} bad` } },
        ])}
      />,
    )
    const row = screen.getByTestId('member-row-0')
    expect(row.textContent).toContain('<U+202E>')
    expect(row.textContent).not.toContain(RLO)
  })
})
