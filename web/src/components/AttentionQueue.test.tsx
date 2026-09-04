// ABOUTME: Tests for the attention queue head: exact counts, inert summaries, honest empty state.
// ABOUTME: SPEC §13.1 puts this on the landing page; it is the operator's first read of the host.
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { AttentionQueue } from './AttentionQueue'
import type { Attention } from '../types'

const item = (over: Partial<Attention> = {}): Attention => ({
  attention_id: 'att-1',
  cursor: '000000000001',
  severity: 'warn',
  kind: 'vm.launch_failed',
  vm_id: '7f3a9c21',
  summary: 'launch failed: artifact hash mismatch',
  system_action: 'held at failed; no retry attempted',
  count: '3',
  acked: false,
  evidence_links: ['/api/v1/vms/7f3a9c21/events'],
  ...over,
})

describe('AttentionQueue', () => {
  it('renders one entry per item with its severity and summary', () => {
    render(<AttentionQueue items={[item(), item({ attention_id: 'att-2', summary: 'privd unreachable' })]} />)
    expect(screen.getByText(/artifact hash mismatch/)).toBeInTheDocument()
    expect(screen.getByText('privd unreachable')).toBeInTheDocument()
    expect(screen.getAllByText('warn')).toHaveLength(2)
  })

  it('renders an occurrence count past MAX_SAFE_INTEGER exactly', () => {
    const huge = '9007199254740993'
    render(<AttentionQueue items={[item({ count: huge })]} />)
    expect(screen.getByText(`×${huge}`)).toBeInTheDocument()
  })

  it('states what the system already did about it', () => {
    render(<AttentionQueue items={[item()]} />)
    expect(screen.getByText(/held at failed/)).toBeInTheDocument()
  })

  it('neutralizes control characters in a summary', () => {
    render(<AttentionQueue items={[item({ summary: `boom${String.fromCodePoint(0x1b)}[2J` })]} />)
    const el = screen.getByTestId('attention-summary')
    expect(el.textContent).not.toContain(String.fromCodePoint(0x1b))
    expect(el.textContent).toContain('U+001B')
  })

  it('marks an acknowledged item so it reads differently from a live one', () => {
    render(<AttentionQueue items={[item({ acked: true })]} />)
    expect(screen.getByText(/acked/i)).toBeInTheDocument()
  })

  it('says the queue is empty rather than rendering nothing', () => {
    render(<AttentionQueue items={[]} />)
    expect(screen.getByText(/nothing needs attention/i)).toBeInTheDocument()
  })
})
