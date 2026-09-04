// ABOUTME: The batch rollup must never read better than its weakest member (§13.1).
// ABOUTME: A member with no verdict yet keeps the batch in progress; it never rounds to success.
import { describe, it, expect } from 'vitest'
import { batchRollup, memberOutcome, everyMemberTerminal } from './batch'
import type { BatchMember } from './types'
import { testVM } from './test/fixtures'

const op = (state: string) => ({
  operation_id: 'op-000001',
  kind: 'vm.create',
  phase: state === 'running' ? 'running' : 'complete',
  state,
  attempt: 1,
  created_at: '2026-09-04T10:00:00Z',
  updated_at: '2026-09-04T10:00:01Z',
})

const member = (position: number, over: Partial<BatchMember> = {}): BatchMember => ({
  position,
  name: `worker-${position}`,
  ...over,
})

describe('memberOutcome', () => {
  it('reads the operation verdict, not the VM state', () => {
    const running = member(0, { vm: testVM({ observed_state: 'running' }), operation: op('succeeded') })
    expect(memberOutcome(running)).toBe('succeeded')
  })

  it('calls a refused member refused, never failed and never pending', () => {
    const refused = member(0, { refusal: { cause: 'capacity_exhausted', message: 'no room' } })
    expect(memberOutcome(refused)).toBe('refused')
  })

  it('is in_progress while the operation is still running', () => {
    expect(memberOutcome(member(0, { operation: op('running') }))).toBe('in_progress')
  })

  it('says unknown when the member carries neither an operation nor a refusal', () => {
    // Better than guessing: the daemon told us nothing about this member.
    expect(memberOutcome(member(0))).toBe('unknown')
  })
})

describe('batchRollup', () => {
  it('is partial when one member is up and another failed', () => {
    const members = [
      member(0, { vm: testVM(), operation: op('succeeded') }),
      member(1, { operation: op('failed') }),
    ]
    expect(batchRollup(members)).toBe('partial')
  })

  it('never says succeeded because the first member started', () => {
    const members = [
      member(0, { vm: testVM(), operation: op('succeeded') }),
      member(1, { operation: op('running') }),
    ]
    expect(batchRollup(members)).toBe('in_progress')
  })

  it('is succeeded only when every member reached terminal success', () => {
    const members = [member(0, { operation: op('succeeded') }), member(1, { operation: op('succeeded') })]
    expect(batchRollup(members)).toBe('succeeded')
  })

  it('is failed when every member is terminal and none succeeded', () => {
    const members = [
      member(0, { operation: op('failed') }),
      member(1, { refusal: { cause: 'capacity_exhausted', message: 'no room' } }),
    ]
    expect(batchRollup(members)).toBe('failed')
  })

  it('stays in progress while any member has no verdict', () => {
    const members = [member(0, { operation: op('succeeded') }), member(1)]
    expect(batchRollup(members)).toBe('in_progress')
  })

  it('is in progress for an empty member list rather than vacuously succeeded', () => {
    expect(batchRollup([])).toBe('in_progress')
  })
})

describe('everyMemberTerminal', () => {
  it('is false while one member is still running, so polling continues', () => {
    expect(everyMemberTerminal([member(0, { operation: op('succeeded') }), member(1, { operation: op('running') })])).toBe(
      false,
    )
  })

  it('is true once each member has succeeded, failed or been refused', () => {
    const members = [
      member(0, { operation: op('succeeded') }),
      member(1, { operation: op('failed') }),
      member(2, { refusal: { cause: 'template_unknown', message: 'no such template' } }),
    ]
    expect(everyMemberTerminal(members)).toBe(true)
  })

  it('is false for a member with no verdict, so polling never stops on silence', () => {
    expect(everyMemberTerminal([member(0)])).toBe(false)
  })
})
