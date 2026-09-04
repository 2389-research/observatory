// ABOUTME: Tests for fleet state in the URL: a reload restores the same view, and
// ABOUTME: nothing the page did not put there is disturbed, invented or leaked.
import { describe, it, expect } from 'vitest'
import { readState, writeState, type FleetState } from './url'

describe('readState', () => {
  it('reads an empty search as no filter and no selection', () => {
    expect(readState('')).toEqual({ stateFilter: [] })
    expect(readState('?')).toEqual({ stateFilter: [] })
  })

  it('reads repeated state params as the filter list, in order', () => {
    expect(readState('?state=running&state=paused')).toEqual({ stateFilter: ['running', 'paused'] })
  })

  it('reads the selected VM', () => {
    expect(readState('?vm=7f3a9c21')).toEqual({ stateFilter: [], selectedVM: '7f3a9c21' })
  })

  it('ignores keys it does not own', () => {
    expect(readState('?utm_source=chat&state=stopped')).toEqual({ stateFilter: ['stopped'] })
  })
})

describe('writeState', () => {
  it('round-trips every state it can hold', () => {
    const states: FleetState[] = [
      { stateFilter: [] },
      { stateFilter: ['running'] },
      { stateFilter: ['running', 'stopped'] },
      { stateFilter: [], selectedVM: 'abc' },
      { stateFilter: ['paused'], selectedVM: 'abc' },
    ]
    for (const s of states) {
      expect(readState(writeState(s))).toEqual(s)
    }
  })

  it('writes an empty search for an empty state, so a cleared filter leaves no debris', () => {
    expect(writeState({ stateFilter: [] })).toBe('')
  })

  it('leaves a key it does not own untouched', () => {
    const next = writeState({ stateFilter: ['running'] }, '?utm_source=chat')
    expect(new URLSearchParams(next).get('utm_source')).toBe('chat')
    expect(readState(next).stateFilter).toEqual(['running'])
  })

  it('drops a filter that was removed instead of accumulating', () => {
    const first = writeState({ stateFilter: ['running', 'paused'] })
    const second = writeState({ stateFilter: ['paused'] }, first)
    expect(readState(second).stateFilter).toEqual(['paused'])
    expect(second.match(/state=/g)).toHaveLength(1)
  })

  it('clears the selection rather than leaving a stale vm key', () => {
    const first = writeState({ stateFilter: [], selectedVM: 'abc' })
    expect(readState(writeState({ stateFilter: [] }, first))).toEqual({ stateFilter: [] })
  })
})
