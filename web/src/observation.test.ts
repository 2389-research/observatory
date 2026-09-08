// ABOUTME: Tests bounded event history, exact boot isolation and notification wording.
// ABOUTME: Decimal cursors and hostile payloads stay data through filtering and display.
import { expect, it } from 'vitest'
import { appendEvents, eventPath, matchesEvent, operationLabel } from './observation'
import type { EventEnvelope } from './types'
const event = (id: string, patch: Partial<EventEnvelope> = {}): EventEnvelope => ({
  event_id: id,
  vm_id: 'vm-a',
  boot_id: 'boot-a',
  kind: 'fs.close_write',
  provenance: 'guest_reported',
  host_received_at: '2026-09-08T00:00:00Z',
  data: { path: '/workspace/file', pid: 42 },
  ...patch,
})
it('deduplicates large decimal cursors and bounds retained history', () => {
  const a = event('9007199254740993'),
    b = event('9007199254740994')
  const result = appendEvents([a], [a, b], 'vm-a', 'boot-a', 1)
  expect(result.events.map((e) => e.event_id)).toEqual([b.event_id])
  expect(result.evicted).toBe(1)
  expect(result.added).toBe(1)
})
it('rejects other VM and boot records even when a response mixes them', () => {
  expect(
    appendEvents(
      [],
      [event('1'), event('2', { vm_id: 'vm-b' }), event('3', { boot_id: 'boot-b' }), event('4', { boot_id: null })],
      'vm-a',
      'boot-a',
    ).events,
  ).toHaveLength(1)
})
it('bounds payload bytes as well as record count', () => {
  const result = appendEvents(
    [],
    [event('1', { data: { path: 'x'.repeat(10000) } }), event('2')],
    'vm-a',
    'boot-a',
    500,
    1000,
  )
  expect(result.events.map((e) => e.event_id)).toEqual(['2'])
  expect(result.evicted).toBe(1)
})
it('shows unknown paths and does not call close-write a content change', () => {
  expect(eventPath(event('1', { data: {} }))).toBe('Path unresolved')
  expect(operationLabel('fs.close_write')).toBe('Closed after write-open')
  expect(matchesEvent(event('1'), { path: 'workspace', process: '42', operation: 'fs.close_write' })).toBe(true)
  expect(matchesEvent(event('1'), { path: 'absent', process: '', operation: '' })).toBe(false)
})

it('accepts host-wide records only when their payload names this exact VM and boot', () => {
  const host = event('1', {
    vm_id: null,
    boot_id: null,
    kind: 'vm.state_changed',
    data: { vm_id: 'vm-a', boot_id: 'boot-a' },
  })
  expect(appendEvents([], [host], 'vm-a', 'boot-a').events).toHaveLength(1)
  expect(
    appendEvents([], [{ ...host, data: { vm_id: 'vm-a', boot_id: 'boot-b' } }], 'vm-a', 'boot-a').events,
  ).toHaveLength(0)
})

it('shows observed hostile basenames when the full path is unresolved and filters those names', () => {
  const unresolved = event('1', { data: { identities: [{ role: 'parent', name_display: '<img src=x>\u202e\u001b' }] } })
  expect(eventPath(unresolved)).toBe('Observed basename <img src=x><U+202E><U+001B> · full path unresolved')
  expect(matchesEvent(unresolved, { path: 'img src', process: '', operation: '' })).toBe(true)
})

it('keeps rename basenames distinct and bounds each displayed name', () => {
  const rename = event('1', {
    data: {
      identities: [
        { role: 'old_parent', name_display: 'old-name' },
        { role: 'new_parent', name_display: 'x'.repeat(4096) },
      ],
    },
  })
  expect(eventPath(rename)).toContain('Old basename old-name')
  expect(eventPath(rename)).toContain('New basename ' + 'x'.repeat(256) + '…')
  expect(eventPath(rename).length).toBeLessThan(400)
})
