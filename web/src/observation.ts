// ABOUTME: Keeps a bounded window of durable events with exact VM and boot identity.
// ABOUTME: Formats notification evidence without inventing paths or content changes.
import type { EventEnvelope } from './types'
import { neutralize } from './text'

export const HISTORY_LIMIT = 500
export const HISTORY_BYTES = 2 * 1024 * 1024
export const PAGE_LIMIT = 100
export const ROW_LIMIT = 100
export const cursor = (value: unknown): value is string =>
  typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value) && value.length <= 20

export function appendEvents(
  previous: EventEnvelope[],
  page: EventEnvelope[],
  vmID: string,
  bootID: string,
  limit = HISTORY_LIMIT,
  bytes = HISTORY_BYTES,
) {
  const seen = new Set(previous.map((e) => e.event_id))
  const additions = page.filter((e) => {
    if (
      !cursor(e.event_id) ||
      (e.vm_id ?? field(e.data.vm_id)) !== vmID ||
      (e.boot_id ?? field(e.data.boot_id)) !== bootID ||
      seen.has(e.event_id)
    )
      return false
    seen.add(e.event_id)
    return true
  })
  const events = [...previous, ...additions].sort((a, b) => (BigInt(a.event_id) < BigInt(b.event_id) ? -1 : 1))
  const sizes = events.map((e) => JSON.stringify(e).length * 2)
  let size = sizes.reduce((a, b) => a + b, 0)
  let evicted = 0
  while (events.length - evicted > limit || size > bytes) {
    size -= sizes[evicted] ?? 0
    evicted++
  }
  return { events: events.slice(evicted), added: additions.length, evicted }
}

export function field(value: unknown): string {
  return typeof value === 'string' || typeof value === 'number' ? String(value) : ''
}
export function eventPath(event: EventEnvelope): string {
  const data = event.data
  const path = field(data.path_display) || field(data.path)
  if (path) return neutralize(path)
  const names: string[] = []
  if (Array.isArray(data.identities)) {
    for (const identity of data.identities.slice(0, 8)) {
      if (!identity || typeof identity !== 'object') continue
      const name = field(identity.name_display)
      if (!name) continue
      const label =
        identity.role === 'old_parent'
          ? 'Old basename'
          : identity.role === 'new_parent'
            ? 'New basename'
            : 'Observed basename'
      names.push(`${label} ${neutralize(name.slice(0, 256))}${name.length > 256 ? '…' : ''}`)
      if (names.length === 4) break
    }
  }
  return names.length ? `${names.join(' · ')} · full path unresolved` : 'Path unresolved'
}
export function operationLabel(kind: string): string {
  const labels: Record<string, string> = {
    'fs.create': 'Created',
    'fs.modify': 'Modification notification',
    'fs.close_write': 'Closed after write-open',
    'fs.rename': 'Renamed / moved',
    'fs.delete': 'Deleted / unlinked',
    'fs.metadata': 'Metadata changed',
    'fs.loss': 'Capture loss',
    'fs.coverage': 'Coverage changed',
  }
  return labels[kind] ?? neutralize(kind)
}
export interface EventFilters {
  path: string
  process: string
  operation: string
}
export function matchesEvent(event: EventEnvelope, filters: EventFilters): boolean {
  return (
    (!filters.path || eventPath(event).toLowerCase().includes(filters.path.toLowerCase())) &&
    (!filters.process || field(event.data.pid) === filters.process) &&
    (!filters.operation || event.kind === filters.operation)
  )
}
