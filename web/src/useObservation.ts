// ABOUTME: Polls the canonical durable event cursor independently of terminal I/O.
// ABOUTME: Scope guards discard stale replies; retries preserve the last accepted cursor.
import { useEffect, useState } from 'react'
import { getJSON } from './api'
import type { EventEnvelope, EventPage } from './types'
import { appendEvents, cursor, PAGE_LIMIT } from './observation'

interface Feed {
  scope: string
  events: EventEnvelope[]
  received: number
  evicted: number
  failure: string
  loading: boolean
  after: string
}
const emptyFeed = (scope: string): Feed => ({
  scope,
  events: [],
  received: 0,
  evicted: 0,
  failure: '',
  loading: true,
  after: '',
})

export function useEventFeed(vmID: string, bootID: string, family: string, interval = 1000) {
  const scope = JSON.stringify([vmID, bootID, family])
  const [state, setState] = useState<Feed>(() => emptyFeed(scope))
  useEffect(() => {
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | undefined
    let request: AbortController | undefined
    let after = ''
    let first = true
    setState(emptyFeed(scope))
    const poll = async () => {
      let delay = interval
      request = new AbortController()
      const timeout = setTimeout(() => request?.abort(), 10000)
      try {
        const params = new URLSearchParams({ vm_id: vmID, boot_id: bootID, limit: String(PAGE_LIMIT) })
        if (family) params.set('family', family)
        if (first) params.set('tail', 'true')
        else if (after) params.set('after', after)
        const page = await getJSON<EventPage>(`/events?${params}`, request.signal)
        if (cancelled) return
        if (
          !Array.isArray(page.events) ||
          page.events.length > PAGE_LIMIT ||
          !page.events.every(
            (e) => e && cursor(e.event_id) && typeof e.kind === 'string' && e.data && typeof e.data === 'object',
          ) ||
          (page.next_after !== '' && !cursor(page.next_after)) ||
          (page.latest_event_id !== '' && !cursor(page.latest_event_id))
        )
          throw new Error('Malformed event page')
        const next = page.next_after || (first ? page.latest_event_id : after)
        if (after && next && BigInt(next) < BigInt(after)) throw new Error('Event cursor moved backwards')
        if (page.events.length && after && next === after) throw new Error('Event page did not advance its cursor')
        after = next
        first = false
        setState((previous) => {
          const current = previous.scope === scope ? previous : emptyFeed(scope)
          const merged = appendEvents(current.events, page.events, vmID, bootID)
          return {
            ...current,
            events: merged.events,
            received: Math.min(Number.MAX_SAFE_INTEGER, current.received + merged.added),
            evicted: current.evicted + merged.evicted,
            after: next,
            failure: '',
            loading: false,
          }
        })
        // Drain full pages promptly, yielding between requests to keep input responsive.
        if (page.events.length === PAGE_LIMIT) delay = 25
      } catch (error) {
        if (!cancelled)
          setState((previous) => ({
            ...previous,
            loading: false,
            failure: error instanceof Error ? error.message : 'Event query failed',
          }))
      } finally {
        clearTimeout(timeout)
      }
      if (!cancelled) timer = setTimeout(() => void poll(), delay)
    }
    if (bootID) void poll()
    return () => {
      cancelled = true
      request?.abort()
      if (timer) clearTimeout(timer)
    }
  }, [vmID, bootID, family, scope, interval])
  return state.scope === scope ? state : emptyFeed(scope)
}
