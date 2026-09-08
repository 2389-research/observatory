// ABOUTME: Polls coverage only for mounted VM views with a shared four-request limit.
// ABOUTME: Scope changes cancel waiting work and retain errors without claiming old reports are current.
import { useEffect, useState } from 'react'
import { getJSON } from './api'
import type { CaptureCoverage } from './types'

let active = 0
const waiting: Array<() => void> = []
function drain() {
  while (active < 4 && waiting.length) waiting.shift()?.()
}
function requestCoverage(vmID: string, signal: AbortSignal): Promise<CaptureCoverage> {
  return new Promise((resolve, reject) => {
    const cancel = () => {
      const index = waiting.indexOf(start)
      if (index >= 0) waiting.splice(index, 1)
      reject(new Error('Coverage request cancelled'))
    }
    const start = () => {
      signal.removeEventListener('abort', cancel)
      if (signal.aborted) {
        cancel()
        return
      }
      active++
      getJSON<CaptureCoverage>(`/vms/${encodeURIComponent(vmID)}/coverage`, signal)
        .then(resolve, reject)
        .finally(() => {
          active--
          drain()
        })
    }
    if (signal.aborted) {
      reject(new Error('Coverage request cancelled'))
      return
    }
    if (waiting.length >= 128) {
      reject(new Error('Coverage request queue is full; retrying'))
      return
    }
    signal.addEventListener('abort', cancel, { once: true })
    waiting.push(start)
    drain()
  })
}

function validCoverage(value: CaptureCoverage, vmID: string): boolean {
  const strings = (list: unknown): boolean =>
    Array.isArray(list) && list.length <= 256 && list.every((item) => typeof item === 'string')
  return (
    value?.vm_id === vmID &&
    typeof value.channel?.state === 'string' &&
    (value.boot_id === undefined || typeof value.boot_id === 'string') &&
    strings(value.gaps) &&
    Array.isArray(value.collectors) &&
    value.collectors.length <= 32 &&
    value.collectors.every(
      (item) =>
        item &&
        typeof item.id === 'string' &&
        typeof item.state === 'string' &&
        typeof item.source === 'string' &&
        typeof item.provenance === 'string' &&
        strings(item.event_classes) &&
        strings(item.scope) &&
        strings(item.exclusions) &&
        strings(item.limitations),
    )
  )
}
export function useCoverage(vmID: string, interval = 10000) {
  const [state, setState] = useState<{ vmID: string; coverage: CaptureCoverage | null; failure: string }>({
    vmID,
    coverage: null,
    failure: '',
  })
  useEffect(() => {
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | undefined
    let request: AbortController | undefined
    const poll = async () => {
      request = new AbortController()
      const timeout = setTimeout(() => request?.abort(), 10000)
      try {
        const value = await requestCoverage(vmID, request.signal)
        if (cancelled) return
        if (!validCoverage(value, vmID)) throw new Error('Invalid coverage response')
        setState({ vmID, coverage: value, failure: '' })
      } catch (error) {
        if (!cancelled)
          setState((previous) => ({
            vmID,
            coverage: previous.vmID === vmID ? previous.coverage : null,
            failure: error instanceof Error ? error.message : 'Coverage query failed',
          }))
      } finally {
        clearTimeout(timeout)
      }
      if (!cancelled) timer = setTimeout(() => void poll(), interval)
    }
    void poll()
    return () => {
      cancelled = true
      request?.abort()
      if (timer) clearTimeout(timer)
    }
  }, [vmID, interval])
  return state.vmID === vmID ? state : { vmID, coverage: null, failure: '' }
}
