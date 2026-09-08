// ABOUTME: Unit-tests cursor retries and scope changes against controlled fetch responses.
// ABOUTME: These boundary stubs do not stand in for the real guest/browser acceptance gate.
import { act, renderHook, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { useEventFeed } from './useObservation'
const response = (body: unknown) => ({ ok: true, json: async () => body }) as Response
const event = (id: string, vm = 'vm-a', boot = 'boot-a') => ({
  event_id: id,
  vm_id: vm,
  boot_id: boot,
  kind: 'fs.modify',
  provenance: 'guest_reported',
  host_received_at: 'now',
  data: {},
})
afterEach(() => vi.unstubAllGlobals())
it('starts at tail then resumes after the exact cursor when a request fails', async () => {
  const requests: string[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      requests.push(url)
      if (requests.length === 1)
        return response({
          events: [event('9007199254740993')],
          next_after: '9007199254740993',
          latest_event_id: '9007199254740993',
        })
      throw new Error('offline')
    }),
  )
  const { result, unmount } = renderHook(() => useEventFeed('vm-a', 'boot-a', 'fs', 10))
  await waitFor(() => expect(result.current.events).toHaveLength(1))
  await waitFor(() => expect(result.current.failure).toBeTruthy())
  expect(requests[0]).toContain('tail=true')
  expect(requests[1]).toContain('after=9007199254740993')
  expect(result.current.events).toHaveLength(1)
  unmount()
})
it('ignores a late response after VM and boot scope changes', async () => {
  let finish: ((value: Response) => void) | undefined
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string) =>
      url.includes('vm-a')
        ? new Promise<Response>((resolve) => {
            finish = resolve
          })
        : Promise.resolve(response({ events: [event('2', 'vm-b', 'boot-b')], next_after: '2', latest_event_id: '2' })),
    ),
  )
  const { result, rerender, unmount } = renderHook(({ vm, boot }) => useEventFeed(vm, boot, 'fs'), {
    initialProps: { vm: 'vm-a', boot: 'boot-a' },
  })
  rerender({ vm: 'vm-b', boot: 'boot-b' })
  await waitFor(() => expect(result.current.events[0]?.vm_id).toBe('vm-b'))
  await act(async () => finish?.(response({ events: [event('1')], next_after: '1', latest_event_id: '2' })))
  expect(result.current.events.map((e) => e.vm_id)).toEqual(['vm-b'])
  unmount()
})

it('aborts a stalled event request so reconnect can retry from its cursor', async () => {
  vi.useFakeTimers()
  try {
    let signal: AbortSignal | undefined
    vi.stubGlobal(
      'fetch',
      vi.fn(
        (_url: string, init?: RequestInit) =>
          new Promise<Response>((_resolve, reject) => {
            signal = init?.signal as AbortSignal | undefined
            signal?.addEventListener('abort', () => reject(new Error('request timed out')), { once: true })
          }),
      ),
    )
    const { result, unmount } = renderHook(() => useEventFeed('vm-a', 'boot-a', 'fs'))
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10000)
    })
    expect(signal?.aborted).toBe(true)
    expect(result.current.failure).toBe('request timed out')
    unmount()
  } finally {
    vi.useRealTimers()
  }
})
