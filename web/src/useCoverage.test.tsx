// ABOUTME: Verifies per-visible-VM coverage requests share a bounded concurrency budget.
// ABOUTME: Unmount cancels queued work so old fleet pages cannot fill the polling queue.
import { act, renderHook, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { useCoverage } from './useCoverage'
afterEach(() => vi.unstubAllGlobals())
it('runs at most four coverage requests and cancels waiting rows on unmount', async () => {
  const releases: Array<() => void> = []
  const fetch = vi.fn(
    (url: string) =>
      new Promise<Response>((resolve) => {
        releases.push(() =>
          resolve({
            ok: true,
            json: async () => ({
              vm_id: url.split('/')[4],
              boot_id: 'boot',
              channel: { state: 'healthy' },
              collectors: [],
              gaps: [],
            }),
          } as Response),
        )
      }),
  )
  vi.stubGlobal('fetch', fetch)
  const hooks = Array.from({ length: 12 }, (_, i) => renderHook(() => useCoverage(`vm-${i}`)))
  await waitFor(() => expect(fetch).toHaveBeenCalledTimes(4))
  hooks.forEach((hook) => hook.unmount())
  await act(async () => {
    releases.forEach((release) => release())
  })
  expect(fetch).toHaveBeenCalledTimes(4)
})
