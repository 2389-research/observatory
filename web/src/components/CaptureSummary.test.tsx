// ABOUTME: Checks fleet rows show channel health without implying file or network capture exists.
// ABOUTME: Uses the same coverage endpoint contract as the detail workspace.
import { act, render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { CaptureSummary } from './CaptureSummary'
afterEach(() => {
  vi.unstubAllGlobals()
  vi.useRealTimers()
})
it('shows absent file and network sensors beside healthy transport', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => ({
      ok: true,
      json: async () => ({
        vm_id: 'vm-a',
        boot_id: 'boot-a',
        channel: { state: 'healthy', observed_dropped: '0' },
        collectors: ['filesystem', 'flow'].map((id) => ({
          id,
          state: 'unavailable',
          enabled: true,
          event_classes: [],
          scope: [],
          exclusions: [],
          limitations: [],
          observed_dropped: null,
          unknown_loss_intervals: null,
          source: id === 'filesystem' ? 'guest' : 'host',
          provenance: id === 'filesystem' ? 'guest_reported' : 'host_observed',
        })),
        gaps: [],
      }),
    })),
  )
  render(<CaptureSummary vmID="vm-a" />)
  expect(await screen.findByText('Transport healthy')).toBeInTheDocument()
  expect(screen.getByText('Files unavailable')).toBeInTheDocument()
  expect(screen.getByText('Flows unavailable')).toBeInTheDocument()
})

it('checks collector status until a report arrives instead of declaring collectors unavailable', () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(
      (_url: string, init?: RequestInit) =>
        new Promise((_resolve, reject) =>
          init?.signal?.addEventListener('abort', () => reject(new Error('cancelled')), { once: true }),
        ),
    ),
  )
  render(<CaptureSummary vmID="vm-a" />)
  expect(screen.getByText('Files checking')).toBeInTheDocument()
  expect(screen.getByText('Flows checking')).toBeInTheDocument()
  expect(screen.queryByText(/Files unavailable/)).toBeNull()
})
it('reports unknown capture when the coverage request fails before any report', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => {
      throw new Error('offline')
    }),
  )
  render(<CaptureSummary vmID="vm-a" />)
  expect(await screen.findByText('Files unknown')).toBeInTheDocument()
  expect(screen.getByText('Flows unknown')).toBeInTheDocument()
})
it('qualifies retained states as last reported when coverage refresh fails', async () => {
  vi.useFakeTimers()
  let calls = 0
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => {
      if (++calls > 1) throw new Error('offline')
      return {
        ok: true,
        json: async () => ({
          vm_id: 'vm-a',
          boot_id: 'boot-a',
          channel: { state: 'healthy', observed_dropped: '0' },
          collectors: [
            {
              id: 'filesystem',
              state: 'healthy',
              enabled: true,
              event_classes: [],
              scope: [],
              exclusions: [],
              limitations: [],
              observed_dropped: '0',
              unknown_loss_intervals: 0,
              source: 'guest',
              provenance: 'guest_reported',
            },
          ],
          gaps: [],
        }),
      }
    }),
  )
  render(<CaptureSummary vmID="vm-a" />)
  await act(async () => {
    await vi.advanceTimersByTimeAsync(10000)
  })
  expect(screen.getByText('Files last reported healthy')).toBeInTheDocument()
  expect(screen.getByText(/current capture unknown/i)).toBeInTheDocument()
})
