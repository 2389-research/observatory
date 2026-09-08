// ABOUTME: Tests that current boot coverage scopes the event workspace and failed coverage stays explicit.
// ABOUTME: Covers late reply isolation using unit-level fetch boundaries.
import { render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import userEvent from '@testing-library/user-event'
import { ObservationWorkspace } from './ObservationWorkspace'
afterEach(() => vi.unstubAllGlobals())
it('waits for current boot coverage before querying events', async () => {
  const urls: string[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      urls.push(url)
      return {
        ok: true,
        json: async () =>
          url.includes('/coverage')
            ? {
                vm_id: 'vm-a',
                boot_id: 'boot-a',
                channel: { state: 'healthy', observed_dropped: '0' },
                collectors: [
                  {
                    id: 'filesystem',
                    state: 'unavailable',
                    enabled: true,
                    event_classes: [],
                    scope: [],
                    exclusions: [],
                    limitations: [],
                    observed_dropped: null,
                    unknown_loss_intervals: null,
                    source: 'guest',
                    provenance: 'guest_reported',
                  },
                ],
                gaps: [],
              }
            : { events: [], next_after: '', latest_event_id: '' },
      }
    }),
  )
  render(<ObservationWorkspace vmID="vm-a" />)
  await waitFor(() => expect(urls.some((url) => url.includes('/events?'))).toBe(true))
  expect(urls[0]).toContain('/vms/vm-a/coverage')
  expect(urls[1]).toContain('boot_id=boot-a')
  expect(screen.getByText(/capture is unavailable/i)).toBeInTheDocument()
})
it('never starts an unscoped event feed when coverage is unavailable', async () => {
  const fetch = vi.fn(async () => {
    throw new Error('connection lost')
  })
  vi.stubGlobal('fetch', fetch)
  render(<ObservationWorkspace vmID="vm-a" />)
  expect(await screen.findByRole('alert')).toHaveTextContent('Coverage unavailable')
  expect(fetch).toHaveBeenCalledTimes(1)
})

it.each([
  ['net.flow', 'flow', 'healthy'],
  ['dns', 'dns', 'disabled'],
  ['policy', 'denial', 'degraded'],
])('uses %s collector coverage for its empty activity state', async (family, id, state) => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => ({
      ok: true,
      json: async () =>
        url.includes('/coverage')
          ? {
              vm_id: 'vm-a',
              boot_id: 'boot-a',
              channel: { state: 'healthy', observed_dropped: '0' },
              collectors: [
                {
                  id,
                  state,
                  enabled: true,
                  event_classes: [],
                  scope: [],
                  exclusions: [],
                  limitations: [],
                  observed_dropped: '0',
                  unknown_loss_intervals: 0,
                  source: 'host',
                  provenance: 'host_observed',
                },
              ],
              gaps: [],
            }
          : { events: [], next_after: '', latest_event_id: '' },
    })),
  )
  render(<ObservationWorkspace vmID="vm-a" />)
  await userEvent.selectOptions(screen.getByLabelText('Event family'), family)
  if (state === 'healthy') expect(await screen.findByText(/No activity observed for this boot/)).toBeInTheDocument()
  else expect(await screen.findByText(new RegExp('Capture is ' + state))).toBeInTheDocument()
})
