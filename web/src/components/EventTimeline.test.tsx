// ABOUTME: Tests safe filesystem rendering, local filters and pause-scroll controls.
// ABOUTME: Fetch stubs exercise component behavior only; real guest delivery has a separate gate.
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import { EventTimeline } from './EventTimeline'
const event = {
  event_id: '1',
  vm_id: 'vm-a',
  boot_id: 'boot-a',
  kind: 'fs.close_write',
  provenance: 'guest_reported',
  host_received_at: '2026-09-08T00:00:00Z',
  data: { path: '/workspace/<img src=x>\u202e\u001b', path_status: 'inferred', pid: 42 },
}
afterEach(() => vi.unstubAllGlobals())
it('renders hostile paths as inert evidence and distinguishes close-write from content comparison', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => ({ ok: true, json: async () => ({ events: [event], next_after: '1', latest_event_id: '1' }) })),
  )
  const { container } = render(<EventTimeline vmID="vm-a" bootID="boot-a" family="fs" captureState="healthy" />)
  expect(await screen.findByText('Closed after write-open')).toBeInTheDocument()
  expect(screen.getByText(/<U\+202E><U\+001B>/)).toBeInTheDocument()
  expect(container.querySelector('img')).toBeNull()
  await userEvent.click(screen.getByRole('button', { name: /closed after write-open/i }))
  expect(screen.getByLabelText('Normalized event JSON')).toHaveTextContent('guest_reported')
  expect(screen.getByLabelText('Normalized event JSON')).toHaveTextContent('inferred')
  await userEvent.type(screen.getByLabelText('Path contains'), 'no-match')
  expect(screen.getByText(/no retained events match/i)).toBeInTheDocument()
})
it('pauses the displayed window while continuing cursor collection and counting unread events', async () => {
  let calls = 0
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => ({
      ok: true,
      json: async () => {
        calls++
        return {
          events: [{ ...event, event_id: String(calls) }],
          next_after: String(calls),
          latest_event_id: String(calls),
        }
      },
    })),
  )
  render(<EventTimeline vmID="vm-a" bootID="boot-a" family="fs" captureState="healthy" interval={10} />)
  await screen.findByText('Closed after write-open')
  await userEvent.click(screen.getByRole('button', { name: 'Pause scrolling' }))
  await waitFor(() => expect(screen.getByText(/unread.*collection continues/i)).toBeInTheDocument())
  expect(screen.getByRole('button', { name: 'Resume scrolling' })).toBeInTheDocument()
})

it('uses host-normalized path quality even when guest data claims exact capture', async () => {
  const hostile = {
    ...event,
    quality: { path_resolution: 'unknown' },
    data: { ...event.data, path_status: 'exact_at_capture' },
  }
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => ({ ok: true, json: async () => ({ events: [hostile], next_after: '1', latest_event_id: '1' }) })),
  )
  render(<EventTimeline vmID="vm-a" bootID="boot-a" family="fs" captureState="healthy" />)
  const row = await screen.findByRole('button', { name: /closed after write-open/i })
  expect(row).toHaveTextContent('path unknown')
  expect(row).not.toHaveTextContent('path exact_at_capture')
})

it('shows and filters an observed hostile basename without inventing its unresolved full path', async () => {
  const unresolved = { ...event, data: { identities: [{ role: 'parent', name_display: '<img src=x>\u202e' }] } }
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => ({
      ok: true,
      json: async () => ({ events: [unresolved], next_after: '1', latest_event_id: '1' }),
    })),
  )
  const { container } = render(<EventTimeline vmID="vm-a" bootID="boot-a" family="fs" captureState="healthy" />)
  expect(await screen.findByText('Observed basename <img src=x><U+202E> · full path unresolved')).toBeInTheDocument()
  expect(container.querySelector('img')).toBeNull()
  await userEvent.type(screen.getByLabelText('Path contains'), 'img src')
  expect(screen.getByRole('button', { name: /closed after write-open/i })).toBeInTheDocument()
  expect(screen.queryByText(/no retained events match/i)).toBeNull()
})
