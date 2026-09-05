// ABOUTME: Tests for the VM detail workspace's lifecycle action row (SPEC §13.2).
// ABOUTME: Delete still travels through the confirm gesture; nothing reaches the wire without one.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, within, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { VMActions } from './VMActions'
import { useFleetControls } from './BulkActions'
import { setCSRFProvider } from '../api'
import { testVM } from '../test/fixtures'
import type { VM } from '../types'

beforeEach(() => setCSRFProvider(() => ({ method: 'none' })))
afterEach(() => vi.unstubAllGlobals())

/** What VMDetail does: one controls object for the single VM on screen. */
function Detail({ vm, onSettled = () => {} }: { vm: VM; onSettled?: () => void }) {
  const controls = useFleetControls(onSettled)
  return <VMActions vm={vm} controls={controls} />
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

const actionOK = (vm: VM, state: string, opID: string) =>
  json({ vm: { ...vm, observed_state: state }, operation: { operation_id: opID } })

const row = () => within(screen.getByTestId('vm-actions'))

/** The body of the first POST, parsed. */
function postedBody(spy: ReturnType<typeof vi.fn>): unknown {
  const call = (spy.mock.calls as [string, RequestInit][]).find(([, init]) => init?.method === 'POST')
  return call === undefined ? undefined : JSON.parse(String(call[1].body))
}

describe('the detail action row', () => {
  it('offers every action the daemon accepts, and says why the state forbids one', () => {
    render(<Detail vm={testVM({ observed_state: 'running' })} />)
    for (const name of [/^pause/i, /^stop/i, /^force stop/i, /^delete/i]) {
      expect(row().getByRole('button', { name })).toBeEnabled()
    }
    const start = row().getByRole('button', { name: /^start/i })
    expect(start).toBeDisabled()
    expect(start).toHaveAccessibleName(/running/i)
    expect(row().getByRole('button', { name: /^resume/i })).toBeDisabled()
  })

  it('sends the action with this VM own revision and reports the operation', async () => {
    const stopped = testVM({ observed_state: 'stopped', revision: '11' })
    const spy = vi.fn((_url: string, _init?: RequestInit) => Promise.resolve(actionOK(stopped, 'starting', 'op-77')))
    vi.stubGlobal('fetch', spy)
    render(<Detail vm={stopped} />)

    await userEvent.click(row().getByRole('button', { name: /^start/i }))

    await waitFor(() => expect(spy).toHaveBeenCalledTimes(1))
    expect((spy.mock.calls[0] as [string])[0]).toBe('/api/v1/vms/vm-1/actions')
    expect(postedBody(spy)).toEqual({ action: 'start', expected_revision: '11' })
    expect(await screen.findByTestId('vm-result')).toHaveTextContent('op-77')
  })

  // §13.2's action row lists Force stop beside Stop. They are two actions on the
  // wire (internal/runtime/manager.go's validActions), and the one that skips the
  // guest's shutdown must say so by name rather than ride in as a flag on stop.
  it('force stop is its own action on the wire', async () => {
    const spy = vi.fn((_url: string, _init?: RequestInit) => Promise.resolve(actionOK(testVM(), 'stopped', 'op-9')))
    vi.stubGlobal('fetch', spy)
    render(<Detail vm={testVM({ observed_state: 'running', revision: '3' })} />)

    await userEvent.click(row().getByRole('button', { name: /^force stop/i }))

    await waitFor(() => expect(spy).toHaveBeenCalledTimes(1))
    expect(postedBody(spy)).toEqual({ action: 'force_stop', expected_revision: '3' })
  })

  it('re-reads the VM once the action has settled', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(actionOK(testVM(), 'paused', 'op-1'))))
    const settled = vi.fn()
    render(<Detail vm={testVM({ observed_state: 'running' })} onSettled={settled} />)

    await userEvent.click(row().getByRole('button', { name: /^pause/i }))
    await waitFor(() => expect(settled).toHaveBeenCalledTimes(1))
  })
})

describe('delete from the detail page', () => {
  it('asks before it deletes, and names the force the live VM will take', async () => {
    const spy = vi.fn((_url: string, _init?: RequestInit) => Promise.resolve(json({ vm: testVM() })))
    vi.stubGlobal('fetch', spy)
    render(<Detail vm={testVM({ name: 'agent-03', observed_state: 'running', revision: '3' })} />)

    await userEvent.click(row().getByRole('button', { name: /^delete/i }))
    const confirm = screen.getByTestId('delete-confirm')
    expect(confirm).toHaveTextContent('agent-03')
    expect(within(confirm).getByTestId('force-targets')).toHaveTextContent('agent-03')
    expect(spy).not.toHaveBeenCalled()

    await userEvent.click(within(confirm).getByRole('button', { name: /delete 1 VM/i }))
    await waitFor(() => expect(spy).toHaveBeenCalledTimes(1))
    const [url, init] = spy.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/api/v1/vms/vm-1?expected_revision=3&force=true')
    expect(init.method).toBe('DELETE')
  })

  it('cancels without sending anything and closes the prompt', async () => {
    const spy = vi.fn(() => Promise.resolve(json({ vm: testVM() })))
    vi.stubGlobal('fetch', spy)
    render(<Detail vm={testVM()} />)

    await userEvent.click(row().getByRole('button', { name: /^delete/i }))
    await userEvent.click(within(screen.getByTestId('delete-confirm')).getByRole('button', { name: /cancel/i }))

    expect(screen.queryByTestId('delete-confirm')).toBeNull()
    expect(spy).not.toHaveBeenCalled()
  })

  // The property BulkActions' comment claims and this extraction has to keep:
  // the confirm gesture is the only caller of DELETE. A page that renders the
  // Delete button without its prompt would have to route the request some other
  // way, and there is no other way — the button asks, and nothing else sends.
  it('a delete nobody confirmed never reaches the wire', async () => {
    const spy = vi.fn(() => Promise.resolve(json({ vm: testVM() })))
    vi.stubGlobal('fetch', spy)
    render(<Detail vm={testVM({ observed_state: 'running' })} />)

    await userEvent.click(row().getByRole('button', { name: /^delete/i }))
    expect(screen.getByTestId('delete-confirm')).toBeInTheDocument()
    expect(spy).not.toHaveBeenCalled()
  })
})
