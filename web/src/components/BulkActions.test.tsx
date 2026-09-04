// ABOUTME: Tests for multi-select lifecycle actions: one request per VM, per-row outcomes.
// ABOUTME: A 409 is never silently retried, and force=true never leaves without a confirm.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, within, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { BulkActions, useFleetControls, runBounded } from './BulkActions'
import { VMTable } from './VMTable'
import { setCSRFProvider } from '../api'
import { testVM } from '../test/fixtures'
import type { VM } from '../types'

beforeEach(() => setCSRFProvider(() => ({ method: 'none' })))
afterEach(() => vi.unstubAllGlobals())

/** What App does: one controls object, shared by the bar and the table. */
function Fleet({ vms, onSettled = () => {} }: { vms: VM[]; onSettled?: () => void }) {
  const controls = useFleetControls(onSettled)
  return (
    <>
      <BulkActions vms={vms} controls={controls} />
      <VMTable vms={vms} controls={controls} />
    </>
  )
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

const actionOK = (vm: VM, state: string, opID: string) =>
  json({ vm: { ...vm, observed_state: state }, operation: { operation_id: opID } })

const revisionConflict = (current: string) =>
  json(
    {
      code: 'revision_mismatch',
      message: `revision is now ${current}; re-read the VM and retry`,
      cause: 'optimistic_concurrency_failure',
      retryable: true,
      details: { current_revision: current },
    },
    409,
  )

/** Three running VMs with three different revisions. */
const three = [
  testVM({ vm_id: 'vm-1', name: 'alpha', revision: '3' }),
  testVM({ vm_id: 'vm-2', name: 'beta', revision: '7' }),
  testVM({ vm_id: 'vm-3', name: 'gamma', revision: '11' }),
]

const row = (vmId: string) => within(screen.getByTestId(`vm-row-${vmId}`))
const selectAll = () => screen.getByRole('checkbox', { name: /select all/i })
const barButton = (name: RegExp) => within(screen.getByTestId('bulk-actions')).getByRole('button', { name })

/** Bodies of every POST the run issued, keyed by VM id. */
function postedRevisions(spy: ReturnType<typeof vi.fn>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [url, init] of spy.mock.calls as [string, RequestInit][]) {
    if (init?.method !== 'POST') continue
    const id = /\/vms\/([^/]+)\/actions/.exec(url)?.[1]
    if (!id) continue
    out[id] = (JSON.parse(init.body as string) as { expected_revision: string }).expected_revision
  }
  return out
}

describe('fan-out', () => {
  it('issues one request per selected VM, each carrying that row own revision', async () => {
    const spy = vi.fn((_url: string, _init?: RequestInit) =>
      Promise.resolve(actionOK(three[0]!, 'stopped', 'op-1')),
    )
    vi.stubGlobal('fetch', spy)
    render(<Fleet vms={three} />)

    await userEvent.click(selectAll())
    await userEvent.click(barButton(/^stop/i))

    await waitFor(() => expect(Object.keys(postedRevisions(spy))).toHaveLength(3))
    expect(postedRevisions(spy)).toEqual({ 'vm-1': '3', 'vm-2': '7', 'vm-3': '11' })
    const [url, init] = spy.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/api/v1/vms/vm-1/actions')
    expect(JSON.parse(init.body as string)).toEqual({ action: 'stop', expected_revision: '3' })
  })

  it('never holds more than four requests in flight at once', async () => {
    const six = Array.from({ length: 6 }, (_, i) =>
      testVM({ vm_id: `vm-${i}`, name: `vm-${i}`, revision: String(i) }),
    )
    let inFlight = 0
    let peak = 0
    const spy = vi.fn(
      () =>
        new Promise<Response>((resolve) => {
          inFlight++
          peak = Math.max(peak, inFlight)
          setTimeout(() => {
            inFlight--
            resolve(actionOK(six[0]!, 'stopped', 'op-1'))
          }, 5)
        }),
    )
    vi.stubGlobal('fetch', spy)
    render(<Fleet vms={six} />)

    await userEvent.click(selectAll())
    await userEvent.click(barButton(/^stop/i))

    await waitFor(() => expect(spy).toHaveBeenCalledTimes(6))
    expect(peak).toBeLessThanOrEqual(4)
  })

  it('calls back once the whole fan-out has settled, so the fleet re-reads', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(actionOK(three[0]!, 'stopped', 'op-1'))))
    const settled = vi.fn()
    render(<Fleet vms={three} onSettled={settled} />)

    await userEvent.click(selectAll())
    await userEvent.click(barButton(/^stop/i))

    await waitFor(() => expect(settled).toHaveBeenCalledTimes(1))
  })
})

describe('per-VM outcomes', () => {
  it('one conflict among three leaves the other two successful and blames only the conflicting row', async () => {
    const spy = vi.fn((url: string) => {
      if (url.includes('vm-2/actions')) return Promise.resolve(revisionConflict('9'))
      if (url.endsWith('/vms/vm-2')) return Promise.resolve(json({ ...three[1]!, revision: '9' }))
      return Promise.resolve(actionOK(three[0]!, 'stopped', 'op-777'))
    })
    vi.stubGlobal('fetch', spy)
    render(<Fleet vms={three} />)

    await userEvent.click(selectAll())
    await userEvent.click(barButton(/^stop/i))

    await waitFor(() => expect(row('vm-2').getByTestId('vm-result')).toHaveTextContent(/revision is now 9/i))
    expect(row('vm-2').getByTestId('vm-result')).toHaveTextContent('optimistic_concurrency_failure')

    for (const id of ['vm-1', 'vm-3']) {
      const result = row(id).getByTestId('vm-result')
      expect(result).toHaveTextContent('op-777')
      expect(result).not.toHaveTextContent(/revision is now/i)
    }
  })

  it('re-reads the conflicting VM and retries only when asked, with the fresh revision', async () => {
    let conflicted = false
    const spy = vi.fn((url: string) => {
      if (url.includes('vm-2/actions')) {
        if (!conflicted) {
          conflicted = true
          return Promise.resolve(revisionConflict('9'))
        }
        return Promise.resolve(actionOK(three[1]!, 'stopped', 'op-late'))
      }
      if (url.endsWith('/vms/vm-2')) return Promise.resolve(json({ ...three[1]!, revision: '9' }))
      return Promise.resolve(actionOK(three[0]!, 'stopped', 'op-777'))
    })
    vi.stubGlobal('fetch', spy)
    render(<Fleet vms={three} />)

    await userEvent.click(selectAll())
    await userEvent.click(barButton(/^stop/i))

    // The re-read happens on its own; the resubmit waits for the operator.
    await waitFor(() => expect(spy.mock.calls.some(([u]) => (u as string).endsWith('/vms/vm-2'))).toBe(true))
    const retry = await row('vm-2').findByRole('button', { name: /retry/i })
    expect(postedRevisions(spy)['vm-2']).toBe('7')

    await userEvent.click(retry)
    await waitFor(() => expect(postedRevisions(spy)['vm-2']).toBe('9'))
    await waitFor(() => expect(row('vm-2').getByTestId('vm-result')).toHaveTextContent('op-late'))
  })

  it('offers no retry for a conflict the daemon calls final', async () => {
    const spy = vi.fn((url: string) => {
      if (url.includes('/actions'))
        return Promise.resolve(
          json(
            {
              code: 'invalid_transition',
              message: 'cannot transition from "stopped" to "stopping"',
              cause: 'lifecycle_state_machine',
              retryable: false,
            },
            409,
          ),
        )
      return Promise.resolve(json({}))
    })
    vi.stubGlobal('fetch', spy)
    render(<Fleet vms={[three[0]!]} />)

    await userEvent.click(selectAll())
    await userEvent.click(barButton(/^stop/i))

    await waitFor(() => expect(row('vm-1').getByTestId('vm-result')).toHaveTextContent(/cannot transition/i))
    expect(row('vm-1').queryByRole('button', { name: /retry/i })).toBeNull()
    // A final conflict is not re-read: nothing to retry with.
    expect(spy.mock.calls.some(([u]) => (u as string).endsWith('/vms/vm-1'))).toBe(false)
  })
})

describe('delete', () => {
  it('sends nothing until the confirm names the VMs and is accepted', async () => {
    const spy = vi.fn(() => Promise.resolve(json({ vm: three[0]! })))
    vi.stubGlobal('fetch', spy)
    render(<Fleet vms={three} />)

    await userEvent.click(selectAll())
    await userEvent.click(barButton(/^delete/i))

    const confirm = screen.getByTestId('delete-confirm')
    expect(confirm).toHaveTextContent('alpha')
    expect(confirm).toHaveTextContent('beta')
    expect(confirm).toHaveTextContent('gamma')
    expect(spy).not.toHaveBeenCalled()

    await userEvent.click(within(confirm).getByRole('button', { name: /cancel/i }))
    expect(spy).not.toHaveBeenCalled()
    expect(screen.queryByTestId('delete-confirm')).toBeNull()
  })

  it('force-stops a live VM only after the confirm, and never forces a stopped one', async () => {
    const live = testVM({ vm_id: 'vm-live', name: 'live', revision: '3', observed_state: 'running' })
    const cold = testVM({ vm_id: 'vm-cold', name: 'cold', revision: '4', observed_state: 'stopped' })
    const spy = vi.fn((_url: string, _init?: RequestInit) => Promise.resolve(json({ vm: cold })))
    vi.stubGlobal('fetch', spy)
    render(<Fleet vms={[live, cold]} />)

    await userEvent.click(selectAll())
    await userEvent.click(barButton(/^delete/i))
    const confirm = screen.getByTestId('delete-confirm')
    // The confirm says what force means and which VMs it applies to.
    expect(confirm).toHaveTextContent(/force/i)
    expect(within(confirm).getByTestId('force-targets')).toHaveTextContent('live')
    expect(within(confirm).getByTestId('force-targets')).not.toHaveTextContent('cold')

    await userEvent.click(within(confirm).getByRole('button', { name: /delete 2 VMs/i }))

    await waitFor(() => expect(spy).toHaveBeenCalledTimes(2))
    const urls = (spy.mock.calls as [string, RequestInit][]).map(([u]) => u)
    expect(urls).toContain('/api/v1/vms/vm-live?expected_revision=3&force=true')
    expect(urls).toContain('/api/v1/vms/vm-cold?expected_revision=4')
    for (const [, init] of spy.mock.calls as [string, RequestInit][]) {
      expect(init.method).toBe('DELETE')
    }
  })
})

describe('legality', () => {
  it('disables an action the VM state forbids and names the reason in the button', () => {
    render(<Fleet vms={[testVM({ vm_id: 'vm-1', observed_state: 'running' })]} />)
    const start = row('vm-1').getByRole('button', { name: /^start/i })
    expect(start).toBeDisabled()
    expect(start).toHaveAccessibleName(/running/i)
  })

  it('leaves the action a VM state permits enabled and unqualified', () => {
    render(<Fleet vms={[testVM({ vm_id: 'vm-1', observed_state: 'stopped' })]} />)
    expect(row('vm-1').getByRole('button', { name: /^start/i })).toBeEnabled()
    expect(row('vm-1').getByRole('button', { name: /^stop/i })).toBeDisabled()
  })

  it('never attempts an illegal action: the bar acts on the rows that permit it and says so', async () => {
    const spy = vi.fn((_url: string, _init?: RequestInit) =>
      Promise.resolve(actionOK(three[0]!, 'stopped', 'op-1')),
    )
    vi.stubGlobal('fetch', spy)
    const mixed = [
      testVM({ vm_id: 'vm-run', name: 'runner', revision: '3', observed_state: 'running' }),
      testVM({ vm_id: 'vm-off', name: 'sleeper', revision: '4', observed_state: 'stopped' }),
    ]
    render(<Fleet vms={mixed} />)

    await userEvent.click(selectAll())
    await userEvent.click(barButton(/^stop/i))

    await waitFor(() => expect(spy).toHaveBeenCalledTimes(1))
    expect((spy.mock.calls[0] as [string])[0]).toBe('/api/v1/vms/vm-run/actions')
    expect(row('vm-off').getByTestId('vm-result')).toHaveTextContent(/stopped/i)
  })

  it('disables a bar action no selected VM permits', async () => {
    render(<Fleet vms={[testVM({ vm_id: 'vm-1', observed_state: 'stopped' })]} />)
    await userEvent.click(selectAll())
    expect(barButton(/^pause/i)).toBeDisabled()
    expect(barButton(/^start/i)).toBeEnabled()
  })
})

describe('selection', () => {
  it('counts the selection and toggles from the keyboard alone', async () => {
    render(<Fleet vms={three} />)
    expect(screen.getByTestId('selection-count')).toHaveTextContent('0 of 3')

    selectAll().focus()
    await userEvent.keyboard(' ')
    expect(screen.getByTestId('selection-count')).toHaveTextContent('3 of 3')

    await userEvent.keyboard(' ')
    expect(screen.getByTestId('selection-count')).toHaveTextContent('0 of 3')
  })

  it('drops a VM from the selection once it leaves the fleet', async () => {
    const { rerender } = render(<Fleet vms={three} />)
    await userEvent.click(selectAll())
    expect(screen.getByTestId('selection-count')).toHaveTextContent('3 of 3')

    rerender(<Fleet vms={[three[0]!, three[2]!]} />)
    expect(screen.getByTestId('selection-count')).toHaveTextContent('2 of 2')
  })

  it('disables every bar action when nothing is selected', () => {
    render(<Fleet vms={three} />)
    for (const name of [/^start/i, /^stop/i, /^pause/i, /^resume/i, /^delete/i]) {
      expect(barButton(name)).toBeDisabled()
    }
  })
})

describe('runBounded', () => {
  it('runs every item exactly once and never exceeds the limit', async () => {
    const items = [1, 2, 3, 4, 5, 6, 7]
    const seen: number[] = []
    let live = 0
    let peak = 0
    await runBounded(items, 3, async (n) => {
      live++
      peak = Math.max(peak, live)
      await Promise.resolve()
      seen.push(n)
      live--
    })
    expect(seen.sort((a, b) => a - b)).toEqual(items)
    expect(peak).toBeLessThanOrEqual(3)
  })

  it('keeps going when one item rejects, so one failure cannot strand the rest', async () => {
    const done: number[] = []
    await runBounded([1, 2, 3], 2, async (n) => {
      if (n === 2) throw new Error('boom')
      done.push(n)
    })
    expect(done.sort()).toEqual([1, 3])
  })
})
