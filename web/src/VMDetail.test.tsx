// ABOUTME: Tests for the VM detail workspace (SPEC §13.2): identity, sessions, the terminal.
// ABOUTME: The stubbed boundaries are fetch and WebSocket; everything else is the real component.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { VMDetail } from './VMDetail'
import { FakeWebSocket } from './test/fakeSocket'
import { testTerminalSession, testVM } from './test/fixtures'

function jsonResponse(body: unknown, status = 200): Response {
  // `text` as well as `json`: the mutation client reads the body as text so a
  // 204 with no body does not go through JSON.parse('').
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => (body === undefined ? '' : JSON.stringify(body)),
  } as Response
}

const openSession = testTerminalSession()

/**
 * A fetch that answers the two reads the workspace makes. `overrides` replaces
 * an answer by URL suffix; `onPost` and `onDelete` observe the mutations.
 */
function routeFetch(o: {
  vm?: Response
  terminals?: Response
  post?: Response
  del?: Response
} = {}) {
  return vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    if (method === 'POST') return o.post ?? jsonResponse(testTerminalSession({ session_id: 'sess-new' }), 201)
    if (method === 'DELETE') return o.del ?? jsonResponse(undefined, 204)
    if (url.endsWith('/coverage'))
      return jsonResponse({
        vm_id: 'vm-1',
        boot_id: 'boot-1',
        channel: { state: 'healthy', observed_dropped: '0' },
        collectors: [],
        gaps: [],
      })
    if (url.includes('/events?')) return jsonResponse({ events: [], next_after: '', latest_event_id: '' })
    if (url.endsWith('/terminals')) return o.terminals ?? jsonResponse({ terminals: [], next_after: '', limit: 20 })
    if (url.includes('/vms/')) return o.vm ?? jsonResponse(testVM({ name: 'agent-03' }))
    throw new Error(`unexpected fetch: ${url}`)
  })
}

function bodyOf(f: ReturnType<typeof routeFetch>, method: string): unknown {
  const call = f.mock.calls.find((c) => (c[1]?.method ?? 'GET') === method)
  return call?.[1]?.body === undefined ? undefined : JSON.parse(String(call[1].body))
}

describe('VMDetail', () => {
  beforeEach(() => {
    FakeWebSocket.reset()
    vi.stubGlobal('WebSocket', FakeWebSocket)
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('names the VM, its lifecycle and what it was built from', async () => {
    vi.stubGlobal('fetch', routeFetch())
    render(<VMDetail vmID="vm-1" onBack={() => {}} />)

    const head = await screen.findByTestId('vm-identity')
    expect(head).toHaveTextContent('agent-03')
    expect(head).toHaveTextContent('running')
    expect(head).toHaveTextContent('standard')
    expect(head).toHaveTextContent('sha256:abc')
    expect(head).toHaveTextContent('1 vCPU')
    expect(head).toHaveTextContent('512 MiB')
  })

  // SPEC §138: never encode observation quality only in lifecycle state. A VM
  // that is running while nothing has been heard from its agent has to read as
  // both, or the header quietly claims the VM is fine.
  it('shows telemetry health beside lifecycle state', async () => {
    vi.stubGlobal(
      'fetch',
      routeFetch({ vm: jsonResponse(testVM({ observed_state: 'running', telemetry_health: 'unavailable' })) }),
    )
    render(<VMDetail vmID="vm-1" onBack={() => {}} />)

    const head = await screen.findByTestId('vm-identity')
    expect(head).toHaveTextContent('running')
    expect(within(head).getByTestId('telemetry-health')).toHaveTextContent('unavailable')
    expect(within(head).getByTestId('telemetry-health')).toHaveTextContent('telemetry')
    expect(within(head).getByTestId('telemetry-health')).not.toHaveTextContent('transport')
  })

  it('keeps the terminal session attached while changing activity filters', async () => {
    vi.stubGlobal(
      'fetch',
      routeFetch({ terminals: jsonResponse({ terminals: [openSession], next_after: '', limit: 20 }) }),
    )
    render(<VMDetail vmID="vm-1" onBack={() => {}} />)
    await waitFor(() => expect(FakeWebSocket.last?.url).toContain('/terminals/sess-1/stream'))
    const socket = FakeWebSocket.last
    await userEvent.selectOptions(await screen.findByLabelText('Event family'), '')
    expect(FakeWebSocket.last).toBe(socket)
    expect(socket.readyState).not.toBe(FakeWebSocket.CLOSED)
    expect(screen.getByTestId('channel-coverage')).toHaveTextContent('Transport healthy')
  })

  it('says no guest address is published rather than inventing one', async () => {
    vi.stubGlobal('fetch', routeFetch())
    render(<VMDetail vmID="vm-1" onBack={() => {}} />)
    // SPEC §13.2 shows addresses; this API reports a network profile and a
    // policy, and nothing that resolves to a guest address. A plausible-looking
    // 10.x here would be a fabricated observation.
    expect(await screen.findByTestId('vm-network')).toHaveTextContent(/no guest address is published/i)
  })

  it('attaches to the session the VM already has', async () => {
    vi.stubGlobal('fetch', routeFetch({ terminals: jsonResponse({ terminals: [openSession], next_after: '', limit: 20 }) }))
    render(<VMDetail vmID="vm-1" onBack={() => {}} />)

    await waitFor(() => expect(FakeWebSocket.last?.url).toContain('/terminals/sess-1/stream'))
    expect(await screen.findByTestId('terminal-state')).toBeInTheDocument()
  })

  it('opens a session on request and attaches to the one the host made', async () => {
    const f = routeFetch()
    vi.stubGlobal('fetch', f)
    render(<VMDetail vmID="vm-1" onBack={() => {}} />)

    await userEvent.click(await screen.findByRole('button', { name: /open a terminal/i }))
    await waitFor(() => expect(FakeWebSocket.last?.url).toContain('/terminals/sess-new/stream'))
    expect(bodyOf(f, 'POST')).toEqual({ rows: 24, cols: 80 })
  })

  it('shows the host refusal when the session cap is reached', async () => {
    vi.stubGlobal(
      'fetch',
      routeFetch({
        post: jsonResponse(
          {
            code: 'conflict',
            message: 'VM vm-1 already has 2 terminal sessions',
            cause: 'terminal_session_cap',
            retryable: false,
            remediation: [{ action: 'close an open session', rationale: 'the cap is per VM' }],
          },
          409,
        ),
      }),
    )
    render(<VMDetail vmID="vm-1" onBack={() => {}} />)

    await userEvent.click(await screen.findByRole('button', { name: /open a terminal/i }))
    expect(await screen.findByText(/already has 2 terminal sessions/)).toBeInTheDocument()
    expect(screen.getByText('terminal_session_cap')).toBeInTheDocument()
    expect(FakeWebSocket.instances).toHaveLength(0)
  })

  it('will not offer a terminal on a VM that is not running, and says why', async () => {
    vi.stubGlobal('fetch', routeFetch({ vm: jsonResponse(testVM({ observed_state: 'stopped' })) }))
    render(<VMDetail vmID="vm-1" onBack={() => {}} />)

    expect(await screen.findByTestId('terminal-unavailable')).toHaveTextContent(/stopped/)
    expect(screen.queryByRole('button', { name: /open a terminal/i })).toBeNull()
  })

  it('closes a session through the host and lets go of the stream', async () => {
    const f = routeFetch({ terminals: jsonResponse({ terminals: [openSession], next_after: '', limit: 20 }) })
    vi.stubGlobal('fetch', f)
    render(<VMDetail vmID="vm-1" onBack={() => {}} />)

    await waitFor(() => expect(FakeWebSocket.last).toBeTruthy())
    const socket = FakeWebSocket.last
    await userEvent.click(await screen.findByRole('button', { name: /close this session/i }))

    await waitFor(() => expect(socket.readyState).toBe(FakeWebSocket.CLOSED))
    expect(f.mock.calls.some((c) => (c[1]?.method ?? 'GET') === 'DELETE' && String(c[0]).endsWith('/terminals/sess-1'))).toBe(true)
  })

  it('lists every session the VM has and attaches to the one chosen', async () => {
    const second = testTerminalSession({ session_id: 'sess-2', pid: 907 })
    vi.stubGlobal(
      'fetch',
      routeFetch({ terminals: jsonResponse({ terminals: [openSession, second], next_after: '', limit: 20 }) }),
    )
    render(<VMDetail vmID="vm-1" onBack={() => {}} />)

    const tabs = await screen.findByTestId('terminal-tabs')
    expect(within(tabs).getAllByRole('tab')).toHaveLength(2)

    await userEvent.click(within(tabs).getByRole('tab', { name: /sess-2/ }))
    await waitFor(() => expect(FakeWebSocket.last.url).toContain('/terminals/sess-2/stream'))
  })

  it('carries the lifecycle actions the workspace is supposed to offer', async () => {
    vi.stubGlobal('fetch', routeFetch())
    render(<VMDetail vmID="vm-1" onBack={() => {}} />)

    const actions = within(await screen.findByTestId('vm-actions'))
    expect(actions.getByRole('button', { name: /^stop/i })).toBeEnabled()
    expect(actions.getByRole('button', { name: /^force stop/i })).toBeEnabled()
    expect(actions.getByRole('button', { name: /^start/i })).toBeDisabled()
  })

  it('stops the VM from the workspace and re-reads what the host now says', async () => {
    let state = 'running'
    const f = vi.fn(async (url: string, init?: RequestInit) => {
      if ((init?.method ?? 'GET') === 'POST' && url.includes('/actions')) {
        state = 'stopped'
        return jsonResponse({ vm: testVM({ observed_state: 'stopped' }), operation: { operation_id: 'op-55' } })
      }
      if (url.endsWith('/terminals')) return jsonResponse({ terminals: [], next_after: '', limit: 20 })
      if (url.includes('/vms/')) return jsonResponse(testVM({ name: 'agent-03', observed_state: state }))
      throw new Error(`unexpected fetch: ${url}`)
    })
    vi.stubGlobal('fetch', f)
    render(<VMDetail vmID="vm-1" onBack={() => {}} />)

    await userEvent.click(within(await screen.findByTestId('vm-actions')).getByRole('button', { name: /^stop/i }))

    expect(await screen.findByTestId('vm-result')).toHaveTextContent('op-55')
    // The workspace does not wait for its 5s poll to agree with the action it
    // just watched succeed.
    await waitFor(() => expect(screen.getByTestId('vm-identity')).toHaveTextContent('stopped'))
  })

  it('asks before it deletes the VM being looked at', async () => {
    const f = routeFetch()
    vi.stubGlobal('fetch', f)
    render(<VMDetail vmID="vm-1" onBack={() => {}} />)

    await userEvent.click(within(await screen.findByTestId('vm-actions')).getByRole('button', { name: /^delete/i }))
    expect(screen.getByTestId('delete-confirm')).toHaveTextContent('agent-03')
    expect(f.mock.calls.some((c) => (c[1]?.method ?? 'GET') === 'DELETE')).toBe(false)
  })

  it('goes back to the fleet', async () => {
    const onBack = vi.fn()
    vi.stubGlobal('fetch', routeFetch())
    render(<VMDetail vmID="vm-1" onBack={onBack} />)

    await userEvent.click(await screen.findByRole('button', { name: /back to the fleet/i }))
    expect(onBack).toHaveBeenCalled()
  })

  it('keeps a hostile VM name as text', async () => {
    vi.stubGlobal('fetch', routeFetch({ vm: jsonResponse(testVM({ name: '<img src=x onerror=boom>' })) }))
    const { container } = render(<VMDetail vmID="vm-1" onBack={() => {}} />)

    await screen.findByTestId('vm-identity')
    expect(container.querySelector('img')).toBeNull()
  })

  it('reports a VM it cannot read instead of an empty page', async () => {
    vi.stubGlobal(
      'fetch',
      routeFetch({
        vm: jsonResponse(
          { code: 'not_found', message: 'VM vm-1 does not exist', cause: 'vm_unknown', retryable: false },
          404,
        ),
      }),
    )
    render(<VMDetail vmID="vm-1" onBack={() => {}} />)
    expect(await screen.findByText('VM vm-1 does not exist')).toBeInTheDocument()
  })
})
