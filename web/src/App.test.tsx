// ABOUTME: Tests for the fleet page shell: load, compose, and fail honestly.
// ABOUTME: fetch is stubbed at the transport seam; the served page is proven end-to-end by the Go tests.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { computeAccessibleName } from 'dom-accessibility-api'
import { App } from './App'
import { SessionProvider } from './session'
import { testOperationEvent } from './test/fixtures'

const host = {
  capacity: {
    usable_memory_mib: 60000,
    reserved_memory_mib: 4096,
    free_memory_mib: 55904,
    usable_vcpu: 16,
    reserved_vcpu: 4,
    free_vcpu: 12,
    usable_disk_mib: 23339,
    reserved_disk_mib: 8320,
    free_disk_mib: 15019,
    active_vms: 1,
  },
  runtime: { available: true, reason: '' },
  vms: { running: 1 },
  admission: {
    allow_memory_overcommit: false,
    cpu_overcommit_ratio: 4,
    reserve_per_vm_host_overhead_mib: 768,
    max_parallel_provisions: 2,
    max_batch_size: 8,
  },
  vm_defaults: {
    vcpu_count: 1,
    memory_mib: 512,
    root_disk_mib: 4096,
    workspace_disk_mib: 8192,
    guest_privilege: 'unprivileged',
    network_profile: 'transport',
    network_policy_id: '',
    max_terminal_sessions: 2,
    stop_grace_seconds: 30,
  },
}

const vms = {
  vms: [
    {
      vm_id: '7f3a9c21-0000-4000-8000-000000000001',
      name: 'agent-03',
      owner: 'local_operator',
      template_id: 'python-dev',
      template_digest: 'sha256:abcdef0123456789',
      desired_state: 'running',
      observed_state: 'running',
      revision: '7',
      resources: { vcpu_count: 2, memory_mib: 2048, root_disk_mib: 4096, workspace_disk_mib: 64 },
      network_profile: 'http_inspect',
      network_policy_id: '',
      labels: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      links: {},
    },
  ],
  next_after: '',
}

const attention = { items: [], next_after: '' }

const operations = {
  events: [testOperationEvent({ event_id: '9', operation_id: 'op-000009', state: 'succeeded' })],
  next_after: '9',
  latest_event_id: '9',
}

const templates = {
  templates: [
    {
      template_id: 'python-dev',
      description: 'Python dev box',
      digest: 'sha256:abcdef0123456789',
      kernel_image: '/srv/vmobs/images/vmlinux',
      root_image: '/srv/vmobs/images/rootfs.img',
      guest_privilege_profiles: ['unprivileged'],
      sensors: ['fanotify'],
      protocol_versions: { guestd: '1' },
    },
  ],
}

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as Response
}

function routeFetch(overrides: Record<string, Response> = {}) {
  return vi.fn(async (url: string) => {
    for (const [suffix, res] of Object.entries(overrides)) {
      if (url.endsWith(suffix)) return res
    }
    if (url.endsWith('/host/status')) return jsonResponse(host)
    if (url.includes('/events')) return jsonResponse(operations)
    if (url.includes('/auth/session')) return jsonResponse({ owner: 'local_operator', method: 'none' })
    if (url.includes('/templates')) return jsonResponse(templates)
    if (url.includes('/vms')) return jsonResponse(vms)
    if (url.includes('/attention')) return jsonResponse(attention)
    throw new Error(`unexpected fetch: ${url}`)
  })
}

/** Every URL this render asked the API for. */
function urls(f: ReturnType<typeof routeFetch>): string[] {
  return f.mock.calls.map((c) => c[0])
}

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true })
  window.history.replaceState(null, '', '/')
})

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe('App', () => {
  it('loads the host, the attention head and the VM table', async () => {
    vi.stubGlobal('fetch', routeFetch())
    render(<App />)
    expect(await screen.findByText('agent-03')).toBeInTheDocument()
    expect(screen.getByText('4096 / 60000 MiB')).toBeInTheDocument()
    expect(screen.getByText(/nothing needs attention/i)).toBeInTheDocument()
  })

  it('surfaces a typed API error with its cause instead of an empty page', async () => {
    const err = {
      code: 'internal',
      message: 'store unavailable',
      cause: 'store_unavailable',
      retryable: true,
    }
    vi.stubGlobal('fetch', routeFetch({ '/host/status': jsonResponse(err, 503) }))
    render(<App />)
    expect(await screen.findByRole('alert')).toHaveTextContent('store_unavailable')
  })

  it('asks the operator to sign in when the session is rejected', async () => {
    const err = { code: 'unauthorized', message: 'no session', cause: 'no_session', retryable: false }
    vi.stubGlobal('fetch', routeFetch({ '/host/status': jsonResponse(err, 401) }))
    render(<App />)
    expect(await screen.findByText(/sign in/i)).toBeInTheDocument()
  })

  it('says when it last refreshed so a stale page is obvious', async () => {
    vi.stubGlobal('fetch', routeFetch())
    render(<App />)
    await screen.findByText('agent-03')
    expect(screen.getByTestId('as-of')).toBeInTheDocument()
  })

  it('re-reads the host on its refresh interval', async () => {
    const f = routeFetch()
    vi.stubGlobal('fetch', f)
    render(<App />)
    await screen.findByText('agent-03')
    const first = f.mock.calls.length
    await vi.advanceTimersByTimeAsync(5000)
    await waitFor(() => expect(f.mock.calls.length).toBeGreaterThan(first))
  })
})

describe('App fleet state in the URL (SPEC §13.7)', () => {
  it('shows the host’s recent operations, not a log of what this tab did', async () => {
    vi.stubGlobal('fetch', routeFetch())
    render(<App />)
    await screen.findByText('agent-03')
    expect(screen.getByTestId('operation-op-000009')).toHaveTextContent('succeeded')
  })

  it('reads the newest operations rather than the oldest page of the stream', async () => {
    const f = routeFetch()
    vi.stubGlobal('fetch', f)
    render(<App />)
    await screen.findByText('agent-03')
    const events = urls(f).find((u) => u.includes('/events'))
    expect(events).toContain('tail=true')
  })

  it('sends a lifecycle filter to /vms and writes it to the URL in the same move', async () => {
    const f = routeFetch()
    vi.stubGlobal('fetch', f)
    render(<App />)
    await screen.findByText('agent-03')

    await userEvent.click(screen.getByLabelText('paused'))

    await waitFor(() => expect(urls(f).some((u) => u.includes('state=paused'))).toBe(true))
    expect(window.location.search).toBe('?state=paused')
  })

  it('restores the filter from the URL, so a reload lands on the same view', async () => {
    window.history.replaceState(null, '', '/?state=running&state=failed')
    const f = routeFetch()
    vi.stubGlobal('fetch', f)
    render(<App />)
    await screen.findByText('agent-03')

    const vmsCall = urls(f).find((u) => u.includes('/vms?'))
    expect(vmsCall).toContain('state=running')
    expect(vmsCall).toContain('state=failed')
    expect(screen.getByLabelText('running')).toBeChecked()
    expect(screen.getByLabelText('failed')).toBeChecked()
    expect(screen.getByLabelText('paused')).not.toBeChecked()
  })

  it('says an empty table is a filter, not an empty host', async () => {
    window.history.replaceState(null, '', '/?state=deleted')
    vi.stubGlobal('fetch', routeFetch({ '/attention?limit=10': jsonResponse(attention) }))
    const f = routeFetch()
    f.mockImplementation(async (url: string) => {
      if (url.includes('/vms?')) return jsonResponse({ vms: [], next_after: '' })
      if (url.endsWith('/host/status')) return jsonResponse(host)
      if (url.includes('/events')) return jsonResponse(operations)
      if (url.includes('/templates')) return jsonResponse(templates)
      return jsonResponse(attention)
    })
    vi.stubGlobal('fetch', f)
    render(<App />)
    expect(await screen.findByText(/no vms match this filter/i)).toBeInTheDocument()
  })

  it('singles out a VM in the URL and takes it back out', async () => {
    vi.stubGlobal('fetch', routeFetch())
    render(<App />)
    const name = await screen.findByRole('button', { name: 'agent-03' })

    await userEvent.click(name)
    await waitFor(() => expect(window.location.search).toBe('?vm=7f3a9c21-0000-4000-8000-000000000001'))
    expect(screen.getByTestId('vm-row-7f3a9c21-0000-4000-8000-000000000001')).toHaveAttribute('aria-current', 'true')

    await userEvent.click(name)
    await waitFor(() => expect(window.location.search).toBe(''))
  })

  it('writes only the two keys it owns, and never a credential', async () => {
    const token = 'csrf-secret-do-not-leak'
    window.history.replaceState(null, '', '/?utm_source=chat')
    const f = routeFetch({
      '/auth/session': jsonResponse({ owner: 'local_operator', method: 'session', csrf_token: token }),
    })
    vi.stubGlobal('fetch', f)
    render(
      <SessionProvider>
        <App />
      </SessionProvider>,
    )
    await screen.findByText('agent-03')
    await userEvent.click(screen.getByLabelText('running'))
    await userEvent.click(screen.getByRole('button', { name: 'agent-03' }))

    expect(window.location.href).not.toContain(token)
    expect(document.cookie).toBe('')
    const keys = [...new URLSearchParams(window.location.search).keys()]
    expect(new Set(keys)).toEqual(new Set(['utm_source', 'state', 'vm']))
  })
})

describe('App keyboard access (SPEC §13.7)', () => {
  const FOCUSABLE =
    'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), a[href], summary'

  it('reaches every enabled control by tabbing', async () => {
    vi.stubGlobal('fetch', routeFetch())
    render(<App />)
    await screen.findByText('agent-03')
    // Opened so the batch form's controls are genuinely on the page; a closed
    // <details> would let this test pass by hiding half the form.
    await userEvent.click(screen.getByText('Launch a batch', { selector: 'summary' }))

    const wanted = Array.from(document.querySelectorAll<HTMLElement>(FOCUSABLE))
    // Guard: an empty list would make the assertion below pass without tabbing.
    expect(wanted.length).toBeGreaterThan(20)
    const reached = new Set<Element>()
    for (let i = 0; i < wanted.length + 2; i++) {
      await userEvent.tab()
      if (document.activeElement) reached.add(document.activeElement)
    }

    const missed = wanted.filter((el) => !reached.has(el))
    expect(missed.map((el) => `${el.tagName}[${computeAccessibleName(el) || el.className}]`)).toEqual([])
  })

  it('gives every input and button a name a screen reader can announce', async () => {
    vi.stubGlobal('fetch', routeFetch())
    render(<App />)
    await screen.findByText('agent-03')
    await userEvent.click(screen.getByText('Launch a batch', { selector: 'summary' }))

    const controls = Array.from(document.querySelectorAll<HTMLElement>('button, input, select, textarea'))
    expect(controls.length).toBeGreaterThan(20)
    const unnamed = controls.filter((el) => computeAccessibleName(el).trim() === '')
    expect(unnamed.map((el) => `${el.tagName}.${el.className}#${el.id}`)).toEqual([])
  })
})
