// ABOUTME: Tests for the fleet page shell: load, compose, and fail honestly.
// ABOUTME: fetch is stubbed at the transport seam; the served page is proven end-to-end by the Go tests.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { App } from './App'

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
    if (url.includes('/templates')) return jsonResponse(templates)
    if (url.includes('/vms')) return jsonResponse(vms)
    if (url.includes('/attention')) return jsonResponse(attention)
    throw new Error(`unexpected fetch: ${url}`)
  })
}

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true })
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
