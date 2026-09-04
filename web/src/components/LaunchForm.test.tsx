// ABOUTME: Tests for the launch form: the preview restates published numbers and never invents one.
// ABOUTME: Over-capacity warns but never blocks — the browser warns, the daemon decides.
import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { LaunchForm } from './LaunchForm'
import { setCSRFProvider } from '../api'
import type { HostStatus, Template } from '../types'

const host: HostStatus = {
  capacity: {
    usable_memory_mib: 8192,
    reserved_memory_mib: 1024,
    free_memory_mib: 2048,
    usable_vcpu: 8,
    reserved_vcpu: 2,
    free_vcpu: 6,
    usable_disk_mib: 100000,
    reserved_disk_mib: 5000,
    free_disk_mib: 20000,
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

const templates: Template[] = [
  {
    template_id: 'standard',
    description: 'Demo VM template',
    digest: 'sha256:abc',
    kernel_image: '/srv/vmobs/images/vmlinux',
    root_image: '/srv/vmobs/images/rootfs.img',
    guest_privilege_profiles: ['unprivileged'],
    sensors: ['fanotify'],
    protocol_versions: { guestd: '1' },
  },
]

const okResponse = (body: unknown, status = 201) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

beforeEach(() => {
  sessionStorage.clear()
  setCSRFProvider(() => ({ method: 'none' }))
})
afterEach(() => vi.unstubAllGlobals())

const renderForm = (onLaunched = vi.fn()) =>
  render(<LaunchForm host={host} templates={templates} onLaunched={onLaunched} />)

describe('LaunchForm reservation preview', () => {
  it('charges the published per-VM overhead, not a number of its own', async () => {
    renderForm()
    // Defaults: the form starts from the first template and the host's own
    // published defaults; memory is set explicitly here.
    await userEvent.clear(screen.getByLabelText(/memory/i))
    await userEvent.type(screen.getByLabelText(/memory/i), '512')

    // 512 requested + 768 published overhead = 1280.
    await waitFor(() =>
      expect(screen.getByTestId('preview-memory')).toHaveTextContent('1280 MiB of 2048 MiB free'),
    )
  })

  it('shows disk as root plus workspace against free disk', async () => {
    renderForm()
    await userEvent.clear(screen.getByLabelText(/root disk/i))
    await userEvent.type(screen.getByLabelText(/root disk/i), '2048')
    await userEvent.clear(screen.getByLabelText(/workspace disk/i))
    await userEvent.type(screen.getByLabelText(/workspace disk/i), '1024')

    await waitFor(() =>
      expect(screen.getByTestId('preview-disk')).toHaveTextContent('3072 MiB of 20000 MiB free'),
    )
  })

  it('warns over capacity but leaves submit enabled — the daemon decides', async () => {
    renderForm()
    await userEvent.clear(screen.getByLabelText(/memory/i))
    await userEvent.type(screen.getByLabelText(/memory/i), '4096')

    await waitFor(() => expect(screen.getByTestId('preview-memory')).toHaveTextContent('over'))
    expect(screen.getByRole('button', { name: /launch/i })).toBeEnabled()
  })
})

describe('LaunchForm submit', () => {
  it('posts exactly the fields the API accepts, with the stored idempotency key', async () => {
    const spy = vi.fn().mockResolvedValue(okResponse({ vm: { vm_id: 'v1' }, operation: { operation_id: 'op-000009' } }))
    vi.stubGlobal('fetch', spy)
    renderForm()

    await userEvent.clear(screen.getByLabelText(/^name/i))
    await userEvent.type(screen.getByLabelText(/^name/i), 'worker-1')
    await userEvent.click(screen.getByRole('button', { name: /launch/i }))

    await waitFor(() => expect(spy).toHaveBeenCalledTimes(1))
    const [url, init] = spy.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/api/v1/vms')
    const sent = JSON.parse(init.body as string) as Record<string, unknown>
    expect(Object.keys(sent).sort()).toEqual(
      ['idempotency_key', 'labels', 'memory_mib', 'name', 'root_disk_mib', 'template_id', 'vcpu_count', 'workspace_disk_mib'].sort(),
    )
    expect(sent.name).toBe('worker-1')
    expect(sent.template_id).toBe('standard')
    expect(sent.idempotency_key).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-/)
  })

  it('shows the operation id after a successful launch', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(okResponse({ vm: { vm_id: 'v1' }, operation: { operation_id: 'op-000009' } })),
    )
    renderForm()
    await userEvent.click(screen.getByRole('button', { name: /launch/i }))
    await waitFor(() => expect(screen.getByTestId('launch-result')).toHaveTextContent('op-000009'))
  })

  it('mints a new key after a success, so the next launch is not a replay', async () => {
    const spy = vi.fn().mockResolvedValue(okResponse({ vm: {}, operation: { operation_id: 'op-1' } }))
    vi.stubGlobal('fetch', spy)
    renderForm()
    const launch = screen.getByRole('button', { name: /launch/i })
    await userEvent.click(launch)
    await waitFor(() => expect(screen.getByTestId('launch-result')).toBeInTheDocument())
    await userEvent.click(launch)
    await waitFor(() => expect(spy).toHaveBeenCalledTimes(2))

    const keys = spy.mock.calls.map(
      (c) => (JSON.parse((c[1] as RequestInit).body as string) as { idempotency_key: string }).idempotency_key,
    )
    expect(keys[0]).not.toBe(keys[1])
  })

  it('reuses the key after a failure, so a retry replays instead of doubling', async () => {
    const spy = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ code: 'internal', cause: 'storage_failure', message: 'no' }), {
        status: 500,
        headers: { 'content-type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', spy)
    renderForm()
    const launch = screen.getByRole('button', { name: /launch/i })
    await userEvent.click(launch)
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    await userEvent.click(launch)
    await waitFor(() => expect(spy).toHaveBeenCalledTimes(2))

    const keys = spy.mock.calls.map(
      (c) => (JSON.parse((c[1] as RequestInit).body as string) as { idempotency_key: string }).idempotency_key,
    )
    expect(keys[0]).toBe(keys[1])
  })

  it('renders the typed refusal in full — message, cause and every remediation', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            code: 'insufficient_capacity',
            message: 'host cannot admit this VM',
            cause: 'admission_refused',
            retryable: false,
            remediation: [
              { action: 'get', rationale: 'shows current reservations' },
              { action: 'stop', rationale: 'frees a running VM' },
            ],
          }),
          { status: 409, headers: { 'content-type': 'application/json' } },
        ),
      ),
    )
    renderForm()
    await userEvent.click(screen.getByRole('button', { name: /launch/i }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('host cannot admit this VM')
    expect(alert).toHaveTextContent('admission_refused')
    expect(alert).toHaveTextContent('shows current reservations')
    expect(alert).toHaveTextContent('frees a running VM')
  })
})

describe('LaunchForm honesty and access', () => {
  it('shows the fields it cannot set yet as disabled controls naming their milestone', () => {
    renderForm()
    for (const label of [/network profile/i, /guest privilege/i, /workspace seed/i, /initial command/i]) {
      const el = screen.getByLabelText(label)
      expect(el).toBeDisabled()
    }
    expect(screen.getByTestId('deferred-fields')).toHaveTextContent(/M2|M3|M4/)
  })

  it('gives every enabled input a label a screen reader can reach', () => {
    renderForm()
    for (const label of [/^name/i, /template/i, /vcpu/i, /memory/i, /root disk/i, /workspace disk/i]) {
      expect(screen.getByLabelText(label)).toBeEnabled()
    }
  })

  it('submits from the keyboard alone', async () => {
    const spy = vi.fn().mockResolvedValue(okResponse({ vm: {}, operation: { operation_id: 'op-1' } }))
    vi.stubGlobal('fetch', spy)
    renderForm()
    screen.getByLabelText(/^name/i).focus()
    await userEvent.keyboard('kbd-vm{Enter}')
    await waitFor(() => expect(spy).toHaveBeenCalledTimes(1))
  })

  it('refuses a second submit while one is in flight', async () => {
    const spy = vi.fn().mockReturnValue(new Promise(() => {}))
    vi.stubGlobal('fetch', spy)
    renderForm()
    const button = screen.getByRole('button', { name: /launch/i })
    await userEvent.click(button)
    await waitFor(() => expect(button).toBeDisabled())
    expect(spy).toHaveBeenCalledTimes(1)
  })
})
