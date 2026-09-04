// ABOUTME: Batch launch tests: the header follows the weakest member and polling stops when all are terminal.
// ABOUTME: The member editor is the launch form's, not a copy — asserted by comparing accessible field sets.
import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { LaunchBatch } from './LaunchBatch'
import { LaunchForm } from './LaunchForm'
import { setCSRFProvider } from '../api'
import { testHost, testTemplates, testVM } from '../test/fixtures'
import type { BatchReply } from '../types'

const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

const op = (state: string, id = 'op-000001') => ({
  operation_id: id,
  kind: 'vm.create',
  phase: state === 'running' ? 'running' : 'complete',
  state,
  attempt: 1,
  created_at: '2026-09-04T10:00:00Z',
  updated_at: '2026-09-04T10:00:01Z',
})

const reply = (members: BatchReply['members'], over: Partial<BatchReply> = {}): BatchReply => ({
  batch: {
    batch_id: 'batch-000001',
    owner: 'local_operator',
    reservation_mode: 'atomic_reservation',
    on_failure: 'keep_successful',
    created_at: '2026-09-04T10:00:00Z',
    updated_at: '2026-09-04T10:00:01Z',
    links: { self: '/api/v1/vm-batches/batch-000001' },
  },
  members,
  ...over,
})

beforeEach(() => {
  sessionStorage.clear()
  setCSRFProvider(() => ({ method: 'none' }))
})
afterEach(() => {
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

const renderBatch = (onLaunched = vi.fn()) =>
  render(<LaunchBatch host={testHost} templates={testTemplates} onLaunched={onLaunched} />)

/** Choose a reservation mode so submit is allowed; the API has no default. */
async function chooseMode(user: ReturnType<typeof userEvent.setup>) {
  await user.selectOptions(screen.getByLabelText(/reservation mode/i), 'best_effort')
}

describe('LaunchBatch member editor', () => {
  it('renders the same field set as the single launch form', () => {
    const batch = render(<LaunchBatch host={testHost} templates={testTemplates} onLaunched={vi.fn()} />)
    const batchFields = batch.container.querySelectorAll('[data-testid="member-fields"]')
    const batchLabels = Array.from(batchFields[0]!.querySelectorAll('label')).map((l) => l.textContent)
    batch.unmount()

    const single = render(<LaunchForm host={testHost} templates={testTemplates} onLaunched={vi.fn()} />)
    const singleFields = single.container.querySelector('[data-testid="member-fields"]')!
    const singleLabels = Array.from(singleFields.querySelectorAll('label')).map((l) => l.textContent)

    expect(batchLabels).toEqual(singleLabels)
    expect(batchLabels.length).toBeGreaterThan(0)
  })

  it('starts with two members and can add and remove them', async () => {
    const user = userEvent.setup()
    const { container } = renderBatch()
    expect(container.querySelectorAll('[data-testid="member-fields"]')).toHaveLength(2)

    await user.click(screen.getByRole('button', { name: /add member/i }))
    expect(container.querySelectorAll('[data-testid="member-fields"]')).toHaveLength(3)

    await user.click(screen.getAllByRole('button', { name: /remove member/i })[0]!)
    expect(container.querySelectorAll('[data-testid="member-fields"]')).toHaveLength(2)
  })
})

describe('LaunchBatch published limits', () => {
  it('warns before submit when the batch is larger than the published max_batch_size', async () => {
    const user = userEvent.setup()
    renderBatch()
    // Two members to start; the fixture host publishes a cap of 8.
    for (let i = 0; i < 7; i++) await user.click(screen.getByRole('button', { name: /add member/i }))

    const warning = await screen.findByTestId('batch-size-warning')
    expect(warning).toHaveTextContent(/9 members/i)
    expect(warning).toHaveTextContent(/8/)
    expect(screen.getByRole('button', { name: /launch batch/i })).toBeDisabled()
  })

  it('does not warn at exactly the published cap', async () => {
    const user = userEvent.setup()
    renderBatch()
    for (let i = 0; i < 6; i++) await user.click(screen.getByRole('button', { name: /add member/i }))
    expect(screen.queryByTestId('batch-size-warning')).toBeNull()
  })

  it('previews the whole batch reservation, multiplied by the member count', async () => {
    const user = userEvent.setup()
    renderBatch()
    // Two members at the host's 512 MiB default plus 768 MiB overhead each.
    expect(screen.getByTestId('batch-preview-memory')).toHaveTextContent('2560 MiB of 2048 MiB free')
    await user.click(screen.getByRole('button', { name: /add member/i }))
    expect(screen.getByTestId('batch-preview-memory')).toHaveTextContent('3840 MiB of 2048 MiB free')
  })
})

describe('LaunchBatch submit', () => {
  it('sends every member with the chosen modes and one idempotency key', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.fn(async () => jsonResponse(reply([{ position: 0, name: 'alpha', operation: op('succeeded') }]), 201))
    vi.stubGlobal('fetch', fetchMock)
    renderBatch()

    await user.type(screen.getAllByLabelText(/^name/i)[0]!, 'alpha')
    await chooseMode(user)
    await user.click(screen.getByRole('button', { name: /launch batch/i }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toContain('/vm-batches')
    const body = JSON.parse(init.body as string)
    expect(body.members).toHaveLength(2)
    expect(body.members[0].name).toBe('alpha')
    expect(body.members[0].template_id).toBe('standard')
    expect(body.reservation_mode).toBe('best_effort')
    expect(body.on_failure).toBe('keep_successful')
    expect(typeof body.idempotency_key).toBe('string')
  })

  it('will not submit without an explicit reservation mode', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.fn(async () => jsonResponse(reply([{ position: 0, name: 'alpha', operation: op('succeeded') }]), 201))
    vi.stubGlobal('fetch', fetchMock)
    renderBatch()

    expect(screen.getByRole('button', { name: /launch batch/i })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: /launch batch/i }))
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('keeps the idempotency key after a failure so a retry replays', async () => {
    const user = userEvent.setup()
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ code: 'internal', message: 'nope', cause: 'storage_failure' }, 500))
      .mockResolvedValueOnce(jsonResponse(reply([{ position: 0, name: 'alpha', operation: op('succeeded') }]), 201))
    vi.stubGlobal('fetch', fetchMock)
    renderBatch()
    await chooseMode(user)

    await user.click(screen.getByRole('button', { name: /launch batch/i }))
    await screen.findByRole('alert')
    await user.click(screen.getByRole('button', { name: /launch batch/i }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))

    const first = JSON.parse((fetchMock.mock.calls[0]![1] as RequestInit).body as string)
    const second = JSON.parse((fetchMock.mock.calls[1]![1] as RequestInit).body as string)
    expect(second.idempotency_key).toBe(first.idempotency_key)
  })

  it('shows the daemon own refusal, cause and remediation, when the batch is refused', async () => {
    const user = userEvent.setup()
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(
          {
            code: 'malformed_request',
            message: 'batch has 9 members, maximum is 8',
            cause: 'batch_too_large',
            retryable: false,
            remediation: [{ action: 'split the batch', rationale: 'the host caps a batch at 8 members' }],
          },
          400,
        ),
      ),
    )
    renderBatch()
    await chooseMode(user)
    await user.click(screen.getByRole('button', { name: /launch batch/i }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('batch has 9 members, maximum is 8')
    expect(alert).toHaveTextContent('batch_too_large')
    expect(alert).toHaveTextContent('split the batch')
  })
})

describe('LaunchBatch progress', () => {
  it('says partial, never succeeded, when one member is up and another failed', async () => {
    const user = userEvent.setup()
    const members = [
      { position: 0, name: 'alpha', vm: testVM({ vm_id: 'vm-a' }), operation: op('succeeded', 'op-000001') },
      {
        position: 1,
        name: 'beta',
        operation: { ...op('failed', 'op-000002'), error: { cause: 'capacity_exhausted', message: 'no room' } },
      },
    ]
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse(reply(members), 201)))
    renderBatch()
    await chooseMode(user)
    await user.click(screen.getByRole('button', { name: /launch batch/i }))

    const header = await screen.findByTestId('batch-state')
    expect(header).toHaveTextContent(/partial/i)
    expect(header).not.toHaveTextContent(/succeeded/i)
  })

  it('gives each member its own row with its own verdict and cause', async () => {
    const user = userEvent.setup()
    const members = [
      { position: 0, name: 'alpha', vm: testVM({ vm_id: 'vm-a' }), operation: op('succeeded', 'op-000001') },
      { position: 1, name: 'beta', refusal: { cause: 'capacity_exhausted', message: 'not enough memory' } },
    ]
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse(reply(members), 201)))
    renderBatch()
    await chooseMode(user)
    await user.click(screen.getByRole('button', { name: /launch batch/i }))

    const rowA = await screen.findByTestId('member-row-0')
    expect(rowA).toHaveTextContent('alpha')
    expect(rowA).toHaveTextContent('vm-a')
    expect(rowA).toHaveTextContent(/succeeded/i)

    const rowB = screen.getByTestId('member-row-1')
    expect(rowB).toHaveTextContent('beta')
    expect(rowB).toHaveTextContent(/refused/i)
    expect(rowB).toHaveTextContent('capacity_exhausted')
    expect(rowB).toHaveTextContent('not enough memory')
    expect(within(rowB).queryByText('vm-a')).toBeNull()
  })

  it('polls the batch while a member is in flight and stops once all are terminal', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
    const pending = [
      { position: 0, name: 'alpha', operation: op('succeeded', 'op-000001') },
      { position: 1, name: 'beta', operation: op('running', 'op-000002') },
    ]
    const settled = [
      { position: 0, name: 'alpha', operation: op('succeeded', 'op-000001') },
      { position: 1, name: 'beta', operation: op('failed', 'op-000002') },
    ]
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(reply(pending), 201))
      .mockResolvedValue(jsonResponse(reply(settled), 200))
    vi.stubGlobal('fetch', fetchMock)
    renderBatch()
    await chooseMode(user)
    await user.click(screen.getByRole('button', { name: /launch batch/i }))

    await waitFor(() => expect(screen.getByTestId('batch-state')).toHaveTextContent(/in progress/i))

    await vi.advanceTimersByTimeAsync(2500)
    await waitFor(() => expect(screen.getByTestId('batch-state')).toHaveTextContent(/partial/i))
    const afterSettle = fetchMock.mock.calls.length
    expect(fetchMock.mock.calls[1]![0]).toContain('/vm-batches/batch-000001')

    // Terminal means done: no further polls.
    await vi.advanceTimersByTimeAsync(10000)
    expect(fetchMock.mock.calls.length).toBe(afterSettle)
  })

  it('marks a replay as a replay rather than a second batch', async () => {
    const user = userEvent.setup()
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(reply([{ position: 0, name: 'alpha', operation: op('succeeded') }], { is_replay: true }), 201),
      ),
    )
    renderBatch()
    await chooseMode(user)
    await user.click(screen.getByRole('button', { name: /launch batch/i }))

    expect(await screen.findByTestId('batch-result')).toHaveTextContent(/replay/i)
  })
})
