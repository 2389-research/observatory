// ABOUTME: Tests for the operation state machine: one submit, one operation, no repeats.
// ABOUTME: Idempotency keys survive a reload so a refresh replays rather than relaunches.
import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, waitFor, act } from '@testing-library/react'
import { ApiFailure } from './api'
import { useOperation, idempotencyKeyFor, clearIdempotencyKey } from './operation'

afterEach(() => vi.unstubAllGlobals())
beforeEach(() => sessionStorage.clear())

type OpReply = { operation_id?: string; operation?: { operation_id?: string } }

function Probe({ fn }: { fn: () => Promise<OpReply> }) {
  const op = useOperation<OpReply>()
  return (
    <>
      <span data-testid="state">{op.state}</span>
      <span data-testid="op">{op.operationId ?? ''}</span>
      <span data-testid="cause">{op.failure?.error?.cause ?? ''}</span>
      <button onClick={() => void op.run(fn)}>go</button>
      <button onClick={() => op.reset()}>reset</button>
    </>
  )
}

describe('useOperation', () => {
  it('moves idle to in_flight to done and publishes the operation id', async () => {
    let release: (v: OpReply) => void = () => {}
    const pending = new Promise<OpReply>((r) => (release = r))
    render(<Probe fn={() => pending} />)

    expect(screen.getByTestId('state')).toHaveTextContent('idle')
    act(() => screen.getByRole('button', { name: 'go' }).click())
    await waitFor(() => expect(screen.getByTestId('state')).toHaveTextContent('in_flight'))

    await act(async () => {
      release({ operation_id: 'op-77' })
      await pending
    })
    await waitFor(() => expect(screen.getByTestId('state')).toHaveTextContent('done'))
    expect(screen.getByTestId('op')).toHaveTextContent('op-77')
  })

  it('finds the operation id nested under operation, as POST /vms answers it', async () => {
    render(<Probe fn={() => Promise.resolve({ operation: { operation_id: 'op-000042' } })} />)
    act(() => screen.getByRole('button', { name: 'go' }).click())
    await waitFor(() => expect(screen.getByTestId('state')).toHaveTextContent('done'))
    expect(screen.getByTestId('op')).toHaveTextContent('op-000042')
  })

  it('keeps the typed failure instead of a bare message', async () => {
    const failure = new ApiFailure(409, {
      code: 'insufficient_capacity',
      message: 'host cannot admit this VM',
      cause: 'admission_refused',
      retryable: false,
    })
    render(<Probe fn={() => Promise.reject(failure)} />)
    act(() => screen.getByRole('button', { name: 'go' }).click())
    await waitFor(() => expect(screen.getByTestId('state')).toHaveTextContent('failed'))
    expect(screen.getByTestId('cause')).toHaveTextContent('admission_refused')
  })

  it('refuses a second run while one is in flight', async () => {
    const fn = vi.fn().mockReturnValue(new Promise(() => {}))
    render(<Probe fn={fn} />)
    act(() => screen.getByRole('button', { name: 'go' }).click())
    act(() => screen.getByRole('button', { name: 'go' }).click())
    await waitFor(() => expect(screen.getByTestId('state')).toHaveTextContent('in_flight'))
    expect(fn).toHaveBeenCalledTimes(1)
  })

  it('reset returns to idle and drops the previous failure', async () => {
    render(<Probe fn={() => Promise.reject(new ApiFailure(500))} />)
    act(() => screen.getByRole('button', { name: 'go' }).click())
    await waitFor(() => expect(screen.getByTestId('state')).toHaveTextContent('failed'))
    act(() => screen.getByRole('button', { name: 'reset' }).click())
    expect(screen.getByTestId('state')).toHaveTextContent('idle')
    expect(screen.getByTestId('cause')).toHaveTextContent('')
  })
})

describe('idempotencyKeyFor', () => {
  const request = { name: 'alpha', template_id: 'dev-small' }

  it('mints UUIDv4 keys when randomUUID is unavailable on an HTTP origin', () => {
    const getRandomValues = crypto.getRandomValues.bind(crypto)
    vi.stubGlobal('crypto', { getRandomValues })

    const first = idempotencyKeyFor('launch-vm', request)
    const second = idempotencyKeyFor('launch-batch', request)

    expect(first).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
    expect(second).not.toBe(first)
    expect(idempotencyKeyFor('launch-vm', { ...request })).toBe(first)
  })

  it('returns the same key for an unchanged request across reloads', () => {
    const first = idempotencyKeyFor('launch-vm', request)
    expect(idempotencyKeyFor('launch-vm', { ...request })).toBe(first)
    expect(first).toMatch(/^[0-9a-f-]{36}$/)
  })

  it('gives different form keys different keys', () => {
    expect(idempotencyKeyFor('launch-vm', request)).not.toBe(idempotencyKeyFor('launch-batch', request))
  })

  it('issues a fresh key after the operation is cleared', () => {
    const first = idempotencyKeyFor('launch-vm', request)
    clearIdempotencyKey('launch-vm')
    expect(idempotencyKeyFor('launch-vm', request)).not.toBe(first)
  })

  it('survives a simulated reload, so a refresh replays instead of relaunching', () => {
    const first = idempotencyKeyFor('launch-vm', request)
    // A reload keeps sessionStorage and loses module state.
    sessionStorage.setItem('vmobs.idempotency.launch-vm', sessionStorage.getItem('vmobs.idempotency.launch-vm')!)
    expect(idempotencyKeyFor('launch-vm', request)).toBe(first)
  })

  // The wedge this replaced: a key outliving the request it was minted for.
  // The daemon keys (owner, kind, key) to one request hash and refuses that key
  // for any other body, so a form that kept its key across an edit was refused
  // with idempotency_key_reused on every later submit, forever, with no way out
  // of the browser -- sessionStorage survives the reload the operator reaches for.
  it('mints a fresh key when the request changed, so an edit is a new launch', () => {
    const first = idempotencyKeyFor('launch-vm', request)
    const second = idempotencyKeyFor('launch-vm', { ...request, name: 'beta' })
    expect(second).not.toBe(first)
    // And the new key is now the stable one: retrying the edited request replays.
    expect(idempotencyKeyFor('launch-vm', { ...request, name: 'beta' })).toBe(second)
  })

  it('ignores a stored entry it cannot read rather than throwing', () => {
    // What a session that started on an older build left behind: a bare key.
    sessionStorage.setItem('vmobs.idempotency.launch-vm', 'de305d54-75b4-431b-adb2-eb6b9e546014')
    expect(idempotencyKeyFor('launch-vm', request)).toMatch(/^[0-9a-f-]{36}$/)
    expect(idempotencyKeyFor('launch-vm', request)).not.toBe('de305d54-75b4-431b-adb2-eb6b9e546014')
  })
})
