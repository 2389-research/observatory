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
  it('returns the same key for a form key across reloads', () => {
    const first = idempotencyKeyFor('launch-vm')
    expect(idempotencyKeyFor('launch-vm')).toBe(first)
    expect(first).toMatch(/^[0-9a-f-]{36}$/)
  })

  it('gives different form keys different keys', () => {
    expect(idempotencyKeyFor('launch-vm')).not.toBe(idempotencyKeyFor('launch-batch'))
  })

  it('issues a fresh key after the operation is cleared', () => {
    const first = idempotencyKeyFor('launch-vm')
    clearIdempotencyKey('launch-vm')
    expect(idempotencyKeyFor('launch-vm')).not.toBe(first)
  })

  it('survives a simulated reload, so a refresh replays instead of relaunching', () => {
    const first = idempotencyKeyFor('launch-vm')
    // A reload keeps sessionStorage and loses module state.
    expect(sessionStorage.getItem('vmobs.idempotency.launch-vm')).toBe(first)
  })
})
