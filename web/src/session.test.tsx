// ABOUTME: Tests for the session context: who the caller is and whether CSRF applies.
// ABOUTME: Stubs fetch at the network boundary; the provider itself is the real one.
import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { SessionProvider, useSession } from './session'

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

afterEach(() => vi.unstubAllGlobals())

function Probe() {
  const s = useSession()
  return (
    <dl>
      <dt>status</dt>
      <dd data-testid="status">{s.status}</dd>
      <dt>owner</dt>
      <dd data-testid="owner">{s.owner ?? ''}</dd>
      <dt>method</dt>
      <dd data-testid="method">{s.method ?? ''}</dd>
      <dt>token</dt>
      <dd data-testid="token">{s.csrfToken ?? ''}</dd>
    </dl>
  )
}

const renderProbe = () =>
  render(
    <SessionProvider>
      <Probe />
    </SessionProvider>,
  )

describe('SessionProvider', () => {
  it('exposes owner, method and token from GET /auth/session', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        json({ owner: 'harper', method: 'session', expires_at: '2026-09-05T00:00:00Z', csrf_token: 'tok-1' }),
      ),
    )
    renderProbe()
    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('ready'))
    expect(screen.getByTestId('owner')).toHaveTextContent('harper')
    expect(screen.getByTestId('method')).toHaveTextContent('session')
    expect(screen.getByTestId('token')).toHaveTextContent('tok-1')
  })

  it('carries no token when authentication is off', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ owner: 'local_operator', method: 'none' })))
    renderProbe()
    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('ready'))
    expect(screen.getByTestId('method')).toHaveTextContent('none')
    expect(screen.getByTestId('token')).toHaveTextContent('')
  })

  it('reports the sign-in state on 401 instead of pretending to be signed in', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ code: 'unauthenticated', cause: 'no_session' }, 401)))
    renderProbe()
    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('signed_out'))
    expect(screen.getByTestId('owner')).toHaveTextContent('')
  })

  it('reports a transport failure as unknown, never as signed out', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('network down')))
    renderProbe()
    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('unknown'))
  })

  it('refresh() refetches and publishes the new token', async () => {
    const spy = vi
      .fn()
      .mockResolvedValueOnce(json({ owner: 'harper', method: 'session', csrf_token: 'tok-1' }))
      .mockResolvedValueOnce(json({ owner: 'harper', method: 'session', csrf_token: 'tok-2' }))
    vi.stubGlobal('fetch', spy)

    function Refresher() {
      const s = useSession()
      return (
        <>
          <span data-testid="token">{s.csrfToken ?? ''}</span>
          <button onClick={() => void s.refresh()}>refresh</button>
        </>
      )
    }
    render(
      <SessionProvider>
        <Refresher />
      </SessionProvider>,
    )
    await waitFor(() => expect(screen.getByTestId('token')).toHaveTextContent('tok-1'))
    screen.getByRole('button', { name: 'refresh' }).click()
    await waitFor(() => expect(screen.getByTestId('token')).toHaveTextContent('tok-2'))
  })
})
