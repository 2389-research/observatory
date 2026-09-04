// ABOUTME: Tests for the API client: typed errors survive, big counters stay strings.
// ABOUTME: Uses a stubbed fetch; the real API is exercised by the Go integration gate.
import { describe, it, expect, vi, afterEach } from 'vitest'
import { getJSON, postJSON, deleteJSON, ApiFailure, setCSRFProvider } from './api'

const okResponse = (body: unknown) =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })

afterEach(() => vi.unstubAllGlobals())

describe('getJSON', () => {
  it('returns the decoded body on success', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(okResponse({ vms: [], next_after: '' })))
    await expect(getJSON('/vms')).resolves.toEqual({ vms: [], next_after: '' })
  })

  it('keeps a revision beyond MAX_SAFE_INTEGER exact, as a string', async () => {
    const huge = '9007199254740993' // MAX_SAFE_INTEGER + 2
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(okResponse({ revision: huge })))
    const got = await getJSON<{ revision: string }>('/vms/x')
    expect(got.revision).toBe(huge)
    expect(typeof got.revision).toBe('string')
  })

  it('throws ApiFailure carrying the typed cause and remediation', async () => {
    const body = {
      code: 'insufficient_capacity',
      message: 'host cannot admit this VM',
      cause: 'admission_refused',
      retryable: false,
      remediation: [{ action: 'get', rationale: 'shows current reservations' }],
    }
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify(body), {
          status: 409,
          headers: { 'content-type': 'application/json' },
        }),
      ),
    )
    await expect(getJSON('/vms')).rejects.toMatchObject({
      status: 409,
      error: { cause: 'admission_refused', code: 'insufficient_capacity' },
    })
  })

  it('reports a non-JSON error body without inventing a cause', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response('gateway exploded', { status: 502 })),
    )
    const err = await getJSON('/vms').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiFailure)
    expect((err as ApiFailure).error).toBeUndefined()
    expect((err as ApiFailure).status).toBe(502)
  })

  it('sends credentials so the session cookie rides along', async () => {
    const spy = vi.fn().mockResolvedValue(okResponse({}))
    vi.stubGlobal('fetch', spy)
    await getJSON('/meta')
    expect(spy).toHaveBeenCalledWith('/api/v1/meta', expect.objectContaining({ credentials: 'same-origin' }))
  })
})

describe('postJSON', () => {
  it('sends the body as JSON with same-origin credentials', async () => {
    const spy = vi.fn().mockResolvedValue(okResponse({ vm_id: 'v1' }))
    vi.stubGlobal('fetch', spy)
    setCSRFProvider(() => ({ method: 'none' }))

    await postJSON('/vms', { name: 'demo' })

    const [url, init] = spy.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/api/v1/vms')
    expect(init.method).toBe('POST')
    expect(init.credentials).toBe('same-origin')
    expect(JSON.parse(init.body as string)).toEqual({ name: 'demo' })
  })

  it('sends X-CSRF-Token when the session carries one', async () => {
    const spy = vi.fn().mockResolvedValue(okResponse({}))
    vi.stubGlobal('fetch', spy)
    setCSRFProvider(() => ({ method: 'session', csrfToken: 'tok-1' }))

    await postJSON('/vms', {})

    const headers = new Headers((spy.mock.calls[0]![1] as RequestInit).headers)
    expect(headers.get('X-CSRF-Token')).toBe('tok-1')
  })

  it('omits X-CSRF-Token when authentication is off', async () => {
    const spy = vi.fn().mockResolvedValue(okResponse({}))
    vi.stubGlobal('fetch', spy)
    setCSRFProvider(() => ({ method: 'none' }))

    await postJSON('/vms', {})

    const headers = new Headers((spy.mock.calls[0]![1] as RequestInit).headers)
    expect(headers.has('X-CSRF-Token')).toBe(false)
  })

  it('refetches the session once and retries once on a rejected CSRF token', async () => {
    const rejected = new Response(
      JSON.stringify({ code: 'forbidden', cause: 'csrf_rejected', message: 'stale token', retryable: true }),
      { status: 403, headers: { 'content-type': 'application/json' } },
    )
    const spy = vi.fn().mockResolvedValueOnce(rejected).mockResolvedValueOnce(okResponse({ ok: true }))
    vi.stubGlobal('fetch', spy)
    const refresh = vi.fn().mockResolvedValue(undefined)
    let token = 'stale'
    setCSRFProvider(() => ({ method: 'session', csrfToken: token }), async () => {
      token = 'fresh'
      await refresh()
    })

    await expect(postJSON('/vms', {})).resolves.toEqual({ ok: true })
    expect(refresh).toHaveBeenCalledTimes(1)
    expect(spy).toHaveBeenCalledTimes(2)
    expect(new Headers((spy.mock.calls[1]![1] as RequestInit).headers).get('X-CSRF-Token')).toBe('fresh')
  })

  it('surfaces a second CSRF rejection instead of retrying again', async () => {
    const rejected = () =>
      new Response(JSON.stringify({ code: 'forbidden', cause: 'csrf_rejected', message: 'no' }), {
        status: 403,
        headers: { 'content-type': 'application/json' },
      })
    const spy = vi.fn().mockResolvedValue(rejected())
    vi.stubGlobal('fetch', spy)
    setCSRFProvider(() => ({ method: 'session', csrfToken: 't' }), async () => {})

    await expect(postJSON('/vms', {})).rejects.toMatchObject({ status: 403 })
    expect(spy).toHaveBeenCalledTimes(2)
  })

  it('never retries a 409: a conflict is an answer, not a stale token', async () => {
    const spy = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ code: 'conflict', cause: 'revision_mismatch', message: 'stale' }), {
        status: 409,
        headers: { 'content-type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', spy)
    setCSRFProvider(() => ({ method: 'session', csrfToken: 't' }), async () => {})

    await expect(postJSON('/vms/x/actions', {})).rejects.toMatchObject({ status: 409 })
    expect(spy).toHaveBeenCalledTimes(1)
  })

  it('never retries a 403 that is not a CSRF rejection', async () => {
    const spy = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ code: 'forbidden', cause: 'not_owner', message: 'not yours' }), {
        status: 403,
        headers: { 'content-type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', spy)
    setCSRFProvider(() => ({ method: 'session', csrfToken: 't' }), async () => {})

    await expect(postJSON('/vms', {})).rejects.toMatchObject({ status: 403, error: { cause: 'not_owner' } })
    expect(spy).toHaveBeenCalledTimes(1)
  })

  it('returns undefined for a 204 rather than choking on an empty body', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 204 })))
    setCSRFProvider(() => ({ method: 'none' }))
    await expect(deleteJSON('/terminals/t1')).resolves.toBeUndefined()
  })
})
