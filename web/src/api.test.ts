// ABOUTME: Tests for the API client: typed errors survive, big counters stay strings.
// ABOUTME: Uses a stubbed fetch; the real API is exercised by the Go integration gate.
import { describe, it, expect, vi, afterEach } from 'vitest'
import { getJSON, ApiFailure } from './api'

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
