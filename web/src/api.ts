// ABOUTME: Fetch client for /api/v1. Every non-2xx becomes an ApiFailure that
// ABOUTME: keeps the daemon's typed cause and remediation instead of a bare status.
import type { ApiError } from './types'

const BASE = '/api/v1'

/** A non-2xx response. `error` is absent when the body was not the typed envelope. */
export class ApiFailure extends Error {
  readonly status: number
  readonly error?: ApiError

  constructor(status: number, error?: ApiError) {
    super(error?.message ?? `request failed with status ${status}`)
    this.name = 'ApiFailure'
    this.status = status
    this.error = error
  }
}

/**
 * GET `path` under /api/v1 and decode it.
 *
 * Decoding leaves every value exactly as the daemon sent it: counters that can
 * outgrow Number.MAX_SAFE_INTEGER arrive as decimal strings and stay strings.
 */
export async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(BASE + path, {
    credentials: 'same-origin',
    headers: { accept: 'application/json' },
  })
  if (!res.ok) {
    throw new ApiFailure(res.status, await typedError(res))
  }
  return (await res.json()) as T
}

/** Read the typed error envelope, or undefined when the body is not one. */
async function typedError(res: Response): Promise<ApiError | undefined> {
  try {
    const body: unknown = await res.json()
    if (body && typeof body === 'object' && 'cause' in body && 'code' in body) {
      return body as ApiError
    }
    return undefined
  } catch {
    return undefined
  }
}
