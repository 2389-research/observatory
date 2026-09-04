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

/** What the session knows that a mutation needs. */
export interface CSRFState {
  method: string
  csrfToken?: string
}

type CSRFGetter = () => CSRFState
type CSRFRefresher = () => Promise<void>

// The daemon runs with authentication off in loopback dev mode, where
// GET /auth/session answers {"owner":"local_operator","method":"none"} and
// there is no token to send. One module-level provider keeps that decision in
// a single place instead of at every call site.
let csrfGetter: CSRFGetter = () => ({ method: 'none' })
let csrfRefresher: CSRFRefresher = async () => {}

/** Point the mutation client at the live session. Called by SessionProvider. */
export function setCSRFProvider(get: CSRFGetter, refresh?: CSRFRefresher): void {
  csrfGetter = get
  csrfRefresher = refresh ?? (async () => {})
}

function mutatingHeaders(): Headers {
  const h = new Headers({ accept: 'application/json', 'content-type': 'application/json' })
  const { method, csrfToken } = csrfGetter()
  if (method === 'session' && csrfToken) {
    h.set('X-CSRF-Token', csrfToken)
  }
  return h
}

/**
 * Decode a response body, or undefined when there is none.
 *
 * A 204 carries no body: DELETE answers with one, and JSON.parse('') throws.
 */
async function decode<T>(res: Response): Promise<T> {
  if (res.status === 204) return undefined as T
  const text = await res.text()
  if (text === '') return undefined as T
  return JSON.parse(text) as T
}

async function send<T>(method: string, path: string, body?: unknown): Promise<T> {
  const init: RequestInit = {
    method,
    credentials: 'same-origin',
    headers: mutatingHeaders(),
  }
  if (body !== undefined) init.body = JSON.stringify(body)

  let res = await fetch(BASE + path, init)

  // A rejected CSRF token is the one failure worth retrying: the token rotates
  // and the browser's copy can be one rotation behind. Refetch it and try once
  // more. Nothing else is retried — a 409 is a real conflict and a 5xx may
  // already have taken effect, so a blind retry could launch a second VM.
  if (res.status === 403) {
    const err = await typedError(res)
    if (err?.cause === 'csrf_rejected') {
      await csrfRefresher()
      res = await fetch(BASE + path, { ...init, headers: mutatingHeaders() })
      if (!res.ok) throw new ApiFailure(res.status, await typedError(res))
      return decode<T>(res)
    }
    throw new ApiFailure(res.status, err)
  }

  if (!res.ok) throw new ApiFailure(res.status, await typedError(res))
  return decode<T>(res)
}

/** POST `body` to `path` under /api/v1 and decode the reply. */
export function postJSON<T>(path: string, body: unknown): Promise<T> {
  return send<T>('POST', path, body)
}

/** DELETE `path` under /api/v1. A 204 resolves to undefined. */
export function deleteJSON<T>(path: string): Promise<T> {
  return send<T>('DELETE', path)
}
