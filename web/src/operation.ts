// ABOUTME: One submit, one operation: the state machine behind every mutating control.
// ABOUTME: Idempotency keys live in sessionStorage so a page refresh replays, never relaunches.
import { useCallback, useRef, useState } from 'react'
import { ApiFailure } from './api'

export type OperationState = 'idle' | 'in_flight' | 'done' | 'failed'

export interface Operation<T> {
  state: OperationState
  result?: T
  operationId?: string
  failure?: ApiFailure
  /** Runs `fn` once; resolves true when it succeeded, false on failure or when one is already in flight. */
  run: (fn: () => Promise<T>) => Promise<boolean>
  reset: () => void
}

const KEY_PREFIX = 'vmobs.idempotency.'

/** What a form's storage entry holds: the key, and the request it was minted for. */
interface StoredKey {
  request: string
  key: string
}

/** Mint a UUIDv4 with the Web Crypto primitive available on HTTP origins. */
function randomUUID(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16))
  bytes[6] = (bytes[6]! & 0x0f) | 0x40
  bytes[8] = (bytes[8]! & 0x3f) | 0x80
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0'))
  return `${hex.slice(0, 4).join('')}-${hex.slice(4, 6).join('')}-${hex.slice(6, 8).join('')}-${hex.slice(8, 10).join('')}-${hex.slice(10).join('')}`
}

/**
 * The idempotency key for a form's current request.
 *
 * SPEC §13.7: "Refreshing a page does not repeat a launch." sessionStorage
 * survives a reload, so a resubmitted form carries the key the daemon already
 * saw and gets its idempotent replay instead of a second VM.
 *
 * The key is bound to the request that minted it, because the daemon binds it
 * the same way: one (owner, kind, key) holds one request hash, and the same key
 * arriving with a different body is refused as idempotency_key_reused. Editing
 * the form after a submit therefore has to mint a new key -- otherwise the form
 * is refused on every later submit, and reloading the page, the one move an
 * operator has, keeps the wedged key instead of clearing it.
 */
export function idempotencyKeyFor(formKey: string, request: unknown): string {
  const storageKey = KEY_PREFIX + formKey
  const fingerprint = JSON.stringify(request)
  const stored = readStoredKey(storageKey)
  if (stored && stored.request === fingerprint) return stored.key
  const fresh: StoredKey = { request: fingerprint, key: randomUUID() }
  sessionStorage.setItem(storageKey, JSON.stringify(fresh))
  return fresh.key
}

/**
 * The stored entry, or undefined when there is nothing this function can trust.
 *
 * A session that began on a build that stored the bare key leaves a string that
 * is not this shape; so does anything else that writes to the slot. Either way
 * the answer is the same as an empty slot -- mint a new key -- because a key we
 * cannot tie to a request is exactly the key that wedges the form.
 */
function readStoredKey(storageKey: string): StoredKey | undefined {
  const raw = sessionStorage.getItem(storageKey)
  if (!raw) return undefined
  try {
    const parsed: unknown = JSON.parse(raw)
    if (
      typeof parsed === 'object' && parsed !== null &&
      typeof (parsed as StoredKey).request === 'string' &&
      typeof (parsed as StoredKey).key === 'string'
    ) {
      return parsed as StoredKey
    }
  } catch {
    // Not JSON at all. Same answer.
  }
  return undefined
}

/** Drop a form's key so the next submit is a new operation, not a replay. */
export function clearIdempotencyKey(formKey: string): void {
  sessionStorage.removeItem(KEY_PREFIX + formKey)
}

/**
 * Where an operation id turns up in a reply.
 *
 * POST /vms answers {vm, operation} and POST /batches answers a batch with its
 * own id, so the id is nested as often as it is top-level. Reading both keeps
 * every caller from unwrapping by hand.
 */
interface WithOperationID {
  operation_id?: string
  operation?: { operation_id?: string }
}

export function useOperation<T>(): Operation<T> {
  const [state, setState] = useState<OperationState>('idle')
  const [result, setResult] = useState<T | undefined>()
  const [failure, setFailure] = useState<ApiFailure | undefined>()
  // A ref, not the state value: two clicks in one React batch both read the
  // same stale state and both would fire.
  const inFlight = useRef(false)

  // Returns the outcome rather than leaving the caller to read `state`: the
  // state a caller sees right after awaiting is the one from the render that
  // dispatched the call, not the one this run just set.
  const run = useCallback(async (fn: () => Promise<T>) => {
    if (inFlight.current) return false
    inFlight.current = true
    setState('in_flight')
    setFailure(undefined)
    try {
      const value = await fn()
      setResult(value)
      setState('done')
      return true
    } catch (e) {
      setFailure(e instanceof ApiFailure ? e : new ApiFailure(0, undefined))
      setState('failed')
      return false
    } finally {
      inFlight.current = false
    }
  }, [])

  const reset = useCallback(() => {
    setState('idle')
    setResult(undefined)
    setFailure(undefined)
  }, [])

  const withID = result as WithOperationID | undefined
  const operationId = withID?.operation_id ?? withID?.operation?.operation_id

  return { state, result, operationId, failure, run, reset }
}
