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

/**
 * The idempotency key for a form, stable until the operation finishes.
 *
 * SPEC §13.7: "Refreshing a page does not repeat a launch." sessionStorage
 * survives a reload, so a resubmitted form carries the key the daemon already
 * saw and gets its idempotent replay instead of a second VM.
 */
export function idempotencyKeyFor(formKey: string): string {
  const storageKey = KEY_PREFIX + formKey
  const existing = sessionStorage.getItem(storageKey)
  if (existing) return existing
  const fresh = crypto.randomUUID()
  sessionStorage.setItem(storageKey, fresh)
  return fresh
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
