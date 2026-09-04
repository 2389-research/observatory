// ABOUTME: The fleet page's view state lives in the query string (SPEC §13.7), so a
// ABOUTME: reload and a shared link land on the same view — and it carries no credentials.

export interface FleetState {
  /** Repeated `?state=` values: the same filter axis GET /vms takes. */
  stateFilter: string[]
  /** `?vm=`: the row the operator singled out. */
  selectedVM?: string
}

const STATE_KEY = 'state'
const VM_KEY = 'vm'

/** Read the view state out of a `location.search`. Unknown keys are not ours. */
export function readState(search: string): FleetState {
  const params = new URLSearchParams(search)
  const state: FleetState = { stateFilter: params.getAll(STATE_KEY) }
  const vm = params.get(VM_KEY)
  if (vm) state.selectedVM = vm
  return state
}

/**
 * Render `state` into a search string, preserving everything in `search` that
 * this module does not own.
 *
 * It writes two keys and reads two keys. Nothing else can reach the URL through
 * here, which is why a session token cannot end up in a link an operator pastes
 * into a ticket.
 */
export function writeState(state: FleetState, search = ''): string {
  const params = new URLSearchParams(search)
  params.delete(STATE_KEY)
  for (const s of state.stateFilter) params.append(STATE_KEY, s)
  if (state.selectedVM) {
    params.set(VM_KEY, state.selectedVM)
  } else {
    params.delete(VM_KEY)
  }
  const query = params.toString()
  return query === '' ? '' : `?${query}`
}
