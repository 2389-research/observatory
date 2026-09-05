// ABOUTME: The fleet's lifecycle controls, and the confirm gesture that is the only path to DELETE.
// ABOUTME: SPEC §13.1: one request per VM, and a fan-out never looks successful because its first did.
import { useCallback, useState } from 'react'
import { ApiFailure, deleteJSON, getJSON, postJSON } from '../api'
import { neutralize } from '../text'
import type { VM } from '../types'

/** Actions POST /vms/{id}/actions accepts (validActions, internal/runtime/manager.go). Delete is not one. */
export type LifecycleAction = 'start' | 'pause' | 'resume' | 'stop' | 'force_stop'

/** Every action a row offers, in the order the buttons appear. */
export type RowAction = LifecycleAction | 'delete'

/** What the fleet bar and each fleet row offer (§13.1), in button order. */
export const ROW_ACTIONS: readonly RowAction[] = ['start', 'pause', 'resume', 'stop', 'delete']

/**
 * States a delete must force its way out of (internal/runtime/manager.go).
 * Anything else is already cold, and forcing it would claim work that is not
 * happening.
 */
const LIVE_STATES = new Set(['provisioning', 'starting', 'running', 'paused', 'stopping'])

/** How many requests the browser keeps open at once. There is no bulk endpoint. */
export const FAN_OUT_LIMIT = 4

/**
 * Whether `action` is legal for this VM right now, and why not when it isn't.
 *
 * These are the daemon's own preconditions (internal/runtime/manager.go's
 * Action and Delete). Restating them lets a row disable what it cannot do
 * instead of sending a request the host will refuse — but the host stays the
 * decider: a row that looks legal here can still come back 409.
 */
export function actionLegality(vm: VM, action: RowAction): { allowed: boolean; reason: string } {
  const state = vm.observed_state
  const no = (want: string) => ({ allowed: false, reason: `needs a ${want} VM; this one is ${state}` })
  switch (action) {
    case 'start':
      return state === 'stopped' ? { allowed: true, reason: '' } : no('stopped')
    case 'pause':
      return state === 'running' ? { allowed: true, reason: '' } : no('running')
    case 'resume':
      return state === 'paused' ? { allowed: true, reason: '' } : no('paused')
    // One rule for both: the daemon accepts either from running, paused or
    // stopping. They differ in what they do to the guest, not in where they are
    // legal.
    case 'stop':
    case 'force_stop':
      return state === 'running' || state === 'paused' || state === 'stopping'
        ? { allowed: true, reason: '' }
        : no('running, paused or stopping')
    case 'delete':
      if (state === 'deleted') return { allowed: false, reason: `this VM is already ${state}` }
      if (state === 'deleting') return { allowed: false, reason: `a delete is already running on this VM` }
      return { allowed: true, reason: '' }
  }
}

/**
 * Run `fn` over `items`, at most `limit` at a time, and resolve when all are
 * done. A rejection is not allowed to strand the items behind it: each worker
 * swallows its own so the pool drains.
 */
export async function runBounded<T>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<void>,
): Promise<void> {
  let next = 0
  const worker = async () => {
    for (;;) {
      const i = next++
      const item = items[i]
      if (item === undefined) return
      try {
        await fn(item)
      } catch {
        // fn records its own outcome; a throw here would abandon the queue.
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker))
}

/** What happened to one VM in the last fan-out. */
export interface VMActionResult {
  action: RowAction
  state: 'in_flight' | 'succeeded' | 'failed' | 'refused'
  /** Present for actions; DELETE answers with a VM and no operation. */
  operationId?: string
  /** The state the daemon reported back, so the row shows its own outcome. */
  observedState?: string
  /** Why this row was never asked — a state the action is illegal for. */
  reason?: string
  failure?: ApiFailure
  /** Set only after a retryable conflict was re-read: the revision to retry with. */
  retryVM?: VM
  /** Whether the delete carried force=true. */
  forced?: boolean
}

export interface FleetControls {
  selected: ReadonlySet<string>
  toggle: (vmId: string) => void
  toggleAll: (vms: VM[]) => void
  results: Record<string, VMActionResult>
  /** Fan an action out over `vms`, skipping the rows whose state forbids it. */
  run: (vms: VM[], action: LifecycleAction) => Promise<void>
  /** Re-submit one row's last action with the revision its re-read produced. */
  retry: (vmId: string) => Promise<void>
  /** VMs a delete has been asked for and not yet confirmed. */
  pendingDelete: VM[]
  askDelete: (vms: VM[]) => void
  cancelDelete: () => void
  confirmDelete: () => Promise<void>
  busy: boolean
}

interface ActionReply {
  vm: VM
  operation: { operation_id: string }
}

/**
 * The state behind every lifecycle control on the fleet page.
 *
 * One store of per-VM results, one fan-out runner, and a delete that can only
 * be issued through the confirm gesture: `confirmDelete` is the sole caller of
 * DELETE, so `force=true` has no path to the wire that skips the dialog.
 */
export function useFleetControls(onSettled: () => void): FleetControls {
  const [selected, setSelected] = useState<ReadonlySet<string>>(() => new Set())
  const [results, setResults] = useState<Record<string, VMActionResult>>({})
  const [pendingDelete, setPendingDelete] = useState<VM[]>([])
  const [busy, setBusy] = useState(false)

  const toggle = useCallback((vmId: string) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (!next.delete(vmId)) next.add(vmId)
      return next
    })
  }, [])

  const toggleAll = useCallback((vms: VM[]) => {
    setSelected((prev) => {
      const all = vms.every((vm) => prev.has(vm.vm_id)) && vms.length > 0
      const next = new Set(prev)
      for (const vm of vms) {
        if (all) next.delete(vm.vm_id)
        else next.add(vm.vm_id)
      }
      return next
    })
  }, [])

  const put = useCallback((vmId: string, r: VMActionResult) => {
    setResults((prev) => ({ ...prev, [vmId]: r }))
  }, [])

  // A conflict is re-read rather than retried from details.current_revision:
  // the VM's state may have moved too, and a retry into a state that now
  // forbids the action would fail the same way with a fresher number.
  const afterFailure = useCallback(
    async (vm: VM, base: VMActionResult, e: unknown): Promise<VMActionResult> => {
      const failure = e instanceof ApiFailure ? e : new ApiFailure(0)
      const r: VMActionResult = { ...base, state: 'failed', failure }
      if (failure.status !== 409 || !failure.error?.retryable) return r
      try {
        r.retryVM = await getJSON<VM>(`/vms/${vm.vm_id}`)
      } catch {
        // The conflict still shows; there is just nothing honest to retry with.
      }
      return r
    },
    [],
  )

  const submit = useCallback(
    async (vm: VM, action: LifecycleAction) => {
      put(vm.vm_id, { action, state: 'in_flight' })
      try {
        const reply = await postJSON<ActionReply>(`/vms/${vm.vm_id}/actions`, {
          action,
          expected_revision: vm.revision,
        })
        put(vm.vm_id, {
          action,
          state: 'succeeded',
          operationId: reply?.operation?.operation_id,
          observedState: reply?.vm?.observed_state,
        })
      } catch (e) {
        put(vm.vm_id, await afterFailure(vm, { action, state: 'failed' }, e))
      }
    },
    [put, afterFailure],
  )

  const destroy = useCallback(
    async (vm: VM) => {
      const forced = LIVE_STATES.has(vm.observed_state)
      put(vm.vm_id, { action: 'delete', state: 'in_flight', forced })
      const query = `?expected_revision=${encodeURIComponent(vm.revision)}${forced ? '&force=true' : ''}`
      try {
        const reply = await deleteJSON<{ vm: VM }>(`/vms/${vm.vm_id}${query}`)
        put(vm.vm_id, {
          action: 'delete',
          state: 'succeeded',
          forced,
          observedState: reply?.vm?.observed_state,
        })
      } catch (e) {
        put(vm.vm_id, await afterFailure(vm, { action: 'delete', state: 'failed', forced }, e))
      }
    },
    [put, afterFailure],
  )

  /** Split into the rows that permit `action` and the rows that do not. */
  const fanOut = useCallback(
    async (vms: VM[], action: RowAction, send: (vm: VM) => Promise<void>) => {
      const permitted: VM[] = []
      for (const vm of vms) {
        const { allowed, reason } = actionLegality(vm, action)
        if (allowed) permitted.push(vm)
        else put(vm.vm_id, { action, state: 'refused', reason })
      }
      setBusy(true)
      try {
        await runBounded(permitted, FAN_OUT_LIMIT, send)
      } finally {
        setBusy(false)
      }
      onSettled()
    },
    [put, onSettled],
  )

  const run = useCallback(
    (vms: VM[], action: LifecycleAction) => fanOut(vms, action, (vm) => submit(vm, action)),
    [fanOut, submit],
  )

  const retry = useCallback(
    async (vmId: string) => {
      const prior = results[vmId]
      const fresh = prior?.retryVM
      if (!prior || !fresh) return
      if (prior.action === 'delete') await destroy(fresh)
      else await submit(fresh, prior.action)
      onSettled()
    },
    [results, submit, destroy, onSettled],
  )

  const askDelete = useCallback((vms: VM[]) => setPendingDelete(vms), [])
  const cancelDelete = useCallback(() => setPendingDelete([]), [])
  const confirmDelete = useCallback(async () => {
    const targets = pendingDelete
    setPendingDelete([])
    await fanOut(targets, 'delete', destroy)
  }, [pendingDelete, fanOut, destroy])

  return {
    selected,
    toggle,
    toggleAll,
    results,
    run,
    retry,
    pendingDelete,
    askDelete,
    cancelDelete,
    confirmDelete,
    busy,
  }
}

export const ACTION_LABEL: Record<RowAction, string> = {
  start: 'Start',
  pause: 'Pause',
  resume: 'Resume',
  stop: 'Stop',
  force_stop: 'Force stop',
  delete: 'Delete',
}

/**
 * The confirm gesture behind every Delete button, wherever one is drawn.
 *
 * It is its own component because three surfaces offer Delete — the fleet bar,
 * the fleet table's rows and the detail workspace — and the prompt and the
 * request are one unit: `confirmDelete` is the sole caller of DELETE, so
 * `force=true` has no path to the wire that skips this prompt. A surface that
 * drew a Delete button without rendering this one would ask and never send.
 */
export function DeleteConfirm({ controls }: { controls: FleetControls }) {
  const { pendingDelete } = controls
  if (pendingDelete.length === 0) return null
  const forceTargets = pendingDelete.filter((vm) => LIVE_STATES.has(vm.observed_state))
  return (
    <div className="delete-confirm" role="alertdialog" aria-label="Confirm delete" data-testid="delete-confirm">
      <p>
        Delete {pendingDelete.length === 1 ? 'this VM' : `these ${pendingDelete.length} VMs`}? A deleted VM and its
        workspace do not come back.
      </p>
      <p className="delete-names">{pendingDelete.map((vm) => neutralize(vm.name)).join(', ')}</p>
      {forceTargets.length > 0 && (
        <p className="delete-force">
          These are still live, so their delete carries <code>force=true</code> — the host stops them first, with no
          chance for the guest to shut down cleanly:{' '}
          <strong data-testid="force-targets">{forceTargets.map((vm) => neutralize(vm.name)).join(', ')}</strong>
        </p>
      )}
      <div className="delete-actions">
        <button type="button" onClick={() => void controls.confirmDelete()}>
          Delete {pendingDelete.length} {pendingDelete.length === 1 ? 'VM' : 'VMs'}
        </button>
        <button type="button" onClick={controls.cancelDelete}>
          Cancel
        </button>
      </div>
    </div>
  )
}

interface Props {
  vms: VM[]
  controls: FleetControls
}

/**
 * The bar above the fleet table: how many rows are selected, and what can be
 * done to them. An action no selected row permits is disabled here rather than
 * sent and refused.
 */
export function BulkActions({ vms, controls }: Props) {
  const chosen = vms.filter((vm) => controls.selected.has(vm.vm_id))
  const allSelected = vms.length > 0 && chosen.length === vms.length

  return (
    <section className="bulk" aria-labelledby="bulk-heading">
      <h2 id="bulk-heading" className="sr-only">
        Fleet actions
      </h2>
      <div className="bulk-bar">
        <label className="bulk-all">
          <input
            type="checkbox"
            checked={allSelected}
            onChange={() => controls.toggleAll(vms)}
            aria-label="Select all VMs"
          />
          <span data-testid="selection-count">
            {chosen.length} of {vms.length} selected
          </span>
        </label>
        <div className="bulk-buttons" data-testid="bulk-actions">
          {ROW_ACTIONS.map((action) => {
            const usable = chosen.filter((vm) => actionLegality(vm, action).allowed)
            return (
              <button
                key={action}
                type="button"
                disabled={usable.length === 0 || controls.busy}
                onClick={() => {
                  if (action === 'delete') controls.askDelete(chosen)
                  else void controls.run(chosen, action)
                }}
              >
                {ACTION_LABEL[action]}
                {chosen.length > 0 && usable.length < chosen.length ? ` (${usable.length})` : ''}
              </button>
            )
          })}
        </div>
      </div>

      <DeleteConfirm controls={controls} />
    </section>
  )
}

/** The action buttons and the last outcome for one row. */
export function RowActions({ vm, controls }: { vm: VM; controls: FleetControls }) {
  return (
    <>
      {ROW_ACTIONS.map((action) => {
        const { allowed, reason } = actionLegality(vm, action)
        return (
          <button
            key={action}
            type="button"
            className="row-action"
            disabled={!allowed || controls.busy}
            title={allowed ? undefined : reason}
            aria-label={allowed ? undefined : `${ACTION_LABEL[action]} ${reason}`}
            onClick={() => {
              if (action === 'delete') controls.askDelete([vm])
              else void controls.run([vm], action)
            }}
          >
            {ACTION_LABEL[action]}
          </button>
        )
      })}
    </>
  )
}

/** One row's outcome: its own operation id, its own refusal, its own conflict. */
export function RowResult({ vm, controls }: { vm: VM; controls: FleetControls }) {
  const result = controls.results[vm.vm_id]
  if (!result) return null
  const { failure } = result
  return (
    <div className="vm-result" data-testid="vm-result">
      <span className={`result-state result-${result.state}`}>
        {ACTION_LABEL[result.action]} {result.state === 'in_flight' ? 'in progress' : result.state}
      </span>
      {result.operationId && (
        <span className="result-op">
          operation <code>{result.operationId}</code>
        </span>
      )}
      {result.observedState && <span className="result-observed">now {result.observedState}</span>}
      {result.reason && <span className="result-reason">{result.reason}</span>}
      {failure && (
        <span className="result-error">
          {neutralize(failure.error?.message ?? 'the host did not answer')}{' '}
          {failure.error?.cause && <code>{failure.error.cause}</code>}
        </span>
      )}
      {result.retryVM && (
        <button type="button" className="link-button" onClick={() => void controls.retry(vm.vm_id)}>
          Retry at revision {result.retryVM.revision}
        </button>
      )}
    </div>
  )
}
