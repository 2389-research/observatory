// ABOUTME: The fleet page (SPEC §13.1): host capacity, attention head, VM table.
// ABOUTME: Every panel comes from one poll of the API; nothing here derives numbers of its own.
import { useCallback, useEffect, useState } from 'react'
import { getJSON, ApiFailure } from './api'
import type { AttentionList, EventEnvelope, EventPage, HostStatus, TemplateList, VMList } from './types'
import { readState, writeState, type FleetState } from './url'
import { HostCapacity } from './components/HostCapacity'
import { LaunchForm } from './components/LaunchForm'
import { LaunchBatch } from './components/LaunchBatch'
import { AttentionQueue } from './components/AttentionQueue'
import { RecentOperations } from './components/RecentOperations'
import { VMTable } from './components/VMTable'
import { BulkActions, useFleetControls } from './components/BulkActions'

const REFRESH_MS = 5000

/**
 * SPEC §5.2's lifecycle states, in the order a VM walks them. Mirrored from
 * validTransitions in internal/store/vms.go; `?state=` takes these verbatim.
 */
const LIFECYCLE_STATES = [
  'provisioning',
  'starting',
  'running',
  'paused',
  'stopping',
  'stopped',
  'failed',
  'deleting',
  'deleted',
] as const

/**
 * The newest operations, not the oldest: without `tail=true` a bounded page of
 * an ascending stream is the first twenty operations this host ever ran.
 */
const OPERATIONS_QUERY = '/events?kind=operation.state_changed&tail=true&limit=20'

interface Fleet {
  host: HostStatus
  vms: VMList
  attention: AttentionList
  templates: TemplateList
  operations: EventEnvelope[]
}

/**
 * `states` is the comma-joined filter rather than an array because a fresh
 * array on every render would rebuild the poll on every render.
 */
function vmsQuery(states: string): string {
  const params = new URLSearchParams({ limit: '100' })
  for (const state of states.split(',').filter((s) => s !== '')) params.append('state', state)
  return `/vms?${params.toString()}`
}

export function App() {
  const [fleet, setFleet] = useState<Fleet | null>(null)
  const [failure, setFailure] = useState<ApiFailure | null>(null)
  const [asOf, setAsOf] = useState<Date | null>(null)
  // The view state arrives from the URL, so a reload and a pasted link land on
  // the same view (SPEC §13.7).
  const [view, setView] = useState<FleetState>(() => readState(window.location.search))

  const stateFilterKey = view.stateFilter.join(',')

  const load = useCallback(async () => {
    try {
      const [host, vms, attention, templates, operations] = await Promise.all([
        getJSON<HostStatus>('/host/status'),
        getJSON<VMList>(vmsQuery(stateFilterKey)),
        getJSON<AttentionList>('/attention?limit=10'),
        getJSON<TemplateList>('/templates'),
        getJSON<EventPage>(OPERATIONS_QUERY),
      ])
      setFleet({ host, vms, attention, templates, operations: operations.events })
      setFailure(null)
      setAsOf(new Date())
    } catch (e) {
      // Keep the last good fleet on screen; the banner says it is stale.
      setFailure(e instanceof ApiFailure ? e : new ApiFailure(0))
    }
  }, [stateFilterKey])

  // Lifecycle actions re-read the fleet the moment they settle, so a row's
  // outcome and the table under it never disagree for a whole poll interval.
  const controls = useFleetControls(() => void load())

  useEffect(() => {
    void load()
    const t = setInterval(() => void load(), REFRESH_MS)
    return () => clearInterval(t)
  }, [load])

  // Only the two keys url.ts owns are written, and only from `view`. No
  // credential has a path into the address bar through here.
  useEffect(() => {
    const search = writeState(view, window.location.search)
    window.history.replaceState(null, '', window.location.pathname + search + window.location.hash)
  }, [view])

  const toggleStateFilter = (state: string) =>
    setView((v) => ({
      ...v,
      stateFilter: v.stateFilter.includes(state)
        ? v.stateFilter.filter((s) => s !== state)
        : [...v.stateFilter, state],
    }))

  const selectVM = (vmID: string) =>
    setView((v) => ({ ...v, selectedVM: v.selectedVM === vmID ? undefined : vmID }))

  if (failure?.status === 401) {
    return (
      <main className="page">
        <h1>Firecracker Observatory</h1>
        <p className="alert" role="alert">
          Sign in to view this host. This page carries no credentials of its own.
        </p>
      </main>
    )
  }

  return (
    <main className="page">
      <header className="page-head">
        <h1>Firecracker Observatory</h1>
        <span className="as-of" data-testid="as-of">
          {asOf ? `read ${asOf.toLocaleTimeString()}` : 'reading…'}
        </span>
      </header>

      {failure && (
        <p className="alert" role="alert">
          <strong>{failure.error?.message ?? 'The host did not answer.'}</strong>{' '}
          {failure.error?.cause && <code>{failure.error.cause}</code>}
          {failure.error?.remediation?.map((r) => (
            <span className="remediation" key={r.action}>
              {r.action}: {r.rationale}
            </span>
          ))}
        </p>
      )}

      {!fleet ? (
        <p className="empty">Reading the host…</p>
      ) : (
        <>
          <HostCapacity status={fleet.host} />
          <section>
            <h2>Attention</h2>
            <AttentionQueue items={fleet.attention.items} />
          </section>
          <section>
            <LaunchForm host={fleet.host} templates={fleet.templates.templates} onLaunched={() => void load()} />
          </section>
          <section>
            {/* Collapsed by default: the batch form is long, and one VM is the
                common case. <details> keeps it keyboard-reachable with no state. */}
            <details className="batch-details">
              <summary>Launch a batch</summary>
              <LaunchBatch host={fleet.host} templates={fleet.templates.templates} onLaunched={() => void load()} />
            </details>
          </section>
          <section>
            <h2>VMs</h2>
            <fieldset className="filter">
              <legend>Lifecycle filter</legend>
              {LIFECYCLE_STATES.map((state) => (
                <label className="filter-option" key={state}>
                  <input
                    type="checkbox"
                    checked={view.stateFilter.includes(state)}
                    onChange={() => toggleStateFilter(state)}
                  />
                  {state}
                </label>
              ))}
            </fieldset>
            <BulkActions vms={fleet.vms.vms} controls={controls} />
            <VMTable
              vms={fleet.vms.vms}
              controls={controls}
              filtered={view.stateFilter.length > 0}
              selectedVM={view.selectedVM}
              onSelectVM={selectVM}
            />
          </section>
          <section>
            <h2>Recent operations</h2>
            <RecentOperations events={fleet.operations} />
          </section>
        </>
      )}
    </main>
  )
}
