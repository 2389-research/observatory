// ABOUTME: SPEC §13.7's recent-operations panel, rendered from the host's own
// ABOUTME: operation.state_changed events — not from a log of what this tab did.
import type { EventEnvelope } from '../types'
import { neutralize, age } from '../text'

/** The payload `operation.state_changed` carries (internal/store/vms.go). */
interface OperationData {
  operation_id?: string
  kind?: string
  vm_id?: string
  phase?: string
  state?: string
  attempt?: number
  error?: { cause?: string; message?: string }
}

interface Row {
  operationId: string
  data: OperationData
  event: EventEnvelope
}

/**
 * One row per operation at its latest phase.
 *
 * An operation emits an event per phase, so a page of events holds several
 * records of the same operation. Showing them all would read as several
 * operations; the last one is what is true now. Re-inserting a key moves it to
 * the end of the map, so the fold also orders operations by latest activity.
 */
export function latestPerOperation(events: EventEnvelope[]): Row[] {
  const byOperation = new Map<string, Row>()
  for (const event of events) {
    const data = event.data as OperationData
    const operationId = data.operation_id
    if (typeof operationId !== 'string' || operationId === '') continue
    byOperation.delete(operationId)
    byOperation.set(operationId, { operationId, data, event })
  }
  return [...byOperation.values()].reverse()
}

function Outcome({ data }: { data: OperationData }) {
  const state = data.state ?? 'unknown'
  return (
    <span className={`op-state op-${state}`}>
      {state}
      {data.phase && state === 'running' && <span className="op-phase"> · {neutralize(data.phase)}</span>}
    </span>
  )
}

export function RecentOperations({ events }: { events: EventEnvelope[] }) {
  const rows = latestPerOperation(events)
  if (rows.length === 0) {
    return (
      <p className="empty">
        No operations in the host&rsquo;s recent event stream. Launches from any browser appear here.
      </p>
    )
  }
  return (
    <ul className="operations">
      {rows.map(({ operationId, data, event }) => {
        // Store-synthesized events name their VM in the payload; the envelope
        // column is null for them.
        const vmID = data.vm_id ?? event.vm_id
        return (
          <li key={operationId} className="operation" data-testid={`operation-${operationId}`}>
            <div className="op-head">
              <code className="op-id">{operationId}</code>
              <span className="op-kind">{neutralize(data.kind ?? 'unknown kind')}</span>
              <Outcome data={data} />
              <span className="op-age" title={event.host_received_at}>
                {age(event.host_received_at)}
              </span>
              <span className="op-provenance">{neutralize(event.provenance)}</span>
            </div>
            {vmID && (
              <div className="op-vm">
                vm <code>{neutralize(vmID)}</code>
              </div>
            )}
            {data.error && (
              <div className="op-error">
                <code>{neutralize(data.error.cause ?? 'unknown_cause')}</code>{' '}
                {neutralize(data.error.message ?? '')}
              </div>
            )}
          </li>
        )
      })}
    </ul>
  )
}
