// ABOUTME: SPEC §13.1 batch launch: one editor per member, a summed reservation preview, honest rollup.
// ABOUTME: "Do not make a batch look successful because its first member started" is the rule this obeys.
import { useEffect, useState, type FormEvent } from 'react'
import { getJSON, postJSON, ApiFailure } from '../api'
import { clearIdempotencyKey, idempotencyKeyFor, useOperation } from '../operation'
import { reservationForAll } from '../reservation'
import { everyMemberTerminal } from '../batch'
import { blankMember, draftBody, draftResources, MemberFields, type MemberDraft } from './MemberFields'
import { ReservationPreview } from './ReservationPreview'
import { OperationFailure } from './OperationFailure'
import { BatchProgress } from './BatchProgress'
import type { BatchReply, HostStatus, Template } from '../types'

const FORM_KEY = 'launch-batch'
const POLL_MS = 2000

interface Props {
  host: HostStatus
  templates: Template[]
  /** Called once the daemon has accepted the batch, so the fleet can be re-read. */
  onLaunched: () => void
}

export function LaunchBatch({ host, templates, onLaunched }: Props) {
  const firstTemplate = templates[0]?.template_id ?? ''
  const [members, setMembers] = useState<MemberDraft[]>(() => [
    blankMember(host.vm_defaults, firstTemplate),
    blankMember(host.vm_defaults, firstTemplate),
  ])
  // No pre-selection: POST /vm-batches requires an explicit reservation_mode
  // and neither SPEC §6.3 nor GET /meta publishes a default to borrow.
  const [reservationMode, setReservationMode] = useState('')
  // on_failure does have a published default, and the API applies it.
  const [onFailure, setOnFailure] = useState('keep_successful')
  const op = useOperation<BatchReply>()
  const [live, setLive] = useState<BatchReply | null>(null)
  const [pollError, setPollError] = useState<string | undefined>()

  const cap = host.admission.max_batch_size
  const overCap = members.length > cap
  const preview = reservationForAll(members.map(draftResources), host)

  const batchId = live?.batch.batch_id
  const settled = live ? everyMemberTerminal(live.members) : false

  // Re-read the batch until every member is terminal, then stop. A batch is
  // not finished because its first member is: §13.1.
  useEffect(() => {
    if (!batchId || settled) return
    let cancelled = false
    const timer = setInterval(() => {
      void (async () => {
        try {
          const next = await getJSON<BatchReply>(`/vm-batches/${batchId}`)
          if (cancelled) return
          setLive(next)
          setPollError(undefined)
        } catch (e) {
          if (cancelled) return
          // A failed poll is not a verdict. Keep the last snapshot and say so.
          const failure = e instanceof ApiFailure ? e : undefined
          setPollError(failure?.error?.message ?? 'The host did not answer the last re-read.')
        }
      })()
    }, POLL_MS)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [batchId, settled])

  function updateMember(index: number, next: MemberDraft) {
    setMembers((prev) => prev.map((m, i) => (i === index ? next : m)))
  }

  async function submit(e: FormEvent) {
    e.preventDefault()
    if (reservationMode === '' || overCap) return
    // Same rule as the single launch: the key survives a failure so a retry is
    // the daemon's replay, and is dropped only once the batch is accepted.
    const idempotencyKey = idempotencyKeyFor(FORM_KEY)
    const ok = await op.run(() =>
      postJSON<BatchReply>('/vm-batches', {
        members: members.map(draftBody),
        reservation_mode: reservationMode,
        on_failure: onFailure,
        idempotency_key: idempotencyKey,
      }),
    )
    if (ok) {
      clearIdempotencyKey(FORM_KEY)
      onLaunched()
    }
  }

  // The POST reply is the first snapshot; every later one comes from a poll.
  useEffect(() => {
    if (op.state === 'done' && op.result) setLive(op.result)
  }, [op.state, op.result])

  const busy = op.state === 'in_flight'
  const canSubmit = !busy && !overCap && reservationMode !== '' && templates.length > 0 && members.length > 0

  return (
    <form className="launch" onSubmit={(e) => void submit(e)} aria-labelledby="batch-heading">
      <h2 id="batch-heading">Launch a batch</h2>

      <div className="batch-modes">
        <p className="field">
          <label htmlFor="batch-reservation-mode">Reservation mode</label>
          <select
            id="batch-reservation-mode"
            value={reservationMode}
            onChange={(e) => setReservationMode(e.target.value)}
          >
            <option value="">Choose…</option>
            <option value="atomic_reservation">atomic_reservation — all members admitted, or none</option>
            <option value="best_effort">best_effort — admit what fits, refuse the rest</option>
          </select>
          <span className="hint">The API has no default; the request must say which.</span>
        </p>
        <p className="field">
          <label htmlFor="batch-on-failure">On failure</label>
          <select id="batch-on-failure" value={onFailure} onChange={(e) => setOnFailure(e.target.value)}>
            <option value="keep_successful">keep_successful — members that launched stay up</option>
            <option value="stop_successful">stop_successful — stop members that already launched</option>
          </select>
          <span className="hint">Defaults to keep_successful, the default the API itself applies.</span>
        </p>
      </div>

      {members.map((m, i) => (
        <fieldset className="batch-member" key={i}>
          <legend>Member {i + 1}</legend>
          <MemberFields
            idPrefix={`batch-${i}`}
            draft={m}
            templates={templates}
            onChange={(next) => updateMember(i, next)}
          />
          <button
            type="button"
            className="link-button"
            onClick={() => setMembers((prev) => prev.filter((_, j) => j !== i))}
            disabled={members.length <= 1}
          >
            Remove member {i + 1}
          </button>
        </fieldset>
      ))}

      <div className="launch-actions">
        <button
          type="button"
          onClick={() => setMembers((prev) => [...prev, blankMember(host.vm_defaults, firstTemplate)])}
        >
          Add member
        </button>
      </div>

      {overCap && (
        <p className="alert" role="alert" data-testid="batch-size-warning">
          This batch has {members.length} members and the host publishes a limit of {cap} per request. The daemon would
          refuse it with <code>batch_too_large</code>.
        </p>
      )}

      <ReservationPreview reservation={preview} host={host} idPrefix="batch-preview" count={members.length} />

      <div className="launch-actions">
        <button type="submit" disabled={!canSubmit}>
          {busy ? 'Launching…' : 'Launch batch'}
        </button>
        {reservationMode === '' && <span className="hint">Choose a reservation mode first.</span>}
        {templates.length === 0 && <span className="hint">This host has no approved templates.</span>}
      </div>

      <OperationFailure failure={op.state === 'failed' ? op.failure : undefined} fallback="The batch was refused" />

      {live && <BatchProgress reply={live} polling={!settled} pollError={pollError} />}
    </form>
  )
}
