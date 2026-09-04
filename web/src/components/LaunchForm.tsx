// ABOUTME: SPEC §13.1 single launch: the fields POST /vms accepts, a reservation
// ABOUTME: preview built from published numbers, and a visible map of what it cannot set yet.
import { useState, type FormEvent } from 'react'
import { postJSON } from '../api'
import { clearIdempotencyKey, idempotencyKeyFor, useOperation } from '../operation'
import { reservationFor } from '../reservation'
import { blankMember, draftBody, draftResources, MemberFields, type MemberDraft } from './MemberFields'
import { DeferredFields } from './DeferredFields'
import { ReservationPreview } from './ReservationPreview'
import { OperationFailure } from './OperationFailure'
import type { HostStatus, Template, VM } from '../types'

const FORM_KEY = 'launch-vm'

interface CreateVMReply {
  vm: VM
  operation: { operation_id: string }
  is_replay?: boolean
}

interface Props {
  host: HostStatus
  templates: Template[]
  /** Called after a launch the daemon accepted, so the fleet can be re-read. */
  onLaunched: () => void
}

export function LaunchForm({ host, templates, onLaunched }: Props) {
  const [draft, setDraft] = useState<MemberDraft>(() =>
    blankMember(host.vm_defaults, templates[0]?.template_id ?? ''),
  )
  const op = useOperation<CreateVMReply>()

  const preview = reservationFor(draftResources(draft), host)

  async function submit(e: FormEvent) {
    e.preventDefault()
    // Minted here, stored, and dropped only once the daemon has accepted: a
    // resubmit after a refresh or a failure carries the same key and lands as
    // the daemon's replay instead of a second VM (SPEC §13.7).
    const idempotencyKey = idempotencyKeyFor(FORM_KEY)
    const ok = await op.run(() =>
      postJSON<CreateVMReply>('/vms', { ...draftBody(draft), idempotency_key: idempotencyKey }),
    )
    if (ok) {
      clearIdempotencyKey(FORM_KEY)
      onLaunched()
    }
  }

  const busy = op.state === 'in_flight'

  return (
    <form className="launch" onSubmit={(e) => void submit(e)} aria-labelledby="launch-heading">
      <h2 id="launch-heading">Launch a VM</h2>

      <MemberFields idPrefix="launch" draft={draft} templates={templates} onChange={setDraft} />

      <ReservationPreview reservation={preview} host={host} />

      <DeferredFields idPrefix="launch" defaults={host.vm_defaults} />

      <div className="launch-actions">
        <button type="submit" disabled={busy || templates.length === 0}>
          {busy ? 'Launching…' : 'Launch VM'}
        </button>
        {templates.length === 0 && <span className="hint">This host has no approved templates.</span>}
      </div>

      {op.state === 'done' && (
        <p className="ok" role="status" data-testid="launch-result">
          {op.result?.is_replay ? 'Replay of an earlier request — no second VM. ' : 'Launch accepted. '}
          operation <code>{op.operationId}</code>
          {op.result?.vm?.vm_id ? (
            <>
              {' '}
              · vm <code>{op.result.vm.vm_id}</code>
            </>
          ) : null}
        </p>
      )}

      <OperationFailure failure={op.state === 'failed' ? op.failure : undefined} fallback="The launch failed" />
    </form>
  )
}
