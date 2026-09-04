// ABOUTME: SPEC §13.1 single launch: the fields POST /vms accepts, a reservation
// ABOUTME: preview built from published numbers, and a visible map of what it cannot set yet.
import { useMemo, useState, type FormEvent } from 'react'
import { postJSON } from '../api'
import { clearIdempotencyKey, idempotencyKeyFor, useOperation } from '../operation'
import { reservationFor, type ReservationLine } from '../reservation'
import type { HostStatus, Template, VM, VMResources } from '../types'

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

/** A blank field means "let the host decide", which the daemon reads as zero. */
function num(text: string): number {
  const n = Number(text)
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0
}

/**
 * Parse `key=value, key=value` into the labels map.
 *
 * Segments without an `=` produce no pair. The parsed result is rendered back
 * under the field so a dropped segment is visible rather than silent.
 */
export function parseLabels(text: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const part of text.split(',')) {
    const trimmed = part.trim()
    const eq = trimmed.indexOf('=')
    if (eq <= 0) continue
    const key = trimmed.slice(0, eq).trim()
    if (key !== '') out[key] = trimmed.slice(eq + 1).trim()
  }
  return out
}

function Line({ label, line, testId }: { label: string; line: ReservationLine; testId: string }) {
  const short = line.requested - line.free
  return (
    <p className={line.over ? 'preview-line over' : 'preview-line'} data-testid={testId}>
      <span className="preview-label">{label}</span>
      <span>
        {line.requested} {line.unit} of {line.free} {line.unit} free
        {line.over ? ` — over by ${short} ${line.unit}` : ''}
      </span>
    </p>
  )
}

export function LaunchForm({ host, templates, onLaunched }: Props) {
  const def = host.vm_defaults
  const [name, setName] = useState('')
  const [templateId, setTemplateId] = useState(templates[0]?.template_id ?? '')
  const [vcpu, setVCPU] = useState(String(def.vcpu_count))
  const [memory, setMemory] = useState(String(def.memory_mib))
  const [rootDisk, setRootDisk] = useState(String(def.root_disk_mib))
  const [workspaceDisk, setWorkspaceDisk] = useState(String(def.workspace_disk_mib))
  const [labelsText, setLabelsText] = useState('')
  const op = useOperation<CreateVMReply>()

  const resources: VMResources = {
    vcpu_count: num(vcpu),
    memory_mib: num(memory),
    root_disk_mib: num(rootDisk),
    workspace_disk_mib: num(workspaceDisk),
  }
  const preview = reservationFor(resources, host)
  const labels = useMemo(() => parseLabels(labelsText), [labelsText])

  async function submit(e: FormEvent) {
    e.preventDefault()
    // Minted here, stored, and dropped only once the daemon has accepted: a
    // resubmit after a refresh or a failure carries the same key and lands as
    // the daemon's replay instead of a second VM (SPEC §13.7).
    const idempotencyKey = idempotencyKeyFor(FORM_KEY)
    const ok = await op.run(() =>
      postJSON<CreateVMReply>('/vms', {
        name,
        template_id: templateId,
        idempotency_key: idempotencyKey,
        vcpu_count: resources.vcpu_count,
        memory_mib: resources.memory_mib,
        root_disk_mib: resources.root_disk_mib,
        workspace_disk_mib: resources.workspace_disk_mib,
        labels,
      }),
    )
    if (ok) {
      clearIdempotencyKey(FORM_KEY)
      onLaunched()
    }
  }

  const busy = op.state === 'in_flight'
  const failure = op.state === 'failed' ? op.failure : undefined

  return (
    <form className="launch" onSubmit={(e) => void submit(e)} aria-labelledby="launch-heading">
      <h2 id="launch-heading">Launch a VM</h2>

      <div className="launch-fields">
        <p className="field">
          <label htmlFor="launch-name">Name</label>
          <input
            id="launch-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="worker-1"
            autoComplete="off"
          />
        </p>
        <p className="field">
          <label htmlFor="launch-template">Template</label>
          <select id="launch-template" value={templateId} onChange={(e) => setTemplateId(e.target.value)}>
            {templates.map((t) => (
              <option key={t.template_id} value={t.template_id}>
                {t.template_id}
              </option>
            ))}
          </select>
        </p>
        <p className="field">
          <label htmlFor="launch-vcpu">vCPU count</label>
          <input id="launch-vcpu" type="number" min="1" value={vcpu} onChange={(e) => setVCPU(e.target.value)} />
        </p>
        <p className="field">
          <label htmlFor="launch-memory">Memory (MiB)</label>
          <input id="launch-memory" type="number" min="1" value={memory} onChange={(e) => setMemory(e.target.value)} />
        </p>
        <p className="field">
          <label htmlFor="launch-root">Root disk (MiB)</label>
          <input id="launch-root" type="number" min="1" value={rootDisk} onChange={(e) => setRootDisk(e.target.value)} />
        </p>
        <p className="field">
          <label htmlFor="launch-workspace">Workspace disk (MiB)</label>
          <input
            id="launch-workspace"
            type="number"
            min="0"
            value={workspaceDisk}
            onChange={(e) => setWorkspaceDisk(e.target.value)}
          />
        </p>
        <p className="field field-wide">
          <label htmlFor="launch-labels">Labels</label>
          <input
            id="launch-labels"
            value={labelsText}
            onChange={(e) => setLabelsText(e.target.value)}
            placeholder="team=infra, run=nightly"
            autoComplete="off"
          />
          <span className="hint" data-testid="parsed-labels">
            {Object.keys(labels).length === 0
              ? 'key=value, comma separated'
              : Object.entries(labels)
                  .map(([k, v]) => `${k}=${v}`)
                  .join(' · ')}
          </span>
        </p>
      </div>

      <div className="preview">
        <h3>Reservation preview</h3>
        <Line label="Memory" line={preview.memory} testId="preview-memory" />
        <Line label="vCPU" line={preview.vcpu} testId="preview-vcpu" />
        <Line label="Disk" line={preview.disk} testId="preview-disk" />
        <p className="hint">
          Memory includes the host&apos;s published per-VM overhead of {host.admission.reserve_per_vm_host_overhead_mib}{' '}
          MiB. Admission is the daemon&apos;s decision; this is only what it would be asked for.
        </p>
      </div>

      <fieldset className="deferred" data-testid="deferred-fields">
        <legend>Set by the host, not by this form</legend>
        <p className="field">
          <label htmlFor="launch-privilege">Guest privilege</label>
          <input id="launch-privilege" value={def.guest_privilege} disabled readOnly />
          <span className="hint">Host default. The API accepts no per-VM override yet.</span>
        </p>
        <p className="field">
          <label htmlFor="launch-network-profile">Network profile</label>
          <input id="launch-network-profile" value={def.network_profile} disabled readOnly />
          <span className="hint">Host default — selectable in M2, when network profiles exist.</span>
        </p>
        <p className="field">
          <label htmlFor="launch-network-policy">Network policy</label>
          <input id="launch-network-policy" value={def.network_policy_id} disabled readOnly />
          <span className="hint">Empty on this host — M2.</span>
        </p>
        <p className="field">
          <label htmlFor="launch-seed">Workspace seed</label>
          <input id="launch-seed" value="" disabled readOnly />
          <span className="hint">Not accepted by the API — M4.</span>
        </p>
        <p className="field">
          <label htmlFor="launch-exec">Initial command</label>
          <input id="launch-exec" value="" disabled readOnly />
          <span className="hint">Not accepted by the API — M4.</span>
        </p>
        <p className="field">
          <label htmlFor="launch-capture">Capture policy</label>
          <input id="launch-capture" value="" disabled readOnly />
          <span className="hint">Not accepted by the API — M3.</span>
        </p>
      </fieldset>

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

      {failure && (
        <div className="alert" role="alert">
          <strong>{failure.error?.message ?? `The launch failed (HTTP ${failure.status}).`}</strong>
          {failure.error?.cause && <code>{failure.error.cause}</code>}
          {failure.error?.remediation && failure.error.remediation.length > 0 && (
            <ul className="remediation-list">
              {failure.error.remediation.map((r) => (
                <li key={r.action}>
                  <code>{r.action}</code> {r.rationale}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </form>
  )
}
