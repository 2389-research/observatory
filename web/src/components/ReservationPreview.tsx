// ABOUTME: Renders what a request would ask the host for, against the host's published free capacity.
// ABOUTME: Every number here came from GET /host/status; this component computes no capacity of its own.
import type { Reservation, ReservationLine } from '../reservation'
import type { HostStatus } from '../types'

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

interface Props {
  reservation: Reservation
  host: HostStatus
  /** Prefixes the test ids so a page showing two previews keeps them apart. */
  idPrefix?: string
  /** Named when the preview covers more than one VM, so the multiplier is visible. */
  count?: number
}

export function ReservationPreview({ reservation, host, idPrefix = 'preview', count }: Props) {
  return (
    <div className="preview">
      <h3>Reservation preview{count !== undefined ? ` — ${count} VM${count === 1 ? '' : 's'}` : ''}</h3>
      <Line label="Memory" line={reservation.memory} testId={`${idPrefix}-memory`} />
      <Line label="vCPU" line={reservation.vcpu} testId={`${idPrefix}-vcpu`} />
      <Line label="Disk" line={reservation.disk} testId={`${idPrefix}-disk`} />
      <p className="hint">
        Memory includes the host&apos;s published per-VM overhead of {host.admission.reserve_per_vm_host_overhead_mib}{' '}
        MiB. Admission is the daemon&apos;s decision; this is only what it would be asked for.
      </p>
    </div>
  )
}
