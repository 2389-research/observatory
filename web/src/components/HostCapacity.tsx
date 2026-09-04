// ABOUTME: Host capacity, reservations and runtime health — the top of SPEC §13.1's fleet view.
// ABOUTME: Reservations are a ledger the host keeps, so these numbers are real; usage is not shown.
import type { HostStatus } from '../types'

function Meter({
  label,
  reserved,
  usable,
  free,
  unit,
}: {
  label: string
  reserved: number
  usable: number
  free: number
  unit: string
}) {
  const pct = usable > 0 ? Math.min(100, (reserved / usable) * 100) : 0
  return (
    <div className="meter">
      <div className="meter-head">
        <span className="meter-label">{label}</span>
        <span className="meter-value">
          {reserved} / {usable} {unit}
        </span>
      </div>
      <div className="bar" role="presentation">
        <div className="bar-fill" style={{ width: `${pct}%` }} />
      </div>
      <div className="meter-foot">
        {free} {unit} free
      </div>
    </div>
  )
}

export function HostCapacity({ status }: { status: HostStatus }) {
  const c = status.capacity
  const states = Object.entries(status.vms).sort(([a], [b]) => a.localeCompare(b))
  return (
    <section className="host">
      {!status.runtime.available && (
        <div className="alert" role="alert">
          <strong>Runtime unavailable.</strong> {status.runtime.reason || 'no reason reported'}
        </div>
      )}

      <div className="meters">
        <Meter
          label="Memory"
          reserved={c.reserved_memory_mib}
          usable={c.usable_memory_mib}
          free={c.free_memory_mib}
          unit="MiB"
        />
        <Meter
          label="vCPU"
          reserved={c.reserved_vcpu}
          usable={c.usable_vcpu}
          free={c.free_vcpu}
          unit="vCPU"
        />
        <Meter
          label="Disk"
          reserved={c.reserved_disk_mib}
          usable={c.usable_disk_mib}
          free={c.free_disk_mib}
          unit="MiB"
        />
      </div>

      <div className="states">
        {states.length === 0 ? (
          <span className="empty">No VMs on this host.</span>
        ) : (
          states.map(([state, count]) => (
            <span className="chip" key={state}>
              <span className={`state state-${state}`}>{state}</span>
              <span className="chip-count">{count}</span>
            </span>
          ))
        )}
      </div>
    </section>
  )
}
