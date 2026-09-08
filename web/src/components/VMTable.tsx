// ABOUTME: The fleet VM table — SPEC §13.1's columns, with the unmeasured ones saying so.
// ABOUTME: Reads only what the API actually reports; never derives a number it wasn't given.
import type { VM } from '../types'
import { neutralize, age } from '../text'
import { CaptureSummary } from './CaptureSummary'
import { RowActions, RowResult, type FleetControls } from './BulkActions'

/**
 * A column SPEC §13.1 asks for that no emitter feeds in this build. Showing 0%
 * here would read as a measurement, and a wrong measurement is worse than a gap.
 * Usage is the last of these: telemetry health is measured from the guest's
 * heartbeat and reports a real state.
 */
function NotMeasured() {
  return (
    <span className="unknown" title="no sensor feeds this column in this build">
      not measured
    </span>
  )
}

function Lifecycle({ vm }: { vm: VM }) {
  return (
    <>
      <span className={`state state-${vm.observed_state}`}>{vm.observed_state}</span>
      {vm.desired_state !== vm.observed_state && (
        <span className="drift">want {vm.desired_state}</span>
      )}
      {vm.failure && (
        <div className="failure">
          {vm.failure.stage}: {neutralize(vm.failure.reason)}
        </div>
      )}
    </>
  )
}

function Labels({ labels }: { labels: Record<string, string> | null }) {
  const entries = Object.entries(labels ?? {})
  if (entries.length === 0) return null
  return (
    <div className="labels">
      {entries.map(([k, v]) => (
        <span className="label" key={k}>
          {neutralize(k)}={neutralize(v)}
        </span>
      ))}
    </div>
  )
}

interface Props {
  vms: VM[]
  controls: FleetControls
  /** A lifecycle filter is active, so an empty table is not an empty host. */
  filtered?: boolean
  /** The VM singled out in the URL (SPEC §13.7), if any. */
  selectedVM?: string
  onSelectVM?: (vmID: string) => void
}

export function VMTable({ vms, controls, filtered = false, selectedVM, onSelectVM }: Props) {
  if (vms.length === 0) {
    return <p className="empty">{filtered ? 'No VMs match this filter.' : 'No VMs on this host.'}</p>
  }
  return (
    <table className="vms">
      <thead>
        <tr>
          <th scope="col">
            <span className="sr-only">Selected</span>
          </th>
          <th>Name / ID</th>
          <th>Template</th>
          <th>Lifecycle</th>
          <th>Transport / capture</th>
          <th>Allocation</th>
          <th>Usage</th>
          <th>Disk</th>
          <th>Network</th>
          <th>Age</th>
          <th>Owner</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {vms.map((vm) => (
          <tr
            key={vm.vm_id}
            data-testid={`vm-row-${vm.vm_id}`}
            className={vm.vm_id === selectedVM ? 'vm-row selected' : 'vm-row'}
            aria-current={vm.vm_id === selectedVM ? 'true' : undefined}
          >
            <td>
              <input
                type="checkbox"
                checked={controls.selected.has(vm.vm_id)}
                onChange={() => controls.toggle(vm.vm_id)}
                aria-label={`Select VM ${neutralize(vm.name)}`}
              />
            </td>
            <td>
              <div className="name" data-testid="vm-name">
                {onSelectVM ? (
                  // Singling out a row writes ?vm= so a reload, or a colleague
                  // opening the link, lands on the same VM.
                  <button
                    type="button"
                    className="link-button"
                    onClick={() => onSelectVM(vm.vm_id)}
                    aria-pressed={vm.vm_id === selectedVM}
                  >
                    {neutralize(vm.name)}
                  </button>
                ) : (
                  neutralize(vm.name)
                )}
              </div>
              <div className="sub">
                <code>{vm.vm_id.slice(0, 8)}</code>
                <span className="rev">rev {vm.revision}</span>
              </div>
            </td>
            <td>
              <div>{neutralize(vm.template_id)}</div>
              <div className="sub">
                <code>{vm.template_digest.slice(0, 19)}</code>
              </div>
            </td>
            <td>
              <Lifecycle vm={vm} />
            </td>
            <td data-testid="vm-telemetry">
              <CaptureSummary vmID={vm.vm_id} />
            </td>
            <td>
              <div>{vm.resources.vcpu_count} vCPU</div>
              <div>{vm.resources.memory_mib} MiB</div>
            </td>
            <td>
              <NotMeasured />
            </td>
            <td>
              <div>{vm.resources.root_disk_mib} MiB root</div>
              <div className="sub">{vm.resources.workspace_disk_mib} MiB workspace</div>
            </td>
            <td>{neutralize(vm.network_profile)}</td>
            <td title={vm.created_at}>{age(vm.created_at)}</td>
            <td>
              <div>{neutralize(vm.owner)}</div>
              <Labels labels={vm.labels} />
            </td>
            <td>
              <div className="row-actions">
                <RowActions vm={vm} controls={controls} />
              </div>
              <RowResult vm={vm} controls={controls} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
