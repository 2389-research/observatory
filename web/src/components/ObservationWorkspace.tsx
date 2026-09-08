// ABOUTME: Uses current boot coverage to bind the event feed to one VM observation scope.
// ABOUTME: Coverage polling and family changes never recreate the adjacent terminal.
import { useState } from 'react'
import { useCoverage } from '../useCoverage'
import { neutralize } from '../text'
import { CoveragePanel } from './CoveragePanel'
import { EventTimeline } from './EventTimeline'

const collectorForFamily: Record<string, string> = {
  fs: 'filesystem',
  'net.flow': 'flow',
  dns: 'dns',
  policy: 'denial',
}

export function ObservationWorkspace({ vmID }: { vmID: string }) {
  const { coverage, failure } = useCoverage(vmID, 5000)
  const [family, setFamily] = useState('fs')
  const current = coverage?.vm_id === vmID ? coverage : null
  const captureState = failure
    ? 'unknown'
    : (current?.collectors.find((collector) => collector.id === collectorForFamily[family])?.state ?? 'unknown')
  return (
    <aside className="observation-workspace" aria-label="VM observation workspace">
      <CoveragePanel coverage={current} failure={failure} />
      <div className="event-family">
        <label>
          Event family{' '}
          <select value={family} onChange={(event) => setFamily(event.target.value)}>
            <option value="fs">Filesystem Activity</option>
            <option value="">All events</option>
            <option value="net.flow">Network flows</option>
            <option value="dns">DNS</option>
            <option value="policy">Policy</option>
            <option value="guest">Guest health</option>
            <option value="terminal">Terminal</option>
          </select>
        </label>
      </div>
      {current?.boot_id ? (
        <>
          <p className="observation-note">
            Boot <code>{neutralize(current.boot_id)}</code>
          </p>
          <EventTimeline
            key={`${vmID}:${current.boot_id}:${family}`}
            vmID={vmID}
            bootID={current.boot_id}
            family={family}
            captureState={captureState}
          />
        </>
      ) : (
        <p className="empty">
          A current boot identity is required to display activity. Coverage and the terminal reconnect independently.
        </p>
      )}
    </aside>
  )
}
