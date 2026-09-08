// ABOUTME: Shows each visible fleet VM's capture status from the same API as its detail view.
// ABOUTME: Requests share a bounded pool and end when the row leaves the current page.
import { useCoverage } from '../useCoverage'
import { neutralize } from '../text'
export function CaptureSummary({ vmID }: { vmID: string }) {
  const { coverage, failure } = useCoverage(vmID)
  const state = (id: string) =>
    coverage?.collectors.find((collector) => collector.id === id)?.state ??
    (coverage || failure ? 'unknown' : 'checking')
  const qualifier = failure && coverage ? 'last reported ' : ''
  return (
    <div className="capture-summary">
      {failure && (
        <div className="failure">
          {coverage ? 'Current capture unknown; showing last report.' : 'Coverage unreadable; current capture unknown.'}
        </div>
      )}
      <div>
        Transport {qualifier}
        {neutralize(coverage?.channel.state ?? (failure ? 'unknown' : 'checking'))}
      </div>
      <div>
        Files {qualifier}
        {neutralize(state('filesystem'))}
      </div>
      <div>
        Flows {qualifier}
        {neutralize(state('flow'))}
      </div>
      {coverage?.gaps.length !== 0 && coverage && (
        <details>
          <summary>Coverage gaps / loss</summary>
          {coverage.gaps.map((gap) => (
            <div key={gap}>{neutralize(gap)}</div>
          ))}
        </details>
      )}
    </div>
  )
}
