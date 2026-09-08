// ABOUTME: Presents transport health separately from each collector's actual scope and loss.
// ABOUTME: Unknown counts, stale reports and exclusions remain visible alongside healthy states.
import type { CaptureCoverage } from '../types'
import { neutralize } from '../text'

const labels: Record<string, string> = {
  filesystem: 'Filesystem',
  process: 'Process',
  flow: 'Network flows',
  dns: 'DNS',
  denial: 'Network denials',
  request: 'HTTP requests',
}
const count = (value: string | number | null | undefined) =>
  value === null || value === undefined ? 'unknown' : neutralize(String(value))
export function CoveragePanel({ coverage, failure }: { coverage: CaptureCoverage | null; failure: string }) {
  return (
    <section className="capture-panel" aria-label="Capture coverage">
      <h2>Capture coverage</h2>
      {failure && (
        <p role="alert" className="failure">
          {coverage ? 'Last report may be stale. ' : 'Coverage unavailable. '}
          {neutralize(failure)}
        </p>
      )}
      {!coverage ? (
        <p className="empty">{failure ? 'Capture status could not be read.' : 'Reading capture status…'}</p>
      ) : (
        <>
          <p data-testid="channel-coverage">
            <strong>Transport {neutralize(coverage.channel.state)}</strong> · {count(coverage.channel.observed_dropped)}{' '}
            observed drops{coverage.channel.reason && <> · {neutralize(coverage.channel.reason)}</>}
          </p>
          <div className="capture-grid">
            {coverage.collectors.map((collector) => (
              <details key={collector.id} className="capture-card" data-testid={`coverage-${collector.id}`}>
                <summary>
                  <strong>{labels[collector.id] ?? neutralize(collector.id)}</strong>{' '}
                  <span>{neutralize(collector.state)}</span>
                </summary>
                <p>
                  {count(collector.observed_dropped)} observed drops · {count(collector.unknown_loss_intervals)}{' '}
                  intervals with unknown loss
                </p>
                {collector.reason && <p>{neutralize(collector.reason)}</p>}
                <p>
                  {neutralize(collector.source)} · {neutralize(collector.provenance)}
                  {collector.capture_mode && <> · {neutralize(collector.capture_mode)}</>}
                </p>
                <dl>
                  <dt>Event classes</dt>
                  <dd>
                    {collector.event_classes.length
                      ? collector.event_classes.map(neutralize).join(', ')
                      : 'None reported'}
                  </dd>
                  <dt>Supported scope</dt>
                  <dd>{collector.scope.length ? collector.scope.map(neutralize).join('; ') : 'None reported'}</dd>
                  <dt>Exclusions</dt>
                  <dd>
                    {collector.exclusions.length ? collector.exclusions.map(neutralize).join('; ') : 'None reported'}
                  </dd>
                  <dt>Last event</dt>
                  <dd>{collector.last_event_at ? neutralize(collector.last_event_at) : 'No event reported'}</dd>
                  <dt>Last success</dt>
                  <dd>{collector.last_success_at ? neutralize(collector.last_success_at) : 'No success reported'}</dd>
                </dl>
                {collector.limitations.map((limitation, index) => (
                  <p key={index}>{neutralize(limitation)}</p>
                ))}
              </details>
            ))}
          </div>
          {coverage.gaps.length > 0 && (
            <p className="coverage-gaps">Coverage gaps / loss history: {coverage.gaps.map(neutralize).join(' · ')}</p>
          )}
        </>
      )}
    </section>
  )
}
