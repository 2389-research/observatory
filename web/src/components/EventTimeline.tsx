// ABOUTME: Shows a bounded live event window beside the terminal without touching its session.
// ABOUTME: Pause freezes the display boundary while capture continues; details preserve normalized evidence.
import { useState } from 'react'
import { useEventFeed } from '../useObservation'
import { eventPath, field, HISTORY_LIMIT, matchesEvent, operationLabel, ROW_LIMIT } from '../observation'
import { neutralize } from '../text'

export function EventTimeline({
  vmID,
  bootID,
  family,
  captureState,
  interval,
}: {
  vmID: string
  bootID: string
  family: string
  captureState: string
  interval?: number
}) {
  const feed = useEventFeed(vmID, bootID, family, interval)
  const [path, setPath] = useState('')
  const [process, setProcess] = useState('')
  const [operation, setOperation] = useState('')
  const [pause, setPause] = useState<{ after: string; received: number } | null>(null)
  const [window, setWindow] = useState(0)
  const [selected, setSelected] = useState<string | null>(null)
  const matching = feed.events.filter((event) => matchesEvent(event, { path, process, operation }))
  const visible = matching
    .filter((event) => !pause || (pause.after !== '' && BigInt(event.event_id) <= BigInt(pause.after)))
    .reverse()
  const maxWindow = Math.max(0, Math.ceil(visible.length / ROW_LIMIT) - 1)
  const page = Math.min(window, maxWindow)
  const rows = visible.slice(page * ROW_LIMIT, (page + 1) * ROW_LIMIT)
  const detail = feed.events.find((event) => event.event_id === selected)
  const hasFilters = path !== '' || process !== '' || operation !== ''
  const pauseScrolling = () => {
    setPause({ after: feed.after, received: feed.received })
    setWindow(0)
  }
  return (
    <section className="event-timeline" aria-label={family === 'fs' ? 'Filesystem Activity' : 'Live event timeline'}>
      <div className="event-toolbar">
        <strong>{family === 'fs' ? 'Filesystem Activity' : 'Live event timeline'}</strong>
        <button
          type="button"
          onClick={() => {
            if (pause) {
              setPause(null)
              setWindow(0)
            } else pauseScrolling()
          }}
        >
          {pause ? 'Resume scrolling' : 'Pause scrolling'}
        </button>
      </div>
      <p className="observation-note">
        {pause
          ? `${Math.max(0, feed.received - pause.received)} unread · collection continues`
          : 'Live · newest events first'}{' '}
        · {feed.events.length} retained · {feed.evicted} left this window
      </p>
      {feed.failure && (
        <p role="alert" className="failure">
          Event updates interrupted: {neutralize(feed.failure)}. Retrying from the last accepted cursor; the terminal
          remains connected independently.
        </p>
      )}
      {family === 'fs' && (
        <p className="observation-note">
          Notifications do not prove content changed. Close-write means a write-open file closed; mmap changes can be
          absent.
        </p>
      )}
      <div className="event-filters">
        <label>
          Path contains
          <input
            value={path}
            onChange={(event) => {
              setPath(event.target.value)
              setWindow(0)
            }}
          />
        </label>
        <label>
          Process PID
          <input
            value={process}
            onChange={(event) => {
              setProcess(event.target.value)
              setWindow(0)
            }}
            inputMode="numeric"
          />
        </label>
        <label>
          Operation
          <select
            value={operation}
            onChange={(event) => {
              setOperation(event.target.value)
              setWindow(0)
            }}
          >
            <option value="">All operations</option>
            {[
              'fs.create',
              'fs.modify',
              'fs.close_write',
              'fs.rename',
              'fs.delete',
              'fs.metadata',
              'fs.loss',
              'fs.coverage',
            ].map((kind) => (
              <option key={kind} value={kind}>
                {operationLabel(kind)}
              </option>
            ))}
          </select>
        </label>
      </div>
      <p className="observation-note">
        Path, PID and operation filters search this retained window only (at most {HISTORY_LIMIT} events / 2 MiB).{' '}
        {ROW_LIMIT} rows per page. Cursor: {feed.after || 'awaiting first page'}.
      </p>
      {rows.length === 0 ? (
        <p className="empty">
          {feed.loading
            ? 'Reading durable events…'
            : pause
              ? 'No paused rows remain in this bounded window. Resume scrolling to see current activity.'
              : hasFilters
                ? 'No retained events match these filters.'
                : captureState !== 'healthy'
                  ? `No activity displayed. Capture is ${neutralize(captureState)}; this does not mean no activity occurred.`
                  : 'No activity observed for this boot in the recent event window.'}
        </p>
      ) : (
        <ol className="event-list" aria-label="Event rows">
          {rows.map((event) => (
            <li key={event.event_id}>
              <button
                type="button"
                className="event-row"
                onClick={() => setSelected(event.event_id)}
                aria-pressed={selected === event.event_id}
              >
                <span className="event-row-head">
                  <strong>{operationLabel(event.kind)}</strong>
                  <time>{neutralize(event.host_received_at)}</time>
                </span>
                <span className="event-path">{eventPath(event)}</span>
                <span className="observation-note">
                  {neutralize(event.provenance)} · path {neutralize(field(event.quality?.path_resolution) || 'unknown')}{' '}
                  ·{' '}
                  {field(event.data.pid)
                    ? `PID ${neutralize(field(event.data.pid))} · process identity unknown`
                    : 'Process unknown'}
                </span>
              </button>
            </li>
          ))}
        </ol>
      )}
      <div className="event-toolbar">
        <button type="button" disabled={page === 0} onClick={() => setWindow(page - 1)}>
          Newer rows
        </button>
        <span>
          Page {page + 1} of {maxWindow + 1}
        </span>
        <button
          type="button"
          disabled={page === maxWindow}
          onClick={() => {
            if (!pause) setPause({ after: feed.after, received: feed.received })
            setWindow(page + 1)
          }}
        >
          Older rows
        </button>
      </div>
      {selected && (
        <section className="event-detail" aria-label="Event detail">
          <div className="event-toolbar">
            <h3>Event {selected}</h3>
            <button type="button" onClick={() => setSelected(null)}>
              Close detail
            </button>
          </div>
          {detail ? (
            <>
              <p>
                Normalized evidence includes source, timestamps, path quality and any supplied loss, truncation,
                redaction or related references.
              </p>
              <pre aria-label="Normalized event JSON">
                {JSON.stringify(detail, null, 2).split('\n').map(neutralize).join('\n')}
              </pre>
            </>
          ) : (
            <p>The selected event left the bounded window.</p>
          )}
        </section>
      )}
    </section>
  )
}
