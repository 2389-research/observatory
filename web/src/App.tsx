// ABOUTME: The fleet page (SPEC §13.1): host capacity, attention head, VM table. Read-only.
// ABOUTME: Every panel comes from one poll of the API; nothing here derives numbers of its own.
import { useCallback, useEffect, useState } from 'react'
import { getJSON, ApiFailure } from './api'
import type { AttentionList, HostStatus, TemplateList, VMList } from './types'
import { HostCapacity } from './components/HostCapacity'
import { LaunchForm } from './components/LaunchForm'
import { LaunchBatch } from './components/LaunchBatch'
import { AttentionQueue } from './components/AttentionQueue'
import { VMTable } from './components/VMTable'

const REFRESH_MS = 5000

interface Fleet {
  host: HostStatus
  vms: VMList
  attention: AttentionList
  templates: TemplateList
}

export function App() {
  const [fleet, setFleet] = useState<Fleet | null>(null)
  const [failure, setFailure] = useState<ApiFailure | null>(null)
  const [asOf, setAsOf] = useState<Date | null>(null)

  const load = useCallback(async () => {
    try {
      const [host, vms, attention, templates] = await Promise.all([
        getJSON<HostStatus>('/host/status'),
        getJSON<VMList>('/vms?limit=100'),
        getJSON<AttentionList>('/attention?limit=10'),
        getJSON<TemplateList>('/templates'),
      ])
      setFleet({ host, vms, attention, templates })
      setFailure(null)
      setAsOf(new Date())
    } catch (e) {
      // Keep the last good fleet on screen; the banner says it is stale.
      setFailure(e instanceof ApiFailure ? e : new ApiFailure(0))
    }
  }, [])

  useEffect(() => {
    void load()
    const t = setInterval(() => void load(), REFRESH_MS)
    return () => clearInterval(t)
  }, [load])

  if (failure?.status === 401) {
    return (
      <main className="page">
        <h1>Firecracker Observatory</h1>
        <p className="alert" role="alert">
          Sign in to view this host. This page carries no credentials of its own.
        </p>
      </main>
    )
  }

  return (
    <main className="page">
      <header className="page-head">
        <h1>Firecracker Observatory</h1>
        <span className="as-of" data-testid="as-of">
          {asOf ? `read ${asOf.toLocaleTimeString()}` : 'reading…'}
        </span>
      </header>

      {failure && (
        <p className="alert" role="alert">
          <strong>{failure.error?.message ?? 'The host did not answer.'}</strong>{' '}
          {failure.error?.cause && <code>{failure.error.cause}</code>}
          {failure.error?.remediation?.map((r) => (
            <span className="remediation" key={r.action}>
              {r.action}: {r.rationale}
            </span>
          ))}
        </p>
      )}

      {!fleet ? (
        <p className="empty">Reading the host…</p>
      ) : (
        <>
          <HostCapacity status={fleet.host} />
          <section>
            <h2>Attention</h2>
            <AttentionQueue items={fleet.attention.items} />
          </section>
          <section>
            <LaunchForm host={fleet.host} templates={fleet.templates.templates} onLaunched={() => void load()} />
          </section>
          <section>
            {/* Collapsed by default: the batch form is long, and one VM is the
                common case. <details> keeps it keyboard-reachable with no state. */}
            <details className="batch-details">
              <summary>Launch a batch</summary>
              <LaunchBatch host={fleet.host} templates={fleet.templates.templates} onLaunched={() => void load()} />
            </details>
          </section>
          <section>
            <h2>VMs</h2>
            <VMTable vms={fleet.vms.vms} />
          </section>
        </>
      )}
    </main>
  )
}
