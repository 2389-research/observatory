// ABOUTME: The VM detail workspace (SPEC §13.2): identity, lifecycle actions, its terminal.
// ABOUTME: It reports only fields the API returns; a guest address it was not given stays unclaimed.
import { lazy, Suspense, useCallback, useEffect, useRef, useState } from 'react'
import { ApiFailure, deleteJSON, getJSON, postJSON } from './api'
import type { TerminalSession, TerminalSessionList, VM } from './types'
import { neutralize, age } from './text'
import { OperationFailure } from './components/OperationFailure'
import { useFleetControls } from './components/BulkActions'
import { VMActions } from './components/VMActions'

// xterm.js and its addon are most of the bundle, and the fleet page never
// draws a terminal. Loaded on demand, the landing page does not pay for it.
const Terminal = lazy(() => import('./Terminal').then((m) => ({ default: m.Terminal })))

const REFRESH_MS = 5000

/** The size a new session opens at, and the size its terminal renders at. */
const ROWS = 24
const COLS = 80

/**
 * A shell needs a running kernel on the other end. The host refuses a create
 * outside this state with `vm_state_conflict`, so the button is absent rather
 * than sent and refused.
 */
function canOpenTerminal(vm: VM): boolean {
  return vm.observed_state === 'running'
}

function isOpen(s: TerminalSession): boolean {
  return s.state === 'open'
}

function Identity({ vm }: { vm: VM }) {
  return (
    <div className="vm-identity" data-testid="vm-identity">
      <h2>
        VM: {neutralize(vm.name)}{' '}
        <span className={`state state-${vm.observed_state}`}>{vm.observed_state}</span>
        {vm.desired_state !== vm.observed_state && <span className="drift">want {vm.desired_state}</span>}
      </h2>
      <dl className="vm-facts">
        <dt>Template</dt>
        <dd>
          {neutralize(vm.template_id)}
          <code>{vm.template_digest}</code>
        </dd>
        <dt>Allocation</dt>
        <dd>
          {vm.resources.vcpu_count} vCPU / {vm.resources.memory_mib} MiB · {vm.resources.root_disk_mib} MiB root ·{' '}
          {vm.resources.workspace_disk_mib} MiB workspace
        </dd>
        <dt>Owner</dt>
        <dd>
          {neutralize(vm.owner)} · created {age(vm.created_at)} · rev {vm.revision}
        </dd>
        <dt>ID</dt>
        <dd>
          <code>{vm.vm_id}</code>
        </dd>
      </dl>
      {vm.failure && (
        <p className="failure">
          {vm.failure.stage}: {neutralize(vm.failure.reason)}
        </p>
      )}
    </div>
  )
}

function Network({ vm }: { vm: VM }) {
  return (
    <div className="vm-network" data-testid="vm-network">
      <dl className="vm-facts">
        <dt>Network profile</dt>
        <dd>{neutralize(vm.network_profile)}</dd>
        <dt>Policy</dt>
        <dd>{vm.network_policy_id === '' ? <span className="unknown">none set</span> : neutralize(vm.network_policy_id)}</dd>
        <dt>Address</dt>
        <dd>
          {/* §13.2 asks for addresses. This API returns a profile and a policy
              and no address of any kind, so there is nothing to print — and a
              plausible-looking 10.x here would be an invented observation. */}
          <span className="unknown" title="the VM API reports no address field in this build">
            no guest address is published
          </span>
        </dd>
      </dl>
    </div>
  )
}

export interface VMDetailProps {
  vmID: string
  onBack: () => void
}

export function VMDetail({ vmID, onBack }: VMDetailProps) {
  const [vm, setVM] = useState<VM | null>(null)
  const [sessions, setSessions] = useState<TerminalSession[]>([])
  const [failure, setFailure] = useState<ApiFailure | null>(null)
  // The session this workspace is attached to. It survives a poll that has not
  // caught up yet, so opening a terminal does not flicker back to another tab.
  const [attached, setAttached] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  // Bumped by every create and close, so an in-flight list read can tell that
  // its answer is older than what this browser already knows.
  const mutations = useRef(0)

  const load = useCallback(async () => {
    // A poll that started before this browser opened or closed a session would
    // hand back a list from before it and undo the change on screen. Reads that
    // raced a mutation are dropped, not trusted.
    const seen = mutations.current
    try {
      const [next, list] = await Promise.all([
        getJSON<VM>(`/vms/${vmID}`),
        getJSON<TerminalSessionList>(`/vms/${vmID}/terminals`),
      ])
      if (mutations.current !== seen) return
      setVM(next)
      setSessions(list.terminals)
      setFailure(null)
    } catch (e) {
      setFailure(e instanceof ApiFailure ? e : new ApiFailure(0))
    }
  }, [vmID])

  // The same controls the fleet page drives its rows with, pointed at the one
  // VM on screen: one definition of what each action is legal on, and one
  // confirm in front of DELETE. Settling re-reads the VM, so the identity block
  // and the action's own outcome cannot disagree for a whole poll interval.
  const controls = useFleetControls(() => void load())

  useEffect(() => {
    void load()
    const t = setInterval(() => void load(), REFRESH_MS)
    return () => clearInterval(t)
  }, [load])

  // Attach to whatever the VM already has. An operator who opened this page to
  // look at a running shell should not have to ask for it again.
  const open = sessions.filter(isOpen)
  const current = attached !== null && open.some((s) => s.session_id === attached) ? attached : (open[0]?.session_id ?? null)

  const openTerminalSession = async () => {
    mutations.current += 1
    setBusy(true)
    try {
      const created = await postJSON<TerminalSession>(`/vms/${vmID}/terminals`, { rows: ROWS, cols: COLS })
      setSessions((prev) => [...prev, created])
      setAttached(created.session_id)
      setFailure(null)
    } catch (e) {
      setFailure(e instanceof ApiFailure ? e : new ApiFailure(0))
    } finally {
      setBusy(false)
    }
  }

  const closeSession = async (sessionID: string) => {
    mutations.current += 1
    setBusy(true)
    try {
      await deleteJSON(`/terminals/${sessionID}`)
      // Drop it here rather than waiting for the poll: the stream is already
      // dead, and a terminal left mounted would spend its reconnect attempts
      // dialling a session the host just closed.
      setSessions((prev) => prev.filter((s) => s.session_id !== sessionID))
      if (attached === sessionID) setAttached(null)
      setFailure(null)
    } catch (e) {
      setFailure(e instanceof ApiFailure ? e : new ApiFailure(0))
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="page">
      <header className="page-head">
        <button type="button" className="link-button" onClick={onBack}>
          ← Back to the fleet
        </button>
      </header>

      <OperationFailure failure={failure ?? undefined} fallback="The host did not answer" />

      {!vm ? (
        <p className="empty">Reading the VM…</p>
      ) : (
        <>
          <section className="vm-head">
            <Identity vm={vm} />
            <Network vm={vm} />
          </section>

          <VMActions vm={vm} controls={controls} />

          <section className="terminal-section">
            <h2>Terminal</h2>
            {!canOpenTerminal(vm) ? (
              <p className="empty" data-testid="terminal-unavailable">
                This VM is {vm.observed_state}. A terminal needs a running guest.
              </p>
            ) : (
              <>
                <div className="terminal-tabs" data-testid="terminal-tabs" role="tablist" aria-label="Terminal sessions">
                  {open.map((s) => (
                    <button
                      key={s.session_id}
                      type="button"
                      role="tab"
                      className={s.session_id === current ? 'terminal-tab active' : 'terminal-tab'}
                      aria-selected={s.session_id === current}
                      onClick={() => setAttached(s.session_id)}
                    >
                      {neutralize(s.session_id)} <span className="sub">pid {s.pid}</span>
                    </button>
                  ))}
                  <button type="button" className="row-action" disabled={busy} onClick={() => void openTerminalSession()}>
                    Open a terminal
                  </button>
                  {current !== null && (
                    <button
                      type="button"
                      className="row-action"
                      disabled={busy}
                      onClick={() => void closeSession(current)}
                    >
                      Close this session
                    </button>
                  )}
                </div>

                {current === null ? (
                  <p className="empty">No terminal is open on this VM.</p>
                ) : (
                  // Keyed by session: attaching to another tab must build a new
                  // socket and a new screen, never reuse one holding another
                  // session's scrollback.
                  <Suspense fallback={<p className="empty">Loading the terminal…</p>}>
                    <Terminal key={current} sessionId={current} rows={ROWS} cols={COLS} />
                  </Suspense>
                )}
              </>
            )}
          </section>
        </>
      )}
    </main>
  )
}
