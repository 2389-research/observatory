// ABOUTME: xterm.js against a real guest PTY (SPEC §8.1): five named states, an
// ABOUTME: ack that means "on screen", and a gap the operator cannot mistake for output.
import { useEffect, useRef, useState } from 'react'
import { Terminal as XTerm } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import { openTerminal, type TerminalControl, type TerminalSocket } from './terminalSocket'
import { neutralize } from './text'

export interface TerminalProps {
  sessionId: string
  /** The size the session was opened with; the fit addon owns it afterwards. */
  rows?: number
  cols?: number
}

/** §8.2's five states. An ambiguous spinner is not one of them. */
type Phase = 'connecting' | 'attached' | 'reconnecting' | 'closed'

interface View {
  phase: Phase
  writer: boolean
  holder: string
  attempt: number
  /** Why the connection dropped, or why the shell ended. */
  reason: string
  exitCode?: number
  signal?: string
  /** The host's last word on the lease or an error, shown beside the state. */
  note: string
  /** The most recent stretch of output nobody will ever see. */
  gap: { from: bigint; to: bigint } | null
}

const START: View = {
  phase: 'connecting',
  writer: false,
  holder: '',
  attempt: 0,
  reason: '',
  note: '',
  gap: null,
}

function stateLine(v: View): string {
  switch (v.phase) {
    case 'connecting':
      return 'connecting'
    case 'attached':
      return v.writer ? 'attached (writer)' : `attached (read-only — ${neutralize(v.holder)} is writing)`
    case 'reconnecting':
      return `reconnecting (attempt ${v.attempt}) — ${neutralize(v.reason)}`
    case 'closed': {
      const parts = [v.reason === '' ? 'the stream ended' : v.reason]
      if (v.exitCode !== undefined) parts.push(`exit code ${v.exitCode}`)
      if (v.signal) parts.push(`signal ${v.signal}`)
      return `closed (${neutralize(parts.join(', '))})`
    }
  }
}

function gapLine(from: bigint, to: bigint): string {
  return `output between byte ${from} and byte ${to} was dropped`
}

export function Terminal({ sessionId, rows = 24, cols = 80 }: TerminalProps) {
  const screenRef = useRef<HTMLDivElement | null>(null)
  const termRef = useRef<XTerm | null>(null)
  const socketRef = useRef<TerminalSocket | null>(null)
  // Read inside xterm's callbacks, which are registered once and would
  // otherwise close over the first render's value forever.
  const writerRef = useRef(false)
  // The offset one past the last byte this browser has actually painted. It is
  // what an ack reports, and what makes a replay gap's first number honest.
  const consumedRef = useRef(0n)
  const [view, setView] = useState<View>(START)

  useEffect(() => {
    const screen = screenRef.current
    if (!screen) return

    const term = new XTerm({
      rows,
      cols,
      scrollback: 5000,
      allowProposedApi: false,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
    })
    // AT-028: OSC 52 is the escape sequence that loads the clipboard. Claiming
    // it here and dropping it means no xterm default and no addon added later
    // can hand a guest the operator's clipboard.
    term.parser.registerOscHandler(52, () => true)

    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(screen)
    fit.fit()
    termRef.current = term

    const socket = openTerminal(sessionId)
    socketRef.current = socket

    function showGap(from: bigint, to: bigint): void {
      // Reset rather than carry on: the parser, the modes and the screen all
      // describe bytes that never arrived (§8.2, AT-023).
      term.reset()
      term.write(`\r\n── ${gapLine(from, to)} ──\r\n`)
      consumedRef.current = to
      setView((v) => ({ ...v, gap: { from, to } }))
    }

    socket.onOutput = (offset, bytes) => {
      const consumed = offset + BigInt(bytes.length)
      // The callback fires when the bytes are on screen. Acking on receive
      // would measure the network and leave §8.3's window decorative.
      term.write(bytes, () => {
        consumedRef.current = consumed
        socket.ack(consumed)
      })
    }

    socket.onControl = (c: TerminalControl) => {
      switch (c.type) {
        case 'attached':
          writerRef.current = c.writer
          setView((v) => ({
            ...v,
            phase: 'attached',
            writer: c.writer,
            holder: c.holder,
            attempt: 0,
            note: '',
          }))
          if (c.gap) showGap(consumedRef.current, c.resumeOffset)
          else consumedRef.current = c.resumeOffset
          return
        case 'lease':
          writerRef.current = c.writer
          setView((v) => ({ ...v, writer: c.writer, holder: c.holder, note: c.reason }))
          return
        case 'dropped':
          showGap(c.fromOffset, c.toOffset)
          return
        case 'error':
          setView((v) => ({ ...v, note: `${c.cause}: ${c.message}` }))
          return
        case 'reconnecting':
          writerRef.current = false
          setView((v) => ({
            ...v,
            phase: 'reconnecting',
            writer: false,
            attempt: c.attempt,
            reason: c.reason,
          }))
          return
        case 'closed':
          writerRef.current = false
          setView((v) => ({
            ...v,
            phase: 'closed',
            writer: false,
            reason: c.reason,
            exitCode: c.exitCode,
            signal: c.signal,
          }))
          return
      }
    }

    const encoder = new TextEncoder()
    const typed = term.onData((d) => {
      if (!writerRef.current) return
      socket.send(encoder.encode(d))
    })
    // Sequences xterm reports as raw bytes rather than text, one char per byte.
    const typedBinary = term.onBinary((d) => {
      if (!writerRef.current) return
      socket.send(Uint8Array.from(d, (ch) => ch.charCodeAt(0) & 0xff))
    })
    const resized = term.onResize(({ rows: r, cols: c }) => {
      // The guest applies only the writer's size (§8.2); a read-only viewer
      // dragging its window would otherwise be answered with a lease nag.
      if (!writerRef.current) return
      socket.resize(r, c)
    })

    // A ResizeObserver would be the finer instrument, but L1b has no resizable
    // panes to observe and jsdom has no observer to polyfill.
    const refit = () => fit.fit()
    window.addEventListener('resize', refit)

    return () => {
      window.removeEventListener('resize', refit)
      typed.dispose()
      typedBinary.dispose()
      resized.dispose()
      socket.close()
      term.dispose()
      termRef.current = null
      socketRef.current = null
      writerRef.current = false
      consumedRef.current = 0n
    }
  }, [sessionId])

  // A size the parent asked for. xterm reports it back through onResize, so the
  // guest hears about it through exactly one path.
  useEffect(() => {
    termRef.current?.resize(cols, rows)
  }, [rows, cols])

  return (
    <section className="terminal-panel">
      <div className="terminal-status">
        <span className="terminal-state" data-testid="terminal-state" role="status">
          {stateLine(view)}
        </span>
        {view.note !== '' && <span className="terminal-note">{neutralize(view.note)}</span>}
        {view.gap && (
          <span className="terminal-gap" role="alert">
            {gapLine(view.gap.from, view.gap.to)}
          </span>
        )}
        {view.phase === 'attached' && !view.writer && (
          <button
            type="button"
            className="row-action"
            onClick={() => socketRef.current?.lease('steal')}
          >
            Take the writer lease
          </button>
        )}
      </div>
      <div className="terminal-screen" ref={screenRef} />
    </section>
  )
}
