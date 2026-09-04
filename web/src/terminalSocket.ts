// ABOUTME: The browser end of GET /terminals/{id}/stream — framing, acks, a
// ABOUTME: debounced resize and a bounded reconnect. It carries no credential.

/**
 * A control message, parsed. The wire is snake_case with counters as decimal
 * strings (SPEC P-03); the parsed form is camelCase with `bigint` offsets,
 * because a byte counter outgrows Number.MAX_SAFE_INTEGER and every consumer
 * would otherwise have to remember not to parse it.
 *
 * `reconnecting` is synthesized here. The host never sends it: it is this
 * module reporting its own state, so §8.2's five named states all arrive
 * through one channel instead of two.
 */
export type TerminalControl =
  | {
      type: 'attached'
      sessionID: string
      connID: string
      resumeOffset: bigint
      gap: boolean
      writer: boolean
      holder: string
      maxInflightBytes: bigint
    }
  | { type: 'lease'; writer: boolean; holder: string; reason: string }
  | { type: 'dropped'; fromOffset: bigint; toOffset: bigint }
  | { type: 'error'; cause: string; message: string }
  | { type: 'closed'; reason: string; exitCode?: number; signal?: string }
  | { type: 'reconnecting'; attempt: number; reason: string }

export type LeaseMode = 'acquire' | 'steal' | 'release'

export interface TerminalSocket {
  /** Called with the absolute stream offset of the first byte and the bytes. */
  onOutput: ((offset: bigint, bytes: Uint8Array) => void) | null
  onControl: ((c: TerminalControl) => void) | null
  /** Type into the shell. Dropped while the socket is down; the guest's ring is the buffer, not this. */
  send(bytes: Uint8Array): void
  /** Report bytes actually on screen (§8.3). `offset` is the first byte NOT yet consumed. */
  ack(offset: bigint): void
  /** Ask the guest for a new window size. Debounced, deduplicated, and held over a reconnect. */
  resize(rows: number, cols: number): void
  lease(mode: LeaseMode): void
  close(): void
}

export interface TerminalSocketOptions {
  /** Reconnect attempts before the socket gives up. */
  maxAttempts?: number
  /** Backoff before attempt `n` (1-based), in milliseconds. */
  backoffMs?: (attempt: number) => number
  /** How long a burst of resizes is coalesced, in milliseconds. */
  resizeDebounceMs?: number
}

/** Bytes of big-endian offset in front of every PTY payload, both directions. */
const OFFSET_BYTES = 8

const DEFAULT_MAX_ATTEMPTS = 5
const DEFAULT_RESIZE_DEBOUNCE_MS = 150

/**
 * Causes that say the session itself is gone. Reconnecting into one of these
 * would burn every attempt on an upgrade the host will refuse, and then blame
 * the network for a session that simply no longer exists.
 */
const TERMINAL_CAUSES = new Set(['session_closed', 'session_stale', 'terminal_session_unknown'])

function defaultBackoff(attempt: number): number {
  return Math.min(250 * 2 ** (attempt - 1), 5000)
}

/**
 * The stream URL for `sessionID` on this page's own origin.
 *
 * Same-origin means the `HttpOnly` session cookie rides along on its own, so
 * nothing here appends a token: §8.4 and §15.1 both forbid a credential in a
 * URL, and a WebSocket URL ends up in logs and history like any other.
 */
export function streamURL(sessionID: string): string {
  const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${scheme}//${window.location.host}/api/v1/terminals/${encodeURIComponent(sessionID)}/stream`
}

/** Read one decimal-string counter. An absent or malformed value reads as 0. */
function bigOf(v: unknown): bigint {
  if (typeof v !== 'string' || !/^\d+$/.test(v)) return 0n
  return BigInt(v)
}

function parseControl(raw: string): TerminalControl | null {
  let body: unknown
  try {
    body = JSON.parse(raw)
  } catch {
    return null
  }
  if (!body || typeof body !== 'object') return null
  const m = body as Record<string, unknown>
  switch (m.type) {
    case 'attached':
      return {
        type: 'attached',
        sessionID: String(m.session_id ?? ''),
        connID: String(m.conn_id ?? ''),
        resumeOffset: bigOf(m.resume_offset),
        gap: m.gap === true,
        writer: m.writer === true,
        holder: String(m.holder ?? ''),
        maxInflightBytes: bigOf(m.max_inflight_bytes),
      }
    case 'lease':
      return {
        type: 'lease',
        writer: m.writer === true,
        holder: String(m.holder ?? ''),
        reason: String(m.reason ?? ''),
      }
    case 'dropped':
      return { type: 'dropped', fromOffset: bigOf(m.from_offset), toOffset: bigOf(m.to_offset) }
    case 'error':
      return { type: 'error', cause: String(m.cause ?? ''), message: String(m.message ?? '') }
    case 'closed':
      return {
        type: 'closed',
        reason: String(m.reason ?? ''),
        exitCode: typeof m.exit_code === 'number' ? m.exit_code : undefined,
        signal: typeof m.signal === 'string' && m.signal !== '' ? m.signal : undefined,
      }
    default:
      return null
  }
}

/**
 * Open the terminal stream for `sessionID`.
 *
 * The returned socket outlives any one connection: handlers, the input
 * sequence and a pending resize survive a reconnect, and every state change
 * arrives as a control message rather than as a callback nobody registered.
 */
export function openTerminal(sessionID: string, opts: TerminalSocketOptions = {}): TerminalSocket {
  const maxAttempts = opts.maxAttempts ?? DEFAULT_MAX_ATTEMPTS
  const backoffMs = opts.backoffMs ?? defaultBackoff
  const debounceMs = opts.resizeDebounceMs ?? DEFAULT_RESIZE_DEBOUNCE_MS
  const url = streamURL(sessionID)

  let ws: WebSocket | null = null
  let attempt = 0
  let done = false
  let retryTimer: ReturnType<typeof setTimeout> | null = null
  let resizeTimer: ReturnType<typeof setTimeout> | null = null

  // The guest drops any input sequence it has already seen, and the host
  // relay counts from zero for each connection, so a reconnect restarts here.
  let seq = 0n
  // At most one resize is outstanding: the newest window size is the only one
  // worth sending, and one that happened while the socket was down still has
  // to reach the guest.
  let pendingResize: { rows: number; cols: number } | null = null
  let sentResize: { rows: number; cols: number } | null = null

  const socket: TerminalSocket = {
    onOutput: null,
    onControl: null,
    send(bytes) {
      if (!ws || ws.readyState !== WebSocket.OPEN) return
      seq += 1n
      const msg = new Uint8Array(OFFSET_BYTES + bytes.length)
      new DataView(msg.buffer).setBigUint64(0, seq)
      msg.set(bytes, OFFSET_BYTES)
      ws.send(msg)
    },
    ack(offset) {
      sendText({ type: 'ack', offset: offset.toString() })
    },
    resize(rows, cols) {
      if (sentResize && sentResize.rows === rows && sentResize.cols === cols) return
      pendingResize = { rows, cols }
      if (resizeTimer !== null) clearTimeout(resizeTimer)
      resizeTimer = setTimeout(() => {
        resizeTimer = null
        flushResize()
      }, debounceMs)
    },
    lease(mode) {
      sendText({ type: 'lease', mode })
    },
    close() {
      done = true
      if (retryTimer !== null) clearTimeout(retryTimer)
      if (resizeTimer !== null) clearTimeout(resizeTimer)
      retryTimer = null
      resizeTimer = null
      const open = ws
      ws = null
      open?.close()
    },
  }

  function sendText(m: Record<string, unknown>): void {
    if (!ws || ws.readyState !== WebSocket.OPEN) return
    ws.send(JSON.stringify(m))
  }

  function flushResize(): void {
    if (!pendingResize) return
    if (!ws || ws.readyState !== WebSocket.OPEN) return
    const { rows, cols } = pendingResize
    pendingResize = null
    sentResize = { rows, cols }
    sendText({ type: 'resize', rows, cols })
  }

  function emit(c: TerminalControl): void {
    socket.onControl?.(c)
  }

  function connect(): void {
    const conn = new WebSocket(url)
    conn.binaryType = 'arraybuffer'
    ws = conn

    conn.onopen = () => {
      attempt = 0
      seq = 0n
      flushResize()
    }

    conn.onmessage = (ev: MessageEvent) => {
      if (typeof ev.data === 'string') {
        const c = parseControl(ev.data)
        if (!c) return
        if (c.type === 'closed' || (c.type === 'error' && TERMINAL_CAUSES.has(c.cause))) {
          // The session is over. Stop reconnecting before the close event
          // arrives, so the shell's own reason is the last word.
          done = true
        }
        emit(c)
        return
      }
      const buf = ev.data as ArrayBuffer
      if (buf.byteLength < OFFSET_BYTES) return
      const offset = new DataView(buf).getBigUint64(0)
      socket.onOutput?.(offset, new Uint8Array(buf, OFFSET_BYTES))
    }

    conn.onclose = (ev: CloseEvent) => {
      if (ws !== conn) return
      ws = null
      if (done) return
      if (attempt >= maxAttempts) {
        done = true
        emit({
          type: 'closed',
          reason: `the connection dropped and ${maxAttempts} reconnect attempts did not restore it`,
        })
        return
      }
      attempt += 1
      emit({
        type: 'reconnecting',
        attempt,
        reason: ev.reason !== '' ? ev.reason : `the connection closed (code ${ev.code})`,
      })
      retryTimer = setTimeout(() => {
        retryTimer = null
        if (!done) connect()
      }, backoffMs(attempt))
    }
  }

  connect()
  return socket
}
