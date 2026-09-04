// ABOUTME: A WebSocket stand-in for tests — the network boundary and nothing else.
// ABOUTME: Terminal, framing and reconnect logic all stay real above it.

/** One message the code under test handed to the socket. */
export type SentMessage = string | Uint8Array

/**
 * A WebSocket whose transport is a test. It records what was sent and lets a
 * test drive open, message and close by hand, which is the only way to observe
 * a reconnect ladder without a server.
 */
export class FakeWebSocket {
  static readonly CONNECTING = 0
  static readonly OPEN = 1
  static readonly CLOSING = 2
  static readonly CLOSED = 3

  /** Every socket opened since the last `reset`, in order. */
  static instances: FakeWebSocket[] = []

  static reset(): void {
    FakeWebSocket.instances = []
  }

  static get last(): FakeWebSocket {
    const s = FakeWebSocket.instances[FakeWebSocket.instances.length - 1]
    if (!s) throw new Error('no socket was opened')
    return s
  }

  readonly url: string
  readyState: number = FakeWebSocket.CONNECTING
  binaryType = 'blob'
  readonly sent: SentMessage[] = []
  onopen: ((e: Event) => void) | null = null
  onmessage: ((e: MessageEvent) => void) | null = null
  onclose: ((e: CloseEvent) => void) | null = null
  onerror: ((e: Event) => void) | null = null

  constructor(url: string) {
    this.url = url
    FakeWebSocket.instances.push(this)
  }

  send(data: SentMessage): void {
    this.sent.push(data)
  }

  close(): void {
    if (this.readyState === FakeWebSocket.CLOSED) return
    this.readyState = FakeWebSocket.CLOSED
    this.onclose?.({ code: 1000, reason: '', wasClean: true } as CloseEvent)
  }

  // --- test drivers ---

  /** The handshake completed. */
  accept(): void {
    this.readyState = FakeWebSocket.OPEN
    this.onopen?.(new Event('open'))
  }

  /** Deliver a host control message. */
  control(body: unknown): void {
    this.onmessage?.({ data: JSON.stringify(body) } as MessageEvent)
  }

  /** Deliver raw text, for the malformed cases. */
  text(raw: string): void {
    this.onmessage?.({ data: raw } as MessageEvent)
  }

  /** Deliver a PTY payload framed the way the host frames it. */
  output(offset: bigint, bytes: Uint8Array): void {
    const buf = new ArrayBuffer(8 + bytes.length)
    new DataView(buf).setBigUint64(0, offset)
    new Uint8Array(buf).set(bytes, 8)
    this.onmessage?.({ data: buf } as MessageEvent)
  }

  /** The connection went away without a close handshake. */
  drop(code = 1006, reason = ''): void {
    this.readyState = FakeWebSocket.CLOSED
    this.onclose?.({ code, reason, wasClean: false } as CloseEvent)
  }

  /** The text messages sent so far, decoded. */
  textSent(): Record<string, unknown>[] {
    return this.sent
      .filter((m): m is string => typeof m === 'string')
      .map((m) => JSON.parse(m) as Record<string, unknown>)
  }

  /** The binary messages sent so far, split into sequence and payload. */
  binarySent(): { seq: bigint; bytes: Uint8Array }[] {
    return this.sent
      .filter((m): m is Uint8Array => typeof m !== 'string')
      .map((m) => ({
        seq: new DataView(m.buffer, m.byteOffset, m.byteLength).getBigUint64(0),
        bytes: m.slice(8),
      }))
  }
}

/** Install FakeWebSocket as the page's WebSocket. Returns nothing; use the class. */
export function installFakeWebSocket(stub: (name: string, value: unknown) => void): void {
  FakeWebSocket.reset()
  stub('WebSocket', FakeWebSocket)
}
