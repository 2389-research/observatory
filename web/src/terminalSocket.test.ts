// ABOUTME: Tests for the terminal stream client: framing, acks, resize, reconnect.
// ABOUTME: Only WebSocket is stubbed; the framing and the ladder under test are real.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { openTerminal, streamURL, type TerminalControl } from './terminalSocket'
import { FakeWebSocket } from './test/fakeSocket'

function attachedMessage(over: Record<string, unknown> = {}) {
  return {
    type: 'attached',
    session_id: 'sess-1',
    conn_id: 'conn-a',
    resume_offset: '0',
    gap: false,
    writer: true,
    holder: 'conn-a',
    max_inflight_bytes: '262144',
    ...over,
  }
}

describe('streamURL', () => {
  beforeEach(() => {
    FakeWebSocket.reset()
    vi.stubGlobal('WebSocket', FakeWebSocket)
  })
  afterEach(() => vi.unstubAllGlobals())

  it('stays on this origin and carries no credential', () => {
    const url = streamURL('sess-1')
    expect(url).toBe(`ws://${window.location.host}/api/v1/terminals/sess-1/stream`)
    expect(url).not.toContain('?')
    expect(url).not.toContain('token')
  })

  it('escapes the session id rather than pasting it into the path', () => {
    expect(streamURL('a/../b')).toContain('/terminals/a%2F..%2Fb/stream')
  })
})

describe('openTerminal', () => {
  let control: TerminalControl[]

  beforeEach(() => {
    FakeWebSocket.reset()
    vi.stubGlobal('WebSocket', FakeWebSocket)
    control = []
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.useRealTimers()
  })

  function open(opts = {}) {
    const s = openTerminal('sess-1', opts)
    s.onControl = (c) => control.push(c)
    return s
  }

  it('asks for binary frames as buffers, not blobs', () => {
    open()
    expect(FakeWebSocket.last.binaryType).toBe('arraybuffer')
  })

  it('parses the attach message, keeping counters out of Number', () => {
    open()
    FakeWebSocket.last.accept()
    FakeWebSocket.last.control(
      attachedMessage({ resume_offset: '9007199254740993', max_inflight_bytes: '262144' }),
    )
    expect(control).toEqual([
      {
        type: 'attached',
        sessionID: 'sess-1',
        connID: 'conn-a',
        resumeOffset: 9007199254740993n,
        gap: false,
        writer: true,
        holder: 'conn-a',
        maxInflightBytes: 262144n,
      },
    ])
  })

  it('hands output up with its absolute offset and the bytes untouched', () => {
    const s = open()
    const seen: { offset: bigint; bytes: number[] }[] = []
    s.onOutput = (offset, bytes) => seen.push({ offset, bytes: [...bytes] })
    FakeWebSocket.last.accept()
    FakeWebSocket.last.output(9007199254740993n, new Uint8Array([0xc3, 0xa9, 0x0a]))
    expect(seen).toEqual([{ offset: 9007199254740993n, bytes: [0xc3, 0xa9, 0x0a] }])
  })

  it('numbers input from one on every connection, because the guest drops what it has seen', () => {
    const s = open()
    FakeWebSocket.last.accept()
    s.send(new Uint8Array([0x61]))
    s.send(new Uint8Array([0x62]))
    expect(FakeWebSocket.last.binarySent()).toEqual([
      { seq: 1n, bytes: new Uint8Array([0x61]) },
      { seq: 2n, bytes: new Uint8Array([0x62]) },
    ])
  })

  it('sends the consumed offset as a decimal string', () => {
    const s = open()
    FakeWebSocket.last.accept()
    s.ack(9007199254740993n)
    expect(FakeWebSocket.last.textSent()).toEqual([{ type: 'ack', offset: '9007199254740993' }])
  })

  it('drops input while the socket is down rather than queueing a keystroke storm', () => {
    const s = open()
    s.send(new Uint8Array([0x61]))
    expect(FakeWebSocket.last.sent).toHaveLength(0)
  })

  it('coalesces a burst of resizes into one message', () => {
    vi.useFakeTimers()
    const s = open({ resizeDebounceMs: 150 })
    FakeWebSocket.last.accept()
    s.resize(24, 80)
    s.resize(25, 90)
    s.resize(30, 100)
    expect(FakeWebSocket.last.textSent()).toEqual([])
    vi.advanceTimersByTime(150)
    expect(FakeWebSocket.last.textSent()).toEqual([{ type: 'resize', rows: 30, cols: 100 }])
  })

  it('does not repeat a size the guest already has', () => {
    vi.useFakeTimers()
    const s = open({ resizeDebounceMs: 150 })
    FakeWebSocket.last.accept()
    s.resize(24, 80)
    vi.advanceTimersByTime(150)
    s.resize(24, 80)
    vi.advanceTimersByTime(150)
    expect(FakeWebSocket.last.textSent()).toEqual([{ type: 'resize', rows: 24, cols: 80 }])
  })

  it('holds a resize that happened while the socket was down and sends it on reconnect', () => {
    vi.useFakeTimers()
    const s = open({ resizeDebounceMs: 150, backoffMs: () => 1000 })
    FakeWebSocket.last.accept()
    FakeWebSocket.last.drop()
    s.resize(40, 120)
    // The debounce fires with nowhere to send: the size is held, not lost.
    vi.advanceTimersByTime(150)
    expect(FakeWebSocket.instances).toHaveLength(1)

    vi.advanceTimersByTime(1000)
    expect(FakeWebSocket.instances).toHaveLength(2)
    FakeWebSocket.last.accept()
    expect(FakeWebSocket.last.textSent()).toEqual([{ type: 'resize', rows: 40, cols: 120 }])
  })

  it('names each reconnect attempt and gives up with a reason', () => {
    vi.useFakeTimers()
    open({ maxAttempts: 2, backoffMs: () => 10 })
    FakeWebSocket.last.accept()

    FakeWebSocket.last.drop(1006, '')
    expect(control).toEqual([
      { type: 'reconnecting', attempt: 1, reason: 'the connection closed (code 1006)' },
    ])
    vi.advanceTimersByTime(10)
    expect(FakeWebSocket.instances).toHaveLength(2)

    FakeWebSocket.last.drop(1006, 'runner went away')
    expect(control[1]).toEqual({ type: 'reconnecting', attempt: 2, reason: 'runner went away' })
    vi.advanceTimersByTime(10)
    expect(FakeWebSocket.instances).toHaveLength(3)

    FakeWebSocket.last.drop()
    expect(control[2]).toEqual({
      type: 'closed',
      reason: 'the connection dropped and 2 reconnect attempts did not restore it',
    })
    vi.advanceTimersByTime(10_000)
    expect(FakeWebSocket.instances).toHaveLength(3)
  })

  it('starts the attempt count over once a connection sticks', () => {
    vi.useFakeTimers()
    open({ maxAttempts: 2, backoffMs: () => 10 })
    FakeWebSocket.last.accept()
    FakeWebSocket.last.drop()
    vi.advanceTimersByTime(10)
    FakeWebSocket.last.accept()
    FakeWebSocket.last.drop()
    expect(control.filter((c) => c.type === 'reconnecting')).toEqual([
      { type: 'reconnecting', attempt: 1, reason: 'the connection closed (code 1006)' },
      { type: 'reconnecting', attempt: 1, reason: 'the connection closed (code 1006)' },
    ])
  })

  it('stops for good when the shell exits', () => {
    vi.useFakeTimers()
    open({ maxAttempts: 5, backoffMs: () => 10 })
    FakeWebSocket.last.accept()
    FakeWebSocket.last.control({ type: 'closed', reason: 'shell exited', exit_code: 0 })
    FakeWebSocket.last.drop()
    vi.advanceTimersByTime(10_000)
    expect(FakeWebSocket.instances).toHaveLength(1)
    expect(control).toEqual([{ type: 'closed', reason: 'shell exited', exitCode: 0 }])
  })

  it('stops for good when the session itself is gone', () => {
    vi.useFakeTimers()
    open({ maxAttempts: 5, backoffMs: () => 10 })
    FakeWebSocket.last.accept()
    FakeWebSocket.last.control({
      type: 'error',
      cause: 'session_stale',
      message: 'the VM rebooted; this session belongs to the previous boot',
    })
    FakeWebSocket.last.drop()
    vi.advanceTimersByTime(10_000)
    expect(FakeWebSocket.instances).toHaveLength(1)
  })

  it('keeps reconnecting after an error the session can survive', () => {
    vi.useFakeTimers()
    open({ maxAttempts: 5, backoffMs: () => 10 })
    FakeWebSocket.last.accept()
    FakeWebSocket.last.control({ type: 'error', cause: 'malformed_message', message: 'nope' })
    FakeWebSocket.last.drop()
    vi.advanceTimersByTime(10)
    expect(FakeWebSocket.instances).toHaveLength(2)
  })

  it('reports a gap and a stolen lease as they arrive', () => {
    open()
    FakeWebSocket.last.accept()
    FakeWebSocket.last.control({ type: 'dropped', from_offset: '10', to_offset: '4096' })
    FakeWebSocket.last.control({
      type: 'lease',
      writer: false,
      holder: 'conn-b',
      reason: 'another connection took the writer lease',
    })
    expect(control).toEqual([
      { type: 'dropped', fromOffset: 10n, toOffset: 4096n },
      {
        type: 'lease',
        writer: false,
        holder: 'conn-b',
        reason: 'another connection took the writer lease',
      },
    ])
  })

  it('ignores a message it cannot read instead of tearing the session down', () => {
    open()
    FakeWebSocket.last.accept()
    FakeWebSocket.last.text('{not json')
    FakeWebSocket.last.control({ type: 'something_new' })
    expect(control).toEqual([])
  })

  it('closing on purpose does not reconnect', () => {
    vi.useFakeTimers()
    const s = open({ maxAttempts: 5, backoffMs: () => 10 })
    FakeWebSocket.last.accept()
    s.close()
    vi.advanceTimersByTime(10_000)
    expect(FakeWebSocket.instances).toHaveLength(1)
    expect(control).toEqual([])
  })

  it('asks for the writer lease in band', () => {
    const s = open()
    FakeWebSocket.last.accept()
    s.lease('steal')
    expect(FakeWebSocket.last.textSent()).toEqual([{ type: 'lease', mode: 'steal' }])
  })
})
