// ABOUTME: Tests for the terminal view: real xterm.js, real framing, stubbed WebSocket.
// ABOUTME: Every §8.2 state, the §8.3 ack rule and AT-028's two denials are asserted here.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Terminal } from './Terminal'
import { FakeWebSocket } from './test/fakeSocket'

function attached(over: Record<string, unknown> = {}) {
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

/** Let xterm's write queue drain and its renderer paint. */
async function painted(): Promise<void> {
  await act(async () => {
    await new Promise((r) => setTimeout(r, 50))
  })
}

function state(): string {
  return screen.getByTestId('terminal-state').textContent ?? ''
}

function screenText(container: HTMLElement): string {
  return container.querySelector('.terminal-screen')?.textContent ?? ''
}

describe('Terminal', () => {
  let writeText: ReturnType<typeof vi.fn>

  beforeEach(() => {
    FakeWebSocket.reset()
    vi.stubGlobal('WebSocket', FakeWebSocket)
    writeText = vi.fn()
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.useRealTimers()
  })

  it('says it is connecting before the host has said anything', () => {
    render(<Terminal sessionId="sess-1" rows={24} cols={80} />)
    expect(state()).toBe('connecting')
  })

  it('writes guest bytes intact when a character is split across two frames', async () => {
    const { container } = render(<Terminal sessionId="sess-1" rows={24} cols={80} />)
    act(() => {
      FakeWebSocket.last.accept()
      FakeWebSocket.last.control(attached())
      // 'é' is 0xC3 0xA9. A decoder per frame would render two replacement
      // characters; the stateful decoder inside xterm renders one letter.
      FakeWebSocket.last.output(0n, new Uint8Array([0x63, 0x61, 0x66, 0xc3]))
      FakeWebSocket.last.output(4n, new Uint8Array([0xa9]))
    })
    await painted()
    expect(screenText(container)).toContain('café')
  })

  it('acks only after the bytes are on screen, and acks the consumed offset', async () => {
    render(<Terminal sessionId="sess-1" rows={24} cols={80} />)
    act(() => {
      FakeWebSocket.last.accept()
      FakeWebSocket.last.control(attached({ resume_offset: '9007199254740993' }))
      FakeWebSocket.last.output(9007199254740993n, new Uint8Array([0x68, 0x69]))
    })
    // Acking here would measure the network, not the browser (§8.3).
    expect(FakeWebSocket.last.textSent()).toEqual([])
    await painted()
    expect(FakeWebSocket.last.textSent()).toEqual([{ type: 'ack', offset: '9007199254740995' }])
  })

  it('renders a guest drop as a divider naming both offsets, and resets the screen', async () => {
    const { container } = render(<Terminal sessionId="sess-1" rows={24} cols={80} />)
    act(() => {
      FakeWebSocket.last.accept()
      FakeWebSocket.last.control(attached())
      FakeWebSocket.last.output(0n, new TextEncoder().encode('older output'))
    })
    await painted()
    expect(screenText(container)).toContain('older output')

    act(() => {
      FakeWebSocket.last.control({ type: 'dropped', from_offset: '12', to_offset: '4096' })
    })
    await painted()
    expect(container.textContent).toContain('output between byte 12 and byte 4096 was dropped')
    expect(screenText(container)).not.toContain('older output')
  })

  it('renders a replay gap on reattach the same way', async () => {
    const { container } = render(<Terminal sessionId="sess-1" rows={24} cols={80} />)
    act(() => {
      FakeWebSocket.last.accept()
      FakeWebSocket.last.control(attached({ gap: true, resume_offset: '65536' }))
    })
    await painted()
    expect(container.textContent).toContain('output between byte 0 and byte 65536 was dropped')
  })

  it('sends what the writer types, numbered for the guest', async () => {
    const { container } = render(<Terminal sessionId="sess-1" rows={24} cols={80} />)
    act(() => {
      FakeWebSocket.last.accept()
      FakeWebSocket.last.control(attached())
    })
    await painted()

    container.querySelector('textarea')?.focus()
    await userEvent.keyboard('hi')
    expect(FakeWebSocket.last.binarySent()).toEqual([
      { seq: 1n, bytes: new Uint8Array([0x68]) },
      { seq: 2n, bytes: new Uint8Array([0x69]) },
    ])
  })

  it('names the writer when this view is read-only and sends no keystrokes', async () => {
    const { container } = render(<Terminal sessionId="sess-1" rows={24} cols={80} />)
    act(() => {
      FakeWebSocket.last.accept()
      FakeWebSocket.last.control(attached({ writer: false, holder: 'conn-b' }))
    })
    await waitFor(() => expect(state()).toBe('attached (read-only — conn-b is writing)'))

    container.querySelector('textarea')?.focus()
    await userEvent.keyboard('rm -rf /{Enter}')
    expect(FakeWebSocket.last.binarySent()).toEqual([])
  })

  it('follows a lease change live', async () => {
    render(<Terminal sessionId="sess-1" rows={24} cols={80} />)
    act(() => {
      FakeWebSocket.last.accept()
      FakeWebSocket.last.control(attached())
    })
    await waitFor(() => expect(state()).toBe('attached (writer)'))

    act(() => {
      FakeWebSocket.last.control({
        type: 'lease',
        writer: false,
        holder: 'conn-b',
        reason: 'another connection took the writer lease',
      })
    })
    await waitFor(() => expect(state()).toBe('attached (read-only — conn-b is writing)'))
    expect(screen.getByText(/another connection took the writer lease/)).toBeInTheDocument()
  })

  it('lets a read-only view ask for the shell', async () => {
    render(<Terminal sessionId="sess-1" rows={24} cols={80} />)
    act(() => {
      FakeWebSocket.last.accept()
      FakeWebSocket.last.control(attached({ writer: false, holder: 'conn-b' }))
    })
    await userEvent.click(await screen.findByRole('button', { name: /take the writer lease/i }))
    expect(FakeWebSocket.last.textSent()).toEqual([{ type: 'lease', mode: 'steal' }])
  })

  it('sends a size change once, debounced', async () => {
    const view = render(<Terminal sessionId="sess-1" rows={24} cols={80} />)
    act(() => {
      FakeWebSocket.last.accept()
      FakeWebSocket.last.control(attached())
    })
    await painted()

    view.rerender(<Terminal sessionId="sess-1" rows={30} cols={100} />)
    view.rerender(<Terminal sessionId="sess-1" rows={40} cols={120} />)
    await waitFor(() =>
      expect(FakeWebSocket.last.textSent().filter((m) => m.type === 'resize')).toEqual([
        { type: 'resize', rows: 40, cols: 120 },
      ]),
    )
  })

  it('walks the named reconnect states and lands on a reason', () => {
    vi.useFakeTimers()
    render(<Terminal sessionId="sess-1" rows={24} cols={80} />)
    act(() => {
      FakeWebSocket.last.accept()
      FakeWebSocket.last.control(attached())
    })
    expect(state()).toBe('attached (writer)')

    act(() => FakeWebSocket.last.drop(1006, 'runner went away'))
    expect(state()).toBe('reconnecting (attempt 1) — runner went away')

    act(() => {
      FakeWebSocket.last.control({ type: 'closed', reason: 'the shell exited', exit_code: 0 })
    })
    expect(state()).toBe('closed (the shell exited, exit code 0)')
  })

  it('never hands the guest the operator clipboard', async () => {
    const { container } = render(<Terminal sessionId="sess-1" rows={24} cols={80} />)
    act(() => {
      FakeWebSocket.last.accept()
      FakeWebSocket.last.control(attached())
      // OSC 52 asks a terminal to load the clipboard. AT-028 says no.
      const osc = new TextEncoder().encode('\x1b]52;c;aGVsbG8=\x07done')
      FakeWebSocket.last.output(0n, osc)
    })
    await painted()
    expect(writeText).not.toHaveBeenCalled()
    expect(screenText(container)).not.toContain('aGVsbG8=')
    expect(screenText(container)).toContain('done')
  })

  it('keeps hostile output as text, never as markup', async () => {
    const { container } = render(<Terminal sessionId="sess-1" rows={24} cols={80} />)
    act(() => {
      FakeWebSocket.last.accept()
      FakeWebSocket.last.control(attached())
      FakeWebSocket.last.output(0n, new TextEncoder().encode('<img src=x onerror=boom>'))
    })
    await painted()
    expect(container.querySelector('img')).toBeNull()
    expect(screenText(container)).toContain('<img src=x onerror=boom>')
  })

  it('closes the stream when it goes away', () => {
    const view = render(<Terminal sessionId="sess-1" rows={24} cols={80} />)
    act(() => FakeWebSocket.last.accept())
    const socket = FakeWebSocket.last
    view.unmount()
    expect(socket.readyState).toBe(FakeWebSocket.CLOSED)
  })
})
