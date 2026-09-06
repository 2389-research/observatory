// ABOUTME: The daemon's refusal is rendered whole, and rendered inert.
// ABOUTME: A message quoting a hostile VM name must not carry its escapes to the page (13.3).
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { OperationFailure } from './OperationFailure'
import { ApiFailure } from '../api'

const RLO = String.fromCodePoint(0x202e)

describe('OperationFailure', () => {
  it('renders the message, the cause and every remediation', () => {
    render(
      <OperationFailure
        failure={
          new ApiFailure(409, {
            code: 'insufficient_capacity',
            message: 'host cannot admit this VM',
            cause: 'admission_refused',
            retryable: false,
            remediation: [{ action: 'get', rationale: 'shows current reservations' }],
          })
        }
        fallback="The launch failed"
      />,
    )
    const alert = screen.getByRole('alert')
    expect(alert).toHaveTextContent('host cannot admit this VM')
    expect(alert).toHaveTextContent('admission_refused')
    expect(alert).toHaveTextContent('shows current reservations')
  })

  // The message and the cause are two facts, and rendered flush they read as one
  // mangled word. Measured 2026-09-06: a real refusal reached an operator as
  // "name is requiredbody_invalid". <strong> and <code> are both inline, JSX
  // drops the whitespace between elements, and `code` carries only a
  // font-family -- so nothing anywhere put a gap between them.
  it('separates the message from the cause code', () => {
    render(
      <OperationFailure
        failure={
          new ApiFailure(400, {
            code: 'malformed_request',
            message: 'name is required',
            cause: 'body_invalid',
            retryable: false,
          })
        }
        fallback="The launch failed"
      />,
    )
    const alert = screen.getByRole('alert')
    expect(alert.textContent).toContain('name is required body_invalid')
  })

  it('falls back to the status when the response carried no message', () => {
    render(<OperationFailure failure={new ApiFailure(502)} fallback="The launch failed" />)
    expect(screen.getByRole('alert')).toHaveTextContent('The launch failed (HTTP 502).')
  })

  it('neutralizes a message and a rationale that quote a hostile name', () => {
    render(
      <OperationFailure
        failure={
          new ApiFailure(400, {
            code: 'malformed_request',
            message: `vm ${RLO}gnp.exe is not a name`,
            cause: 'name_invalid',
            retryable: false,
            remediation: [{ action: 'get', rationale: `rename ${RLO}gnp.exe first` }],
          })
        }
        fallback="failed"
      />,
    )
    const alert = screen.getByRole('alert')
    expect(alert.textContent).toContain('<U+202E>')
    expect(alert.textContent).not.toContain(RLO)
  })
})
