// ABOUTME: The daemon's own typed refusal, rendered whole: message, cause, every remediation.
// ABOUTME: Never a browser's paraphrase of why a request was refused (SPEC P-06).
import { neutralize } from '../text'
import type { ApiFailure } from '../api'

interface Props {
  failure: ApiFailure | undefined
  /** Used only when the response carried no message of its own. */
  fallback: string
}

export function OperationFailure({ failure, fallback }: Props) {
  if (!failure) return null
  return (
    <div className="alert" role="alert">
      {/* A refusal quotes what it refused, so a hostile VM name reaches this
          text. Neutralized here, not at the call sites, so every alert on the
          page is inert by construction (SPEC 13.3). */}
      <strong>
        {failure.error?.message ? neutralize(failure.error.message) : `${fallback} (HTTP ${failure.status}).`}
      </strong>{' '}
      {/* The space is written, not left to CSS. Both elements are inline and
          JSX drops the whitespace between them, so without it the sentence and
          the machine code arrive as one word -- and copied text and a screen
          reader would carry the same mangling however the chip is painted. */}
      {failure.error?.cause && <code className="cause">{neutralize(failure.error.cause)}</code>}
      {failure.error?.remediation && failure.error.remediation.length > 0 && (
        <ul className="remediation-list">
          {failure.error.remediation.map((r) => (
            <li key={r.action}>
              <code>{neutralize(r.action)}</code> {neutralize(r.rationale)}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
