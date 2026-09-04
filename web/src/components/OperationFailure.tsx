// ABOUTME: The daemon's own typed refusal, rendered whole: message, cause, every remediation.
// ABOUTME: Never a browser's paraphrase of why a request was refused (SPEC P-06).
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
      <strong>{failure.error?.message ?? `${fallback} (HTTP ${failure.status}).`}</strong>
      {failure.error?.cause && <code>{failure.error.cause}</code>}
      {failure.error?.remediation && failure.error.remediation.length > 0 && (
        <ul className="remediation-list">
          {failure.error.remediation.map((r) => (
            <li key={r.action}>
              <code>{r.action}</code> {r.rationale}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
