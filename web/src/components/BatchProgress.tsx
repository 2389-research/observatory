// ABOUTME: One row per batch member, each carrying its own verdict, VM and typed cause (§13.1).
// ABOUTME: The header states the rollup only; the tally lives beside it so "partial" never reads "succeeded".
import { batchRollup, memberOutcome, BATCH_STATE_LABEL, MEMBER_OUTCOME_LABEL } from '../batch'
import type { BatchMember, BatchReply } from '../types'

/** The cause and message for this member, from whichever field the daemon used. */
function memberCause(member: BatchMember): { cause: string; message: string } | null {
  if (member.refusal) return member.refusal
  if (member.operation?.error) return member.operation.error
  return null
}

function MemberRow({ member }: { member: BatchMember }) {
  const outcome = memberOutcome(member)
  const cause = memberCause(member)
  return (
    <li className={`member-row member-${outcome}`} data-testid={`member-row-${member.position}`}>
      <span className="member-name">{member.name || `member ${member.position}`}</span>
      <span className="member-outcome">{MEMBER_OUTCOME_LABEL[outcome]}</span>
      {member.vm?.vm_id && (
        <span className="member-vm">
          vm <code>{member.vm.vm_id}</code>
        </span>
      )}
      {member.operation?.operation_id && (
        <span className="member-op">
          operation <code>{member.operation.operation_id}</code>
        </span>
      )}
      {cause && (
        <span className="member-cause">
          <code>{cause.cause}</code> {cause.message}
        </span>
      )}
    </li>
  )
}

interface Props {
  reply: BatchReply
  /** True while the page is still re-reading the batch, so a stale row says so. */
  polling: boolean
  /** Set when a poll failed: the rows below are the last answer, not the current one. */
  pollError?: string
}

export function BatchProgress({ reply, polling, pollError }: Props) {
  const state = batchRollup(reply.members)
  const tally = reply.members.reduce<Record<string, number>>((acc, m) => {
    const outcome = memberOutcome(m)
    acc[outcome] = (acc[outcome] ?? 0) + 1
    return acc
  }, {})

  return (
    <section className="batch-progress" aria-labelledby="batch-progress-heading">
      <h3 id="batch-progress-heading">
        Batch <code>{reply.batch.batch_id}</code>
      </h3>

      <p className="batch-result" data-testid="batch-result">
        {reply.is_replay
          ? 'Replay of an earlier request — no second batch. '
          : 'Batch accepted. '}
        {reply.batch.reservation_mode} · on failure {reply.batch.on_failure}
      </p>

      <p>
        <span className={`batch-state batch-${state}`} data-testid="batch-state">
          {BATCH_STATE_LABEL[state]}
        </span>{' '}
        <span className="batch-tally" data-testid="batch-tally">
          {Object.entries(tally)
            .map(([outcome, n]) => `${n} ${MEMBER_OUTCOME_LABEL[outcome as keyof typeof MEMBER_OUTCOME_LABEL]}`)
            .join(' · ')}
        </span>
        {polling && <span className="hint"> re-reading…</span>}
      </p>

      {pollError && (
        <p className="alert" role="alert" data-testid="batch-poll-error">
          The rows below are the last answer this page got, not the current one. {pollError}
        </p>
      )}

      <ul className="member-rows">
        {reply.members.map((m) => (
          <MemberRow key={m.position} member={m} />
        ))}
      </ul>
    </section>
  )
}
