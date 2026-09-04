// ABOUTME: The batch rollup rule from SPEC §13.1: a batch never reads better than its weakest member.
// ABOUTME: Pure functions, so the honesty rule is testable without rendering anything.
import type { BatchMember } from './types'

/**
 * What the daemon has said about one member.
 *
 * `unknown` is a real answer: a member carrying neither an operation nor a
 * refusal has no verdict, and calling that success or failure would invent one.
 */
export type MemberOutcome = 'succeeded' | 'failed' | 'refused' | 'in_progress' | 'unknown'

export type BatchState = 'succeeded' | 'partial' | 'failed' | 'in_progress'

/**
 * A member's outcome, read from its operation rather than its VM.
 *
 * The operation is the launch's own verdict. A VM row can say `running` while
 * its launch operation is still finishing, and the reverse during teardown.
 */
export function memberOutcome(member: BatchMember): MemberOutcome {
  if (member.refusal) return 'refused'
  if (!member.operation) return 'unknown'
  switch (member.operation.state) {
    case 'succeeded':
      return 'succeeded'
    case 'failed':
      return 'failed'
    default:
      return 'in_progress'
  }
}

/** True once this member can no longer change: it succeeded, failed or was refused. */
export function memberTerminal(member: BatchMember): boolean {
  const outcome = memberOutcome(member)
  return outcome === 'succeeded' || outcome === 'failed' || outcome === 'refused'
}

/** Polling stops on this, so `unknown` deliberately keeps it false. */
export function everyMemberTerminal(members: BatchMember[]): boolean {
  return members.length > 0 && members.every(memberTerminal)
}

/**
 * The batch's headline state.
 *
 * SPEC §13.1: "Do not make a batch look successful because its first member
 * started." Anything unresolved holds the whole batch at `in_progress`, and an
 * empty batch is `in_progress` rather than vacuously successful.
 */
export function batchRollup(members: BatchMember[]): BatchState {
  if (!everyMemberTerminal(members)) return 'in_progress'
  const succeeded = members.filter((m) => memberOutcome(m) === 'succeeded').length
  if (succeeded === members.length) return 'succeeded'
  if (succeeded === 0) return 'failed'
  return 'partial'
}

/** The words a reader sees, kept next to the rule that produces them. */
export const BATCH_STATE_LABEL: Record<BatchState, string> = {
  succeeded: 'succeeded',
  partial: 'partial',
  failed: 'failed',
  in_progress: 'in progress',
}

export const MEMBER_OUTCOME_LABEL: Record<MemberOutcome, string> = {
  succeeded: 'succeeded',
  failed: 'failed',
  refused: 'refused',
  in_progress: 'in progress',
  unknown: 'no verdict yet',
}
