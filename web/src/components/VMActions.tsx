// ABOUTME: The VM detail workspace's lifecycle action row (SPEC §13.2), for the one VM on screen.
// ABOUTME: Same controls, same legality rules and same delete confirm as the fleet page's row.
import type { VM } from '../types'
import {
  ACTION_LABEL,
  DeleteConfirm,
  RowResult,
  actionLegality,
  type FleetControls,
  type RowAction,
} from './BulkActions'

/**
 * What the detail workspace offers, in button order.
 *
 * §13.2's row lists Force stop where §13.1's multi-select does not, and that is
 * the difference kept here: forcing a whole selection at once is a bigger
 * gesture than §13.1 asks for, while on the single VM an operator is looking at
 * it is the action the spec names. Export and Clone template are in §13.2's
 * sketch too; the routes behind them are registered stubs in this build, so a
 * button for either would be a control that cannot work.
 */
export const DETAIL_ACTIONS: readonly RowAction[] = ['start', 'pause', 'resume', 'stop', 'force_stop', 'delete']

/**
 * The action row on the VM detail workspace.
 *
 * It shares `useFleetControls` with the fleet page rather than keeping a second
 * copy of the legality rules and the delete gesture: one definition of what an
 * action is legal on, and one prompt in front of every DELETE.
 */
export function VMActions({ vm, controls }: { vm: VM; controls: FleetControls }) {
  return (
    <div className="vm-actions" data-testid="vm-actions">
      <div className="row-actions">
        {DETAIL_ACTIONS.map((action) => {
          const { allowed, reason } = actionLegality(vm, action)
          return (
            <button
              key={action}
              type="button"
              className="row-action"
              disabled={!allowed || controls.busy}
              title={allowed ? undefined : reason}
              aria-label={allowed ? undefined : `${ACTION_LABEL[action]} ${reason}`}
              onClick={() => {
                if (action === 'delete') controls.askDelete([vm])
                else void controls.run([vm], action)
              }}
            >
              {ACTION_LABEL[action]}
            </button>
          )
        })}
      </div>
      <DeleteConfirm controls={controls} />
      <RowResult vm={vm} controls={controls} />
    </div>
  )
}
