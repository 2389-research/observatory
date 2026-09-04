// ABOUTME: The §13.1 launch controls this milestone cannot honour, shown disabled with the milestone that lands them.
// ABOUTME: A control the API would ignore is worse than a control that says why it is off.
import type { VMDefaults } from '../types'

interface Props {
  idPrefix: string
  defaults: VMDefaults
}

export function DeferredFields({ idPrefix, defaults }: Props) {
  const id = (field: string) => `${idPrefix}-${field}`
  return (
    <fieldset className="deferred" data-testid="deferred-fields">
      <legend>Set by the host, not by this form</legend>
      <p className="field">
        <label htmlFor={id('privilege')}>Guest privilege</label>
        <input id={id('privilege')} value={defaults.guest_privilege} disabled readOnly />
        <span className="hint">Host default. The API accepts no per-VM override yet.</span>
      </p>
      <p className="field">
        <label htmlFor={id('network-profile')}>Network profile</label>
        <input id={id('network-profile')} value={defaults.network_profile} disabled readOnly />
        <span className="hint">Host default — selectable in M2, when network profiles exist.</span>
      </p>
      <p className="field">
        <label htmlFor={id('network-policy')}>Network policy</label>
        <input id={id('network-policy')} value={defaults.network_policy_id} disabled readOnly />
        <span className="hint">Empty on this host — M2.</span>
      </p>
      <p className="field">
        <label htmlFor={id('seed')}>Workspace seed</label>
        <input id={id('seed')} value="" disabled readOnly />
        <span className="hint">Not accepted by the API — M4.</span>
      </p>
      <p className="field">
        <label htmlFor={id('exec')}>Initial command</label>
        <input id={id('exec')} value="" disabled readOnly />
        <span className="hint">Not accepted by the API — M4.</span>
      </p>
      <p className="field">
        <label htmlFor={id('capture')}>Capture policy</label>
        <input id={id('capture')} value="" disabled readOnly />
        <span className="hint">Not accepted by the API — M3.</span>
      </p>
    </fieldset>
  )
}
