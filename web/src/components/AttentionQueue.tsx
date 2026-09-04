// ABOUTME: The attention queue head — what the host wants an operator to look at first.
// ABOUTME: Summaries come from guest-influenced text, so every one goes through neutralize().
import type { Attention } from '../types'
import { neutralize } from '../text'

export function AttentionQueue({ items }: { items: Attention[] }) {
  if (items.length === 0) {
    return <p className="empty">Nothing needs attention.</p>
  }
  return (
    <ul className="attention">
      {items.map((a) => (
        <li className={a.acked ? 'attn acked' : 'attn'} key={a.attention_id}>
          <div className="attn-head">
            <span className={`sev sev-${a.severity}`}>{a.severity}</span>
            <span className="attn-kind">{neutralize(a.kind)}</span>
            {a.count !== '1' && <span className="attn-count">×{a.count}</span>}
            {a.acked && <span className="attn-acked">acked</span>}
          </div>
          <div className="attn-summary" data-testid="attention-summary">
            {neutralize(a.summary)}
          </div>
          <div className="attn-action">{neutralize(a.system_action)}</div>
          {a.evidence_links.length > 0 && (
            <div className="attn-links">
              {a.evidence_links.map((href) => (
                <a href={href} key={href}>
                  evidence
                </a>
              ))}
            </div>
          )}
        </li>
      ))}
    </ul>
  )
}
