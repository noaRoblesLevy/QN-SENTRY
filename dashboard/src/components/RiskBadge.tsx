import type { Risk } from '../types'
import { RISK_LABELS } from '../lib/risk'
import './RiskBadge.css'

// Risk colours reuse the severity scale: the house style keeps colour for risk only,
// and always shows the word next to it
const TONE = { low: 'low', moderate: 'medium', high: 'high', very_high: 'critical' } as const

/** "75 Very high" for a scored scan or client; "No score yet" otherwise. A score from a
 * partial scan gets an asterisk: a failed module may have missed findings. */
function RiskBadge({ risk, showScore = true }: { risk: Risk; showScore?: boolean }) {
  if (risk.risk_score === null || risk.risk_level === null) {
    return <span className="risk-none">No score yet</span>
  }
  const incomplete = risk.risk_complete === false
  const title = incomplete
    ? 'Risk score from 0 to 100, incomplete: a module failed in this scan, so findings may be missing'
    : 'Risk score from 0 to 100 (data contract 10.7)'
  return (
    <span className={`risk-badge risk-${TONE[risk.risk_level]}`} title={title}>
      {showScore && <strong>{risk.risk_score}</strong>}
      {RISK_LABELS[risk.risk_level]}
      {incomplete && <span aria-label="incomplete">*</span>}
    </span>
  )
}

export default RiskBadge
