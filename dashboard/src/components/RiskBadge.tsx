import type { Risk } from '../types'
import { RISK_LABELS } from '../lib/risk'
import './RiskBadge.css'

// Risk colours reuse the severity scale: the house style keeps colour for risk only,
// and always shows the word next to it
const TONE = { low: 'low', moderate: 'medium', high: 'high', very_high: 'critical' } as const

/** "75 Very high" for a scored scan or client; "No score yet" otherwise */
function RiskBadge({ risk, showScore = true }: { risk: Risk; showScore?: boolean }) {
  if (risk.risk_score === null || risk.risk_level === null) {
    return <span className="risk-none">No score yet</span>
  }
  return (
    <span className={`risk-badge risk-${TONE[risk.risk_level]}`} title="Risk score from 0 to 100 (data contract 10.7)">
      {showScore && <strong>{risk.risk_score}</strong>}
      {RISK_LABELS[risk.risk_level]}
    </span>
  )
}

export default RiskBadge
