import type { Risk, RiskLevel, Severity } from '../types'

// Same method as the backend (backend/qnsentry/risk.py, data contract 10.7).
// Only used by the mock API; with the real backend the score comes from the API.
const WEIGHTS: Record<Severity, number> = { critical: 25, high: 10, medium: 4, low: 1, info: 0 }
const SCALE = 50

export const RISK_LABELS: Record<RiskLevel, string> = {
  low: 'Low',
  moderate: 'Moderate',
  high: 'High',
  very_high: 'Very high',
}

export function computeRisk(severities: Severity[]): Risk {
  const points = severities.reduce((sum, severity) => sum + WEIGHTS[severity], 0)
  const score = Math.round(100 * (1 - Math.exp(-points / SCALE)))
  const level: RiskLevel = score >= 75 ? 'very_high' : score >= 50 ? 'high' : score >= 25 ? 'moderate' : 'low'
  return { risk_score: score, risk_level: level }
}

export const NO_RISK: Risk = { risk_score: null, risk_level: null }
