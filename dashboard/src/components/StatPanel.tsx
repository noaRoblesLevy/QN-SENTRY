import type { ReactNode } from 'react'
import { formatNumber } from '../lib/format'
import './StatPanel.css'

type StatPanelProps = {
  label: ReactNode
  value: number
}

function StatPanel({ label, value }: StatPanelProps) {
  return (
    <div className="stat-panel">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{formatNumber(value)}</div>
    </div>
  )
}

export default StatPanel
