import type { Severity } from '../types'
import { SEVERITY_LABELS } from '../lib/labels'
import './SeverityBadge.css'

// Never colour alone: the word is always shown next to the colour (house style)
function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`severity-badge severity-${severity}`}>
      <span className="severity-dot" aria-hidden="true" />
      {SEVERITY_LABELS[severity]}
    </span>
  )
}

export default SeverityBadge
