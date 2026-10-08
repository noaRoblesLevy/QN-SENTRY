import type { ReactNode } from 'react'
import { CircleCheck, CircleDashed, CircleX, Clock, TriangleAlert } from 'lucide-react'
import type { ModuleStatus, ScanStatus } from '../types'
import { COMPLETED_WITH_WARNINGS, MODULE_STATUS_LABELS, SCAN_STATUS_LABELS } from '../lib/labels'
import Spinner from './Spinner'
import './StatusBadge.css'

type StatusBadgeProps =
  | { kind: 'scan'; status: ScanStatus }
  | { kind: 'module'; status: ModuleStatus; hasWarnings?: boolean }

const ICON = { size: 16, strokeWidth: 1.5, 'aria-hidden': true } as const

// Icon and tone per status. Status is not risk, so it never uses the severity colours.
const APPEARANCE: Record<ScanStatus | ModuleStatus, { icon: ReactNode; tone: 'muted' | 'active' | 'strong' }> = {
  pending: { icon: <CircleDashed {...ICON} />, tone: 'muted' },
  queued: { icon: <Clock {...ICON} />, tone: 'muted' },
  running: { icon: <Spinner />, tone: 'active' },
  completed: { icon: <CircleCheck {...ICON} />, tone: 'active' },
  partial: { icon: <TriangleAlert {...ICON} />, tone: 'strong' },
  failed: { icon: <CircleX {...ICON} />, tone: 'strong' },
}

function StatusBadge(props: StatusBadgeProps) {
  const withWarnings = props.kind === 'module' && props.status === 'completed' && props.hasWarnings
  const label = withWarnings
    ? COMPLETED_WITH_WARNINGS
    : props.kind === 'scan'
      ? SCAN_STATUS_LABELS[props.status]
      : MODULE_STATUS_LABELS[props.status]
  // Completed with warnings looks like a partial scan: done, but something needs a look
  const { icon, tone } = withWarnings ? APPEARANCE.partial : APPEARANCE[props.status]

  return (
    <span className={`status-badge status-${tone}`}>
      {icon}
      {label}
    </span>
  )
}

export default StatusBadge
