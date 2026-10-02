import type { ModuleName, ModuleStatus, ScanStatus, Severity } from '../types'

// Highest first: used for sorting and for the summary tiles
export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

// Same order as the worker runs them (data contract 10.4.1)
export const MODULES: ModuleName[] = ['attack_surface', 'metadata', 'phishing', 'breach']

export const SEVERITY_LABELS: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
}

export const MODULE_LABELS: Record<ModuleName, string> = {
  attack_surface: 'Attack surface',
  metadata: 'Document metadata',
  phishing: 'Phishing domains',
  breach: 'Employee breaches',
}

export const SCAN_STATUS_LABELS: Record<ScanStatus, string> = {
  queued: 'Queued',
  running: 'Running',
  completed: 'Completed',
  partial: 'Completed with errors',
  failed: 'Failed',
}

// A completed module with warnings keeps the status "completed" (#32); only the label differs
export const COMPLETED_WITH_WARNINGS = 'Completed with warnings'

export const MODULE_STATUS_LABELS: Record<ModuleStatus, string> = {
  pending: 'Waiting',
  running: 'Running',
  completed: 'Completed',
  failed: 'Failed',
}

export function severityRank(severity: Severity): number {
  return SEVERITIES.indexOf(severity)
}

export function isScanActive(status: ScanStatus): boolean {
  return status === 'queued' || status === 'running'
}
