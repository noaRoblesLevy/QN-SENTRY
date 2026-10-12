// Types follow the data contract in docs/project/10-data-contract.md

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export type ModuleName = 'attack_surface' | 'metadata' | 'phishing' | 'breach'

export type ScanStatus = 'queued' | 'running' | 'completed' | 'partial' | 'failed'

export type ModuleStatus = 'pending' | 'running' | 'completed' | 'failed'

// Risk score (data contract 10.7): null while a scan runs, when it failed, or without scans
export type RiskLevel = 'low' | 'moderate' | 'high' | 'very_high'

export type Risk = {
  risk_score: number | null
  risk_level: RiskLevel | null
  // false when the score comes from a partial scan (a module failed)
  risk_complete: boolean | null
}

export type ScanSummary = Risk & {
  id: number
  status: ScanStatus
  created_at: string
}

export type Domain = {
  id: number
  name: string
  // A scan needs both (#3, #48)
  permission_confirmed: boolean
  verified: boolean
  // The TXT record that proves ownership, e.g. "qn-sentry-verify=3f9a..."
  verification_record: string
  // Addresses the user confirmed may get a port scan (#81)
  port_scan_ips: string[]
  // Only included by GET /api/clients/{id}, newest first
  scans?: ScanSummary[]
}

export type Client = Risk & {
  id: number
  name: string
  domains: Domain[]
}

export type ModuleRun = {
  module: ModuleName
  status: ModuleStatus
  finding_count: number
  error: string | null
  // Problems that did not stop the module, one readable sentence each; [] when there are none
  // (data contract, open question 4 of #32). The status stays "completed".
  warnings: string[]
}

export type Scan = Risk & {
  id: number
  domain: string
  status: ScanStatus
  created_at: string
  modules: ModuleRun[]
}

export type Finding = {
  id: number
  module: ModuleName
  type: string
  title: string
  description: string
  severity: Severity
  asset: string
  details: Record<string, unknown>
  created_at: string
}

/** An address of a domain's hosts, and whether it may get a port scan (#81) */
export type Address = {
  ip: string
  // Host names that resolved to it in the latest scan; [] for an approved address the
  // latest scan did not see anymore
  hosts: string[]
  approved: boolean
}
