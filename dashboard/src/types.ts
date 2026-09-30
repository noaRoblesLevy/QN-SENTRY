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
}

export type ScanSummary = Risk & {
  id: number
  status: ScanStatus
  created_at: string
}

export type Domain = {
  id: number
  name: string
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
