import type { Client, Domain, Finding, ModuleName, ModuleRun, Risk, Scan, ScanStatus, ScanSummary } from '../types'
import { MODULES } from '../lib/labels'
import { computeRisk, NO_RISK } from '../lib/risk'
import { ApiError, type Api } from './api'
import { failingModule, findingTemplates, mockClients, mockScanHistory, type StoredClient } from './mockData'

// An in-memory imitation of the backend. A scan waits in the queue briefly and
// then runs the four modules one after another, like the Celery worker will.
const QUEUE_MS = 2_000
const MODULE_MS = 5_000
const LATENCY_MS = 250

const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/

type StoredScan = {
  id: number
  domainId: number
  startedAt: number
  findings: Finding[]
}

const clients: StoredClient[] = structuredClone(mockClients)
const scans: StoredScan[] = []
let nextClientId = Math.max(...clients.map((c) => c.id)) + 1
let nextDomainId = Math.max(...clients.flatMap((c) => c.domains.map((d) => d.id))) + 1
let nextScanId = 1
let nextFindingId = 1

for (const { domainId, startedAgoMs } of mockScanHistory) {
  createScan(domainId, Date.now() - startedAgoMs)
}

function delay<T>(value: () => T): Promise<T> {
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      try {
        resolve(structuredClone(value()))
      } catch (error) {
        reject(error)
      }
    }, LATENCY_MS)
  })
}

function findDomain(domainId: number): Domain {
  const domain = clients.flatMap((c) => c.domains).find((d) => d.id === domainId)
  if (!domain) throw new ApiError(404, 'Domain not found')
  return domain
}

function findScan(scanId: number): StoredScan {
  const scan = scans.find((s) => s.id === scanId)
  if (!scan) throw new ApiError(404, 'Scan not found')
  return scan
}

function createScan(domainId: number, startedAt: number): StoredScan {
  const domain = findDomain(domainId)
  const failing = failingModule(domain.name)
  const scan: StoredScan = {
    id: nextScanId++,
    domainId,
    startedAt,
    findings: findingTemplates(domain.name)
      .filter((f) => f.module !== failing?.module)
      .map((f) => ({ ...f, id: nextFindingId++, created_at: '' })),
  }
  scans.push(scan)
  return scan
}

/** Where a scan is now, computed from how long ago it started */
function progress(scan: StoredScan, now = Date.now()) {
  const domain = findDomain(scan.domainId)
  const failing = failingModule(domain.name)
  const elapsed = now - scan.startedAt
  const current = elapsed < QUEUE_MS ? -1 : Math.floor((elapsed - QUEUE_MS) / MODULE_MS)
  const finishedAt = (index: number) => new Date(scan.startedAt + QUEUE_MS + (index + 1) * MODULE_MS).toISOString()

  const modules: ModuleRun[] = MODULES.map((module, index) => {
    const fails = failing?.module === module
    const count = scan.findings.filter((f) => f.module === module).length
    if (index < current) {
      return fails
        ? { module, status: 'failed', finding_count: 0, error: failing.error }
        : { module, status: 'completed', finding_count: count, error: null }
    }
    return { module, status: index === current ? 'running' : 'pending', finding_count: 0, error: null }
  })

  let status: ScanStatus
  if (current < 0) status = 'queued'
  else if (current < MODULES.length) status = 'running'
  else status = modules.some((m) => m.status === 'failed') ? 'partial' : 'completed'

  const done = new Set<ModuleName>(modules.filter((m) => m.status === 'completed').map((m) => m.module))
  const findings = scan.findings
    .filter((f) => done.has(f.module))
    .map((f) => ({ ...f, created_at: finishedAt(MODULES.indexOf(f.module)) }))

  return { domain, status, modules, findings }
}

/** Risk of a scan (data contract 10.7): only completed and partial scans have a score */
function scanRisk(scan: StoredScan): Risk {
  const { status, findings } = progress(scan)
  return status === 'completed' || status === 'partial' ? computeRisk(findings.map((f) => f.severity)) : NO_RISK
}

function summary(scan: StoredScan): ScanSummary {
  return { id: scan.id, status: progress(scan).status, created_at: new Date(scan.startedAt).toISOString(), ...scanRisk(scan) }
}

/** A client's risk is that of its riskiest domain, using each domain's newest scored scan */
function withRisk(client: StoredClient): Client {
  const latest = client.domains.map((domain) =>
    scans
      .filter((s) => s.domainId === domain.id)
      .sort((a, b) => b.startedAt - a.startedAt)
      .map(scanRisk)
      .find((risk) => risk.risk_score !== null),
  )
  const scored = latest.filter((risk): risk is Risk => risk !== undefined)
  const worst = scored.sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0))[0]
  return { ...client, ...(worst ?? NO_RISK) }
}

export const mockApi: Api = {
  listClients: () => delay(() => clients.map(withRisk)),

  getClient: (clientId) =>
    delay(() => {
      const client = clients.find((c) => c.id === clientId)
      if (!client) throw new ApiError(404, 'Client not found')
      return {
        ...withRisk(client),
        domains: client.domains.map((domain) => ({
          ...domain,
          scans: scans
            .filter((s) => s.domainId === domain.id)
            .sort((a, b) => b.startedAt - a.startedAt)
            .map(summary),
        })),
      }
    }),

  createClient: (name) =>
    delay(() => {
      const trimmed = name.trim()
      if (!trimmed) throw new ApiError(422, 'Enter a client name.')
      if (clients.some((c) => c.name.toLowerCase() === trimmed.toLowerCase())) {
        throw new ApiError(409, `A client named ${trimmed} already exists.`)
      }
      const client: StoredClient = { id: nextClientId++, name: trimmed, domains: [] }
      clients.push(client)
      return withRisk(client)
    }),

  addDomain: (clientId, name) =>
    delay(() => {
      const client = clients.find((c) => c.id === clientId)
      if (!client) throw new ApiError(404, 'Client not found')
      const domainName = name.trim().toLowerCase()
      if (!DOMAIN_RE.test(domainName)) {
        throw new ApiError(422, 'Enter a domain name like example.be, without https:// or a path.')
      }
      if (clients.some((c) => c.domains.some((d) => d.name === domainName))) {
        throw new ApiError(409, `${domainName} is already added.`)
      }
      const domain: Domain = { id: nextDomainId++, name: domainName }
      client.domains.push(domain)
      return domain
    }),

  startScan: (domainId) =>
    delay(() => {
      findDomain(domainId)
      const active = scans.find((s) => s.domainId === domainId && ['queued', 'running'].includes(progress(s).status))
      if (active) throw new ApiError(409, 'A scan is already running for this domain.')
      return summary(createScan(domainId, Date.now()))
    }),

  getScan: (scanId) =>
    delay((): Scan => {
      const scan = findScan(scanId)
      const { domain, status, modules } = progress(scan)
      return {
        id: scan.id,
        domain: domain.name,
        status,
        created_at: new Date(scan.startedAt).toISOString(),
        modules,
        ...scanRisk(scan),
      }
    }),

  getFindings: (scanId) => delay(() => progress(findScan(scanId)).findings),
}
