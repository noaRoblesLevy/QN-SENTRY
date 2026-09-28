import type { Client, Domain, Finding, Scan, ScanSummary } from '../types'

/** Everything the dashboard asks the backend (data contract 10.5). */
export type Api = {
  listClients(): Promise<Client[]>
  getClient(clientId: number): Promise<Client>
  createClient(name: string): Promise<Client>
  addDomain(clientId: number, name: string): Promise<Domain>
  startScan(domainId: number): Promise<ScanSummary>
  getScan(scanId: number): Promise<Scan>
  getFindings(scanId: number): Promise<Finding[]>
}

export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}
