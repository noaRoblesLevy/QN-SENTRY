import type { Address, Client, Domain, Finding, Scan, ScanSummary } from '../types'

/** Everything the dashboard asks the backend (data contract 10.5). */
export type Api = {
  listClients(): Promise<Client[]>
  getClient(clientId: number): Promise<Client>
  createClient(name: string): Promise<Client>
  /** Rename a client; same rules as creating one (#16) */
  renameClient(clientId: number, name: string): Promise<Client>
  /** Delete a client with all its domains, scans and findings (#16, GDPR art. 17) */
  deleteClient(clientId: number): Promise<void>
  /** Delete a domain with its scans, findings and port scan approvals (#16) */
  deleteDomain(domainId: number): Promise<void>
  /** permissionConfirmed: the user confirmed they own the domain or may scan it (#3) */
  addDomain(clientId: number, name: string, permissionConfirmed: boolean): Promise<Domain>
  confirmPermission(domainId: number): Promise<Domain>
  /** Looks up the TXT record; fails with the reason when it is not there (#48) */
  verifyDomain(domainId: number): Promise<Domain>
  /** The addresses the latest scan found for the domain, and which may get a port scan (#81) */
  getAddresses(domainId: number): Promise<Address[]>
  /** Replaces the addresses that may get a port scan; [] clears them */
  setPortScanAddresses(domainId: number, ips: string[]): Promise<Address[]>
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
