import { Fragment, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import { CircleCheck, Copy, Radar, ShieldCheck } from 'lucide-react'
import { api } from '../api'
import Button from '../components/Button'
import InlineAddForm from '../components/InlineAddForm'
import PageHeader from '../components/PageHeader'
import PortScanScope from '../components/PortScanScope'
import Panel from '../components/Panel'
import RelativeTime from '../components/RelativeTime'
import { EmptyState, ErrorState, LoadingState } from '../components/States'
import RiskBadge from '../components/RiskBadge'
import StatusBadge from '../components/StatusBadge'
import { useAsync } from '../hooks/useAsync'
import { plural } from '../lib/format'
import { isScanActive } from '../lib/labels'
import type { Client, Domain } from '../types'
import NotFoundPage from './NotFoundPage'
import './ClientPage.css'

const POLL_MS = 5_000

/** A scan needs confirmed permission (#3) and verified ownership (#48) */
function canScan(domain: Domain): boolean {
  return domain.permission_confirmed && domain.verified
}

function hasActiveScan(client: Client): boolean {
  return client.domains.some((domain) => domain.scans?.some((scan) => isScanActive(scan.status)))
}

function ClientPage() {
  const clientId = Number(useParams().clientId)
  if (!Number.isInteger(clientId)) return <NotFoundPage />
  return <ClientView clientId={clientId} />
}

function ClientView({ clientId }: { clientId: number }) {
  const navigate = useNavigate()
  const { data: client, error, loading, reload } = useAsync(`client-${clientId}`, () => api.getClient(clientId), {
    // Keep the scan statuses fresh while a scan runs (data contract 10.5.1)
    pollInterval: (data) => (hasActiveScan(data) ? POLL_MS : null),
  })
  const [startingDomainId, setStartingDomainId] = useState<number>()
  const [scanError, setScanError] = useState<string>()
  // Confirming or verifying one domain at a time, with the error per domain
  const [checkingDomainId, setCheckingDomainId] = useState<number>()
  const [checkErrors, setCheckErrors] = useState<Record<number, string>>({})
  const [copiedDomainId, setCopiedDomainId] = useState<number>()

  async function checkDomain(domain: Domain, action: (domainId: number) => Promise<Domain>) {
    setCheckingDomainId(domain.id)
    setCheckErrors((errors) => ({ ...errors, [domain.id]: '' }))
    try {
      await action(domain.id)
      reload()
    } catch (err) {
      setCheckErrors((errors) => ({
        ...errors,
        [domain.id]: err instanceof Error ? err.message : 'Something went wrong. Try again.',
      }))
    } finally {
      setCheckingDomainId(undefined)
    }
  }

  async function copyRecord(domain: Domain) {
    try {
      await navigator.clipboard.writeText(domain.verification_record)
      setCopiedDomainId(domain.id)
    } catch {
      // Clipboard access can be blocked; the record stays selectable on screen
    }
  }

  async function startScan(domain: Domain) {
    setStartingDomainId(domain.id)
    setScanError(undefined)
    try {
      const scan = await api.startScan(domain.id)
      navigate(`/scans/${scan.id}`)
    } catch (err) {
      setScanError(`Could not start a scan of ${domain.name}: ${err instanceof Error ? err.message : 'unknown error'}`)
      setStartingDomainId(undefined)
      // A withdrawn verification (the TXT record was removed) shows the verification step again
      reload()
    }
  }

  async function addDomain(name: string, permissionConfirmed: boolean) {
    await api.addDomain(clientId, name, permissionConfirmed)
    reload()
  }

  if (loading) return <LoadingState label="Loading client" />
  if (error || !client) {
    return (
      <>
        <PageHeader title="Client" breadcrumbs={[{ label: 'Clients', to: '/' }]} />
        <Panel title="Could not load this client">
          <ErrorState error={error ?? new Error('Client not found')} onRetry={reload} />
        </Panel>
      </>
    )
  }

  const scanHistory = client.domains
    .flatMap((domain) => (domain.scans ?? []).map((scan) => ({ ...scan, domain: domain.name })))
    .sort((a, b) => b.created_at.localeCompare(a.created_at))

  return (
    <>
      <PageHeader
        title={client.name}
        breadcrumbs={[{ label: 'Clients', to: '/' }, { label: client.name }]}
        meta={
          <>
            <span>{plural(client.domains.length, 'domain')}</span>
            <RiskBadge risk={client} />
          </>
        }
      />

      <Panel title="Domains" meta="Run a scan to assess what an attacker can find about a domain." flush>
        {scanError && (
          <p className="inline-alert" role="alert">
            {scanError}
          </p>
        )}
        {client.domains.length === 0 ? (
          <EmptyState title="No domains yet">Add a domain below to run the first scan.</EmptyState>
        ) : (
          <table className="data-table domains-table">
            <thead>
              <tr>
                <th scope="col">Domain</th>
                <th scope="col">Ownership</th>
                <th scope="col">Last scan</th>
                <th scope="col" className="actions">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {client.domains.map((domain) => {
                const lastScan = domain.scans?.[0]
                const running = lastScan !== undefined && isScanActive(lastScan.status)
                const allowed = canScan(domain)
                return (
                  <Fragment key={domain.id}>
                    <tr className={allowed ? undefined : 'needs-check'}>
                      <td className="mono">{domain.name}</td>
                      <td>
                        {domain.verified ? (
                          <span className="ownership ownership-verified">
                            <CircleCheck size={16} strokeWidth={1.5} aria-hidden="true" />
                            Verified
                          </span>
                        ) : (
                          <span className="muted">
                            {domain.permission_confirmed ? 'Not verified' : 'Permission needed'}
                          </span>
                        )}
                      </td>
                      <td>
                        {lastScan ? (
                          <span className="last-scan">
                            <StatusBadge kind="scan" status={lastScan.status} />
                            {lastScan.risk_score !== null && <RiskBadge risk={lastScan} />}
                            <span className="muted">
                              <RelativeTime iso={lastScan.created_at} />
                            </span>
                          </span>
                        ) : (
                          <span className="muted">Never scanned</span>
                        )}
                      </td>
                      <td className="actions">
                        <span className="row-actions">
                          {lastScan && (
                            <Link className="button button-ghost" to={`/scans/${lastScan.id}`}>
                              View scan
                            </Link>
                          )}
                          <Button
                            icon={<Radar size={16} strokeWidth={1.5} aria-hidden="true" />}
                            onClick={() => startScan(domain)}
                            disabled={!allowed || running || startingDomainId !== undefined}
                            title={allowed ? undefined : 'Verify the domain first (see below)'}
                          >
                            {running ? 'Scan running' : 'Run scan'}
                          </Button>
                        </span>
                      </td>
                    </tr>
                    {!allowed && (
                      <tr className="verify-row">
                        <td colSpan={4}>
                          {!domain.permission_confirmed ? (
                            <div className="verify-step">
                              <p>
                                This domain was added before the permission check. Confirm that you own{' '}
                                <span className="mono">{domain.name}</span> or have written permission to scan it.
                              </p>
                              <Button
                                icon={<ShieldCheck size={16} strokeWidth={1.5} aria-hidden="true" />}
                                onClick={() => checkDomain(domain, api.confirmPermission)}
                                disabled={checkingDomainId !== undefined}
                              >
                                Confirm permission
                              </Button>
                            </div>
                          ) : (
                            <div className="verify-step">
                              <p>
                                Prove that you control <span className="mono">{domain.name}</span>: add this TXT record
                                to its DNS, then click Verify. A new record can take a few minutes to become visible.
                              </p>
                              <div className="verify-record">
                                <code className="mono">{domain.verification_record}</code>
                                <Button
                                  variant="ghost"
                                  icon={<Copy size={16} strokeWidth={1.5} aria-hidden="true" />}
                                  onClick={() => copyRecord(domain)}
                                >
                                  {copiedDomainId === domain.id ? 'Copied' : 'Copy'}
                                </Button>
                                <Button
                                  icon={<ShieldCheck size={16} strokeWidth={1.5} aria-hidden="true" />}
                                  onClick={() => checkDomain(domain, api.verifyDomain)}
                                  disabled={checkingDomainId !== undefined}
                                >
                                  {checkingDomainId === domain.id ? 'Checking' : 'Verify'}
                                </Button>
                              </div>
                            </div>
                          )}
                          {checkErrors[domain.id] && (
                            <p className="field-error" role="alert">
                              {checkErrors[domain.id]}
                            </p>
                          )}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        )}
      </Panel>

      {client.domains.some((domain) => domain.verified) && (
        <Panel
          title="Port scan"
          meta="Only addresses you confirm get a port scan: a domain can point to shared hosting that belongs to someone else."
        >
          {client.domains
            .filter((domain) => domain.verified)
            .map((domain) => (
              <div key={domain.id} className="port-scan-domain">
                <h3 className="mono">{domain.name}</h3>
                <PortScanScope domain={domain} />
              </div>
            ))}
        </Panel>
      )}

      <Panel title="Add a domain">
        <InlineAddForm
          label="Domain"
          placeholder="badsecurityinc.be"
          buttonLabel="Add domain"
          hint="You will then prove that you control the domain with a DNS record."
          confirmation="I own this domain or have written permission to scan it."
          onAdd={addDomain}
        />
      </Panel>

      {scanHistory.length > 0 && (
        <Panel title="Scan history" meta={plural(scanHistory.length, 'scan')} flush>
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">Started</th>
                <th scope="col">Domain</th>
                <th scope="col">Status</th>
                <th scope="col" className="actions">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {scanHistory.map((scan) => (
                <tr key={scan.id}>
                  <td>
                    <RelativeTime iso={scan.created_at} />
                  </td>
                  <td className="mono">{scan.domain}</td>
                  <td>
                    <StatusBadge kind="scan" status={scan.status} />
                  </td>
                  <td className="actions">
                    <Link to={`/scans/${scan.id}`}>View scan</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}
    </>
  )
}

export default ClientPage
