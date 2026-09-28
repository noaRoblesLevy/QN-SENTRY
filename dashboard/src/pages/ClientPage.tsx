import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import { Radar } from 'lucide-react'
import { api } from '../api'
import Button from '../components/Button'
import InlineAddForm from '../components/InlineAddForm'
import PageHeader from '../components/PageHeader'
import Panel from '../components/Panel'
import RelativeTime from '../components/RelativeTime'
import { EmptyState, ErrorState, LoadingState } from '../components/States'
import StatusBadge from '../components/StatusBadge'
import { useAsync } from '../hooks/useAsync'
import { plural } from '../lib/format'
import { isScanActive } from '../lib/labels'
import type { Client, Domain } from '../types'
import NotFoundPage from './NotFoundPage'
import './ClientPage.css'

const POLL_MS = 5_000

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

  async function startScan(domain: Domain) {
    setStartingDomainId(domain.id)
    setScanError(undefined)
    try {
      const scan = await api.startScan(domain.id)
      navigate(`/scans/${scan.id}`)
    } catch (err) {
      setScanError(`Could not start a scan of ${domain.name}: ${err instanceof Error ? err.message : 'unknown error'}`)
      setStartingDomainId(undefined)
    }
  }

  async function addDomain(name: string) {
    await api.addDomain(clientId, name)
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
        meta={plural(client.domains.length, 'domain')}
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
                return (
                  <tr key={domain.id}>
                    <td className="mono">{domain.name}</td>
                    <td>
                      {lastScan ? (
                        <span className="last-scan">
                          <StatusBadge kind="scan" status={lastScan.status} />
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
                          disabled={running || startingDomainId !== undefined}
                        >
                          {running ? 'Scan running' : 'Run scan'}
                        </Button>
                      </span>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel title="Add a domain">
        <InlineAddForm
          label="Domain"
          placeholder="badsecurityinc.be"
          buttonLabel="Add domain"
          hint="Only add domains you own or have written permission to scan."
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
