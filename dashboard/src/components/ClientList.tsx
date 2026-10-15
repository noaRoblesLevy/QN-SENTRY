import { Link } from 'react-router'
import type { Client } from '../types'
import RelativeTime from './RelativeTime'
import RiskBadge from './RiskBadge'
import StatusBadge from './StatusBadge'
import './ClientList.css'

type ClientListProps = {
  clients: Client[]
}

/** The name of the domain the last scan ran on; the overview sends only its id (#16) */
function domainName(client: Client, domainId: number): string {
  return client.domains.find((domain) => domain.id === domainId)?.name ?? 'a domain'
}

function ClientList({ clients }: ClientListProps) {
  return (
    <table className="data-table">
      <thead>
        <tr>
          <th scope="col">Client</th>
          <th scope="col">Risk</th>
          <th scope="col">Domains</th>
          <th scope="col">Last scan</th>
          <th scope="col" className="numeric">
            Count
          </th>
        </tr>
      </thead>
      <tbody>
        {clients.map((client) => (
          <tr key={client.id}>
            <td>
              <Link to={`/clients/${client.id}`}>{client.name}</Link>
            </td>
            <td>
              <RiskBadge risk={client} />
            </td>
            <td>
              {client.domains.length === 0 ? (
                <span className="muted">No domains yet</span>
              ) : (
                <ul className="domain-list">
                  {client.domains.map((domain) => (
                    <li key={domain.id} className="mono">
                      {domain.name}
                    </li>
                  ))}
                </ul>
              )}
            </td>
            <td>
              {client.last_scan ? (
                <Link to={`/scans/${client.last_scan.id}`} className="client-last-scan">
                  <StatusBadge kind="scan" status={client.last_scan.status} />
                  <span className="muted mono">{domainName(client, client.last_scan.domain_id)}</span>
                  <span className="muted">
                    <RelativeTime iso={client.last_scan.created_at} />
                  </span>
                </Link>
              ) : (
                <span className="muted">Never scanned</span>
              )}
            </td>
            <td className="numeric">{client.domains.length}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export default ClientList
