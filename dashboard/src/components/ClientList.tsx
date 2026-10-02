import { Link } from 'react-router'
import type { Client } from '../types'
import RiskBadge from './RiskBadge'
import './ClientList.css'

type ClientListProps = {
  clients: Client[]
}

function ClientList({ clients }: ClientListProps) {
  return (
    <table className="data-table">
      <thead>
        <tr>
          <th scope="col">Client</th>
          <th scope="col">Risk</th>
          <th scope="col">Domains</th>
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
            <td className="numeric">{client.domains.length}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export default ClientList
