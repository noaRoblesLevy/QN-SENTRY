import type { Client } from '../types'
import './ClientList.css'

type ClientListProps = {
  clients: Client[]
}

function ClientList({ clients }: ClientListProps) {
  return (
    <section className="panel">
      <div className="panel-header">
        <h2 className="panel-title">All clients</h2>
        <span className="panel-meta">
          {clients.length} {clients.length === 1 ? 'client' : 'clients'}
        </span>
      </div>
      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th scope="col">Client</th>
              <th scope="col">Domains</th>
              <th scope="col" className="numeric">Count</th>
            </tr>
          </thead>
          <tbody>
            {clients.map((client) => (
              <tr key={client.id}>
                <td className="client-name">{client.name}</td>
                <td>
                  <ul className="domain-list">
                    {client.domains.map((domain) => (
                      <li key={domain.id} className="domain">
                        {domain.name}
                      </li>
                    ))}
                  </ul>
                </td>
                <td className="numeric">{client.domains.length}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}

export default ClientList
