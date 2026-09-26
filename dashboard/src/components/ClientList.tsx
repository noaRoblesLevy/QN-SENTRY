import type { Client } from '../types'

type ClientListProps = {
  clients: Client[]
}

function ClientList({ clients }: ClientListProps) {
  return (
    <section>
      <h2>Clients</h2>
      <ul>
        {clients.map((client) => (
          <li key={client.id}>
            <strong>{client.name}</strong>
            <ul>
              {client.domains.map((domain) => (
                <li key={domain.id}>{domain.name}</li>
              ))}
            </ul>
          </li>
        ))}
      </ul>
    </section>
  )
}

export default ClientList
