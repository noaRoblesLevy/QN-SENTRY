import { useNavigate } from 'react-router'
import { api } from '../api'
import ClientList from '../components/ClientList'
import InlineAddForm from '../components/InlineAddForm'
import PageHeader from '../components/PageHeader'
import Panel from '../components/Panel'
import { EmptyState, ErrorState, LoadingState } from '../components/States'
import { useAsync } from '../hooks/useAsync'
import { plural } from '../lib/format'

function ClientsPage() {
  const navigate = useNavigate()
  const { data: clients, error, loading, reload } = useAsync('clients', () => api.listClients())

  async function addClient(name: string) {
    const client = await api.createClient(name)
    // Next step for a new client is adding its domains
    navigate(`/clients/${client.id}`)
  }

  return (
    <>
      <PageHeader title="Clients" meta="The organisations you assess. Add a client, then its domains." />

      <Panel title="Add a client">
        <InlineAddForm label="Client name" placeholder="BadSecurityInc" buttonLabel="Add client" onAdd={addClient} />
      </Panel>

      <Panel title="All clients" meta={clients && plural(clients.length, 'client')} flush>
        {loading && <LoadingState label="Loading clients" />}
        {error && <ErrorState error={error} onRetry={reload} />}
        {clients?.length === 0 && (
          <EmptyState title="No clients yet">Add your first client above to start an assessment.</EmptyState>
        )}
        {clients && clients.length > 0 && <ClientList clients={clients} />}
      </Panel>
    </>
  )
}

export default ClientsPage
