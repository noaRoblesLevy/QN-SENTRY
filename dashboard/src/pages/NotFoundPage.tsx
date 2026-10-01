import { Link } from 'react-router'
import PageHeader from '../components/PageHeader'
import Panel from '../components/Panel'
import { EmptyState } from '../components/States'

function NotFoundPage() {
  return (
    <>
      <PageHeader title="Page not found" breadcrumbs={[{ label: 'Clients', to: '/' }]} />
      <Panel title="Nothing here">
        <EmptyState title="This page does not exist.">
          Check the address, or go back to <Link to="/">all clients</Link>.
        </EmptyState>
      </Panel>
    </>
  )
}

export default NotFoundPage
