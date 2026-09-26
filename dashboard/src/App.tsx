import './App.css'
import { mockClients } from './api/mockData'
import ClientList from './components/ClientList'

function App() {
  return (
    <>
      <nav>
        <h1>QN-SENTRY</h1>
      </nav>
      <ClientList clients={mockClients} />
    </>
  )
}

export default App
