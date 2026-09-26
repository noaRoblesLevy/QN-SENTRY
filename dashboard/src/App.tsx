import './App.css'
import { mockClients } from './api/mockData'
import ClientList from './components/ClientList'
import ThemeToggle from './components/ThemeToggle'

function App() {
  return (
    <>
      <header className="topbar">
        <span className="brand">QN-SENTRY</span>
        <ThemeToggle />
      </header>
      <main className="page">
        <h1 className="page-title">Clients</h1>
        <ClientList clients={mockClients} />
      </main>
    </>
  )
}

export default App
