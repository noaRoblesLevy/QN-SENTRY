import { Link, NavLink, Outlet } from 'react-router'
import { usingMockApi } from './api'
import ThemeToggle from './components/ThemeToggle'
import './App.css'

/** The frame around every page: top bar with navigation, then the page itself */
function App() {
  return (
    <>
      <header className="topbar">
        <div className="topbar-left">
          <Link to="/" className="brand">
            QN-SENTRY
          </Link>
          <nav aria-label="Main" className="main-nav">
            <NavLink to="/" end>
              Clients
            </NavLink>
          </nav>
        </div>
        <div className="topbar-right">
          {usingMockApi && (
            <span className="demo-badge" title="The backend is not connected yet. Scans are simulated.">
              Demo data
            </span>
          )}
          <ThemeToggle />
        </div>
      </header>
      <main className="page">
        <Outlet />
      </main>
    </>
  )
}

export default App
