import { isRouteErrorResponse, Link, useRouteError } from 'react-router'
import '../App.css'

/** Shown when a page crashes, so the user sees a message instead of a blank screen */
function ErrorPage() {
  const error = useRouteError()
  const message = isRouteErrorResponse(error)
    ? `${error.status} ${error.statusText}`
    : error instanceof Error
      ? error.message
      : 'Unknown error'

  return (
    <main className="page">
      <h1 className="page-title">Something went wrong</h1>
      <p className="error-page-message">{message}</p>
      <Link to="/">Back to all clients</Link>
    </main>
  )
}

export default ErrorPage
