import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { createBrowserRouter } from 'react-router'
import { RouterProvider } from 'react-router/dom'
import './index.css'
import './styles/table.css'
import App from './App.tsx'
import ClientPage from './pages/ClientPage.tsx'
import ClientsPage from './pages/ClientsPage.tsx'
import ErrorPage from './pages/ErrorPage.tsx'
import NotFoundPage from './pages/NotFoundPage.tsx'
import ScanPage from './pages/ScanPage.tsx'

const router = createBrowserRouter([
  {
    path: '/',
    element: <App />,
    errorElement: <ErrorPage />,
    children: [
      { index: true, element: <ClientsPage /> },
      { path: 'clients/:clientId', element: <ClientPage /> },
      { path: 'scans/:scanId', element: <ScanPage /> },
      { path: '*', element: <NotFoundPage /> },
    ],
  },
])

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
)
