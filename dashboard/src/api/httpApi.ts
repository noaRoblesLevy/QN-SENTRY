import { ApiError, type Api } from './api'

// In development Vite forwards /api to the backend (see vite.config.ts);
// in Docker, nginx does the same (see nginx.conf.template).
const BASE_URL = import.meta.env.VITE_API_URL ?? ''

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${BASE_URL}${path}`, {
      ...init,
      headers: { 'Content-Type': 'application/json', ...init?.headers },
    })
  } catch {
    throw new ApiError(0, 'Could not reach the QN-SENTRY API. Check that the backend is running.')
  }

  if (!response.ok) {
    throw new ApiError(response.status, await errorMessage(response))
  }
  return (await response.json()) as T
}

// FastAPI returns errors as {"detail": "..."}; fall back to the status text
async function errorMessage(response: Response): Promise<string> {
  try {
    const body = await response.json()
    if (typeof body?.detail === 'string') return body.detail
  } catch {
    // Not JSON
  }
  return `Request failed: ${response.status} ${response.statusText}`
}

function post<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) })
}

/** Direct link to the PDF report of a finished scan (downloaded by the browser, not fetched) */
export function reportUrl(scanId: number): string {
  return `${BASE_URL}/api/scans/${scanId}/report.pdf`
}

export const httpApi: Api = {
  listClients: () => request('/api/clients'),
  getClient: (clientId) => request(`/api/clients/${clientId}`),
  createClient: (name) => post('/api/clients', { name }),
  addDomain: (clientId, name) => post(`/api/clients/${clientId}/domains`, { name }),
  startScan: (domainId) => post(`/api/domains/${domainId}/scans`),
  getScan: (scanId) => request(`/api/scans/${scanId}`),
  getFindings: (scanId) => request(`/api/scans/${scanId}/findings`),
}
