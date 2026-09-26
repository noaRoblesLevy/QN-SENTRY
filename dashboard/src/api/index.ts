import type { Api } from './api'
import { httpApi } from './httpApi'
import { mockApi } from './mockApi'

// The mock API is used until the backend exists. Set VITE_USE_MOCK_API=false
// (in dashboard/.env.local or as a Docker build argument) to use the real API.
export const usingMockApi = import.meta.env.VITE_USE_MOCK_API !== 'false'

export const api: Api = usingMockApi ? mockApi : httpApi

export { ApiError } from './api'
