/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** "false" to use the real backend instead of simulated demo data */
  readonly VITE_USE_MOCK_API?: string
  /** Base URL of the API; empty means the same origin (/api is proxied) */
  readonly VITE_API_URL?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
