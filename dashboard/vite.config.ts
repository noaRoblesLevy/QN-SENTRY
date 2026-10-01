import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // During development, forward API calls to the FastAPI backend
    proxy: {
      '/api': process.env.API_PROXY_TARGET ?? 'http://localhost:8000',
    },
  },
})
