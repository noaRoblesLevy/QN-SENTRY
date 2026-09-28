# QN-SENTRY Dashboard

The web interface of QN-SENTRY: manage clients and their domains, start scans, follow the progress per module and review the findings. Built with React, TypeScript and Vite, styled after the QN-SENTRY design system (dark first, IBM Plex Sans and Mono).

## Running it

```bash
pnpm install
pnpm dev          # http://localhost:5173
pnpm lint         # ESLint
pnpm build        # type check + production build in dist/
```

## Demo data or the real API

Until the backend exists, the dashboard uses a **mock API** (`src/api/mockApi.ts`) that imitates the backend: it validates input, keeps data in memory (reset on reload) and simulates scans that run the four modules one after another, with the findings planted in the test environment. A "Demo data" badge in the top bar shows when it is active.

To use the real FastAPI backend, create `dashboard/.env.local`:

```
VITE_USE_MOCK_API=false
```

`pnpm dev` then forwards every `/api` request to `http://localhost:8000`. Use another address with `API_PROXY_TARGET=http://host:port pnpm dev`.

The endpoints and data shapes follow the data contract in [`docs/project/10-data-contract.md`](../docs/project/10-data-contract.md); the TypeScript types are in `src/types.ts`.

## Docker

```bash
docker build -t qn-sentry-dashboard .
docker run -p 8080:80 -e API_UPSTREAM=http://api:8000 qn-sentry-dashboard
```

nginx serves the built app and forwards `/api` to `API_UPSTREAM` (default `http://api:8000`, the backend service in Docker Compose). Build with `--build-arg VITE_USE_MOCK_API=true` for a standalone demo without a backend.

## Structure

```
src/
├── api/          API client: real (httpApi), simulated (mockApi, mockData), switch (index)
├── components/   Reusable pieces: Button, Panel, SeverityBadge, FindingsTable, ...
├── hooks/        useAsync: loading, errors and polling
├── lib/          Labels and formatting (severities, modules, relative times)
├── pages/        One file per screen: ClientsPage, ClientPage, ScanPage
├── styles/       Shared table styles
├── index.css     Design tokens (colours, spacing, fonts) for the dark and light theme
├── theme.ts      Dark/light theme switch, remembered in localStorage
└── types.ts      Types from the data contract
```

## Screens

| URL | Screen |
|---|---|
| `/` | All clients; add a client |
| `/clients/:id` | A client's domains, their last scan and scan history; add a domain; run a scan |
| `/scans/:id` | Scan progress per module (refreshes every 5 seconds while running), findings summary per severity, findings grouped by module and sorted by severity, with filters |
