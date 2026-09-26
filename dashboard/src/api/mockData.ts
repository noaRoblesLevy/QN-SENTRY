import type { Client } from '../types'

// Fake data until the API (GET /api/clients) is available.
// Other clients use the reserved .example TLD, so they can never be real domains.
export const mockClients: Client[] = [
  {
    id: 1,
    name: 'BadSecurityInc',
    domains: [
      { id: 1, name: 'badsecurityinc.be' },
    ],
  },
  {
    id: 2,
    name: 'Peeters Bakery',
    domains: [
      { id: 2, name: 'peeters-bakery.example' },
      { id: 3, name: 'peeters-bread.example' },
    ],
  },
  {
    id: 3,
    name: 'Maes Accounting',
    domains: [
      { id: 4, name: 'maes-accounting.example' },
    ],
  },
]
