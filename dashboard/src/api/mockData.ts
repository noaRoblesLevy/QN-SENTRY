import type { Client, Finding, ModuleName } from '../types'

/** A fake TXT record value; the real one is an HMAC made by the backend (#48) */
export function mockVerificationRecord(domain: string): string {
  let hash = 0
  for (const char of domain) hash = (hash * 31 + char.charCodeAt(0)) >>> 0
  return `qn-sentry-verify=${hash.toString(16).padStart(8, '0').repeat(4)}`
}

function verifiedDomain(name: string) {
  return { permission_confirmed: true, verified: true, verification_record: mockVerificationRecord(name) }
}

export function unverifiedDomain(name: string) {
  return { permission_confirmed: true, verified: false, verification_record: mockVerificationRecord(name) }
}

// Fake data until the API is available.
// Other clients use the reserved .example TLD, so they can never be real domains.
export const mockClients: Client[] = [
  {
    id: 1,
    name: 'BadSecurityInc',
    domains: [{ id: 1, name: 'badsecurityinc.be', ...verifiedDomain('badsecurityinc.be') }],
  },
  {
    id: 2,
    name: 'Peeters Bakery',
    domains: [
      { id: 2, name: 'peeters-bakery.example', ...verifiedDomain('peeters-bakery.example') },
      { id: 3, name: 'peeters-bread.example', ...verifiedDomain('peeters-bread.example') },
    ],
  },
  {
    id: 3,
    name: 'Maes Accounting',
    // Not verified yet, to show the verification step
    domains: [{ id: 4, name: 'maes-accounting.example', ...unverifiedDomain('maes-accounting.example') }],
  },
]

const HOUR = 60 * 60 * 1000

// Scans that already happened when the dashboard opens
export const mockScanHistory: { domainId: number; startedAgoMs: number }[] = [
  { domainId: 1, startedAgoMs: 3 * HOUR },
  { domainId: 3, startedAgoMs: 26 * HOUR },
]

// Domains whose phishing module fails, to show a scan that completes with errors
export function failingModule(domain: string): { module: ModuleName; error: string } | null {
  return domain.includes('bread')
    ? { module: 'phishing', error: 'dnstwist is not installed in the worker image' }
    : null
}

export type FindingTemplate = Omit<Finding, 'id' | 'created_at'>

/** Homoglyph lookalike: badsecurityinc.be -> badsecuritylnc.be (lowercase l instead of i) */
function lookalikeOf(domain: string): string {
  const [label, ...rest] = domain.split('.')
  const i = label.lastIndexOf('i')
  const fake = i >= 0 ? `${label.slice(0, i)}l${label.slice(i + 1)}` : `${label}s`
  return [fake, ...rest].join('.')
}

/** The findings planted in the test environment (docs/project/04-test-environment.md) */
export function findingTemplates(domain: string): FindingTemplate[] {
  const lookalike = lookalikeOf(domain)
  return [
    {
      module: 'attack_surface',
      type: 'subdomain',
      title: `Subdomain dev.${domain}`,
      description: 'A subdomain that is publicly resolvable. Forgotten staging or test subdomains often run outdated or unprotected software.',
      severity: 'info',
      asset: `dev.${domain}`,
      details: { ips: ['203.0.113.10'], source: 'certificate transparency' },
    },
    {
      module: 'attack_surface',
      type: 'subdomain',
      title: `Subdomain mail.${domain}`,
      description: 'A subdomain that is publicly resolvable.',
      severity: 'info',
      asset: `mail.${domain}`,
      details: { ips: ['203.0.113.11'], source: 'subfinder' },
    },
    {
      module: 'attack_surface',
      type: 'web_service',
      title: `Admin login page on staging subdomain dev.${domain}`,
      description: 'An administration login page is reachable from the internet on a staging subdomain. Attackers can try leaked or guessed passwords against it.',
      severity: 'medium',
      asset: `https://dev.${domain}/admin`,
      details: { status_code: 200, title: 'Admin login', technologies: ['nginx', 'PHP 7.4'] },
    },
    {
      module: 'attack_surface',
      type: 'web_service',
      title: `Outdated web server nginx 1.18.0 on www.${domain}`,
      description: 'The web server reveals an outdated version in its HTTP headers. Known vulnerabilities for this version are public.',
      severity: 'medium',
      asset: `https://www.${domain}`,
      details: { status_code: 200, webserver: 'nginx/1.18.0', technologies: ['nginx 1.18.0'] },
    },
    {
      module: 'attack_surface',
      type: 'open_port',
      title: `PostgreSQL exposed to the internet on dev.${domain}:5432`,
      description: 'A database port is reachable from the internet. Databases should only be reachable from the internal network.',
      severity: 'high',
      asset: `dev.${domain}:5432`,
      details: { port: 5432, protocol: 'tcp', service: 'postgresql', version: '13.4' },
    },
    {
      module: 'attack_surface',
      type: 'open_port',
      title: `SSH on non-standard port dev.${domain}:2222`,
      description: 'SSH runs on a non-standard port. This hides it from quick scans only; it is still reachable for password attacks.',
      severity: 'low',
      asset: `dev.${domain}:2222`,
      details: { port: 2222, protocol: 'tcp', service: 'ssh', product: 'OpenSSH', version: '8.2p1' },
    },
    {
      module: 'metadata',
      type: 'document_metadata',
      title: 'Metadata in budget-2026.xlsx: 2 names, internal file path',
      description: 'A public spreadsheet reveals employee names and an internal file server path. Attackers use this to target employees and to learn the internal network layout.',
      severity: 'medium',
      asset: `https://www.${domain}/files/budget-2026.xlsx`,
      details: {
        people: ['Jan Peeters', 'Sofie Maes'],
        software: ['Microsoft Excel 2013'],
        internal_paths: ['\\\\SRV-FS01\\Finance\\budget-2026.xlsx'],
      },
    },
    {
      module: 'metadata',
      type: 'document_metadata',
      title: 'Metadata in employee-handbook.pdf: 1 name, outdated Office version',
      description: 'A public document reveals an author name and the outdated software used to create it.',
      severity: 'low',
      asset: `https://www.${domain}/files/employee-handbook.pdf`,
      details: { people: ['Sofie Maes'], software: ['Microsoft Word 2010'], internal_paths: [] },
    },
    {
      module: 'metadata',
      type: 'email_address',
      title: `Public email address info@${domain}`,
      description: 'An email address published on the company website.',
      severity: 'info',
      asset: `info@${domain}`,
      details: { found_on: `https://www.${domain}/contact` },
    },
    {
      module: 'metadata',
      type: 'email_convention',
      title: `Email naming convention detected: first.last@${domain}`,
      description: 'Knowing the naming convention, anyone can derive the email address of every employee whose name is public.',
      severity: 'low',
      asset: domain,
      details: { convention: 'first.last', matched: ['sofie.maes'] },
    },
    {
      module: 'phishing',
      type: 'lookalike_domain',
      title: `Registered lookalike domain ${lookalike} (can receive email)`,
      description: 'This domain looks like the company domain and has a mail server. It can be used to send phishing emails to employees and customers.',
      severity: 'high',
      asset: lookalike,
      details: { fuzzer: 'homoglyph', a: ['198.51.100.23'], mx: [`mail.${lookalike}`] },
    },
    {
      module: 'phishing',
      type: 'lookalike_certificate',
      title: `TLS certificate issued for lookalike domain ${lookalike}`,
      description: 'A certificate was issued for a lookalike domain, which usually means a website is being set up on it.',
      severity: 'high',
      asset: lookalike,
      details: { issuer: "C=US, O=Let's Encrypt, CN=R11", not_before: '2026-09-28', crtsh_id: 14839201 },
    },
    {
      module: 'phishing',
      type: 'email_security',
      title: 'Email spoofing possible: permissive SPF and DMARC p=none',
      description: `Anyone can send email that appears to come from @${domain}, and receiving mail servers are told not to block it.`,
      severity: 'high',
      asset: domain,
      details: { spf: 'v=spf1 +all', dmarc: 'v=DMARC1; p=none', dkim: 'not found' },
    },
    {
      module: 'breach',
      type: 'breached_email',
      title: `jan.peeters@${domain} appears in 2 data breaches`,
      description: 'This business email address appears in known data breaches, including one that exposed passwords. If the employee reuses that password, an attacker can try to log in to company systems.',
      severity: 'high',
      asset: `jan.peeters@${domain}`,
      details: {
        origin: "derived from 'Jan Peeters' (first.last)",
        breaches: [
          { name: 'ExampleShop', date: '2021-06-22', data: ['Emails', 'Passwords'] },
          { name: 'ExampleForum', date: '2019-03-10', data: ['Emails', 'Usernames'] },
        ],
      },
    },
    {
      module: 'breach',
      type: 'breached_email',
      title: `sofie.maes@${domain} appears in 1 data breach`,
      description: 'This business email address appears in a known data breach. No passwords were exposed.',
      severity: 'medium',
      asset: `sofie.maes@${domain}`,
      details: {
        origin: 'found publicly',
        breaches: [{ name: 'ExampleNewsletter', date: '2023-01-15', data: ['Emails', 'Names'] }],
      },
    },
  ]
}
