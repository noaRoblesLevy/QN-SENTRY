# 5. Legal and Ethical Framework

This chapter describes which scanning is permitted, how personal data is handled, and **how the platform enforces it**. Each measure lists where it is implemented or which issue implements it.

## 5.1 Authorisation

Scanning systems without the owner's permission can constitute unauthorised access or an attempt thereof under Belgian criminal law. QN-Sentry is therefore designed to assess only domains the user is authorised to assess.

| Measure | How it is enforced | Status |
|---|---|---|
| Only our own infrastructure during the project | All tests target `badsecurityinc.be` and `badsecuritylnc.be`, registered by the team, and the team's own Vercel projects and Google Cloud VM | In place |
| False-positive checks on real domains | To check that a check does not report problems that are not there, its evaluation is also run on real, well-configured domains (e.g. the SPF check of #44 on 12 domains such as `kdg.be` and `github.com`). This only reads **public DNS records** through a normal resolver: no request reaches the servers of those organisations, and the results are not stored. Scans, crawling, downloads and port scans only ever target our own domains | In place |
| Target allowlist | Scans can only be started for domains an administrator has approved; the API refuses others | Planned: #3 |
| Domain ownership verification | Before approval, the client proves ownership by adding a DNS TXT record (`qn-sentry-verify=<token>`) | Planned: #48 (*Should*) |
| Permission on record | When a domain is added, the dashboard states that only domains you own or have written permission to scan may be added | In place (dashboard, #31) |
| Scope agreement | In a real-world deployment, an assessment requires a signed agreement with the client defining the scope (domains, period, techniques) | Organisational |

The usage documentation of the modules' command-line tools (their `__main__.py`) carries a similar warning, e.g. "Only scan domains you own or have written permission to assess."

## 5.2 Non-intrusive Techniques

QN-Sentry only performs reconnaissance: it collects publicly available information and detects services. It **never** exploits vulnerabilities, attempts logins, tests whether leaked passwords still work, or performs denial-of-service testing. Because it cannot prove that something is directly exploitable, the `critical` severity is rarely used (data contract 10.2).

Per module, what touches the client's systems and how it is limited (status per 01/10: Phishing, Breach and Document Metadata are merged, certificates #49 and Have I Been Pwned #56 are in review, Attack Surface is planned):

| Module | What it does | Contact with the client's systems | Limits |
|---|---|---|---|
| Attack Surface (#4 to #6) | Subdomains from passive sources, DNS resolution, open ports, service versions, web technologies | Subdomain discovery is passive; port scans, version detection and HTTP requests are active | Planned: top ports only, rate-limited, TCP connect scan (no raw packets, the worker runs as non-root). IP addresses of CDNs and hosting providers are only checked on ports 80 and 443 (`naabu -exclude-cdn`): the website runs on Vercel, and a port scan of its IP would scan Vercel's infrastructure, not the client's |
| Document Metadata (#7) | Crawls the website, downloads public documents, reads their metadata | Requests to the company's own website only | Exact hosts only, depth 3, at most 120 s at 10 requests per second, at most 50 documents of 20 MB. Known gap: a redirect from the website to another host is still followed by the crawler and the downloader before it is refused, so that host receives a request; to be fixed in #66 |
| Phishing: lookalikes (#9) | Generates lookalike names and checks which are registered | None; DNS lookups only, also for third-party lookalike domains: no WHOIS, banners or web pages | 16 parallel DNS lookups; the resolver is tested first, so a broken resolver fails instead of reporting "nothing found" |
| Phishing: certificates (#10) | Searches Certificate Transparency logs for lookalike certificates | None; public CT search services | At most 25 lookalikes per scan (fair use) |
| Phishing: email security (#29) | Reads the SPF, DMARC and DKIM records of the company domain | None; public DNS records | A few DNS lookups |
| Employee Breach (#11 to #13) | Checks business email addresses against a breach source | None; the address is looked up at the breach source (the local test dataset, or Have I Been Pwned in review in #56) | No login attempts, never retrieves passwords |

## 5.3 GDPR

Several modules process personal data. The table below lists which data, where it is kept, and how the GDPR principles apply.

| Personal data | Found by | Kept in | Why it is needed |
|---|---|---|---|
| Names of employees (document authors) | Document Metadata (#7) | Findings, and the scan context for the Breach module | Shows what an attacker can learn; lets the Breach module derive addresses (#12) |
| Usernames (`BSI\ljanssens`) | Document Metadata (#7) | Findings | Shows the login name format an attacker would use |
| Business email addresses | Metadata (#8), Breach (#12) | Findings | Needed to check them against breach sources |
| Breach records | Employee Breach (#11) | Findings: breach name, date and kinds of data only | Shows which accounts are at risk of credential stuffing |
| Business email addresses sent to Have I Been Pwned | Employee Breach with `BREACH_SOURCE=hibp` (#13, in review in #56) | Not kept by QN-Sentry beyond the findings; HIBP receives one address per request | Only way to check real addresses against known breaches |

| Principle | Implementation in QN-Sentry | Status |
|---|---|---|
| **Lawfulness** | In a real deployment, processing rests on the client's legitimate interest in securing its organisation (GDPR art. 6(1)(f)). Employees are informed that their business addresses are checked (art. 13 and 14). | Organisational |
| **Purpose limitation** | Personal data is used solely to assess the organisation's security exposure. | In place |
| **Data minimisation** | The Breach module stores only the email address, the breach name, the date and the *kinds* of data exposed, never passwords or other leaked data. Downloaded documents are kept in a temporary folder only during the analysis and then deleted. | In place (#11, #7) |
| **Storage limitation** | Scan results are automatically deleted after a retention period of 90 days (configurable). | Planned: #46 (in review in #52) |
| **Transfers outside the EU** | With `BREACH_SOURCE=hibp`, each business email address is sent to Have I Been Pwned, which is operated from Australia. Australia has no EU adequacy decision, so this is a transfer under GDPR chapter V. Only the address is sent, and only to check it against known breaches. A real deployment needs a valid transfer basis (e.g. standard contractual clauses, art. 46) and must mention the transfer in the information to employees. The demo and the default configuration use the local test dataset, so no personal data leaves the platform. | Organisational; HIBP source in review (#56) |
| **Security** | The database and task queue are only reachable inside the Docker network; every container runs as a non-root user (the dashboard since #60); secrets live in `.env`, never in Git. | In place (#33, #60) |
| | The API, including the PDF reports with personal data, has no authentication yet. Until then its port is bound to `127.0.0.1`, so it is only reachable from the machine it runs on. | In place (`127.0.0.1`); authentication planned: #20 |
| | Login with roles, so each client only sees their own data. | Planned: #20 |
| | Traffic encrypted with HTTPS through Caddy. | Planned: #18 |
| **Roles** | In a real-world deployment, the client is the data controller and the QN-Sentry operator acts as data processor, which requires a data processing agreement (GDPR art. 28). | Organisational |

During this project, only fictitious persons and data are used (section 5.4).

## 5.4 The Test Environment

The test environment (#2, chapter 4) deliberately contains weaknesses. It is built so that it harms no one:

| Measure | Why |
|---|---|
| Every page of the BadSecurityInc website states that the company is fictitious, and has `noindex, nofollow` | Search engines do not list the fake people; visitors are not misled |
| All people, email addresses, documents and breaches are made up, and the breaches have clearly fictitious names (ExampleShop, PretendSpamList) | No real person's data is processed |
| The lookalike page on `badsecuritylnc.be` has no form or input at all and states it is a test | It can never collect credentials |
| The MX record of `badsecuritylnc.be` points to `mail.badsecuritylnc.be`, a host name that does not exist | The lookalike cannot actually receive or send mail |
| Exposed services on the VM are decoys (a fake SSH banner, a login page that always fails) running up-to-date software. Planned: the VM is not deployed yet (#2) | Nothing genuinely vulnerable is on the internet |
| The deliberately weak SPF (`+all`) and DMARC (`p=none`) are only on our own fictitious domain, which has no users | Someone could send spoofed mail "from" `badsecurityinc.be`, but it misleads no real organisation |
| After the project, the weak records, the lookalike domain, the Vercel projects and the VM are removed (checklist: #61) | The weaknesses do not stay online longer than needed |

## 5.5 Third-party Services

| Service | Used by | Terms we respect |
|---|---|---|
| Have I Been Pwned | Breach (#13, in review in #56) | API key; rate limits (a pause between requests, wait for `Retry-After` on HTTP 429); attribution of HIBP as the source (CC BY 4.0) in the findings and the report; the transfer outside the EU (5.3) |
| Cert Spotter | Phishing certificates (#10, in review in #49) | Without an API key the service is for personal or evaluation use only, which covers this student project; a real deployment needs an API key (`CERTSPOTTER_API_KEY`, #49). At most 25 lookups per scan |
| crt.sh | Phishing certificates (#10), fallback | Fair use: only used when Cert Spotter fails |
| Google Cloud | Test VM | Google Cloud Acceptable Use Policy: we only scan our own resources |
| Vercel, one.com | Test website, DNS | Hosting and DNS of our own fictitious domains |

## 5.6 Business Context: NIS2

The Belgian NIS2 law requires organisations in scope, including many SMEs in critical supply chains, to take appropriate cybersecurity risk management measures. An external exposure assessment such as QN-Sentry supports these organisations in identifying risks and in demonstrating that they actively manage them.
