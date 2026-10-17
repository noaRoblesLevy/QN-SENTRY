# QN-Sentry: Final Report

**Integration Project 2 (IP3-ISB), KdG, 2026-2027**
Noa Robles Levy and Quinten Morreel
Repository: https://github.com/noaRoblesLevy/QN-SENTRY

> **Draft.** This report follows the structure of section 9.2 of the deliverables. Everything that is already settled in the code, the pull requests and the measurements is written out; what can only be written at the end is marked **TO COMPLETE**, with what is needed. Sections that describe Quinten's parts are marked *(Quinten)*.

---

## 1. Description and Goal

### 1.1 The problem

Small and medium-sized enterprises (SMEs) are attacked as often as large companies, but rarely have a security team. An attack usually starts with reconnaissance using public information only: forgotten subdomains and services, names and usernames hidden in the metadata of public documents, lookalike domains to send phishing from, a domain whose email can be spoofed, and employee addresses that appear in data breaches. Most SMEs have no idea what an attacker can learn about them this way.

### 1.2 The goal

QN-Sentry is an OSINT platform for digital risk assessment. Given a company domain, it performs an on-demand, **passive** assessment of the organisation's external exposure and presents the result in a dashboard, a PDF report for management and a risk score. The SME sees its attack surface from an attacker's perspective, before an attacker does.

It is built for managed service providers (MSPs) and IT administrators who manage several SMEs: one platform holds many clients, each with one or more domains.

### 1.3 Scope

| In scope | Out of scope |
|---|---|
| Passive and non-intrusive reconnaissance: subdomains, open ports and service versions, document metadata, lookalike domains and their certificates, SPF/DMARC/DKIM, breach lookups of business addresses | Exploiting vulnerabilities, logging in, testing leaked passwords, denial of service, profiling individuals on social media |
| An on-demand assessment per scan | Continuous monitoring (future work) |
| Our own fictitious company BadSecurityInc as the only target | Any domain without explicit permission |

### 1.4 Result in one paragraph

**TO COMPLETE** after the feature freeze (25/10): which modules and platform features were delivered, the final detection rate and precision on the planted weaknesses (chapter 5), and one sentence on the demo.

---

## 2. Technical Implementation and Justification of Choices

### 2.1 Architecture

```
Browser ──> nginx (dashboard) ──/api──> FastAPI (api) ──> PostgreSQL
                                           │                   ▲
                                           ▼                   │
                                    Redis (queue) ──> Celery worker ──> OSINT modules ──> internet
```

| Component | Technology | Why |
|---|---|---|
| API | Python 3.13, FastAPI | Same language as the modules; request validation and interactive documentation (`/docs`) for free |
| Scans | Celery worker with Redis as queue | A scan takes from tens of seconds to minutes. The API stores the scan, puts a task in Redis and answers at once; a worker runs it. A crashed web request never loses a scan, and more workers scale out. |
| Database | PostgreSQL with SQLAlchemy 2, migrations with Alembic | Structured data (clients, domains, scans, module runs, findings) with cascading deletes for GDPR retention; JSONB for module-specific details |
| Dashboard | React 19, TypeScript, Vite, served by nginx | A single-page app that polls a running scan every 5 seconds; nginx forwards `/api`, so browser and API share one origin |
| Periodic tasks | Celery Beat | The nightly GDPR clean-up |
| Deployment | Docker Compose | One command starts all seven services; the same environment on every machine |

**Why a queue instead of running scans in the API.** A web request that waits minutes for a scan blocks a server thread, times out in proxies and loses the scan when the process restarts. With a queue the API stays responsive and a scan survives a crash: the worker only acknowledges a task when it is finished (`task_acks_late`), so Redis hands an interrupted task to another worker.

**Why Python for the modules.** The OSINT tools (dnstwist, dnspython, katana, exiftool) are either Python libraries or command-line tools with JSON output that Python wraps easily; one language for API, worker and modules means one test setup and one review culture. C++ or Go would only add speed where the bottleneck is the network, not the CPU.

### 2.2 The data contract

Before writing any module we agreed on one format for a finding (`module`, `type`, `title`, `description`, `severity`, `asset`, `details`) and on the module interface: a module gets a `ScanContext`, may add to it (names, addresses) for later modules, and **returns** its findings; only the worker writes to the database (`docs/project/10-data-contract.md`).

Because of that contract the dashboard, the PDF report and the risk score contain no module-specific code, the dashboard could be built against a mock API before the backend existed, and every module can be run on its own from the command line.

### 2.3 Reliability of a scan *(worker: Quinten)*

| Problem | Solution |
|---|---|
| The same task delivered twice (after a worker crash) would run the scan twice and duplicate findings | `claim_scan` moves a scan from `queued` to `running` in one atomic `UPDATE ... WHERE status = 'queued'`; only one delivery can succeed |
| A worker that stopped leaves a scan "running" forever and blocks its domain | A scan older than `SCAN_TIMEOUT_MINUTES` counts as stuck: the next start marks it failed |
| One failing module would make the whole scan useless | The worker catches the error per module, marks that module `failed` and continues; the scan ends as `partial` |
| A module that silently returns nothing looks like a clean result | Rule of the contract: a module that could not check anything raises; partial failures are kept apart (warnings per module run, #32) |

### 2.4 The modules

#### Attack Surface Mapping *(Quinten)*

**TO COMPLETE** (#4 to #6): subdomain discovery (subfinder, Certificate Transparency, dnsx), port scanning (naabu with `-exclude-cdn`, a TCP connect scan because the worker runs as non-root), service and web technology detection (httpx), and the choices made.

#### Document Metadata Analysis *(Quinten)*

The module crawls the client's website with **katana** (exact hosts only, depth 3, at most 120 s at 10 requests per second), downloads at most 50 public documents of 20 MB into a temporary folder that is deleted after the analysis, and reads their metadata with **exiftool**. It interprets the tags into people, usernames (`BSI\ljanssens`, `C:\Users\<name>\`), software (Office `AppVersion` mapped to 2007, 2010, ...), internal paths (`\\SRV-FS01\Finance\...`) and printer or scanner names. A document that leaks internal paths is `medium`, other leaks are `low`, a cleaned document gives no finding. Author names go into the scan context for the Breach module.

**TO COMPLETE** *(Quinten)*: email addresses and the naming convention (#8), and the fix of the redirect gap (#66).

#### Phishing Domain Detection

Three checks, each allowed to fail without losing the others:

1. **Lookalike domains** (#9). dnstwist generates hundreds of variants of the domain (typos, homoglyphs such as `badsecuritylnc.be`, other top-level domains) and 16 threads look up their NS, A, AAAA and MX records. A registered lookalike with a mail server is `high` (it can send and receive phishing), one without is `low`. A lookalike whose name or mail servers lie inside the client's own domain is a defensive registration (`info`); sharing a DNS provider is noted but not trusted, because attackers use the same providers. Before the lookups the resolver is tested with a name that always exists (`a.root-servers.net`): a resolver that denies everything would otherwise produce "no lookalikes".
2. **Certificates for lookalikes** (#10). Certificate Transparency logs record every public TLS certificate, often before a phishing site goes live. Cert Spotter is asked first, crt.sh as backup; only **valid** certificates count, so the result does not depend on which service answered. An empty answer from the backup after the first service failed counts as "not checked", not as "clean", and a service that fails three times in a row is skipped for the rest of the scan (circuit breaker).
3. **Email security** (#29, #44). SPF, DMARC and DKIM records are read and judged by pure functions (testable without DNS). The combination matters: a weak DMARC is `high` when SPF does not stop spoofing either (no SPF, `+all`, or an SPF record that receivers ignore because it needs more than 10 DNS lookups, loops, or includes a domain without SPF record, RFC 7208).

#### Employee Breach Exposure

The module checks business addresses from the scan context against a **pluggable breach source**: a local, fictitious dataset (default, used in the demo) or Have I Been Pwned (#13). Only the breach name, date and the *kinds* of data are stored, never the leaked data. A breach with passwords or malware-stolen credentials is `high`, one with other personal data `medium`, a spam list `low`; fabricated breaches are left out. For HIBP, a temporary error skips one address instead of the whole module, the rate limit is respected (`Retry-After` on HTTP 429), and HIBP is credited as the source.

**Derived addresses (#12).** Most employees never publish their address, but their name is in the metadata of a document. When the Metadata module has detected the company's address convention (e.g. `firstname.lastname`) from the addresses it found, the Breach module derives the likely address of every author without a published one. Multi-word last names ("Van den Broeck") can be written joined or separated; when the documents do not show which, both are tried. A derived address is only stored when it appears in a breach, and the finding says it was derived and from which name and convention, so an address that does not exist never becomes a finding. Without a detected convention nothing is derived: a guess without evidence would check addresses that probably do not exist. On BadSecurityInc this finds `pieter.mertens@badsecurityinc.be` (`high`), derived from the author of the annual report, an address published nowhere.

### 2.5 Risk score

One number per scan and per client, so management sees at a glance how exposed the organisation is (#19, data contract 10.7).

- Each finding adds points by severity (critical 25, high 10, medium 4, low 1, info 0), and `score = 100 × (1 − e^(−points/50))`. A plain sum would reach 100 after a few findings; an average would drop when harmless findings are added. This curve has neither problem and never decreases when a finding is added.
- The score is at least the floor of the worst finding (critical 75, high 50, medium 25), decided in review: without it one critical finding scored 39, "moderate", while critical means "fix immediately".
- A partial scan keeps its score but is marked incomplete; a running or failed scan has none.
- A scan with warnings, a partial scan or one with a module that could not check everything keeps its score but is marked incomplete (an asterisk in the dashboard), so a missing check never looks like a low risk.
- The score is stored when the scan finishes, with the version of the method (#59). Reading it never loads the findings, so the client list stays fast as the history grows, and when the weights change, old scans keep the score they got and show which method computed it.

### 2.6 PDF report

The report (#17) is written for management: a summary in plain language, the totals per severity, every critical, high and medium finding with its explanation, the others in a table, and what was checked. It is generated with reportlab from plain data, so it is tested without a database. Choices: a failed scan gets no report (it would read as a clean result); the bundled DejaVu fonts print Cyrillic and Greek homoglyphs correctly, with their `xn--` form next to them; sources that require attribution (Have I Been Pwned) are credited.

### 2.7 Privacy and security by design

| Measure | Where |
|---|---|
| A domain is only scanned after the user confirms permission **and** proves control with a DNS TXT record derived from a secret (HMAC), checked again at every scan | `verification.py`, domains and scans API (#3, #48) |
| An active port scan only reaches addresses the user approved per domain, that the scan found again, and that do not belong to a CDN or shared hosting | `ScanContext.port_scan_targets()` (#81, #5) |
| Scan results are deleted after 90 days, also stuck scans, every night and when the worker starts | `worker/retention.py` (#46) |
| Documents only exist in a temporary folder during the analysis | Metadata module |
| Breach data: only names, dates and kinds of data | Breach module |
| The platform runs locally by design: API and dashboard bound to `127.0.0.1`, database and Redis without published ports, so the software and the scan data never leave the operator's own machine | `docker-compose.yml` |
| Every container runs as a non-root user | Dockerfiles (#60) |
| Secrets only in `.env`, never in Git | `.gitignore` |

The full legal and ethical framework is chapter 5 of the project documentation.

### 2.8 Quality: how we know it works

- **Unit tests** without network: DNS, HTTP, the clock and external tools are replaced by fakes. 422 automated tests in total (15/10/2026): 390 that run without a network or database, and 32 API tests against a real PostgreSQL (run in continuous integration and locally with `QNSENTRY_TEST_DATABASE=1`). The interpretation functions (exiftool tags, SPF/DMARC records, the risk score) take plain data, so they are tested without the tools or the network.
- **Reviews:** every change went through a pull request reviewed by the other team member, who also ran it, merged it with `main` and probed edge cases. Many real bugs were found this way (chapter 3).
- **Integration tests** in Docker Compose of all open pull requests together, on separate ports and volumes.
- **Detection rate** against the planted weaknesses (chapter 5).
- **Continuous integration** *(set up by Quinten, #75)*: every pull request runs the tests, pyflakes, a check that the migrations match the models (against PostgreSQL, also running the API tests) and the dashboard lint and build. `main` is protected: the three checks must pass, the branch must be up to date with `main`, and one approving review is required.

---

## 3. Problems, Solutions and Troubleshooting

The problems that cost the most time, how we found them and what we changed. The installation-level troubleshooting is in `docs/known-issues.md`.

| Problem | How it showed / was found | Cause | Solution |
|---|---|---|---|
| Lookalike check silently skipped in Docker | Integration test of all PRs: the phishing module reported only 3 of 5 planted weaknesses inside the worker, 5 of 5 locally | Docker's embedded DNS (`127.0.0.11`) does not answer an NS query for a bare top-level domain; the resolver check concluded DNS was broken | Test the resolver with the A record of `a.root-servers.net` (#54) |
| "Nothing found" that means "nothing checked" | Design review of the lookalike check: without network every lookup times out and dnstwist reports no lookalikes | Failures and empty results look the same | Contract rule: fail loudly when nothing could be checked; partial failures become warnings (#32) |
| crt.sh unreliable | HTTP 502 errors and new certificates missing for 14 hours | Overloaded free service with indexing delay | Cert Spotter first, valid certificates only, uncertain answers not reported as clean, circuit breaker (#49) |
| Office documents gave no metadata *(Quinten)* | Testing against the real website | exiftool needs the Perl library Archive::Zip to look inside `.docx` and `.xlsx` | Install `libarchive-zip-perl` in the worker image |
| Broken JSON lines from katana *(Quinten)* | Testing against the real website | `str.splitlines()` also splits on U+0085, which appeared in binary response bodies | `split("\n")` and `-omit-body` |
| Redirects reach other hosts *(Quinten)* | Review with two local servers, one playing a third party | katana and `urlopen` follow redirects before the host is checked | Redirects are no longer followed (#66, #71) |
| A detection rate that could be gamed | Review of the measurement | One finding could tick off two expected entries, and reporting everything would score 100% | Maximum bipartite matching, and precision next to recall (#47) |
| Report unreadable for homoglyphs | Review: "bаdsecurityinc.be" printed as "b■dsecurityinc.be" | The built-in PDF fonts only cover Latin | Bundled DejaVu fonts (#17) |
| GDPR clean-up kept stuck scans forever | Review with a 100-day-old `running` scan | Only finished scans were deleted | Also delete queued or running scans older than the scan timeout (#46) |
| A database change would wipe all data | Adding a column for warnings (#32) | `create_all` never alters an existing table | Alembic migrations with a `migrate` service; existing databases are stamped (#62) |
| Port conflicts with other projects on the same laptop | `port is already allocated` | Other Compose projects on 8000 and 8080 | `docker-compose.override.yml` with `!override` |
| PDF files corrupted in Git | A committed test document did not open | Line-ending conversion of binary files | `*.pdf binary` and `*.ttf binary` in `.gitattributes` |

| A scan that hangs for no reason | Metadata module sometimes never finished | katana checks for updates at every start, and that request could hang | `-duc` on every ProjectDiscovery tool (#76) |
| Phishing module takes over 15 minutes and skips DKIM | Real scan on one network, 5 seconds on another | Docker's DNS let every name that does not exist time out (5 s) instead of answering; phishing looks up hundreds of them | Public resolvers by default, `DNS_SERVERS` setting, fallback to the container's DNS when a network blocks them (#80) |
| "0 subdomains" without network *(Quinten)* | Review: the module run with `--network none` | subfinder and dnsx exit with 0 when they reach nothing | Read their error output: no DNS fails the module, failed sources become a warning (#4) |
| An approval for an address the client no longer uses *(Quinten)* | Review with a test: the address changed between two scans | Approvals were kept per address forever, and cloud addresses are reused | A port scan only targets approved addresses found again in the same scan (#81) |
| A blocked network looks like a closed server *(Quinten)* | Review in a lab network with `--network none` | naabu exits with 0 when no connection is possible | A warning when an approved address has no open port (#5) |

**TO COMPLETE**: problems of the test VM *(Quinten)* and of the last weeks.

---

## 4. Business Context

### 4.1 SMEs

Belgium's economy is an economy of small companies. At the end of 2022 Belgium had almost 1.142 million active SMEs, and 95.6% of its enterprises were micro-enterprises with fewer than ten employees, against an EU average of 93.7% (FPS Economy, as reported by The Brussels Times, [1]). Most of them have no security team and no budget for a penetration test.

They are attacked all the same. In the Flemish government's cybersecurity barometer for 2024, 45.8% of Flemish businesses fell victim to a cyberattack, and the study notes that small and medium enterprises in particular often have inadequate procedures and measures ([2]).

Most attacks start with reconnaissance that costs an attacker nothing: names and usernames from public documents, a lookalike domain, a domain whose email can be spoofed, addresses that appeared in a data breach. That is exactly the information QN-Sentry collects, so an SME sees what an attacker sees before the attack, without needing in-house expertise.

### 4.2 Managed service providers

Many SMEs outsource IT to an MSP. QN-Sentry is designed for that model: one installation holds many clients, each with several domains, and the PDF report is what the MSP hands to its client. An assessment is a concrete, recurring service an MSP can offer, and the risk score makes progress visible between two assessments.

### 4.3 NIS2

The European NIS2 Directive (Directive (EU) 2022/2555, [3]) obliges organisations in critical and important sectors to manage their cybersecurity risks. Belgium transposed it with the law of 26 April 2024 establishing a framework for the cybersecurity of network and information systems of general interest for public security, published in the Belgian Official Gazette on 17 May 2024 and in force since 18 October 2024 ([4], [5]). The Centre for Cybersecurity Belgium (CCB) is the competent authority ([5], [6]).

What it means for SMEs:

- **Directly:** the law applies to entities in the listed sectors, as *essential* or *important* entities depending on sector and size; in principle from medium-sized enterprises upwards ([5], [6]). Covered entities had to register with the CCB, take appropriate and proportionate risk-management measures, report significant incidents, and their management bodies must be trained in cyber risk ([5], [6]).
- **Indirectly, through the supply chain:** supply chain security is one of the required risk-management measures ([6]). A covered company therefore asks its suppliers, many of them SMEs and MSPs, to show that they manage their own risks.

An external exposure assessment supports both: it identifies concrete risks (spoofable email domains, exposed services, leaked credentials) and it documents that they are checked regularly. It does **not** make an organisation compliant on its own: NIS2 asks for a complete risk-management approach, of which knowing your external exposure is one part.

> **To verify before submission** (the official texts could not be retrieved automatically; these come from secondary sources): the exact size thresholds per sector, the incident reporting deadlines (an early warning within 24 hours, a notification within 72 hours and a final report within one month are commonly cited), and the maximum fines. Check them in the Directive on EUR-Lex and in the Belgian law on the Official Gazette, and quote from there.

### 4.4 GDPR

QN-Sentry processes personal data: names in document metadata, usernames, business email addresses and the breaches they appear in.

| Principle | How QN-Sentry applies it |
|---|---|
| Lawfulness | In a real deployment: the client's legitimate interest in securing its organisation, with employees informed (art. 6(1)(f), 13, 14) |
| Purpose limitation | Only used to assess the organisation's exposure |
| Data minimisation | Breach details limited to names, dates and kinds of data; documents kept only during the analysis |
| Storage limitation | Automatic deletion after 90 days |
| Security | Local and single-user by design: all ports bound to `127.0.0.1` (the software and scan data stay on the operator's machine), non-root containers, secrets outside Git. Multi-user login with roles is future work for a shared deployment (#20) |
| Transfers outside the EU | Have I Been Pwned is operated from Australia; only the address is sent, and the default source is the local dataset |
| Roles | The client is controller, the operator of QN-Sentry processor (art. 28 agreement) |

All tests use fictitious people and data on our own domains (chapter 5.4 of the project documentation).

---

## 5. Conclusion

### 5.1 Detection rate

The test environment BadSecurityInc contains weaknesses we planted on purpose; their expected findings are the ground truth in `testenv/detection-rate/expected-findings.json`. The script `detection_rate.py` pairs every expected entry with at most one finding and reports three numbers.

| Measured | Scan | Detection rate (recall) | Expected severity | Precision | Not yet measurable |
|---|---|---|---|---|---|
| 01/10/2026 | `main` + open PRs #49 to #54 | 16/16 (100%) | 100% | 100% | 12 entries (Attack Surface, addresses from #8 and #12) |
| 08/10/2026 | `main` after merging #49 to #77 | 24/24 (100%) | 100% | 100% | 5 entries (Attack Surface) |
| 09/10/2026 | `main` with subdomains (#4) | 25/25 (100%) | 100% | 100% | 4 entries (the test VM #2, web services #6) |
| **TO COMPLETE** | final version after 25/10 | | | | |

A scan without the certificate check (#49) scored 15/16 with the certificate reported as missed, which shows the measurement detects a missing capability.

### 5.2 Strengths

**TO COMPLETE** in the final version; candidates: one contract for every module; no silent "nothing found"; privacy built in (retention, minimisation); a measurable detection rate with precision; thorough mutual reviews that found real bugs.

### 5.3 Weaknesses

**TO COMPLETE**; candidates: the platform is single-user and local by design, so there is no login with roles yet (a shared, multi-tenant deployment would need authentication, #20); dependence on free external services (Certificate Transparency, passive DNS sources) that are sometimes slow or down; breach coverage limited to published and derived addresses.

### 5.4 Future work

Scheduled scans and change detection between scans, alerts for new high-risk findings, live Certificate Transparency monitoring, the HIBP domain search for verified domains (#63), and remembering which addresses a user deliberately excluded from the port scan, so they count as a scope choice instead of a warning (#86).

### 5.5 Self-reflection

**TO COMPLETE** *(each team member separately)*.

---

## 6. Timesheet and Progress

The weekly timesheets (who, what, when, hours) are on Google Drive. **TO COMPLETE**: the totals per person and per week, copied from those timesheets.

### Progress against the planning

| Week | Planned (chapter 7) | Reached |
|---|---|---|
| 1 (28/09 to 04/10) | Domains, data model and finding format, Compose skeleton, modules as command-line proofs of concept | Data contract (26/09), walking skeleton end to end (28/09), dashboard with mock API (28/09), test website and lookalike online (29/09), Phishing, Metadata and Breach modules merged (28/09 to 30/09), PDF report, risk score, retention and detection rate in review (30/09), migrations (01/10). Well ahead of the planning for the platform; Attack Surface and the test VM behind |
| 2 (05/10 to 11/10) | Modules write findings to PostgreSQL; Celery workers and Redis operational; BadSecurityInc target server online with first planted findings | The first two were already reached in week 1. Also done: permission and ownership verification (#3, #48, a week 4 *Should*), warnings per module (#32), continuous integration and branch protection, email addresses and derived breach addresses (#8, #12), installation and user guides, subdomains and port scan with per-address consent (#4, #5, #81), public DNS resolvers (#80); detection rate 25/25. **Behind:** the target server (test VM, #2) is not online yet, so the planted services on it cannot be measured |
| 3 (12/10 to 18/10) | End-to-end MVP | In progress (status 15/10). Done: the risk score is stored per scan (#59), a warning when an approved address has no open port (#5), the report brought up to date with week 2 (#69), and the phishing module uses public DNS resolvers (#80, closed). The whole chain works end to end for a verified domain. **Still needed for the MVP:** the test VM online (#2), web services and technologies (#6), multi-client management (#16), authentication (#20) and the Caddy proxy with the install script (#18), all Quinten's or shared. **TO COMPLETE** at the end of the week: whether the MVP was reached on 18/10 |
| 4 (19/10 to 25/10) | Feature freeze | **TO COMPLETE** |
| 5 (26/10 to 01/11) | Delivery | **TO COMPLETE** |

---

## 7. Sources

**TO COMPLETE**: the date each source was consulted. Only dates we can show are filled in; a source without a date is still to be checked by the person who used it.

| Source | URL | Used for | Consulted |
|---|---|---|---|
| Cert Spotter API reference (SSLMate) | https://sslmate.com/help/reference/ct_search_api_v1 | Certificate search, pagination, terms without a key | 01/10/2026 |
| Have I Been Pwned API v3 | https://haveibeenpwned.com/API/v3 | Breach source, rate limits, flags, attribution | 30/09/2026 *(review of #56)* |
| RFC 7208, Sender Policy Framework | https://www.rfc-editor.org/rfc/rfc7208 | SPF evaluation, 10-lookup limit, permerror | 30/09/2026 *(review of #57)* |
| RFC 7489, DMARC | https://www.rfc-editor.org/rfc/rfc7489 | DMARC policies | |
| RFC 6962, Certificate Transparency | https://www.rfc-editor.org/rfc/rfc6962 | Background of CT logs | |
| dnstwist | https://github.com/elceef/dnstwist | Lookalike domain generation (version 20250130) | |
| katana (ProjectDiscovery) | https://github.com/projectdiscovery/katana | Website crawler (version 1.7.0) | |
| ExifTool | https://exiftool.org | Document metadata | |
| crt.sh | https://crt.sh | Backup Certificate Transparency search | |
| Alembic documentation | https://alembic.sqlalchemy.org | Database migrations | |
| DejaVu fonts | https://github.com/dejavu-fonts/dejavu-fonts | Unicode fonts in the PDF report (version 2.37) | 01/10/2026 |
| GDPR (Regulation (EU) 2016/679) | https://eur-lex.europa.eu/eli/reg/2016/679/oj | Legal framework | |
| [1] The Brussels Times, "Record number of SMEs in Belgium, number of jobs rising" (22/01/2024), figures of the FPS Economy | https://www.brusselstimes.com/887135/record-number-of-smes-in-belgium-number-of-jobs-rising | 4.1: number of SMEs, share of micro-enterprises | 08/10/2026 |
| [2] The Brussels Times, "Almost half of Flemish companies were cyberattack victims in 2024" (04/05/2025), on the cybersecurity barometer commissioned by the Flemish government | https://www.brusselstimes.com/1563269/almost-half-of-flemish-companies-were-cyberattack-victims-in-2024 | 4.1: share of victims, SMEs | 08/10/2026 |
| [3] Directive (EU) 2022/2555 (NIS2) | https://eur-lex.europa.eu/eli/dir/2022/2555/oj | 4.3 | **TO COMPLETE**: read the text itself |
| [4] Belgian law of 26 April 2024 (NIS2 law), Belgian Official Gazette 17/05/2024 | https://www.ejustice.just.fgov.be | 4.3 | **TO COMPLETE**: read the text itself |
| [5] Fieldfisher, "Navigating NIS2: Understanding Belgium's Transposition Law for Cybersecurity Compliance" | https://www.fieldfisher.com/en/locations/belgium/insights/navigating-nis2-understanding-belgium-s-transposit | 4.3: publication, entry into force, registration, CCB | 08/10/2026 (via search) |
| [6] PwC Belgium, "NIS 2 directive" | https://www.pwc.be/en/services/cyber-privacy/NIS-2-directive.html | 4.3: scope, registration, measures | 08/10/2026 (via search) |
| Centre for Cybersecurity Belgium, NIS2 pages | https://ccb.belgium.be | 4.3 | **TO COMPLETE**: the site refuses automated access, read it in a browser |
