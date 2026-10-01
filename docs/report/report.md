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

**TO COMPLETE**: addresses derived from author names and the naming convention (#12), with the result on BadSecurityInc.

### 2.5 Risk score

One number per scan and per client, so management sees at a glance how exposed the organisation is (#19, data contract 10.7).

- Each finding adds points by severity (critical 25, high 10, medium 4, low 1, info 0), and `score = 100 × (1 − e^(−points/50))`. A plain sum would reach 100 after a few findings; an average would drop when harmless findings are added. This curve has neither problem and never decreases when a finding is added.
- The score is at least the floor of the worst finding (critical 75, high 50, medium 25), decided in review: without it one critical finding scored 39, "moderate", while critical means "fix immediately".
- A partial scan keeps its score but is marked incomplete; a running or failed scan has none.
- The score is computed from the findings when requested, not stored, because there were no migrations yet; storing it is #59 now that Alembic is in.

### 2.6 PDF report

The report (#17) is written for management: a summary in plain language, the totals per severity, every critical, high and medium finding with its explanation, the others in a table, and what was checked. It is generated with reportlab from plain data, so it is tested without a database. Choices: a failed scan gets no report (it would read as a clean result); the bundled DejaVu fonts print Cyrillic and Greek homoglyphs correctly, with their `xn--` form next to them; sources that require attribution (Have I Been Pwned) are credited.

### 2.7 Privacy and security by design

| Measure | Where |
|---|---|
| Scan results are deleted after 90 days, also stuck scans, every night and when the worker starts | `worker/retention.py` (#46) |
| Documents only exist in a temporary folder during the analysis | Metadata module |
| Breach data: only names, dates and kinds of data | Breach module |
| API and dashboard bound to `127.0.0.1`; database and Redis without published ports | `docker-compose.yml` |
| Every container runs as a non-root user | Dockerfiles (#60) |
| Secrets only in `.env`, never in Git | `.gitignore` |

The full legal and ethical framework is chapter 5 of the project documentation.

### 2.8 Quality: how we know it works

- **Unit tests** without network: DNS, HTTP, the clock and external tools are replaced by fakes. **TO COMPLETE**: final number of tests.
- **Reviews:** every change went through a pull request reviewed by the other team member, who also ran it, merged it with `main` and probed edge cases. Many real bugs were found this way (chapter 3).
- **Integration tests** in Docker Compose of all open pull requests together, on separate ports and volumes.
- **Detection rate** against the planted weaknesses (chapter 5).
- **TO COMPLETE** *(Quinten, #67)*: continuous integration on every pull request.

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
| Redirects reach other hosts *(Quinten)* | Review with two local servers, one playing a third party | katana and `urlopen` follow redirects before the host is checked | Open, #66; chapter 5.2 states the gap |
| A detection rate that could be gamed | Review of the measurement | One finding could tick off two expected entries, and reporting everything would score 100% | Maximum bipartite matching, and precision next to recall (#47) |
| Report unreadable for homoglyphs | Review: "bаdsecurityinc.be" printed as "b■dsecurityinc.be" | The built-in PDF fonts only cover Latin | Bundled DejaVu fonts (#17) |
| GDPR clean-up kept stuck scans forever | Review with a 100-day-old `running` scan | Only finished scans were deleted | Also delete queued or running scans older than the scan timeout (#46) |
| A database change would wipe all data | Adding a column for warnings (#32) | `create_all` never alters an existing table | Alembic migrations with a `migrate` service; existing databases are stamped (#62) |
| Port conflicts with other projects on the same laptop | `port is already allocated` | Other Compose projects on 8000 and 8080 | `docker-compose.override.yml` with `!override` |
| PDF files corrupted in Git | A committed test document did not open | Line-ending conversion of binary files | `*.pdf binary` and `*.ttf binary` in `.gitattributes` |

**TO COMPLETE**: problems of the Attack Surface module and the test VM *(Quinten)*, and of the last weeks.

---

## 4. Business Context

### 4.1 SMEs

**TO COMPLETE** with sources: share of SMEs in the Belgian economy, how often they are hit by phishing and ransomware, and why they rarely have security staff. Point to make: reconnaissance costs an attacker almost nothing and uses exactly the information QN-Sentry collects.

### 4.2 Managed service providers

Many SMEs outsource IT to an MSP. QN-Sentry is designed for that model: one installation holds many clients, each with several domains, and the PDF report is what the MSP hands to its client. An assessment is a concrete, recurring service an MSP can offer, and the risk score makes progress visible between two assessments.

### 4.3 NIS2

**TO COMPLETE** with sources (Belgian NIS2 law and the Centre for Cybersecurity Belgium): which organisations fall under it, the duty to take appropriate risk-management measures, and why suppliers of those organisations (often SMEs) are asked to show the same. An external exposure assessment helps to identify risks and to show that they are managed; it does not make an organisation compliant on its own.

### 4.4 GDPR

QN-Sentry processes personal data: names in document metadata, usernames, business email addresses and the breaches they appear in.

| Principle | How QN-Sentry applies it |
|---|---|
| Lawfulness | In a real deployment: the client's legitimate interest in securing its organisation, with employees informed (art. 6(1)(f), 13, 14) |
| Purpose limitation | Only used to assess the organisation's exposure |
| Data minimisation | Breach details limited to names, dates and kinds of data; documents kept only during the analysis |
| Storage limitation | Automatic deletion after 90 days |
| Security | Local-only ports, non-root containers, secrets outside Git; authentication planned (#20) |
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
| **TO COMPLETE** | final version after 25/10 | | | | |

A scan without the certificate check (#49) scored 15/16 with the certificate reported as missed, which shows the measurement detects a missing capability.

### 5.2 Strengths

**TO COMPLETE** in the final version; candidates: one contract for every module; no silent "nothing found"; privacy built in (retention, minimisation); a measurable detection rate with precision; thorough mutual reviews that found real bugs.

### 5.3 Weaknesses

**TO COMPLETE**; candidates: no authentication yet; ownership verification and allowlist (#3, #48); dependence on free external services; breach coverage limited to published and derived addresses.

### 5.4 Future work

Scheduled scans and change detection between scans, alerts for new high-risk findings, live Certificate Transparency monitoring, the HIBP domain search for verified domains (#63), storing the risk score (#59).

### 5.5 Self-reflection

**TO COMPLETE** *(each team member separately)*.

---

## 6. Timesheet and Progress

The weekly timesheets (who, what, when, hours) are on Google Drive. **TO COMPLETE**: the totals per person and per week, copied from those timesheets.

### Progress against the planning

| Week | Planned (chapter 7) | Reached |
|---|---|---|
| 1 (28/09 to 04/10) | Domains, data model and finding format, Compose skeleton, modules as command-line proofs of concept | Data contract (26/09), walking skeleton end to end (28/09), dashboard with mock API (28/09), test website and lookalike online (29/09), Phishing, Metadata and Breach modules merged (28/09 to 30/09), PDF report, risk score, retention and detection rate in review (30/09), migrations (01/10). Well ahead of the planning for the platform; Attack Surface and the test VM behind |
| 2 (05/10 to 11/10) | **TO COMPLETE** | |
| 3 (12/10 to 18/10) | End-to-end MVP | **TO COMPLETE** |
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
| Belgian NIS2 law, Centre for Cybersecurity Belgium | https://ccb.belgium.be | Business context | |
