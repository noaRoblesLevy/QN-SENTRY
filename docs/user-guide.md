# User Guide

How to assess a company with QN-Sentry: add it as a client, add its domain, run a scan, read the findings, the risk score and the report. It assumes QN-Sentry is running (see the [installation guide](installation.md)) and open on http://localhost:8080.

> **Only add domains you own or have written permission to assess.** QN-Sentry only uses public information and never tries to log in or exploit anything, but a scan does look up DNS records, crawl the website and download its public documents (see the [legal and ethical framework](project/05-legal-ethical.md)). During this project, the only domain to scan is `badsecurityinc.be`, the fictitious test company.

## 1. Words used in the dashboard

| Word | Meaning |
|---|---|
| **Client** | An organisation you assess, e.g. BadSecurityInc |
| **Domain** | A domain name of that client, e.g. `badsecurityinc.be`. A domain belongs to one client only. |
| **Scan** | One assessment of one domain at one moment. Every scan runs the four modules. |
| **Module** | One kind of check: Attack surface, Document metadata, Phishing domains, Employee breaches |
| **Finding** | One thing a module found, with a severity, a plain-language explanation and technical details |
| **Severity** | How serious a finding is: Info, Low, Medium, High or Critical (section 5) |

## 2. Add a client and its domain

1. On the **Clients** page, type the client's name under **Add a client** and click **Add client**.
2. Click the client in the list to open its page.
3. Under **Add a domain**, type the domain without `https://` or a path, e.g. `badsecurityinc.be`, tick **I own this domain or have written permission to scan it.** and click **Add domain**.
4. **Prove that you control the domain.** Under the domain the dashboard shows a TXT record, e.g. `qn-sentry-verify=2d0a9cfec5a8809343668cb8a658c897`. Click **Copy**, add it as a TXT record to the domain at its DNS provider (one.com for `badsecurityinc.be`), wait a few minutes and click **Verify**. The **Ownership** column then says **Verified** and **Run scan** becomes available.

The record is checked again at **every scan**. Removing it withdraws the permission: the next scan is refused and the domain shows the verification step again. Keep the record as long as the domain may be scanned.

A domain added before this check existed shows **Confirm permission** first; click it to confirm, then verify as above.

| Message | What it means |
|---|---|
| `Enter a valid domain name, e.g. example.be` | Only the domain name, in letters, digits, hyphens and dots, e.g. `badsecurityinc.be` |
| `badsecurityinc.be is already added.` | The domain already belongs to a client (this one or another). Open that client instead. |
| `Confirm that you own this domain or have written permission to scan it.` | Tick the confirmation before adding the domain |
| `The TXT record ... was not found on ...` | The record is not visible in DNS yet: check it at the DNS provider and try again in a few minutes |
| `The TXT record ... is no longer on ..., so the permission to scan it is withdrawn.` | The record was removed. Add it again and click **Verify** |
| `The DNS records of ... could not be looked up. Try again in a moment.` | A DNS problem, not a missing record: nothing changed, try again |

A client can have several domains (e.g. a `.be` and a `.com`); each domain is scanned separately.

## 3. Run a scan

On the client page, click **Run scan** next to the domain. The dashboard opens the scan page right away; the scan runs in the background, so you can leave the page and come back.

The **Progress** table shows each module:

| Status | Meaning |
|---|---|
| Waiting | The module has not started yet |
| Running | The module is working |
| Completed | The module finished; the number of findings is shown |
| Completed with warnings | The module finished, but a part of it could not be checked; each warning is shown under it, e.g. "1 of 12 document(s) could not be downloaded". The module's results are real, but findings may be missing for that part |
| Failed | The module could not run; the reason is shown under it (e.g. the website could not be reached). The other modules still run. |

The page refreshes itself every 5 seconds until the scan has finished. The scan as a whole ends as:

| Scan status | Meaning |
|---|---|
| Completed | Every module finished |
| Completed with errors | The scan finished, but at least one module failed: its part of the results is missing |
| Failed | The scan could not run at all (e.g. the worker stopped). Start a new scan. |

A scan of `badsecurityinc.be` currently takes about half a minute: Document metadata about 15 seconds (crawling the site and reading 12 documents), Phishing domains about 10 seconds (hundreds of DNS lookups). Attack surface will take longer once it scans ports (#4 to #6).

Only one scan per domain can run at a time; **Run scan** on a domain with a running scan gives `A scan is already running for this domain.`

## 4. Read the findings

The scan page shows, from top to bottom:

1. **Totals per severity**, and the **risk score** (section 6).
2. **Progress** per module (section 3).
3. **Findings**, grouped per module and sorted from most to least severe. Filter them with **Module** and **Severity**.

Click a finding to open it: you see the explanation (what it is, why it is a risk, what to do) and the technical details, such as the DNS records, the document's metadata or the breaches an address appears in.

What the modules look for, and what to do about it:

| Module | Examples of findings | Typical advice |
|---|---|---|
| Attack surface | Forgotten subdomains, open ports, outdated server versions | Remove what is not used; update or shield what is |
| Document metadata | Author names, usernames, internal paths (`\\SRV-FS01\...`), old Office versions in public documents | Remove metadata before publishing ("Inspect Document" in Office) |
| Phishing domains | Registered lookalike domains (e.g. `badsecuritylnc.be`), certificates for them, weak SPF, DMARC or DKIM | Consider a takedown or defensive registration; set SPF to `-all` and DMARC to `p=reject` |
| Employee breaches | Business email addresses in known data breaches | Change the leaked passwords everywhere they were used, turn on multi-factor authentication |

## 5. Severity levels

| Level | Meaning | Example |
|---|---|---|
| Info | Useful to know, not a risk on its own | A subdomain was found |
| Low | Small risk, follow up when convenient | A document reveals an employee's name |
| Medium | Clear risk, should be fixed | A document reveals internal file paths |
| High | Serious risk, fix soon | A lookalike domain that can receive email; an address in a breach with passwords |
| Critical | Directly exploitable, fix immediately | Used sparingly: QN-Sentry only looks from the outside, so it can rarely prove that |

The full rules are in the [data contract](project/10-data-contract.md), section 10.2.

## 6. Risk score

Every finished scan gets a score from 0 to 100 with a level: **Low** (0 to 24), **Moderate** (25 to 49), **High** (50 to 74) or **Very high** (75 to 100). The client's score is that of its riskiest domain.

- Each finding adds points by severity, and the score grows more slowly as points add up, so many small findings never outweigh a few serious ones by accident.
- The score is at least the level of the worst finding: one High finding always gives at least 50 (High), one Critical at least 75 (Very high).
- A score is marked **incomplete** with `*` and "Based on N of 4 modules without problems" when a module failed (**Completed with errors**), reported warnings, or is not available in this version (Attack surface, until #4 to #6): findings may be missing there. A client's score is incomplete when the latest scan of any of its domains is.
- A running or failed scan has no score ("No score yet").

How it is calculated: [data contract](project/10-data-contract.md), section 10.7.

## 7. The PDF report

On a finished scan, click **Download report** for a PDF written for management: a summary, the totals and risk score, every important finding explained in plain language, the other findings in a table, and what was checked. It is marked confidential: it contains names and email addresses of employees.

A failed scan has no report: nothing was checked, so a report would look like a clean result. Run a new scan instead.

## 8. Scan history and data retention

The client page lists every scan under **Scan history**; click **View scan** to open an earlier one. Comparing two scans shows whether a problem was fixed.

Scan results are kept for **90 days** and then deleted automatically, because findings contain personal data (GDPR). The period is set by `RETENTION_DAYS` (see the [installation guide](installation.md#3-configuration)).

## 9. Light and dark

The button at the top right switches between the dark and the light theme. The choice is remembered in the browser.

When something does not work as described, see [Known issues and difficult points](known-issues.md).
