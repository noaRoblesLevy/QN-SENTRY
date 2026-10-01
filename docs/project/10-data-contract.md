# 10. Data Contract

This chapter defines the agreements between the parts of QN-Sentry: the format of a finding, the severity levels, how modules are called, what information modules share, and the API used by the dashboard. All modules, the worker, the dashboard, the PDF report and the risk score depend on these agreements, so changes are made through a pull request reviewed by both team members.

## 10.1 Finding Format

A *finding* is one thing a module discovers about the client's external exposure. Every module returns its results in the same format, so the dashboard, the report and the risk score never need module-specific code.

| Field | Type | Meaning | Example |
|---|---|---|---|
| `module` | text | The module that produced the finding | `phishing` |
| `type` | text | The kind of finding, as a fixed code (see 10.1.1) | `lookalike_domain` |
| `title` | text | Short one-liner shown in the dashboard | `Registered lookalike domain badsecuritylnc.be` |
| `description` | text | Explanation in plain language of why this is a risk, used in the report | `This domain looks like the company domain and can send email. It can be used to send phishing emails to employees and customers.` |
| `severity` | text | How serious the finding is (see 10.2) | `high` |
| `asset` | text | What the finding is about: a domain, host, host and port, URL or email address | `badsecuritylnc.be` |
| `details` | JSON | Module-specific technical data | `{"fuzzer": "homoglyph", "mx": ["mail.badsecuritylnc.be"]}` |

The database adds `id`, `scan_id` and `created_at` automatically; modules do not set these.

Example of a complete finding:

```json
{
  "module": "breach",
  "type": "breached_email",
  "title": "jan.peeters@badsecurityinc.be appears in 2 data breaches",
  "description": "This business email address appears in known data breaches, including one that exposed passwords. If the employee reuses that password, an attacker can try to log in to company systems.",
  "severity": "high",
  "asset": "jan.peeters@badsecurityinc.be",
  "details": {
    "origin": "derived from 'Jan Peeters' (first.last)",
    "breaches": [
      { "name": "ExampleShop", "date": "2021-06-22", "data": ["Emails", "Passwords"] },
      { "name": "ExampleForum", "date": "2019-03-10", "data": ["Emails", "Usernames"] }
    ]
  }
}
```

### 10.1.1 Finding Types

`type` is a fixed code, never free text. The dashboard, risk score and future change detection use it instead of the title, so titles can be reworded without breaking anything. Initial list, extended through a pull request when a module needs a new type:

| Module | Types |
|---|---|
| `attack_surface` | `subdomain`, `open_port`, `web_service` |
| `metadata` | `document_metadata`, `email_address`, `email_convention` |
| `phishing` | `lookalike_domain`, `lookalike_certificate`, `email_security` |
| `breach` | `breached_email` |

## 10.2 Severity Levels

Severity is based on two questions: how easily can an attacker abuse this, and how much damage can it do?

| Level | Meaning | Example from BadSecurityInc |
|---|---|---|
| `info` | Useful to know, not a risk on its own | Subdomain `mail.badsecurityinc.be` found |
| `low` | Small risk, follow up when convenient | `badsecuritylnc.be` registered without an MX record |
| `medium` | Clear risk, should be fixed | DMARC policy set to `p=none`, allowing email spoofing |
| `high` | Serious risk, fix soon | `badsecuritylnc.be` registered with an MX record; `jan.peeters@badsecurityinc.be` in a breach that exposed passwords |
| `critical` | Directly exploitable without further steps, fix immediately | A database reachable from the internet without a password |

Because QN-Sentry only performs passive reconnaissance, it can rarely prove that something is directly exploitable. `critical` is therefore used sparingly, so the higher levels keep their meaning.

## 10.3 Module Interface

Every module works the same way, so the worker can run them one after another in a loop and each team member can build modules independently.

- **Input:** the module receives the scan context (see 10.4), which contains the domain being scanned and information from earlier modules.
- **Output:** the module returns a list of findings in the format of 10.1.
- **Database:** modules never write to the database. Only the worker stores findings. This keeps modules testable without a database and keeps all database code in one place.

### 10.3.1 Error Handling

| Situation | Example | Behaviour |
|---|---|---|
| Part of a module fails, but it still has useful results | crt.sh times out, but dnstwist already found lookalike domains | The module catches the error, logs a warning and returns the findings it has |
| The whole module cannot run | dnstwist is not installed | The module raises an error. The worker marks the module as `failed` with the error message and continues with the next module |

Rule of thumb: *do I still have something useful to return?* If yes, catch the error. If no, let it through.

### 10.3.2 Scan and Module Status

| Scan status | Meaning |
|---|---|
| `queued` | The scan is waiting for a worker |
| `running` | Modules are running |
| `completed` | All modules finished successfully |
| `partial` | The scan finished, but at least one module failed |
| `failed` | The scan could not run at all |

Each module in a scan has its own status: `pending`, `running`, `completed` or `failed`. The dashboard shows these to display the progress per module.

## 10.4 Scan Context

Modules share information through a scan context. The worker creates it at the start of a scan and passes it to every module. Modules fill in what they discover, so later modules can use it.

| Field | Type | Filled by | Example |
|---|---|---|---|
| `domain` | text | Worker, at the start of the scan | `badsecurityinc.be` |
| `person_names` | list of text | Metadata | `["Jan Peeters", "Sofie Maes"]` |
| `emails` | list of text | Metadata | `["info@badsecurityinc.be", "sofie.maes@badsecurityinc.be"]` |
| `email_convention` | text, or empty if unknown | Metadata | `first.last` |

The Breach module combines these to derive likely addresses that were never published:

```
"Jan Peeters" + first.last + badsecurityinc.be  ->  jan.peeters@badsecurityinc.be
```

### 10.4.1 Module Order

Because modules depend on each other through the context, they always run in this order:

1. Attack Surface Mapping
2. Document Metadata Analysis
3. Phishing Domain Detection
4. Employee Breach Exposure (needs the names, emails and convention from Metadata)

### 10.4.2 Email Conventions

`email_convention` only uses values from this list. The list is defined in one place in the code and used by both the Metadata module (which detects the convention) and the Breach module (which applies it), so both always use exactly the same values.

| Value | Result for "Jan Peeters" |
|---|---|
| `first.last` | `jan.peeters@` |
| `firstlast` | `janpeeters@` |
| `flast` | `jpeeters@` |
| `f.last` | `j.peeters@` |
| `first_last` | `jan_peeters@` |
| `last.first` | `peeters.jan@` |
| `first` | `jan@` |
| *(empty)* | No convention detected; the Breach module only checks published addresses |

## 10.5 API Endpoints

The dashboard communicates with the backend through these REST endpoints. All endpoints return JSON.

| Method | URL | Purpose |
|---|---|---|
| `GET` | `/api/clients` | List all clients |
| `POST` | `/api/clients` | Create a client |
| `GET` | `/api/clients/{id}` | Get a client with its domains and their scans |
| `POST` | `/api/clients/{id}/domains` | Add a domain to a client |
| `POST` | `/api/domains/{id}/scans` | Start a scan for a domain |
| `GET` | `/api/scans/{id}` | Get the scan status and the status per module |
| `GET` | `/api/scans/{id}/findings` | Get the findings of a scan |

Example response of `GET /api/scans/7`:

```json
{
  "id": 7,
  "domain": "badsecurityinc.be",
  "status": "running",
  "created_at": "2026-10-14T10:02:11Z",
  "modules": [
    { "module": "attack_surface", "status": "completed", "finding_count": 12, "error": null },
    { "module": "metadata", "status": "running", "finding_count": 0, "error": null },
    { "module": "phishing", "status": "pending", "finding_count": 0, "error": null },
    { "module": "breach", "status": "pending", "finding_count": 0, "error": null }
  ]
}
```

### 10.5.1 Scan Progress

A scan takes 10 to 30 minutes. The dashboard uses polling: while a scan is `queued` or `running`, it requests `GET /api/scans/{id}` every 5 seconds. Polling stops when the scan is `completed`, `partial` or `failed`. A delay of a few seconds does not matter for a scan of this length, and polling is much simpler than pushing updates over WebSockets.

### 10.5.2 Later Endpoints

These are added by their own issues and are not part of the walking skeleton (#1):

| Endpoint | Issue |
|---|---|
| Approve a domain on the target allowlist | #3 |
| Download the PDF report of a scan | #17 |
| Log in | #20 |

### 10.5.3 Request and Response Bodies

| Endpoint | Request body | Success | Response |
|---|---|---|---|
| `GET /api/clients` | | `200` | List of clients: `id`, `name`, `domains` (`id`, `name`), `risk_score`, `risk_level`, `risk_complete` (10.7) |
| `POST /api/clients` | `{"name": "BadSecurityInc"}` | `201` | The new client, with an empty `domains` list |
| `GET /api/clients/{id}` | | `200` | The client with `risk_score`, `risk_level` and `risk_complete`; every domain also has `scans` (`id`, `status`, `created_at`, `risk_score`, `risk_level`, `risk_complete`), newest first |
| `POST /api/clients/{id}/domains` | `{"name": "badsecurityinc.be"}` | `201` | The new domain: `id`, `name` |
| `POST /api/domains/{id}/scans` | | `201` | The new scan: `id`, `status` (`queued`), `created_at` |
| `GET /api/scans/{id}` | | `200` | See the example above, plus `risk_score`, `risk_level` and `risk_complete` (10.7) |
| `GET /api/scans/{id}/findings` | | `200` | List of findings in the format of 10.1, plus `id` and `created_at` |

Names are trimmed. Domain names are stored in lowercase without a trailing dot and must be a plain domain name (`badsecurityinc.be`, not `https://badsecurityinc.be/`).

### 10.5.4 Rules and Errors

- **A domain belongs to one client only.** Adding a domain that already exists, for any client, returns `409`.
- **One active scan per domain.** Starting a scan while another scan of that domain is `queued` or `running` returns `409`.
- **Stuck scans do not block their domain.** A scan still `queued` or `running` after `SCAN_TIMEOUT_MINUTES` (default 120) is marked `failed` when a new scan of that domain is started. Its unfinished modules get the reason as `error`.
- **Interrupted scans end as `failed`.** If a worker stops during a scan, the scan is marked `failed` ("The worker stopped during this scan") instead of being run again, so findings are never stored twice.
- **Every error has the same shape:** `{"detail": "..."}`, with one readable sentence the dashboard can show as is. This includes validation errors: FastAPI returns a list of error objects by default, and the API turns that into a single message.

| Status | When | Example `detail` |
|---|---|---|
| `404` | The client, domain or scan does not exist | `Scan not found` |
| `409` | The request conflicts with the rules above | `A scan is already running for this domain.` |
| `422` | The request body is invalid | `Enter a valid domain name, e.g. example.be` |
| `503` | The scan could not be queued (Redis unavailable); the scan is marked `failed` | `The scan queue is unavailable. Try again later.` |

## 10.6 Open Questions

- **Name normalisation:** how names with multiple words, hyphens or accents are converted to email addresses (e.g. "Sofie Van den Broeck" becomes `sofie.vandenbroeck` or `sofie.van.den.broeck`; "Gérard" becomes `gerard`). The Metadata module (#8) and the Breach module (#12) must use the same rule.
- **Descriptions:** does each module write its own `description`, or is there one fixed text per `type` that is reused?
- **Combined findings:** some findings are more serious in combination (e.g. a permissive SPF record together with DMARC `p=none`). Does the module decide this, or does the risk score (#19) look at combinations?

## 10.7 Risk Score

One number from 0 to 100 that summarises a scan for management (#19). Agreed in the review of #53; the values live in one place (`backend/qnsentry/risk.py`).

1. Every finding adds points by severity:

| Severity | Points |
|---|---|
| `critical` | 25 |
| `high` | 10 |
| `medium` | 4 |
| `low` | 1 |
| `info` | 0 |

2. `curve = 100 × (1 − e^(−points / 50))`, rounded.
3. `score = max(curve, floor of the worst finding)`:

| Worst finding | Floor |
|---|---|
| `critical` | 75 (very high) |
| `high` | 50 (high) |
| `medium` | 25 (moderate) |
| `low`, `info` | 0 |

The curve gives diminishing returns: the first serious findings raise the score the most, the score never exceeds 100, and adding a finding never lowers it. A plain sum would reach 100 after a few findings and stop telling anything apart; an average would drop when harmless findings are added.

The floor makes the level match the worst finding: with the curve alone, one critical finding ("fix immediately", 10.2) would score 39 "moderate", and a manager who only reads the level would be misled. Above the floor the curve decides, so many findings still weigh more than one.

| Score | Level (`risk_level`) |
|---|---|
| 0 to 24 | `low` |
| 25 to 49 | `moderate` |
| 50 to 74 | `high` |
| 75 to 100 | `very_high` |

| Example | Points | Score |
|---|---|---|
| Only `info` findings | 0 | 0, low |
| One `medium` | 4 | 25, moderate (floor; curve 8) |
| One `high` | 10 | 50, high (floor; curve 18) |
| One `critical` | 25 | 75, very high (floor; curve 39) |
| 20 `low` | 20 | 33, moderate (curve) |
| Real scan of `badsecurityinc.be` on 30/09: 4 high, 4 medium, 8 low | 64 | 72, high (curve) |
| Full ground truth of the test environment (#47): 7 high, 6 medium, 9 low | 103 | 87, very high (curve) |

Rules:
- **Scan:** only a `completed` or `partial` scan has a score. While a scan runs the findings are incomplete, and a `failed` scan would look safe because it found little: both return `null`.
- **Partial scan:** keeps its score, with `risk_complete: false`, because a failed module may have missed findings. The dashboard marks the score with an asterisk and shows "Based on 3 of 4 modules". `risk_complete` is `true` for a completed scan and `null` without a score.
- **Client:** the score of its **riskiest domain**, using each domain's newest scan that has a score; `risk_complete` comes from that scan.
- The score is **computed from the stored findings** when it is requested, not stored separately, so it always matches the findings. Changing the weights therefore also changes the score of older scans.

