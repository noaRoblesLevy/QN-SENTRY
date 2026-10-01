# QN-Sentry

**An OSINT platform for digital risk assessment for SMEs.**

Given a company domain, QN-Sentry performs an on-demand OSINT assessment of the organisation's external exposure and presents the results in a dashboard and report with a risk score. This way, an SME sees its attack surface from an attacker's perspective, before an attacker does.

> **Status:** in development – Integration Project 2, ISB (2026–2027)

## Modules

- **Attack Surface Mapping** – subdomains, open ports, service versions and web technologies
- **Document Metadata Analysis** – author names, usernames, software versions and internal paths leaked in public documents
- **Phishing Domain Detection** – registered lookalike domains, certificates for lookalikes and email security (SPF, DMARC, DKIM)
- **Employee Breach Exposure** – business email addresses that appear in known data breaches

## Technology

Python · FastAPI · Celery + Redis · PostgreSQL · React · Caddy · Docker Compose

## Getting started

Requirements: Docker with Docker Compose.

```bash
cp .env.example .env          # then choose your own database password in .env
docker compose up -d --build
```

| Service | Address | Purpose |
|---|---|---|
| `dashboard` | http://localhost:8080 | Web interface: clients, domains, scans and findings |
| `api` | http://localhost:8000/docs | REST API with interactive documentation |
| `worker` | – | Celery worker that runs the scans |
| `migrate` | – | Brings the database schema up to date, then exits; `api` and `worker` wait for it |
| `db` | internal only | PostgreSQL |
| `redis` | internal only | Task queue between the API and the worker |

The dashboard's nginx forwards `/api` to the `api` service, so the dashboard and the API share one address. For development with live reload, see [`dashboard/README.md`](dashboard/README.md).

## Project structure

```
backend/qnsentry/
├── api/          FastAPI app: routers (endpoints) and schemas (request and response bodies)
├── db/           SQLAlchemy models, the database session and the Alembic migrations
├── modules/      OSINT modules and the module interface
├── worker/       Celery app and the task that runs a scan
└── config.py     Settings read from environment variables
```

## Database migrations

The schema is managed with [Alembic](https://alembic.sqlalchemy.org/): every change to [`backend/qnsentry/db/models.py`](backend/qnsentry/db/models.py) needs a migration in `backend/qnsentry/db/migrations/versions/`. The `migrate` service applies new migrations on every `docker compose up`, so existing data is kept.

After changing a model, generate the migration with the next number (`0002`, `0003`, ...):

```bash
docker compose up -d db
docker compose run --rm -u root -v ./backend/qnsentry/db/migrations/versions:/app/qnsentry/db/migrations/versions migrate alembic revision --autogenerate --rev-id 0002 -m "add warnings to module runs"
```

On Linux, add `-u "$(id -u):$(id -g)"` instead of `-u root`, or the generated file is owned by root (Docker Desktop on Windows and macOS handles this itself).

Always read the generated file before committing it: autogenerate can miss changes (a renamed column becomes a drop and an add) and writes the CHECK constraint of an enum column twice; remove those `sa.CheckConstraint` lines, the `sa.Enum` creates the constraint itself.

Before merging a pull request that changes a model, check that the models and the migrations match (prints `No new upgrade operations detected`):

```bash
docker compose run --rm migrate alembic check
```

Databases created before Alembic (by `create_all`) are marked as migration `0001` the first time `migrate` runs, without changing their tables.

The API and the worker no longer create tables themselves: when running them outside Docker, run `python -m qnsentry.db.migrate` first.

## How a scan runs

1. `POST /api/domains/{id}/scans` stores a scan (`queued`) with one module run per module (`pending`) and puts a task in Redis. The API does not wait for the scan.
2. A Celery worker picks up the task and runs the modules one after another, in the order of `MODULES` in `backend/qnsentry/modules/__init__.py`.
3. For each module, the worker marks it `running`, calls `module.run(context)`, stores the returned findings and its warnings, and marks it `completed`. If a module raises an exception, it is marked `failed` with the error message and the next module still runs.
4. The scan ends as `completed`, or `partial` when at least one module failed. The dashboard polls `GET /api/scans/{id}` to show the progress.

## Finding format

Every module returns its results in the same format, so the dashboard, the report and the risk score never need module-specific code. The full agreement, including the finding types and severity levels, is in the [data contract](docs/project/10-data-contract.md).

| Field | Meaning |
|---|---|
| `module` | Name of the module that produced the finding, e.g. `phishing` |
| `type` | Fixed code for the kind of finding, e.g. `lookalike_domain` (contract 10.1.1) |
| `title` | Short one-liner shown in the dashboard |
| `description` | Plain-language explanation of the risk, used in the report |
| `severity` | `info`, `low`, `medium`, `high` or `critical` (contract 10.2) |
| `asset` | What the finding is about: a domain, host, host and port, URL or email address |
| `details` | Module-specific technical data (JSON) |

The database adds `id`, `scan_id` and `created_at`.

## Adding a module

A module is a class that implements the interface in [`backend/qnsentry/modules/base.py`](backend/qnsentry/modules/base.py):

```python
from qnsentry.db.models import Severity
from qnsentry.modules.base import Finding, Module, ScanContext


class PhishingModule(Module):
    name = "phishing"

    def run(self, context: ScanContext) -> list[Finding]:
        findings = []
        # ... look up lookalike domains for context.domain ...
        findings.append(
            Finding(
                module=self.name,
                type="lookalike_domain",
                title="Registered lookalike domain badsecuritylnc.be",
                description="This domain looks like the company domain ...",
                severity=Severity.HIGH,
                asset="badsecuritylnc.be",
                details={"fuzzer": "homoglyph"},
            )
        )
        return findings
```

Rules (contract 10.3):

- **Never write to the database.** Return the findings; the worker stores them. This keeps modules testable without a database.
- **Share information through the context.** Read what earlier modules found (e.g. `context.person_names` from Metadata) and fill in what later modules need.
- **Partial failure:** if part of the module fails but it still has useful results, catch the error, call `context.warn("One readable sentence, with a count and without personal data")` and return what you have. The warning is shown with the module in the dashboard and the report.
- **Total failure:** if the module cannot run at all (e.g. a tool is missing), raise an exception. The worker marks the module as `failed` and continues.
- **External tools** (subfinder, nmap, dnstwist, ...) are installed in `backend/Dockerfile.worker`.

To activate the module, replace its `PlaceholderModule` in `MODULES` in [`backend/qnsentry/modules/__init__.py`](backend/qnsentry/modules/__init__.py). Keep the order of the list: modules later in the list can use what earlier modules added to the context.

## Documentation

See [`docs/`](docs/README.md) for the full project overview: features, architecture, test environment, legal framework, planning, risks and the data contract.

## Responsible use

QN-Sentry only performs non-intrusive reconnaissance and only scans domains that have been explicitly approved. All testing is done exclusively on domains owned by the team. See [Legal and Ethical Framework](docs/project/05-legal-ethical.md).
