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

## Documentation

See [`docs/`](docs/README.md) for the full project overview: features, architecture, test environment, legal framework, planning and risks.

## Responsible use

QN-Sentry only performs non-intrusive reconnaissance and only scans domains that have been explicitly approved. All testing is done exclusively on domains owned by the team. See [Legal and Ethical Framework](docs/project/05-legal-ethical.md).
