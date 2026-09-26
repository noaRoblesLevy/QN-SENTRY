# 6. Task Division

Each team member is responsible for two OSINT modules and part of the platform, so both gain end-to-end experience with security tooling and system architecture. The assignment of team members to roles A and B will be confirmed in a next version of this document.

| | Student A – Network & Platform | Student B – Threat Intelligence & Presentation |
|---|---|---|
| **OSINT modules** | Attack Surface Mapping; Document Metadata Analysis | Phishing Domain Detection; Employee Breach Exposure |
| **Backend** | Scan orchestration (Celery workers, Redis); core API endpoints (clients, domains, scans) | Risk score calculation; target allowlist and domain ownership verification; user authentication |
| **Frontend & output** | – | React dashboard; PDF report |
| **Infrastructure** | Docker Compose, PostgreSQL, Caddy, install script; Google Cloud target server | – |
| **Test environment** | Planted findings for own modules (subdomains, decoy services, documents with metadata) | Planted findings for own modules (lookalike domain, email security, team page, breach test dataset); BadSecurityInc website |

## Shared Responsibilities

- Common data model and finding format (week 1, before module development starts)
- Code reviews via pull requests in the shared GitHub repository
- Report, presentation and demo
- Weekly timesheet and planning updates on Google Drive
- Peer and self assessments
