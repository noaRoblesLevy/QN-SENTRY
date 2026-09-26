# 6. Task Division

Each team member is responsible for two OSINT modules and part of the platform, so both gain end-to-end experience with security tooling and system architecture. Ownership is tracked through the assignees of the GitHub issues.

| | Quinten – Network & Platform | Noa – Threat Intelligence & Presentation |
|---|---|---|
| **OSINT modules** | Attack Surface Mapping (#4, #5, #6); Document Metadata Analysis (#7, #8) | Phishing Domain Detection (#9, #10, #29); Employee Breach Exposure (#11, #12, #13) |
| **Backend** | Core API and multi-client management (#16); scan progress per module (#14); target allowlist (#3); user authentication (#20) | Risk score calculation (#19) |
| **Frontend & output** | – | Dashboard with findings (#15); PDF report (#17) |
| **Infrastructure** | Docker Compose, PostgreSQL, Celery + Redis; Caddy and install script (#18); Google Cloud target server | – |
| **Test environment** (#2) | Target server, subdomains, decoy services, documents with metadata | BadSecurityInc website, team page, lookalike domain, email security configuration, breach test dataset |
| **Documentation** | Risks (#27); installation instructions (#28) | Legal and ethical framework (#25); report and demo scenario (#28) |
| **Future extensions** | Scheduled scanning (#21); change detection (#22) | Alerts (#23); live CT monitoring (#24) |

## Shared Responsibilities

- Walking skeleton (#1): Quinten sets up the backend, Celery worker and Docker Compose; Noa sets up the React dashboard
- Common data model and finding format (week 1, before module development starts); in particular the format of author names and the email naming convention passed from #7/#8 to #12
- Weighting of severities for the risk score (#19)
- Task division and planning (#26)
- Code reviews via pull requests in the shared GitHub repository
- Report, presentation and demo (#28)
- Weekly timesheet and planning updates on Google Drive
- Peer and self assessments
