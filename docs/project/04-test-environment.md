# 4. Test Environment

## 4.1 Approach

All testing is performed on infrastructure owned by the team. We create a fictitious company with its own domain, website and services, in which we deliberately plant findings for each OSINT module. Because the expected findings are known in advance, the test environment also serves as a ground truth to measure the detection rate of the platform (`testenv/detection-rate/expected-findings.json`, #47).

## 4.2 Components

| Component | Description |
|---|---|
| Fictitious company | BadSecurityInc, a fictitious Belgian SME |
| Company domain | `badsecurityinc.be`, registered at one.com, which also manages its DNS |
| Lookalike domain | `badsecuritylnc.be` (homoglyph: lowercase *l* instead of *i*), with an MX record and a page that states it is a test |
| Company website | A public website on Vercel (`badsecurityinc.be` and `www.badsecurityinc.be`) with a team page, contact information and downloadable documents (`testenv/website/`) |
| Target server | A Google Cloud Compute Engine VM, in a separate Google Cloud project, for what a static website host cannot offer: the staging subdomain `dev.badsecurityinc.be` and a decoy SSH service, in Docker containers (`testenv/vm/`) |
| Breach test dataset | A local dataset with fictitious breach records, used by the Employee Breach module by default and in the demo |

The website runs on Vercel instead of the VM: it is free, always online and gets HTTPS automatically, so the Metadata and Phishing modules can be tested without the VM running. The VM is only started for the Attack Surface tests.

## 4.3 Planted Findings

| Module | Planted finding |
|---|---|
| Attack Surface Mapping | A forgotten staging subdomain (`dev.`) with an exposed admin login page |
| Attack Surface Mapping | An outdated web server version visible in HTTP headers (`nginx/1.18.0`, `PHP/7.4.3`) |
| Attack Surface Mapping | SSH (OpenSSH 8.2p1 banner) on the non-standard port 2222 |
| Attack Surface Mapping | Subdomains visible in Certificate Transparency logs |
| Document Metadata Analysis | 12 public documents (PDF, DOCX, XLSX, PPTX) containing author names, usernames, internal file paths (e.g. `\\SRV-FS01\Finance\`), printer names and outdated Office versions; one cleaned document that must not give a finding |
| Phishing Domain Detection | A registered lookalike domain with a valid TLS certificate (visible in Certificate Transparency logs) and an MX record |
| Phishing Domain Detection | A weak email security configuration on the company domain: a permissive SPF record (`+all`) and a DMARC policy of `p=none`, allowing email spoofing |
| Employee Breach Exposure | Fictitious employees on the team page, revealing the email naming convention; several of their addresses appear in the breach test dataset |

The exact expected findings, with their severity, are in `testenv/detection-rate/expected-findings.json`.

## 4.4 Safety Measures

- Exposed services are **decoys**: they show a realistic banner or login page but contain no real data and cannot be logged into. The software behind them is up to date.
- The test environment contains no personal data; all employees, documents and breaches are fictitious. The decoys do not log the addresses of visitors, and their container logs are limited in size.
- Pages that look real (the staging login, the website, the lookalike page) state that BadSecurityInc is fictitious and ask search engines not to index them.
- Scans are only started for the team's own domains. The platform will enforce this with a **target allowlist** and DNS ownership verification (planned: #3, #48).
- The VM is stopped when it is not used, and the whole environment is removed after the project with a checklist (#61).
- The test environment is deployed with Docker Compose, so it can be reset and reused by fellow students.
