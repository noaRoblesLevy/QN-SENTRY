# 4. Test Environment

## 4.1 Approach

All testing is performed on infrastructure owned by the team. We create a fictitious company with its own domain, website and services, in which we deliberately plant findings for each OSINT module. Because the expected findings are known in advance, the test environment also serves as a ground truth to measure the detection rate of the platform.

## 4.2 Components

| Component | Description |
|---|---|
| Fictitious company | BadSecurityInc, a fictitious Belgian SME |
| Company domain | `badsecurityinc.be` |
| Lookalike domain | `badsecuritylnc.be` (homoglyph: lowercase *l* instead of *i*) |
| Target server | A Google Cloud Compute Engine VM, in a separate Google Cloud project, hosting the company website, subdomains and decoy services in Docker containers |
| Company website | A public website for BadSecurityInc with a team page, contact information and downloadable documents |
| Breach test dataset | A local dataset with fictitious breach records, used by the Employee Breach module in demo mode |

## 4.3 Planted Findings

| Module | Planted finding |
|---|---|
| Attack Surface Mapping | A forgotten staging subdomain (`dev.`) with an exposed admin login page |
| Attack Surface Mapping | An outdated web server version visible in HTTP headers |
| Attack Surface Mapping | SSH on a non-standard port; a database port exposed to the internet (decoy) |
| Attack Surface Mapping | Subdomains visible in Certificate Transparency logs |
| Document Metadata Analysis | 10–15 public documents (PDF, DOCX, XLSX) containing author names, usernames, internal file paths (e.g. `\\SRV-FS01\Finance\`), printer names and outdated Office versions |
| Phishing Domain Detection | A registered lookalike domain with a valid TLS certificate (visible on crt.sh) and an MX record |
| Phishing Domain Detection | A weak email security configuration on the company domain: a permissive SPF record and a DMARC policy of `p=none`, allowing email spoofing |
| Employee Breach Exposure | Fictitious employees on the team page, revealing the email naming convention; several of their addresses appear in the breach test dataset |

## 4.4 Safety Measures

- Exposed services are **decoys**: they show a realistic banner or login page but contain no real data and cannot be logged into.
- The target server contains no personal data; all employees and documents are fictitious.
- The platform enforces a **target allowlist**: scans can only be started for domains that have been explicitly approved, preventing accidental scanning of third parties.
- The test environment is deployed with Docker Compose, so it can be reset and reused by fellow students.
