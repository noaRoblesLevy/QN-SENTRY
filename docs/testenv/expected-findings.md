# Expected Findings

The findings deliberately planted in the BadSecurityInc test environment (see [`testenv/`](../../testenv/README.md)). This is the ground truth used to measure the detection rate of QN-Sentry: after a scan of `badsecurityinc.be`, every row below should appear as a finding.

Status: ✅ in place · ⏳ planned

## Attack Surface Mapping

| Planted | Expected finding | Type | Status |
|---|---|---|---|
| `dev.badsecurityinc.be`, visible in Certificate Transparency logs | Subdomain discovered | `subdomain` | ⏳ VM |
| `www.badsecurityinc.be` | Subdomain discovered | `subdomain` | ⏳ Vercel |
| Decoy SSH banner on port 2222 | Open port with OpenSSH 8.2p1 on a non-standard port | `open_port` | ⏳ VM |
| Staging admin login on `dev.badsecurityinc.be` | Web service with an admin login page | `web_service` | ⏳ VM |
| Headers `Server: nginx/1.18.0`, `X-Powered-By: PHP/7.4.3` | Outdated web server and PHP version | `web_service` | ⏳ VM |

## Document Metadata Analysis

| Planted | Expected finding | Type | Status |
|---|---|---|---|
| Public documents with author names, usernames, software versions and internal paths | Leaked metadata per document | `document_metadata` | ⏳ Noa |
| Email addresses on the team page | Published email addresses | `email_address` | ⏳ Noa |
| Addresses following `first.last@badsecurityinc.be` | Detected naming convention | `email_convention` | ⏳ Noa |

## Phishing Domain Detection

| Planted | Expected finding | Type | Status |
|---|---|---|---|
| `badsecuritylnc.be` registered, with an MX record | Registered lookalike domain that can send email | `lookalike_domain` | ⏳ DNS + Vercel |
| TLS certificate for `badsecuritylnc.be` | Certificate for a lookalike domain | `lookalike_certificate` | ⏳ Vercel |
| Permissive SPF and DMARC `p=none` on `badsecurityinc.be` | Company domain can be spoofed | `email_security` | ⏳ DNS |

## Employee Breach Exposure

| Planted | Expected finding | Type | Status |
|---|---|---|---|
| Published addresses that appear in the breach test dataset | Breached business email | `breached_email` | ⏳ Noa |
| Author names from documents that, with the convention, match an address in the dataset | Breached derived address | `breached_email` | ⏳ Noa |
