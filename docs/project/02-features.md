# 2. Features

**Priorities:** *Must* = part of the minimum viable product; *Should* = added if time allows; *Could* = future extension.

## 2.1 OSINT Modules

| Module | Description | Priority |
|---|---|---|
| **Attack Surface Mapping** | Discovers subdomains (passive sources and certificate logs), resolves IP addresses, detects open ports and identifies public web services, software versions and technologies. | Must |
| **Document Metadata Analysis** | Crawls the company website for public documents (PDF, DOCX, XLSX) and extracts metadata such as author names, usernames, software versions and internal file paths. | Must |
| **Phishing Domain Detection** | Generates lookalike variants of the company domain (typos, homoglyphs, alternative TLDs), checks which are registered, and searches Certificate Transparency logs (crt.sh) for certificates issued to lookalike domains. Also checks the email security of the company domain (SPF, DMARC, DKIM): without a strict DMARC policy, attackers can send email that appears to come from the company itself. | Must |
| **Employee Breach Exposure** | Collects business email addresses of the organisation (from the website, document metadata and the detected email naming convention) and checks whether they appear in known data breaches. Uses a pluggable breach source: the Have I Been Pwned API for real-world use and a local test dataset for the demo environment. | Must |

**Module integration:** the Metadata module discovers author names and the email naming convention (e.g. `firstname.lastname`), which the Employee Breach module uses to derive likely email addresses.

## 2.2 Platform Features

| Feature | Description | Priority |
|---|---|---|
| **On-demand scanning** | Start a full assessment for a client domain from the dashboard; progress is shown per module. | Must |
| **Multi-client management** | Manage multiple clients, each with one or more domains, from a single platform. | Must |
| **Target allowlist** | Scans can only be started for domains that have been explicitly approved by an administrator, preventing accidental or malicious scanning of third parties. | Must |
| **Dashboard** | Web interface showing the findings per client, grouped by module and severity. | Must |
| **Reporting** | Generates a PDF summary report for management; the main deliverable for the client. | Must |
| **Automated deployment** | The entire platform is deployed with a single installation script using Docker Compose. | Must |
| **Risk score** | Calculates a score per client based on the number and severity of the findings. | Should |
| **User authentication** | Login with roles (administrator, client), so each client only sees their own data. | Should |
| **Domain ownership verification** | Before a domain can be added to the allowlist, the client proves ownership by adding a unique DNS TXT record (e.g. `qn-sentry-verify=<token>`). | Should |

## 2.3 Future Extensions

| Feature | Description | Priority |
|---|---|---|
| **Scheduled scanning** | Scans run automatically on a configurable interval (e.g. daily or weekly). | Could |
| **Change detection** | Compares each scan with the previous one and highlights new, changed and resolved findings. | Could |
| **Alerts** | Notifications (Discord, e-mail) for new high-risk findings. | Could |
| **Live CT monitoring** | Real-time monitoring of newly issued certificates via a self-hosted certstream server. | Could |
