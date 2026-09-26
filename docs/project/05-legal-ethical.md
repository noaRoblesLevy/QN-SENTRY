# 5. Legal and Ethical Framework

## 5.1 Authorisation

Scanning systems without the owner's permission can constitute unauthorised access or an attempt thereof under Belgian criminal law. QN-Sentry is therefore designed to assess only domains the user is authorised to assess:

- During this project, all scans target exclusively infrastructure owned by the team (`badsecurityinc.be`, `badsecuritylnc.be`).
- The platform enforces a target allowlist, optionally combined with domain ownership verification via a DNS TXT record.
- In a real-world deployment, an assessment requires a signed agreement with the client defining the scope (domains, period, techniques).

## 5.2 Non-intrusive Techniques

QN-Sentry only performs reconnaissance: it collects publicly available information and detects services, but never exploits vulnerabilities, attempts logins, or performs denial-of-service testing. Port and service scans are rate-limited to avoid impact on the target.

## 5.3 GDPR

Several modules process personal data: author names in document metadata, employee names and business email addresses, and breach records. We apply the following principles:

| Principle | Implementation in QN-Sentry |
|---|---|
| **Purpose limitation** | Personal data is used solely to assess the organisation's security exposure. |
| **Data minimisation** | The Employee Breach module stores only the email address, the breach name and the breach date, never passwords or other leaked data. |
| **Storage limitation** | Scan results are automatically deleted after a retention period of 90 days (configurable). |
| **Security** | Access to the platform requires authentication; each client only sees their own data; traffic is encrypted with HTTPS. |
| **Roles** | In a real-world deployment, the client is the data controller and the QN-Sentry operator acts as data processor, which requires a data processing agreement (GDPR art. 28). |

During this project, only fictitious persons and data are used.

## 5.4 Third-party Services

The platform respects the terms of use of the external sources it relies on, such as the Have I Been Pwned API (API key, rate limits, attribution) and crt.sh (fair use). Scanning our own resources on Google Cloud complies with the Google Cloud Acceptable Use Policy.

## 5.5 Business Context: NIS2

The Belgian NIS2 law requires organisations in scope, including many SMEs in critical supply chains, to take appropriate cybersecurity risk management measures. An external exposure assessment such as QN-Sentry supports these organisations in identifying risks and in demonstrating that they actively manage them.
