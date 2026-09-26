# 1. Project Description

## 1.1 Problem

Small and medium-sized enterprises (SMEs) are increasingly targeted by cyberattacks, yet they rarely have a dedicated security team. Before attacking, adversaries perform reconnaissance using publicly available information: forgotten subdomains, exposed services, metadata in public documents, lookalike domains for phishing, and employee credentials leaked in data breaches. Most SMEs have no overview of what an attacker can find about them.

## 1.2 Solution

QN-Sentry is an OSINT platform for digital risk assessment for SMEs. Given a company domain, the platform performs an on-demand OSINT assessment of the organisation's external exposure and presents the results in a dashboard and report with a risk score. This way, an SME sees its attack surface from an attacker's perspective, before an attacker does.

## 1.3 Target Audience

- SMEs that want insight into their own external exposure
- IT administrators and managed service providers (MSPs) who manage multiple SMEs and assess all their clients from a single platform
- Management, through a readable summary report and risk score

## 1.4 Scope

**In scope:** passive and non-intrusive reconnaissance, including subdomain discovery, port and service detection, document metadata analysis, lookalike domain detection, email security checks and breach lookups for business email addresses. The service is offered as a one-time, on-demand assessment.

**Out of scope:** exploitation of vulnerabilities, active attacks, social media profiling of individuals, and scanning of any infrastructure without explicit permission. All testing is performed exclusively on domains registered by the team, hosting a fictitious company.

**Future extension:** continuous, scheduled monitoring with change detection and alerting.
