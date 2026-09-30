# 11. Demo Scenario

First version (part of #28). The live demo of the presentation (section 9.3, 6 minutes) against the BadSecurityInc test environment. To be rehearsed end-to-end and updated when the remaining modules land.

## 11.1 Storyline

The audience plays the owner of BadSecurityInc, a small Belgian company that thinks it has "nothing interesting" online. In six minutes QN-Sentry shows what an attacker finds with public information only: who works there, what software they run, how to impersonate their email and which passwords of employees have leaked. The risk score and the PDF report turn that into something a manager can act on.

One rule for the whole demo: **every finding shown was planted on purpose** (section 4.3), so the detection rate at the end is measured, not claimed.

## 11.2 Script

A full scan takes minutes, not seconds (DNS lookups of hundreds of lookalike candidates, crawling and downloading documents). So the demo **starts a live scan first** and walks through a **finished scan made the same morning** while it runs. At the end the live scan is shown as finished, which proves the results were not staged.

| Time | Screen | Action | What to say |
|---|---|---|---|
| 0:00 | Clients page | Add client "BadSecurityInc" with domain `badsecurityinc.be` | "This is all an MSP enters: a company name and its domain." |
| 0:30 | Client page | Start an assessment; the modules go from pending to running | "The API only queues the scan; a worker runs the four modules in the background, so the dashboard stays responsive." |
| 1:00 | Client page | Open the scan of this morning (same client, completed) | "While that runs, this is the same scan from this morning." |
| 1:15 | Scan page, risk badge | Point at the risk score and level | "One number for the manager: every finding adds points by severity, and the score saturates towards 100, so ten low findings never outweigh one critical." (section 10.7) |
| 1:45 | Findings, Metadata | Open `budget-2026.xlsx` and `it-security-policy.pdf` | "Public documents leak the file server name `SRV-FS01`, usernames like `ljanssens` and Word 2010. That is a map of the internal network and a list of login names." |
| 2:30 | Findings, Phishing | Lookalike `badsecuritylnc.be` (high) and its certificate | "An l instead of an i. It has a mail server, so it can send and receive mail, and a valid certificate, so the fake website shows a padlock." |
| 3:15 | Findings, Phishing | SPF `+all` and DMARC `p=none` (both high) | "Worse: the real domain lets anyone send mail as badsecurityinc.be. An attacker does not even need the lookalike." |
| 3:45 | Findings, Breach | Addresses in breaches, `jan.peeters` with passwords (high) | "These addresses are on the team page; the breach data shows which ones leaked with a password. We store the breach names and data types, never the leaked data (GDPR)." |
| 4:30 | Findings, Attack Surface | `dev.` subdomain, admin login, outdated nginx/PHP | "A forgotten staging server, found through certificate logs." |
| 5:00 | Scan page | Download the PDF report and open it | "The report is what the MSP hands to the client: summary, risk score, and per finding what it means and what to do." |
| 5:30 | Client page | Back to the live scan: completed, same findings | "And the live scan has finished with the same results." |
| 5:45 | Slide | Detection rate table (section 11.4) | Hand over to the conclusion. |

## 11.3 Preparation

**The day before**

- [ ] Test environment is online: `https://www.badsecurityinc.be` loads, the documents under `/files/` download, `badsecuritylnc.be` has its MX record and certificate
- [ ] `docker compose up -d --build` on the demo laptop from a clean checkout of the release tag
- [ ] Run the detection-rate script against a fresh scan (`testenv/detection-rate`, see its README) and put the result on the conclusion slide
- [ ] Record the backup video of the full script

**The morning of the demo**

- [ ] Run the scan that is shown during the walkthrough and check it is `completed`, not `partial`
- [ ] Check the network of the room: the lookalike check refuses to run on a resolver that denies existing names (filtering networks). If the room network filters DNS, use a phone hotspot
- [ ] Delete the BadSecurityInc client that is added live during rehearsals, so "add client" works in the demo
- [ ] Dashboard open in a browser with a large font, the PDF viewer ready, notifications off

## 11.4 Expected Results

The ground truth is `testenv/detection-rate/expected-findings.json`. The findings shown in the script, with their expected severity:

| Module | Finding | Severity |
|---|---|---|
| Metadata | 4 documents with internal paths or usernames and old Office versions | medium |
| Metadata | 7 documents with author names, a username or a printer name | low |
| Phishing | Lookalike `badsecuritylnc.be` with a mail server | high |
| Phishing | Certificate for the lookalike | high |
| Phishing | SPF `+all` | high |
| Phishing | DMARC `p=none` | high |
| Phishing | No DKIM key | low |
| Breach | `jan.peeters`, `lars.janssens` (passwords), `pieter.mertens` (derived from a document author) | high |
| Breach | `sofie.maes`, `lotte.vandenbroeck` | medium |
| Attack Surface | `dev.` subdomain, admin login, outdated server headers, SSH on port 2222 | info to medium |

The cleaned `privacy-notice.pdf` must **not** appear: it shows that the platform does not simply report every document.

## 11.5 Fallbacks

| Problem during the demo | Fallback |
|---|---|
| The live scan is slow or ends `partial` | Keep walking through the morning scan; mention which external source was slow (the module error is shown per module) |
| No internet or DNS filtered | Morning scan only; the dashboard, report and risk score work offline |
| The demo laptop fails | Backup video, then screenshots in the slides |
| A question about a module that was not shown | The data contract and the module explanation in the README |

## 11.6 Open Points

This first version assumes the whole platform is finished. What the script depends on that is not on `main` yet (30/09/2026):

| Part of the script | Depends on |
|---|---|
| Risk score (1:15) | #53 |
| PDF report (5:00) | #51 |
| Lookalike certificate (2:30) | #49; lookalikes inside Docker need #54 |
| Breach addresses from the team page (3:45) | Metadata email extraction #8; derived address `pieter.mertens` #12 |
| Attack Surface (4:30) | #4, #5, #6 and the test VM #2 |
| "Add client" with an ownership check | #48 (if the check is built, the TXT record of `badsecurityinc.be` must be set before the demo) |

When all of these are merged: rehearse the script with a timer, adjust the timings in 11.2, and replace this section with the rehearsal notes.
