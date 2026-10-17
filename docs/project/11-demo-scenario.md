# 11. Demo Scenario

First version (part of #28). The live demo of the presentation (section 9.3, 6 minutes) against the BadSecurityInc test environment. To be rehearsed end-to-end and updated when the remaining modules land.

## 11.1 Storyline

The audience plays the owner of BadSecurityInc, a small Belgian company that thinks it has "nothing interesting" online. In six minutes QN-Sentry shows what an attacker finds with public information only: who works there, what software they run, how to impersonate their email and which passwords of employees have leaked. The risk score and the PDF report turn that into something a manager can act on.

One rule for the whole demo: **every finding shown was planted on purpose** (section 4.3), so the detection rate at the end is measured, not claimed.

## 11.2 Script

A full scan takes minutes, not seconds (DNS lookups of hundreds of lookalike candidates, crawling and downloading documents). So the demo **starts a live scan first** and walks through a **finished scan made the same morning** while it runs. At the end the live scan is shown as finished, which proves the results were not staged.

Both scans belong to the same client. The client BadSecurityInc is therefore **not** added live: a domain belongs to one client only (10.5.4), so adding `badsecurityinc.be` again gives `409`, and deleting the client to make it work would also delete the morning scan (`ON DELETE CASCADE`). The add-client form is only shown.

| Time | Screen | Action | What to say |
|---|---|---|---|
| 0:00 | Clients page | Open the "add client" form without submitting it, then open BadSecurityInc | "This is all an MSP enters: a company name and its domain. BadSecurityInc is already added." |
| 0:30 | Client page | Start a new scan of `badsecurityinc.be` (allowed: the morning scan is completed); the modules go from pending to running | "The API only queues the scan; a worker runs the four modules in the background, so the dashboard stays responsive." |
| 1:00 | Client page | Open the scan of this morning in the scan history (completed) | "While that runs, this is the same scan from this morning." |
| 1:15 | Scan page, risk badge | Point at the risk score and level | "One number for the manager: every finding adds points by severity, and the score saturates towards 100, so ten low findings never outweigh one critical." (section 10.7) |
| 1:45 | Findings, Metadata | Open `budget-2026.xlsx` and `it-security-policy.pdf` | "Public documents leak the file server name `SRV-FS01`, the username `ljanssens` and outdated Office versions (Excel 2007, Word 2013). That is a map of the internal network and a list of login names." |
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
- [ ] Create the release tag `v1.0` on the final `main` (see 11.6), then on the demo laptop, from a clean checkout of that tag, run `./install.sh` with the team's `DOMAIN_VERIFICATION_SECRET` exported, so the TXT record already on `badsecurityinc.be` (#48) keeps verifying
- [ ] Confirm the TXT record for `badsecurityinc.be` is still set for the team secret, then open the client and check it shows as verified (the ownership check #48 refuses `Verify` and every scan otherwise)
- [ ] Run the detection-rate script against a fresh scan (`testenv/detection-rate`, see its README) and put the result on the conclusion slide
- [ ] Record the backup video of the full script

**The morning of the demo**

- [ ] Run the scan that is shown during the walkthrough and check it is `completed`, not `partial`, and that no module shows "Completed with warnings"
- [ ] Check the network of the room: run one full scan on it and check that it finishes in about half a minute. A resolver that denies existing names (filtering networks) makes the lookalike check refuse to run; a resolver that is slow for names that do not exist makes it take more than 15 minutes. In both cases, use a phone hotspot
- [ ] Do **not** delete the BadSecurityInc client: it holds the morning scan. Check that no scan of `badsecurityinc.be` is still running, otherwise the live scan at 0:30 gives `409`
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
| Breach | `info@badsecurityinc.be` (published on the site, only the address leaked in PretendSpamList) | low |
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

Updated 17/10/2026. Almost everything the script depends on is now on `main`: the risk score (#53), the PDF report (#51), lookalike certificates (#49, #54), metadata email extraction (#8) and the derived address `pieter.mertens` (#12), the ownership check (#48), and the detection-rate measurement (#55, `testenv/detection-rate`). Two things are still open:

| Part of the script | Depends on | State |
|---|---|---|
| Attack Surface at 4:30 (web services, outdated server headers) | #6 | Subdomains (#4) and the port and service scan (#5) are merged; web services (#6) is the last module |
| The whole live demo against the test environment | #2 | The VM with the `dev.` subdomain and the decoys must be online |

Because the ownership check (#48) is built, the TXT record for `badsecurityinc.be` must be set for the team's `DOMAIN_VERIFICATION_SECRET` before the demo, or `Verify` and every scan refuse the domain. `install.sh` keeps that secret when it is exported (see 11.3).

Until #6 lands, the PDF report shows Attack Surface as "not available in this version" (#51); say so when the report is opened at 5:00. The release tag `v1.0` is created on the final `main` after the feature freeze (25/10).

When #6 and #2 land: rehearse the script with a timer, adjust the timings in 11.2, and replace this section with the rehearsal notes.
