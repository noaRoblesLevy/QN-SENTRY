# 11. Demo Scenario

Part of #28. The live demo of the presentation (section 9.3, 6 minutes) against the BadSecurityInc test environment.

**This version is written for a demo without the test VM (#2).** We have no Google Cloud credits left, so the VM with the `dev.` subdomain and the decoys will most likely not be online. Everything below runs against the live Vercel hosting of `badsecurityinc.be` and the lookalike. The steps that only apply if the VM does land after all are marked **(VM only)**.

## 11.1 Storyline

The audience plays the owner of BadSecurityInc, a small Belgian company that thinks it has "nothing interesting" online. In six minutes QN-Sentry shows what an attacker finds with public information only: who works there, what software they run, how to impersonate their email and which passwords of employees have leaked. The risk score and the PDF report turn that into something a manager can act on.

One rule for the whole demo: **every finding shown was planted on purpose** (section 4.3), so the detection rate at the end is measured, not claimed. The one exception is the `dev.` staging server and its decoy SSH port: those live on the VM (#2), which is not part of this demo. They stay in the ground truth as `pending` and are reported as **not measured**, never as found or missed (section 11.4).

## 11.2 Script

A full scan of `badsecurityinc.be` takes about a minute or two, not seconds (DNS lookups of hundreds of lookalike candidates, crawling and downloading documents). So the demo **starts a live scan first** and walks through a **finished scan made the same morning** while it runs. At the end the live scan is shown as finished, which proves the results were not staged.

Both scans belong to the same client. The client BadSecurityInc is therefore **not** added live: a domain belongs to one client only (10.5.4), so adding `badsecurityinc.be` again gives `409`, and deleting the client to make it work would also delete the morning scan (`ON DELETE CASCADE`). The add-client form is only shown; the client itself was added during the preparation (11.3).

| Time | Screen | Action | What to say |
|---|---|---|---|
| 0:00 | Clients page | Open the "add client" form without submitting it, then open BadSecurityInc | "This is all an MSP enters: a company name and its domain. BadSecurityInc was added this morning and its ownership verified." |
| 0:30 | Client page | Start a new scan of `badsecurityinc.be` (allowed: the morning scan is completed); the modules go from pending to running | "The API only queues the scan; a worker runs the four modules in the background, so the dashboard stays responsive." |
| 1:00 | Client page | Open the scan of this morning in the scan history (completed) | "While that runs, this is the same scan from this morning." |
| 1:15 | Scan page, risk badge | Point at the risk score and level, and at the asterisk | "One number for the manager: every finding adds points by severity, and the score saturates towards 100, so ten low findings never outweigh one critical. The asterisk means the scan is incomplete: the company's website is on shared hosting, which we deliberately did not approve for an active scan, so that one check could not run." (sections 10.7 and 11.3) |
| 1:45 | Findings, Metadata | Open `budget-2026.xlsx` and `it-security-policy.pdf` | "Public documents leak the file server name `SRV-FS01`, the username `ljanssens` and outdated Office versions (Excel 2007, Word 2013). That is a map of the internal network and a list of login names." |
| 2:30 | Findings, Phishing | Lookalike `badsecuritylnc.be` (high) and its certificate | "An l instead of an i. It has a mail server, so it can send and receive mail, and a valid certificate, so the fake website shows a padlock." |
| 3:15 | Findings, Phishing | SPF `+all` and DMARC `p=none` (both high) | "Worse: the real domain lets anyone send mail as badsecurityinc.be. An attacker does not even need the lookalike." |
| 3:45 | Findings, Breach | Addresses in breaches, `jan.peeters` with passwords (high) | "These addresses are on the team page; the breach data shows which ones leaked with a password. We store the breach names and data types, never the leaked data (GDPR)." |
| 4:30 | Findings, Attack Surface | The web service on `www.badsecurityinc.be` (status, title, technologies), then the Port scan panel | "Attack Surface maps what is reachable: the website, its server software and what it runs. The port scan panel is empty on purpose: this site is on shared hosting (Vercel), so we did not approve it for an active port scan. On a company's own server this is where the open ports and outdated services would show." |
| 5:00 | Scan page | Download the PDF report and open it | "The report is what the MSP hands to the client: summary, the same risk score as on screen, and per finding what it means and what to do." |
| 5:30 | Client page | Back to the live scan: completed, same findings | "And the live scan has finished with the same results." |
| 5:45 | Slide | Detection rate table (section 11.4) | Hand over to the conclusion. |

## 11.3 Preparation

**The day before**

- [ ] Test environment is online: `https://www.badsecurityinc.be` loads, the documents under `/files/` download, `badsecuritylnc.be` has its MX record and certificate
- [ ] Create the release tag `v1.0` on the final `main` (see 11.6), then on the demo laptop, from a clean checkout of that tag, run the install script with the team's `DOMAIN_VERIFICATION_SECRET` exported, so the TXT record already on `badsecurityinc.be` (#48) keeps verifying:
  - Linux/macOS: `DOMAIN_VERIFICATION_SECRET=<secret> ./install.sh`
  - Windows: `powershell -ExecutionPolicy Bypass -File .\install.ps1 -DomainVerificationSecret <secret>`
- [ ] Set up the client and a first scan, because a clean install starts with an empty database:
  - [ ] Add the client **BadSecurityInc** with domain `badsecurityinc.be` and confirm permission to scan it
  - [ ] Open the client and press **Verify**; it must show as verified (the ownership check #48 refuses `Verify` and every scan otherwise)
  - [ ] Run a first scan and let it finish, so the email addresses and the breach findings appear (they only exist after a scan)
  - [ ] Leave the website address on shared hosting **unapproved**: Vercel is shared hosting, so an active port scan of it is never approved (#81). This is deliberate and is what the demo shows at 4:30
  - [ ] **(VM only)** if the VM did land: approve the VM's address, run the scan again and check that the `dev.` open ports appear. `dev.` only gets a port scan after a first scan found its address and someone approved it (#81)
- [ ] Run the detection-rate script against a fresh scan (`testenv/detection-rate`, see its README) and put the result on the conclusion slide. The `dev.` and port entries are `pending` in the ground truth, so the script reports them as not measured
- [ ] Record the backup video of the full script

**The morning of the demo**

- [ ] Run the scan that is shown during the walkthrough and check that it finishes and shows **only the expected warning**: Attack Surface flags that the website address on shared hosting could not be confirmed and was deliberately not approved for an active scan. That one expected warning makes the scan count as incomplete, so the risk score carries an asterisk (that is the `*` explained at 1:15). Any **other** warning, or a module ending in error, means something is wrong, not the demo
- [ ] Check the network of the room: run one full scan on it and check that it finishes in a minute or two. A resolver that denies existing names (filtering networks) makes the lookalike check refuse to run; a resolver that is very slow for names that do not exist can make the phishing module take many minutes (the slow-resolver fallback of #80). In both cases, use a phone hotspot
- [ ] Do **not** delete the BadSecurityInc client: it holds the morning scan. Check that no scan of `badsecurityinc.be` is still running, otherwise the live scan at 0:30 gives `409`
- [ ] Dashboard open in a browser with a large font, the PDF viewer ready, notifications off

> A clean checkout in a folder that has the **same name** as an earlier one stops with "There is no .env, but the database of an earlier installation still exists" (a leftover Docker volume). Install in a fresh folder name, or remove the old volume first, so this does not surprise anyone the day before.

## 11.4 Expected Results

The ground truth is `testenv/detection-rate/expected-findings.json`. Entries marked `pending` there (the `dev.` staging server, its web service and admin login, the outdated and unpatched-PHP headers, and the decoy SSH port) live on the VM (#2) and are **not part of this demo**: the detection-rate script lists them as **not measured**, not as found or missed.

The findings shown in the script, with their expected severity:

| Module | Finding | Severity |
|---|---|---|
| Attack Surface | `www.badsecurityinc.be` subdomain, and the web services on the apex and `www` (status, title, technologies) | info |
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

Not measured (VM only, `pending` in the ground truth): the `dev.` subdomain, its admin login page, its outdated server headers, its unpatched-PHP (PHP2Shell) header and the decoy SSH on port 2222.

The cleaned `privacy-notice.pdf` must **not** appear: it shows that the platform does not simply report every document.

## 11.5 Fallbacks

| Problem during the demo | Fallback |
|---|---|
| The live scan is slow or ends `partial` | Keep walking through the morning scan; mention which external source was slow (the module error is shown per module) |
| No internet or DNS filtered | Morning scan only; the dashboard, report and risk score work offline |
| The phishing module hangs for minutes | A slow resolver for non-existent names (#80); switch to the phone hotspot and use the morning scan |
| The demo laptop fails | Backup video, then screenshots in the slides |
| A question about the `dev.` staging server | Explain honestly that the VM is not part of this demo (no cloud credits); the Attack Surface module finds and scans it, which the ground truth and the report document |
| A question about a module that was not shown | The data contract and the module explanation in the README |

## 11.6 Open Points

Updated 02/11/2026. Everything the script depends on is now on `main`: the risk score (#53), the PDF report (#51) which now shows the stored risk score next to the summary (#88), lookalike certificates (#49, #54), metadata email extraction (#8) and the derived address `pieter.mertens` (#12), the ownership check (#48), the full Attack Surface module including web services (#4, #5, #6), and the detection-rate measurement (#55, `testenv/detection-rate`).

One thing remains open, and it shapes this whole version of the demo:

| Part of the script | Depends on | State |
|---|---|---|
| The `dev.` staging server (subdomain, admin login, outdated and unpatched-PHP headers, decoy SSH on 2222) | #2 | The test VM will most likely **not** be online: no Google Cloud credits left. These findings are `pending` in the ground truth and reported as not measured. This demo runs against the live Vercel hosting instead |

Because the ownership check (#48) is built, the TXT record for `badsecurityinc.be` must be set for the team's `DOMAIN_VERIFICATION_SECRET` before the demo, or `Verify` and every scan refuse the domain. The install script keeps that secret when it is exported (see 11.3).

Attack Surface is a real module (not a placeholder), so the PDF report shows its findings and warnings; it does not say "not available in this version". That line only applies to a module that still returns a placeholder finding (#1), which none of the four do any more.

Next: rehearse the script with a timer against the live environment, and adjust the timings in 11.2 to what the rehearsal shows.
