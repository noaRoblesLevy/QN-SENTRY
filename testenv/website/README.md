# BadSecurityInc Website

The public website of the fictitious company BadSecurityInc (`www.badsecurityinc.be`), part of the test environment (#2). It gives the Document Metadata module (#7, #8) and the Breach module (#11, #12) something real to find, and it is the ground truth for their detection rate.

Every page shows a banner that the company is fictitious and has `noindex`, so search engines do not list the fake people.

## Contents

| Path | What |
|---|---|
| `index.html`, `team.html`, `contact.html`, `downloads.html`, `investors.html` | The site (plain HTML and CSS, no build step) |
| `files/` | 12 public documents with planted metadata |
| `tools/generate_documents.py` | Generates the documents; every planted value is defined there |

The expected findings of a scan, with their severity, are in [`testenv/detection-rate/expected-findings.json`](../detection-rate/expected-findings.json): the single source used to measure the detection rate (#47).
| `../lookalike/index.html` | The page on the lookalike domain `badsecuritylnc.be` |

Regenerate the documents after changing the planted values:

```bash
pip install -r testenv/website/tools/requirements.txt
python testenv/website/tools/generate_documents.py
```

## Deploy on Vercel

Both sites run on the Vercel account `noarobleslevy-7996`, as two projects without a framework or build command:

| Vercel project | Folder | Domains | Test URL |
|---|---|---|---|
| `badsecurityinc-website` | `testenv/website` | `badsecurityinc.be`, `www.badsecurityinc.be` | https://badsecurityinc-website.vercel.app |
| `badsecuritylnc-lookalike` | `testenv/lookalike` | `badsecuritylnc.be` | https://badsecuritylnc-lookalike.vercel.app |

They are deployed with the Vercel CLI, using a separate login folder so it does not interfere with other Vercel accounts on the same machine:

```bash
vercel --global-config ~/.vercel-qnsentry login          # once, with the QN-Sentry account
cd testenv/website   && vercel --global-config ~/.vercel-qnsentry deploy --prod
cd testenv/lookalike && vercel --global-config ~/.vercel-qnsentry deploy --prod
```

`.vercelignore` keeps this README and `tools/` off the site: they list every planted value.

### DNS at one.com

The domains stay on the one.com nameservers. All records of the test environment:

| Name | Type | Value | Purpose | Status |
|---|---|---|---|---|
| `badsecurityinc.be` | `A` | `76.76.21.21` | Website on Vercel | ✅ 30/09 |
| `www.badsecurityinc.be` | `A` | `76.76.21.21` | Website on Vercel | ✅ 30/09 |
| `badsecuritylnc.be` | `A` | `76.76.21.21` | Lookalike page on Vercel, gets a TLS certificate (#10) | ✅ 30/09 |
| `badsecuritylnc.be` | `MX` | `10 mail.badsecuritylnc.be` | Lookalike can receive email: `high` in #9 | ✅ 30/09 |
| `badsecurityinc.be` | `TXT` | `v=spf1 +all` | Every server may send as the company: `high` in #29 | ✅ 30/09 |
| `_dmarc.badsecurityinc.be` | `TXT` | `v=DMARC1; p=none` | Spoofed mail is delivered: `high` in #29 | ✅ 30/09 |
| `dev.badsecurityinc.be` | `A` | IP of the test VM | Staging site and decoy SSH (`testenv/vm/`) | ⏳ with the VM |

The MX record only has to exist: no mail server runs on the lookalike. Vercel requests a Let's Encrypt certificate automatically for its domains, which makes them visible in Certificate Transparency logs (needed for #10).

Checked on 30/09: the phishing module reports the lookalike, the SPF record and the DMARC policy as `high`, as planned.

## Planted findings

### Team page: email addresses and naming convention

| Person | Role | Address | Where |
|---|---|---|---|
| Jan Peeters | CEO | `jan.peeters@` | Team page |
| Sofie Maes | Finance | `sofie.maes@` | Team page, contact page, investors page |
| Lars Janssens | IT administrator | `lars.janssens@` | Team page |
| Emma Claes | HR | `emma.claes@` | Team page |
| Tom Wouters | Sales | `tom.wouters@` | Team page |
| Lotte Van den Broeck | Marketing | `lotte.vandenbroeck@` | Team page |
| Gérard Dubois | Logistics | `gerard.dubois@` | Team page |
| Pieter Mertens | Accountant (part time) | *not published* | **Only in document metadata**: `pieter.mertens@` must be derived (#12) |

Also published: `info@`, `sales@`, `helpdesk@`, `jobs@`.

Expected: `email_address` findings for the published addresses and an `email_convention` finding for `first.last`. "Lotte Van den Broeck" and "Gérard Dubois" test the name normalisation of open question 10.6 (#32): the site uses `lotte.vandenbroeck` and `gerard.dubois` (words joined, accents removed).

### Document metadata

| Document | Planted | Expected severity |
|---|---|---|
| `budget-2026.xlsx` (linked from the investors page) | Author Pieter Mertens, last modified by Sofie Maes, Excel 2007, link base `\\SRV-FS01\Finance\Budget\` | medium (internal path) |
| `employee-handbook.pdf` | Author Emma Claes, title `\\SRV-FS01\HR\Handbook\employee-handbook-v3.docx`, Word 2010 | medium (internal path) |
| `it-security-policy.pdf` | Author Lars Janssens, keywords `C:\Users\ljanssens\Documents\Policies`, subject "Draft, internal use only" | medium (internal path, Windows username) |
| `job-vacancy-it-administrator.docx` | Author Lars Janssens, last modified by `BSI\ljanssens`, template `\\SRV-FS01\Templates\BSI-letterhead.dotx`, Word 2010 | medium (internal path, domain username) |
| `price-list-2026.xlsx` | Author Tom Wouters, last modified by `BSI\twouters`, Excel 2013 | low (name, username) |
| `delivery-schedule-q4.xlsx` | Author Gérard Dubois, last modified by `BSI\gdubois` | low |
| `company-presentation.pptx` | Author Lotte Van den Broeck, last modified by Gérard Dubois | low |
| `company-brochure-2026.pdf` | Author Lotte Van den Broeck, Word 2016 | low |
| `annual-report-2025.pdf` | Author Pieter Mertens (not on the team page), Excel 2013 | low |
| `terms-and-conditions.pdf` | Author `jpeeters` (username), Word 2010 | low |
| `signed-order-form-example.pdf` | Scanner `KONICA MINOLTA bizhub C308`, device name `BSI-MFP-2F` | low (printer) |
| `privacy-notice.pdf` | **No metadata** (cleaned before publishing) | no finding: the good example |

Together they reveal:
- **Usernames** follow `BSI\flast` (Windows domain `BSI`), a second convention next to the email addresses
- The **file server** `SRV-FS01` with shares `Finance`, `HR` and `Templates`
- **Outdated Office versions** (2007 and 2010)

Checked with exiftool 13.59. exiftool reports `AppVersion` as a number: 12.0 = Office 2007, 14.0 = Office 2010, 15.0 = Office 2013, 16.0 = Office 2016 or later.
