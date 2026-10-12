# Detection rate (issue #47)

Measures how many of the weaknesses planted in the BadSecurityInc test environment a scan actually finds.

- `expected-findings.json`: the ground truth. Every finding a scan of `badsecurityinc.be` should report, with the expected severity and what was planted. `must_not_find` holds false-positive checks (the cleaned `privacy-notice.pdf`, the company's own domain as a lookalike).
- `detection_rate.py`: compares the findings of a scan with the ground truth. Standard library only.

## Usage

```bash
# Against a running QN-Sentry (the API port; scan id from the dashboard or POST /api/domains/{id}/scans)
python testenv/detection-rate/detection_rate.py --api http://localhost:8000 --scan 12

# Against a saved findings file, output as JSON (for the report)
python testenv/detection-rate/detection_rate.py --findings findings.json --json
```

Every result states the scan, the time it was measured and the commit of the ground truth, so a number in the report can always be traced back.

## How findings are matched

An entry matches a finding when `module` and `type` are equal, the `asset` matches (`*` is a wildcard, case-insensitive) and the entry's `details` are a subset of the finding's details (e.g. `{"check": "spf"}`).

**Each finding counts for at most one entry, and each entry for at most one finding.** Entries and findings are paired with a maximum bipartite matching, so one finding can never tick off two entries (the admin login and the outdated server on `dev.` share a pattern and are told apart by `details`), and a finding is never given to the wrong entry when a pairing for both exists.

The report lists per module:

| Column | Meaning |
|---|---|
| Detected | expected entries found / expected entries (pending entries not counted) |
| Pending | entries that cannot be found yet: the module or that part of the test environment does not exist yet (the reason is in `pending`) |
| Sev. differs | found, but with another severity than expected |
| Unexpected | findings that match no entry: a new real finding (add it to the ground truth) or a false positive (add it to `must_not_find`) |
| Duplicates | a second finding for an entry that was already found |
| False pos. | `must_not_find` entries that were reported |

And three numbers for the conclusion:

| Number | Formula | Why |
|---|---|---|
| Detection rate (recall) | found / expected | How much of what is there the scan finds |
| Detected with the expected severity | found with the right severity / expected | Finding a `high` as `low` gives the client the wrong picture |
| Precision | found / (found + unexpected + duplicates + false positives) | A scanner that reports everything would get a perfect detection rate; precision shows it |

`placeholder` findings (stand-ins for modules that are not built yet) are ignored. When a pending module is merged, remove the `pending` key of its entries so they count.

`expected-findings.json` is the **single source** of the expected findings. `testenv/website/README.md` lists how the documents are planted and links here for the expected results.

## Results

| Measured | Scan | Ground truth | Detection rate | Expected severity | Precision | Pending |
|---|---|---|---|---|---|---|
| 01/10/2026 | 2: `main` plus #49 to #54 | `fb2f8aa` | 16/16 (100%) | 100% | 100% | 12 |
| 01/10/2026 | 3: `main` plus #53, without #49 | `fb2f8aa` | 15/16 (94%): lookalike certificate missed | 94% | 100% | 12 |
| 08/10/2026 | 13: `main` with #70, #71 and #74 | `f5b7b42` | 22/23 (96%): lookalike certificate missed, #49 not merged yet | 96% | 100% | 6 |
| 08/10/2026 | 14: `main` with every module except Attack Surface (#49 to #77 merged) | `a9cd852` | 24/24 (100%) | 100% | 100% | 5 (Attack Surface) |

Scan 14 is the first complete one apart from Attack Surface: every planted weakness of the Metadata, Phishing and Breach modules is found with its expected severity, including `pieter.mertens@` (derived from a document author, #12), and nothing else is reported. Scan 13 was the first with the addresses of #74: Metadata 13/13 (documents, addresses, convention) and Breach 5/5; `br-pieter` waits for #12.

Per module for scan 2: Metadata 11/11, Phishing 5/5; Attack Surface (5) and Breach (6) and the email convention (1) are pending. Scan 3 shows the measurement doing its job: without the certificate check of #49, `ph-certificate` is reported as missed.

## Tests

The tests run with the backend tests (`cd backend && pytest`, see `testpaths` in `backend/pyproject.toml`), or on their own:

```bash
pytest testenv/detection-rate
```
