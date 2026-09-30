# Detection rate (issue #47)

Measures how many of the weaknesses planted in the BadSecurityInc test environment a scan actually finds.

- `expected-findings.json`: the ground truth. Every finding a scan of `badsecurityinc.be` should report, with the expected severity and what was planted. `must_not_find` holds false-positive checks (the cleaned `privacy-notice.pdf`, the company's own domain as a lookalike).
- `detection_rate.py`: compares the findings of a scan with the ground truth. Standard library only.

## Usage

```bash
# Against a running QN-Sentry (scan id from the dashboard or POST /api/scans)
python testenv/detection-rate/detection_rate.py --api http://localhost:8080 --scan 12

# Against a saved findings file, output as JSON (for the report)
python testenv/detection-rate/detection_rate.py --findings findings.json --json
```

## How findings are matched

An entry matches a finding when `module` and `type` are equal, the `asset` matches (`*` is a wildcard, case-insensitive) and the entry's `details` are a subset of the finding's details (e.g. `{"check": "spf"}`).

The report lists per module:

| Column | Meaning |
|---|---|
| Detected | expected entries found / expected entries (pending entries not counted) |
| Pending | entries that cannot be found yet: the module or that part of the test environment does not exist yet (the reason is in `pending`) |
| Severity differs | found, but with another severity than expected |
| Unexpected | findings that are not in the ground truth (a new real finding, or a false positive to add to `must_not_find`) |
| False pos. | `must_not_find` entries that were reported |

`placeholder` findings (stand-ins for modules that are not built yet) are ignored.

When a pending module is merged, remove the `pending` key of its entries so they count.

## Result so far

Scan of `badsecurityinc.be` on 30/09/2026 (main plus the open PRs #49 to #54, in Docker):

| Module | Detected | Pending |
|---|---|---|
| Attack Surface | - | 5 (#4, #5, #6, test VM #2) |
| Metadata | 11/11 | 1 (email convention, #8) |
| Phishing | 5/5 | 0 |
| Breach | - | 6 (addresses from #8 and #12) |

Detection rate 16/16, no false positives, no unexpected findings.

## Tests

```bash
pytest testenv/detection-rate
```
