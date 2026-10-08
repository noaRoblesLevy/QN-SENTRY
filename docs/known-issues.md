# Known Issues and Difficult Points

What QN-Sentry cannot do (yet), and how to solve the problems we ran into ourselves. Each item links to its issue.

## Limitations

| Limitation | Why | Issue |
|---|---|---|
| **No login.** Anyone who can reach the dashboard or the API sees every client and report. | Authentication with roles is planned. Until then both are bound to `127.0.0.1`, so only the machine itself can reach them. | #20 |
| **Anyone with access can add any domain, which blocks it for its real owner.** Adding a domain needs a confirmation of permission, and scanning it needs a DNS TXT record (#3, #48), so a domain of someone else can never be scanned. But it can be added, and the real owner then gets `409 already added`. | Fine for one MSP per installation; with logins and roles (#20) adding domains can be limited to administrators. | #20 |
| **Attack surface is a placeholder.** The module returns one informational finding and does not discover subdomains or open ports yet. | Being built, together with the test VM it is tested against. | #4, #5, #6, #2 |
| **Only linked documents are found.** A document that no page links to stays invisible to the crawler, as it does to an attacker who only browses. | By design: the crawler stays on the client's hosts, at most 3 links deep, 120 s and 50 documents. | |
| **DKIM can only be checked for common names.** A missing DKIM key is reported as Low, because the domain may use a selector name that DNS cannot list. | DNS has no way to list the selectors of a domain. | |
| **Certificates of lookalikes depend on public services.** Cert Spotter allows a small number of free queries per hour; crt.sh is often overloaded and hours behind. | A lookalike that could not be checked reliably is not reported as "no certificate". A real deployment sets `CERTSPOTTER_API_KEY`. | #49 |
| **Have I Been Pwned needs a paid API key**, and sends business addresses to a service outside the EU. | The default and the demo use the local, fictitious dataset. See the legal framework, 5.3. | #13, #56 |
| **One worker runs two scans at a time.** Further scans wait in the queue. | `--concurrency=2` in `backend/Dockerfile.worker`. A scan of `badsecurityinc.be` takes about half a minute. | |

## Troubleshooting

### Ports already in use

`docker compose up` fails with `Bind for 0.0.0.0:8000 failed: port is already allocated` (or 8080): another project uses the port. Remap QN-Sentry's ports with a `docker-compose.override.yml`, see the [installation guide](installation.md#ports-already-in-use).

### The services do not start after changing `.env`

| Error in `docker compose logs migrate` or `api` | Cause | Fix |
|---|---|---|
| `postgres_password Field required` | `POSTGRES_PASSWORD` is missing | Set it in `.env` |
| `int_parsing` | A remark after a value, e.g. `RETENTION_DAYS=90  # days` | Remarks on their own line |
| `greater_than_equal` | `RETENTION_DAYS` or `SCAN_TIMEOUT_MINUTES` below 1 | Use 1 or more: 0 would delete every result each night |

### `migrate` stops with "The database has only some of the QN-Sentry tables"

The database has some of QN-Sentry's tables but not all, and no migration history, so `migrate` does not know which version it is and refuses to guess. That only happens to a database that was broken by hand. If the data is not needed: `docker compose down -v` and `docker compose up -d --build` start with an empty database.

### The dashboard says "Could not reach the QN-SENTRY API"

The API is not running or not healthy. `docker compose ps` shows its state and `docker compose logs api` why. The API waits for `migrate`: if that failed, the API never starts.

### A module fails

The reason is shown under the module on the scan page. The other modules still run and the scan ends as **Completed with errors**.

| Message | Cause | Fix |
|---|---|---|
| `The website https://... could not be crawled` | The site is offline, or DNS or TLS failed | Check the site in a browser; scan again later |
| `The DNS resolver ... does not resolve names that must exist` | The DNS resolver of the container gives wrong answers (see below) | Another network, or another resolver |
| `Certificate Transparency could not be searched reliably` | Cert Spotter and crt.sh both failed or were rate-limited | Scan again later, or set `CERTSPOTTER_API_KEY` |
| `katana is not installed in the worker image` / `exiftool ...` | The worker image is outdated | `docker compose up -d --build` |

### A scan takes much longer than half a minute

A scan of `badsecurityinc.be` normally takes about half a minute. When the Phishing domains module takes many minutes, the DNS resolver is slow for names that **do not exist**: instead of answering "does not exist" at once, it lets each question time out (5 seconds). The resolver check passes, because existing names do resolve, but the lookalike check asks about hundreds of names that do not exist. Seen on a network where Docker's DNS (`127.0.0.11`) took 5 s per such name while `1.1.1.1` answered in 0.2 s, which turned 5 seconds into more than 15 minutes. Run the scan on another network, e.g. a phone hotspot.

### DNS-filtering networks

Some networks (company, school or hotel Wi-Fi, some home routers) answer "does not exist" for names they filter. The lookalike check would then report "no lookalikes", which looks like a clean result while nothing was checked. So before every scan it looks up a name that always exists (`a.root-servers.net`), and fails with a clear message if that does not work. Run the scan on another network, e.g. a phone hotspot.

Docker's own DNS server (`127.0.0.11`) does not answer every kind of question either: an earlier version of that check failed inside the worker only. The current check works with it.

### A scan stays on "Queued" or "Running"

- **Queued** and nothing happens: the worker is not running (`docker compose ps`, `docker compose logs worker`).
- **Running** for a long time: the worker probably stopped during the scan. After `SCAN_TIMEOUT_MINUTES` (120) the scan counts as stuck: the next **Run scan** on that domain marks it failed and starts a new one. A scan that was interrupted because the worker restarted is marked failed as soon as the worker picks it up again.

### The report shows squares instead of letters

Old versions used a PDF font without Cyrillic letters, so a homoglyph lookalike (`bаdsecurityinc.be` with a Cyrillic а) was printed as `b■dsecurityinc.be`. The report now uses the bundled DejaVu fonts; rebuild with `docker compose up -d --build`.

## Difficult points

What took us the most time, and why the code looks the way it does. The details are in the code comments and the pull requests.

| Topic | What was hard | How it was solved |
|---|---|---|
| Never a silent "nothing found" | A security tool that reports "no problems" when a check could not run gives false confidence | Every module fails loudly when it could not check anything; partial failures are kept apart (and become warnings, #32) |
| Scans that run twice or get stuck | Redis hands a task to another worker when one crashes | The worker claims a scan with one atomic `UPDATE ... WHERE status = 'queued'`; stuck scans time out (#36) |
| crt.sh | Slow, often HTTP 502, hours behind | Cert Spotter first, crt.sh as backup, only valid certificates, and a circuit breaker (#49) |
| Office metadata | exiftool silently returned nothing for `.docx` and `.xlsx` | Install `libarchive-zip-perl` next to exiftool in the worker image |
| A fair detection rate | A scanner that reports everything finds everything | Ground truth of planted weaknesses, each finding paired with at most one, and precision next to recall (#47) |
| Changing the database | `create_all` never changes an existing table | Alembic migrations, applied by the `migrate` service (#62) |
| Staying on the client's website | katana and Python's `urlopen` follow a redirect to another host before our check sees it | katana never follows redirects (`-disable-redirects`) and the downloader refuses an off-host redirect before following it (#66) |
| A scan that hung now and then | katana checks GitHub for a new version at every start, and a hanging check hung the crawl | `-disable-update-check`, which also stops the scan from contacting ProjectDiscovery (#76) |
