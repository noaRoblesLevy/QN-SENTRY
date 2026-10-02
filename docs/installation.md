# Installation Guide

How to install, configure, update and remove QN-Sentry on your own machine. It takes about ten minutes, most of it waiting for the first build.

> Only scan domains you own or have written permission to assess (see the [legal and ethical framework](project/05-legal-ethical.md)). During this project that means `badsecurityinc.be` only.

## 1. Requirements

| What | Version / size | Check with |
|---|---|---|
| Docker Engine or Docker Desktop (Windows, macOS, Linux) | Docker 24 or newer | `docker --version` |
| Docker Compose plugin | 2.24 or newer | `docker compose version` |
| Git | any recent version | `git --version` |
| Free disk space | about 3 GB for the images | |
| Free memory | about 2 GB while a scan runs | |
| Free ports on `127.0.0.1` | `8000` (API) and `8080` (dashboard) | see [Ports already in use](#ports-already-in-use) |

The platform also needs outbound internet access during a scan:

| Traffic | Why |
|---|---|
| DNS (UDP/TCP 53) to the resolver of your machine | Lookalike domains and SPF, DMARC and DKIM records |
| HTTPS (443) to the scanned website | Crawling the site and downloading its public documents |
| HTTPS to `api.certspotter.com` and `crt.sh` | Certificates of lookalike domains (Certificate Transparency) |
| HTTPS to `haveibeenpwned.com` | Only when `BREACH_SOURCE=hibp` |

A network that filters DNS (some company, school or hotel networks) makes the lookalike check fail on purpose instead of reporting "nothing found"; see [Known issues](known-issues.md#dns-filtering-networks).

## 2. Install

### Get the code

```bash
git clone https://github.com/noaRoblesLevy/QN-SENTRY.git
cd QN-SENTRY
```

### Create the configuration

```bash
cp .env.example .env
```

On Windows PowerShell: `Copy-Item .env.example .env`.

Open `.env` and replace `change-me` with a long random password for the database. To generate one:

```bash
openssl rand -base64 24                                   # macOS, Linux, Git Bash
```

```powershell
[Convert]::ToBase64String((1..24 | ForEach-Object { Get-Random -Maximum 256 }))   # PowerShell
```

`.env` is in `.gitignore`: never commit it.

### Start

```bash
docker compose up -d --build
```

The first build downloads the base images, installs the OSINT tools (katana and exiftool) and builds the dashboard, which takes a few minutes. Later starts take seconds.

What happens, in order:

1. `db` (PostgreSQL) and `redis` start and report healthy.
2. `migrate` creates or updates the database schema with Alembic, then exits.
3. `api`, `worker` and `beat` start once `migrate` has succeeded; `dashboard` starts after `api`.

### Check that it works

```bash
docker compose ps
```

`db`, `redis`, `api`, `worker`, `beat` and `dashboard` are `running`; `migrate` is listed as `exited (0)` with `docker compose ps -a`.

| Check | Expected |
|---|---|
| Open http://localhost:8080 | The QN-Sentry dashboard with the Clients page |
| Open http://localhost:8000/api/health | `{"status":"ok","database":"ok"}` |
| `docker compose logs migrate` | Ends with `Database schema is up to date` |
| `docker compose logs worker` | `celery@... ready.` |

Continue with the [user guide](user-guide.md) to run a first scan.

## 3. Configuration

All settings are environment variables in `.env`. The `api`, `worker`, `beat` and `migrate` services read the file; restart them after a change with `docker compose up -d`.

| Variable | Default | Meaning |
|---|---|---|
| `POSTGRES_DB` | `qnsentry` | Database name |
| `POSTGRES_USER` | `qnsentry` | Database user |
| `POSTGRES_PASSWORD` | none: **required** | Database password; the services do not start without it |
| `SCAN_TIMEOUT_MINUTES` | `120` | A scan still queued or running after this many minutes counts as stuck and no longer blocks its domain (at least 1) |
| `RETENTION_DAYS` | `90` | Scan results older than this are deleted every night at 03:00 UTC and when the worker starts (GDPR storage limitation; at least 1) |
| `BREACH_SOURCE` | `local` | `local`: the fictitious test dataset; `hibp`: Have I Been Pwned (needs an API key) |
| `BREACH_DATASET` | the bundled test data | Path to another JSON dataset for the `local` source |
| `HIBP_API_KEY` | none | Have I Been Pwned API key, required for `BREACH_SOURCE=hibp`; never commit it |
| `HIBP_MIN_INTERVAL_SECONDS` | `6` | Pause between Have I Been Pwned requests; 6 fits the smallest plan (10 per minute). The pause is per scan and the worker runs two scans at once: use 12 when two HIBP scans can run together |
| `CERTSPOTTER_API_KEY` | none | Cert Spotter API key for the certificate check of lookalike domains. Without a key the service is for personal or evaluation use only, with a small hourly limit; a real deployment needs one |

Rules for `.env`:

- Put remarks on their **own** line starting with `#`. Text after a value becomes part of the value: `RETENTION_DAYS=90  # days` is read as `90  # days` and nothing starts.
- A value below 1 for `RETENTION_DAYS` or `SCAN_TIMEOUT_MINUTES` is refused: the services stop with a clear error instead of deleting all results.

## 4. Update

```bash
git pull
docker compose up -d --build
```

`migrate` applies new database migrations before the API and worker start again, so existing clients, scans and findings are kept.

## 5. Stop and remove

| Goal | Command | Data |
|---|---|---|
| Stop everything | `docker compose down` | Kept |
| Start again | `docker compose up -d` | Kept |
| Remove everything, including all clients, scans and findings | `docker compose down -v` | **Deleted** |

## Ports already in use

If another project already uses port 8000 or 8080, `docker compose up` fails with `Bind for 0.0.0.0:8000 failed: port is already allocated`. Create a file `docker-compose.override.yml` next to `docker-compose.yml`, which Docker Compose reads automatically:

```yaml
services:
  api:
    ports: !override
      - "127.0.0.1:18000:8000"
  dashboard:
    ports: !override
      - "127.0.0.1:18080:8080"
```

Inside the container the dashboard listens on 8080 (it runs as a non-root user, which cannot use port 80), so the right-hand side is `8080`. `!override` replaces the ports instead of adding to them. The dashboard is then on http://localhost:18080 and the API on http://localhost:18000. Do not commit this file: add it to `.git/info/exclude`.

**Windows: a port can be reserved without any program using it.** Windows (WinNAT, Hyper-V) reserves ranges of ports for itself. Then the error is different: `ports are not available ... An attempt was made to access a socket in a way forbidden by its access permissions`, although no other project uses the port. Show the reserved ranges with:

```powershell
netsh interface ipv4 show excludedportrange protocol=tcp
```

and choose ports outside them in the same `docker-compose.override.yml`.

## Security notes

- The API and dashboard are bound to `127.0.0.1`: they are only reachable from the machine itself. There is no login yet (#20), so do not publish these ports on a network.
- The database and Redis have no published ports; only the containers can reach them.
- Every container runs as a non-root user.

More problems and their solutions: [Known issues and difficult points](known-issues.md).
