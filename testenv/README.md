# Test Environment: BadSecurityInc

BadSecurityInc is a fictitious Belgian SME that QN-Sentry is tested against (issue #2). It deliberately exposes information and services so every module has something to find. It is the **only** infrastructure QN-Sentry may be tested against.

The expected findings, with their severity, are in one place: the ground truth [`detection-rate/expected-findings.json`](detection-rate/expected-findings.json) (#47), which the detection-rate script compares a scan with.

## Components

| Component | Where | Owner |
|---|---|---|
| `badsecurityinc.be` and `badsecuritylnc.be` | Registered at one.com, DNS managed there | Quinten |
| `badsecurityinc.be` and `www.badsecurityinc.be`: website, team page, documents | Vercel, see [`website/`](website/README.md) | Noa |
| `badsecuritylnc.be`: lookalike page | Vercel, see [`lookalike/`](lookalike/) | Noa |
| `dev.badsecurityinc.be` and a decoy SSH service | Google Cloud VM, see [`vm/`](vm/) | Quinten |
| Breach test dataset | In the Breach module | Noa |

## The VM (`vm/`)

| Service | Port | What a scanner sees | What it really is |
|---|---|---|---|
| `staging` | 80, 443 | A forgotten staging admin login on `dev.badsecurityinc.be`, served by `nginx/1.18.0` with `PHP/7.4.3` | Static HTML served by an up-to-date Caddy; the login always fails and the headers are fake |
| `decoy-ssh` | 2222 | OpenSSH 8.2p1 on a non-standard port | A Python script that sends an SSH banner and closes the connection: no login, no shell |

Nothing else is published: the VM exposes exactly ports 80, 443 and 2222 (plus SSH for management, see below).

### Safety rules

- **Decoys only.** Nothing on the VM runs genuinely outdated or vulnerable software. The VM is on the internet, so other scanners find it too.
- **No real data.** All people, email addresses and documents are fictitious.
- **No personal data of visitors.** The decoy SSH never logs the addresses of the clients that connect (on the internet, every bot), Caddy keeps no access log and never stores what is typed into the decoy login, and the container logs are limited to a few MB.
- **Not misleading.** The staging page says it belongs to a fictitious company in a student project, and asks search engines not to index it (`noindex` and `robots.txt`).
- **Limited load.** The decoy SSH sends its banner and closes the connection at once, so no connection stays open and a flood of bots costs almost nothing.
- **Manage the VM with SSH keys only**, on its normal port and restricted by the firewall. Never with passwords.
- **Stop the VM when you are not testing**, and remove it after the project with the teardown checklist (#61).

### Run locally

QN-Sentry's dashboard already uses port 8080, so the local test uses 8081, and only on `127.0.0.1`:

```bash
cd testenv/vm
cp .env.example .env          # STAGING_ADDRESS=http://localhost:8081
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --build
```

- Staging site: http://localhost:8081 (check the fake headers with `curl -I http://localhost:8081`). Use the host name `localhost`: Caddy serves the site for that name only, so `127.0.0.1:8081` gives an empty page, like the VM's IP address does instead of `dev.badsecurityinc.be`.
- Decoy SSH banner: `127.0.0.1:2222`

Stop it with the same `-f` options and `down`.

### Deploy on the VM

Set `STAGING_ADDRESS=dev.badsecurityinc.be` in `.env`, point the DNS record `dev` to the VM and run `docker compose up -d --build` (without the local file). Caddy then requests an HTTPS certificate automatically, which also makes `dev.badsecurityinc.be` visible in Certificate Transparency logs.
