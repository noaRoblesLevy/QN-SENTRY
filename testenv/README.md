# Test Environment: BadSecurityInc

BadSecurityInc is a fictitious Belgian SME that QN-Sentry is tested against (issue #2). It deliberately exposes information and services so every module has something to find. It is the **only** infrastructure QN-Sentry may be tested against.

The expected results are listed in [`docs/testenv/expected-findings.md`](../docs/testenv/expected-findings.md).

## Components

| Component | Where | Owner |
|---|---|---|
| `badsecurityinc.be` and `badsecuritylnc.be` | Registered at one.com, DNS managed there | Quinten |
| `www.badsecurityinc.be`: website, team page, documents | Vercel | Noa |
| `badsecuritylnc.be`: lookalike page | Vercel | Noa |
| `dev.badsecurityinc.be` and a non-web service | VM, see [`vm/`](vm/) | Quinten |
| Breach test dataset | In the Breach module | Noa |

## The VM (`vm/`)

| Service | Port | What a scanner sees | What it really is |
|---|---|---|---|
| `staging` | 80, 443 | A forgotten staging admin login on `dev.badsecurityinc.be`, served by `nginx/1.18.0` with `PHP/7.4.3` | Static HTML served by an up-to-date Caddy; the login always fails and the headers are fake |
| `decoy-ssh` | 2222 | OpenSSH 8.2p1 on a non-standard port | A Python script that sends an SSH banner and closes the connection: no login, no shell |

### Safety rules

- **Decoys only.** Nothing on the VM runs genuinely outdated or vulnerable software. The VM is on the internet, so other scanners find it too.
- **No real data.** All people, email addresses and documents are fictitious.
- **Manage the VM with SSH keys only**, on its normal port and restricted by the firewall. Never with passwords.
- **Stop the VM when you are not testing.**

### Run locally

```bash
cd testenv/vm
cp .env.example .env          # STAGING_ADDRESS=http://localhost:8080
docker compose up -d --build
```

- Staging site: http://localhost:8080 (check the headers with `curl -I http://localhost:8080`)
- Decoy SSH banner: port 2222

### Deploy on the VM

Set `STAGING_ADDRESS=dev.badsecurityinc.be` in `.env`, point the DNS record `dev` to the VM and run the same `docker compose up -d --build`. Caddy then requests an HTTPS certificate automatically, which also makes `dev.badsecurityinc.be` visible in Certificate Transparency logs.
