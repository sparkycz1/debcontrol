<p align="center">
  <img src="app/web/static/img/favicon.svg" alt="debcontrol" width="96">
</p>

<h1 align="center">debcontrol</h1>

<p align="center">
  <b>Your whole Debian fleet in one browser tab. No agents, just SSH.</b><br>
  Updates with rollback, monitoring, Docker, security audits, uptime checks,<br>
  a browser terminal and scheduled maintenance for Debian, Ubuntu and Proxmox.
</p>

<p align="center">
  <a href="https://github.com/sparkycz1/debcontrol/actions/workflows/ci.yml"><img src="https://github.com/sparkycz1/debcontrol/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/sparkycz1/debcontrol/actions/workflows/codeql.yml"><img src="https://github.com/sparkycz1/debcontrol/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://github.com/sparkycz1/debcontrol/actions/workflows/fuzz.yml"><img src="https://github.com/sparkycz1/debcontrol/actions/workflows/fuzz.yml/badge.svg" alt="Fuzz"></a>
  <a href="https://github.com/sparkycz1/debcontrol/actions/workflows/scorecard.yml"><img src="https://github.com/sparkycz1/debcontrol/actions/workflows/scorecard.yml/badge.svg" alt="Scorecard"></a>
  <a href="https://github.com/sparkycz1/debcontrol/actions/workflows/release.yml"><img src="https://github.com/sparkycz1/debcontrol/actions/workflows/release.yml/badge.svg" alt="Release"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/sparkycz1/debcontrol"><img src="https://api.securityscorecards.dev/projects/github.com/sparkycz1/debcontrol/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://github.com/sparkycz1/debcontrol/releases/latest"><img src="https://img.shields.io/github/v/release/sparkycz1/debcontrol?color=c8102e" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-PolyForm%20Noncommercial-blue" alt="License"></a>
</p>

<p align="center">
  <a href=".github/SECURITY.md"><img src="https://img.shields.io/badge/security-policy-blue" alt="Security policy"></a>
  <a href="https://github.com/sparkycz1/debcontrol/security"><img src="https://img.shields.io/badge/secret%20scanning-enabled-brightgreen" alt="Secret scanning"></a>
  <a href=".github/dependabot.yml"><img src="https://img.shields.io/badge/dependabot-enabled-025E8C?logo=dependabot&logoColor=white" alt="Dependabot"></a>
  <a href="https://github.com/sparkycz1/debcontrol/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/pip--audit-in%20CI-4B8BBE" alt="pip-audit"></a>
  <a href="https://github.com/astral-sh/ruff"><img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json" alt="Ruff"></a>
  <a href="https://mypy-lang.org/"><img src="https://img.shields.io/badge/mypy-strict-2A6DB2" alt="mypy strict"></a>
  <a href="https://github.com/sparkycz1/debcontrol/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/browser%20test-Playwright-2EAD33?logo=playwright&logoColor=white" alt="Playwright browser test"></a>
  <a href="https://github.com/astral-sh/uv"><img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json" alt="uv"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.15-3776AB?logo=python&logoColor=white" alt="Python 3.15">
  <img src="https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/htmx-3366CC?logo=htmx&logoColor=white" alt="htmx">
  <img src="https://img.shields.io/badge/SQLAlchemy%202.1-D71F00?logo=sqlalchemy&logoColor=white" alt="SQLAlchemy 2.1">
  <img src="https://img.shields.io/badge/PostgreSQL%2018-4169E1?logo=postgresql&logoColor=white" alt="PostgreSQL 18">
  <img src="https://img.shields.io/badge/Redis%208-DC382D?logo=redis&logoColor=white" alt="Redis 8">
  <img src="https://img.shields.io/badge/Celery-37814A?logo=celery&logoColor=white" alt="Celery">
  <img src="https://img.shields.io/badge/Docker%20Compose-2496ED?logo=docker&logoColor=white" alt="Docker Compose">
  <img src="https://img.shields.io/badge/Caddy-1F88C0?logo=caddy&logoColor=white" alt="Caddy">
  <img src="https://img.shields.io/badge/i18n-English%20%7C%20%C4%8Ce%C5%A1tina-c8102e" alt="English and Czech">
</p>

<p align="center">
  <a href="#-quick-start"><b>Quick start</b></a> ·
  <a href="https://github.com/sparkycz1/debcontrol/wiki"><b>Documentation</b></a> ·
  <a href="#-screenshots"><b>Screenshots</b></a> ·
  <a href="https://github.com/sparkycz1/debcontrol/wiki/REST-API"><b>REST API</b></a> ·
  <a href="https://github.com/sparkycz1/debcontrol/releases"><b>Releases</b></a> ·
  <a href=".github/SECURITY.md"><b>Security</b></a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/wiki/sparkycz1/debcontrol/images/dashboard-fleet.png" alt="Every machine of the fleet as a card on the Dashboard" width="900">
</p>

## ✨ What it does

| | |
|---|---|
| ⬆️ **Updates you can undo** | Preview what apt will install and remove, update one machine or a whole group, roll back afterwards, take a Proxmox snapshot first. Pending security updates are listed fleet-wide with their CVEs. |
| 📈 **Monitoring** | CPU, memory, disks, network, temperatures, S.M.A.R.T. and GPUs, with history and drag-to-zoom charts. A disk-full forecast warns days ahead. |
| 🐳 **Docker** | Container updates that put the old one back if the new one fails, Trivy + Grype scans, Compose stacks from an editor or Git, restic backups. |
| 🛡️ **Security audit** | Lynis plus the vps-audit checks on every machine, a hardening index and how to fix each finding. |
| 🔐 **Checks & status page** | HTTP, TLS, ping, TCP, DNS, SMTP, SSH and heartbeat checks, an SLA report and a public status page. |
| ⏱️ **Scheduling** | Cron any action per time zone, maintenance windows, a month calendar, Wake-on-LAN. |
| 🖥️ **Terminal, logs, runbooks** | A browser SSH terminal (optionally recorded), journal and log files, saved procedures with parameters. |
| 🔔 **Notifications** | Email, webhook, ntfy, Gotify, Telegram, Discord, Pushover, Mattermost, Slack or Teams, on events or thresholds. |
| 🧠 **AI assistant** | Ask your fleet in plain language. It only *proposes*; you confirm every command. |
| 🟧 **Proxmox** | Guests, backups per guest, snapshots, ZFS, Backup Server and Mail Gateway. |

## 💡 Why debcontrol

- 🔌 **Agentless.** One SSH key and a scoped `sudoers` line per machine.
  Nothing to install, no extra open port.
- 🛡️ **Safe by default.** SSH host keys are pinned (no trust on first
  use), secrets are encrypted with AES-256-GCM, a strict Content Security
  Policy, and every change goes to a hash-chained audit log.
- 👥 **Built for a team.** Custom roles, machine-group scoping, LDAP, OIDC
  SSO, TOTP and passkeys.
- 🔁 **Everything scriptable.** A full read/write REST API mirrors the web
  UI, with Swagger docs at `/api` and Prometheus metrics.
- 🌍 **Your language.** Every page in English and Czech. A new language is
  one JSON file.
- 📈 **Scales.** From a homelab of five boxes to a few thousand machines
  ([sizing guide](https://github.com/sparkycz1/debcontrol/wiki/Host-Requirements)).

## 🚀 Quick start

You need Docker with Compose v2.

```bash
git clone https://github.com/sparkycz1/debcontrol.git
cd debcontrol
python3 scripts/setup.py
```

The wizard generates every secret, asks a few questions (time zone,
language, the bundled Caddy for HTTPS, the admin password, the port),
starts the stack and creates the first administrator. Then open
`http://<host>:8080` and add your first machine.

> [!WARNING]
> The app itself speaks **plain HTTP**. Put TLS in front of it: the
> bundled [Caddy](https://github.com/sparkycz1/debcontrol/wiki/Reverse-Proxy-Caddy)
> (automatic Let's Encrypt), or your own
> [nginx](https://github.com/sparkycz1/debcontrol/wiki/Reverse-Proxy-Nginx) or
> [Traefik](https://github.com/sparkycz1/debcontrol/wiki/Reverse-Proxy-Traefik).

<details>
<summary><b>Manual setup instead of the wizard</b></summary>

```bash
cp .env.example .env
python3 scripts/generate_secrets.py   # paste the printed values into .env
docker compose up -d --build
docker compose exec web python scripts/create_admin.py --username admin
```

With the bundled Caddy: set `DOMAIN` and `ACME_EMAIL` in `.env`, point
the domain's DNS at this host, open ports 80/tcp, 443/tcp and 443/udp,
then
`docker compose -f docker-compose.yml -f docker-compose.caddy.yml up -d --build`.

Every variable is explained in
[Installation](https://github.com/sparkycz1/debcontrol/wiki/Installation).
</details>

**Updating** later: `./scripts/upgrade.sh`, or one click in
**Settings → Update** ([how](https://github.com/sparkycz1/debcontrol/wiki/Installation#updating)).

## 🖼️ Screenshots

| | |
|---|---|
| ![Dashboard](https://raw.githubusercontent.com/wiki/sparkycz1/debcontrol/images/dashboard.png) | ![Machine list](https://raw.githubusercontent.com/wiki/sparkycz1/debcontrol/images/machines.png) |
| **Dashboard**: fleet tiles and trends | **Machines**: status, updates, reboot flags |
| ![Monitoring](https://raw.githubusercontent.com/wiki/sparkycz1/debcontrol/images/monitoring.png) | ![Docker](https://raw.githubusercontent.com/wiki/sparkycz1/debcontrol/images/docker.png) |
| **Monitoring**: history with drag-to-zoom | **Docker**: updates, scans, stacks, backups |
| ![Checks](https://raw.githubusercontent.com/wiki/sparkycz1/debcontrol/images/checks.png) | ![Light theme](https://raw.githubusercontent.com/wiki/sparkycz1/debcontrol/images/dashboard-light.png) |
| **Checks**: from outside, with a status page | **Light theme**, one click away |

## 📚 Documentation

Everything lives in the **[wiki](https://github.com/sparkycz1/debcontrol/wiki)**:

- **Set it up**: [Installation](https://github.com/sparkycz1/debcontrol/wiki/Installation) ·
  [Host requirements](https://github.com/sparkycz1/debcontrol/wiki/Host-Requirements) ·
  [Machine requirements](https://github.com/sparkycz1/debcontrol/wiki/Machine-Requirements) ·
  [Ansible onboarding](https://github.com/sparkycz1/debcontrol/wiki/Ansible-Onboarding)
- **Use it**: [every feature, page by page](https://github.com/sparkycz1/debcontrol/wiki/Home)
- **Script it**: [REST API](https://github.com/sparkycz1/debcontrol/wiki/REST-API)
- **Understand or change it**: [Architecture and security model](https://github.com/sparkycz1/debcontrol/wiki/Architecture) ·
  [Development](https://github.com/sparkycz1/debcontrol/wiki/Development)

Officially supported targets: Debian and its derivatives (Ubuntu, Proxmox
VE, Backup Server and Mail Gateway) for as long as each is supported
upstream ([details](https://github.com/sparkycz1/debcontrol/wiki/Machine-Requirements#os)).

## 🔒 Security

Found a vulnerability? Please report it privately, see
[SECURITY.md](.github/SECURITY.md). CI runs CodeQL, pip-audit, fuzzing and
a browser test under the real CSP on every change; Dependabot keeps
dependencies current.

## 🤝 Contributing

Issues and pull requests are welcome, see [CONTRIBUTING.md](CONTRIBUTING.md).
debcontrol started as a tool for managing my own homelab, and much of it
was written with AI assistance.

## 📄 License

[PolyForm Noncommercial 1.0.0](LICENSE): free for noncommercial use.
Commercial use needs a separate agreement with the licensor.
