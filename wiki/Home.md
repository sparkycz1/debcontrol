# debcontrol wiki

debcontrol is a web application for managing Debian machines over SSH.
There is no login yet — see [Architecture](Architecture.md) for the
security model and what's intentionally deferred.

## Pages

- **[Installation](Installation.md)** — Docker quick start, running with or
  without the bundled Caddy reverse proxy, environment variables reference.
- **[Architecture](Architecture.md)** — technology choices, project
  structure, and the security decisions made from day one.
- **[SSH Host Key Verification](SSH-Host-Key-Verification.md)** — how
  debcontrol pins SSH host keys and why it never "trusts on first use".
- **[Managed Machine Requirements](Managed-Machine-Requirements.md)** —
  what a Debian machine needs (network, account, packages) to be added.
- **[Development](Development.md)** — running the app locally without
  Docker, tests, linting, and database migrations.

## Reverse proxy guides

debcontrol itself only speaks plain HTTP on `127.0.0.1:8000` — it always
expects to sit behind a TLS-terminating reverse proxy. Pick one:

- **[Caddy (bundled)](Reverse-Proxy-Caddy.md)** — the easiest path:
  `docker-compose.caddy.yml` gives you automatic HTTPS (Let's Encrypt),
  TLS 1.3 only, and HTTP/3 with no manual certificate handling.
  Also useful if you'd rather run your own separate Caddy instance.
- **[nginx](Reverse-Proxy-Nginx.md)** — if you already run nginx for other
  sites on this host.
- **[Traefik](Reverse-Proxy-Traefik.md)** — if you already run Traefik
  (e.g. alongside other Docker Compose projects).

## Feature overview

| Tab | Status |
|---|---|
| Machines | Add/view/remove managed machines, pin host keys, test connectivity, auto-discovered facts, online/offline status, self-registration review |
| Machine groups | Organize machines into named groups |
| Users | Placeholder — no login/authentication yet |
| Settings | Shows the app's SSH public key and background-check intervals |
