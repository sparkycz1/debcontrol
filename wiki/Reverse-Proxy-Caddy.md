# 🔒 Reverse proxy: Caddy

*HTTPS with zero certificate ceremony — Caddy just handles it.*

Two ways to use it:

- **Bundled** — `docker-compose.caddy.yml` runs Caddy for you, wired to
  `web` automatically. Default choice.
- **Standalone** — you already run your own Caddy. Point it at
  `127.0.0.1:8080` (or your `APP_PORT`), then set
  `APP_BIND_ADDRESS=127.0.0.1` in `.env` so the app is only reachable
  through the proxy.

## 📦 Option A — the bundled Caddy

### Requirements

- `DOMAIN` and `ACME_EMAIL` set in `.env`.
- DNS: an A/AAAA record for `DOMAIN` pointing at this host.
- Reachable from the internet: `80/tcp` (ACME challenge + HTTP→HTTPS
  redirect), `443/tcp` (HTTPS), `443/udp` (HTTP/3).

### Run it

```bash
docker compose -f docker-compose.yml -f docker-compose.caddy.yml up -d --build
```

Caddy will automatically request and renew a certificate from Let's
Encrypt for `DOMAIN`, store it (and its ACME account state) in the
`caddy_data` named volume, and reverse-proxy everything to `web:8080`
over the internal Docker network.

### What's configured (`./Caddyfile`)

- **TLS 1.3 only** — 1.2 and older rejected outright.
- **HTTP/3** enabled.
- **HSTS**, two-year max-age. `preload` is included — strip it until
  you've confirmed HTTPS works, since preload-list submission is hard to undo.
- Hardened headers (`nosniff`, `no-referrer`, `Server` stripped) and
  conservative request/idle timeouts.
- **5MB request body cap** — the app has no file-upload endpoint; the
  largest legitimate body is a pasted runbook, SSH key, or a config/
  notification-rule JSON/YAML import, all comfortably under that. Rejects
  an oversized POST at the proxy, before it reaches `web` at all.

### Verifying it worked

```bash
curl -sIv https://your-domain.example.com/healthz 2>&1 | grep -Ei 'HTTP/|strict-transport|server:'
```

Look for `HTTP/2`/`HTTP/3`, a `200`, and `Strict-Transport-Security`.
Confirm HTTP/3 and TLS 1.3-only directly:

```bash
curl --http3 -sI https://your-domain.example.com/healthz

openssl s_client -connect your-domain.example.com:443 -tls1_2 </dev/null   # should fail
openssl s_client -connect your-domain.example.com:443 -tls1_3 </dev/null   # should succeed
```

### Troubleshooting

- **No certificate**: `docker compose logs caddy`. Usual suspects — DNS
  not propagated yet, port 80 blocked/taken, or `ACME_EMAIL`/`DOMAIN`
  still at their `.env.example` placeholders.
- **443/tcp works, HTTP/3 doesn't**: `443/udp` is almost always the one
  firewall rule people forget.
- **LAN-only, no public domain**: this config needs Let's Encrypt to
  reach you — see [Installation](Installation.md)'s `tls internal` steps
  instead (also what makes WebAuthn/passkeys and terminal clipboard
  copy/paste work at all over plain HTTP on a LAN).

## 🔧 Option B — your own standalone Caddy instance

Add a site block pointing at wherever `web` is reachable — typically
`127.0.0.1:8080` if Caddy runs on the same host:

```caddyfile
your-domain.example.com {
	tls {
		protocols tls1.3 tls1.3
	}

	request_body {
		max_size 5MB
	}

	header {
		Strict-Transport-Security "max-age=63072000; includeSubDomains"
		X-Content-Type-Options "nosniff"
		Referrer-Policy "no-referrer"
		-Server
	}

	reverse_proxy 127.0.0.1:8080 {
		header_up X-Forwarded-Proto {scheme}
	}
}
```

Running Caddy as a container in a different Compose project? Join it to
debcontrol's Docker network and resolve `web` by name instead of going
through the published (all-interfaces) `8080` port — more locked-down.
