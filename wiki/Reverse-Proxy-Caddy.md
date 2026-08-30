# 🔒 Reverse proxy: Caddy

There are two ways to use Caddy with debcontrol:

- **Bundled**: `docker-compose.caddy.yml` in this repo runs Caddy for you,
  wired to the `web` service automatically. Use this unless you already
  run a reverse proxy on this host.
- **Standalone**: you already run your own Caddy instance (for other
  sites, or because you prefer managing it outside this repo). Point it at
  debcontrol's `127.0.0.1:8080`.

## Option A — the bundled Caddy

### Requirements

- `DOMAIN` and `ACME_EMAIL` set in `.env`.
- DNS: an A (and/or AAAA) record for `DOMAIN` pointing at this host's
  public IP.
- Ports `80/tcp`, `443/tcp`, and `443/udp` open and reachable from the
  internet:
  - `80/tcp` — used for the ACME HTTP-01 challenge and to redirect plain
    HTTP to HTTPS.
  - `443/tcp` — HTTPS (HTTP/1.1 and HTTP/2).
  - `443/udp` — HTTP/3 (QUIC).

### Run it

```bash
docker compose -f docker-compose.yml -f docker-compose.caddy.yml up -d --build
```

Caddy will automatically request and renew a certificate from Let's
Encrypt for `DOMAIN`, store it (and its ACME account state) in the
`caddy_data` named volume, and reverse-proxy everything to `web:8080`
over the internal Docker network.

### What's configured (`./Caddyfile`)

- **TLS 1.3 only** — `tls { protocols tls1.3 tls1.3 }` on the site block;
  TLS 1.2 and older are rejected outright.
- **HTTP/3** — enabled via the global `servers { protocols h1 h2 h3 }`
  option (also the default once automatic HTTPS is active, but stated
  explicitly here for clarity).
- **HSTS** — `Strict-Transport-Security` with a two-year max-age. The
  `preload` directive is included; remove it until you've confirmed
  everything works correctly over HTTPS, since preload-list submission is
  hard to undo.
- **Hardened headers** — `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, and the `Server` header is stripped so
  the proxy software isn't advertised.
- **Request/idle timeouts** — conservative defaults under
  `servers { timeouts { ... } }` to reduce exposure to slow-request style
  abuse.

### Verifying it worked

```bash
curl -sIv https://your-domain.example.com/healthz 2>&1 | grep -Ei 'HTTP/|strict-transport|server:'
```

You should see `HTTP/2` or `HTTP/3` in the response line (curl needs
HTTP/3 support compiled in to show `HTTP/3`; otherwise it'll negotiate
HTTP/2, which is still correct), an `HTTP/1.1 200`/`200` status, and the
`Strict-Transport-Security` header. To confirm HTTP/3 specifically:

```bash
curl --http3 -sI https://your-domain.example.com/healthz
```

To confirm only TLS 1.3 is accepted:

```bash
openssl s_client -connect your-domain.example.com:443 -tls1_2 </dev/null
# should fail to negotiate
openssl s_client -connect your-domain.example.com:443 -tls1_3 </dev/null
# should succeed
```

### Troubleshooting

- **Certificate not issued**: check `docker compose logs caddy`. Common
  causes: DNS not yet propagated, port 80 blocked by a firewall or another
  process already bound to it, or `ACME_EMAIL`/`DOMAIN` left as the
  `.env.example` placeholders.
- **Works on 443/tcp but not HTTP/3**: check that `443/udp` is actually
  open on any firewall/cloud security group in front of this host — it's
  easy to forget the UDP rule since most setups only think about TCP.
- **Local/LAN-only use, no public domain**: this bundled config assumes a
  public domain reachable by Let's Encrypt. For LAN-only deployments,
  replace the site address with `tls internal` in `./Caddyfile` (Caddy
  will mint its own local CA and self-signed certs); browsers/clients will
  need to trust that internal CA manually.

## Option B — your own standalone Caddy instance

If you run Caddy separately (not via this repo's compose files), add a
site block pointing at wherever debcontrol's `web` service is reachable
from your Caddy host — typically `127.0.0.1:8080` if Caddy runs directly
on the same machine as `docker compose up -d --build` (the base file,
without `docker-compose.caddy.yml`):

```caddyfile
your-domain.example.com {
	tls {
		protocols tls1.3 tls1.3
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

If your Caddy instance is itself a container in a different Compose
project, join it to debcontrol's Docker network so it can resolve the
`web` service by name, rather than going through the published `8080`
port at all — the base `docker-compose.yml` publishes that port on every
interface (not just loopback), so joining the network is the more
locked-down option even though going through `127.0.0.1:8080` would also
work.
