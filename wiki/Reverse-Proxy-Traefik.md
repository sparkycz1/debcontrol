# 🔒 Reverse proxy: Traefik

*Docker labels doing the routing — because typing config files is for people without Traefik.*

For when debcontrol (base `docker-compose.yml`, no Caddy overlay) exposes
`127.0.0.1:8080` and Traefik already runs on the same host. Once
working, set `APP_BIND_ADDRESS=127.0.0.1` in `.env` so the app is only
reachable through the proxy.

Two ways to wire it up: a static **file provider** entry, or **Docker
labels** via Traefik's Docker provider. File provider is simpler when
debcontrol and Traefik aren't in the same Compose project (the default here).

## ⚙️ Static config (`traefik.yml`)

```yaml
entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
  websecure:
    address: ":443"
    http3: {}

certificatesResolvers:
  letsencrypt:
    acme:
      email: admin@example.com
      storage: /letsencrypt/acme.json
      httpChallenge:
        entryPoint: web

providers:
  file:
    directory: /etc/traefik/dynamic
    watch: true
```

`http3: {}` enables HTTP/3 on the `websecure` entrypoint (Traefik still
needs `443/udp` published/open for QUIC to actually work).

## 🔐 TLS options: restrict to TLS 1.3 only (`dynamic/tls.yml`)

```yaml
tls:
  options:
    tls13only:
      minVersion: VersionTLS13
      maxVersion: VersionTLS13
```

## 🔀 Route to debcontrol (`dynamic/debcontrol.yml`)

```yaml
http:
  routers:
    debcontrol:
      rule: "Host(`your-domain.example.com`)"
      entryPoints:
        - websecure
      service: debcontrol
      tls:
        certResolver: letsencrypt
        options: tls13only@file
      middlewares:
        - debcontrol-headers

  middlewares:
    debcontrol-headers:
      headers:
        stsSeconds: 63072000
        stsIncludeSubdomains: true
        contentTypeNosniff: true
        referrerPolicy: "no-referrer"
        customResponseHeaders:
          Server: ""

  services:
    debcontrol:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8080"
```

Traefik running inside Docker? `127.0.0.1` there means the Traefik
*container*, not the host — use `network_mode: host`, or the Docker-bridge
gateway address (`ip addr show docker0`, commonly `172.17.0.1`) instead.

## 🏷️ Alternative: Docker label-based discovery

Prefer Traefik's Docker provider over the file provider? `web` and
Traefik need a shared Docker network — add an external network to both
compose files, then label `web`:

```yaml
labels:
  - traefik.enable=true
  - traefik.http.routers.debcontrol.rule=Host(`your-domain.example.com`)
  - traefik.http.routers.debcontrol.entrypoints=websecure
  - traefik.http.routers.debcontrol.tls.certresolver=letsencrypt
  - traefik.http.routers.debcontrol.tls.options=tls13only@file
  - traefik.http.services.debcontrol.loadbalancer.server.port=8080
```

Needs exposing the Docker socket to Traefik — a meaningfully larger trust
boundary than the file provider. Only worth it if you already accept
that trade-off for your other services.

## 🔎 Verifying

```bash
curl -sIv https://your-domain.example.com/healthz 2>&1 | grep -Ei 'HTTP/|strict-transport|server:'
curl --http3 -sI https://your-domain.example.com/healthz   # confirms HTTP/3
openssl s_client -connect your-domain.example.com:443 -tls1_2 </dev/null   # should fail
```
