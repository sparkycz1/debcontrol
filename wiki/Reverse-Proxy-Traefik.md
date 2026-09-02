# 🔒 Reverse proxy: Traefik

Use this if you already run Traefik on the host where debcontrol's
`docker compose up -d --build` (the base file, without
`docker-compose.caddy.yml`) is running, exposing the app on
`127.0.0.1:8080` (or whatever `APP_PORT` you set in `.env`).

Two ways to wire Traefik up to a service: a static **file provider** entry
pointing at an address, or **Docker labels** read via Traefik's Docker
provider. The file provider is simpler when debcontrol and Traefik aren't
in the same Compose project (the default here).

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

If Traefik itself runs inside Docker, `127.0.0.1` from its point of view
is the Traefik *container*, not the host — either run Traefik with
`network_mode: host`, or use the host's Docker-bridge gateway address
(commonly `172.17.0.1`, verify with `ip addr show docker0`) instead of
`127.0.0.1` in the service URL above.

## 🏷️ Alternative: Docker label-based discovery

If you'd rather use Traefik's Docker provider (labels on the `web`
container) instead of the file provider above, `web` and Traefik need to
share a Docker network — add an external network to both
`docker-compose.yml` (on the `web` service) and Traefik's compose file,
then label `web`:

```yaml
labels:
  - traefik.enable=true
  - traefik.http.routers.debcontrol.rule=Host(`your-domain.example.com`)
  - traefik.http.routers.debcontrol.entrypoints=websecure
  - traefik.http.routers.debcontrol.tls.certresolver=letsencrypt
  - traefik.http.routers.debcontrol.tls.options=tls13only@file
  - traefik.http.services.debcontrol.loadbalancer.server.port=8080
```

This requires exposing the Docker socket to the Traefik container, which
is a meaningfully larger trust boundary than the file-provider approach
above — only do this if you already accept that trade-off for your other
services.

## 🔎 Verifying

```bash
curl -sIv https://your-domain.example.com/healthz 2>&1 | grep -Ei 'HTTP/|strict-transport|server:'
curl --http3 -sI https://your-domain.example.com/healthz   # confirms HTTP/3
openssl s_client -connect your-domain.example.com:443 -tls1_2 </dev/null   # should fail
```
