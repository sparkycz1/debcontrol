# 🔒 Reverse proxy: nginx

Use this if you already run nginx on the host where debcontrol's
`docker compose up -d --build` (the base file, without
`docker-compose.caddy.yml`) is running, exposing the app on
`127.0.0.1:8080` (or whatever `APP_PORT` you set in `.env`).

## ✅ Prerequisites

- A certificate for your domain. Easiest via
  [certbot](https://certbot.eff.org/) (webroot or nginx plugin). HTTP/3
  additionally requires nginx built with `--with-http_v3_module` — check
  with `nginx -V 2>&1 | grep -o with-http_v3_module`. This ships in nginx
  mainline releases; some distro-packaged builds omit it, in which case
  TLS 1.3 over HTTP/2 (below, without the HTTP/3 section) works fine and
  is much simpler to set up.

## ⚙️ Base config: TLS 1.3 only, reverse proxy to debcontrol

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name your-domain.example.com;

    # For certbot's HTTP-01 challenge.
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;

    server_name your-domain.example.com;

    ssl_certificate     /etc/letsencrypt/live/your-domain.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.example.com/privkey.pem;

    # Only TLS 1.3 — no 1.2/1.1/1.0 fallback.
    ssl_protocols TLSv1.3;

    server_tokens off;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Reload nginx after installing this:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

## 🚀 Optional: adding HTTP/3

Only if your nginx build includes the QUIC/HTTP-3 module. Add to the HTTPS
server block:

```nginx
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    listen 443 quic reuseport;
    listen [::]:443 quic reuseport;
    http2 on;
    http3 on;
    quic_retry on;

    add_header Alt-Svc 'h3=":443"; ma=86400' always;

    # ... rest of the block as above ...
}
```

The `Alt-Svc` header is what tells browsers an HTTP/3 endpoint is
available so they can upgrade on a subsequent request. Directive names
for QUIC/HTTP-3 have shifted across nginx releases — if `http3 on;` isn't
recognized, check `nginx -v` and the changelog for your specific version.

## 🔎 Verifying

```bash
curl -sIv https://your-domain.example.com/healthz 2>&1 | grep -Ei 'HTTP/|strict-transport|server:'
openssl s_client -connect your-domain.example.com:443 -tls1_2 </dev/null   # should fail
openssl s_client -connect your-domain.example.com:443 -tls1_3 </dev/null  # should succeed
```

## 🔄 Certificate renewal

If using certbot, its systemd timer/cron job handles renewal; add a
post-renewal hook to reload nginx:

```bash
echo "systemctl reload nginx" | sudo tee /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
```
