# 📁 About this folder

This directory holds the project documentation, written to become the
**GitHub wiki** once this repository is pushed to GitHub. It isn't a GitHub
wiki yet — a wiki only exists once a repo is on GitHub with the feature
enabled, and it lives in its own separate git repository
(`<repo>.wiki.git`).

## 🚀 How to publish this as the actual GitHub wiki

1. Push this repository to GitHub.
2. Go to the repo's **Settings → Features** and make sure **Wikis** is
   enabled.
3. Open the **Wiki** tab once and create the initial "Home" page (GitHub
   requires at least one page to exist before the wiki's git repo is
   created).
4. Clone the wiki repo locally:
   ```bash
   git clone https://github.com/<owner>/<repo>.wiki.git
   ```
5. Copy every `.md` file from this folder (except this `README.md`) into
   the cloned wiki repo, then commit and push:
   ```bash
   cp wiki/*.md ../debcontrol.wiki/
   rm ../debcontrol.wiki/README.md   # this file itself isn't a wiki page
   cd ../debcontrol.wiki
   git add -A
   git commit -m "Import wiki pages"
   git push
   ```
6. From then on, treat `<repo>.wiki.git` as the source of truth for the
   wiki and keep this folder in sync manually (or drop this folder from
   the main repo once the wiki is live — your call).

## 📑 Pages

- [Home](Home.md) — overview and table of contents
- [Installation](Installation.md) — Docker quick start, with or without Caddy
- [Architecture](Architecture.md) — stack choices and security model
- [SSH Host Key Verification](SSH-Host-Key-Verification.md) — the fingerprint-pinning flow, explained
- [Managed Machine Requirements](Managed-Machine-Requirements.md) — what a Debian machine needs to be managed
- [Ansible Onboarding](Ansible-Onboarding.md) — a playbook that does that automatically and self-registers the machine
- [Reverse Proxy: Caddy](Reverse-Proxy-Caddy.md) — using the bundled Caddy service
- [Reverse Proxy: nginx](Reverse-Proxy-Nginx.md) — bring your own nginx
- [Reverse Proxy: Traefik](Reverse-Proxy-Traefik.md) — bring your own Traefik
- [Development](Development.md) — running locally, tests, migrations
