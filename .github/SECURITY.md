# 🔒 Security Policy

## Supported versions

Only the **latest released version** (the most recent [tag/release](https://github.com/sparkycz1/debcontrol/releases)) is supported with security fixes. There are no maintained older branches — upgrade to the latest release before reporting an issue, and after a fix ships.

| Version | Supported |
|---|---|
| Latest release | ✅ |
| Anything older | ❌ |

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.** Instead, open a private draft security advisory: this repository's **Security** tab → **Advisories** → **Report a vulnerability** / **New draft security advisory**.

Include, if known:
- The affected version/commit.
- Steps to reproduce, or a proof of concept.
- The impact you'd expect (what an attacker could actually do).

## Scope

This is a self-hosted admin tool for managing Debian/Ubuntu machines over SSH — the threat model and existing safeguards are documented in the wiki:

- [Architecture → Security essentials](https://github.com/sparkycz1/debcontrol/wiki/Architecture#-security-essentials) — CSRF, HTTP headers, startup validation, container hardening, plus links to [Authentication & RBAC](https://github.com/sparkycz1/debcontrol/wiki/Authentication-RBAC), [Machine Management](https://github.com/sparkycz1/debcontrol/wiki/Machine-Management) (SSH host key pinning, secrets at rest), and [Audit Log](https://github.com/sparkycz1/debcontrol/wiki/Audit-Log).
- [AI Assistant](https://github.com/sparkycz1/debcontrol/wiki/AI-Assistant) — the confirm-before-execute rule, permission model, and the residual prompt-injection risk it deliberately does not eliminate.
- [SSH Host Key Verification](https://github.com/sparkycz1/debcontrol/wiki/SSH-Host-Key-Verification) — why there's no trust-on-first-use.

Dependency vulnerabilities are tracked automatically via [Dependabot](dependabot.yml) (alerts and security updates are enabled on this repository).
