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

- [Architecture → Security essentials](../wiki/Architecture.md#-security-essentials) — CSRF, HTTP headers, startup validation, container hardening, plus links to [Authentication & RBAC](../wiki/Authentication-RBAC.md), [Machine Management](../wiki/Machine-Management.md) (SSH host key pinning, secrets at rest), and [Audit Log](../wiki/Audit-Log.md).
- [AI Assistant](../wiki/AI-Assistant.md) — the confirm-before-execute rule, permission model, and the residual prompt-injection risk it deliberately does not eliminate.
- [SSH Host Key Verification](../wiki/SSH-Host-Key-Verification.md) — why there's no trust-on-first-use.

Dependency vulnerabilities are tracked automatically via [Dependabot](dependabot.yml) (alerts and security updates are enabled on this repository).
