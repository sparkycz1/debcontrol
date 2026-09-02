"""Small colored badge icons shown next to a machine's name, keyed by
`Machine.os_id` (from `/etc/os-release`'s `ID=`, or the special-cased
`"proxmox"` — see `app.ssh.facts`'s `FACTS_COMMAND`).

Deliberately **not** reproductions of each distribution's actual
trademarked logo artwork — this app has no license to redistribute those,
and vendoring exact brand assets (and keeping them up to date) is a bigger
commitment than "which small icon shows next to a machine name" warrants.
Instead: a two-letter initials badge in each distribution's own brand
color, covering the distributions this app's users are most likely to
actually run (Debian/Ubuntu-family first, since that's what this app
targets, plus Proxmox VE and the other common general-purpose distros) —
and a generic gray "Linux" badge for anything else, so every machine gets
*some* badge rather than a blank space or a broken image.

Rendered by `partials/_os_badge.html` (an inline `<svg>`, matching this
app's "no external icon fonts/images, CSP-safe" convention elsewhere —
see `macros/charts.html`'s own docstring for the same reasoning).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OsBadge:
    label: str  # Full display name, used as the badge's tooltip/alt text.
    initials: str  # 1-2 letters shown inside the badge.
    color: str  # Background color — each distribution's own brand color
    # where there is a well-known one, otherwise a neutral pick.


_BADGES: dict[str, OsBadge] = {
    "debian": OsBadge("Debian", "De", "#a80030"),
    "ubuntu": OsBadge("Ubuntu", "Ub", "#e95420"),
    "linuxmint": OsBadge("Linux Mint", "Mi", "#87cf3e"),
    "proxmox": OsBadge("Proxmox VE", "Px", "#e57000"),
    "fedora": OsBadge("Fedora", "Fe", "#294172"),
    "rhel": OsBadge("RHEL", "RH", "#ee0000"),
    "centos": OsBadge("CentOS", "Ce", "#932279"),
    "rocky": OsBadge("Rocky Linux", "Ro", "#10b981"),
    "almalinux": OsBadge("AlmaLinux", "Al", "#0057b8"),
    "opensuse": OsBadge("openSUSE", "Su", "#73ba25"),
    "opensuse-leap": OsBadge("openSUSE Leap", "Su", "#73ba25"),
    "opensuse-tumbleweed": OsBadge("openSUSE Tumbleweed", "Su", "#73ba25"),
    "arch": OsBadge("Arch Linux", "Ar", "#1793d1"),
    "raspbian": OsBadge("Raspberry Pi OS", "Pi", "#c51a4a"),
}

# Anything else Linux-based (or unrecognized) — still a badge, not a blank
# space or a broken image.
FALLBACK_BADGE = OsBadge("Linux", "Li", "#6b7280")


def badge_for(os_id: str | None) -> OsBadge:
    if not os_id:
        return FALLBACK_BADGE
    return _BADGES.get(os_id.strip().lower(), FALLBACK_BADGE)
