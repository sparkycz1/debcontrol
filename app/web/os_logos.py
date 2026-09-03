"""Small colored badge icons shown next to a machine's name, keyed by
`Machine.os_id` (from `/etc/os-release`'s `ID=`, or the special-cased
`"proxmox"` — see `app.ssh.facts`'s `FACTS_COMMAND`).

Each badge draws a distribution's *real* mark — not a hand-drawn
approximation — from the icon artwork shipped in
`app/web/static/img/os/*.svg`. Those files are pulled as-is from Simple
Icons (https://simpleicons.org, MIT-licensed at the repo level; the
project's FAQ addresses redistributing marks this way for identification
purposes: https://github.com/simple-icons/simple-icons#legal-side-notes).
Each SVG is a single monochrome `<path>` on a 24x24 grid — this module
extracts that path, recolors it white, and scales/centers it inside the
20x20 badge circle already drawn by `partials/_os_badge.html`. The mark
itself (and each project's name) remains that project's own trademark;
using it here is nominative use — identifying whose OS a machine runs,
not implying endorsement.

Covers the distributions this app's users are most likely to actually run
(Debian/Ubuntu-family first, since that's what this app targets, plus
Proxmox VE and the other common general-purpose distros) — falling back
to initials-only for the long tail (including the handful with no Simple
Icons entry of their own, e.g. Devuan, KDE neon), and a generic Tux badge
for anything else entirely, so every machine gets *some* badge rather
than a blank space or a broken image.

To add a distribution: drop `<slug>.svg` (a Simple Icons file, or any
single-path 24x24 SVG) into `app/web/static/img/os/`, then add an entry
to `_BADGES` below via `_badge(..., icon="<slug>.svg")`.

Rendered by `partials/_os_badge.html` (an inline `<svg>`, matching this
app's "no external icon fonts/images, CSP-safe" convention elsewhere —
see `macros/charts.html`'s own docstring for the same reasoning). The
`<g>` returned by `glyph` is placed inside a 20x20 viewBox circle already
drawn by that macro — built here from files this module controls, never
from anything a machine reports, so the macro's `| safe` on it carries no
injection risk.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_ICON_DIR = Path(__file__).resolve().parent / "static" / "img" / "os"

# Simple Icons ships each mark as a single <path> on a 0 0 24 24 grid with
# no fill set (so it renders black by default). This scales that 24x24
# path down and centers it inside the badge's 20x20 circle, leaving a
# small margin, and recolors it white to sit on the badge's brand-color
# background.
_ICON_SCALE = 14 / 24
_ICON_OFFSET = (20 - 24 * _ICON_SCALE) / 2

_PATH_D_RE = re.compile(r'<path[^>]*\sd="([^"]+)"')


@lru_cache
def _load_icon_glyph(filename: str) -> str:
    """Read one `<path>` out of `app/web/static/img/os/<filename>` and
    return it as ready-to-inline `<g>` markup (see module docstring)."""
    svg = (_ICON_DIR / filename).read_text(encoding="utf-8")
    match = _PATH_D_RE.search(svg)
    if match is None:
        raise ValueError(f"no <path d=...> found in app/web/static/img/os/{filename}")
    return (
        f'<g fill="#fff" transform="translate({_ICON_OFFSET:.3f},{_ICON_OFFSET:.3f}) '
        f'scale({_ICON_SCALE:.4f})"><path d="{match.group(1)}"/></g>'
    )


@dataclass(frozen=True)
class OsBadge:
    label: str  # Full display name, used as the badge's tooltip/alt text.
    color: str  # Background color — each distribution's own brand color
    # where there is a well-known one, otherwise a neutral pick.
    initials: str = ""  # Shown when there's no `icon` artwork for this OS.
    glyph: str = ""  # Raw inner SVG markup (see module docstring); empty
    # means "fall back to `initials`" — set by `_badge` below.


def _badge(label: str, color: str, *, initials: str = "", icon: str = "") -> OsBadge:
    return OsBadge(
        label=label,
        color=color,
        initials=initials or label[:2],
        glyph=_load_icon_glyph(icon) if icon else "",
    )


_BADGES: dict[str, OsBadge] = {
    # --- Debian and its derivatives ---
    "debian": _badge("Debian", "#a80030", icon="debian.svg"),
    "kali": _badge("Kali Linux", "#557c94", icon="kali.svg"),
    "devuan": _badge("Devuan", "#3f51b5"),  # no Simple Icons mark — initials
    "mx": _badge("MX Linux", "#3d3d3d", icon="mx.svg"),
    "deepin": _badge("Deepin", "#0050ff", icon="deepin.svg"),
    # --- Ubuntu and its derivatives ---
    "ubuntu": _badge("Ubuntu", "#e95420", icon="ubuntu.svg"),
    "pop": _badge("Pop!_OS", "#48b9c7", icon="pop.svg"),
    "elementary": _badge("elementary OS", "#64baff", icon="elementary.svg"),
    "zorin": _badge("Zorin OS", "#0cc1f3", icon="zorin.svg"),
    "neon": _badge("KDE neon", "#1d99f3"),  # no Simple Icons mark — initials
    "linuxmint": _badge("Linux Mint", "#87cf3e", icon="linuxmint.svg"),
    "proxmox": _badge("Proxmox VE", "#e57000", icon="proxmox.svg"),
    "arch": _badge("Arch Linux", "#1793d1", icon="arch.svg"),
    "manjaro": _badge("Manjaro", "#35bf5c", icon="manjaro.svg"),
    # Raspberry Pi OS has no mark of its own in Simple Icons — the
    # Raspberry Pi Foundation's own logo is the closest real mark available.
    "raspbian": _badge("Raspberry Pi OS", "#c51a4a", icon="raspbian.svg"),
    # --- Everything else this app is likely to see ---
    "fedora": _badge("Fedora", "#294172", icon="fedora.svg"),
    "rhel": _badge("RHEL", "#ee0000", icon="rhel.svg"),
    "centos": _badge("CentOS", "#932279", icon="centos.svg"),
    "rocky": _badge("Rocky Linux", "#10b981", icon="rocky.svg"),
    "almalinux": _badge("AlmaLinux", "#0057b8", icon="almalinux.svg"),
    "opensuse": _badge("openSUSE", "#73ba25", icon="opensuse.svg"),
    "opensuse-leap": _badge("openSUSE Leap", "#73ba25", icon="opensuse.svg"),
    "opensuse-tumbleweed": _badge("openSUSE Tumbleweed", "#73ba25", icon="opensuse.svg"),
}

# Anything else Linux-based (or unrecognized) — still a badge, not a blank
# space or a broken image. Simple Icons' generic "Linux" mark is Tux.
FALLBACK_BADGE = _badge("Linux", "#6b7280", initials="Li", icon="linux.svg")


def badge_for(os_id: str | None) -> OsBadge:
    if not os_id:
        return FALLBACK_BADGE
    return _BADGES.get(os_id.strip().lower(), FALLBACK_BADGE)
