"""Small colored badge icons shown next to a machine's name, keyed by
`Machine.os_id` (from `/etc/os-release`'s `ID=`, or the special-cased
`"proxmox"` — see `app.ssh.facts`'s `FACTS_COMMAND`).

Hand-drawn glyphs (plain SVG shapes — circles, arcs, polygons), each
evoking its distribution's real mark (Debian's swirl, Ubuntu's circle of
friends, Mint's shield, Arch's peaked "A", Raspberry Pi's berry cluster)
rather than an exact reproduction of the official artwork file — this
repo has no licensed copy of those to vendor (and no way to fetch one at
build time), so redrawing the shape by hand from scratch, in the same
brand color, is what's actually achievable here. Covers the distributions
this app's users are most likely to actually run (Debian/Ubuntu-family
first, since that's what this app targets, plus Proxmox VE and the other
common general-purpose distros) — falling back to initials-only for the
long tail, and a generic penguin glyph for anything else entirely, so
every machine gets *some* badge rather than a blank space or a broken
image. Drop an actual official SVG per distribution into
`app/web/static/img/os/` and wire it into `_BADGES` below instead, if
you'd rather use the real artwork than this module's approximations.

Rendered by `partials/_os_badge.html` (an inline `<svg>`, matching this
app's "no external icon fonts/images, CSP-safe" convention elsewhere —
see `macros/charts.html`'s own docstring for the same reasoning). `glyph`
is raw SVG markup placed inside a 20x20 viewBox circle already drawn by
that macro — trusted, hand-written content from this module only, never
derived from anything a machine reports, so the macro's `| safe` on it
carries no injection risk.
"""

from __future__ import annotations

from dataclasses import dataclass

# --- Reusable glyphs -----------------------------------------------------
# Each assumes a 20x20 viewBox with the badge's own circle already drawn
# (center 10,10 radius 10) and draws in white (`#fff`) on top of it.

_GLYPH_SWIRL = (
    '<path d="M14 6.5A5 5 0 1 0 14 13.5" stroke="#fff" stroke-width="1.4" '
    'fill="none" stroke-linecap="round"/>'
    '<path d="M12 8.5A2.6 2.6 0 1 0 12 11.5" stroke="#fff" stroke-width="1.2" '
    'fill="none" stroke-linecap="round"/>'
)  # Debian and its close derivatives — a simple two-turn spiral, evoking
# the swirl without reproducing it.

_GLYPH_ORBIT = (
    '<circle cx="10" cy="10" r="5.5" fill="none" stroke="#fff" stroke-width="0.8" opacity="0.55"/>'
    '<circle cx="10" cy="4.7" r="1.7" fill="#fff"/>'
    '<circle cx="14.8" cy="12.6" r="1.7" fill="#fff"/>'
    '<circle cx="5.2" cy="12.6" r="1.7" fill="#fff"/>'
)  # Ubuntu — three dots in orbit.

_GLYPH_SHIELD = (
    '<rect x="5.5" y="5" width="9" height="9" rx="1.5" '
    'fill="none" stroke="#fff" stroke-width="1.3"/>'
    '<circle cx="10" cy="9.5" r="1.6" fill="#fff"/>'
    '<path d="M8 11.5v1.3a2 2 0 0 0 4 0v-1.3" fill="none" stroke="#fff" stroke-width="1.3"/>'
)  # Linux Mint — a rounded square outline (the shield the wordmark sits in).

_GLYPH_DIAMOND = (
    '<polygon points="10,4 16,10 10,16 4,10" fill="none" stroke="#fff" stroke-width="1.4"/>'
    '<circle cx="10" cy="10" r="2" fill="#fff"/>'
)  # Proxmox VE — a diamond outline with a core dot (virtualization/cluster).

_GLYPH_PEAK = '<polygon points="10,4.5 16,15.5 4,15.5" fill="#fff"/>'
# Arch Linux — a simple upward peak (its logo is a stylized peaked "A").

_GLYPH_BERRY = (
    '<circle cx="10" cy="5.5" r="1.6" fill="#fff"/>'
    '<circle cx="6.7" cy="8.5" r="1.6" fill="#fff"/>'
    '<circle cx="13.3" cy="8.5" r="1.6" fill="#fff"/>'
    '<circle cx="8.3" cy="12.2" r="1.6" fill="#fff"/>'
    '<circle cx="11.7" cy="12.2" r="1.6" fill="#fff"/>'
)  # Raspberry Pi OS — a small cluster of "berries".

_GLYPH_PENGUIN = (
    '<ellipse cx="10" cy="12.5" rx="4" ry="5" fill="#fff"/>'
    '<circle cx="10" cy="6" r="3" fill="#fff"/>'
    '<ellipse cx="10" cy="13" rx="2" ry="3.4" fill="#6b7280"/>'
    '<circle cx="8.8" cy="5.3" r="0.5" fill="#374151"/>'
    '<circle cx="11.2" cy="5.3" r="0.5" fill="#374151"/>'
    '<polygon points="9.3,7 10.7,7 10,8.3" fill="#e0ab4a"/>'
)  # Generic fallback — a plain, original penguin silhouette (not a
# reproduction of Tux's specific character design), the same generic
# mascot association "Linux" already carries.


@dataclass(frozen=True)
class OsBadge:
    label: str  # Full display name, used as the badge's tooltip/alt text.
    color: str  # Background color — each distribution's own brand color
    # where there is a well-known one, otherwise a neutral pick.
    initials: str = ""  # Shown when there's no hand-drawn `glyph`.
    glyph: str = ""  # Raw inner SVG markup (see module docstring); empty
    # means "fall back to `initials`" — set by `_finish` below.


def _badge(label: str, color: str, *, initials: str = "", glyph: str = "") -> OsBadge:
    return OsBadge(label=label, color=color, initials=initials or label[:2], glyph=glyph)


_BADGES: dict[str, OsBadge] = {
    # --- Debian and its derivatives — the swirl glyph, each in its own color ---
    "debian": _badge("Debian", "#a80030", glyph=_GLYPH_SWIRL),
    "kali": _badge("Kali Linux", "#557c94", glyph=_GLYPH_SWIRL),
    "devuan": _badge("Devuan", "#3f51b5", glyph=_GLYPH_SWIRL),
    "mx": _badge("MX Linux", "#3d3d3d", glyph=_GLYPH_SWIRL),
    "deepin": _badge("Deepin", "#0050ff", glyph=_GLYPH_SWIRL),
    # --- Ubuntu and its derivatives — the orbit glyph ---
    "ubuntu": _badge("Ubuntu", "#e95420", glyph=_GLYPH_ORBIT),
    "pop": _badge("Pop!_OS", "#48b9c7", glyph=_GLYPH_ORBIT),
    "elementary": _badge("elementary OS", "#64baff", glyph=_GLYPH_ORBIT),
    "zorin": _badge("Zorin OS", "#0cc1f3", glyph=_GLYPH_ORBIT),
    "neon": _badge("KDE neon", "#1d99f3", glyph=_GLYPH_ORBIT),
    "linuxmint": _badge("Linux Mint", "#87cf3e", glyph=_GLYPH_SHIELD),
    "proxmox": _badge("Proxmox VE", "#e57000", glyph=_GLYPH_DIAMOND),
    "arch": _badge("Arch Linux", "#1793d1", glyph=_GLYPH_PEAK),
    "manjaro": _badge("Manjaro", "#35bf5c", glyph=_GLYPH_PEAK),
    "raspbian": _badge("Raspberry Pi OS", "#c51a4a", glyph=_GLYPH_BERRY),
    # --- Everything else this app is likely to see, initials-only ---
    "fedora": _badge("Fedora", "#294172"),
    "rhel": _badge("RHEL", "#ee0000"),
    "centos": _badge("CentOS", "#932279"),
    "rocky": _badge("Rocky Linux", "#10b981"),
    "almalinux": _badge("AlmaLinux", "#0057b8"),
    "opensuse": _badge("openSUSE", "#73ba25"),
    "opensuse-leap": _badge("openSUSE Leap", "#73ba25"),
    "opensuse-tumbleweed": _badge("openSUSE Tumbleweed", "#73ba25"),
}

# Anything else Linux-based (or unrecognized) — still a badge, not a blank
# space or a broken image.
FALLBACK_BADGE = _badge("Linux", "#6b7280", initials="Li", glyph=_GLYPH_PENGUIN)


def badge_for(os_id: str | None) -> OsBadge:
    if not os_id:
        return FALLBACK_BADGE
    return _BADGES.get(os_id.strip().lower(), FALLBACK_BADGE)
