from __future__ import annotations

from app.web.os_logos import FALLBACK_BADGE, badge_for


def test_badge_for_known_distro():
    badge = badge_for("debian")
    assert badge.label == "Debian"
    assert badge.initials == "De"


def test_badge_for_is_case_insensitive():
    assert badge_for("Ubuntu") == badge_for("ubuntu")


def test_badge_for_proxmox_special_case():
    # See app.ssh.facts.FACTS_COMMAND's OS_ID gathering — "proxmox" isn't a
    # real /etc/os-release ID= value, it's synthesized by this app.
    badge = badge_for("proxmox")
    assert badge.label == "Proxmox VE"


def test_badge_for_none_is_the_fallback():
    assert badge_for(None) == FALLBACK_BADGE


def test_badge_for_unknown_distro_is_the_fallback():
    assert badge_for("some-obscure-distro") == FALLBACK_BADGE


def test_debian_family_shares_the_swirl_glyph():
    debian = badge_for("debian")
    kali = badge_for("kali")
    assert debian.glyph and debian.glyph == kali.glyph
    assert debian.color != kali.color  # same glyph, each its own brand color


def test_fallback_badge_has_a_glyph_not_just_initials():
    assert FALLBACK_BADGE.glyph != ""


def test_long_tail_distro_falls_back_to_initials_only():
    fedora = badge_for("fedora")
    assert fedora.glyph == ""
    assert fedora.initials == "Fe"
