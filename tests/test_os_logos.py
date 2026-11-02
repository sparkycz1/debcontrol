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


def test_debian_and_kali_have_their_own_distinct_logo_marks():
    debian = badge_for("debian")
    kali = badge_for("kali")
    assert debian.glyph and kali.glyph
    assert debian.glyph != kali.glyph  # each distro draws its own real mark
    assert debian.color != kali.color


def test_fallback_badge_has_a_glyph_not_just_initials():
    assert FALLBACK_BADGE.glyph != ""


def test_distro_with_a_real_logo_mark_uses_it_not_initials():
    fedora = badge_for("fedora")
    assert fedora.glyph != ""
    assert fedora.initials == "Fe"


def test_distro_with_no_upstream_mark_falls_back_to_initials_only():
    # Devuan and KDE neon have no Simple Icons entry of their own (see
    # app/web/os_logos.py) — initials-only, same as an unknown distro.
    devuan = badge_for("devuan")
    assert devuan.glyph == ""
    assert devuan.initials == "De"


def test_committed_sprite_is_up_to_date():
    """Regenerate with `uv run python -m app.web.os_logos`."""
    from pathlib import Path

    from app.web.os_logos import SPRITE_PATH, sprite_svg

    committed = Path("app/web/static", SPRITE_PATH).read_text(encoding="utf-8")
    assert committed == sprite_svg()


def test_every_badge_with_a_mark_has_its_symbol_in_the_sprite():
    from app.web.os_logos import _BADGES, sprite_svg

    sprite = sprite_svg()
    for badge in (*_BADGES.values(), FALLBACK_BADGE):
        if badge.glyph:
            assert f'<symbol id="{badge.symbol}"' in sprite


async def test_machine_list_references_the_sprite_instead_of_inlining_paths(
    client, db_session_factory
):
    from tests.test_onboarding import _make_machine

    await _make_machine(db_session_factory)
    response = await client.get("/machines")
    assert "img/os-badges.svg?v=" in response.text
    assert "<path d=" not in response.text.split('class="os-badge"', 1)[1][:600]
