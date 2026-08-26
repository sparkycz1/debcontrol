"""Ochrana proti CSRF pro formuláře (double-submit cookie).

Aplikace zatím nemá přihlašování / session, takže nejde postavit na tom.
Vzor: při GETu, který vykresluje formulář, se nastaví (pokud chybí) náhodná
cookie `csrftoken` a stejná hodnota se vloží jako skryté pole do formuláře.
Při POSTu se obě hodnoty musí shodovat — útočníkova cizí stránka cookie
uživatele přečíst ani nastavit nedokáže (SameSite=Strict, HttpOnly).

Použití v routeru, který vykresluje formulář:

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(request, "tpl.html", {"csrf_token": csrf_token, ...})
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response

Token musí být v `context` už PŘED vykreslením šablony (`TemplateResponse`
tělo vykreslí okamžitě v konstruktoru) — proto je rozdělené na "získej
hodnotu" a "ulož do cookie" místo jedné funkce nad hotovou odpovědí.
"""

from __future__ import annotations

import secrets

from fastapi import HTTPException, Request, Response, status

from app.core.config import get_settings

CSRF_COOKIE_NAME = "csrftoken"
CSRF_FORM_FIELD = "csrf_token"
_COOKIE_MAX_AGE_SECONDS = 60 * 60 * 8


def get_or_create_csrf_token(request: Request) -> tuple[str, str | None]:
    """Vrátí (token_pro_šablonu, hodnota_pro_novou_cookie_nebo_None).

    Druhý prvek je `None`, pokud klient už platnou cookie má — pak se nemá
    znovu nastavovat (zbytečně by se prodlužovala její platnost).
    """
    existing = request.cookies.get(CSRF_COOKIE_NAME)
    if existing:
        return existing, None
    new_token = secrets.token_urlsafe(32)
    return new_token, new_token


def set_csrf_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        CSRF_COOKIE_NAME,
        token,
        httponly=True,
        samesite="strict",
        secure=get_settings().is_production,
        max_age=_COOKIE_MAX_AGE_SECONDS,
    )


async def verify_csrf(request: Request) -> None:
    """FastAPI dependency — zařaď do každého stav měnícího (POST/PUT/DELETE) endpointu."""
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    form = await request.form()
    form_token = form.get(CSRF_FORM_FIELD)
    if (
        not cookie_token
        or not form_token
        or not secrets.compare_digest(str(form_token), cookie_token)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Neplatný nebo chybějící CSRF token — obnov stránku a zkus to znovu.",
        )
