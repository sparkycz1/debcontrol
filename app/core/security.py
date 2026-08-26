"""Šifrování citlivých dat uložených v databázi (SSH hesla, privátní klíče).

Používáme Fernet (AES-128-CBC + HMAC, autentizované šifrování) z knihovny
`cryptography`. Klíč se NIKDY neukládá do DB ani do repa — jen v `ENCRYPTION_KEY`
v prostředí. Bez čtení autentizace (bez přihlášení) tato aplikace zatím není,
ale tajemství strojů (hesla/klíče k cizím serverům) chráníme šifrováním
od prvního commitu.

Pozn.: Toto NENÍ náhrada za autentizaci/autorizaci uživatelů aplikace — to
přidáme v další fázi. Řeší to jen ochranu dat "at rest" v Postgresu.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings


class DecryptionError(Exception):
    """Dešifrování selhalo — poškozená nebo zfalšovaná data, případně špatný klíč."""


def _fernet() -> Fernet:
    key = get_settings().encryption_key.get_secret_value()
    return Fernet(key.encode("utf-8"))


def encrypt_secret(plaintext: str) -> bytes:
    """Zašifruje citlivý řetězec (heslo, privátní klíč) pro uložení do DB."""
    return _fernet().encrypt(plaintext.encode("utf-8"))


def decrypt_secret(ciphertext: bytes) -> str:
    """Dešifruje hodnotu uloženou přes `encrypt_secret`."""
    try:
        return _fernet().decrypt(ciphertext).decode("utf-8")
    except InvalidToken as exc:
        raise DecryptionError("Nepodařilo se dešifrovat uložené tajemství.") from exc
