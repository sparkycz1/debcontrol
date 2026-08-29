"""TOTP (RFC 6238) two-factor authentication — enrollment and verification.

Available to `local` and `ldap` accounts (see `app.db.models.user`); not to
`oidc` accounts, since the provider's own login already handles its own MFA
(if any) for those.

The secret (`User.totp_secret_encrypted`) is encrypted at rest with
`app.core.security`, the same as SSH passwords — it's a long-lived shared
secret capable of generating valid codes forever, effectively a password.
Recovery codes are hashed instead (`app.auth.security.hash_password`), since
they're single-use and only need to be *checked*, never displayed again.
"""

from __future__ import annotations

import secrets

import pyotp
import qrcode
import qrcode.image.svg

_ISSUER = "debcontrol"
# One step of drift either way (±30s) — enough slack for clocks that are a
# little off without meaningfully widening the guessing window.
_VALID_WINDOW = 1
RECOVERY_CODE_COUNT = 8


def generate_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str) -> str:
    """`otpauth://` URI for an authenticator app to scan — see `qr_code_svg`."""
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=_ISSUER)


def qr_code_svg(uri: str) -> str:
    """Render `uri` as an inline SVG `<svg>...</svg>` string — embedded
    directly in the enrollment page rather than as an `<img>`, so it needs
    no `data:` URI and nothing served through `img-src` in the CSP."""
    image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    return image.to_string(encoding="unicode")


def verify_code(secret: str, code: str) -> bool:
    code = code.strip()
    if not code:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=_VALID_WINDOW)


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """Plaintext codes to show the user exactly once at enrollment — the
    caller is responsible for hashing and storing them
    (`app.db.models.totp_recovery_code.TotpRecoveryCode.code_hash`)."""
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(5)  # 10 hex chars, 40 bits — single-use, low-volume.
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes
