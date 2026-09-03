"""WebAuthn/passkey registration and authentication — a second login
factor alongside TOTP (`app.auth.totp`), or in its place. Thin wrapper
around [py_webauthn](https://github.com/duo-labs/py_webauthn), which does
the actual cryptographic ceremony verification (attestation/assertion
signature checking); this module is just relying-party bookkeeping:
deriving the RP id/origin from the request, and shaping options/results
around `app.db.models.webauthn_credential.WebAuthnCredential`.

**RP id and origin are derived from the request, not configured** — same
"whatever domain this instance is actually reached at" reasoning
`app.auth.oidc`'s redirect URI already uses. WebAuthn requires the RP id
to be the domain itself (no scheme/port) and the origin to be the exact
scheme+host+port the browser's `navigator.credentials` call ran against;
getting either wrong fails the ceremony outright rather than degrading, so
there is no sensible static default to fall back to.

Available to `local` and `ldap` accounts only, same restriction as TOTP —
see `app.auth.totp`'s module docstring.
"""

from __future__ import annotations

import uuid

import webauthn
from fastapi import Request
from webauthn.authentication.verify_authentication_response import VerifiedAuthentication
from webauthn.helpers import parse_authentication_credential_json
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidJSONStructure,
    InvalidRegistrationResponse,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRequestOptions,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from webauthn.registration.verify_registration_response import VerifiedRegistration

from app.db.models.webauthn_credential import WebAuthnCredential

RP_NAME = "debcontrol"


class WebAuthnError(Exception):
    """A registration/authentication ceremony failed verification — bad
    signature, wrong challenge, wrong origin, replayed/cloned
    authenticator. Always carries a message safe to show the user."""


def rp_id_and_origin(request: Request) -> tuple[str, str]:
    """`(rp_id, origin)` for the request's own host — see module
    docstring. `request.url.hostname` is already the bare host (no port,
    no scheme), exactly what `rp_id` needs to be."""
    hostname = request.url.hostname
    if not hostname:
        raise WebAuthnError("Could not determine this server's hostname.")
    origin = f"{request.url.scheme}://{request.url.netloc}"
    return hostname, origin


def generate_registration(
    request: Request, *, user_id: uuid.UUID, username: str, existing: list[WebAuthnCredential]
) -> tuple[PublicKeyCredentialCreationOptions, bytes]:
    """Options for `navigator.credentials.create()`, plus the challenge to
    stash (in a short-lived signed cookie — see `app.auth.sessions`) until
    the browser's response comes back. `existing` is excluded so the same
    authenticator can't be registered twice."""
    rp_id, _origin = rp_id_and_origin(request)
    options = webauthn.generate_registration_options(
        rp_id=rp_id,
        rp_name=RP_NAME,
        user_id=user_id.bytes,
        user_name=username,
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=cred.credential_id) for cred in existing
        ],
        # No platform/cross-platform restriction — a laptop's Touch ID and
        # a USB security key are both fine. `preferred` (not `required`)
        # user verification: still request it (a PIN/biometric, not just
        # presence), but don't hard-fail registering an authenticator that
        # can't do it.
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    return options, options.challenge


def verify_registration(
    *, credential: str, expected_challenge: bytes, request: Request
) -> VerifiedRegistration:
    """Raises `WebAuthnError` on any verification failure. Returns the
    verified result — caller builds and stores the `WebAuthnCredential`
    row from it."""
    rp_id, origin = rp_id_and_origin(request)
    try:
        return webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
        )
    except InvalidRegistrationResponse as exc:
        raise WebAuthnError(f"Passkey registration failed: {exc}") from exc


def credential_id_from_authentication_json(credential: str) -> bytes:
    """The raw credential id out of a browser's `navigator.credentials.get()`
    response, parsed *before* verification — the caller needs it to look up
    which of the account's stored `WebAuthnCredential` rows (and which
    public key) to verify against; `verify_authentication` below doesn't
    select that for you, it just checks a signature against whichever
    `stored` you hand it."""
    try:
        return parse_authentication_credential_json(credential).raw_id
    except InvalidJSONStructure as exc:
        raise WebAuthnError(f"Passkey sign-in failed: {exc}") from exc


def generate_authentication(
    request: Request, *, credentials: list[WebAuthnCredential]
) -> tuple[PublicKeyCredentialRequestOptions, bytes]:
    """Options for `navigator.credentials.get()` against `credentials` (the
    pending login's own registered passkeys — never anyone else's)."""
    rp_id, _origin = rp_id_and_origin(request)
    options = webauthn.generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=cred.credential_id) for cred in credentials
        ],
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return options, options.challenge


def verify_authentication(
    *,
    credential: str,
    expected_challenge: bytes,
    request: Request,
    stored: WebAuthnCredential,
) -> VerifiedAuthentication:
    """Raises `WebAuthnError` on any verification failure, **including** a
    signature counter that didn't advance — the spec's own signal that
    this credential may have been cloned onto a second authenticator (see
    `WebAuthnCredential.sign_count`'s own docstring). Caller updates
    `stored.sign_count`/`last_used_at` after this returns successfully."""
    rp_id, origin = rp_id_and_origin(request)
    try:
        return webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=stored.public_key,
            credential_current_sign_count=stored.sign_count,
        )
    except InvalidAuthenticationResponse as exc:
        raise WebAuthnError(f"Passkey sign-in failed: {exc}") from exc
