"""LDAP bind authentication — "search then bind", the standard, directory-
agnostic pattern: a service account (configured in Settings) searches for the
user's DN by username, then a *second* connection binds as that DN with the
password just entered to actually check it. The user's own credentials are
never used for anything but that final bind.

`ldap3` is a synchronous library — every call here runs in a worker thread
(`asyncio.to_thread`) so it doesn't block the event loop.

TLS certificate verification (for `ldaps://` and STARTTLS alike) is on by
default and configurable — `AppSettings.ldap_tls_verify` — since `ldap3`
itself defaults to *no* verification at all when a `Server` isn't given an
explicit `Tls` object, which would otherwise make "secure by default" an
accident of remembering to pass one rather than an actual guarantee. Off
is meant for a directory whose certificate an admin already knows isn't
verifiable (self-signed, expired, wrong hostname) and still wants to use —
same trade-off a browser's "proceed anyway" click makes.
"""

from __future__ import annotations

import asyncio
import ssl

import ldap3
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

from app.core.security import decrypt_secret
from app.db.models.app_settings import AppSettings


class LdapUnavailableError(Exception):
    """The directory itself couldn't be reached or is misconfigured — as
    opposed to a plain wrong-password result. Callers show a distinct
    "the directory is unavailable" message rather than "invalid credentials"
    for this, since it isn't the user's fault and retrying with a different
    password won't help."""


def _authenticate_sync(
    *,
    server_uri: str,
    use_starttls: bool,
    bind_dn: str,
    bind_password: str,
    search_base: str,
    search_filter_template: str,
    username: str,
    password: str,
    timeout: int,
    tls_verify: bool,
) -> bool:
    use_ssl = server_uri.lower().startswith("ldaps://")
    # `ldap3.Server` defaults to *not* validating the certificate at all
    # (`Tls()`'s own default is `ssl.CERT_NONE`) whenever `tls=` isn't
    # given explicitly — always pass one, so verification is opt-out
    # (`ldap_tls_verify=False`), never an accidental opt-out by omission.
    # STARTTLS reuses the same `Tls` object via `start_tls()` below.
    tls = ldap3.Tls(validate=ssl.CERT_REQUIRED if tls_verify else ssl.CERT_NONE)
    server = ldap3.Server(server_uri, use_ssl=use_ssl, tls=tls, connect_timeout=timeout)

    try:
        with ldap3.Connection(
            server,
            user=bind_dn,
            password=bind_password,
            receive_timeout=timeout,
        ) as service_conn:
            if use_starttls:
                service_conn.start_tls()
            if not service_conn.bind():
                raise LdapUnavailableError(
                    f"Could not bind the service account: {service_conn.result}"
                )

            search_filter = search_filter_template.format(username=escape_filter_chars(username))
            service_conn.search(search_base, search_filter, attributes=[])
            if len(service_conn.entries) != 1:
                # Not found, or the filter matched more than one entry —
                # either way, there's no single DN to bind as.
                return False
            user_dn = service_conn.entries[0].entry_dn

        # A second, independent connection for the actual credential check —
        # deliberately not reusing/rebinding the service connection, so a
        # bug here can never leave that connection authenticated as the
        # service account when it should have failed as the user.
        with ldap3.Connection(
            server, user=user_dn, password=password, receive_timeout=timeout
        ) as user_conn:
            if use_starttls:
                user_conn.start_tls()
            return bool(user_conn.bind())
    except LDAPException as exc:
        raise LdapUnavailableError(str(exc)) from exc


async def authenticate(app_settings: AppSettings, username: str, password: str) -> bool:
    """True if `username`/`password` is a valid LDAP bind. Raises
    `LdapUnavailableError` if the directory can't be reached or Settings
    doesn't have enough configured to even try."""
    # A blank password is an "unauthenticated bind" in LDAP — many servers
    # accept it as trivially successful regardless of the DN, which would
    # otherwise let anyone in as any known username. Reject it outright
    # before ever attempting the user-bind step.
    if not password:
        return False
    if not app_settings.ldap_server_uri or not app_settings.ldap_user_search_base:
        raise LdapUnavailableError(
            "LDAP is not fully configured — set the server, bind DN, and search base in Settings."
        )

    bind_password = (
        decrypt_secret(app_settings.ldap_bind_password_encrypted)
        if app_settings.ldap_bind_password_encrypted
        else ""
    )

    return await asyncio.to_thread(
        _authenticate_sync,
        server_uri=app_settings.ldap_server_uri,
        use_starttls=app_settings.ldap_use_starttls,
        bind_dn=app_settings.ldap_bind_dn or "",
        bind_password=bind_password,
        search_base=app_settings.ldap_user_search_base,
        search_filter_template=app_settings.ldap_user_search_filter,
        username=username,
        password=password,
        timeout=app_settings.ldap_connect_timeout_seconds,
        tls_verify=app_settings.ldap_tls_verify,
    )
