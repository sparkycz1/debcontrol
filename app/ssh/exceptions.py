"""Výjimky pro SSH vrstvu."""

from __future__ import annotations


class SSHConnectionError(Exception):
    """Obecná chyba při navazování SSH spojení (síť, autentizace, timeout, ...)."""


class HostKeyError(SSHConnectionError):
    """Nadtřída pro problémy s ověřením host klíče serveru."""


class UnknownHostKeyError(HostKeyError):
    """Stroj ještě nemá připnutý (potvrzený) otisk SSH host klíče."""


class HostKeyMismatchError(HostKeyError):
    """Server prezentoval jiný klíč, než jaký má stroj připnutý — možný MITM."""
