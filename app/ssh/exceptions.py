"""Exceptions for the SSH layer."""

from __future__ import annotations


class SSHConnectionError(Exception):
    """Generic SSH connection failure (network, auth, timeout, ...)."""


class HostKeyError(SSHConnectionError):
    """Base class for problems verifying the server's host key."""


class UnknownHostKeyError(HostKeyError):
    """The machine doesn't have a pinned (confirmed) SSH host key fingerprint yet."""


class HostKeyMismatchError(HostKeyError):
    """The server presented a different key than the one pinned — possible MITM."""

    def __init__(self, message: str, *, presented_fingerprint: str | None = None) -> None:
        super().__init__(message)
        # What the server showed instead — kept so the change can be
        # reported, and accepted by an operator who verified it.
        self.presented_fingerprint = presented_fingerprint
