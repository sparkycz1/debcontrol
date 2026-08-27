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
