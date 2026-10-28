"""Compose stacks debcontrol deploys itself (`DockerStack`): checking what
a person entered, turning a stored stack into its deploy script, the
versions it keeps to roll back to, and the webhook that deploys a Git
stack when its repository changes.

**Deploy keys.** An SSH repository is reached with a deploy key: made
here (Ed25519) or pasted, stored encrypted like the token, and only its
public half is ever shown again. The repository host's key is pinned:
pasted known_hosts lines, or the key seen on the first connection, which
every later connection must match (`git_known_hosts`).

**The webhook token** is shown once, when it is made, and stored only as
its SHA-256 (`webhook_token_hash`), like an API token: the URL
`/hooks/docker/<token>` is the whole credential, and whoever has it can
do exactly one thing — have the stack pulled from its own, configured
repository and deployed. It cannot change what is deployed from where.
"""

from __future__ import annotations

import difflib
import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass, field

import yaml
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decrypt_secret, encrypt_secret
from app.db.models.docker import DockerStack, DockerStackVersion, StackSource
from app.services.docker_gate import GATES, normalize_gate
from app.ssh.docker_cli import DockerCommandError, is_project_name_valid
from app.ssh.docker_compose import (
    MAX_COMPOSE_OVERRIDES,
    MAX_FILE_BYTES,
    GitSource,
    StackFiles,
    build_stack_check_script,
    build_stack_script,
    is_branch_valid,
    is_repository_url_valid,
    is_ssh_git_url_valid,
    normalize_compose_path,
    normalize_known_hosts,
    normalize_stack_directory,
)

WEBHOOK_PREFIX = "/hooks/docker/"
DEFAULT_BRANCH = "main"
DEFAULT_COMPOSE_PATH = "compose.yaml"
# Deployed versions kept per stack (when it keeps a history).
HISTORY_LIMIT = 20
_MAX_KEY_BYTES = 16 * 1024


def generate_ssh_key(comment: str) -> tuple[str, str]:
    """A new Ed25519 deploy key: (OpenSSH private key, public key line)."""
    key = ed25519.Ed25519PrivateKey.generate()
    return _serialize_key(key, comment)


def _serialize_key(
    key: ed25519.Ed25519PrivateKey | ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey,
    comment: str,
) -> tuple[str, str]:
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode()
    public = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode()
    return private, f"{public} {comment}"[:1024]


def load_ssh_key(text: str, comment: str) -> tuple[str, str] | None:
    """A pasted private key (OpenSSH or PEM, no passphrase), normalized to
    OpenSSH: (private key, public key line); None when it isn't one."""
    data = text.strip().replace("\r\n", "\n").encode()
    if not data or len(data) > _MAX_KEY_BYTES:
        return None
    for loader in (serialization.load_ssh_private_key, serialization.load_pem_private_key):
        try:
            key = loader(data, password=None)
        except (ValueError, TypeError, UnsupportedAlgorithm):
            continue
        if isinstance(key, ed25519.Ed25519PrivateKey | ec.EllipticCurvePrivateKey):
            return _serialize_key(key, comment)
        if isinstance(key, rsa.RSAPrivateKey) and key.key_size >= 2048:
            return _serialize_key(key, comment)
        return None
    return None


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_webhook_token() -> tuple[str, str]:
    """(token, its hash)."""
    token = secrets.token_urlsafe(32)
    return token, hash_token(token)


async def find_by_webhook(db: AsyncSession, token: str) -> DockerStack | None:
    if not token or len(token) > 128:
        return None
    digest = hash_token(token)
    result = await db.execute(select(DockerStack).where(DockerStack.webhook_token_hash == digest))
    stack = result.scalar_one_or_none()
    # The lookup is by hash already; compared again in constant time anyway.
    if stack is None or not hmac.compare_digest(stack.webhook_token_hash or "", digest):
        return None
    return stack


async def list_stacks(db: AsyncSession, machine_id: uuid.UUID) -> list[DockerStack]:
    result = await db.execute(
        select(DockerStack).where(DockerStack.machine_id == machine_id).order_by(DockerStack.name)
    )
    return list(result.scalars().all())


async def get_stack(
    db: AsyncSession, machine_id: uuid.UUID, stack_id: uuid.UUID
) -> DockerStack | None:
    stack = await db.get(DockerStack, stack_id, populate_existing=True)
    return stack if stack is not None and stack.machine_id == machine_id else None


async def directory_taken(db: AsyncSession, machine_id: uuid.UUID, directory: str) -> bool:
    """Another stack of the machine already uses this chosen directory."""
    if not directory:
        return False
    query = select(DockerStack.id).where(
        DockerStack.machine_id == machine_id, DockerStack.directory == directory
    )
    return (await db.execute(query.limit(1))).first() is not None


async def name_taken(
    db: AsyncSession, machine_id: uuid.UUID, name: str, exclude: uuid.UUID | None = None
) -> bool:
    query = select(DockerStack.id).where(
        DockerStack.machine_id == machine_id, DockerStack.name == name
    )
    if exclude is not None:
        query = query.where(DockerStack.id != exclude)
    return (await db.execute(query.limit(1))).first() is not None


def validate_compose(content: str) -> None:
    """A YAML mapping with a `services` section — the rest is for
    `docker compose config` on the machine to judge."""
    if not content.strip():
        raise DockerCommandError("The compose file is empty.")
    if len(content.encode()) > MAX_FILE_BYTES:
        raise DockerCommandError("The compose file is too large.")
    try:
        parsed = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise DockerCommandError(f"The compose file is not valid YAML: {exc}") from exc
    if not isinstance(parsed, dict) or not isinstance(parsed.get("services"), dict):
        raise DockerCommandError("The compose file needs a \"services\" section.")


GENERATE_KEY = "generate"


def _host_of(url: str | None) -> str:
    """The server part of a repository address (HTTPS or SSH)."""
    if not url:
        return ""
    if "://" in url:
        return url.split("://", 1)[1].split("/", 1)[0].rsplit("@", 1)[-1].lower()
    return url.split(":", 1)[0].rsplit("@", 1)[-1].lower()


@dataclass
class StackForm:
    """What the stack form (or the API) sends, checked."""

    name: str
    source: str
    compose: str = ""
    env: str | None = None
    git_url: str = ""
    git_branch: str = DEFAULT_BRANCH
    git_compose_path: str = DEFAULT_COMPOSE_PATH
    # None = keep the stored token; "" = remove it.
    git_token: str | None = None
    auto_sync: bool = False
    # Where the files go on the machine, chosen once when the stack is
    # made: "" = the default directory; None = keep what is stored.
    directory: str | None = None
    # More compose files from the repository (overrides), in order.
    git_compose_overrides: list[str] = field(default_factory=list)
    # None = keep the stored deploy key; "" = remove it; GENERATE = make a
    # new one; anything else = a pasted private key.
    git_ssh_key: str | None = None
    # None = keep the stored host keys; "" = forget them (recorded again on
    # the next connection); else known_hosts lines.
    git_known_hosts: str | None = None
    keep_history: bool = False
    auto_rollback: bool = False
    vulnerability_gate: str = "off"
    # Set by `validate` when the key was made or pasted: (private, public).
    new_ssh_key: tuple[str, str] | None = None
    errors: list[str] = field(default_factory=list)

    def validate(self, stored: DockerStack | None = None) -> list[str]:
        """`stored`: the stack being edited (a kept deploy key counts)."""
        errors: list[str] = []
        self.name = self.name.strip().lower()
        if not is_project_name_valid(self.name):
            errors.append("docker.stack.error.name")
        if self.source not in (StackSource.EDITOR, StackSource.GIT):
            errors.append("docker.stack.error.source")
        if self.env is not None and len(self.env.encode()) > MAX_FILE_BYTES:
            errors.append("docker.stack.error.env")
        if self.directory is not None:
            directory = normalize_stack_directory(self.directory)
            if directory is None:
                errors.append("docker.stack.error.directory")
            else:
                self.directory = directory
        if self.source == StackSource.EDITOR:
            try:
                validate_compose(self.compose)
            except DockerCommandError:
                errors.append("docker.stack.error.compose")
        elif self.source == StackSource.GIT:
            self.git_url = self.git_url.strip()
            self.git_branch = self.git_branch.strip() or DEFAULT_BRANCH
            path = normalize_compose_path(self.git_compose_path.strip() or DEFAULT_COMPOSE_PATH)
            if not is_repository_url_valid(self.git_url):
                errors.append("docker.stack.error.git_url")
            if not is_branch_valid(self.git_branch):
                errors.append("docker.stack.error.git_branch")
            if path is None:
                errors.append("docker.stack.error.git_path")
            else:
                self.git_compose_path = path
            if self.git_token is not None and any(c in self.git_token for c in "\n\r\0"):
                errors.append("docker.stack.error.git_token")
            overrides = [p.strip() for p in self.git_compose_overrides if p.strip()]
            normalized = [normalize_compose_path(p) for p in overrides]
            if len(overrides) > MAX_COMPOSE_OVERRIDES or any(p is None for p in normalized):
                errors.append("docker.stack.error.git_overrides")
            else:
                self.git_compose_overrides = [p for p in normalized if p is not None]
            errors += self._validate_ssh(stored)
        if self.vulnerability_gate not in GATES:
            errors.append("docker.stack.error.gate")
        self.errors = errors
        return errors

    def _validate_ssh(self, stored: DockerStack | None) -> list[str]:
        errors: list[str] = []
        comment = f"debcontrol-{self.name or 'stack'}"
        if self.git_ssh_key == GENERATE_KEY:
            self.new_ssh_key = generate_ssh_key(comment)
        elif self.git_ssh_key:
            self.new_ssh_key = load_ssh_key(self.git_ssh_key, comment)
            if self.new_ssh_key is None:
                errors.append("docker.stack.error.git_ssh_key_invalid")
        if self.git_known_hosts:
            known = normalize_known_hosts(self.git_known_hosts)
            if known is None:
                errors.append("docker.stack.error.git_known_hosts")
            else:
                self.git_known_hosts = known
        has_key = self.new_ssh_key is not None or (
            self.git_ssh_key is None
            and stored is not None
            and stored.git_ssh_key_encrypted is not None
        )
        if is_ssh_git_url_valid(self.git_url) and not has_key and not errors:
            errors.append("docker.stack.error.git_ssh_key_missing")
        return errors

    def apply(self, stack: DockerStack) -> None:
        """Copy onto `stack` (call `validate` first)."""
        stack.name = self.name
        stack.source = self.source
        stack.keep_history = self.keep_history
        stack.auto_rollback = self.auto_rollback
        stack.vulnerability_gate = normalize_gate(self.vulnerability_gate)
        if self.directory is not None:
            stack.directory = self.directory or None
        if self.env is not None:
            stack.env_encrypted = encrypt_secret(self.env) if self.env.strip() else None
        if self.source == StackSource.EDITOR:
            stack.compose_content = self.compose
            stack.git_url = stack.git_branch = stack.git_compose_path = None
            stack.git_token_encrypted = None
            stack.git_compose_overrides = None
            stack.git_ssh_key_encrypted = stack.git_ssh_public_key = None
            stack.git_known_hosts = None
            stack.auto_sync = False
        else:
            if self.git_known_hosts is None and _host_of(stack.git_url) != _host_of(self.git_url):
                # Another server: its key gets recorded (or pasted) anew.
                stack.git_known_hosts = None
            elif self.git_known_hosts is not None:
                stack.git_known_hosts = self.git_known_hosts or None
            if self.new_ssh_key is not None:
                stack.git_ssh_key_encrypted = encrypt_secret(self.new_ssh_key[0])
                stack.git_ssh_public_key = self.new_ssh_key[1]
            elif self.git_ssh_key == "":
                stack.git_ssh_key_encrypted = stack.git_ssh_public_key = None
            stack.git_compose_overrides = list(self.git_compose_overrides) or None
            stack.git_url = self.git_url
            stack.git_branch = self.git_branch
            stack.git_compose_path = self.git_compose_path
            if self.git_token is not None:
                token = self.git_token.strip()
                stack.git_token_encrypted = encrypt_secret(token) if token else None
            stack.auto_sync = self.auto_sync


def env_text(stack: DockerStack) -> str:
    return decrypt_secret(stack.env_encrypted) if stack.env_encrypted else ""


def git_source(stack: DockerStack, *, commit: str = "") -> GitSource:
    if stack.source != StackSource.GIT or not stack.git_url:
        raise DockerCommandError("This stack does not come from Git.")
    ssh = is_ssh_git_url_valid(stack.git_url)
    token = (
        decrypt_secret(stack.git_token_encrypted)
        if stack.git_token_encrypted and not ssh
        else ""
    )
    key = decrypt_secret(stack.git_ssh_key_encrypted) if stack.git_ssh_key_encrypted and ssh else ""
    return GitSource(
        url=stack.git_url,
        branch=stack.git_branch or DEFAULT_BRANCH,
        compose_path=stack.git_compose_path or DEFAULT_COMPOSE_PATH,
        token=token,
        overrides=tuple(stack.git_compose_overrides or ()),
        ssh_key=key,
        known_hosts=stack.git_known_hosts or "",
        commit=commit,
    )


def stack_files(stack: DockerStack, *, commit: str = "") -> StackFiles:
    """The stack as stored (a Git stack at `commit` when given)."""
    directory = stack.directory or ""
    if stack.source == StackSource.GIT:
        return StackFiles(
            stack.name, env=env_text(stack), git=git_source(stack, commit=commit),
            directory=directory,
        )
    return StackFiles(
        stack.name, compose=stack.compose_content or "", env=env_text(stack), directory=directory
    )


def previous_files(stack: DockerStack) -> StackFiles | None:
    """What was deployed last (successfully), to put back when a deploy
    goes wrong; None when that isn't known (never deployed, or last
    deployed before 0.124.0)."""
    if stack.deployed_hash is None:
        return None
    if stack.deployed_env_encrypted is None and stack.deployed_compose is None and (
        stack.source == StackSource.EDITOR or stack.env_encrypted is not None
    ):
        # Deployed before 0.124.0: which .env went with it is not known.
        return None
    env = decrypt_secret(stack.deployed_env_encrypted) if stack.deployed_env_encrypted else ""
    directory = stack.directory or ""
    if stack.source == StackSource.GIT:
        if not stack.deployed_commit:
            return None
        source = git_source(stack, commit=stack.deployed_commit)
        return StackFiles(stack.name, env=env, git=source, directory=directory)
    if stack.deployed_compose is None:
        return None
    return StackFiles(stack.name, compose=stack.deployed_compose, env=env, directory=directory)


def content_hash(stack: DockerStack) -> str:
    """What "deployed as stored" is checked against: the compose file (for
    a Git stack, its source settings) plus the `.env`."""
    digest = hashlib.sha256()
    if stack.source == StackSource.EDITOR:
        digest.update((stack.compose_content or "").encode())
    else:
        source = f"{stack.git_url}\n{stack.git_branch}\n{stack.git_compose_path}"
        if stack.git_compose_overrides:
            # Only when set, so stacks from before overrides keep their hash.
            source += "\n" + "\n".join(stack.git_compose_overrides)
        digest.update(source.encode())
    digest.update(b"\0")
    digest.update(env_text(stack).encode())
    return digest.hexdigest()


def deploy_script(
    stack: DockerStack,
    *,
    pull: bool = True,
    commit: str = "",
    up: bool = True,
    report_images: bool = False,
) -> str:
    """The job script deploying `stack` as stored — carries its secrets,
    so only ever sent on standard input (`app.ssh.detached_jobs`). With
    auto-rollback on, it waits for the containers after `up` and puts the
    previous version back when they don't come up."""
    return build_stack_script(
        stack_files(stack, commit=commit),
        pull=pull,
        up=up,
        report_images=report_images,
        health=stack.auto_rollback,
        previous=previous_files(stack) if stack.auto_rollback else None,
    )


def check_script(stack: DockerStack) -> str:
    """The check before a deploy (`build_stack_check_script`)."""
    files = stack_files(stack)
    if stack.source == StackSource.GIT:
        return build_stack_check_script(files, deployed_commit=stack.deployed_commit or "")
    return build_stack_check_script(files, diff=compose_diff(stack))


def _env_keys(text: str) -> dict[str, str]:
    keys: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key, _, value = stripped.partition("=")
            keys[key.removeprefix("export ").strip()] = value
    return keys


def env_changes(old: str, new: str) -> list[str]:
    """What changed in a `.env`, by variable name only — values are secret."""
    before, after = _env_keys(old), _env_keys(new)
    lines = [f"+ {key}" for key in sorted(after.keys() - before.keys())]
    lines += [f"- {key}" for key in sorted(before.keys() - after.keys())]
    lines += [
        f"~ {key}" for key in sorted(before.keys() & after.keys()) if before[key] != after[key]
    ]
    return lines


def compose_diff(stack: DockerStack) -> str:
    """For a stack written in debcontrol: the compose file as stored against
    the one deployed, and the `.env` variables that changed (names only)."""
    if stack.deployed_hash is None:
        return "Not deployed yet: everything is new."
    if stack.deployed_compose is None:
        return "The deployed version is not known (deployed before 0.124.0)."
    deployed_env = (
        decrypt_secret(stack.deployed_env_encrypted) if stack.deployed_env_encrypted else ""
    )
    diff = list(
        difflib.unified_diff(
            stack.deployed_compose.splitlines(),
            (stack.compose_content or "").splitlines(),
            "compose.yaml (deployed)",
            "compose.yaml (saved)",
            lineterm="",
        )
    )
    env = env_changes(deployed_env, env_text(stack))
    if env:
        diff += ["", ".env (names only):", *env]
    return "\n".join(diff) or "No changes against the deployed version."


async def record_deployed(
    db: AsyncSession, stack: DockerStack, *, commit: str | None, deployed_by: str | None
) -> None:
    """After a successful deploy: what is on the machine now and, when the
    stack keeps a history, a new version (the oldest beyond
    `HISTORY_LIMIT` go). Does not commit."""
    stack.deployed_commit = commit or (
        stack.deployed_commit if stack.source == StackSource.GIT else None
    )
    stack.deployed_hash = content_hash(stack)
    stack.deployed_compose = stack.compose_content if stack.source == StackSource.EDITOR else None
    stack.deployed_env_encrypted = stack.env_encrypted
    if not stack.keep_history:
        return
    db.add(
        DockerStackVersion(
            stack_id=stack.id,
            source=stack.source,
            compose_content=stack.deployed_compose,
            env_encrypted=stack.env_encrypted,
            git_url=stack.git_url,
            git_branch=stack.git_branch,
            git_compose_path=stack.git_compose_path,
            git_compose_overrides=list(stack.git_compose_overrides or []) or None,
            commit=stack.deployed_commit,
            content_hash=stack.deployed_hash,
            deployed_by=deployed_by,
        )
    )
    await db.flush()
    keep = (
        select(DockerStackVersion.id)
        .where(DockerStackVersion.stack_id == stack.id)
        .order_by(DockerStackVersion.created_at.desc(), DockerStackVersion.id.desc())
        .limit(HISTORY_LIMIT)
    )
    await db.execute(
        delete(DockerStackVersion)
        .where(DockerStackVersion.stack_id == stack.id, DockerStackVersion.id.not_in(keep))
        .execution_options(synchronize_session=False)
    )


async def list_versions(db: AsyncSession, stack_id: uuid.UUID) -> list[DockerStackVersion]:
    result = await db.execute(
        select(DockerStackVersion)
        .where(DockerStackVersion.stack_id == stack_id)
        .order_by(DockerStackVersion.created_at.desc(), DockerStackVersion.id.desc())
        .limit(HISTORY_LIMIT)
    )
    return list(result.scalars().all())


async def get_version(
    db: AsyncSession, stack: DockerStack, version_id: uuid.UUID
) -> DockerStackVersion | None:
    version = await db.get(DockerStackVersion, version_id)
    return version if version is not None and version.stack_id == stack.id else None


def restore_version(stack: DockerStack, version: DockerStackVersion) -> str:
    """Make `version` the stack's stored settings again, for a rollback;
    returns the commit to deploy ("" for a stack written in debcontrol).
    Rolling a Git stack back turns auto-sync off, or the next check would
    deploy the branch's newest commit again right away."""
    stack.env_encrypted = version.env_encrypted
    if version.source == StackSource.EDITOR:
        stack.source = StackSource.EDITOR
        stack.compose_content = version.compose_content or ""
        return ""
    stack.source = StackSource.GIT
    if _host_of(stack.git_url) != _host_of(version.git_url):
        stack.git_known_hosts = None
    stack.git_url = version.git_url
    stack.git_branch = version.git_branch
    stack.git_compose_path = version.git_compose_path
    stack.git_compose_overrides = version.git_compose_overrides
    stack.auto_sync = False
    return version.commit or ""


def version_diff(stack: DockerStack, version: DockerStackVersion) -> str:
    """A version written in debcontrol against the stack as stored now."""
    if version.source != StackSource.EDITOR:
        return ""
    diff = difflib.unified_diff(
        (version.compose_content or "").splitlines(),
        (stack.compose_content or "").splitlines() if stack.source == StackSource.EDITOR else [],
        "compose.yaml (this version)",
        "compose.yaml (saved now)",
        lineterm="",
    )
    old_env = decrypt_secret(version.env_encrypted) if version.env_encrypted else ""
    lines = list(diff)
    env = env_changes(old_env, env_text(stack))
    if env:
        lines += ["", ".env (names only):", *env]
    return "\n".join(lines)


def is_changed(stack: DockerStack) -> bool:
    """Stored settings differ from what was deployed last."""
    return stack.deployed_hash is not None and stack.deployed_hash != content_hash(stack)
