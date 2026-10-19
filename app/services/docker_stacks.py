"""Compose stacks debcontrol deploys itself (`DockerStack`): checking what
a person entered, turning a stored stack into its deploy script, and the
webhook that deploys a Git stack when its repository changes.

**The webhook token** is shown once, when it is made, and stored only as
its SHA-256 (`webhook_token_hash`), like an API token: the URL
`/hooks/docker/<token>` is the whole credential, and whoever has it can
do exactly one thing — have the stack pulled from its own, configured
repository and deployed. It cannot change what is deployed from where.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass, field

import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decrypt_secret, encrypt_secret
from app.db.models.docker import DockerStack, StackSource
from app.ssh.docker_cli import DockerCommandError, is_project_name_valid
from app.ssh.docker_compose import (
    MAX_FILE_BYTES,
    GitSource,
    build_deploy_script,
    is_branch_valid,
    is_git_url_valid,
    normalize_compose_path,
    normalize_stack_directory,
)

WEBHOOK_PREFIX = "/hooks/docker/"
DEFAULT_BRANCH = "main"
DEFAULT_COMPOSE_PATH = "compose.yaml"


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
    errors: list[str] = field(default_factory=list)

    def validate(self) -> list[str]:
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
            if not is_git_url_valid(self.git_url):
                errors.append("docker.stack.error.git_url")
            if not is_branch_valid(self.git_branch):
                errors.append("docker.stack.error.git_branch")
            if path is None:
                errors.append("docker.stack.error.git_path")
            else:
                self.git_compose_path = path
            if self.git_token is not None and any(c in self.git_token for c in "\n\r\0"):
                errors.append("docker.stack.error.git_token")
        self.errors = errors
        return errors

    def apply(self, stack: DockerStack) -> None:
        """Copy onto `stack` (call `validate` first)."""
        stack.name = self.name
        stack.source = self.source
        if self.directory is not None:
            stack.directory = self.directory or None
        if self.env is not None:
            stack.env_encrypted = encrypt_secret(self.env) if self.env.strip() else None
        if self.source == StackSource.EDITOR:
            stack.compose_content = self.compose
            stack.git_url = stack.git_branch = stack.git_compose_path = None
            stack.git_token_encrypted = None
            stack.auto_sync = False
        else:
            stack.git_url = self.git_url
            stack.git_branch = self.git_branch
            stack.git_compose_path = self.git_compose_path
            if self.git_token is not None:
                token = self.git_token.strip()
                stack.git_token_encrypted = encrypt_secret(token) if token else None
            stack.auto_sync = self.auto_sync


def env_text(stack: DockerStack) -> str:
    return decrypt_secret(stack.env_encrypted) if stack.env_encrypted else ""


def git_source(stack: DockerStack) -> GitSource:
    if stack.source != StackSource.GIT or not stack.git_url:
        raise DockerCommandError("This stack does not come from Git.")
    token = decrypt_secret(stack.git_token_encrypted) if stack.git_token_encrypted else ""
    return GitSource(
        url=stack.git_url,
        branch=stack.git_branch or DEFAULT_BRANCH,
        compose_path=stack.git_compose_path or DEFAULT_COMPOSE_PATH,
        token=token,
    )


def content_hash(stack: DockerStack) -> str:
    """What "deployed as stored" is checked against: the compose file (for
    a Git stack, its source settings) plus the `.env`."""
    digest = hashlib.sha256()
    if stack.source == StackSource.EDITOR:
        digest.update((stack.compose_content or "").encode())
    else:
        source = f"{stack.git_url}\n{stack.git_branch}\n{stack.git_compose_path}"
        digest.update(source.encode())
    digest.update(b"\0")
    digest.update(env_text(stack).encode())
    return digest.hexdigest()


def deploy_script(stack: DockerStack, *, pull: bool = True) -> str:
    """The job script deploying `stack` as stored — carries its secrets,
    so only ever sent on standard input (`app.ssh.detached_jobs`)."""
    env = env_text(stack)
    directory = stack.directory or ""
    if stack.source == StackSource.GIT:
        return build_deploy_script(
            stack.name, git=git_source(stack), env=env, pull=pull, directory=directory
        )
    return build_deploy_script(
        stack.name, compose=stack.compose_content or "", env=env, pull=pull, directory=directory
    )


def is_changed(stack: DockerStack) -> bool:
    """Stored settings differ from what was deployed last."""
    return stack.deployed_hash is not None and stack.deployed_hash != content_hash(stack)
