"""Whole-application backup and restore from the web UI (Backup & restore)
and the REST API — everything the database holds, in one passphrase-
encrypted file, restorable onto this instance or a fresh one.

**What's in it**: every table (machines and their credentials, groups,
users and roles, scheduled tasks, notification rules, settings, the SSH
identity key, the audit log, history...), plus this instance's
`ENCRYPTION_KEY` so a restore onto an instance with a different key can
re-encrypt every stored secret (`*_encrypted` columns) under its own.
Nothing outside the database is needed: the SSH key lives in the database
too, and the data volume only holds a GeoIP cache that re-downloads.
`.env` itself is not included — the target instance keeps its own.

**Format** (`.dcbak`): `MAGIC`, a 16-byte scrypt salt and an 8-byte nonce
prefix, then the payload in chunks, each `flag (1) | length (4) |
AES-256-GCM ciphertext`. The flag (1 on the last chunk) is the chunk's
associated data, so a truncated or reordered file fails to decrypt
rather than restoring half a database. The payload is a ZIP with
`manifest.json` and one `tables/<name>.jsonl` (one JSON object per row).

**Restore** checks the passphrase (GCM authentication), the app, the
format and that the backup's database revision equals this instance's —
moving between versions means upgrading the backed-up instance (or this
one) first. Then, in one transaction, every table is emptied and refilled
from the file, secrets re-encrypted if the keys differ. Every session,
including the one doing the restore, is replaced by the backup's — the
caller signs everyone out.
"""

from __future__ import annotations

import base64
import enum
import io
import json
import os
import struct
import tempfile
import uuid
import zipfile
from collections.abc import Iterator
from datetime import UTC, date, datetime
from pathlib import Path
from typing import IO, Any

import sqlalchemy as sa
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from sqlalchemy.ext.asyncio import AsyncSession

import app.db.models  # noqa: F401 - every table registered on Base.metadata
from app.core.security import (
    DecryptionError,
    current_encryption_key,
    decrypt_secret_with_key,
    encrypt_secret_with_key,
)
from app.core.version import APP_VERSION
from app.db.base import Base

APP_NAME = "debcontrol"
FILE_EXTENSION = "dcbak"
MAGIC = b"DCBAK1\n"
FORMAT_VERSION = 1
MIN_PASSPHRASE_LENGTH = 12

_SALT_LENGTH = 16
_NONCE_PREFIX_LENGTH = 8
_CHUNK_SIZE = 1024 * 1024
_INSERT_BATCH = 500
# Not an app table: `alembic upgrade` owns it, and a restore requires the
# backup's revision to equal this instance's anyway.
_SKIPPED_TABLES = frozenset({"alembic_version"})


class BackupError(Exception):
    """A backup couldn't be made or restored; the message says why."""


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode("utf-8"))


def _encrypt_file(src: IO[bytes], dst: IO[bytes], passphrase: str) -> None:
    salt = os.urandom(_SALT_LENGTH)
    prefix = os.urandom(_NONCE_PREFIX_LENGTH)
    aead = AESGCM(_derive_key(passphrase, salt))
    dst.write(MAGIC + salt + prefix)
    counter = 0
    chunk = src.read(_CHUNK_SIZE)
    while True:
        following = src.read(_CHUNK_SIZE)
        flag = b"\x00" if following else b"\x01"
        nonce = prefix + struct.pack(">I", counter)
        ciphertext = aead.encrypt(nonce, chunk, flag)
        dst.write(flag + struct.pack(">I", len(ciphertext)) + ciphertext)
        if not following:
            return
        chunk = following
        counter += 1


def _decrypt_file(src: IO[bytes], dst: IO[bytes], passphrase: str) -> None:
    header = src.read(len(MAGIC) + _SALT_LENGTH + _NONCE_PREFIX_LENGTH)
    if not header.startswith(MAGIC) or len(header) < len(MAGIC) + _SALT_LENGTH:
        raise BackupError(f"This isn't a {APP_NAME} full backup file.")
    salt = header[len(MAGIC) : len(MAGIC) + _SALT_LENGTH]
    prefix = header[len(MAGIC) + _SALT_LENGTH :]
    aead = AESGCM(_derive_key(passphrase, salt))
    counter = 0
    while True:
        frame = src.read(5)
        if len(frame) < 5:
            raise BackupError("The backup file is incomplete (truncated).")
        flag, length = frame[:1], struct.unpack(">I", frame[1:])[0]
        ciphertext = src.read(length)
        if len(ciphertext) != length:
            raise BackupError("The backup file is incomplete (truncated).")
        try:
            dst.write(aead.decrypt(prefix + struct.pack(">I", counter), ciphertext, flag))
        except InvalidTag as exc:
            raise BackupError("Wrong passphrase, or the backup file is damaged.") from exc
        if flag == b"\x01":
            if src.read(1):
                raise BackupError("The backup file has data after its end.")
            return
        counter += 1


# --- Row encoding -----------------------------------------------------------


def _encode(column: sa.Column[Any], value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, bytes | bytearray | memoryview):
        return base64.b64encode(bytes(value)).decode("ascii")
    if isinstance(value, uuid.UUID):
        return str(value)
    return value


def _decode(column: sa.Column[Any], value: Any) -> Any:
    column_type = column.type
    if value is None:
        # A JSON column would otherwise store JSON `null`, not SQL NULL.
        return sa.null() if isinstance(column_type, sa.JSON) else None
    if isinstance(column_type, sa.Enum):
        enum_class = column_type.enum_class
        return enum_class(value) if enum_class is not None else value
    if isinstance(column_type, sa.DateTime):
        parsed = datetime.fromisoformat(value)
        return parsed.astimezone(UTC) if parsed.tzinfo else parsed
    if isinstance(column_type, sa.Date):
        return date.fromisoformat(value)
    if isinstance(column_type, sa.LargeBinary):
        return base64.b64decode(value)
    if isinstance(column_type, sa.Uuid):
        return uuid.UUID(value)
    return value


def _tables() -> list[sa.Table]:
    return [t for t in Base.metadata.sorted_tables if t.name not in _SKIPPED_TABLES]


def _secret_columns(table: sa.Table) -> list[str]:
    return [
        c.name
        for c in table.columns
        if c.name.endswith("_encrypted") and isinstance(c.type, sa.LargeBinary)
    ]


async def _database_revision(db: AsyncSession) -> str | None:
    try:
        async with db.begin_nested():
            result = await db.execute(sa.text("SELECT version_num FROM alembic_version"))
            return result.scalar_one_or_none()
    except sa.exc.DBAPIError:
        return None  # no Alembic table (a test database built from the models)


# --- Backup -----------------------------------------------------------------


async def write_backup(db: AsyncSession, destination: IO[bytes], passphrase: str) -> dict[str, Any]:
    """Writes an encrypted full backup to `destination`; returns its manifest
    (without the key)."""
    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise BackupError(f"The passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters.")
    counts: dict[str, int] = {}
    with tempfile.TemporaryFile() as plain:
        with zipfile.ZipFile(plain, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for table in _tables():
                count = 0
                with archive.open(f"tables/{table.name}.jsonl", "w", force_zip64=True) as entry:
                    result = await db.stream(sa.select(table))
                    async for row in result:
                        record = {
                            column.name: _encode(column, row._mapping[column])
                            for column in table.columns
                        }
                        entry.write(json.dumps(record, ensure_ascii=False).encode("utf-8"))
                        entry.write(b"\n")
                        count += 1
                counts[table.name] = count
            manifest = {
                "format": FORMAT_VERSION,
                "app": APP_NAME,
                "app_version": APP_VERSION,
                "database_revision": await _database_revision(db),
                "created_at": datetime.now(UTC).isoformat(),
                "tables": counts,
            }
            archive.writestr(
                "manifest.json",
                json.dumps({**manifest, "encryption_key": current_encryption_key()}, indent=2),
            )
        plain.seek(0)
        _encrypt_file(plain, destination, passphrase)
    return manifest


# --- Restore ----------------------------------------------------------------


def _rows(archive: zipfile.ZipFile, name: str) -> Iterator[dict[str, Any]]:
    with archive.open(name) as entry:
        for line in io.TextIOWrapper(entry, encoding="utf-8"):
            if line.strip():
                yield json.loads(line)


async def restore_backup(db: AsyncSession, source: IO[bytes], passphrase: str) -> dict[str, Any]:
    """Replaces the whole database with the backup in `source` and commits.
    Raises `BackupError` (nothing changed) if the file can't be used."""
    with tempfile.TemporaryFile() as plain:
        _decrypt_file(source, plain, passphrase)
        plain.seek(0)
        try:
            archive = zipfile.ZipFile(plain)
            manifest = json.loads(archive.read("manifest.json"))
        except (zipfile.BadZipFile, KeyError, ValueError) as exc:
            raise BackupError("The backup file's contents are damaged.") from exc
        with archive:
            return await _restore_from_archive(db, archive, manifest)


async def _check_manifest(
    db: AsyncSession, manifest: dict[str, Any], tables: list[sa.Table]
) -> None:
    if manifest.get("app") != APP_NAME:
        raise BackupError(f"This backup is from {manifest.get('app')!r}, not {APP_NAME}.")
    if manifest.get("format") != FORMAT_VERSION:
        raise BackupError("This backup was made in a format this version can't read.")
    current_revision = await _database_revision(db)
    backup_revision = manifest.get("database_revision")
    if current_revision is not None and backup_revision != current_revision:
        raise BackupError(
            f"This backup is from version {manifest.get('app_version')} (database revision "
            f"{backup_revision}); this instance is {APP_VERSION} ({current_revision}). Restore "
            "it onto the same version, then upgrade."
        )
    unknown = set(manifest.get("tables", {})) - {table.name for table in tables}
    if unknown:
        names = ", ".join(sorted(unknown))
        raise BackupError(f"This backup has tables this version doesn't: {names}.")


async def _empty_database(db: AsyncSession, tables: list[sa.Table], *, postgres: bool) -> None:
    if not postgres:
        for table in reversed(tables):
            await db.execute(table.delete())
        return
    # Rows go back in dependency order, but a self- or cross-referencing
    # foreign key could still trip mid-way; with a superuser (the Compose
    # `db` user is one) the whole restore is checked as one unit instead.
    try:
        async with db.begin_nested():
            await db.execute(sa.text("SET LOCAL session_replication_role = replica"))
    except sa.exc.DBAPIError:
        # Not a superuser: carry on without it — rows still arrive in
        # dependency order, which is enough for this app's schema.
        pass
    names = ", ".join(f'"{table.name}"' for table in tables)
    await db.execute(sa.text(f"TRUNCATE {names} RESTART IDENTITY CASCADE"))


async def _load_table(
    db: AsyncSession,
    archive: zipfile.ZipFile,
    table: sa.Table,
    *,
    keys: tuple[str, str] | None,
) -> None:
    """Inserts one table's rows; `keys` = (backup key, this instance's key)
    when stored secrets need re-encrypting."""
    secret_columns = _secret_columns(table) if keys else []
    columns = {column.name: column for column in table.columns}
    batch: list[dict[str, Any]] = []
    for record in _rows(archive, f"tables/{table.name}.jsonl"):
        row = {
            name: _decode(columns[name], value) for name, value in record.items() if name in columns
        }
        if keys:
            for name in secret_columns:
                if isinstance(row.get(name), bytes):
                    row[name] = encrypt_secret_with_key(
                        decrypt_secret_with_key(row[name], keys[0]), keys[1]
                    )
        batch.append(row)
        if len(batch) >= _INSERT_BATCH:
            await db.execute(table.insert(), batch)
            batch = []
    if batch:
        await db.execute(table.insert(), batch)


async def _restore_from_archive(
    db: AsyncSession, archive: zipfile.ZipFile, manifest: dict[str, Any]
) -> dict[str, Any]:
    tables = _tables()
    await _check_manifest(db, manifest, tables)
    old_key = str(manifest.get("encryption_key") or "")
    new_key = current_encryption_key()
    keys = (old_key, new_key) if old_key and old_key != new_key else None
    postgres = db.get_bind().dialect.name == "postgresql"
    try:
        await _empty_database(db, tables, postgres=postgres)
        for table in tables:
            if table.name in manifest.get("tables", {}):
                await _load_table(db, archive, table, keys=keys)
        if postgres:
            for table in tables:
                primary = list(table.primary_key.columns)
                if len(primary) == 1 and isinstance(primary[0].type, sa.Integer):
                    await db.execute(sa.text(_reset_sequence_sql(table.name, primary[0].name)))
        await db.commit()
    except DecryptionError as exc:
        await db.rollback()
        raise BackupError(
            "A stored secret in the backup couldn't be decrypted with the key it carries."
        ) from exc
    except (KeyError, ValueError, TypeError, sa.exc.DBAPIError) as exc:
        await db.rollback()
        raise BackupError(f"The backup couldn't be restored: {exc}") from exc
    return {key: value for key, value in manifest.items() if key != "encryption_key"}


def _reset_sequence_sql(table: str, column: str) -> str:
    # Table and column names come from the app's own metadata, never input.
    return (
        f"SELECT setval(pg_get_serial_sequence('\"{table}\"', '{column}'), "  # noqa: S608
        f'COALESCE(MAX("{column}"), 1), MAX("{column}") IS NOT NULL) FROM "{table}"'
    )


def backup_filename(now: datetime | None = None) -> str:
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    return f"{APP_NAME}-backup-{stamp}.{FILE_EXTENSION}"


def temporary_path() -> Path:
    handle, name = tempfile.mkstemp(suffix=f".{FILE_EXTENSION}")
    os.close(handle)
    return Path(name)
