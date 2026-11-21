"""Pictures attached to an AI conversation message: checking an upload,
storing it, and handing it back to the chat and to the provider.

**What is accepted** is decided from the file's own first bytes, never from
the browser's `Content-Type` or the file name: PNG, JPEG, GIF and WebP —
the four formats every supported provider takes. SVG is refused on purpose
(it is a document that can carry script, and the attachment route serves
what is stored). The route serves a picture with that sniffed type,
`nosniff` and `inline`, so what the browser renders is always one of the
four.

**Limits** keep a turn's request within what the providers take and the
table small: `MAX_IMAGES_PER_MESSAGE` pictures per message, each at most
`MAX_IMAGE_BYTES` (5 MB) and all of them together at most
`MAX_TOTAL_BYTES` (25 MB, inside the bundled Caddy's 26 MB request limit).
A provider may refuse a picture smaller than that (Anthropic takes at
most 5 MB of base64, about 3.75 MB of picture); its error shows in the
chat. A
conversation's pictures are sent again with every later turn (the
provider keeps no state between calls), so a long conversation with many
pictures costs input tokens on each reply — the chat's hint says so.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import undefer

from app.ai.base import ImageInput
from app.db.models.ai_attachment import AiAttachment

MAX_IMAGES_PER_MESSAGE = 5
MAX_IMAGE_BYTES = 5_000_000
# All pictures of one message together — keeps the upload under the bundled
# Caddy's 26 MB request body limit (`Caddyfile`), form fields included.
MAX_TOTAL_BYTES = 25_000_000
ACCEPT = "image/png,image/jpeg,image/gif,image/webp"
_FILENAME_MAX = 255


class AttachmentError(ValueError):
    """An upload that can't be attached. `key` is the i18n key of the
    message shown to the person; `params` fills it."""

    def __init__(self, key: str, **params: object) -> None:
        super().__init__(key)
        self.key = key
        self.params = params


@dataclass(frozen=True)
class Upload:
    filename: str
    data: bytes


def sniff_media_type(data: bytes) -> str | None:
    """The picture's real type from its magic bytes, or `None`."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def _clean_filename(name: str) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = "".join(ch for ch in base if ch.isprintable()).strip()
    return cleaned[:_FILENAME_MAX] or "image"


def validate(uploads: Sequence[Upload]) -> list[tuple[str, str, bytes]]:
    """`(filename, media_type, data)` for each upload, or `AttachmentError`
    for the first one that breaks a rule."""
    if len(uploads) > MAX_IMAGES_PER_MESSAGE:
        raise AttachmentError("ai.attach.too_many", count=MAX_IMAGES_PER_MESSAGE)
    if sum(len(upload.data) for upload in uploads) > MAX_TOTAL_BYTES:
        raise AttachmentError("ai.attach.too_large_total", mb=f"{MAX_TOTAL_BYTES / 1_000_000:g}")
    checked: list[tuple[str, str, bytes]] = []
    for upload in uploads:
        name = _clean_filename(upload.filename)
        if len(upload.data) > MAX_IMAGE_BYTES:
            raise AttachmentError(
                "ai.attach.too_large", name=name, mb=f"{MAX_IMAGE_BYTES / 1_000_000:g}"
            )
        media_type = sniff_media_type(upload.data)
        if media_type is None:
            raise AttachmentError("ai.attach.bad_type", name=name)
        checked.append((name, media_type, upload.data))
    return checked


def add_to_message(
    db: AsyncSession,
    conversation_id: uuid.UUID,
    message_id: uuid.UUID,
    images: Iterable[tuple[str, str, bytes]],
) -> None:
    """Stage the rows; the caller commits together with the message."""
    for filename, media_type, data in images:
        db.add(
            AiAttachment(
                conversation_id=conversation_id,
                message_id=message_id,
                media_type=media_type,
                filename=filename,
                size=len(data),
                data=data,
            )
        )


async def by_message(
    db: AsyncSession, conversation_id: uuid.UUID
) -> dict[uuid.UUID, list[AiAttachment]]:
    """The conversation's pictures per message, without their bytes — what
    the chat page needs to show them."""
    result = await db.execute(
        select(AiAttachment)
        .where(AiAttachment.conversation_id == conversation_id)
        .order_by(AiAttachment.created_at, AiAttachment.id)
    )
    grouped: dict[uuid.UUID, list[AiAttachment]] = {}
    for row in result.scalars().all():
        grouped.setdefault(row.message_id, []).append(row)
    return grouped


async def images_by_message(
    db: AsyncSession, conversation_id: uuid.UUID
) -> dict[uuid.UUID, list[ImageInput]]:
    """The same with the bytes, for the history sent to the provider."""
    result = await db.execute(
        select(AiAttachment)
        .options(undefer(AiAttachment.data))
        .where(AiAttachment.conversation_id == conversation_id)
        .order_by(AiAttachment.created_at, AiAttachment.id)
    )
    grouped: dict[uuid.UUID, list[ImageInput]] = {}
    for row in result.scalars().all():
        grouped.setdefault(row.message_id, []).append(ImageInput(row.media_type, row.data))
    return grouped


async def get(
    db: AsyncSession, conversation_id: uuid.UUID, attachment_id: uuid.UUID
) -> AiAttachment | None:
    result = await db.execute(
        select(AiAttachment)
        .options(undefer(AiAttachment.data))
        .where(
            AiAttachment.id == attachment_id,
            AiAttachment.conversation_id == conversation_id,
        )
    )
    return result.scalar_one_or_none()
