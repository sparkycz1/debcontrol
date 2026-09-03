"""Creating/reusing `Tag` rows by name and keeping the table free of
orphans — the only place `app.db.models.machine_tag` rows are written.
See that module's own docstring for the data model.
"""

from __future__ import annotations

import re
import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine import Machine
from app.db.models.machine_tag import Tag, machine_tags

MAX_TAG_LENGTH = 64

# A comma or a newline (a `<textarea>`-pasted list, or a plain
# comma-separated `<input>`) both split a tag list the same way.
_TAG_SPLIT_RE = re.compile(r"[,\n]+")


def normalize_tag_names(names: list[str]) -> list[str]:
    """Lowercase, trim, cap length, drop blanks, and de-duplicate —
    order-preserving. Used for both the web form's comma-separated text
    and the REST API's JSON array, so "prod" typed twice, in either shape,
    always ends up as the same one tag."""
    seen: set[str] = set()
    result: list[str] = []
    for raw in names:
        name = raw.strip().lower()[:MAX_TAG_LENGTH]
        if name and name not in seen:
            seen.add(name)
            result.append(name)
    return result


def parse_tag_names_from_text(raw: str) -> list[str]:
    """The web form's `<input name="tags">` — a comma/newline-separated
    string — into the same normalized list `normalize_tag_names` produces
    from a JSON array."""
    return normalize_tag_names(_TAG_SPLIT_RE.split(raw))


async def set_machine_tags(db: AsyncSession, machine: Machine, names: list[str]) -> None:
    """Replace `machine`'s tags with the ones named in `names` (already
    normalized) — creating any that don't exist yet, and deleting any
    *other* tag left with zero machines afterward, so there's never a
    separate "manage tags" page needed just to clean up a rename or a
    typo. `machine` must already be persistent (flushed, has an `id`).
    Caller commits.

    Deliberately works at the Core (association-table row) level rather
    than reading/assigning `machine.tags` as an ORM collection: on an
    `AsyncSession`, touching an unloaded relationship attribute as plain
    Python (not through `await session.execute(...)`/`refresh(...)`) raises
    `MissingGreenlet` — whether `machine` was loaded with `tags` eagerly
    populated already isn't something this function should have to assume
    about its caller.
    """
    previous_result = await db.execute(
        select(machine_tags.c.tag_id).where(machine_tags.c.machine_id == machine.id)
    )
    previous_tag_ids = set(previous_result.scalars().all())

    new_tag_ids: set[uuid.UUID] = set()
    if names:
        result = await db.execute(select(Tag).where(Tag.name.in_(names)))
        existing = {tag.name: tag for tag in result.scalars().all()}
        for name in names:
            tag = existing.get(name)
            if tag is None:
                tag = Tag(name=name)
                db.add(tag)
                await db.flush()  # assign an id before it's referenced below
                existing[name] = tag
            new_tag_ids.add(tag.id)

    to_remove = previous_tag_ids - new_tag_ids
    to_add = new_tag_ids - previous_tag_ids

    if to_remove:
        await db.execute(
            machine_tags.delete().where(
                machine_tags.c.machine_id == machine.id,
                machine_tags.c.tag_id.in_(to_remove),
            )
        )
    for tag_id in to_add:
        await db.execute(machine_tags.insert().values(machine_id=machine.id, tag_id=tag_id))
    await db.flush()

    # A previously-loaded `machine.tags` collection (e.g. the object came
    # from a `selectinload`-backed query) would otherwise keep showing the
    # old membership for the rest of this session.
    await db.refresh(machine, attribute_names=["tags"])

    for tag_id in to_remove:
        count = (
            await db.execute(
                select(func.count())
                .select_from(machine_tags)
                .where(machine_tags.c.tag_id == tag_id)
            )
        ).scalar_one()
        if count == 0:
            tag = await db.get(Tag, tag_id)
            if tag is not None:
                await db.delete(tag)
