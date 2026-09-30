"""Per-provider configuration for the AI assistant (see `app.ai`).

There are exactly five provider kinds and they're a closed, code-defined
set (`AiProviderKind`) — not rows an admin creates — because each one needs
its own wire-format client implementation in `app.ai.providers`. A "new
provider" is a code change, not a configuration change; the only thing an
admin decides is which of the five are enabled, with which API key.

One `AiProviderConfig` row exists per kind at all times, created lazily on
first access to the AI settings panel — see
`app.ai.config.get_or_create_ai_provider_configs`, which is the same
create-or-fetch-on-conflict shape as
`app.core.app_settings.get_or_create_app_settings`. Keeping a row per kind
(rather than only for configured ones) means the Settings page renders the
same five sub-forms whether or not anything has been set up yet, and the
`AiModel` rows fetched for a provider have a stable parent to hang off.

`api_key_encrypted` is Fernet-encrypted at rest with the same key as SSH
passwords and the LDAP bind password (`app.core.security`), and is only
ever decrypted inside `app.ai.providers` immediately before being put in an
outbound HTTP header to that provider's own host. It is never rendered into
a template, never logged, and never included in any response body — the
Settings page shows only a "unchanged" placeholder, exactly like
`oidc_client_secret` / `ldap_bind_password`.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, LargeBinary, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.pg_enum import pg_enum


class AiProviderKind(enum.StrEnum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    GEMINI = "gemini"
    OPENROUTER = "openrouter"
    # Any OpenAI-compatible HTTP endpoint (litellm, vLLM, Ollama's
    # OpenAI-compatible surface, a corporate gateway, ...) — the only kind
    # for which `base_url` is meaningful, and required when enabled.
    OPENAI_COMPATIBLE = "openai_compatible"


class AiProviderConfig(Base):
    """One row per `AiProviderKind` — see the module docstring."""

    __tablename__ = "ai_provider_configs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    kind: Mapped[AiProviderKind] = mapped_column(
        pg_enum(AiProviderKind, name="ai_provider_kind"), unique=True, nullable=False
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    api_key_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # Only meaningful for OPENAI_COMPATIBLE (validated server-side in
    # app/web/routes/settings.py); ignored for the four fixed-endpoint kinds.
    base_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    models_fetched_at: Mapped[datetime | None] = mapped_column(nullable=True)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # lazy="selectin" for the same reason `Role.permission_grants` uses it:
    # the Settings page and the "new conversation" model dropdown both read
    # `config.models` while rendering a template, which is outside any
    # `await` — a genuinely lazy load there would raise MissingGreenlet.
    models: Mapped[list[AiModel]] = relationship(
        back_populates="provider",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="AiModel.model_id",
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"AiProviderConfig(kind={self.kind!r}, enabled={self.enabled!r})"


# The `models` relationship above names its target as the *string*
# "AiModel", which SQLAlchemy resolves against its registry when mappers are
# configured — so that class has to have been imported by then or mapper
# configuration fails with "expression 'AiModel' failed to locate a name".
# Importing it here, at the bottom (the top would be a circular import,
# since `ai_model` needs `AiProviderConfig` for its own back-reference),
# makes that guaranteed rather than dependent on some other module in the
# process happening to have imported it first — which is exactly the kind of
# thing that holds in the web app and then breaks in a Celery worker with a
# narrower import graph.
from app.db.models.ai_model import AiModel  # noqa: E402  (see above)
