"""Clients for the five supported AI providers.

**Every provider with an official Python SDK now uses it** rather than
this app hand-building and maintaining its own requests against their
documented wire formats: `anthropic` (Anthropic), `openai` (plain OpenAI,
and any self-hosted/proxied "OpenAI-compatible" endpoint — litellm, vLLM, a
corporate gateway — which speaks the identical wire format), `openrouter`
(OpenRouter's own SDK, not the `openai` one — see `OpenRouterClient`), and
`google-genai` (Gemini). Each SDK's own request/response typing,
retry/backoff behavior, and error types, instead of this app re-deriving
them from documentation and keeping them in sync by hand as the APIs
evolve. `OpenAICompatibleClient` still wraps one `AsyncOpenAI` instance for
the two kinds that are genuinely the same wire format (OpenAI itself, and
"any other OpenAI-compatible endpoint" — differing only in base URL and
whether a key is required); OpenRouter gets its own dedicated class instead
because it has its own official SDK, distinct from `openai`'s, and using it
means richer typed access to OpenRouter-specific response fields
(`openrouter_metadata`, cost accounting, etc.) that the OpenAI-shaped wire
format doesn't carry — none of that is surfaced by this app today, but the
client is now built on the SDK that actually models it.

Two HTTP client packages end up in play, purely as a fact of depending on
these SDKs as they currently ship, not a choice made in this module:
`anthropic` and `openai` build on `httpx2` — what the rest of this app
uses too — while `openrouter` and `google-genai` still build on plain
`httpx`, the only reason that package is still a dependency. `http_client=`/
`httpx_async_client=`/`transport=` (whichever the given SDK calls it) is
how `tests/test_ai_providers.py` injects a `MockTransport` of the matching
package and reaches no real network, for every client here.

**The API key never leaves this module.** It arrives decrypted from
`app.core.security.decrypt_secret`, goes straight into the SDK client
constructor, and is never logged, never rendered, and never put into an
exception message — errors are built from the provider's own status code
and message only, via `_wrap_provider_error` (every client here funnels
through it).

Two explicit timeouts, not one blanket number: listing models is a quick
admin action on the Settings page (15s), while a chat turn can legitimately
involve a slow model producing a long answer (90s).

`provider_native` messages (what's stored in `AiMessage.provider_native`
and replayed verbatim into the next turn — see `app.ai.base`) stay plain
JSON-serializable dicts even where an SDK has its own typed model classes,
via `.model_dump(mode="json", exclude_none=True[, by_alias=True])` on
whatever the SDK handed back. This keeps old rows written before a given
SDK migration (still the hand-built wire-format shape) and new rows
written after it interchangeable — a conversation started before this
migration replays its history the same way a new one does, because both
are just the wire format's own JSON, never a Python SDK object.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

import anthropic
import httpx
import httpx2
import openai
import openrouter as openrouter_sdk
from google import genai
from google.genai import errors as genai_errors
from google.genai import types as genai_types

from app.ai.base import (
    AiProviderError,
    BaseAiClient,
    ChatTurnResult,
    ModelInfo,
    ToolCall,
    ToolDefinition,
)
from app.core.security import DecryptionError, decrypt_secret
from app.db.models.ai_provider import AiProviderConfig, AiProviderKind

logger = logging.getLogger(__name__)

# No `/v1` suffix, unlike the OpenAI-family base URLs below — the
# `anthropic` SDK's routes already include their own `/v1/...` prefix, so a
# base URL that also ends in `/v1` doubles it (`/v1/v1/messages`).
ANTHROPIC_API_BASE = "https://api.anthropic.com"
OPENAI_API_BASE = "https://api.openai.com/v1"
# Gemini's default base URL is baked into `google-genai` itself (same
# `v1beta` host this used to hit by hand) — no constant needed here anymore.

# Plain floats (total-time budgets), not `httpx.Timeout`/`httpx2.Timeout`
# objects with separate connect/read phases — every SDK here accepts either,
# and a single number is enough: what actually matters is "give up after N
# seconds," not tuning the connect phase separately from the read phase.
MODELS_TIMEOUT_SECONDS = 15.0
CHAT_TIMEOUT_SECONDS = 90.0
# google-genai's `HttpOptions.timeout` wants milliseconds, not seconds.
_GEMINI_MODELS_TIMEOUT_MS = int(MODELS_TIMEOUT_SECONDS * 1000)
_GEMINI_CHAT_TIMEOUT_MS = int(CHAT_TIMEOUT_SECONDS * 1000)
# So does `openrouter`'s `timeout_ms=`.
_OPENROUTER_MODELS_TIMEOUT_MS = int(MODELS_TIMEOUT_SECONDS * 1000)
_OPENROUTER_CHAT_TIMEOUT_MS = int(CHAT_TIMEOUT_SECONDS * 1000)

MAX_OUTPUT_TOKENS = 4096

# Anthropic's list-models endpoint pages at 20 by default; ask for the
# documented maximum so a real catalog fits in as few pages as possible —
# the SDK's own `AsyncPage` handles walking `has_more`/`last_id` beyond that.
_ANTHROPIC_PAGE_LIMIT = 1000

# Enough of a failing response body to diagnose the problem, not enough to
# dump a provider's entire error document into an audit-visible message.
_ERROR_BODY_CHARS = 400


def _wrap_provider_error(provider: str, exc: Exception) -> AiProviderError:
    """Every SDK-based client here funnels its exceptions through this one
    helper, so an operator sees a consistently-shaped message regardless of
    which client hit the problem. Every SDK's HTTP-level error class here
    carries a `.message`, and an HTTP status code under one of two
    attribute names depending on the SDK (`anthropic.AnthropicError`/
    `openai.OpenAIError`/`openrouter.errors.OpenRouterError` use
    `.status_code`; `google.genai.errors.APIError` uses `.code`) — both
    attributes are simply absent on a connection/timeout error, which is
    what the fallback branch is for."""
    status_code = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    message = str(getattr(exc, "message", None) or exc)[:_ERROR_BODY_CHARS].strip()
    if status_code is not None:
        return AiProviderError(f"{provider} returned HTTP {status_code}: {message}")
    return AiProviderError(f"{provider} request failed: {message}")


class AnthropicClient(BaseAiClient):
    """Anthropic's official SDK (`anthropic.AsyncAnthropic`) — the Messages
    API (`.messages.create`) and Models API (`.models.list`, which handles
    `has_more`/`last_id` pagination internally when iterated)."""

    kind_value = AiProviderKind.ANTHROPIC.value

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = ANTHROPIC_API_BASE,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        http_client = httpx2.AsyncClient(transport=transport) if transport is not None else None
        self._client = anthropic.AsyncAnthropic(
            api_key=api_key, base_url=base_url, http_client=http_client
        )

    async def list_models(self) -> list[ModelInfo]:
        models: list[ModelInfo] = []
        try:
            page = await self._client.models.list(
                limit=_ANTHROPIC_PAGE_LIMIT, timeout=MODELS_TIMEOUT_SECONDS
            )
            models.extend(
                [
                    ModelInfo(id=entry.id, display_name=entry.display_name or None)
                    async for entry in page
                ]
            )
        except anthropic.AnthropicError as exc:
            raise _wrap_provider_error("Anthropic", exc) from exc
        return models

    async def send(
        self,
        messages: list[Any],
        tools: list[ToolDefinition],
        model: str,
        system_prompt: str,
    ) -> ChatTurnResult:
        kwargs: dict[str, Any] = {}
        if tools:
            kwargs["tools"] = [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.parameters,
                }
                for tool in tools
            ]
            kwargs["tool_choice"] = {"type": "auto"}

        try:
            response = await self._client.messages.create(
                model=model,
                max_tokens=MAX_OUTPUT_TOKENS,
                system=system_prompt,
                messages=messages,
                timeout=CHAT_TIMEOUT_SECONDS,
                **kwargs,
            )
        except anthropic.AnthropicError as exc:
            raise _wrap_provider_error("Anthropic", exc) from exc

        # `exclude_none=True`: the SDK's typed blocks carry several
        # optional fields (e.g. `citations`, `toolset_name`) that are
        # `None` here and were never part of the raw wire format this app
        # used to build by hand — dropping them keeps `provider_native`
        # (replayed verbatim next turn) the same minimal shape as before.
        blocks = [
            block.model_dump(mode="json", exclude_none=True) for block in response.content
        ]
        texts = [str(b["text"]) for b in blocks if b.get("type") == "text" and b.get("text")]
        tool_calls = [
            ToolCall(
                id=str(b.get("id") or uuid.uuid4()),
                name=str(b.get("name") or ""),
                arguments=b["input"] if isinstance(b.get("input"), dict) else {},
            )
            for b in blocks
            if b.get("type") == "tool_use"
        ]

        return ChatTurnResult(
            text="\n\n".join(texts) if texts else None,
            tool_calls=tool_calls,
            input_tokens=response.usage.input_tokens if response.usage else 0,
            output_tokens=response.usage.output_tokens if response.usage else 0,
            # The exact content-block array, echoed back verbatim next turn.
            raw_assistant_message={"role": "assistant", "content": blocks},
        )

    def build_user_message(self, text: str) -> Any:
        return {"role": "user", "content": text}

    def build_tool_result_messages(
        self, result: ChatTurnResult, outputs: list[tuple[ToolCall, str]]
    ) -> list[Any]:
        return [
            result.raw_assistant_message,
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": call.id, "content": output}
                    for call, output in outputs
                ],
            },
        ]


class OpenAICompatibleClient(BaseAiClient):
    """The OpenAI official SDK (`openai.AsyncOpenAI`) — `.chat.completions`
    + `.models.list`.

    Used for two provider kinds — plain OpenAI, and any self-hosted/proxied
    OpenAI-compatible endpoint (litellm, vLLM, a corporate gateway) — which
    differ only in base URL and whether a key is required. (OpenRouter used
    to be a third kind here, back when there was no dedicated SDK for it to
    use instead — see `OpenRouterClient`.) `AsyncOpenAI` itself requires
    *some* string for `api_key` (raises at construction otherwise, unlike
    the raw-httpx version of this client, which could just omit the
    header) — a self-hosted endpoint's model listing may need no real key
    at all, so a harmless placeholder stands in for one when none is
    configured. A chat turn against a provider that actually needs a real
    key still fails normally, with that provider's own 401.
    """

    _NO_KEY_PLACEHOLDER = "unset"

    def __init__(
        self,
        api_key: str | None,
        base_url: str,
        kind: AiProviderKind,
        *,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        self.kind_value = kind.value
        self._label = {
            AiProviderKind.OPENAI: "OpenAI",
            AiProviderKind.OPENAI_COMPATIBLE: "The OpenAI-compatible endpoint",
        }.get(kind, kind.value)
        http_client = httpx2.AsyncClient(transport=transport) if transport is not None else None
        self._client = openai.AsyncOpenAI(
            api_key=api_key or self._NO_KEY_PLACEHOLDER,
            base_url=base_url,
            http_client=http_client,
        )

    async def list_models(self) -> list[ModelInfo]:
        try:
            page = await self._client.models.list(timeout=MODELS_TIMEOUT_SECONDS)
            return [ModelInfo(id=entry.id) async for entry in page]
        except openai.OpenAIError as exc:
            raise _wrap_provider_error(self._label, exc) from exc

    async def send(
        self,
        messages: list[Any],
        tools: list[ToolDefinition],
        model: str,
        system_prompt: str,
    ) -> ChatTurnResult:
        kwargs: dict[str, Any] = {}
        if tools:
            kwargs["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.parameters,
                    },
                }
                for tool in tools
            ]
            kwargs["tool_choice"] = "auto"

        try:
            response = await self._client.chat.completions.create(
                model=model,
                messages=[{"role": "system", "content": system_prompt}, *messages],
                timeout=CHAT_TIMEOUT_SECONDS,
                **kwargs,
            )
        except openai.OpenAIError as exc:
            raise _wrap_provider_error(self._label, exc) from exc

        choice = response.choices[0] if response.choices else None
        # `exclude_none=True`: drops fields like `refusal`/`audio` that are
        # `None` here and weren't part of the raw wire format this client
        # used to build by hand — keeps `provider_native` (replayed verbatim
        # next turn) the same minimal shape as before.
        message: dict[str, Any] = (
            choice.message.model_dump(mode="json", exclude_none=True) if choice else {}
        )

        tool_calls: list[ToolCall] = []
        for entry in message.get("tool_calls") or []:
            function = entry.get("function") or {}
            raw_arguments = function.get("arguments")
            try:
                arguments = json.loads(raw_arguments) if raw_arguments else {}
            except ValueError:
                # A model can emit malformed JSON here. Treat it as an empty
                # argument set rather than failing the whole turn — the tool
                # layer validates its own arguments anyway, and will report a
                # useful "missing target" back to the model.
                logger.warning("Discarding unparseable tool-call arguments from %s", self._label)
                arguments = {}
            tool_calls.append(
                ToolCall(
                    id=str(entry.get("id") or uuid.uuid4()),
                    name=str(function.get("name") or ""),
                    arguments=arguments if isinstance(arguments, dict) else {},
                )
            )

        usage = response.usage
        content = message.get("content")
        return ChatTurnResult(
            text=str(content) if content else None,
            tool_calls=tool_calls,
            input_tokens=usage.prompt_tokens if usage else 0,
            output_tokens=usage.completion_tokens if usage else 0,
            raw_assistant_message=message,
        )

    def build_user_message(self, text: str) -> Any:
        return {"role": "user", "content": text}

    def build_tool_result_messages(
        self, result: ChatTurnResult, outputs: list[tuple[ToolCall, str]]
    ) -> list[Any]:
        return [
            result.raw_assistant_message,
            *(
                {"role": "tool", "tool_call_id": call.id, "content": output}
                for call, output in outputs
            ),
        ]


class OpenRouterClient(BaseAiClient):
    """OpenRouter's own official SDK (`openrouter`, published separately
    from `openai` — see the module docstring) — `.chat.send_async` +
    `.models.list_async`.

    OpenRouter's wire format is OpenAI-compatible (a `ChatMessages` union
    discriminated on `role`, `tool_calls[].function.{name,arguments}` with
    `arguments` a JSON string, `usage.{prompt,completion}_tokens`), so the
    message-building and tool-call-parsing logic here is line-for-line the
    same as `OpenAICompatibleClient`'s — only the SDK object being called
    differs. No `api_key` placeholder hack needed here (unlike
    `OpenAICompatibleClient`'s `AsyncOpenAI`): this SDK accepts `None`
    directly, matching what unauthenticated model listing has always
    supported for OpenRouter.
    """

    kind_value = AiProviderKind.OPENROUTER.value

    def __init__(
        self, api_key: str | None, *, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        async_client = httpx.AsyncClient(transport=transport) if transport is not None else None
        self._client = openrouter_sdk.OpenRouter(api_key=api_key, async_client=async_client)

    async def list_models(self) -> list[ModelInfo]:
        try:
            response = await self._client.models.list_async(
                timeout_ms=_OPENROUTER_MODELS_TIMEOUT_MS
            )
        except Exception as exc:
            raise _wrap_provider_error("OpenRouter", exc) from exc
        # The SDK's 1.x line wraps the model list one level deeper than 0.x
        # did (`response.result.data` instead of `response.data`) and added
        # pagination (`response.next`) — this app only ever showed the
        # single page 0.x returned, so that's preserved rather than
        # following `.next`. `list_async` can also return `None` now for a
        # transport-level empty/malformed reply, not something that should
        # raise — same "no models" outcome an empty `.data` list already
        # produced before.
        if response is None:
            return []
        return [
            ModelInfo(id=entry.id, display_name=entry.name) for entry in response.result.data
        ]

    async def send(
        self,
        messages: list[Any],
        tools: list[ToolDefinition],
        model: str,
        system_prompt: str,
    ) -> ChatTurnResult:
        kwargs: dict[str, Any] = {}
        if tools:
            kwargs["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.parameters,
                    },
                }
                for tool in tools
            ]
            kwargs["tool_choice"] = "auto"

        try:
            response = await self._client.chat.send_async(
                model=model,
                messages=[{"role": "system", "content": system_prompt}, *messages],
                timeout_ms=_OPENROUTER_CHAT_TIMEOUT_MS,
                **kwargs,
            )
        except Exception as exc:
            raise _wrap_provider_error("OpenRouter", exc) from exc

        choice = response.choices[0] if response.choices else None
        message: dict[str, Any] = (
            choice.message.model_dump(mode="json", exclude_none=True) if choice else {}
        )

        tool_calls: list[ToolCall] = []
        for entry in message.get("tool_calls") or []:
            function = entry.get("function") or {}
            raw_arguments = function.get("arguments")
            try:
                arguments = json.loads(raw_arguments) if raw_arguments else {}
            except ValueError:
                logger.warning("Discarding unparseable tool-call arguments from OpenRouter")
                arguments = {}
            tool_calls.append(
                ToolCall(
                    id=str(entry.get("id") or uuid.uuid4()),
                    name=str(function.get("name") or ""),
                    arguments=arguments if isinstance(arguments, dict) else {},
                )
            )

        usage = response.usage
        content = message.get("content")
        return ChatTurnResult(
            text=str(content) if content else None,
            tool_calls=tool_calls,
            input_tokens=usage.prompt_tokens if usage else 0,
            output_tokens=usage.completion_tokens if usage else 0,
            raw_assistant_message=message,
        )

    def build_user_message(self, text: str) -> Any:
        return {"role": "user", "content": text}

    def build_tool_result_messages(
        self, result: ChatTurnResult, outputs: list[tuple[ToolCall, str]]
    ) -> list[Any]:
        return [
            result.raw_assistant_message,
            *(
                {"role": "tool", "tool_call_id": call.id, "content": output}
                for call, output in outputs
            ),
        ]


class GeminiClient(BaseAiClient):
    """Google's official SDK (`google-genai`, `google.genai.Client`) —
    `.aio.models.generate_content` + `.aio.models.list`.

    `contents`/`tools` are still built as the same plain camelCase-or-not
    dicts this client always sent (`{"role": ..., "parts": [...]}`,
    `functionCall`/`functionResponse` parts) — `google-genai`'s pydantic
    models accept either the wire format's camelCase or their own
    snake_case field names on the way in (`populate_by_name`), so nothing
    about the message-building/tool-result logic below needed to change,
    only the transport calling it. `automatic_function_calling` is
    explicitly disabled: this app's own agentic loop (`app.ai.tools`)
    decides when a tool actually runs — including a human confirmation step
    for anything sensitive — and the SDK executing a declared function on
    its own would bypass that entirely. In practice it likely never would
    have (auto-calling only triggers for tools declared as native Python
    callables, not the plain dict declarations built here), but there is no
    reason to rely on that.
    """

    kind_value = AiProviderKind.GEMINI.value

    def __init__(
        self, api_key: str, *, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        http_options = genai_types.HttpOptions(
            httpx_async_client=httpx.AsyncClient(transport=transport)
            if transport is not None
            else None
        )
        self._client = genai.Client(api_key=api_key, http_options=http_options)

    async def list_models(self) -> list[ModelInfo]:
        models: list[ModelInfo] = []
        try:
            pager = await self._client.aio.models.list(
                config=genai_types.ListModelsConfig(
                    http_options=genai_types.HttpOptions(timeout=_GEMINI_MODELS_TIMEOUT_MS)
                )
            )
            async for entry in pager:
                # Only models that can actually answer a chat turn — the
                # catalog also lists embedding-only and other
                # non-generative models.
                if "generateContent" not in (entry.supported_actions or []):
                    continue
                if not entry.name:
                    continue
                models.append(
                    ModelInfo(
                        id=entry.name.removeprefix("models/"),
                        display_name=entry.display_name,
                    )
                )
        except genai_errors.APIError as exc:
            raise _wrap_provider_error("Gemini", exc) from exc
        return models

    async def send(
        self,
        messages: list[Any],
        tools: list[ToolDefinition],
        model: str,
        system_prompt: str,
    ) -> ChatTurnResult:
        config = genai_types.GenerateContentConfig(
            system_instruction=system_prompt,
            automatic_function_calling=genai_types.AutomaticFunctionCallingConfig(disable=True),
            http_options=genai_types.HttpOptions(timeout=_GEMINI_CHAT_TIMEOUT_MS),
            tools=(
                [{"function_declarations": [_gemini_declaration(t) for t in tools]}]
                if tools
                else None
            ),
        )

        try:
            response = await self._client.aio.models.generate_content(
                model=model, contents=messages, config=config
            )
        except genai_errors.APIError as exc:
            raise _wrap_provider_error("Gemini", exc) from exc

        candidates = response.candidates or []
        content = candidates[0].content if candidates and candidates[0].content else None
        parts = content.parts or [] if content else []
        # `by_alias=True`: keeps the camelCase (`functionCall`, ...) shape
        # this client has always stored in `provider_native`, so an older
        # conversation's history (written before this SDK migration) and a
        # new one are byte-for-byte the same shape on replay.
        part_dicts = [p.model_dump(mode="json", exclude_none=True, by_alias=True) for p in parts]

        texts: list[str] = []
        tool_calls: list[ToolCall] = []
        for part in parts:
            if part.text:
                texts.append(part.text)
            if part.function_call is not None:
                tool_calls.append(
                    ToolCall(
                        id=str(part.function_call.id or uuid.uuid4()),
                        name=part.function_call.name or "",
                        arguments=part.function_call.args or {},
                    )
                )

        usage = response.usage_metadata
        return ChatTurnResult(
            text="\n\n".join(texts) if texts else None,
            tool_calls=tool_calls,
            input_tokens=(usage.prompt_token_count or 0) if usage else 0,
            output_tokens=(usage.candidates_token_count or 0) if usage else 0,
            raw_assistant_message={"role": "model", "parts": part_dicts},
        )

    def build_user_message(self, text: str) -> Any:
        return {"role": "user", "parts": [{"text": text}]}

    def build_tool_result_messages(
        self, result: ChatTurnResult, outputs: list[tuple[ToolCall, str]]
    ) -> list[Any]:
        responses: list[dict[str, Any]] = []
        for call, output in outputs:
            function_response: dict[str, Any] = {
                "name": call.name,
                "response": {"result": output},
            }
            # Only echo an id the provider actually gave us — a synthesized
            # UUID would be a value Gemini never issued.
            if _looks_like_provider_id(call.id):
                function_response["id"] = call.id
            responses.append({"functionResponse": function_response})
        return [
            result.raw_assistant_message,
            {"role": "user", "parts": responses},
        ]


def _gemini_declaration(tool: ToolDefinition) -> dict[str, Any]:
    """One `functionDeclaration`. `parameters` is omitted entirely for a
    tool that takes none — Gemini's schema dialect is a subset of JSON
    Schema, and a declaration with an empty `properties` object is not the
    documented way to say "no arguments"; leaving the key out is."""
    declaration: dict[str, Any] = {"name": tool.name, "description": tool.description}
    if tool.parameters.get("properties"):
        declaration["parameters"] = tool.parameters
    return declaration


def _looks_like_provider_id(value: str) -> bool:
    """True unless the id is one this app synthesized locally (a UUID4)."""
    try:
        uuid.UUID(value)
    except ValueError:
        return True
    return False


def decrypted_api_key(config: AiProviderConfig) -> str | None:
    """The provider's API key in plaintext, or None if none is stored.

    The only place this value is produced. Callers hand it straight to a
    client constructor; it must never be returned to a template, a response
    body, or a log line.
    """
    if config.api_key_encrypted is None:
        return None
    try:
        return decrypt_secret(config.api_key_encrypted)
    except DecryptionError as exc:
        raise AiProviderError(
            "The stored API key for this provider could not be decrypted — "
            "re-enter it on the Settings page."
        ) from exc


def build_client(config: AiProviderConfig) -> BaseAiClient:
    """Construct the right client for a provider row. Raises
    `AiProviderError` if the row isn't usable (missing key or base URL).

    No `transport=` passthrough here (an earlier version had one, never
    actually used by any caller) — the four client classes want two
    different transport types between them (`httpx2` for `AnthropicClient`/
    `OpenAICompatibleClient`, plain `httpx` for `OpenRouterClient`/
    `GeminiClient` — see the module docstring), so tests construct the
    client class they need directly instead of going through this factory.
    """
    api_key = decrypted_api_key(config)

    if config.kind == AiProviderKind.ANTHROPIC:
        if not api_key:
            raise AiProviderError("No Anthropic API key is configured.")
        return AnthropicClient(api_key)

    if config.kind == AiProviderKind.GEMINI:
        if not api_key:
            raise AiProviderError("No Gemini API key is configured.")
        return GeminiClient(api_key)

    if config.kind == AiProviderKind.OPENAI:
        if not api_key:
            raise AiProviderError("No OpenAI API key is configured.")
        return OpenAICompatibleClient(api_key, OPENAI_API_BASE, AiProviderKind.OPENAI)

    if config.kind == AiProviderKind.OPENROUTER:
        # Listing models needs no key; a chat turn does. Not enforced here,
        # so an admin can still fetch the catalog before pasting a key —
        # `OpenRouterClient`/its SDK accept `None` directly, no placeholder
        # needed (unlike `OpenAICompatibleClient`'s `AsyncOpenAI`).
        return OpenRouterClient(api_key)

    if not config.base_url:
        raise AiProviderError("This OpenAI-compatible provider has no base URL configured.")
    return OpenAICompatibleClient(api_key, config.base_url, AiProviderKind.OPENAI_COMPATIBLE)
