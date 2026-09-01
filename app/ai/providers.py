"""Clients for the five supported AI providers.

**Anthropic and the three OpenAI-wire-format kinds (OpenAI, OpenRouter, any
"OpenAI-compatible" endpoint) use their official SDKs** (`anthropic`,
`openai`) rather than hand-built requests — each SDK's own request/response
typing, retry/backoff behavior, and error types, instead of this app
re-deriving them from documentation and keeping them in sync by hand as the
APIs evolve. `OpenAICompatibleClient` still wraps one `AsyncOpenAI` instance
for all three of those kinds, since they differ only in base URL and
whether a key is required — one class, three configurations, same as before.

**Gemini stays on a plain `httpx.AsyncClient`** against its REST API —
there's no official-SDK decision pending for it in this module yet, it's
simply unconverted.

Both `anthropic` and `openai` in the versions this app pins build on
`httpx2` (a distinct package from the `httpx` this app uses everywhere
else, including for Gemini below) for their own HTTP layer — not something
this app chose, just a fact of depending on those SDKs as they currently
ship. `http_client=httpx2.AsyncClient(transport=...)` is how a test
(`tests/test_ai_providers.py`) still injects a `MockTransport` and reaches
no real network, the same idea as the plain-httpx `transport=` this module
used everywhere before, just spelled with the other package for these two
clients specifically.

**The API key never leaves this module.** It arrives decrypted from
`app.core.security.decrypt_secret`, goes straight into the SDK/request
(or, for Gemini, its documented `?key=` query parameter), and is never
logged, never rendered, and never put into an exception message — errors
are built from the provider's own status code and message only, via
`_wrap_provider_error` for the two SDK-based clients and `_raise_for_status`
for Gemini's raw HTTP calls.

Two explicit timeouts, not one blanket number: listing models is a quick
admin action on the Settings page (15s), while a chat turn can legitimately
involve a slow model producing a long answer (90s).

Wire formats (Gemini's own, and what's sent to/parsed from the two SDKs)
were checked against each provider's current published documentation
rather than written from memory — in particular Gemini's function-calling
round trip (`tools[].functionDeclarations`, a `model` turn echoing the
`functionCall` part, then a `user` turn carrying `functionResponse`).
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
OPENROUTER_API_BASE = "https://openrouter.ai/api/v1"
GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta"

# Plain floats (total-time budgets), not `httpx.Timeout`/`httpx2.Timeout`
# objects with separate connect/read phases — both SDKs accept either, and
# a single number is enough here: what actually matters is "give up after
# N seconds," not tuning the connect phase separately from the read phase.
MODELS_TIMEOUT_SECONDS = 15.0
CHAT_TIMEOUT_SECONDS = 90.0
# Gemini's own raw httpx calls still want the old two-phase form.
_GEMINI_MODELS_TIMEOUT = httpx.Timeout(MODELS_TIMEOUT_SECONDS, connect=15.0)
_GEMINI_CHAT_TIMEOUT = httpx.Timeout(CHAT_TIMEOUT_SECONDS, connect=15.0)

MAX_OUTPUT_TOKENS = 4096

# Anthropic's list-models endpoint pages at 20 by default; ask for the
# documented maximum so a real catalog fits in as few pages as possible —
# the SDK's own `AsyncPage` handles walking `has_more`/`last_id` beyond that.
_ANTHROPIC_PAGE_LIMIT = 1000

# Enough of a failing response body to diagnose the problem, not enough to
# dump a provider's entire error document into an audit-visible message.
_ERROR_BODY_CHARS = 400


def _wrap_provider_error(provider: str, exc: Exception) -> AiProviderError:
    """Both `anthropic.AnthropicError` and `openai.OpenAIError` subclasses
    carry `.status_code`/`.message` for an HTTP-level failure (missing on a
    connection/timeout error, which is what the fallback branch is for) —
    this builds the same "HTTP <code>: <body>" shape `_raise_for_status`
    below builds for Gemini's own raw calls, so an operator sees a
    consistent message regardless of which client hit the problem."""
    status_code = getattr(exc, "status_code", None)
    message = str(getattr(exc, "message", None) or exc)[:_ERROR_BODY_CHARS].strip()
    if status_code is not None:
        return AiProviderError(f"{provider} returned HTTP {status_code}: {message}")
    return AiProviderError(f"{provider} request failed: {message}")


def _raise_for_status(response: httpx.Response, provider: str) -> None:
    if response.status_code < 400:
        return
    body = response.text[:_ERROR_BODY_CHARS].strip()
    raise AiProviderError(f"{provider} returned HTTP {response.status_code}: {body}")


def _parse_json(response: httpx.Response, provider: str) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError as exc:
        raise AiProviderError(f"{provider} returned a non-JSON response.") from exc
    if not isinstance(payload, dict):
        raise AiProviderError(f"{provider} returned an unexpected response shape.")
    return payload


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
            async for entry in page:
                models.append(
                    ModelInfo(id=entry.id, display_name=entry.display_name or None)
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

    Used for three provider kinds — plain OpenAI, OpenRouter, and any
    self-hosted/proxied OpenAI-compatible endpoint (litellm, vLLM, a
    corporate gateway) — which differ only in base URL and whether a key is
    required. `AsyncOpenAI` itself requires *some* string for `api_key`
    (raises at construction otherwise, unlike the raw-httpx version of this
    client, which could just omit the header) — OpenRouter's model listing
    needs no real key at all, so a harmless placeholder stands in for one
    when none is configured. A chat turn against a provider that actually
    needs a real key still fails normally, with that provider's own 401.
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
            AiProviderKind.OPENROUTER: "OpenRouter",
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


class GeminiClient(BaseAiClient):
    """Google's Generative Language API (`v1beta`, `:generateContent`).

    The one format most likely to be got wrong from memory, so it was
    checked against Google's current documentation rather than assumed:
    tools are `[{"functionDeclarations": [...]}]`; a tool call comes back as
    a `functionCall` part inside `candidates[0].content.parts`; and feeding
    a result back means appending a `"model"` turn holding that same
    `functionCall` part, then a `"user"` turn holding a `functionResponse`
    part whose `name` matches the call (echoing the call's `id` too when the
    provider supplied one — the documented way responses are matched to
    calls). Field names are sent in the camelCase form the current docs use;
    protobuf JSON accepts either casing, and matching the docs is the lower
    risk of the two.
    """

    kind_value = AiProviderKind.GEMINI.value

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = GEMINI_API_BASE,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._transport = transport

    async def list_models(self) -> list[ModelInfo]:
        async with httpx.AsyncClient(
            timeout=_GEMINI_MODELS_TIMEOUT, transport=self._transport
        ) as client:
            response = await client.get(
                f"{self._base_url}/models", params={"key": self._api_key}
            )
        _raise_for_status(response, "Gemini")
        payload = _parse_json(response, "Gemini")

        models: list[ModelInfo] = []
        for entry in payload.get("models") or []:
            if not isinstance(entry, dict) or not entry.get("name"):
                continue
            # Only models that can actually answer a chat turn — the catalog
            # also lists embedding-only and other non-generative models.
            methods = entry.get("supportedGenerationMethods") or []
            if "generateContent" not in methods:
                continue
            models.append(
                ModelInfo(
                    id=str(entry["name"]).removeprefix("models/"),
                    display_name=(
                        str(entry["displayName"]) if entry.get("displayName") else None
                    ),
                )
            )
        return models

    async def send(
        self,
        messages: list[Any],
        tools: list[ToolDefinition],
        model: str,
        system_prompt: str,
    ) -> ChatTurnResult:
        body: dict[str, Any] = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": messages,
        }
        if tools:
            body["tools"] = [{"functionDeclarations": [_gemini_declaration(t) for t in tools]}]

        async with httpx.AsyncClient(
            timeout=_GEMINI_CHAT_TIMEOUT, transport=self._transport
        ) as client:
            response = await client.post(
                f"{self._base_url}/models/{model}:generateContent",
                params={"key": self._api_key},
                json=body,
            )
        _raise_for_status(response, "Gemini")
        payload = _parse_json(response, "Gemini")

        candidates = payload.get("candidates") or []
        parts: list[Any] = []
        if candidates and isinstance(candidates[0], dict):
            content = candidates[0].get("content")
            if isinstance(content, dict):
                parts = content.get("parts") or []

        texts: list[str] = []
        tool_calls: list[ToolCall] = []
        for part in parts:
            if not isinstance(part, dict):
                continue
            if part.get("text"):
                texts.append(str(part["text"]))
            function_call = part.get("functionCall")
            if isinstance(function_call, dict):
                args = function_call.get("args")
                tool_calls.append(
                    ToolCall(
                        id=str(function_call.get("id") or uuid.uuid4()),
                        name=str(function_call.get("name") or ""),
                        arguments=args if isinstance(args, dict) else {},
                    )
                )

        usage = payload.get("usageMetadata") or {}
        return ChatTurnResult(
            text="\n\n".join(texts) if texts else None,
            tool_calls=tool_calls,
            input_tokens=int(usage.get("promptTokenCount") or 0),
            output_tokens=int(usage.get("candidatesTokenCount") or 0),
            raw_assistant_message={"role": "model", "parts": parts},
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
    actually used by any caller) — `AnthropicClient`/`OpenAICompatibleClient`
    and `GeminiClient` now want different transport types (`httpx2` vs.
    plain `httpx`, see the module docstring), so tests construct the client
    class they need directly instead of going through this factory.
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
        # so an admin can still fetch the catalog before pasting a key.
        return OpenAICompatibleClient(api_key, OPENROUTER_API_BASE, AiProviderKind.OPENROUTER)

    if not config.base_url:
        raise AiProviderError("This OpenAI-compatible provider has no base URL configured.")
    return OpenAICompatibleClient(api_key, config.base_url, AiProviderKind.OPENAI_COMPATIBLE)
