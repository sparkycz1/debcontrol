"""HTTP clients for the five supported AI providers.

Three implementations cover five kinds, because OpenAI, OpenRouter, and any
"OpenAI-compatible" endpoint all speak the same wire format — they differ
only in base URL and key, so `OpenAICompatibleClient` is instantiated three
ways rather than copied three times.

Everything here is plain `httpx.AsyncClient` against the provider's own
host. There is no vendor SDK involved, deliberately: the three request/
response shapes are small, and pinning three separate SDKs (each with its
own release cadence, its own transitive dependencies, and its own opinion
about async) to get JSON we can build by hand would be a much larger
dependency surface than this feature justifies. httpx is already a runtime
dependency (see `pyproject.toml`).

**The API key never leaves this module.** It arrives decrypted from
`app.core.security.decrypt_secret`, goes straight into an outbound request
header (or, for Gemini, its documented `?key=` query parameter) to that
provider's own host, and is never logged, never rendered, and never put
into an exception message — `_raise_for_status` builds errors from the
status code and a truncated response body only.

Two explicit timeouts, not one blanket number: listing models is a quick
admin action on the Settings page (15s), while a chat turn can legitimately
involve a slow model producing a long answer (90s). Both set connect and
read separately so a black-holed TCP connect fails fast rather than
consuming the whole read budget.

Wire formats were checked against each provider's current published
documentation rather than written from memory — in particular Gemini's
function-calling round trip (`tools[].functionDeclarations`, a `model` turn
echoing the `functionCall` part, then a `user` turn carrying
`functionResponse`) and Anthropic's models-list pagination
(`has_more`/`last_id` driving an `after_id` query parameter).
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

import httpx

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

ANTHROPIC_API_BASE = "https://api.anthropic.com/v1"
ANTHROPIC_VERSION = "2023-06-01"
OPENAI_API_BASE = "https://api.openai.com/v1"
OPENROUTER_API_BASE = "https://openrouter.ai/api/v1"
GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta"

MODELS_TIMEOUT = httpx.Timeout(15.0, connect=15.0, read=15.0)
CHAT_TIMEOUT = httpx.Timeout(90.0, connect=15.0, read=90.0)

MAX_OUTPUT_TOKENS = 4096

# Anthropic's list-models endpoint pages at 20 by default; ask for the
# documented maximum and follow `has_more`/`last_id` rather than assuming
# one page is the whole catalog.
_ANTHROPIC_PAGE_LIMIT = 1000
_ANTHROPIC_MAX_PAGES = 20

# Enough of a failing response body to diagnose the problem, not enough to
# dump a provider's entire error document into an audit-visible message.
_ERROR_BODY_CHARS = 400


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
    """Anthropic Messages API (`/v1/messages`) and Models API (`/v1/models`)."""

    kind_value = AiProviderKind.ANTHROPIC.value

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = ANTHROPIC_API_BASE,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._transport = transport

    def _headers(self) -> dict[str, str]:
        return {
            "x-api-key": self._api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        }

    async def list_models(self) -> list[ModelInfo]:
        models: list[ModelInfo] = []
        params: dict[str, Any] = {"limit": _ANTHROPIC_PAGE_LIMIT}
        async with httpx.AsyncClient(
            timeout=MODELS_TIMEOUT, transport=self._transport
        ) as client:
            for _page in range(_ANTHROPIC_MAX_PAGES):
                response = await client.get(
                    f"{self._base_url}/models", headers=self._headers(), params=params
                )
                _raise_for_status(response, "Anthropic")
                payload = _parse_json(response, "Anthropic")
                for entry in payload.get("data") or []:
                    if isinstance(entry, dict) and entry.get("id"):
                        models.append(
                            ModelInfo(
                                id=str(entry["id"]),
                                display_name=(
                                    str(entry["display_name"])
                                    if entry.get("display_name")
                                    else None
                                ),
                            )
                        )
                if not payload.get("has_more") or not payload.get("last_id"):
                    break
                params = {"limit": _ANTHROPIC_PAGE_LIMIT, "after_id": payload["last_id"]}
        return models

    async def send(
        self,
        messages: list[Any],
        tools: list[ToolDefinition],
        model: str,
        system_prompt: str,
    ) -> ChatTurnResult:
        body: dict[str, Any] = {
            "model": model,
            "max_tokens": MAX_OUTPUT_TOKENS,
            "system": system_prompt,
            "messages": messages,
        }
        if tools:
            body["tools"] = [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.parameters,
                }
                for tool in tools
            ]
            body["tool_choice"] = {"type": "auto"}

        async with httpx.AsyncClient(timeout=CHAT_TIMEOUT, transport=self._transport) as client:
            response = await client.post(
                f"{self._base_url}/messages", headers=self._headers(), json=body
            )
        _raise_for_status(response, "Anthropic")
        payload = _parse_json(response, "Anthropic")

        blocks = payload.get("content") or []
        texts: list[str] = []
        tool_calls: list[ToolCall] = []
        for block in blocks:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text" and block.get("text"):
                texts.append(str(block["text"]))
            elif block.get("type") == "tool_use":
                arguments = block.get("input")
                tool_calls.append(
                    ToolCall(
                        id=str(block.get("id") or uuid.uuid4()),
                        name=str(block.get("name") or ""),
                        arguments=arguments if isinstance(arguments, dict) else {},
                    )
                )

        usage = payload.get("usage") or {}
        return ChatTurnResult(
            text="\n\n".join(texts) if texts else None,
            tool_calls=tool_calls,
            input_tokens=int(usage.get("input_tokens") or 0),
            output_tokens=int(usage.get("output_tokens") or 0),
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
    """The OpenAI `/chat/completions` + `/models` wire format.

    Used for three provider kinds — plain OpenAI, OpenRouter, and any
    self-hosted/proxied OpenAI-compatible endpoint (litellm, vLLM, a
    corporate gateway) — which differ only in base URL and whether a key is
    required. OpenRouter's model listing needs no auth at all, but the key
    is sent anyway when one is configured, since doing so is harmless and
    keeps one code path.
    """

    def __init__(
        self,
        api_key: str | None,
        base_url: str,
        kind: AiProviderKind,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self.kind_value = kind.value
        self._label = {
            AiProviderKind.OPENAI: "OpenAI",
            AiProviderKind.OPENROUTER: "OpenRouter",
            AiProviderKind.OPENAI_COMPATIBLE: "The OpenAI-compatible endpoint",
        }.get(kind, kind.value)
        self._transport = transport

    def _headers(self) -> dict[str, str]:
        headers = {"content-type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    async def list_models(self) -> list[ModelInfo]:
        async with httpx.AsyncClient(
            timeout=MODELS_TIMEOUT, transport=self._transport
        ) as client:
            response = await client.get(f"{self._base_url}/models", headers=self._headers())
        _raise_for_status(response, self._label)
        payload = _parse_json(response, self._label)
        return [
            ModelInfo(id=str(entry["id"]))
            for entry in (payload.get("data") or [])
            if isinstance(entry, dict) and entry.get("id")
        ]

    async def send(
        self,
        messages: list[Any],
        tools: list[ToolDefinition],
        model: str,
        system_prompt: str,
    ) -> ChatTurnResult:
        body: dict[str, Any] = {
            "model": model,
            "messages": [{"role": "system", "content": system_prompt}, *messages],
        }
        if tools:
            body["tools"] = [
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
            body["tool_choice"] = "auto"

        async with httpx.AsyncClient(timeout=CHAT_TIMEOUT, transport=self._transport) as client:
            response = await client.post(
                f"{self._base_url}/chat/completions", headers=self._headers(), json=body
            )
        _raise_for_status(response, self._label)
        payload = _parse_json(response, self._label)

        choices = payload.get("choices") or []
        message: dict[str, Any] = {}
        if choices and isinstance(choices[0], dict):
            raw_message = choices[0].get("message")
            if isinstance(raw_message, dict):
                message = raw_message

        tool_calls: list[ToolCall] = []
        for entry in message.get("tool_calls") or []:
            if not isinstance(entry, dict):
                continue
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

        usage = payload.get("usage") or {}
        content = message.get("content")
        return ChatTurnResult(
            text=str(content) if content else None,
            tool_calls=tool_calls,
            input_tokens=int(usage.get("prompt_tokens") or 0),
            output_tokens=int(usage.get("completion_tokens") or 0),
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
            timeout=MODELS_TIMEOUT, transport=self._transport
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

        async with httpx.AsyncClient(timeout=CHAT_TIMEOUT, transport=self._transport) as client:
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


def build_client(
    config: AiProviderConfig, *, transport: httpx.AsyncBaseTransport | None = None
) -> BaseAiClient:
    """Construct the right client for a provider row. Raises
    `AiProviderError` if the row isn't usable (missing key or base URL)."""
    api_key = decrypted_api_key(config)

    if config.kind == AiProviderKind.ANTHROPIC:
        if not api_key:
            raise AiProviderError("No Anthropic API key is configured.")
        return AnthropicClient(api_key, transport=transport)

    if config.kind == AiProviderKind.GEMINI:
        if not api_key:
            raise AiProviderError("No Gemini API key is configured.")
        return GeminiClient(api_key, transport=transport)

    if config.kind == AiProviderKind.OPENAI:
        if not api_key:
            raise AiProviderError("No OpenAI API key is configured.")
        return OpenAICompatibleClient(
            api_key, OPENAI_API_BASE, AiProviderKind.OPENAI, transport=transport
        )

    if config.kind == AiProviderKind.OPENROUTER:
        # Listing models needs no key; a chat turn does. Not enforced here,
        # so an admin can still fetch the catalog before pasting a key.
        return OpenAICompatibleClient(
            api_key, OPENROUTER_API_BASE, AiProviderKind.OPENROUTER, transport=transport
        )

    if not config.base_url:
        raise AiProviderError("This OpenAI-compatible provider has no base URL configured.")
    return OpenAICompatibleClient(
        api_key, config.base_url, AiProviderKind.OPENAI_COMPATIBLE, transport=transport
    )
