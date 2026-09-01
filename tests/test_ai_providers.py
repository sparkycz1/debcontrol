"""Provider client tests.

Every provider call is served by a mock transport — no test in this file
(or anywhere else in the suite) may reach a real provider, both for the
obvious reason and because these assertions are about the request this app
*builds*, which a live API would only answer, never confirm.

Two mock-transport flavors, matching `app.ai.providers`' own split:
`_transport` (plain `httpx.MockTransport`) for `OpenRouterClient`/
`GeminiClient`, which build on plain `httpx`; `_transport2`
(`httpx2.MockTransport`) for `AnthropicClient`/`OpenAICompatibleClient`,
which hand their SDK an `httpx2.AsyncClient` as `http_client=` —
`anthropic`/`openai` build on `httpx2` (a distinct package from plain
`httpx`) for their own HTTP layer, not something this app chose, just how
those SDKs currently ship.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import httpx2
import pytest

from app.ai.base import AiProviderError, ToolDefinition
from app.ai.providers import (
    AnthropicClient,
    GeminiClient,
    OpenAICompatibleClient,
    OpenRouterClient,
    build_client,
)
from app.core.security import encrypt_secret
from app.db.models.ai_provider import AiProviderConfig, AiProviderKind

TOOLS = [
    ToolDefinition(
        name="list_machines",
        description="List machines.",
        parameters={
            "type": "object",
            "properties": {"group_name": {"type": "string"}},
            "required": [],
        },
    ),
    ToolDefinition(
        name="list_groups",
        description="List groups.",
        parameters={"type": "object", "properties": {}, "required": []},
    ),
]


def _transport(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def _transport2(
    handler: Callable[[httpx2.Request], httpx2.Response],
) -> httpx2.MockTransport:
    return httpx2.MockTransport(handler)


# --- Anthropic ---------------------------------------------------------------


async def test_anthropic_list_models_follows_pagination():
    seen_params = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen_params.append(dict(request.url.params))
        assert request.headers["x-api-key"] == "secret-key"
        assert request.headers["anthropic-version"] == "2023-06-01"
        if "after_id" not in request.url.params:
            return httpx2.Response(
                200,
                json={
                    "data": [{"id": "claude-a", "display_name": "Claude A"}],
                    "has_more": True,
                    "last_id": "claude-a",
                },
            )
        return httpx2.Response(
            200, json={"data": [{"id": "claude-b"}], "has_more": False, "last_id": None}
        )

    client = AnthropicClient("secret-key", transport=_transport2(handler))
    models = await client.list_models()

    assert [m.id for m in models] == ["claude-a", "claude-b"]
    assert models[0].display_name == "Claude A"
    assert seen_params[1]["after_id"] == "claude-a"


async def test_anthropic_send_text_response():
    captured: dict[str, Any] = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx2.Response(
            200,
            json={
                "content": [{"type": "text", "text": "Hello there"}],
                "usage": {"input_tokens": 11, "output_tokens": 3},
            },
        )

    client = AnthropicClient("secret-key", transport=_transport2(handler))
    result = await client.send(
        [{"role": "user", "content": "hi"}], TOOLS, "claude-a", "SYSTEM"
    )

    body = captured["body"]
    assert captured["url"] == "https://api.anthropic.com/v1/messages"
    assert body["system"] == "SYSTEM"
    assert body["model"] == "claude-a"
    assert body["tool_choice"] == {"type": "auto"}
    assert [t["name"] for t in body["tools"]] == ["list_machines", "list_groups"]
    # Anthropic names the schema field `input_schema`, not `parameters`.
    assert body["tools"][0]["input_schema"]["type"] == "object"

    assert result.text == "Hello there"
    assert result.tool_calls == []
    assert (result.input_tokens, result.output_tokens) == (11, 3)


async def test_anthropic_send_tool_call_and_history_round_trip():
    blocks = [
        {"type": "text", "text": "Looking that up."},
        {"type": "tool_use", "id": "tu_1", "name": "list_machines", "input": {"group_name": "web"}},
    ]

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            200, json={"content": blocks, "usage": {"input_tokens": 5, "output_tokens": 7}}
        )

    client = AnthropicClient("secret-key", transport=_transport2(handler))
    result = await client.send([], TOOLS, "claude-a", "SYSTEM")

    assert len(result.tool_calls) == 1
    call = result.tool_calls[0]
    assert (call.id, call.name, call.arguments) == ("tu_1", "list_machines", {"group_name": "web"})
    # The assistant turn must be echoed back verbatim, blocks and all.
    assert result.raw_assistant_message == {"role": "assistant", "content": blocks}

    follow_up = client.build_tool_result_messages(result, [(call, "machine-a")])
    assert follow_up[0] == {"role": "assistant", "content": blocks}
    assert follow_up[1] == {
        "role": "user",
        "content": [{"type": "tool_result", "tool_use_id": "tu_1", "content": "machine-a"}],
    }


async def test_anthropic_http_error_becomes_provider_error_without_the_key():
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(401, text='{"error": "invalid x-api-key"}')

    client = AnthropicClient("super-secret-key", transport=_transport2(handler))
    with pytest.raises(AiProviderError) as excinfo:
        await client.list_models()

    assert "401" in str(excinfo.value)
    assert "super-secret-key" not in str(excinfo.value)


# --- OpenAI-style (OpenAI / any self-hosted OpenAI-compatible endpoint) ------


async def test_openai_list_models():
    def handler(request: httpx2.Request) -> httpx2.Response:
        assert request.headers["Authorization"] == "Bearer sk-test"
        assert str(request.url) == "https://api.openai.com/v1/models"
        return httpx2.Response(200, json={"data": [{"id": "gpt-x"}, {"id": "gpt-y"}]})

    client = OpenAICompatibleClient(
        "sk-test",
        "https://api.openai.com/v1",
        AiProviderKind.OPENAI,
        transport=_transport2(handler),
    )
    assert [m.id for m in await client.list_models()] == ["gpt-x", "gpt-y"]


async def test_openai_send_text_and_system_prompt_placement():
    captured: dict[str, Any] = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx2.Response(
            200,
            json={
                "choices": [{"message": {"role": "assistant", "content": "done"}}],
                "usage": {"prompt_tokens": 9, "completion_tokens": 2},
            },
        )

    client = OpenAICompatibleClient(
        "sk-test",
        "https://api.openai.com/v1",
        AiProviderKind.OPENAI,
        transport=_transport2(handler),
    )
    result = await client.send([{"role": "user", "content": "hi"}], TOOLS, "gpt-x", "SYSTEM")

    body = captured["body"]
    assert captured["url"] == "https://api.openai.com/v1/chat/completions"
    # The system prompt is a message here, not a top-level field.
    assert body["messages"][0] == {"role": "system", "content": "SYSTEM"}
    assert body["tool_choice"] == "auto"
    assert body["tools"][0]["type"] == "function"
    assert body["tools"][0]["function"]["name"] == "list_machines"

    assert result.text == "done"
    assert (result.input_tokens, result.output_tokens) == (9, 2)


async def test_openai_send_tool_call_parses_json_arguments():
    message = {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": "call_1",
                "type": "function",
                "function": {
                    "name": "list_machines",
                    "arguments": '{"group_name": "web"}',
                },
            }
        ],
    }

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json={"choices": [{"message": message}], "usage": {}})

    client = OpenAICompatibleClient(
        None,
        "https://litellm.internal/v1",
        AiProviderKind.OPENAI_COMPATIBLE,
        transport=_transport2(handler),
    )
    result = await client.send([], TOOLS, "some/model", "SYSTEM")

    call = result.tool_calls[0]
    assert call.arguments == {"group_name": "web"}
    follow_up = client.build_tool_result_messages(result, [(call, "machine-a")])
    # Not an exact `== message` anymore: the SDK's own `.model_dump(...,
    # exclude_none=True)` drops `"content": None` entirely rather than
    # keeping the explicit null the raw wire format used — functionally
    # identical (both mean "no content") once replayed to the API, just no
    # longer byte-for-byte the same dict this test used to build by hand.
    assert follow_up[0] == {k: v for k, v in message.items() if v is not None}
    assert follow_up[1] == {"role": "tool", "tool_call_id": "call_1", "content": "machine-a"}


async def test_openai_compatible_uses_the_configured_base_url():
    def handler(request: httpx2.Request) -> httpx2.Response:
        assert str(request.url) == "https://litellm.internal/v1/models"
        return httpx2.Response(200, json={"data": [{"id": "local-model"}]})

    client = OpenAICompatibleClient(
        None,
        "https://litellm.internal/v1/",
        AiProviderKind.OPENAI_COMPATIBLE,
        transport=_transport2(handler),
    )
    assert [m.id for m in await client.list_models()] == ["local-model"]


# --- OpenRouter ---------------------------------------------------------------
# OpenRouter's own SDK (`openrouter`, not `openai`) speaks the identical
# OpenAI wire format, so these mirror the OpenAI-style tests above almost
# line for line — only the client class (and the fact that a key is
# genuinely optional here) differs.


async def test_openrouter_list_models():
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://openrouter.ai/api/v1/models"
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "id": "openai/gpt-5",
                        "name": "GPT-5",
                        "created": 1,
                        "canonical_slug": "openai/gpt-5",
                        "context_length": 128000,
                        "architecture": {
                            "input_modalities": ["text"],
                            "output_modalities": ["text"],
                            "tokenizer": "x",
                            "modality": "text->text",
                        },
                        "links": {"details": "https://openrouter.ai/openai/gpt-5"},
                        "default_parameters": None,
                        "per_request_limits": None,
                        "pricing": {"prompt": "0", "completion": "0"},
                        "supported_parameters": [],
                        "supported_voices": None,
                        "top_provider": {"is_moderated": False},
                    }
                ]
            },
        )

    # No key at all — listing models is not supposed to require one.
    client = OpenRouterClient(None, transport=_transport(handler))
    models = await client.list_models()

    assert [m.id for m in models] == ["openai/gpt-5"]
    assert models[0].display_name == "GPT-5"


async def test_openrouter_send_text_and_system_prompt_placement():
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "id": "gen-1",
                "created": 1,
                "model": "openai/gpt-5",
                "object": "chat.completion",
                "system_fingerprint": None,
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": "done"},
                    }
                ],
                "usage": {"prompt_tokens": 9, "completion_tokens": 2, "total_tokens": 11},
            },
        )

    client = OpenRouterClient("or-key", transport=_transport(handler))
    result = await client.send(
        [{"role": "user", "content": "hi"}], TOOLS, "openai/gpt-5", "SYSTEM"
    )

    body = captured["body"]
    assert captured["url"] == "https://openrouter.ai/api/v1/chat/completions"
    assert body["messages"][0] == {"role": "system", "content": "SYSTEM"}
    assert body["tool_choice"] == "auto"
    assert body["tools"][0]["type"] == "function"
    assert body["tools"][0]["function"]["name"] == "list_machines"

    assert result.text == "done"
    assert (result.input_tokens, result.output_tokens) == (9, 2)


async def test_openrouter_send_tool_call_parses_json_arguments():
    message = {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": "call_1",
                "type": "function",
                "function": {"name": "list_machines", "arguments": '{"group_name": "web"}'},
            }
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "gen-1",
                "created": 1,
                "model": "m",
                "object": "chat.completion",
                "system_fingerprint": None,
                "choices": [{"index": 0, "finish_reason": "tool_calls", "message": message}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            },
        )

    # No key here either — a chat turn against a provider that actually
    # needs one still fails normally, with OpenRouter's own 401.
    client = OpenRouterClient(None, transport=_transport(handler))
    result = await client.send(
        [{"role": "user", "content": "hi"}], TOOLS, "m", "SYSTEM"
    )

    call = result.tool_calls[0]
    assert call.arguments == {"group_name": "web"}
    follow_up = client.build_tool_result_messages(result, [(call, "machine-a")])
    assert follow_up[0] == message
    assert follow_up[1] == {"role": "tool", "tool_call_id": "call_1", "content": "machine-a"}


async def test_openrouter_http_error_becomes_provider_error_without_the_key():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": "invalid key", "code": 401}})

    client = OpenRouterClient("super-secret-key", transport=_transport(handler))
    with pytest.raises(AiProviderError) as excinfo:
        await client.list_models()

    assert "401" in str(excinfo.value)
    assert "super-secret-key" not in str(excinfo.value)


# --- Gemini ------------------------------------------------------------------


async def test_gemini_list_models_filters_and_strips_prefix():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-goog-api-key"] == "gem-key"
        return httpx.Response(
            200,
            json={
                "models": [
                    {
                        "name": "models/gemini-pro",
                        "displayName": "Gemini Pro",
                        # Real REST field name — the SDK maps it to its own
                        # `supported_actions` internally (checked live, not
                        # assumed: it does *not* accept `supportedActions`).
                        "supportedGenerationMethods": ["generateContent"],
                    },
                    {
                        "name": "models/embedding-001",
                        "supportedGenerationMethods": ["embedContent"],
                    },
                ]
            },
        )

    client = GeminiClient("gem-key", transport=_transport(handler))
    models = await client.list_models()

    assert [m.id for m in models] == ["gemini-pro"]
    assert models[0].display_name == "Gemini Pro"


async def test_gemini_send_builds_the_documented_request_shape():
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "candidates": [{"content": {"role": "model", "parts": [{"text": "ok"}]}}],
                "usageMetadata": {"promptTokenCount": 4, "candidatesTokenCount": 6},
            },
        )

    client = GeminiClient("gem-key", transport=_transport(handler))
    result = await client.send(
        [{"role": "user", "parts": [{"text": "hi"}]}], TOOLS, "gemini-pro", "SYSTEM"
    )

    body = captured["body"]
    assert captured["path"] == "/v1beta/models/gemini-pro:generateContent"
    assert body["systemInstruction"]["parts"] == [{"text": "SYSTEM"}]
    declarations = body["tools"][0]["functionDeclarations"]
    assert [d["name"] for d in declarations] == ["list_machines", "list_groups"]
    # A no-argument tool omits `parameters` entirely rather than sending an
    # empty properties object — Gemini's schema dialect wants it left out.
    assert "parameters" in declarations[0]
    assert "parameters" not in declarations[1]

    assert result.text == "ok"
    assert (result.input_tokens, result.output_tokens) == (4, 6)


async def test_gemini_send_tool_call_and_function_response_round_trip():
    parts = [
        {"functionCall": {"name": "list_machines", "id": "fc_1", "args": {"group_name": "web"}}}
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"candidates": [{"content": {"role": "model", "parts": parts}}]}
        )

    client = GeminiClient("gem-key", transport=_transport(handler))
    result = await client.send(
        [{"role": "user", "parts": [{"text": "hi"}]}], TOOLS, "gemini-pro", "SYSTEM"
    )

    call = result.tool_calls[0]
    assert (call.id, call.name, call.arguments) == ("fc_1", "list_machines", {"group_name": "web"})
    assert result.raw_assistant_message == {"role": "model", "parts": parts}

    follow_up = client.build_tool_result_messages(result, [(call, "machine-a")])
    assert follow_up[0] == {"role": "model", "parts": parts}
    assert follow_up[1] == {
        "role": "user",
        "parts": [
            {
                "functionResponse": {
                    "name": "list_machines",
                    "response": {"result": "machine-a"},
                    "id": "fc_1",
                }
            }
        ],
    }


async def test_gemini_synthesized_call_id_is_not_echoed_back():
    """A response with no `id` gets a locally generated one, which must not
    be sent back as if the provider had issued it."""
    parts = [{"functionCall": {"name": "list_groups", "args": {}}}]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"candidates": [{"content": {"role": "model", "parts": parts}}]}
        )

    client = GeminiClient("gem-key", transport=_transport(handler))
    result = await client.send(
        [{"role": "user", "parts": [{"text": "hi"}]}], TOOLS, "gemini-pro", "SYSTEM"
    )
    follow_up = client.build_tool_result_messages(result, [(result.tool_calls[0], "none")])

    assert "id" not in follow_up[1]["parts"][0]["functionResponse"]


async def test_gemini_http_error_becomes_provider_error_without_the_key():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": "invalid api key", "code": 401}})

    client = GeminiClient("super-secret-key", transport=_transport(handler))
    with pytest.raises(AiProviderError) as excinfo:
        await client.list_models()

    assert "401" in str(excinfo.value)
    assert "super-secret-key" not in str(excinfo.value)


# --- The factory -------------------------------------------------------------


def test_build_client_picks_the_right_implementation():
    def config(kind: AiProviderKind, **kwargs: Any) -> AiProviderConfig:
        return AiProviderConfig(kind=kind, api_key_encrypted=encrypt_secret("k"), **kwargs)

    assert isinstance(build_client(config(AiProviderKind.ANTHROPIC)), AnthropicClient)
    assert isinstance(build_client(config(AiProviderKind.GEMINI)), GeminiClient)
    assert isinstance(build_client(config(AiProviderKind.OPENAI)), OpenAICompatibleClient)
    assert isinstance(build_client(config(AiProviderKind.OPENROUTER)), OpenRouterClient)
    assert isinstance(
        build_client(config(AiProviderKind.OPENAI_COMPATIBLE, base_url="https://x/v1")),
        OpenAICompatibleClient,
    )


def test_build_client_refuses_an_unconfigured_provider():
    with pytest.raises(AiProviderError):
        build_client(AiProviderConfig(kind=AiProviderKind.ANTHROPIC))
    with pytest.raises(AiProviderError):
        build_client(
            AiProviderConfig(
                kind=AiProviderKind.OPENAI_COMPATIBLE, api_key_encrypted=encrypt_secret("k")
            )
        )
