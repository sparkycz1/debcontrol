"""Provider-neutral types and the client interface every AI provider
implements.

**Why `messages` is provider-native rather than a shared format.** The
three wire formats this app speaks disagree, in ways that matter, about
what must be echoed back for a tool round trip to be accepted:

- Anthropic wants the assistant turn re-sent as the exact content-block
  array it returned (including the `tool_use` block), followed by a `user`
  turn holding `tool_result` blocks keyed by `tool_use_id`.
- OpenAI-style APIs want the assistant message re-sent verbatim with its
  `tool_calls`, followed by one `{"role": "tool", "tool_call_id": ...}`
  message per call.
- Gemini wants a `model` turn holding the `functionCall` part, followed by
  a `user` turn holding a `functionResponse` part matched by function name
  (and `id`, when the provider supplied one).

A single shared history format would therefore have to be translated back
into whichever of those three the provider actually demands — and any field
the shared format didn't model (Anthropic's block ids, OpenAI's
`tool_call_id`, Gemini's part ordering) would be lost in the round trip,
producing a history the provider rejects. So `send()` takes each provider's
own list of message dicts, and each client also knows how to *build* those
dicts (`build_user_message`, `build_tool_result_messages`). What gets
persisted in `AiMessage.provider_native` is exactly those dicts, so a later
turn can replay the conversation without reconstructing anything.

`ChatTurnResult.raw_assistant_message` is the same idea for one turn: it
holds whatever provider-native shape has to be appended to history for that
provider's next call.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any


class AiProviderError(Exception):
    """A provider call failed — bad key, HTTP error, unparseable response.

    Always carries a message safe to show a user in the chat thread, and
    never contains the API key (see `app.ai.providers`, which builds these
    from the status code and a truncated body, not from request headers).
    """


@dataclass(frozen=True)
class ToolDefinition:
    """One tool as offered to the model.

    `parameters` is a JSON Schema object kept deliberately simple — object
    / string / enum / array-of-string only, no `$schema`, no `$ref`, no
    nested objects — because Gemini's schema dialect is a subset of JSON
    Schema and rejects several keywords the other two accept. Keeping the
    catalog inside the intersection means one schema works for all three
    providers unchanged. See `app.ai.tools`.
    """

    name: str
    description: str
    parameters: dict[str, Any]


@dataclass(frozen=True)
class ToolCall:
    """One tool invocation the model asked for.

    `id` is the provider's own correlation id where it has one (Anthropic's
    `tool_use.id`, OpenAI's `tool_calls[].id`, Gemini's optional
    `functionCall.id`); for Gemini responses without one it's synthesized
    locally, since Gemini matches a `functionResponse` by function *name*.
    """

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class ChatTurnResult:
    text: str | None
    tool_calls: list[ToolCall] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    # Provider-native shape to append to history before the next call —
    # see the module docstring.
    raw_assistant_message: Any = None


@dataclass(frozen=True)
class ModelInfo:
    id: str
    display_name: str | None = None


class BaseAiClient(abc.ABC):
    """One provider's HTTP surface: list its models, and run one chat turn.

    Instances are cheap and short-lived — one is built per operation from
    an `AiProviderConfig` (see `app.ai.providers.build_client`), holds the
    decrypted API key only for the duration of that operation, and is never
    cached or shared.
    """

    #: For audit/usage records and error messages.
    kind_value: str

    @abc.abstractmethod
    async def list_models(self) -> list[ModelInfo]:
        """Fetch the provider's catalog. Raises `AiProviderError`."""

    @abc.abstractmethod
    async def send(
        self,
        messages: list[Any],
        tools: list[ToolDefinition],
        model: str,
        system_prompt: str,
    ) -> ChatTurnResult:
        """Run one chat turn. `messages` is this provider's own history
        representation (see the module docstring). Raises `AiProviderError`."""

    @abc.abstractmethod
    def build_user_message(self, text: str) -> Any:
        """This provider's native representation of a user turn."""

    @abc.abstractmethod
    def build_tool_result_messages(
        self, result: ChatTurnResult, outputs: list[tuple[ToolCall, str]]
    ) -> list[Any]:
        """The native messages to append after `result` so the model sees
        the outcome of the tool calls it asked for: the echoed assistant
        turn first, then the tool results, in whatever shape this provider
        requires."""
