"""Anthropic Messages-API backend — serves both Claude and GLM (z-ai).

GLM rides the *same* Anthropic Messages wire as Claude, just at a different
base_url (``https://api.z.ai/api/anthropic``) — that's the house convention from
pwnkit. So this one backend covers both: pass ``base_url``/``api_key`` for GLM, and
toggle ``structured`` (GLM's compat endpoint lacks Claude's structured-output
feature, so we fall back to schema-in-prompt + parse) and ``thinking``.

Install with the ``llm`` extra. See ``providers.build_llm`` for the routing.
"""

from __future__ import annotations

import json
from typing import Any

from .usage import TrackedLLM, record_sdk_usage

DEFAULT_MODEL = "claude-opus-4-8"


class AnthropicLLM(TrackedLLM):
    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        max_tokens: int = 4096,
        structured: bool = True,
        thinking: dict[str, Any] | None = None,
        client: Any | None = None,
    ) -> None:
        super().__init__()  # self.usage ledger — see llm/usage.py
        self.model = model
        self.max_tokens = max_tokens
        self.structured = structured
        # default to Claude adaptive thinking; callers (GLM) override or disable
        self.thinking: dict[str, Any] | None = (
            thinking if thinking is not None else {"type": "adaptive"}
        )
        self._base_url = base_url
        self._api_key = api_key
        self._client = client

    def _ensure_client(self) -> Any:
        if self._client is None:
            import anthropic  # lazy: keeps the package importable without the extra

            kw: dict[str, Any] = {}
            if self._base_url:
                kw["base_url"] = self._base_url
            if self._api_key:
                kw["api_key"] = self._api_key
            self._client = anthropic.Anthropic(**kw)
        return self._client

    def _create_message(
        self,
        system: str,
        messages: list[dict[str, Any]],
        schema: dict[str, Any],
    ) -> Any:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system,
            "messages": messages,
        }
        if self.thinking:
            kwargs["thinking"] = self.thinking
        if self.structured:
            kwargs["output_config"] = {
                "format": {"type": "json_schema", "schema": schema}
            }
        else:
            # GLM / compat endpoints: ask for JSON in the prompt and parse it.
            kwargs["system"] = (
                f"{system}\n\nRespond ONLY with a JSON object matching this schema:\n"
                f"{json.dumps(schema)}"
            )
        try:
            return self._ensure_client().messages.create(**kwargs)
        except Exception:
            self.usage.note_failed()
            raise

    @staticmethod
    def _extract_json(response: Any) -> dict[str, Any]:
        text = next(block.text for block in response.content if block.type == "text")
        # Real models (especially the GLM schema-in-prompt path) fence/prefix JSON.
        from .jsonparse import extract_json

        return extract_json(text)

    def _decode_response(self, response: Any) -> dict[str, Any]:
        try:
            out = self._extract_json(response)
        except Exception:
            self.usage.note_failed()
            raise
        # The Messages API always returns usage; record it so the eval harness
        # prices the run instead of reporting a confident 0 (this was dropped
        # entirely before — see llm/usage.py).
        record_sdk_usage(
            self.usage, getattr(response, "usage", None), "input_tokens", "output_tokens"
        )
        self.usage.note_ok()
        return out

    def begin_conversation(
        self,
        system: str,
        prompt: str,
        schema: dict[str, Any],
    ) -> AnthropicConversation | None:
        # Claude signs extended-thinking blocks and requires them to return
        # verbatim. Anthropic-compatible GLM does not require that round-trip,
        # so preserve its established one-shot behavior.
        if self._base_url is not None or self.thinking is None:
            return None
        return AnthropicConversation(self, system, prompt, schema)

    def complete_json(
        self, system: str, prompt: str, schema: dict[str, Any]
    ) -> dict[str, Any]:
        conversation = self.begin_conversation(system, prompt, schema)
        if conversation is not None:
            return conversation.complete_json()
        response = self._create_message(
            system,
            [{"role": "user", "content": prompt}],
            schema,
        )
        return self._decode_response(response)


class AnthropicConversation:
    """One in-process Claude Messages conversation with retained thinking blocks."""

    def __init__(
        self,
        llm: AnthropicLLM,
        system: str,
        prompt: str,
        schema: dict[str, Any],
    ) -> None:
        self._llm = llm
        self._system = system
        self._schema = schema
        self._model = llm.model
        self._messages: list[dict[str, Any]] = [
            {"role": "user", "content": prompt}
        ]

    def append_user(self, text: str) -> None:
        """Append a follow-up, merging adjacent user prompts when needed."""
        if not text.strip():
            return
        if self._messages and self._messages[-1]["role"] == "user":
            prior = self._messages[-1]["content"]
            if isinstance(prior, str):
                self._messages[-1]["content"] = f"{prior}\n\n{text}"
                return
        self._messages.append({"role": "user", "content": text})

    @staticmethod
    def _block_type(block: Any) -> str | None:
        value = block.get("type") if isinstance(block, dict) else getattr(block, "type", None)
        return value if isinstance(value, str) else None

    def _strip_thinking_for_model_switch(self) -> None:
        """Remove model-bound thinking blocks before a changed model sees history."""
        rebuilt: list[dict[str, Any]] = []
        for message in self._messages:
            role = message["role"]
            content = message["content"]
            if role == "assistant" and isinstance(content, list):
                content = [
                    block
                    for block in content
                    if self._block_type(block)
                    not in {"thinking", "redacted_thinking"}
                ]
                if not content:
                    continue
            if (
                role == "user"
                and rebuilt
                and rebuilt[-1]["role"] == "user"
                and isinstance(rebuilt[-1]["content"], str)
                and isinstance(content, str)
            ):
                rebuilt[-1]["content"] = f"{rebuilt[-1]['content']}\n\n{content}"
            else:
                rebuilt.append({"role": role, "content": content})
        self._messages = rebuilt

    def complete_json(self) -> dict[str, Any]:
        if self._llm.model != self._model:
            self._strip_thinking_for_model_switch()
            self._model = self._llm.model
        response = self._llm._create_message(
            self._system,
            self._messages,
            self._schema,
        )
        # The SDK accepts response.content directly on the next Messages request.
        # Do not serialize, reconstruct, filter, or summarize it: thinking,
        # redacted_thinking, and signatures are part of the assistant turn.
        self._messages.append({"role": "assistant", "content": response.content})
        return self._llm._decode_response(response)

    def budget_prompt(self) -> str:
        """Expose a stable approximation for the scheduler's budget gate."""
        return f"{self._system}\n\n{self._messages!r}"
