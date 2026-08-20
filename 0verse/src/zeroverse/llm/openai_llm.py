"""OpenAI-compatible LLM backend — works with ANY gateway that speaks the OpenAI
Chat Completions API, including a self-hosted router/proxy.

Point it at your gateway with ``OPENAI_BASE_URL`` (+ ``OPENAI_API_KEY``); pick the
model with ``ZEROVERSE_LLM_MODEL``. Implements the provider-neutral ``LLM``
interface, so the rest of 0verse doesn't change. Install with the ``llm`` extra.
"""

from __future__ import annotations

import json
import os
from typing import Any

from .usage import TrackedLLM, record_sdk_usage

DEFAULT_MODEL = "gpt-4o-mini"


class OpenAILLM(TrackedLLM):
    def __init__(
        self,
        model: str = "",
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        client: Any | None = None,
    ) -> None:
        super().__init__()  # self.usage ledger — see llm/usage.py
        self.model = model or os.environ.get("ZEROVERSE_LLM_MODEL", DEFAULT_MODEL)
        self._base_url = base_url or os.environ.get("OPENAI_BASE_URL")
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self._client = client

    def _ensure_client(self) -> Any:
        if self._client is None:
            from openai import OpenAI  # lazy: package imports without the extra

            self._client = OpenAI(base_url=self._base_url, api_key=self._api_key)
        return self._client

    def complete_json(
        self, system: str, prompt: str, schema: dict[str, Any]
    ) -> dict[str, Any]:
        client = self._ensure_client()
        sys_msg = (
            f"{system}\n\nRespond ONLY with a JSON object matching this schema:\n"
            f"{json.dumps(schema)}"
        )
        try:
            resp = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": sys_msg},
                    {"role": "user", "content": prompt},
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
            )
            text = resp.choices[0].message.content or "{}"
            # Routers/local models don't always honor json_object cleanly — recover
            # the object robustly (fences, preamble) instead of crashing.
            from .jsonparse import extract_json

            out = extract_json(text)
        except Exception:
            self.usage.note_failed()
            raise
        # A bare gateway may omit `usage`; record_sdk_usage marks that UNREPORTED
        # rather than counting it as zero tokens.
        record_sdk_usage(
            self.usage, getattr(resp, "usage", None), "prompt_tokens", "completion_tokens"
        )
        self.usage.note_ok()
        return out
