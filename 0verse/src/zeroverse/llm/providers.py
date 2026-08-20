"""Provider routing — build the right LLM backend from a provider name or model id.

Mirrors the pwnkit house convention (engine ``llm-api.ts``):
  * route by **model-id prefix** first (``glm*`` -> z-ai, ``gpt-*``/``o[1-9]`` -> openai,
    ``claude*`` -> anthropic),
  * else walk an env-key priority ladder.

GLM (z-ai) rides the Anthropic Messages wire at ``https://api.z.ai/api/anthropic``
with ``Z_AI_API_KEY`` — so it's just the Anthropic backend with a base_url override.

This module is intentionally self-contained so it can be lifted into a shared
``0llm`` Python package used across the Python tools (0verse, noeris, ...).
"""

from __future__ import annotations

import os
import re

from ..agent import LLM
from .anthropic_llm import DEFAULT_MODEL as CLAUDE_DEFAULT
from .anthropic_llm import AnthropicLLM
from .openai_llm import OpenAILLM

# z-ai (GLM) — Anthropic-compatible endpoint, NOT OpenAI-compatible.
ZAI_DEFAULT_BASE_URL = "https://api.z.ai/api/anthropic"
ZAI_DEFAULT_MODEL = "glm-4.6"

_ALIASES = {"anthropic": "claude", "z-ai": "glm", "zai": "glm", "chatgpt-codex": "codex"}


def _is_glm(m: str) -> bool:
    return "glm" in m or m.startswith("z-ai/")


def _is_gpt(m: str) -> bool:
    return m.startswith("gpt-") or bool(re.match(r"^o[1-9]", m))


def _is_claude(m: str) -> bool:
    return m.startswith("claude") or any(x in m for x in ("sonnet", "opus", "haiku"))


def detect_provider(model: str | None = None) -> str:
    """Pick a provider from the model id, else from which API keys are present."""
    m = (model or "").lower()
    if m:
        if _is_glm(m):
            return "glm"
        if _is_claude(m):
            return "claude"
        if _is_gpt(m):
            return "openai"
    # env-key priority ladder. A metered key wins; the ChatGPT-OAuth Codex
    # credential is the last resort (it's a subscription, not a billed key).
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "claude"
    if os.environ.get("Z_AI_API_KEY"):
        return "glm"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    from .codex_llm import codex_auth_available

    if codex_auth_available():
        return "codex"
    return "claude"


def build_llm(provider: str | None = None, model: str | None = None) -> LLM:
    """Construct an LLM backend. `provider` overrides routing; else infer from model/env."""
    prov = _ALIASES.get((provider or "").lower(), provider) if provider else None
    prov = prov or detect_provider(model)

    if prov == "glm":
        budget = int(os.environ.get("ZEROVERSE_ZAI_THINKING_BUDGET", "2048"))
        return AnthropicLLM(
            model=model or os.environ.get("ZEROVERSE_LLM_MODEL", ZAI_DEFAULT_MODEL),
            base_url=os.environ.get("Z_AI_BASE_URL", ZAI_DEFAULT_BASE_URL),
            api_key=os.environ.get("Z_AI_API_KEY"),
            structured=False,  # GLM compat endpoint lacks structured outputs
            thinking={"type": "enabled", "budget_tokens": budget} if budget > 0 else None,
        )
    if prov == "claude":
        return AnthropicLLM(model=model or CLAUDE_DEFAULT)
    if prov == "gateway":
        # the 0llm gateway (sidecar at localhost, or your hosted router) — it does
        # the real provider routing/codex/GLM/ensemble; 0verse just talks OpenAI to it.
        return OpenAILLM(
            model=model or os.environ.get("ZEROLLM_MODEL", "gpt-5.5"),
            base_url=os.environ.get("LLM_GATEWAY_URL", "http://localhost:8080/v1"),
            api_key=os.environ.get("LLM_GATEWAY_TOKEN", "gateway"),
        )
    if prov == "openai":
        return OpenAILLM(model=model or "")
    if prov == "codex":
        # ChatGPT-OAuth Responses API (no metered key needed) — see codex_llm.
        from .codex_llm import DEFAULT_MODEL as CODEX_DEFAULT
        from .codex_llm import CodexOAuthLLM

        return CodexOAuthLLM(model=model or os.environ.get("ZEROVERSE_LLM_MODEL", CODEX_DEFAULT))
    raise ValueError(f"unknown LLM provider: {prov!r}")
