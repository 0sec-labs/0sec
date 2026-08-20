"""Provider routing + the GLM (z-ai) backend over the Anthropic wire."""

import json
from typing import Any

from zeroverse.agent import TriageAgent
from zeroverse.analyze import Finding
from zeroverse.llm.anthropic_llm import AnthropicLLM
from zeroverse.llm.providers import (
    ZAI_DEFAULT_BASE_URL,
    ZAI_DEFAULT_MODEL,
    build_llm,
    detect_provider,
)


def test_detect_provider_by_model() -> None:
    assert detect_provider("glm-4.6") == "glm"
    assert detect_provider("glm-5.2") == "glm"
    assert detect_provider("gpt-4o") == "openai"
    assert detect_provider("o3-mini") == "openai"
    assert detect_provider("claude-opus-4-8") == "claude"


def test_build_glm_uses_anthropic_wire() -> None:
    llm = build_llm(provider="glm")
    assert isinstance(llm, AnthropicLLM)
    assert llm._base_url == ZAI_DEFAULT_BASE_URL      # https://api.z.ai/api/anthropic
    assert llm.model == ZAI_DEFAULT_MODEL             # glm-4.6
    assert llm.structured is False                    # GLM lacks structured outputs
    assert llm.thinking == {"type": "enabled", "budget_tokens": 2048}


def test_build_aliases_and_claude() -> None:
    assert build_llm(provider="z-ai").model.startswith("glm")
    assert build_llm(provider="anthropic").model == "claude-opus-4-8"


def test_codex_provider_builds(tmp_path: Any) -> None:
    # codex now routes to the ChatGPT-OAuth Responses backend (no metered key).
    import os

    from zeroverse.llm.codex_llm import CodexOAuthLLM

    auth = tmp_path / "auth.json"
    auth.write_text(json.dumps({"tokens": {"access_token": "x", "account_id": "a"}}))
    os.environ["ZEROVERSE_CODEX_AUTH"] = str(auth)
    try:
        llm = build_llm(provider="codex")
    finally:
        os.environ.pop("ZEROVERSE_CODEX_AUTH", None)
    assert isinstance(llm, CodexOAuthLLM)
    assert llm.model == "gpt-5.5"


# --- GLM backend over a fake Anthropic client (no network) -----------------

class _Block:
    type = "text"
    def __init__(self, text: str) -> None:
        self.text = text


class _Resp:
    def __init__(self, text: str) -> None:
        self.content = [_Block(text)]


class _Messages:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> _Resp:
        self.calls.append(kwargs)
        return _Resp(json.dumps(self._payload))


class _FakeAnthropic:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.messages = _Messages(payload)


def test_glm_backend_no_structured_output() -> None:
    payload = {
        "is_real": True, "bug_class": "CWE-78", "severity": "high",
        "explanation": "x", "input_example": "y",
    }
    client = _FakeAnthropic(payload)
    glm = AnthropicLLM(model="glm-4.6", structured=False,
                       thinking={"type": "enabled", "budget_tokens": 2048}, client=client)
    finding = Finding("getenv", "system", "main", 0x1000, 0x1010, 4)
    v = TriageAgent(glm).triage(finding, "system(getenv(\"CMD\"));")
    assert v.is_real and v.bug_class == "CWE-78"
    sent = client.messages.calls[0]
    assert sent["model"] == "glm-4.6"
    assert "output_config" not in sent                # GLM path: no structured output
    assert "schema" in sent["system"].lower()         # schema embedded in the prompt
    assert sent["thinking"] == {"type": "enabled", "budget_tokens": 2048}
