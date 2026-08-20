"""OpenAI-compatible backend (works with any router) — injected fake client,
so it runs with no SDK and no network."""

import json
from typing import Any

from zeroverse.agent import TriageAgent, Verdict
from zeroverse.analyze import Finding
from zeroverse.llm.openai_llm import OpenAILLM

CMDI = Finding("getenv", "system", "main", 0x1000, 0x1010, 4)


class _Msg:
    def __init__(self, content: str) -> None:
        self.content = content


class _Choice:
    def __init__(self, content: str) -> None:
        self.message = _Msg(content)


class _Resp:
    def __init__(self, content: str) -> None:
        self.choices = [_Choice(content)]


class _Completions:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> _Resp:
        self.calls.append(kwargs)
        return _Resp(json.dumps(self._payload))


class _Chat:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.completions = _Completions(payload)


class _FakeOpenAI:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.chat = _Chat(payload)


def test_openai_router_structured_output() -> None:
    payload = {
        "is_real": True, "bug_class": "CWE-78", "severity": "high",
        "explanation": "env var reaches system()", "input_example": 'CMD="; id"',
    }
    client = _FakeOpenAI(payload)
    llm = OpenAILLM(model="my-router-model", client=client)
    v = TriageAgent(llm).triage(CMDI, "system(getenv(\"CMD\"));")
    assert isinstance(v, Verdict) and v.is_real and v.bug_class == "CWE-78"
    sent = client.chat.completions.calls[0]
    assert sent["model"] == "my-router-model"
    assert sent["response_format"] == {"type": "json_object"}
    # schema is embedded in the system message for broad router compatibility
    assert "schema" in sent["messages"][0]["content"].lower()
