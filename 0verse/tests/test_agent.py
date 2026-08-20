"""LLM triage agent — exercised with MockLLM and an injected fake Claude client,
so it runs with no API key and no network."""

import json
from typing import Any

from zeroverse.agent import MockLLM, TriageAgent, Verdict
from zeroverse.analyze import Finding
from zeroverse.llm.anthropic_llm import AnthropicLLM

CMDI = Finding(
    source="getenv", sink="system", function="main",
    source_addr=0x1000, sink_addr=0x1010, path_len=4,
)


def test_triage_with_mock_llm() -> None:
    v = TriageAgent(MockLLM()).triage(CMDI, "char *p = getenv(\"CMD\"); system(p);")
    assert isinstance(v, Verdict)
    assert v.is_real is True
    assert v.severity == "high"
    assert "CWE-78" in v.bug_class
    assert v.input_example  # non-empty candidate trigger


def test_triage_buffer_overflow() -> None:
    of = Finding(source="read", sink="strcpy", function="f", source_addr=0, sink_addr=8, path_len=0)
    v = TriageAgent(MockLLM()).triage(of, "strcpy(buf, big);")
    assert v.is_real is True and "CWE-120" in v.bug_class


def test_triage_fmtstring_is_real() -> None:
    # the fmtstring lens proved the format operand is tainted (origin tag); the
    # MockLLM stub must flag it real so its no-trigger differential oracle runs
    # (instead of falling through to an unattributed whole-program fuzz crash).
    fs = Finding(
        source="read", sink="printf", function="sudo_debug",
        source_addr=0, sink_addr=0x10, path_len=0, origin="bugclass:fmtstring",
    )
    v = TriageAgent(MockLLM()).triage(fs, "printf(&format, &format);")
    assert v.is_real is True and "CWE-134" in v.bug_class
    # a printf NOT tagged by the fmtstring lens stays filtered (no origin tag)
    plain = Finding(source="read", sink="printf", function="f",
                    source_addr=0, sink_addr=0, path_len=0)
    assert TriageAgent(MockLLM()).triage(plain, 'printf("ok\\n");').is_real is False


def test_triage_negative() -> None:
    benign = Finding(
        source="read", sink="malloc", function="f",
        source_addr=0, sink_addr=8, path_len=2,
    )
    v = TriageAgent(MockLLM()).triage(benign, "malloc(n);")
    assert v.is_real is False and v.severity == "info"


def test_verdict_from_json() -> None:
    v = Verdict.from_json({
        "is_real": True, "bug_class": "CWE-120", "severity": "critical",
        "explanation": "x", "input_example": "AAAA",
    })
    assert v.bug_class == "CWE-120" and v.severity == "critical"


# --- AnthropicLLM with an injected fake client (no SDK, no network) ---------

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


class _FakeClient:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.messages = _Messages(payload)


def test_anthropic_llm_structured_output() -> None:
    payload = {
        "is_real": True, "bug_class": "CWE-78", "severity": "high",
        "explanation": "tainted env var reaches system()", "input_example": 'CMD="; id"',
    }
    client = _FakeClient(payload)
    llm = AnthropicLLM(client=client)
    v = TriageAgent(llm).triage(CMDI, "system(getenv(\"CMD\"));")
    assert v.is_real and v.bug_class == "CWE-78"
    # defaults: claude-opus-4-8 + adaptive thinking + json_schema output
    sent = client.messages.calls[0]
    assert sent["model"] == "claude-opus-4-8"
    assert sent["thinking"] == {"type": "adaptive"}
    assert sent["output_config"]["format"]["type"] == "json_schema"



def test_anthropic_conversation_replays_thinking_blocks_verbatim() -> None:
    class Block:
        def __init__(self, block_type: str, **fields: Any) -> None:
            self.type = block_type
            for key, value in fields.items():
                setattr(self, key, value)

    class Response:
        def __init__(self, content: list[Any]) -> None:
            self.content = content

    class Messages:
        def __init__(self, responses: list[Response]) -> None:
            self.responses = responses
            self.calls: list[dict[str, Any]] = []

        def create(self, **kwargs: Any) -> Response:
            self.calls.append(kwargs)
            return self.responses.pop(0)

    class Client:
        def __init__(self, messages: Messages) -> None:
            self.messages = messages

    first_content = [
        Block("thinking", thinking="inspect the callee", signature="sig-1"),
        Block("text", text=json.dumps({"action": "call"})),
    ]
    second_content = [
        Block("thinking", thinking="inspect the caller", signature="sig-2"),
        Block("text", text=json.dumps({"action": "verdict"})),
    ]
    third_content = [Block("text", text=json.dumps({"action": "verdict"}))]
    messages = Messages(
        [Response(first_content), Response(second_content), Response(third_content)]
    )
    llm = AnthropicLLM(client=Client(messages))
    conversation = llm.begin_conversation("system", "opening", {"type": "object"})
    assert conversation is not None

    assert conversation.complete_json() == {"action": "call"}
    conversation.append_user("tool observation")
    assert conversation.complete_json() == {"action": "verdict"}

    second_request = messages.calls[1]["messages"]
    assert second_request[1]["content"] is first_content
    assert second_request[2] == {"role": "user", "content": "tool observation"}

    llm.model = "claude-sonnet-4-6"
    conversation.append_user("switch models")
    assert conversation.complete_json() == {"action": "verdict"}
    third_request = messages.calls[2]["messages"]
    for message in third_request:
        if message["role"] == "assistant":
            assert all(block.type != "thinking" for block in message["content"])