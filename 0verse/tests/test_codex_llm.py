"""ChatGPT-OAuth (Codex) Responses backend — SSE parse, JSON recovery, retry,
token refresh, and graceful-degrade wiring, all exercised with a fake transport
(no network)."""

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

from zeroverse.agent import VERDICT_SCHEMA, TriageAgent, Verdict
from zeroverse.analyze import Finding
from zeroverse.llm.codex_llm import (
    CodexOAuthLLM,
    LLMAuthError,
    LLMError,
    LLMTransientError,
)

CMDI = Finding("getenv", "system", "main", 0x1000, 0x1010, 4)
VERDICT = {
    "is_real": True, "bug_class": "CWE-78", "severity": "high",
    "explanation": "env var reaches system()", "input_example": 'CMD="; id"',
}


def _sse(text: str, *, usage: dict[str, int] | None = None) -> list[bytes]:
    """Build a Responses API SSE stream that emits `text` as output_text deltas."""
    lines: list[bytes] = []
    for ch in (text[i : i + 8] for i in range(0, len(text), 8)):
        lines.append(
            f'data: {json.dumps({"type": "response.output_text.delta", "delta": ch})}'.encode()
        )
    completed = {"type": "response.completed", "response": {"usage": usage or {}}}
    lines.append(f"data: {json.dumps(completed)}".encode())
    lines.append(b"data: [DONE]")
    return lines


def _auth(tmp_path: Path) -> Path:
    p = tmp_path / "auth.json"
    p.write_text(json.dumps({
        "tokens": {"access_token": "tok", "account_id": "acct", "refresh_token": "r"}
    }))
    return p


def test_happy_path_parses_and_records_usage(tmp_path: Path) -> None:
    stream = _sse(json.dumps(VERDICT), usage={"input_tokens": 100, "output_tokens": 20})

    def transport(body: dict[str, Any], headers: dict[str, str]) -> Iterable[bytes]:
        assert headers["Authorization"] == "Bearer tok"
        assert headers["chatgpt-account-id"] == "acct"
        assert body["stream"] is True
        return stream

    llm = CodexOAuthLLM(auth_path=_auth(tmp_path), transport=transport)
    v = TriageAgent(llm).triage(CMDI, "system(getenv(\"CMD\"));")
    assert isinstance(v, Verdict) and v.is_real and v.bug_class == "CWE-78"
    assert llm.last_usage == {"input_tokens": 100, "output_tokens": 20}
    assert llm.total_usage["output_tokens"] == 20


def test_fenced_json_is_recovered(tmp_path: Path) -> None:
    fenced = f"Here is the verdict:\n```json\n{json.dumps(VERDICT)}\n```"

    def transport(body: dict[str, Any], headers: dict[str, str]) -> Iterable[bytes]:
        return _sse(fenced)

    llm = CodexOAuthLLM(auth_path=_auth(tmp_path), transport=transport)
    out = llm.complete_json("sys", "prompt", VERDICT_SCHEMA)
    assert out["bug_class"] == "CWE-78"


def test_completed_without_deltas(tmp_path: Path) -> None:
    # Some responses carry the text only in response.completed.output, no deltas.
    completed = {
        "type": "response.completed",
        "response": {
            "usage": {"input_tokens": 5, "output_tokens": 5},
            "output": [{
                "type": "message",
                "content": [{"type": "output_text", "text": json.dumps(VERDICT)}],
            }],
        },
    }
    lines = [f"data: {json.dumps(completed)}".encode()]

    llm = CodexOAuthLLM(auth_path=_auth(tmp_path), transport=lambda b, h: lines)
    out = llm.complete_json("sys", "prompt", VERDICT_SCHEMA)
    assert out["severity"] == "high"


def test_retry_then_succeed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("zeroverse.llm.codex_llm.time.sleep", lambda *_: None)
    calls = {"n": 0}

    def transport(body: dict[str, Any], headers: dict[str, str]) -> Iterable[bytes]:
        calls["n"] += 1
        if calls["n"] == 1:
            raise LLMTransientError("HTTP 429")
        return _sse(json.dumps(VERDICT))

    llm = CodexOAuthLLM(auth_path=_auth(tmp_path), transport=transport)
    out = llm.complete_json("sys", "prompt", VERDICT_SCHEMA)
    assert out["is_real"] is True
    assert calls["n"] == 2


def test_auth_error_triggers_refresh(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    refreshed = {"done": False}

    def fake_refresh(self: CodexOAuthLLM) -> None:
        refreshed["done"] = True

    monkeypatch.setattr(CodexOAuthLLM, "_refresh_token", fake_refresh)
    calls = {"n": 0}

    def transport(body: dict[str, Any], headers: dict[str, str]) -> Iterable[bytes]:
        calls["n"] += 1
        if calls["n"] == 1:
            raise LLMAuthError("HTTP 401")
        return _sse(json.dumps(VERDICT))

    llm = CodexOAuthLLM(auth_path=_auth(tmp_path), transport=transport)
    out = llm.complete_json("sys", "prompt", VERDICT_SCHEMA)
    assert refreshed["done"] and out["is_real"] is True


def test_unparseable_forever_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("zeroverse.llm.codex_llm.time.sleep", lambda *_: None)

    def transport(body: dict[str, Any], headers: dict[str, str]) -> Iterable[bytes]:
        return _sse("I cannot help with that.")

    llm = CodexOAuthLLM(auth_path=_auth(tmp_path), max_retries=2, transport=transport)
    with pytest.raises(LLMError):
        llm.complete_json("sys", "prompt", VERDICT_SCHEMA)


def test_stream_error_event_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("zeroverse.llm.codex_llm.time.sleep", lambda *_: None)
    err = {"type": "response.failed", "error": {"message": "model overloaded"}}
    lines = [f"data: {json.dumps(err)}".encode()]

    llm = CodexOAuthLLM(auth_path=_auth(tmp_path), max_retries=1, transport=lambda b, h: lines)
    with pytest.raises(LLMError):
        llm.complete_json("sys", "prompt", VERDICT_SCHEMA)


def test_triage_degrades_on_backend_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The agent must NOT crash when the live backend fails — it degrades to an
    # honest structural hypothesis (PoV oracle still gates confirmation).
    monkeypatch.setattr("zeroverse.llm.codex_llm.time.sleep", lambda *_: None)

    def transport(body: dict[str, Any], headers: dict[str, str]) -> Iterable[bytes]:
        raise LLMTransientError("HTTP 503")

    llm = CodexOAuthLLM(auth_path=_auth(tmp_path), max_retries=2, transport=transport)
    v = TriageAgent(llm).triage(CMDI, "system(getenv(\"CMD\"));")
    assert isinstance(v, Verdict)
    assert "LLM triage unavailable" in v.explanation
    assert v.bug_class.startswith("suspected")


# --- reasoning summary is accumulated, not discarded (issue #1705) ----------


def test_reasoning_summary_deltas_are_accumulated_and_kept_out_of_the_json(
    tmp_path: Path,
) -> None:
    # `_parse_sse` used to `continue` past every non-output_text event. The summary
    # must be captured, and must NOT join the answer text — that string goes
    # straight into extract_json.
    lines: list[bytes] = []
    for chunk in ("I should check ", "whether the length is bounded."):
        evt = {"type": "response.reasoning_summary_text.delta", "delta": chunk}
        lines.append(f"data: {json.dumps(evt)}".encode())
    lines += _sse(json.dumps(VERDICT))

    llm = CodexOAuthLLM(auth_path=_auth(tmp_path), transport=lambda b, h: lines)
    out = llm.complete_json("sys", "prompt", VERDICT_SCHEMA)

    assert out["bug_class"] == "CWE-78"          # the JSON still parses cleanly
    assert llm.last_reasoning_summary == "I should check whether the length is bounded."


def test_reasoning_summary_parts_are_separated(tmp_path: Path) -> None:
    lines = [
        b'data: {"type": "response.reasoning_summary_text.delta", "delta": "part one"}',
        b'data: {"type": "response.reasoning_summary_part.added", "part": {}}',
        b'data: {"type": "response.reasoning_summary_text.delta", "delta": "part two"}',
        *_sse(json.dumps(VERDICT)),
    ]
    llm = CodexOAuthLLM(auth_path=_auth(tmp_path), transport=lambda b, h: lines)
    llm.complete_json("sys", "prompt", VERDICT_SCHEMA)
    assert llm.last_reasoning_summary == "part one\n\npart two"


def test_reasoning_summary_recovered_from_a_non_streamed_response(tmp_path: Path) -> None:
    completed = {
        "type": "response.completed",
        "response": {
            "usage": {},
            "output": [
                {"type": "reasoning", "summary": [{"type": "summary_text", "text": "why"}]},
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": json.dumps(VERDICT)}],
                },
            ],
        },
    }
    lines = [f"data: {json.dumps(completed)}".encode(), b"data: [DONE]"]
    llm = CodexOAuthLLM(auth_path=_auth(tmp_path), transport=lambda b, h: lines)
    out = llm.complete_json("sys", "prompt", VERDICT_SCHEMA)
    assert out["bug_class"] == "CWE-78"
    assert llm.last_reasoning_summary == "why"


def test_reasoning_summary_resets_between_calls(tmp_path: Path) -> None:
    with_reasoning = [
        b'data: {"type": "response.reasoning_summary_text.delta", "delta": "first call"}',
        *_sse(json.dumps(VERDICT)),
    ]
    plain = _sse(json.dumps(VERDICT))
    streams = [with_reasoning, plain]

    llm = CodexOAuthLLM(
        auth_path=_auth(tmp_path), transport=lambda b, h: streams.pop(0)
    )
    llm.complete_json("sys", "one", VERDICT_SCHEMA)
    assert llm.last_reasoning_summary == "first call"
    llm.complete_json("sys", "two", VERDICT_SCHEMA)
    assert llm.last_reasoning_summary == ""      # not carried over from call one


def test_reasoning_is_not_requested_by_default(tmp_path: Path) -> None:
    # Default behaviour is byte-identical to before: no `reasoning` field on the
    # body, so the undocumented ChatGPT compat endpoint sees the same request.
    bodies: list[dict[str, Any]] = []

    def transport(body: dict[str, Any], headers: dict[str, str]) -> Iterable[bytes]:
        bodies.append(body)
        return _sse(json.dumps(VERDICT))

    llm = CodexOAuthLLM(auth_path=_auth(tmp_path), transport=transport)
    llm.complete_json("sys", "prompt", VERDICT_SCHEMA)
    assert "reasoning" not in bodies[0]
    assert bodies[0]["store"] is False

    opted_in = CodexOAuthLLM(
        auth_path=_auth(tmp_path), transport=transport, reasoning_summary="auto"
    )
    opted_in.complete_json("sys", "prompt", VERDICT_SCHEMA)
    assert bodies[1]["reasoning"] == {"summary": "auto"}
