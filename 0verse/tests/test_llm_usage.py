"""LLM call/token accounting (#298) — the ledger that stops a dead LLM lane from
reading as a cheap one.

Before ``zeroverse.llm.usage`` the magma runner read
``getattr(llm, "total_usage", {})``: ``AnthropicLLM``/``OpenAILLM`` had no such
attribute and threw the SDK's usage away, and the codex backend advanced its
counters only on a ``response.completed`` that carried a ``usage`` object. All of
"never called", "every call failed", "provider reports no usage" and "genuinely
free" therefore rendered as ``0`` tokens / ``$0.00``. These tests pin the four
states apart, with fake transports/clients — no network.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from zeroverse.llm.anthropic_llm import AnthropicLLM
from zeroverse.llm.codex_llm import (
    CodexOAuthLLM,
    LLMAuthError,
    LLMError,
    LLMTransientError,
)
from zeroverse.llm.openai_llm import OpenAILLM
from zeroverse.llm.usage import (
    STATUS_ALL_FAILED,
    STATUS_MEASURED,
    STATUS_NO_CALLS,
    STATUS_UNREPORTED,
    UsageTracker,
    merge_accounting,
    record_sdk_usage,
)

SCHEMA = {"type": "object", "properties": {"answer": {"type": "string"}}}
PAYLOAD = {"answer": "ok"}


# --- the ledger itself -----------------------------------------------------

def test_fresh_tracker_is_no_calls_not_zero_cost() -> None:
    t = UsageTracker()
    assert t.status == STATUS_NO_CALLS
    assert t.total_usage == {"input_tokens": 0, "output_tokens": 0}


def test_only_failures_is_all_failed() -> None:
    t = UsageTracker()
    t.note_failed()
    t.note_failed()
    assert t.status == STATUS_ALL_FAILED


def test_call_without_provider_usage_is_unreported_not_measured() -> None:
    t = UsageTracker()
    t.record(0, 0, reported=False)
    t.note_ok()
    # The call happened; the tokens are UNKNOWN. That is not the same as 0.
    assert t.status == STATUS_UNREPORTED
    assert t.usage_reported is False


def test_reported_usage_is_measured_and_sums() -> None:
    t = UsageTracker()
    t.record(100, 20)
    t.note_ok()
    t.record(5, 1)
    t.note_ok()
    assert t.status == STATUS_MEASURED
    assert t.total_usage == {"input_tokens": 105, "output_tokens": 21}
    assert t.last_usage == {"input_tokens": 5, "output_tokens": 1}


def test_record_sdk_usage_handles_missing_object_and_fields() -> None:
    t = UsageTracker()
    record_sdk_usage(t, None, "input_tokens", "output_tokens")
    assert t.usage_reported is False

    record_sdk_usage(t, SimpleNamespace(other=1), "input_tokens", "output_tokens")
    assert t.usage_reported is False

    record_sdk_usage(t, SimpleNamespace(input_tokens=7, output_tokens=3),
                     "input_tokens", "output_tokens")
    assert t.usage_reported is True
    assert t.total_usage == {"input_tokens": 7, "output_tokens": 3}


def test_merge_rederives_status_from_summed_counters() -> None:
    dead = UsageTracker()
    dead.note_failed()
    other = UsageTracker()
    other.note_failed()
    # Two dead scans must not average into anything but "dead".
    assert merge_accounting([dead.to_dict(), other.to_dict()])["status"] == (
        STATUS_ALL_FAILED
    )

    good = UsageTracker()
    good.record(10, 2)
    good.note_ok()
    merged = merge_accounting([dead.to_dict(), good.to_dict()])
    assert merged["status"] == STATUS_MEASURED
    assert merged["calls_ok"] == 1 and merged["calls_failed"] == 1
    assert merged["input_tokens"] == 10 and merged["output_tokens"] == 2


def test_merge_of_nothing_is_no_calls() -> None:
    assert merge_accounting([])["status"] == STATUS_NO_CALLS


# --- codex backend ---------------------------------------------------------

def _sse(text: str, *, usage: dict[str, int] | None = None) -> list[bytes]:
    lines = [
        f'data: {json.dumps({"type": "response.output_text.delta", "delta": text})}'.encode()
    ]
    completed: dict[str, Any] = {"type": "response.completed", "response": {}}
    if usage is not None:
        completed["response"]["usage"] = usage
    lines.append(f"data: {json.dumps(completed)}".encode())
    return lines


def _auth(tmp_path: Path) -> Path:
    p = tmp_path / "auth.json"
    p.write_text(json.dumps({"tokens": {"access_token": "t", "account_id": "a"}}))
    return p


def test_codex_records_usage_when_the_wire_reports_it(tmp_path: Path) -> None:
    stream = _sse(json.dumps(PAYLOAD), usage={"input_tokens": 100, "output_tokens": 20})
    llm = CodexOAuthLLM(auth_path=_auth(tmp_path), transport=lambda b, h: stream)
    llm.complete_json("sys", "prompt", SCHEMA)
    assert llm.usage.status == STATUS_MEASURED
    assert llm.total_usage == {"input_tokens": 100, "output_tokens": 20}
    assert llm.usage.calls_ok == 1


def test_codex_call_with_no_usage_object_is_unreported(tmp_path: Path) -> None:
    # The ChatGPT-OAuth Responses wire is subscription-billed and may return no
    # usage object at all. That must read as "tokens unknown", NOT "$0.00".
    stream = _sse(json.dumps(PAYLOAD))
    llm = CodexOAuthLLM(auth_path=_auth(tmp_path), transport=lambda b, h: stream)
    llm.complete_json("sys", "prompt", SCHEMA)
    assert llm.usage.calls_ok == 1
    assert llm.usage.status == STATUS_UNREPORTED


def test_codex_counts_a_dead_lane(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # An expired credential / 5xx wall: TriageAgent swallows the exception, so the
    # ledger is the ONLY evidence the model was never reached.
    monkeypatch.setattr("zeroverse.llm.codex_llm.time.sleep", lambda *_: None)

    def transport(body: dict[str, Any], headers: dict[str, str]) -> Iterable[bytes]:
        raise LLMTransientError("HTTP 503")

    llm = CodexOAuthLLM(auth_path=_auth(tmp_path), max_retries=2, transport=transport)
    with pytest.raises(LLMError):
        llm.complete_json("sys", "prompt", SCHEMA)
    assert llm.usage.calls_ok == 0
    assert llm.usage.calls_failed == 1
    assert llm.usage.status == STATUS_ALL_FAILED


def test_codex_counts_a_failed_token_refresh(tmp_path: Path) -> None:
    # A 401 on an auth.json with no refresh_token: `_refresh_token` raises
    # LLMAuthError straight out of the retry loop. That path bypassed the old
    # counters entirely, so an expired credential left NO trace at all.
    def transport(body: dict[str, Any], headers: dict[str, str]) -> Iterable[bytes]:
        raise LLMAuthError("HTTP 401")

    llm = CodexOAuthLLM(auth_path=_auth(tmp_path), max_retries=2, transport=transport)
    with pytest.raises(LLMAuthError):
        llm.complete_json("sys", "prompt", SCHEMA)
    assert llm.usage.calls_ok == 0
    assert llm.usage.status == STATUS_ALL_FAILED


# --- anthropic / openai backends -------------------------------------------

def test_anthropic_records_sdk_usage() -> None:
    resp = SimpleNamespace(
        content=[SimpleNamespace(type="text", text=json.dumps(PAYLOAD))],
        usage=SimpleNamespace(input_tokens=311, output_tokens=42),
    )
    client = SimpleNamespace(messages=SimpleNamespace(create=lambda **kw: resp))
    llm = AnthropicLLM(client=client)
    assert llm.complete_json("sys", "prompt", SCHEMA) == PAYLOAD
    # This was silently discarded before — every claude/GLM run priced at $0.00.
    assert llm.total_usage == {"input_tokens": 311, "output_tokens": 42}
    assert llm.usage.status == STATUS_MEASURED


def test_anthropic_counts_failures() -> None:
    def boom(**kw: Any) -> Any:
        raise RuntimeError("overloaded")

    client = SimpleNamespace(messages=SimpleNamespace(create=boom))
    llm = AnthropicLLM(client=client)
    with pytest.raises(RuntimeError):
        llm.complete_json("sys", "prompt", SCHEMA)
    assert llm.usage.status == STATUS_ALL_FAILED


def test_openai_records_sdk_usage() -> None:
    resp = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps(PAYLOAD)))],
        usage=SimpleNamespace(prompt_tokens=9, completion_tokens=4),
    )
    client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=lambda **kw: resp))
    )
    llm = OpenAILLM(client=client)
    assert llm.complete_json("sys", "prompt", SCHEMA) == PAYLOAD
    assert llm.total_usage == {"input_tokens": 9, "output_tokens": 4}
    assert llm.usage.status == STATUS_MEASURED


def test_openai_gateway_without_usage_is_unreported() -> None:
    resp = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps(PAYLOAD)))],
        usage=None,
    )
    client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=lambda **kw: resp))
    )
    llm = OpenAILLM(client=client)
    llm.complete_json("sys", "prompt", SCHEMA)
    assert llm.usage.status == STATUS_UNREPORTED
