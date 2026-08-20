"""Robust JSON recovery from a real model's messy text output."""

import pytest

from zeroverse.llm.jsonparse import extract_json


def test_clean_json() -> None:
    assert extract_json('{"a": 1}') == {"a": 1}


def test_markdown_fenced() -> None:
    text = 'Here is the verdict:\n```json\n{"is_real": true, "sev": "high"}\n```\n'
    assert extract_json(text) == {"is_real": True, "sev": "high"}


def test_bare_fence() -> None:
    assert extract_json("```\n{\"x\": 2}\n```") == {"x": 2}


def test_preamble_and_trailing_prose() -> None:
    text = 'Sure! {"k": "v", "n": 3} — hope that helps.'
    assert extract_json(text) == {"k": "v", "n": 3}


def test_brace_inside_string_does_not_close_early() -> None:
    text = '{"code": "if (x) { y(); }", "ok": true}'
    assert extract_json(text) == {"code": "if (x) { y(); }", "ok": True}


def test_nested_object() -> None:
    text = 'noise {"outer": {"inner": [1, 2]}, "z": 9} more'
    assert extract_json(text) == {"outer": {"inner": [1, 2]}, "z": 9}


def test_no_json_raises() -> None:
    with pytest.raises(ValueError):
        extract_json("I cannot help with that request.")
