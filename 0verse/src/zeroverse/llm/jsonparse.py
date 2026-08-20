"""Robust JSON extraction from a real model's free-form text.

MockLLM returns clean JSON; *real* models don't. They wrap the object in ```json
fences, prepend a sentence ("Here is the verdict:"), append a trailing comment, or
emit a reasoning preamble before the object. ``json.loads`` chokes on every one of
those, so each backend that talks to a live model routes its output through
``extract_json`` instead of a bare ``json.loads``.

Strategy (cheapest first):
  1. straight ``json.loads`` — the happy path;
  2. strip a Markdown code fence (```json ... ``` or ``` ... ```);
  3. scan for the first balanced ``{...}`` object, respecting strings/escapes.

Raises ``ValueError`` only when no JSON object can be recovered at all — callers
turn that into a graceful degrade, never a crash.
"""

from __future__ import annotations

import json
import re
from typing import Any

_FENCE = re.compile(r"```(?:json|JSON)?\s*(.*?)```", re.DOTALL)


def _balanced_object(text: str) -> str | None:
    """Return the first top-level ``{...}`` substring, honoring string literals so
    a ``}`` inside a string doesn't close the object early. None if none found."""
    start = text.find("{")
    while start != -1:
        depth = 0
        in_str = False
        esc = False
        for i in range(start, len(text)):
            c = text[i]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
                continue
            if c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return text[start : i + 1]
        start = text.find("{", start + 1)
    return None


def extract_json(text: str) -> dict[str, Any]:
    """Recover a JSON object from a live model's (possibly messy) text output."""
    if text is None:
        raise ValueError("no text to parse")
    candidates: list[str] = [text.strip()]
    m = _FENCE.search(text)
    if m:
        candidates.append(m.group(1).strip())
    bal = _balanced_object(text)
    if bal:
        candidates.append(bal)
    for cand in candidates:
        if not cand:
            continue
        try:
            obj = json.loads(cand)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(obj, dict):
            return obj
    raise ValueError(f"no JSON object found in model output (len={len(text)})")
