"""LLM-driven structured-input synthesis (issue #52).

Hermetic unit tests: a stub LLM returns canned candidate JSON so the module's
format inference, prompt construction, hex decoding, filtering, and degradation
are all exercised with no network. The real-target ARVO run is a bench
experiment, reported separately (not a CI test).
"""

from __future__ import annotations

from typing import Any

import pytest

from zeroverse.inputsynth import (
    SYNTH_SCHEMA,
    TargetContext,
    context_from_finding,
    infer_format,
    synthesize_candidates,
    synthesize_inputs,
)


class StubLLM:
    """Records the (system, prompt, schema) it was called with and replays a
    canned response — the anti-cheat guard checks the prompt never carries a PoC."""

    def __init__(self, response: dict[str, Any] | Exception) -> None:
        self.response = response
        self.system = ""
        self.prompt = ""
        self.schema: dict[str, Any] | None = None

    def complete_json(
        self, system: str, prompt: str, schema: dict[str, Any]
    ) -> dict[str, Any]:
        self.system, self.prompt, self.schema = system, prompt, schema
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _ctx() -> TargetContext:
    return TargetContext(
        file_format="ICC colour profile ('acsp' magic at offset 36)",
        harness_name="cms_postscript_fuzzer",
        sink_function="WriteCLUT @ cmsps2.c:667",
        overflow_reason="the CLUT output-channel count scales the buffer",
        sink_decompiled="void WriteCLUT(...) { for (i=0;i<nChan;i++) ... }",
    )


# --- format inference -------------------------------------------------------


@pytest.mark.parametrize(
    ("harness", "needle"),
    [
        ("cms_postscript_fuzzer", "ICC"),
        ("hb-draw-fuzzer", "sfnt"),
        ("libraw_cr2_fuzzer", "RAW"),
        ("tiff_read_rgba_fuzzer", "TIFF"),
        ("some_png_fuzzer", "PNG"),
    ],
)
def test_infer_format_from_harness(harness: str, needle: str) -> None:
    assert needle.lower() in infer_format(harness).lower()


def test_infer_format_falls_back_to_strings() -> None:
    assert "ICC" in infer_format("mystery_fuzzer", strings=["acsp", "lcms internal"])


def test_infer_format_empty_when_unknown() -> None:
    assert infer_format("mystery_fuzzer", strings=["nothing", "useful"]) == ""


# --- synthesis happy path ---------------------------------------------------


def test_synthesize_decodes_hex_candidates() -> None:
    llm = StubLLM({"candidates": [
        {"hex": "6163737000", "note": "acsp header"},
        {"hex": "0x00010203", "note": "0x-prefixed"},
        {"hex": "de ad be ef", "note": "whitespaced"},
    ]})
    res = synthesize_inputs(_ctx(), llm, n=3)
    assert res.candidates == [b"acsp\x00", b"\x00\x01\x02\x03", b"\xde\xad\xbe\xef"]
    assert res.notes[0] == "acsp header"
    assert not res.error


def test_synthesize_candidates_wrapper_returns_bytes() -> None:
    llm = StubLLM({"candidates": [{"hex": "4141"}]})
    assert synthesize_candidates(_ctx(), llm) == [b"AA"]


def test_prompt_carries_format_and_sink_but_no_poc() -> None:
    llm = StubLLM({"candidates": []})
    synthesize_inputs(_ctx(), llm)
    # the sink + format reach the model ...
    assert "WriteCLUT" in llm.prompt
    assert "ICC" in llm.prompt
    # ... and the schema is the structured candidate array.
    assert llm.schema == SYNTH_SCHEMA
    # anti-cheat: TargetContext has no channel for a reference input, so the
    # prompt can only contain what we put in the context above.
    assert "poc" not in llm.prompt.lower()


# --- filtering & robustness -------------------------------------------------


def test_odd_length_and_empty_hex_dropped() -> None:
    llm = StubLLM({"candidates": [
        {"hex": "abc"},        # odd length -> dropped
        {"hex": ""},           # empty -> dropped
        {"hex": "zzzz"},       # no hex digits -> dropped
        {"hex": "cafe"},       # valid
    ]})
    res = synthesize_inputs(_ctx(), llm)
    assert res.candidates == [b"\xca\xfe"]


def test_duplicates_deduped_preserving_order() -> None:
    llm = StubLLM({"candidates": [{"hex": "4142"}, {"hex": "4142"}, {"hex": "4143"}]})
    assert synthesize_inputs(_ctx(), llm).candidates == [b"AB", b"AC"]


def test_oversized_candidate_dropped() -> None:
    ctx = _ctx()
    ctx.max_input_size = 4
    llm = StubLLM({"candidates": [{"hex": "41" * 8}, {"hex": "42" * 2}]})
    assert synthesize_inputs(ctx, llm).candidates == [b"BB"]


def test_backend_failure_degrades_to_empty_with_error() -> None:
    llm = StubLLM(RuntimeError("rate limited"))
    res = synthesize_inputs(_ctx(), llm)
    assert res.candidates == []
    assert "RuntimeError" in res.error


def test_missing_candidates_array_reports_error() -> None:
    res = synthesize_inputs(_ctx(), StubLLM({"nope": 1}))
    assert res.candidates == []
    assert "candidates" in res.error


def test_non_dict_items_skipped() -> None:
    llm = StubLLM({"candidates": ["not-a-dict", {"hex": "00"}, 42]})
    assert synthesize_inputs(_ctx(), llm).candidates == [b"\x00"]


# --- context factory --------------------------------------------------------


def test_context_from_finding_infers_format() -> None:
    ctx = context_from_finding(harness_name="hb-shape-fuzzer", sink_function="sanitize")
    assert "sfnt" in ctx.file_format.lower()
    assert ctx.sink_function == "sanitize"


def test_context_from_finding_respects_explicit_format() -> None:
    ctx = context_from_finding(file_format="custom fmt", harness_name="hb-x")
    assert ctx.file_format == "custom fmt"
