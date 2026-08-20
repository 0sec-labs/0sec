"""Issue #52 wiring: pipeline feeds LLM-crafted format-valid candidates to the
ASan-file oracle (confirm_asan_file synth_candidates). Opt-in, degrades safely."""

from zeroverse.agent import Verdict
from zeroverse.analyze import Finding
from zeroverse.pipeline import _synth_asan_candidates


class _SynthLLM:
    def complete_json(self, system, prompt, schema):
        # SYNTH_SCHEMA shape consumed by inputsynth.synthesize_inputs
        return {"candidates": [{"hex": "ffd8ffe1", "note": "JPEG SOI+APP1"}]}


class _BadLLM:
    def complete_json(self, system, prompt, schema):
        raise RuntimeError("backend down")


_F = Finding("fread", "memcpy", "ProcessExifDir", 0, 0, 1)
_V = Verdict(True, "CWE-125", "high", "oversized EXIF count over-reads", "")
_DC = {"ProcessExifDir": "void ProcessExifDir(uchar* p){ memcpy(dst, p+8, p[4]); }"}


def test_synth_candidates_opt_in(monkeypatch):
    monkeypatch.delenv("ZEROVERSE_SYNTH_INPUTS", raising=False)
    assert _synth_asan_candidates(_F, _V, _DC, "jhead-asan", _SynthLLM()) is None  # off
    monkeypatch.setenv("ZEROVERSE_SYNTH_INPUTS", "1")
    cands = _synth_asan_candidates(_F, _V, _DC, "jhead-asan", _SynthLLM())
    assert cands == [b"\xff\xd8\xff\xe1"]                      # LLM hex decoded


def test_synth_candidates_degrade(monkeypatch):
    monkeypatch.setenv("ZEROVERSE_SYNTH_INPUTS", "1")
    assert _synth_asan_candidates(_F, _V, _DC, "jhead-asan", None) is None      # no llm
    assert _synth_asan_candidates(_F, _V, _DC, "jhead-asan", _BadLLM()) is None  # backend fail
