"""LLM-driven pseudo-C bug scan — exercised with a deterministic stub LLM so it
runs with no API key and no network. The real-target codex run is a bench
experiment, not a CI test."""

from __future__ import annotations

from typing import Any

from zeroverse import llm_scan
from zeroverse.analyze import Finding
from zeroverse.backends.ghidra import ProgramMeta

# A cursor-loop OOB store with a cast index and NO libc sink — the exact shape the
# regex/name lenses miss (mirrors the lcms OutputValueSampler flaw).
SAMPLER_C = """
void OutputValueSampler(short *pcVar4, undefined4 *param_2, int *In)
{
  int local_14;
  local_14 = 0;
  do {
    In[(int)pcVar4] = *(short *)((long)param_2 + (long)local_14 * 2);
    local_14 = local_14 + 1;
    pcVar4 = pcVar4 + 1;
  } while (local_14 != (int)pcVar4);
  return;
}
"""

# A bounded, benign helper — the model should return is_bug=false.
SAFE_C = """
int clamp_index(int i, int n)
{
  if (i < 0) { i = 0; }
  if (i >= n) { i = n + -1; }
  return i;
}
"""


class StubScanLLM:
    """Returns a pseudo-C-scan verdict keyed on function name — deterministic, no net.
    Flags the sampler as an OOB write; everything else is clean."""

    def __init__(self) -> None:
        self.seen: list[str] = []

    def complete_json(
        self, system: str, prompt: str, schema: dict[str, Any]
    ) -> dict[str, Any]:
        assert "is_bug" in schema["properties"]  # the scan schema, not the triage one
        assert "Ghidra" in system  # pseudo-C framing reached the model
        for line in prompt.splitlines():
            if line.startswith("Function: "):
                self.seen.append(line[len("Function: "):])
                break
        if "OutputValueSampler" in prompt:
            return {
                "is_bug": True,
                "cwe": "CWE-787 out-of-bounds write",
                "vulnerable_line": "In[(int)pcVar4] = *(short *)(...)",
                "source": "cmsSAMPLER16 callback input",
                "sink": "In[(int)pcVar4] store",
                "explanation": "cursor loop stores through an unbounded cast index",
            }
        return {
            "is_bug": False, "cwe": "", "vulnerable_line": "",
            "source": "", "sink": "", "explanation": "index is clamped",
        }


def _meta(**decompiled: str) -> ProgramMeta:
    return ProgramMeta(decompiled_c=dict(decompiled))


def test_locates_oob_store_in_cursor_loop() -> None:
    meta = _meta(OutputValueSampler=SAMPLER_C, clamp_index=SAFE_C)
    results = llm_scan.llm_scan_functions(meta, StubScanLLM(), budget=10)
    bugs = [r for r in results if r.is_bug]
    assert [b.function for b in bugs] == ["OutputValueSampler"]
    assert "CWE-787" in bugs[0].cwe
    assert bugs[0].vulnerable_line  # the model quoted the offending line


def test_negative_is_reported_not_fabricated() -> None:
    # A build with only the benign helper yields NO bug hypotheses — an honest miss.
    results = llm_scan.llm_scan_functions(_meta(clamp_index=SAFE_C), StubScanLLM())
    assert [r for r in results if r.is_bug] == []


def test_to_finding_is_a_hypothesis() -> None:
    r = llm_scan.LlmScanFinding(
        function="OutputValueSampler", is_bug=True, cwe="CWE-787",
        vulnerable_line="In[(int)pcVar4] = ...", source="callback", sink="store",
        explanation="oob",
    )
    f = llm_scan.to_finding(r)
    assert isinstance(f, Finding)
    assert f.function == "OutputValueSampler"
    assert f.origin == "llm-pseudoc"
    # addresses are 0 -> the address-keyed angr/oracle stages skip it (hypothesis).
    assert f.sink_addr == 0 and f.source_addr == 0


def test_select_candidates_prioritizes_store_heavy_and_skips_noise() -> None:
    meta = _meta(
        OutputValueSampler=SAMPLER_C,
        clamp_index=SAFE_C,
        __asan_memcpy="void __asan_memcpy() { return; }",  # runtime noise -> dropped
    )
    picks = llm_scan.select_candidates(meta, budget=10)
    assert "__asan_memcpy" not in picks           # noise filtered
    assert picks[0] == "OutputValueSampler"        # store-heavy ranked first


def test_skip_excludes_already_flagged_functions() -> None:
    meta = _meta(OutputValueSampler=SAMPLER_C, clamp_index=SAFE_C)
    picks = llm_scan.select_candidates(meta, budget=10, skip={"OutputValueSampler"})
    assert "OutputValueSampler" not in picks


def test_stage_gated_off_without_real_llm(monkeypatch: Any) -> None:
    # No real LLM (mock/CI path) -> the stage is a no-op regardless of the env flag.
    monkeypatch.setenv("ZEROVERSE_LLM_SCAN", "1")
    base = [Finding(source="a", sink="b", function="f", source_addr=0, sink_addr=0,
                    path_len=0)]
    out, note = llm_scan.llm_scan_stage(list(base), _meta(g=SAMPLER_C), llm=None)
    assert out == base and note == ""


def test_stage_unions_hypotheses_on_real_lane(monkeypatch: Any) -> None:
    monkeypatch.setenv("ZEROVERSE_LLM_SCAN", "1")
    meta = _meta(OutputValueSampler=SAMPLER_C, clamp_index=SAFE_C)
    base: list[Finding] = []
    out, note = llm_scan.llm_scan_stage(base, meta, StubScanLLM())
    fns = {f.function for f in out}
    assert "OutputValueSampler" in fns
    assert any(f.origin == "llm-pseudoc" for f in out)
    assert "llm-pseudoc-scan" in note and "OutputValueSampler" in note


def test_stage_complements_does_not_rescan_flagged(monkeypatch: Any) -> None:
    # A regex lens already flagged OutputValueSampler -> the LLM scan skips it
    # (complement, not replacement) and adds nothing new here.
    monkeypatch.setenv("ZEROVERSE_LLM_SCAN", "1")
    meta = _meta(OutputValueSampler=SAMPLER_C)
    already = [Finding(source="x", sink="y", function="OutputValueSampler",
                       source_addr=0, sink_addr=0, path_len=0, origin="bugclass:loop")]
    out, _note = llm_scan.llm_scan_stage(already, meta, StubScanLLM())
    assert len(out) == 1 and out[0].origin == "bugclass:loop"


def test_stage_disabled_flag_off(monkeypatch: Any) -> None:
    monkeypatch.setenv("ZEROVERSE_LLM_SCAN", "0")
    out, note = llm_scan.llm_scan_stage([], _meta(g=SAMPLER_C), StubScanLLM())
    assert out == [] and note == ""
