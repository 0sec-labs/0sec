"""Exploration-first (cold) agentic mode — the LLM starts at the attacker-input
entry and FOLLOWS THE DATA to the bug, instead of being handed a ranked suspect.

Everything here runs with a scripted mock LLM over a synthetic ``ProgramMeta``: no
codex, no Ghidra, no network. The scripted model walks entry -> parser -> buggy leaf
by calling ``callees``/``read_function``, consults the demoted ranker
(``suggest_suspicious``) as a HINT and the coverage frontier (``unexplored``), and
reaches a verdict. The asserts pin down the architectural contract:

  * the walk STARTS at the input entry (``find_entry``), not at a forced ranked pick —
    even when a different function ranks #1;
  * ranking is only a hint tool the model may consult, never a filter;
  * the visited/frontier tracking is real (it shrinks as the model reads, and reports
    exhaustion honestly);
  * the loop stays bounded (max_steps + repeat-guard); and
  * the entry fallback is HONEST when no input entry exists.
"""

from __future__ import annotations

from typing import Any

from zeroverse import agentic
from zeroverse.backends.ghidra import ProgramMeta
from zeroverse.localize import find_entry, localize_candidates, read_region

# --- a synthetic program with a real input->parser->buggy-leaf path ---------

# The attacker-input entry: libFuzzer harness. find_entry anchors taint here and
# explore MUST start here (its data/size params are the untrusted source).
_ENTRY_C = """
int LLVMFuzzerTestOneInput(uchar *data, ulong size)
{
  if (size < 8) {
    return 0;
  }
  parse_chunk(data, size);
  return 0;
}
"""

# The parser: reads a COUNT from the input bytes and passes it down to the leaf. This
# is the function the input flows through.
_PARSE_CHUNK_C = """
void parse_chunk(uchar *data, ulong size)
{
  uint uVar1;
  uVar1 = *(uint *)(data + 4);
  copy_samples(data, uVar1);
  return;
}
"""

# The buggy leaf: an attacker-controlled COUNT drives an index into a FIXED 16-byte
# stack array — a classic stack OOB write (CWE-787). buffer_size recovers the bound.
_COPY_SAMPLES_C = """
void copy_samples(uchar *src, uint count)
{
  uint uVar1;
  uchar auStack_28 [16];
  for (uVar1 = 0; uVar1 < count; uVar1 = uVar1 + 1) {
    auStack_28[uVar1] = src[uVar1];
  }
  return;
}
"""

# A large, reachable, diffuse function that the taint ranker floats to #1 (parse
# signal + inlined-blob size bonus) — but which is NOT on the bug path. Its presence
# proves explore starts at the ENTRY, not at the top-ranked candidate.
_MEGA_PARSER_C = (
    "void mega_parser(uchar *data, ulong size)\n{\n  uint i;\n  uint acc;\n  acc = 0;\n"
    + "  /* recovered inline body region, decompiled filler line */\n" * 200
    + "  for (i = 0; i < size; i = i + 1) {\n    acc = acc + data[i];\n  }\n"
    + "  return;\n}\n"
)

# An unreachable decoy (no path from the entry): must never appear in the reachable
# frontier, only via the suggest_suspicious hint at most.
_DECOY_C = """
int decoy_unreachable(int a, int b)
{
  int local_10 [4];
  local_10[a] = b;
  return local_10[0];
}
"""


def _explore_meta() -> ProgramMeta:
    return ProgramMeta(
        decompiled_c={
            "LLVMFuzzerTestOneInput": _ENTRY_C,
            "parse_chunk": _PARSE_CHUNK_C,
            "copy_samples": _COPY_SAMPLES_C,
            "mega_parser": _MEGA_PARSER_C,
            "decoy_unreachable": _DECOY_C,
        },
        callgraph={
            "LLVMFuzzerTestOneInput": ["parse_chunk", "mega_parser"],
            "parse_chunk": ["copy_samples"],
        },
        structs=[],
    )


# A program with NO recovered input entry (no LLVMFuzzerTestOneInput / main): explore
# must fall back to the top ranked candidate and SAY SO.
_STANDALONE_A_C = """
void transform_block(uchar *buf, uint n)
{
  uint uVar1;
  uchar auStack_18 [8];
  for (uVar1 = 0; uVar1 < n; uVar1 = uVar1 + 1) {
    auStack_18[uVar1] = buf[uVar1];
  }
  return;
}
"""

_STANDALONE_B_C = """
int checksum(uchar *buf, uint n)
{
  uint uVar1;
  int iVar2;
  iVar2 = 0;
  for (uVar1 = 0; uVar1 < n; uVar1 = uVar1 + 1) {
    iVar2 = iVar2 + buf[uVar1];
  }
  return iVar2;
}
"""


def _no_entry_meta() -> ProgramMeta:
    return ProgramMeta(
        decompiled_c={
            "transform_block": _STANDALONE_A_C,
            "checksum": _STANDALONE_B_C,
        },
        callgraph={"transform_block": ["checksum"]},
        structs=[],
    )


# --- a libraw-shaped fan-out: one entry -> a dispatcher -> DOZENS of camera-format
# parsers, with the real bug on ONE deep branch. This is the shape that defeated the
# cold libraw run (20 undirected steps went down the wrong branches). The dynamic
# reachable_hint (a coverage trace) narrows the fan-out to the executed few.


def _decoy_parser(name: str) -> str:
    # A reachable camera-format parser with genuine parse signal (byte assembly + a
    # bounded copy) so the taint ranker floats it high — burying the real bug.
    return (
        f"void {name}(uchar *data, ulong size)\n"
        "{\n"
        "  uint uVar1;\n"
        "  uint i;\n"
        "  uchar buf [64];\n"
        "  uVar1 = *(uint *)(data + 2) << 8 | (uint)data[6];\n"
        "  for (i = 0; i < uVar1 && i < 64; i = i + 1) {\n"
        "    buf[i] = data[i];\n"
        "  }\n"
        "  return;\n"
        "}\n"
    )


# The real bug, deep on the RAF/makernote branch: an attacker COUNT parsed from the
# makernote header drives an UNCLAMPED index into a fixed 32-byte stack array (CWE-787).
_MAKERNOTE_C = """
void parseAdobeRAFMakernote(uchar *data, ulong size)
{
  uint uVar1;
  uint i;
  uchar auStack_40 [32];
  uVar1 = *(uint *)(data + 0x10) << 8 | (uint)data[0x14];
  for (i = 0; i < uVar1; i = i + 1) {
    auStack_40[i] = data[i + 0x18];
  }
  return;
}
"""

_RAF_ENTRY_C = """
int LLVMFuzzerTestOneInput(uchar *data, ulong size)
{
  if (size < 0x20) {
    return 0;
  }
  raf_dispatch(data, size);
  return 0;
}
"""

_RAF_DISPATCH_C = """
void raf_dispatch(uchar *data, ulong size)
{
  uint uVar1;
  uVar1 = (uint)*data;
  /* fan out to every camera-format parser by tag */
  parseAdobeRAFMakernote(data, size);
  return;
}
"""

_N_DECOYS = 30


def _fanout_meta() -> ProgramMeta:
    decompiled = {
        "LLVMFuzzerTestOneInput": _RAF_ENTRY_C,
        "raf_dispatch": _RAF_DISPATCH_C,
        "parseAdobeRAFMakernote": _MAKERNOTE_C,
    }
    dispatch_callees = ["parseAdobeRAFMakernote"]
    for i in range(_N_DECOYS):
        nm = f"parse_camfmt_{i:02d}"
        decompiled[nm] = _decoy_parser(nm)
        dispatch_callees.append(nm)
    callgraph = {
        "LLVMFuzzerTestOneInput": ["raf_dispatch"],
        "raf_dispatch": dispatch_callees,
    }
    return ProgramMeta(decompiled_c=decompiled, callgraph=callgraph, structs=[])


class ScriptedLLM:
    """Replays a fixed list of action dicts, one per ``complete_json`` call, and records
    the prompts it saw so a test can assert observations were fed back."""

    def __init__(self, script: list[dict[str, Any]]) -> None:
        self.script = list(script)
        self.prompts: list[str] = []
        self.systems: list[str] = []

    def complete_json(self, system: str, prompt: str, schema: dict[str, Any]) -> dict[str, Any]:
        self.systems.append(system)
        self.prompts.append(prompt)
        assert "action" in schema["required"]
        if not self.script:
            return {"action": "verdict", "is_bug": False, "explanation": "out of script"}
        return self.script.pop(0)


# --- the flagship trajectory: entry -> parser -> buggy leaf -> verdict -------


def test_explore_follows_data_from_entry_to_buggy_leaf() -> None:
    # The model NAVIGATES: it lists the entry's callees, descends into the parser,
    # checks the frontier, consults the ranker as a hint, reads the buggy leaf, recovers
    # the fixed buffer size, and concludes an OOB write — the loop follows the model's
    # own navigation the whole way.
    script = [
        {
            "thought": "input enters at the entry — see which callees receive it",
            "action": "call",
            "tool": "callees",
            "args": {"name": "LLVMFuzzerTestOneInput"},
        },
        {
            "thought": "parse_chunk takes data/size — read it",
            "action": "call",
            "tool": "read_function",
            "args": {"name": "parse_chunk"},
        },
        {
            "thought": "it reads a count from data+4 and passes it down; what's left?",
            "action": "call",
            "tool": "unexplored",
            "args": {},
        },
        {
            "thought": "consult the heuristic leads (optional)",
            "action": "call",
            "tool": "suggest_suspicious",
            "args": {},
        },
        {
            "thought": "copy_samples receives the attacker count — read it",
            "action": "call",
            "tool": "read_function",
            "args": {"name": "copy_samples"},
        },
        {
            "thought": "auStack_28 is indexed by count — recover its real bound",
            "action": "call",
            "tool": "buffer_size",
            "args": {"function": "copy_samples", "pointer_var": "auStack_28"},
        },
        {
            "thought": "fixed 16-byte stack array indexed by an unclamped attacker count",
            "action": "verdict",
            "is_bug": True,
            "cwe": "CWE-787",
            "sink": "auStack_28[count]",
            "source": "count read from data+4 (attacker-controlled)",
            "explanation": "count from input drives a write past a fixed 16-byte stack "
            "buffer: data -> parse_chunk -> copy_samples",
        },
    ]
    llm = ScriptedLLM(script)
    res = agentic.explore(_explore_meta(), llm, max_steps=20)

    # started at the true input entry, chosen via find_entry (not a ranked pick)
    assert res.start_function == "LLVMFuzzerTestOneInput"
    assert res.entry_source == "input-entry"
    # reached the verdict by following its own navigation
    assert res.stop_reason == "verdict"
    assert res.verdict is not None and res.verdict.is_bug
    assert res.verdict.cwe == "CWE-787"
    assert [s.action for s in res.steps] == [
        "call",
        "call",
        "call",
        "call",
        "call",
        "call",
        "verdict",
    ]
    # the loop followed the model's edges: parse_chunk's body was fed back before the
    # frontier step, and copy_samples' body before the buffer_size step.
    assert "copy_samples" in llm.prompts[2]  # callees(entry)->... then read
    assert "auStack_28" in llm.prompts[5]  # copy_samples body fed back
    # the buffer_size observation (the fixed-array bound) reached the model pre-verdict
    assert "LOCAL STACK ARRAY" in llm.prompts[6] and "16" in llm.prompts[6]
    # the exploration system prompt drove the run (not the seeded _SYSTEM)
    assert llm.systems[0] == agentic._EXPLORE_SYSTEM


def test_explore_first_prompt_frames_exploration_at_the_entry() -> None:
    llm = ScriptedLLM(
        [
            {
                "thought": "conclude",
                "action": "verdict",
                "is_bug": False,
                "explanation": "nothing yet",
            },
        ]
    )
    res = agentic.explore(_explore_meta(), llm)
    p0 = llm.prompts[0]
    # the opening frames the task as EXPLORATION from the input entry, with the entry
    # body inline — not "Investigate function X".
    assert "UNTRUSTED INPUT ENTERS" in p0
    assert "LLVMFuzzerTestOneInput" in p0
    assert "exploration entry" in p0
    assert "parse_chunk(data, size)" in p0  # the entry body is inline
    # the demoted-ranker + frontier tools are advertised in the menu
    assert "suggest_suspicious()" in p0 and "unexplored()" in p0
    assert res.start_function == "LLVMFuzzerTestOneInput"


def test_explore_starts_at_entry_not_top_ranked_candidate() -> None:
    # The whole point of the shift: even though mega_parser RANKS #1 (parse signal +
    # inlined-blob size bonus), exploration begins at the input ENTRY, not the ranker's
    # pick. Ranking is not the ceiling anymore.
    meta = _explore_meta()
    top = localize_candidates(meta, limit=1)
    assert top and top[0] == "mega_parser"  # the ranker would pick this
    llm = ScriptedLLM(
        [
            {"thought": "done", "action": "verdict", "is_bug": False, "explanation": "x"},
        ]
    )
    res = agentic.explore(meta, llm)
    assert res.start_function == find_entry(meta.decompiled_c, meta.callgraph)
    assert res.start_function == "LLVMFuzzerTestOneInput"
    assert res.start_function != top[0]  # NOT the ranked start


# --- ranking demoted to an OPTIONAL hint ------------------------------------


def test_suggest_suspicious_is_a_hint_not_a_filter() -> None:
    tb = agentic.ToolBox(_explore_meta())
    obs = tb.suggest_suspicious()
    # it explicitly disclaims being a filter / forced start
    assert "HINT ONLY" in obs
    assert "NOT a filter" in obs
    assert "ANY function" in obs and "ANY call edge" in obs
    # it still surfaces leads (the ranker machinery is intact, just demoted)
    assert "taint-proximity leads" in obs or "memory-op-shape leads" in obs
    assert "mega_parser" in obs  # a ranked lead appears
    # advertised in the exploration menu but NOT in the seeded run_agent menu
    assert "suggest_suspicious" in tb.explore_catalog_text()
    assert "suggest_suspicious" not in tb.catalog_text()
    assert "suggest_suspicious" in tb.tool_names()  # still dispatchable


# --- coverage frontier / visited tracking -----------------------------------


def test_unexplored_frontier_shrinks_and_exhausts() -> None:
    tb = agentic.ToolBox(_explore_meta())
    tb.entry = "LLVMFuzzerTestOneInput"
    # nothing visited yet: the frontier is the reachable set (entry + parse_chunk +
    # copy_samples + mega_parser), and the UNREACHABLE decoy is excluded.
    first = tb.unexplored()
    assert "parse_chunk" in first and "copy_samples" in first and "mega_parser" in first
    assert "decoy_unreachable" not in first  # not reachable from the entry
    assert "visited so far: 0" in first

    # reading functions marks them visited; the frontier shrinks accordingly.
    tb.read_function("LLVMFuzzerTestOneInput")
    tb.read_function("parse_chunk")
    mid = tb.unexplored()
    frontier_line = mid.splitlines()[1]  # the ranked unread names
    assert "parse_chunk" not in frontier_line  # now visited -> off the frontier
    assert "copy_samples" in frontier_line  # still unread
    assert "visited so far: 2" in mid

    # once every reachable function is read, the frontier is honestly EXHAUSTED.
    tb.read_function("copy_samples")
    tb.read_function("mega_parser")
    last = tb.unexplored()
    assert "EXHAUSTED" in last
    assert "conclude" in last


def test_unexplored_without_entry_falls_back_to_all_functions() -> None:
    # No entry set (reach is None): the frontier degrades to all non-noise functions,
    # and says so, rather than crashing.
    tb = agentic.ToolBox(_no_entry_meta())
    obs = tb.unexplored()
    assert "no input entry" in obs
    assert "transform_block" in obs and "checksum" in obs


def test_explore_records_visited_frontier_on_the_result() -> None:
    script = [
        {
            "thought": "descend",
            "action": "call",
            "tool": "read_function",
            "args": {"name": "parse_chunk"},
        },
        {
            "thought": "descend",
            "action": "call",
            "tool": "read_function",
            "args": {"name": "copy_samples"},
        },
        {
            "thought": "done",
            "action": "verdict",
            "is_bug": True,
            "cwe": "CWE-787",
            "sink": "s",
            "source": "in",
            "explanation": "e",
        },
    ]
    res = agentic.explore(_explore_meta(), ScriptedLLM(script))
    # the entry (read to build the header) plus every function the model read
    assert res.visited[0] == "LLVMFuzzerTestOneInput"
    assert "parse_chunk" in res.visited and "copy_samples" in res.visited
    # and the auditable transcript surfaces the coverage + entry provenance
    text = res.transcript()
    assert "entry_source=input-entry" in text
    assert "visited (" in text and "copy_samples" in text


# --- honest entry fallback when there is no input source --------------------


def test_explore_fallback_is_honest_when_no_entry() -> None:
    # No LLVMFuzzerTestOneInput / main: explore falls back to the top ranked candidate
    # and RECORDS that it is not a true input source.
    meta = _no_entry_meta()
    assert find_entry(meta.decompiled_c, meta.callgraph) is None
    llm = ScriptedLLM(
        [
            {"thought": "done", "action": "verdict", "is_bug": False, "explanation": "x"},
        ]
    )
    res = agentic.explore(meta, llm)
    assert res.entry_source == "fallback-ranked"
    # the fallback start is the top ranked candidate...
    assert res.start_function == localize_candidates(meta, limit=1)[0]
    # ...and the model is TOLD the caveat, verbatim, in the opening prompt.
    assert "NO input entry point" in llm.prompts[0]
    assert "NOT a true input source" in llm.prompts[0]


def test_explore_provided_entry_is_used() -> None:
    llm = ScriptedLLM(
        [
            {"thought": "done", "action": "verdict", "is_bug": False, "explanation": "x"},
        ]
    )
    res = agentic.explore(_explore_meta(), llm, entry="parse_chunk")
    assert res.start_function == "parse_chunk"
    assert res.entry_source == "provided"
    assert "caller-specified entry" in llm.prompts[0]


# --- bounded loop: budget + repeat-guard stay intact ------------------------


def test_explore_stops_at_max_steps_without_verdict() -> None:
    calls = [
        {
            "thought": "look",
            "action": "call",
            "tool": "search_functions",
            "args": {"substr": f"q{i}"},
        }
        for i in range(30)
    ]
    res = agentic.explore(_explore_meta(), ScriptedLLM(calls), max_steps=5)
    assert res.stop_reason == "max_steps"
    assert res.verdict is None
    assert len(res.steps) == 5


def test_explore_repeat_guard_aborts_on_identical_calls() -> None:
    same = {"thought": "again", "action": "call", "tool": "unexplored", "args": {}}
    res = agentic.explore(_explore_meta(), ScriptedLLM([dict(same) for _ in range(10)]))
    assert res.stop_reason == "loop-guard"
    assert res.verdict is None
    assert "[repeat]" in res.steps[-1].observation


def test_explore_final_turn_forces_verdict() -> None:
    llm = ScriptedLLM(
        [
            {
                "thought": "one look",
                "action": "call",
                "tool": "callees",
                "args": {"name": "LLVMFuzzerTestOneInput"},
            },
            {
                "thought": "must conclude",
                "action": "verdict",
                "is_bug": False,
                "explanation": "bounded",
            },
        ]
    )
    res = agentic.explore(_explore_meta(), llm, max_steps=2)
    assert res.stop_reason == "verdict"
    assert "[FINAL TURN]" in llm.prompts[-1]


# --- the exploration prompt encodes the strategy ----------------------------


def test_exploration_system_prompt_frames_follow_the_data() -> None:
    s = agentic._EXPLORE_SYSTEM
    assert "FOLLOW THE DATA" in s
    assert "EXPLORE" in s
    assert "unexplored()" in s and "suggest_suspicious()" in s
    assert "HINT" in s and "never a filter" in s
    # it keeps the sink->parent pivot guidance the seeded prompt has
    assert "arg_provenance" in s and "callers" in s and "UPSTREAM" in s


# --- the seeded run_agent path is untouched ---------------------------------


def test_run_agent_still_seeded_and_records_visited() -> None:
    # explore is additive: run_agent still starts at the given function, with no
    # entry_source, and now also reports what it visited.
    llm = ScriptedLLM(
        [
            {
                "thought": "resolve",
                "action": "call",
                "tool": "read_function",
                "args": {"name": "copy_samples"},
            },
            {
                "thought": "oob",
                "action": "verdict",
                "is_bug": True,
                "cwe": "CWE-787",
                "sink": "auStack_28[count]",
                "source": "count",
                "explanation": "oob write",
            },
        ]
    )
    res = agentic.run_agent(_explore_meta(), "parse_chunk", llm, max_steps=8)
    assert res.start_function == "parse_chunk"
    assert res.entry_source == ""  # seeded mode: no entry provenance
    assert res.stop_reason == "verdict" and res.verdict is not None
    assert "parse_chunk" in res.visited  # header read marks it
    assert "copy_samples" in res.visited  # and the model's read
    # the seeded opener is unchanged
    assert "Investigate function 'parse_chunk'" in llm.prompts[0]


# ===========================================================================
# (1) DYNAMIC-REACHABILITY-GUIDED FRONTIER (the strong mechanism)
# ===========================================================================


def test_reachable_hint_restricts_frontier_to_executed_set() -> None:
    # The libraw failure: the entry fans out to DOZENS of camera-format parsers, and an
    # undirected walk goes down the wrong branch. A dynamic coverage trace of the target
    # PoC names the ~few functions ACTUALLY EXECUTED — the real path.
    tb = agentic.ToolBox(_fanout_meta())
    tb.entry = "LLVMFuzzerTestOneInput"

    # WITHOUT the hint: the frontier is the whole static-reachable fan-out (dozens).
    static = tb.unexplored()
    assert "parse_camfmt" in static  # decoys dominate the static frontier
    assert "more)" in static  # far more than the 20 shown

    # WITH the hint = the executed set (a coverage trace): the frontier is RESTRICTED to
    # the functions known to run on THIS input — the real RAF/makernote path — and the
    # dozens of unexecuted decoys drop out.
    tb2 = agentic.ToolBox(_fanout_meta())
    tb2.entry = "LLVMFuzzerTestOneInput"
    tb2.reachable_hint = {"raf_dispatch", "parseAdobeRAFMakernote"}
    dyn = tb2.unexplored()
    frontier_line = dyn.splitlines()[1]
    assert "parseAdobeRAFMakernote" in frontier_line  # the deep bug is right there
    assert "raf_dispatch" in frontier_line
    assert "parse_camfmt" not in frontier_line  # the unexecuted fan-out is gone
    assert "KNOWN TO EXECUTE" in dyn  # honest framing in the banner


def test_reachable_hint_lets_the_llm_reach_a_deep_function_static_walk_ranks_low() -> None:
    # End-to-end: with the coverage trace, the model consults unexplored(), sees the
    # deep makernote parser surfaced (not buried under 30 decoys), reads it, and reaches
    # the verdict. The trace does NOT name the bug — the model still reasons about which
    # executed function holds it.
    script = [
        {
            "thought": "what actually executes on this input?",
            "action": "call",
            "tool": "unexplored",
            "args": {},
        },
        {
            "thought": "the makernote parser is on the real path — read it",
            "action": "call",
            "tool": "read_function",
            "args": {"name": "parseAdobeRAFMakernote"},
        },
        {
            "thought": "fixed 32-byte array indexed by an unclamped attacker count",
            "action": "call",
            "tool": "buffer_size",
            "args": {"function": "parseAdobeRAFMakernote", "pointer_var": "auStack_40"},
        },
        {
            "thought": "OOB write",
            "action": "verdict",
            "is_bug": True,
            "cwe": "CWE-787",
            "sink": "auStack_40[i]",
            "source": "count from makernote header",
            "explanation": "unclamped count drives a write past a fixed 32-byte buffer",
        },
    ]
    llm = ScriptedLLM(script)
    res = agentic.explore(
        _fanout_meta(),
        llm,
        max_steps=20,
        reachable_hint={"raf_dispatch", "parseAdobeRAFMakernote"},
    )
    assert res.start_function == "LLVMFuzzerTestOneInput"
    assert res.entry_source == "input-entry"
    assert res.stop_reason == "verdict"
    assert res.verdict is not None and res.verdict.is_bug and res.verdict.cwe == "CWE-787"
    # the unexplored() observation the model saw (prompt after step 0) surfaced the deep
    # function and NOT the unexecuted decoys — the restriction is what led it there.
    unexplored_obs = llm.prompts[1]
    assert "parseAdobeRAFMakernote" in unexplored_obs
    assert "parse_camfmt" not in unexplored_obs
    # and the opening header told the model dynamic coverage is available (honest).
    assert "DYNAMIC COVERAGE AVAILABLE" in llm.prompts[0]
    assert "REASON about which executed function holds the bug" in llm.prompts[0]


def test_reachable_hint_does_not_filter_read_function() -> None:
    # The hint restricts the FRONTIER, never the read surface: an unexecuted decoy is
    # still fully readable (not a wall).
    tb = agentic.ToolBox(_fanout_meta())
    tb.entry = "LLVMFuzzerTestOneInput"
    tb.reachable_hint = {"parseAdobeRAFMakernote"}
    body = tb.read_function("parse_camfmt_05")  # outside the executed set
    assert "parse_camfmt_05" in body and "not found" not in body


# ===========================================================================
# (2) INPUT-FORMAT HINTS from magic bytes (the light mechanism)
# ===========================================================================


def test_input_format_hints_maps_magic_bytes_to_keywords() -> None:
    fh = agentic.input_format_hints
    # Fuji RAF — the libraw target format.
    raf = fh(b"FUJIFILMCCD-RAW " + b"\x00" * 32)
    assert "fuji" in raf and "raf" in raf and "makernote" in raf
    # TIFF, both byte orders (the Exif/makernote container).
    assert "tiff" in fh(b"II\x2a\x00" + b"\x08\x00\x00\x00")
    assert "tiff" in fh(b"MM\x00\x2a" + b"\x00\x00\x00\x08")
    assert "makernote" in fh(b"II\x2a\x00rest")
    # JPEG / JFIF.
    jpg = fh(b"\xff\xd8\xff\xe0\x00\x10JFIF")
    assert "jpeg" in jpg and "exif" in jpg
    # PNG (8-byte signature).
    assert "png" in fh(b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x0d")
    # OpenEXR.
    exr = fh(b"\x76\x2f\x31\x01\x02\x00\x00\x00")
    assert "exr" in exr and "openexr" in exr
    # ICC profile — offset-anchored 'acsp' at byte 36.
    icc = fh(b"\x00" * 36 + b"acsp" + b"\x00" * 8)
    assert "icc" in icc and "acsp" in icc


def test_input_format_hints_is_robust_to_short_and_unknown_input() -> None:
    fh = agentic.input_format_hints
    assert fh(b"") == []  # empty
    assert fh(b"II") == []  # too short for the TIFF signature
    assert fh(b"\x00\x01") == []  # unknown 2-byte prefix
    assert fh(b"not a known container at all") == []  # unknown text
    # an ICC-length buffer WITHOUT the 'acsp' signature is not misread as ICC.
    assert fh(b"\x00" * 40) == []


# ===========================================================================
# (3) FORMAT HINTS bias frontier ORDER (a prior, never a filter)
# ===========================================================================


def test_format_hints_bias_frontier_order_without_filtering() -> None:
    tb = agentic.ToolBox(_fanout_meta())
    tb.entry = "LLVMFuzzerTestOneInput"
    tb.format_hints = ["fuji", "raf", "makernote"]  # from a RAF PoC's magic bytes
    obs = tb.unexplored()
    # the RAF/makernote-named functions FLOAT UP (their names match the format prior)...
    assert obs.index("parseAdobeRAFMakernote") < obs.index("parse_camfmt")
    # ...but the non-matching decoys are NOT filtered out — still on the frontier.
    assert "parse_camfmt" in obs
    # and it says the prior was applied (a soft prior, not a filter).
    assert "format-hint prior" in obs and "not a filter" in obs


def test_format_hints_bias_is_carried_through_explore_header() -> None:
    llm = ScriptedLLM(
        [
            {"thought": "done", "action": "verdict", "is_bug": False, "explanation": "x"},
        ]
    )
    agentic.explore(
        _fanout_meta(),
        llm,
        max_steps=4,
        format_hints=agentic.input_format_hints(b"FUJIFILMCCD-RAW " + b"\x00" * 32),
    )
    p0 = llm.prompts[0]
    assert "INPUT FORMAT" in p0
    assert "fuji" in p0 and "soft prior, NOT a filter" in p0


# ===========================================================================
# (4) NO-HINT PATH IS BYTE-IDENTICAL TO THE CURRENT BEHAVIOR
# ===========================================================================


def test_no_hint_frontier_ranking_is_unchanged() -> None:
    # With neither prior set, _rank_frontier is exactly the plain taint-proximity sort
    # (the leading format-tier key is a uniform constant), and unexplored() contains no
    # prior banners — the existing behavior is preserved verbatim.
    tb = agentic.ToolBox(_explore_meta())
    tb.entry = "LLVMFuzzerTestOneInput"
    pool = ["copy_samples", "parse_chunk", "mega_parser"]
    order = {fn: i for i, fn in enumerate(tb.localize_candidates(limit=200))}
    expected = sorted(pool, key=lambda f: (order.get(f, 10**6), f))
    assert tb._rank_frontier(pool) == expected

    obs = tb.unexplored()
    assert "format-hint prior" not in obs
    assert "KNOWN TO EXECUTE" not in obs
    assert obs.splitlines()[0].endswith("ranked by input proximity:")


def test_input_format_hints_detects_embedded_makernote_marker():
    """A TIFF container with an EMBEDDED 'Adobe' makernote must yield adobe/raf/fuji
    keywords (the libraw GT: outer magic is TIFF but the bug is parseAdobeRAFMakernote).
    Outer-magic-only detection returned [] here — the regression this guards."""
    from zeroverse.agentic import input_format_hints

    poc = b"II\x2a\x00" + b"\x00" * 80 + b"Adobe" + b"\x00" * 8 + b"MakerNote"
    hints = input_format_hints(poc)
    assert "tiff" in hints  # outer container still detected
    assert "adobe" in hints and "makernote" in hints and "raf" in hints  # embedded marker
    # a clean format with no embedded marker is unchanged (no spurious keywords)
    assert input_format_hints(b"\x89PNG\r\n\x1a\n" + b"\x00" * 40) == [
        "png",
        "idat",
        "chunk",
        "zlib",
        "inflate",
        "scanline",
        "filter",
    ]


# --- confirmation gate: don't drop an unproven suspicion --------------------


def test_confirmation_gate_forces_proof_before_a_hedged_false_verdict() -> None:
    """A false verdict that VOICES an unproven suspicion but ran NO proving tool is
    nudged once; the model then runs a proving tool and concludes for real."""
    script = [
        {
            "thought": "read the leaf",
            "action": "call",
            "tool": "read_function",
            "args": {"name": "copy_samples"},
        },
        {
            "thought": "looks bounded but I did not prove the negative offset case",
            "action": "verdict",
            "is_bug": False,
            "cwe": "",
            "sink": "auStack_28[count]",
            "explanation": "the index could be a negative offset but I did not prove it",
        },
        {
            "thought": "prove it",
            "action": "call",
            "tool": "buffer_size",
            "args": {"function": "copy_samples", "pointer_var": "auStack_28"},
        },
        {
            "thought": "fixed 16 vs unclamped count",
            "action": "verdict",
            "is_bug": True,
            "cwe": "CWE-787",
            "sink": "auStack_28[count]",
            "explanation": "OOB write",
        },
    ]
    res = agentic.explore(_explore_meta(), ScriptedLLM(script), max_steps=20)
    assert "confirm-gate" in [s.action for s in res.steps]  # gate fired
    assert res.verdict is not None and res.verdict.is_bug is True  # proceeded past the hedge


def test_confirmation_gate_does_not_fire_on_a_confident_clean_verdict() -> None:
    script = [
        {
            "thought": "clean",
            "action": "verdict",
            "is_bug": False,
            "cwe": "",
            "sink": "",
            "explanation": "all accesses are bounded by a checked length; safe",
        }
    ]
    res = agentic.explore(_explore_meta(), ScriptedLLM(script), max_steps=20)
    assert "confirm-gate" not in [s.action for s in res.steps]
    assert res.verdict is not None and res.verdict.is_bug is False


def test_confirmation_gate_fires_at_most_once() -> None:
    hedge = {
        "thought": "did not prove the underflow",
        "action": "verdict",
        "is_bug": False,
        "explanation": "possible negative offset, did not prove it",
    }
    res = agentic.explore(_explore_meta(), ScriptedLLM([dict(hedge), dict(hedge)]), max_steps=20)
    actions = [s.action for s in res.steps]
    assert actions.count("confirm-gate") == 1  # nudged once, no infinite loop
    assert res.verdict is not None and res.verdict.is_bug is False


def test_confirmation_gate_fires_on_flagged_unproven_sink_despite_confident_verdict() -> None:
    """BEHAVIORAL trigger: the model flags a sink as caller-owned/unchecked in a mid-walk
    THOUGHT, never runs a proving tool, then emits a CONFIDENT (non-hedged) false verdict.
    The gate must still fire — on the flagged-but-unproven signal, not verdict vocabulary.
    (This is the exact libraw failure: strong suspicion at step ~9, confident false at the end.)"""
    script = [
        {
            "thought": (
                "copy_samples blindly reads from a caller-owned pointer; need to check callers"
            ),
            "action": "call",
            "tool": "read_function",
            "args": {"name": "copy_samples"},
        },
        {
            "thought": "the wrappers look fine and checks are sufficient",
            "action": "verdict",
            "is_bug": False,
            "cwe": "N/A",
            "sink": "N/A",
            "explanation": "found no sink where bounds are exceeded; all accesses are checked",
        },
        {
            "thought": "actually prove the offset now",
            "action": "call",
            "tool": "buffer_size",
            "args": {"function": "copy_samples", "pointer_var": "auStack_28"},
        },
        {
            "thought": "an underflowed offset reads before the buffer",
            "action": "verdict",
            "is_bug": True,
            "cwe": "CWE-125",
            "sink": "auStack_28[idx]",
            "explanation": "OOB read",
        },
    ]
    res = agentic.explore(_explore_meta(), ScriptedLLM(script), max_steps=20)
    assert "confirm-gate" in [s.action for s in res.steps]  # behavioral trigger fired
    assert res.verdict is not None and res.verdict.is_bug is True


def test_confirmation_gate_intercepts_loop_guard_abort_when_suspicion_armed() -> None:
    """A walk that FLAGS a sink then gets stuck re-calling a tool would loop-guard abort
    with verdict=None — silently bypassing the gate. The gate must intercept that
    non-verdict termination and force the proof (the exact 5th-libraw-run failure)."""
    same = {
        "thought": "copy_samples blindly reads a caller-owned pointer with no size check",
        "action": "call",
        "tool": "unexplored",
        "args": {},
    }
    script = [dict(same) for _ in range(5)] + [
        {
            "thought": "prove the offset now",
            "action": "call",
            "tool": "buffer_size",
            "args": {"function": "copy_samples", "pointer_var": "auStack_28"},
        },
        {
            "thought": "underflowed offset reads before the buffer",
            "action": "verdict",
            "is_bug": True,
            "cwe": "CWE-125",
            "sink": "auStack_28[idx]",
            "explanation": "OOB read",
        },
    ]
    res = agentic.explore(_explore_meta(), ScriptedLLM(script), max_steps=25)
    assert "confirm-gate" in [s.action for s in res.steps]  # intercepted, not aborted
    assert res.verdict is not None and res.verdict.is_bug is True


# --- temporal safety: the explorer must reason about POINTER LIFETIME, not just
# spatial bounds. A buffer freed in one branch and used unconditionally after is a
# use-after-free (CWE-416) — the shape a purely spatial (offset/bounds) method skips.

_UAF_ENTRY_C = """
int LLVMFuzzerTestOneInput(uchar *data, ulong size)
{
  if (size < 4) {
    return 0;
  }
  handle_record(data, size);
  return 0;
}
"""

# The freed pointer is used AFTER the free on the fall-through path: parse_into fills
# buf, an error branch frees it, and emit() then dereferences the dangling buf. The
# free site and the use site are both reachable from the untrusted entry.
_UAF_HANDLER_C = """
void handle_record(uchar *data, ulong size)
{
  char *buf;
  buf = (char *)malloc(0x40);
  parse_into(buf, data);
  if (data[0] == 0) {
    free(buf);
  }
  emit(buf, size);
  return;
}
"""


def _uaf_meta() -> ProgramMeta:
    return ProgramMeta(
        decompiled_c={
            "LLVMFuzzerTestOneInput": _UAF_ENTRY_C,
            "handle_record": _UAF_HANDLER_C,
        },
        callgraph={
            "LLVMFuzzerTestOneInput": ["handle_record"],
            "handle_record": [],
        },
        structs=[],
    )


def test_explore_reaches_use_after_free_verdict() -> None:
    # The model descends from the input entry into the handler, sees buf freed in the
    # error branch then used unconditionally after, and concludes a UAF (CWE-416) — a
    # TEMPORAL verdict the loop carries through unmodified (no spatial proving needed).
    script = [
        {
            "thought": "input enters at the entry — see which callees receive it",
            "action": "call",
            "tool": "callees",
            "args": {"name": "LLVMFuzzerTestOneInput"},
        },
        {
            "thought": "handle_record takes data/size — read it",
            "action": "call",
            "tool": "read_function",
            "args": {"name": "handle_record"},
        },
        {
            "thought": "buf is freed when data[0]==0 but emit(buf) uses it afterward on "
            "the fall-through path — the freed pointer is dereferenced later",
            "action": "verdict",
            "is_bug": True,
            "cwe": "CWE-416",
            "sink": "emit(buf) after free(buf)",
            "source": "buf freed in the data[0]==0 branch, used after",
            "explanation": "use-after-free: buf freed then passed to emit on the "
            "fall-through path: data -> handle_record -> free(buf) -> emit(buf)",
        },
    ]
    llm = ScriptedLLM(script)
    res = agentic.explore(_uaf_meta(), llm, max_steps=20)

    assert res.start_function == "LLVMFuzzerTestOneInput"
    assert res.entry_source == "input-entry"
    assert res.stop_reason == "verdict"  # not intercepted / aborted
    assert res.verdict is not None and res.verdict.is_bug
    assert res.verdict.cwe == "CWE-416"
    # the handler body (with the free) was fed back before the verdict
    assert "free(buf)" in llm.prompts[2]
    # the run was driven by the exploration system prompt
    assert llm.systems[0] == agentic._EXPLORE_SYSTEM


def test_explore_system_prompt_carries_temporal_lifetime_hook() -> None:
    # The temporal reasoning hook must actually be in the exploration system prompt:
    # a pointer freed/released is DANGLING and a later use is a UAF/double-free.
    sysp = agentic._EXPLORE_SYSTEM
    assert "POINTER LIFETIME" in sysp
    assert "dangling" in sysp.lower()
    assert "use-after-free (CWE-416)" in sysp
    assert "double-free (CWE-415)" in sysp
    # names the decompiled free/release forms the lens also keys on
    assert "operator.delete" in sysp and "_cmsUnref" in sysp and "realloc" in sysp
    # and the reassignment suppressor is stated (so the agent doesn't over-flag)
    assert "p = NULL" in sysp
    # the conclusion clause now admits a temporal verdict, not only spatial OOB
    assert "use-after-free/double-free" in sysp


def test_confirmation_gate_forces_proof_on_unproven_spatial_true_verdict() -> None:
    """Confident is_bug=True for a spatial OOB with ZERO proving tools is an unverified
    claim (the dominant libraw run-3/4 failure) — the gate forces a prove step first."""
    script = [
        {
            "thought": "this indexes past the buffer",
            "action": "verdict",
            "is_bug": True,
            "cwe": "CWE-125",
            "sink": "buf[i]",
            "explanation": "oob read",
        },
        {
            "thought": "prove it",
            "action": "call",
            "tool": "buffer_size",
            "args": {"function": "copy_samples", "pointer_var": "auStack_28"},
        },
        {
            "thought": "confirmed fixed 16 vs unclamped count",
            "action": "verdict",
            "is_bug": True,
            "cwe": "CWE-125",
            "sink": "auStack_28[i]",
            "explanation": "proven oob",
        },
    ]
    res = agentic.explore(_explore_meta(), ScriptedLLM(script), max_steps=20)
    assert "confirm-gate" in [s.action for s in res.steps]
    assert res.verdict is not None and res.verdict.is_bug is True


def test_confirmation_gate_does_not_gate_unproven_uaf_true_verdict() -> None:
    """UAF/temporal (CWE-416) is NOT proven by arg_provenance/buffer_size — a 0-proving
    True there must be accepted, not gated (the gate is scoped to spatial OOB claims)."""
    script = [
        {
            "thought": "freed then used on the reachable path",
            "action": "verdict",
            "is_bug": True,
            "cwe": "CWE-416",
            "sink": "use(p)",
            "explanation": "uaf",
        }
    ]
    res = agentic.explore(_explore_meta(), ScriptedLLM(script), max_steps=20)
    assert "confirm-gate" not in [s.action for s in res.steps]
    assert res.verdict is not None and res.verdict.is_bug is True


# ===========================================================================
# EXPLORATION-POLICY frontier (the harfbuzz breadth fix): the format-hint prior
# must DOMINATE raw input-proximity, so the SANITIZE/CFF2 path outranks the
# higher-taint DRAW path (`_get_path`/`_get_bounds`) the cold walk drowned in.
# ===========================================================================


def _font_draw(name: str, *, huge: bool = False) -> str:
    """A DRAW/getter-shaped function with STRONG parse signal (multi-byte assembly +
    indexing + memcpy) so the taint ranker floats it HIGH — the wrong path. ``huge``
    inflates it to a ~19KB inlined blob, the ASan-heavy body the explorer drowned in."""
    filler = "  /* recovered inline decompiled filler line */\n" * (400 if huge else 1)
    return (
        f"void {name}(uchar *data, ulong size)\n{{\n"
        "  uint uVar1; uint uVar2; uint i; uchar buf [128];\n"
        "  uVar1 = *(uint *)(data + 2) << 8 | (uint)data[6];\n"
        "  uVar2 = (uint)data[7] << 0x10 | (uint)data[8];\n"
        + filler
        + "  for (i = 0; i < uVar1 && i < 128; i = i + 1) {\n"
        "    buf[i] = data[i + uVar2];\n  }\n"
        "  memcpy(buf, data, uVar1);\n  return;\n}\n"
    )


# The real sink: a small body that takes a COUNT parameter (weaker DIRECT-input signal
# than the draw funcs, so it ranks LOW on raw taint) and indexes a fixed 32-byte stack
# array with it — a CWE-787. Its NAME matches the font hints cff/cff2/sanitize (score 3).
_FONT_SANITIZE_C = """
void sanitize_blob_cff2(uchar *src, uint count)
{
  uint i;
  uchar auStack_40 [32];
  for (i = 0; i < count; i = i + 1) {
    auStack_40[i] = src[i];
  }
  return;
}
"""

_FONT_ENTRY_C = """
int LLVMFuzzerTestOneInput(uchar *data, ulong size)
{
  if (size < 0x20) {
    return 0;
  }
  hb_dispatch(data, size);
  return 0;
}
"""

_FONT_DISPATCH_C = """
void hb_dispatch(uchar *data, ulong size)
{
  uint c;
  _get_path(data, size);
  _get_bounds(data, size);
  hb_glyph_extents(data, size);
  c = (uint)data[4];
  sanitize_blob_cff2(data, c);
  return;
}
"""


def _font_meta() -> ProgramMeta:
    """A harfbuzz-shaped program: the input dispatches into a huge DRAW path
    (`_get_path`/`_get_bounds`, high taint) and a `hb_glyph_extents` getter that grazes
    ONE hint keyword, alongside the small `sanitize_blob_cff2` sink (the real CFF2 OOB)
    whose name matches THREE hint keywords but ranks LOW on raw taint."""
    return ProgramMeta(
        decompiled_c={
            "LLVMFuzzerTestOneInput": _FONT_ENTRY_C,
            "hb_dispatch": _FONT_DISPATCH_C,
            "_get_path": _font_draw("_get_path", huge=True),
            "_get_bounds": _font_draw("_get_bounds"),
            "hb_glyph_extents": _font_draw("hb_glyph_extents"),
            "sanitize_blob_cff2": _FONT_SANITIZE_C,
        },
        callgraph={
            "LLVMFuzzerTestOneInput": ["hb_dispatch"],
            "hb_dispatch": ["_get_path", "_get_bounds", "hb_glyph_extents", "sanitize_blob_cff2"],
        },
        structs=[],
    )


# Font hints as recovered from an OTF PoC's magic bytes (OTTO).
_FONT_HINTS = agentic.input_format_hints(b"OTTO" + b"\x00" * 40)


def test_rank_frontier_hint_match_dominates_higher_taint() -> None:
    """The core policy fix: a hint-matching `sanitize_blob_cff2` must rank ABOVE the
    higher-taint, non-matching DRAW funcs `_get_path`/`_get_bounds`. Without the prior
    the draw path wins on raw input-proximity (the exact harfbuzz miss)."""
    tb = agentic.ToolBox(_font_meta())
    tb.entry = "LLVMFuzzerTestOneInput"
    pool = ["sanitize_blob_cff2", "_get_path", "_get_bounds"]

    # Baseline: with NO hints, raw taint puts the DRAW path first, the sink LAST.
    plain = tb._rank_frontier(pool)
    assert plain.index("_get_path") < plain.index("sanitize_blob_cff2")
    assert plain.index("_get_bounds") < plain.index("sanitize_blob_cff2")

    # With the font prior, the sink DOMINATES both higher-taint draw funcs.
    tb.format_hints = list(_FONT_HINTS)
    ranked = tb._rank_frontier(pool)
    assert ranked[0] == "sanitize_blob_cff2"
    assert ranked.index("sanitize_blob_cff2") < ranked.index("_get_path")
    assert ranked.index("sanitize_blob_cff2") < ranked.index("_get_bounds")


def test_rank_frontier_grades_by_keyword_count_not_a_binary_tier() -> None:
    """Grading (not a binary matches/doesn't tier) is what breaks the harfbuzz tie:
    `sanitize_blob_cff2` matches cff/cff2/sanitize (3 hits) and must outrank
    `hb_glyph_extents`, which grazes ONE generic keyword (`glyph`) but has HIGHER taint.
    A binary tier would put both in tier-0 and let taint pick the wrong (glyph) one."""
    tb = agentic.ToolBox(_font_meta())
    tb.entry = "LLVMFuzzerTestOneInput"
    tb.format_hints = list(_FONT_HINTS)
    pool = ["sanitize_blob_cff2", "hb_glyph_extents"]

    # taint alone would rank the glyph getter above the sink...
    taint = tb.localize_candidates(limit=200)
    assert taint.index("hb_glyph_extents") < taint.index("sanitize_blob_cff2")
    # ...but the 3-keyword sink outranks the 1-keyword getter under graded matching.
    assert tb._rank_frontier(pool) == ["sanitize_blob_cff2", "hb_glyph_extents"]


def test_frontier_steers_off_the_big_decoy_to_the_hint_sink() -> None:
    """End-to-end: the model would tunnel into the 19KB `_get_path` decoy (top taint),
    but with the format prior `unexplored()` floats the small `sanitize_blob_cff2` sink
    to the FRONT of the frontier; a walk that trusts the frontier reaches a proven
    verdict on it. Proves the policy steers breadth, not just the ranker in isolation."""
    meta = _font_meta()
    # the drowning decoy really is huge; the sink is small and navigable.
    assert len(meta.decompiled_c["_get_path"]) > 15000
    assert len(meta.decompiled_c["sanitize_blob_cff2"]) < 400

    # the frontier the model sees ranks the sink ahead of the big decoy + draw path.
    tb = agentic.ToolBox(meta)
    tb.entry = "LLVMFuzzerTestOneInput"
    tb.format_hints = list(_FONT_HINTS)
    frontier = tb.unexplored()
    assert frontier.index("sanitize_blob_cff2") < frontier.index("_get_path")
    assert frontier.index("sanitize_blob_cff2") < frontier.index("hb_glyph_extents")
    assert "format-hint prior" in frontier and "not a filter" in frontier

    # a scripted walk that follows the top of that frontier reaches the bug + proves it.
    script = [
        {
            "thought": "survey the frontier before diving",
            "action": "call",
            "tool": "unexplored",
            "args": {},
        },
        {
            "thought": "top hint-matching frontier pick is the cff2 sanitize sink",
            "action": "call",
            "tool": "read_function",
            "args": {"name": "sanitize_blob_cff2"},
        },
        {
            "thought": "unclamped count indexes a fixed 32-byte stack array",
            "action": "call",
            "tool": "buffer_size",
            "args": {"function": "sanitize_blob_cff2", "pointer_var": "auStack_40"},
        },
        {
            "thought": "fixed 32 vs unclamped attacker count",
            "action": "verdict",
            "is_bug": True,
            "cwe": "CWE-787",
            "sink": "auStack_40[i]",
            "source": "count parsed from font input",
            "explanation": "OOB write: unclamped count indexes a fixed 32-byte stack array",
        },
    ]
    res = agentic.explore(meta, ScriptedLLM(script), max_steps=20, format_hints=list(_FONT_HINTS))
    assert res.verdict is not None and res.verdict.is_bug is True
    assert "sanitize_blob_cff2" in res.visited
    # the model never had to drown in the 19KB decoy to reach the verdict.
    assert "_get_path" not in res.visited


# ===========================================================================
# read_region ANTI-DROWNING: a missing landmark in a huge inlined body must NOT
# be a dead end — it falls back to sequential windowed chunks the model can page.
# ===========================================================================


def _huge_inlined_body() -> str:
    # a ~30KB body with a memcpy sink buried deep and NO 'cff2_sink' landmark.
    lines = [
        f"  iVar{i} = *(int *)(param_1 + {i * 4});  /* inlined field load */" for i in range(1500)
    ]
    lines.insert(900, "  memcpy(dst, src, attacker_len);  /* the real sink */")
    return "void inlined_parent(char *param_1){\n" + "\n".join(lines) + "\n}\n"


def test_read_region_landmark_miss_falls_back_to_chunks() -> None:
    """A landmark absent from a 30KB body must not dead-end: read_region falls back to
    the FIRST sequential window plus a continuation hint, so the body stays navigable."""
    body = _huge_inlined_body()
    out = read_region(body, around="cff2_sink_not_here")
    # honest about the miss (kept for the existing 'not found' contract)...
    assert "not found" in out
    # ...but it FALLS BACK to sequential windows instead of stopping.
    assert "falling back to SEQUENTIAL windows" in out
    assert "window 1 of" in out
    # it returns real body content from the head (not an empty dead-end message).
    assert "inlined field load" in out
    # and tells the model how to continue: a concrete next offset.
    assert "read_region(offset=" in out
    assert "more window(s)" in out


def test_read_region_chunk_continuation_pages_forward() -> None:
    """The continuation hint's offset actually pages forward: the second window shows
    LATER content (the buried memcpy sink) that the first head window did not."""
    body = _huge_inlined_body()
    first = read_region(body, around="missing_landmark")
    assert "memcpy(dst, src, attacker_len)" not in first  # sink is past the head window
    # extract the offset the tail hint told us to continue at, and page to it.
    import re as _re

    m = _re.search(r"read_region\(offset=(\d+)\)", first)
    assert m is not None
    nxt = read_region(body, offset=int(m.group(1)))
    assert "char offset" in nxt
    # paging forward reaches deeper content than the head window (progress, not a loop).
    assert "char offset" in nxt and nxt != first


# ===========================================================================
# ADVERSARIAL VERIFICATION: a SECOND, skeptical pass that tries to REFUTE a
# confident POSITIVE finding before it stands — the fix for confident FALSE
# POSITIVES (the harfbuzz CFFIndex::operator[] miss: the model claimed an
# unchecked OOB read over a sink that ACTUALLY HAS the offset bounds check).
# ===========================================================================

# A GUARDED sink modeled on the harfbuzz case: the offset read IS bounds-checked
# (`if (offset1 < offset0 || offset1 > count) return`) — but a first pass reasoning
# over the decompiled rendering can MISS/OMIT that check and flag a CWE-125 OOB read.
_GUARDED_SINK_C = """
uint cff_index_get(uchar *base, uint idx, uint count)
{
  uint offset0;
  uint offset1;
  offset0 = *(uint *)(base + idx * 4);
  offset1 = *(uint *)(base + idx * 4 + 4);
  if (offset1 < offset0 || offset1 > count) {
    return 0;
  }
  return (uint)*(uchar *)(base + offset1);
}
"""

_GUARDED_ENTRY_C = """
int LLVMFuzzerTestOneInput(uchar *data, ulong size)
{
  if (size < 8) {
    return 0;
  }
  cff_index_get(data, (uint)data[0], (uint)size);
  return 0;
}
"""


def _guarded_meta() -> ProgramMeta:
    return ProgramMeta(
        decompiled_c={
            "LLVMFuzzerTestOneInput": _GUARDED_ENTRY_C,
            "cff_index_get": _GUARDED_SINK_C,
        },
        callgraph={"LLVMFuzzerTestOneInput": ["cff_index_get"]},
        structs=[],
    )


def test_adversarial_verification_refutes_false_positive_and_downgrades() -> None:
    """(a) The explorer confidently flags a CWE-125 OOB read on cff_index_get; the
    SKEPTIC re-reads the sink, FINDS the offset bounds check the first pass missed, and
    REFUTES — explore downgrades the verdict to is_bug=False and cites the guard."""
    script = [
        # --- first pass: the (wrong) confident positive ---
        {
            "thought": "input enters here; see who receives it",
            "action": "call",
            "tool": "callees",
            "args": {"name": "LLVMFuzzerTestOneInput"},
        },
        {
            "thought": "read the index getter",
            "action": "call",
            "tool": "read_function",
            "args": {"name": "cff_index_get"},
        },
        {
            "thought": "trace the buffer base",
            "action": "call",
            "tool": "buffer_size",
            "args": {"function": "cff_index_get", "pointer_var": "base"},
        },
        {
            "thought": "offset1 indexes base with no visible clamp",
            "action": "verdict",
            "is_bug": True,
            "cwe": "CWE-125",
            "sink": "read of *(base + offset1) in cff_index_get",
            "source": "offset1 parsed from attacker input",
            "explanation": "cff_index_get reads *(base+offset1) with an attacker offset1 "
            "and no bounds check",
        },
        # --- second pass: the SKEPTIC finds the guard the first pass missed ---
        {
            "thought": "audit: re-read the sink and hunt for the guard",
            "action": "call",
            "tool": "read_function",
            "args": {"name": "cff_index_get"},
        },
        {
            "thought": "there IS a range check on offset1 before the read",
            "action": "verdict",
            "is_bug": False,
            "cwe": "CWE-125",
            "sink": "if (offset1 < offset0 || offset1 > count) return — bounds check present",
            "source": "offset1",
            "explanation": "cff_index_get DOES bounds-check offset1 (offset1 < offset0 || "
            "offset1 > count) before reading *(base+offset1); the first pass "
            "missed it — safe",
        },
    ]
    llm = ScriptedLLM(script)
    res = agentic.explore(_guarded_meta(), llm, max_steps=20)

    # the two-phase flow ran: the skeptic pass used the adversarial system prompt
    assert agentic._VERIFY_SYSTEM in llm.systems
    # the finding was REFUTED and DOWNGRADED
    assert res.review is not None and res.review.upheld is False
    assert res.verdict is not None and res.verdict.is_bug is False
    # the concrete guard the skeptic found is recorded...
    assert "offset1" in res.review.checked_guard and "bounds check" in res.review.checked_guard
    # ...and folded into the downgraded verdict's explanation for the report.
    assert "[ADVERSARIAL-VERIFICATION: REFUTED]" in res.verdict.explanation
    assert "offset1" in res.verdict.explanation
    # the skeptic was seeded with the exact claimed finding + the sink body
    verify_header = next(
        p for p, s in zip(llm.prompts, llm.systems, strict=True) if s == agentic._VERIFY_SYSTEM
    )
    assert "CWE-125" in verify_header and "cff_index_get" in verify_header
    assert "REFUTE" in verify_header


def test_adversarial_verification_upholds_when_no_guard_found() -> None:
    """(b) A REAL bug (copy_samples: unclamped count into a fixed 16-byte stack array):
    the skeptic hunts for a clamp, finds none, and UPHOLDS — is_bug=True stands."""
    script = [
        # --- first pass: the (correct) positive ---
        {
            "thought": "read the leaf",
            "action": "call",
            "tool": "read_function",
            "args": {"name": "copy_samples"},
        },
        {
            "thought": "recover the fixed bound",
            "action": "call",
            "tool": "buffer_size",
            "args": {"function": "copy_samples", "pointer_var": "auStack_28"},
        },
        {
            "thought": "unclamped count writes past the fixed array",
            "action": "verdict",
            "is_bug": True,
            "cwe": "CWE-787",
            "sink": "auStack_28[count] in copy_samples",
            "source": "count from data+4",
            "explanation": "unclamped attacker count writes past a fixed 16-byte auStack_28 "
            "in copy_samples",
        },
        # --- second pass: the skeptic looks hard and finds NO guard ---
        {
            "thought": "audit: re-read copy_samples for a clamp",
            "action": "call",
            "tool": "read_function",
            "args": {"name": "copy_samples"},
        },
        {
            "thought": "check the buffer bound vs the loop count",
            "action": "call",
            "tool": "buffer_size",
            "args": {"function": "copy_samples", "pointer_var": "auStack_28"},
        },
        {
            "thought": "the loop count is never clamped on any reaching path",
            "action": "verdict",
            "is_bug": True,
            "cwe": "CWE-787",
            "sink": "auStack_28[count] — no clamp on count on any path",
            "source": "count",
            "explanation": "hunted for a clamp in copy_samples and its callers; count is "
            "never bounded; the OOB write stands",
        },
    ]
    llm = ScriptedLLM(script)
    res = agentic.explore(_explore_meta(), llm, max_steps=20)

    assert agentic._VERIFY_SYSTEM in llm.systems  # the skeptic pass ran
    assert res.review is not None and res.review.upheld is True
    assert res.verdict is not None and res.verdict.is_bug is True  # finding STANDS
    assert res.verdict.cwe == "CWE-787"
    assert "REFUTED" not in res.verdict.explanation  # not downgraded


def test_adversarial_verification_can_be_disabled() -> None:
    """(c) adversarial=False bypasses the second pass entirely — the raw first-pass
    positive is returned, no skeptic prompt, no review."""
    script = [
        {
            "thought": "read the leaf",
            "action": "call",
            "tool": "read_function",
            "args": {"name": "copy_samples"},
        },
        {
            "thought": "recover the bound",
            "action": "call",
            "tool": "buffer_size",
            "args": {"function": "copy_samples", "pointer_var": "auStack_28"},
        },
        {
            "thought": "oob",
            "action": "verdict",
            "is_bug": True,
            "cwe": "CWE-787",
            "sink": "auStack_28[count]",
            "source": "count",
            "explanation": "oob write",
        },
    ]
    llm = ScriptedLLM(script)
    res = agentic.explore(_explore_meta(), llm, max_steps=20, adversarial=False)

    assert res.verdict is not None and res.verdict.is_bug is True
    assert res.review is None  # no verification recorded
    assert agentic._VERIFY_SYSTEM not in llm.systems  # skeptic never invoked


def test_adversarial_verification_skips_a_false_verdict() -> None:
    """(d) A negative verdict needs no refutation — it is never sent to the skeptic."""
    script = [
        {
            "thought": "all accesses bounded",
            "action": "verdict",
            "is_bug": False,
            "cwe": "",
            "sink": "",
            "explanation": "every access is bounded by a checked length; safe",
        },
    ]
    llm = ScriptedLLM(script)
    res = agentic.explore(_explore_meta(), llm, max_steps=20)

    assert res.verdict is not None and res.verdict.is_bug is False
    assert res.review is None  # nothing to verify
    assert agentic._VERIFY_SYSTEM not in llm.systems  # skeptic never invoked


def test_verify_finding_uncited_refutation_does_not_downgrade() -> None:
    """The BALANCE rule: a skeptic that argues 'safe' but names NO concrete guard does
    NOT get to discard a finding — an over-eager refutation without a cited guard is
    treated as UPHELD, so a real bug is not dropped on a hand-wave."""
    verdict = agentic.AgentVerdict(
        is_bug=True,
        cwe="CWE-125",
        sink="read of buf[i] in cff_index_get",
        source="i from input",
        explanation="unchecked read in cff_index_get",
    )
    # skeptic asserts safety but cites no guard (empty sink) -> must be kept (upheld).
    llm = ScriptedLLM(
        [
            {
                "thought": "probably fine",
                "action": "verdict",
                "is_bug": False,
                "cwe": "CWE-125",
                "sink": "",
                "explanation": "looks safe to me",
            },
        ]
    )
    review = agentic.verify_finding(_guarded_meta(), verdict, llm)
    assert review.upheld is True
    assert review.checked_guard == ""
    assert "no concrete guard" in review.reason.lower() or "uncited" in review.reason.lower()


def test_verify_finding_inconclusive_upholds() -> None:
    """When the skeptic reaches no verdict within budget, the finding is KEPT (upheld),
    never silently dropped."""
    verdict = agentic.AgentVerdict(
        is_bug=True,
        cwe="CWE-787",
        sink="auStack_28[count] in copy_samples",
        source="count",
        explanation="oob write in copy_samples",
    )
    # a skeptic that only ever calls a tool, never concluding, exhausts max_steps.
    calls = [
        {
            "thought": "look",
            "action": "call",
            "tool": "search_functions",
            "args": {"substr": f"z{i}"},
        }
        for i in range(10)
    ]
    review = agentic.verify_finding(_explore_meta(), verdict, ScriptedLLM(calls), max_steps=4)
    assert review.upheld is True
    assert "no conclusion" in review.reason.lower()


def test_verify_system_prompt_frames_skeptical_refutation() -> None:
    s = agentic._VERIFY_SYSTEM
    assert "SKEPTIC" in s
    assert "REFUTE" in s and "FALSE POSITIVE" in s
    assert "DEFAULT TO REFUTED" in s
    # it names the guard shapes + the tools it re-runs on the exact offset/buffer
    assert "bounds check" in s and "clamp" in s and "early-return" in s
    assert "arg_provenance" in s and "buffer_size" in s and "callers" in s
    # and states the HONEST limit: cannot recover a decompiler-DROPPED guard
    assert "dropped" in s.lower() and "same decompiled code" in s.lower()
