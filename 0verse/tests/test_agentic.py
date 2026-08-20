"""Agentic tool-loop scanner — loop mechanics, tool routing, and termination
exercised with a scripted mock LLM (no codex, no Ghidra, no network).

The mock returns a pre-scripted list of actions; the test asserts the ReAct loop
executes each tool, feeds the observation back, and terminates on the verdict —
and that the tools themselves resolve a raw ``+ N`` offset access to the recovered
struct field (the ``find_structs_for_pointer`` behavior the real run depends on).
"""

from __future__ import annotations

from typing import Any

from zeroverse import agentic
from zeroverse.backends.ghidra import ProgramMeta

# The WriteCLUT shape, offset-arithmetic form: a loop reads a fixed array at +0x10
# indexed by uVar5, bounded by a count read from +8. cVar2 is a _cms_interp_struc*.
WRITECLUT_C = """
void WriteCLUT(int *io, char *cVar2)
{
  uint uVar5;
  uVar5 = 0;
  while (uVar5 < *(uint *)(cVar2 + 8)) {
    write_u16(io, *(ushort *)(cVar2 + 0x10 + uVar5 * 4));
    uVar5 = uVar5 + 1;
  }
  return;
}
"""

HELPER_C = """
int write_u16(int *io, ushort v) { return io_put(io, v); }
"""

# Recovered struct: nInputs (a count) at +8, nSamples[15] (a FIXED array) at +0x10.
INTERP_STRUCT = {
    "name": "_cms_interp_struc",
    "size": 0x40,
    "fields": [
        {"offset": 0, "type": "Context", "name": "ContextID", "is_array": False, "count": 0},
        {"offset": 8, "type": "uint", "name": "nInputs", "is_array": False, "count": 0},
        {"offset": 0x10, "type": "uint[15]", "name": "nSamples", "is_array": True, "count": 15},
    ],
}


def _meta() -> ProgramMeta:
    return ProgramMeta(
        decompiled_c={"WriteCLUT": WRITECLUT_C, "write_u16": HELPER_C},
        callgraph={"WriteCLUT": ["write_u16"], "cmsWriteTag": ["WriteCLUT"]},
        structs=[INTERP_STRUCT],
    )


class ScriptedLLM:
    """Replays a fixed list of action dicts, one per ``complete_json`` call, and
    records the prompts it saw so the test can assert observations were fed back."""

    def __init__(self, script: list[dict[str, Any]]) -> None:
        self.script = list(script)
        self.prompts: list[str] = []

    def complete_json(self, system: str, prompt: str, schema: dict[str, Any]) -> dict[str, Any]:
        self.prompts.append(prompt)
        assert "action" in schema["required"]  # the agent schema, not the scan one
        if not self.script:
            return {"action": "verdict", "is_bug": False, "explanation": "out of script"}
        return self.script.pop(0)


# --- tool-surface unit checks ----------------------------------------------


def test_find_structs_for_pointer_resolves_offset_to_array() -> None:
    tb = agentic.ToolBox(_meta())
    obs = tb.find_structs_for_pointer("WriteCLUT", "cVar2")
    # It resolved cVar2's +8 and +0x10 displacements to the recovered struct...
    assert "_cms_interp_struc" in obs
    assert "nInputs" in obs and "nSamples" in obs
    # ...and flagged the fixed-size array (the OOB target).
    assert "FIXED-SIZE ARRAY" in obs
    assert "0x8" in obs and "0x10" in obs  # the matched offsets are reported


def test_find_structs_for_pointer_unknown_base_lists_available() -> None:
    tb = agentic.ToolBox(_meta())
    obs = tb.find_structs_for_pointer("WriteCLUT", "nope")
    assert "no offset arithmetic" in obs and "cVar2" in obs


def test_read_function_suggests_close_names() -> None:
    tb = agentic.ToolBox(_meta())
    assert "not found" in tb.read_function("WriteCLut")
    assert "WriteCLUT" in tb.read_function("WriteCLut")  # close-name suggestion
    assert "while" in tb.read_function("WriteCLUT")  # real body returned


def test_callers_and_callees_from_callgraph() -> None:
    tb = agentic.ToolBox(_meta())
    assert "cmsWriteTag" in tb.callers("WriteCLUT")
    assert "write_u16" in tb.callees("WriteCLUT")
    # An indirect/entry target has no callers -> honest note, not a crash.
    assert "no known callers" in tb.callers("cmsWriteTag")


def test_get_struct_and_search_and_candidates() -> None:
    tb = agentic.ToolBox(_meta())
    assert "nSamples" in tb.get_struct("_cms_interp_struc")
    assert "not found" in tb.get_struct("bogus")
    assert "WriteCLUT" in tb.search_functions("write")
    assert "no function name contains" in tb.search_functions("zzz")
    # loop_oob lens surfaces WriteCLUT (tainted-count driven loop store) or reports none.
    cand = tb.list_candidates()
    assert "candidate" in cand or "no candidate" in cand


def test_unknown_tool_returns_error_observation() -> None:
    tb = agentic.ToolBox(_meta())
    assert "unknown tool" in tb.call("frobnicate", {})


# --- buffer_size provenance tool -------------------------------------------
#
# Synthetic decompiled bodies exercising each provenance class the tool must
# classify: local stack array, heap malloc, calloc(count,size), caller-owned
# parameter, and an unrecoverable load. No Ghidra/codex — pure string dispatch.

_STACK_C = """
void parse_stack(uchar *in, uint n)
{
  int local_20;
  undefined1 auStack_48 [32];
  for (local_20 = 0; local_20 < n; local_20 = local_20 + 1) {
    auStack_48[local_20] = in[local_20];
  }
  return;
}
"""

_HEAP_C = """
void parse_heap(uchar *in, uint n)
{
  char *pcVar1;
  uint uVar2;
  uVar2 = n;
  pcVar1 = (char *)malloc((ulong)(n + 1) * 4);
  memcpy(pcVar1, in, (ulong)uVar2 * 4);
  return;
}
"""

_CALLOC_C = """
void parse_calloc(uchar *in, uint count)
{
  short *psVar1;
  psVar1 = (short *)calloc((ulong)count, 2);
  psVar1[count] = 0;
  return;
}
"""

_PARAM_C = """
void fill_dst(char *dst, uchar *src, uint len)
{
  uint uVar1;
  for (uVar1 = 0; uVar1 < len; uVar1 = uVar1 + 1) {
    dst[uVar1] = src[uVar1];
  }
  return;
}
"""

_LOAD_C = """
void use_field(long ctx)
{
  char *pcVar1;
  pcVar1 = *(char **)(ctx + 0x18);
  pcVar1[64] = 'x';
  return;
}
"""


def _buf_meta() -> ProgramMeta:
    return ProgramMeta(
        decompiled_c={
            "parse_stack": _STACK_C,
            "parse_heap": _HEAP_C,
            "parse_calloc": _CALLOC_C,
            "fill_dst": _PARAM_C,
            "use_field": _LOAD_C,
        },
        callgraph={"outer": ["fill_dst"], "other": ["fill_dst"]},
        structs=[],
    )


def test_buffer_size_local_stack_array() -> None:
    tb = agentic.ToolBox(_buf_meta())
    obs = tb.buffer_size("parse_stack", "auStack_48")
    assert "LOCAL STACK ARRAY" in obs
    assert "32" in obs  # recovered element count
    assert "stack-buffer-overflow" in obs


def test_buffer_size_heap_malloc_recovers_size_expr() -> None:
    tb = agentic.ToolBox(_buf_meta())
    obs = tb.buffer_size("parse_heap", "pcVar1")
    assert "HEAP ALLOCATION" in obs
    assert "malloc" in obs
    # the (possibly nested) size expression is recovered, not just "malloc(...)"
    assert "(n + 1) * 4" in obs


def test_buffer_size_calloc_flags_count_times_size() -> None:
    tb = agentic.ToolBox(_buf_meta())
    obs = tb.buffer_size("parse_calloc", "psVar1")
    assert "HEAP ALLOCATION" in obs and "calloc" in obs
    assert "count*size" in obs  # the (count, element_size) note fired
    assert "(ulong)count, 2" in obs


def test_buffer_size_parameter_is_caller_owned_and_lists_callers() -> None:
    tb = agentic.ToolBox(_buf_meta())
    obs = tb.buffer_size("fill_dst", "dst")
    assert "PARAMETER" in obs and "caller-owned" in obs
    # it surfaces the callers so the agent can pivot to recover the real size
    assert "outer" in obs and "other" in obs


def test_buffer_size_unknown_load_is_honest() -> None:
    tb = agentic.ToolBox(_buf_meta())
    obs = tb.buffer_size("use_field", "pcVar1")
    assert "UNKNOWN" in obs
    # it shows the RHS it saw rather than guessing a size
    assert "ctx + 0x18" in obs


def test_buffer_size_missing_function_and_dispatch() -> None:
    tb = agentic.ToolBox(_buf_meta())
    assert "not found" in tb.buffer_size("nope", "p")
    assert "empty pointer_var" in tb.buffer_size("parse_stack", "")
    # routes through the generic call() dispatcher with the documented arg names
    routed = tb.call("buffer_size", {"function": "parse_stack", "pointer_var": "auStack_48"})
    assert "LOCAL STACK ARRAY" in routed
    assert "buffer_size" in tb.tool_names()


# --- ReAct loop mechanics ---------------------------------------------------


def test_loop_routes_tools_then_terminates_on_verdict() -> None:
    script = [
        {
            "thought": "offset arithmetic on cVar2 — resolve it",
            "action": "call",
            "tool": "find_structs_for_pointer",
            "args": {"function": "WriteCLUT", "base_var": "cVar2"},
        },
        {
            "thought": "nSamples[15] indexed by nInputs count — OOB",
            "action": "verdict",
            "is_bug": True,
            "cwe": "CWE-125",
            "sink": "nSamples[nInputs]",
            "source": "attacker-controlled nInputs",
            "explanation": "fixed 15-element array read past its end",
        },
    ]
    llm = ScriptedLLM(script)
    res = agentic.run_agent(_meta(), "WriteCLUT", llm, max_steps=8)

    assert res.stop_reason == "verdict"
    assert res.verdict is not None
    assert res.verdict.is_bug and res.verdict.cwe == "CWE-125"
    # Two turns: one tool call, one verdict.
    assert [s.action for s in res.steps] == ["call", "verdict"]
    # The struct observation was fed back into the second prompt.
    assert "_cms_interp_struc" in llm.prompts[1]
    # The starting body is in the first prompt (no pre-baked struct context there).
    assert "WriteCLUT" in llm.prompts[0] and "_cms_interp_struc" not in llm.prompts[0]


def test_loop_uses_provider_native_conversation_when_available() -> None:
    class Conversation:
        def __init__(self, script: list[dict[str, Any]]) -> None:
            self.script = script
            self.appended: list[str] = []
            self.calls = 0

        def append_user(self, text: str) -> None:
            self.appended.append(text)

        def complete_json(self) -> dict[str, Any]:
            self.calls += 1
            return self.script.pop(0)

    class NativeLLM:
        def __init__(self) -> None:
            self.conversation: Conversation | None = None
            self.opening: tuple[str, str, dict[str, Any]] | None = None

        def begin_conversation(
            self, system: str, prompt: str, schema: dict[str, Any]
        ) -> Conversation:
            self.opening = (system, prompt, schema)
            self.conversation = Conversation(
                [
                    {
                        "thought": "inspect callers",
                        "action": "call",
                        "tool": "callees",
                        "args": {"name": "WriteCLUT"},
                    },
                    {
                        "thought": "the helper adds no unsafe access",
                        "action": "verdict",
                        "is_bug": False,
                        "explanation": "no bug found",
                    },
                ]
            )
            return self.conversation

    llm = NativeLLM()
    res = agentic.run_agent(_meta(), "WriteCLUT", llm, max_steps=4)

    assert res.stop_reason == "verdict"
    assert llm.opening is not None and "WriteCLUT" in llm.opening[1]
    assert llm.conversation is not None and llm.conversation.calls == 2
    assert any("Tool callees" in text for text in llm.conversation.appended)


def test_loop_stops_at_max_steps_without_verdict() -> None:
    # The model keeps calling distinct tools and never concludes.
    calls = [
        {
            "thought": "look",
            "action": "call",
            "tool": "search_functions",
            "args": {"substr": f"q{i}"},
        }
        for i in range(10)
    ]
    llm = ScriptedLLM(calls)
    res = agentic.run_agent(_meta(), "WriteCLUT", llm, max_steps=4)
    assert res.stop_reason == "max_steps"
    assert res.verdict is None
    assert len(res.steps) == 4


def test_loop_guard_aborts_on_repeated_identical_call() -> None:
    same = {"thought": "again", "action": "call", "tool": "callees", "args": {"name": "WriteCLUT"}}
    llm = ScriptedLLM([dict(same) for _ in range(10)])
    res = agentic.run_agent(_meta(), "WriteCLUT", llm, max_steps=8)
    assert res.stop_reason == "loop-guard"
    assert res.verdict is None
    # The repeated observation carried the cached result + a nudge.
    assert "[repeat]" in res.steps[-1].observation


def test_final_turn_forces_verdict_prompt() -> None:
    llm = ScriptedLLM(
        [
            {
                "thought": "one look",
                "action": "call",
                "tool": "callees",
                "args": {"name": "WriteCLUT"},
            },
            {
                "thought": "must conclude",
                "action": "verdict",
                "is_bug": False,
                "explanation": "bounded",
            },
        ]
    )
    res = agentic.run_agent(_meta(), "WriteCLUT", llm, max_steps=2)
    assert res.stop_reason == "verdict"
    assert "[FINAL TURN]" in llm.prompts[-1]


def test_start_function_missing_returns_error() -> None:
    llm = ScriptedLLM([])
    res = agentic.run_agent(_meta(), "does_not_exist", llm)
    assert res.stop_reason == "error" and res.verdict is None


def test_verdict_inferred_without_explicit_action() -> None:
    # A model that returns bug fields but forgets action='verdict' still terminates.
    # (Prove first — a spatial TRUE verdict with zero proving tools is gated.)
    llm = ScriptedLLM(
        [
            {
                "thought": "resolve",
                "action": "call",
                "tool": "get_struct",
                "args": {"name": "_cms_interp_struc"},
            },
            {
                "thought": "done",
                "is_bug": True,
                "cwe": "CWE-125",
                "sink": "s",
                "source": "in",
                "explanation": "e",
            },
        ]
    )
    res = agentic.run_agent(_meta(), "WriteCLUT", llm, max_steps=4)
    assert res.stop_reason == "verdict" and res.verdict is not None
    assert res.verdict.cwe == "CWE-125"


def test_transcript_renders_full_trajectory() -> None:
    llm = ScriptedLLM(
        [
            {
                "thought": "resolve",
                "action": "call",
                "tool": "get_struct",
                "args": {"name": "_cms_interp_struc"},
            },
            {
                "thought": "oob",
                "action": "verdict",
                "is_bug": True,
                "cwe": "CWE-125",
                "sink": "nSamples",
                "source": "nInputs",
                "explanation": "oob read",
            },
        ]
    )
    res = agentic.run_agent(_meta(), "WriteCLUT", llm)
    text = res.transcript()
    assert "get_struct" in text and "VERDICT" in text and "CWE-125" in text
    assert "[stop: verdict]" in text


# --- broadened candidate selection + deasan integration --------------------
#
# The loop-OOB lens keys on ONE shape (a tainted-count loop store). These exercise
# the broader memory-op ranker that gives the agent leads of OTHER shapes, and the
# deasan pass that strips ASan noise at the tool surface. Pure string dispatch — no
# Ghidra, no codex.

# A bounds-check-ORDERING OOB read: the guard uses <= (off-by-one) and there is no
# loop store, so loop_oob_lens walks past it — but it is a real CWE-125 the broad
# memory-op ranker must still surface as a lead.
_OOB_READ_C = """
uint sanitize_read(char *buf, int n, int i)
{
  if (i <= n) {
    return (uint)buf[i];
  }
  return 0;
}
"""

# A plain leaf with no memory operations — must rank BELOW the memop functions.
_INERT_C = """
int add_two(int a, int b)
{
  return a + b + 1;
}
"""

# An ASan-instrumented body: a real indexed store buried in shadow checks + a report.
_ASAN_STORE_C = """
void copy_bytes(char *dst, char *src, uint n)
{
  uint i;
  char cVar1;
  for (i = 0; i < n; i = i + 1) {
    cVar1 = *(char *)(((ulong)(dst + i) >> 3) + 0x7fff8000);
    if ((cVar1 != '\\0') && ((char)((byte)(dst + i) & 7) >= cVar1)) {
      __asan_report_store1(dst + i);
    }
    dst[i] = src[i];
  }
  return;
}
"""


def _broad_meta() -> ProgramMeta:
    return ProgramMeta(
        decompiled_c={
            "sanitize_read": _OOB_READ_C,
            "copy_bytes": _ASAN_STORE_C,
            "add_two": _INERT_C,
            "LLVMFuzzerTestOneInput": (
                "int LLVMFuzzerTestOneInput(char *data, ulong size)\n"
                "{ return sanitize_read(data, (int)size, (int)size); }\n"
            ),
        },
        callgraph={
            "LLVMFuzzerTestOneInput": ["sanitize_read", "copy_bytes"],
        },
        structs=[],
    )


def test_rank_memops_surfaces_non_loop_oob_shapes() -> None:
    tb = agentic.ToolBox(_broad_meta())
    ranked = tb.rank_memops(limit=10)
    # the memory-op functions rank above the inert leaf...
    assert "sanitize_read" in ranked and "copy_bytes" in ranked
    assert ranked.index("sanitize_read") < ranked.index("add_two") if "add_two" in ranked else True
    # ...and the bounds-check-ordering OOB read (which loop_oob_lens misses) is present.
    from zeroverse.bugclasses import loop_oob_lens

    lens_hits = {
        f.function for f in loop_oob_lens(_broad_meta().decompiled_c, _broad_meta().callgraph)
    }
    assert "sanitize_read" not in lens_hits  # the lens misses it
    assert "sanitize_read" in ranked  # the broad ranker catches it


def test_list_candidates_reports_both_sources() -> None:
    tb = agentic.ToolBox(_broad_meta())
    out = tb.list_candidates()
    # the broad memory-op source is present and labeled distinctly from the lens
    assert "broad memory-op candidates" in out
    assert "sanitize_read" in out


def test_toolbox_deasans_bodies_at_the_surface() -> None:
    tb = agentic.ToolBox(_broad_meta())
    assert tb._asan_funcs == 1  # copy_bytes detected as ASan
    body = tb.read_function("copy_bytes")
    # the tool observation the model reads is clean...
    assert "__asan_report" not in body and "0x7fff8000" not in body
    # ...but the real store + loop survive
    assert "dst[i] = src[i];" in body
    assert "for (i = 0; i < n" in body


# --- arg_provenance (the sink -> parent data-flow tool) ---------------------
#
# Synthetic decompiled bodies exercising each argument-computation shape the tool
# must classify: direct arithmetic on parameters, a precomputed offset temporary, a
# struct-length field, a loop induction var, a constant, and the error paths. Pure
# string dispatch — no Ghidra/codex. The flagship scenario is the libraw shape: a
# leaf sink that bounds-checks its OWN buffer but is handed an out-of-range offset
# computed with bad arithmetic in a caller.

# A safe leaf sink: it clamps the offset against its own buffer, so a per-function
# scan judges it "no bug". The real flaw is the OFFSET a caller passes in.
_READ_U32_C = """
uint read_u32(uchar *buf, int off)
{
  if ((off < 0) || (0x1000 < off)) {
    return 0;
  }
  return *(uint *)(buf + off);
}
"""

# The buggy caller: reads a count from the input and computes the offset it feeds the
# (safe) sink as `base + count * 4` — unclamped arithmetic on caller-controlled data.
_PARSE_TAG_C = """
uint parse_tag(uchar *data, int base)
{
  uint uVar1;
  int iVar2;
  uVar1 = *(uint *)(data + 8);
  iVar2 = base + uVar1 * 4;
  return read_u32(data, iVar2);
}
"""

# Direct arithmetic in the call itself: offset = param * 4 + header_len.
_DIRECT_ARITH_C = """
void feed(uchar *data, uint header_len, uint param)
{
  read_val(data, param * 4 + header_len);
  return;
}
"""

# The offset is a struct/length field loaded from caller memory.
_FIELD_ARG_C = """
void feed_field(long ctx, uchar *buf)
{
  uint uVar1;
  uVar1 = *(uint *)(ctx + 0x10);
  read_val(buf, uVar1);
  return;
}
"""

# The index is a plain loop induction variable — bounded by the loop condition.
_LOOP_ARG_C = """
void feed_loop(uchar *dst, uint n)
{
  uint uVar1;
  for (uVar1 = 0; uVar1 < n; uVar1 = uVar1 + 1) {
    store_byte(dst, uVar1);
  }
  return;
}
"""

# A constant offset — bounded, not attacker-influenced.
_CONST_ARG_C = """
void feed_const(uchar *buf)
{
  read_val(buf, 0x20);
  return;
}
"""


def _prov_meta() -> ProgramMeta:
    return ProgramMeta(
        decompiled_c={
            "read_u32": _READ_U32_C,
            "parse_tag": _PARSE_TAG_C,
            "feed": _DIRECT_ARITH_C,
            "feed_field": _FIELD_ARG_C,
            "feed_loop": _LOOP_ARG_C,
            "feed_const": _CONST_ARG_C,
        },
        callgraph={
            "parse_tag": ["read_u32"],
            "parse_file": ["parse_tag"],
        },
        structs=[],
    )


def test_arg_provenance_direct_arithmetic_on_parameters() -> None:
    tb = agentic.ToolBox(_prov_meta())
    obs = tb.arg_provenance("feed", "read_val", 1)
    # the raw offset expression is recovered verbatim...
    assert "param * 4 + header_len" in obs
    # ...the arithmetic operators are named...
    assert "multiply(*)" in obs and "add(+)" in obs
    # ...both parameter operands are surfaced...
    assert "param" in obs and "header_len" in obs
    # ...and the assessment steers the upstream pivot.
    assert "CALLER-CONTROLLED" in obs and "OUT-OF-RANGE" in obs
    assert "PIVOT UPSTREAM" in obs


def test_arg_provenance_precomputed_offset_temp_folds_arithmetic() -> None:
    # The offset is precomputed into `iVar2`; the arithmetic lives in its assignment.
    tb = agentic.ToolBox(_prov_meta())
    obs = tb.arg_provenance("parse_tag", "read_u32", 1)
    assert "iVar2" in obs
    assert "= base + uVar1 * 4" in obs  # the traced assignment is shown
    assert "multiply(*)" in obs and "add(+)" in obs  # folded from the assignment
    assert "derived-from-parameter" in obs
    assert "CALLER-CONTROLLED" in obs and "OUT-OF-RANGE" in obs


def test_arg_provenance_struct_length_field() -> None:
    tb = agentic.ToolBox(_prov_meta())
    obs = tb.arg_provenance("feed_field", "read_val", 1)
    assert "struct-field" in obs
    assert "0x10" in obs  # the field offset it loaded from
    assert "STRUCT FIELD" in obs  # the assessment branch
    assert "validated" in obs


def test_arg_provenance_loop_induction_is_bounded() -> None:
    tb = agentic.ToolBox(_prov_meta())
    obs = tb.arg_provenance("feed_loop", "store_byte", 1)
    assert "loop-induction" in obs
    assert "LOOP INDUCTION" in obs
    assert "bounded by the loop condition" in obs


def test_arg_provenance_constant_is_not_attacker_influenced() -> None:
    tb = agentic.ToolBox(_prov_meta())
    obs = tb.arg_provenance("feed_const", "read_val", 1)  # arg 0 is buf, arg 1 is 0x20
    assert "0x20" in obs
    assert "constant" in obs


def test_arg_provenance_error_paths_are_honest() -> None:
    tb = agentic.ToolBox(_prov_meta())
    # a sink the function never calls
    assert "no call to memcpy" in tb.arg_provenance("read_u32", "memcpy", 0)
    # an out-of-range argument index (read_val here takes 2 args)
    assert "out of range" in tb.arg_provenance("feed", "read_val", 5)
    # a missing function / empty sink
    assert "not found" in tb.arg_provenance("nope", "read_val", 0)
    assert "empty sink_call" in tb.arg_provenance("feed", "", 0)


def test_arg_provenance_routes_through_dispatch_with_string_index() -> None:
    # the model may emit arg_index as a JSON string ("1") — the dispatcher coerces it.
    tb = agentic.ToolBox(_prov_meta())
    routed = tb.call(
        "arg_provenance",
        {"function": "parse_tag", "sink_call": "read_u32", "arg_index": "1"},
    )
    assert "CALLER-CONTROLLED" in routed
    assert "arg_provenance" in tb.tool_names()


def test_arg_provenance_no_callers_is_noop_safe() -> None:
    # An indirect-dispatch / entry function has no callers: the tool still reports the
    # local computation honestly, and callers() degrades to a note (no crash).
    tb = agentic.ToolBox(_prov_meta())
    assert "no known callers" in tb.callers("parse_file") or "parse_file" not in tb.callgraph
    # parse_tag's own arg still analyzable even if we cannot pivot past the entry
    obs = tb.arg_provenance("parse_tag", "read_u32", 1)
    assert "CALLER-CONTROLLED" in obs


def test_agent_pivots_from_safe_sink_to_tainted_caller() -> None:
    # The flagship trajectory: the model starts on a leaf sink it judges LOCALLY safe
    # (read_u32 clamps its own offset), walks callers, pulls arg_provenance on the
    # caller's offset computation, finds unclamped arithmetic on caller-controlled
    # input, and reaches an is_bug verdict — the sink->parent pivot the strategy adds.
    script = [
        {
            "thought": "read_u32 clamps off against 0x1000 — locally safe. Before "
            "concluding, check who computes the offset it receives.",
            "action": "call",
            "tool": "callers",
            "args": {"name": "read_u32"},
        },
        {
            "thought": "parse_tag calls it — inspect how it computes the offset arg.",
            "action": "call",
            "tool": "arg_provenance",
            "args": {"function": "parse_tag", "sink_call": "read_u32", "arg_index": 1},
        },
        {
            "thought": "offset = base + count*4 from an unchecked header count — the "
            "caller can drive read_u32 out of range.",
            "action": "verdict",
            "is_bug": True,
            "cwe": "CWE-125",
            "sink": "read_u32(data, base + count*4)",
            "source": "attacker-controlled count field at data+8",
            "explanation": "parse_tag feeds the safe sink an unclamped computed offset",
        },
    ]
    llm = ScriptedLLM(script)
    res = agentic.run_agent(_prov_meta(), "read_u32", llm, max_steps=8)

    assert res.stop_reason == "verdict"
    assert res.verdict is not None and res.verdict.is_bug
    assert res.verdict.cwe == "CWE-125"
    assert [s.action for s in res.steps] == ["call", "call", "verdict"]
    # the callers observation was fed back before the arg_provenance step...
    assert "parse_tag" in llm.prompts[1]
    # ...and the arg_provenance pivot assessment was fed back before the verdict.
    assert "CALLER-CONTROLLED" in llm.prompts[2] and "PIVOT UPSTREAM" in llm.prompts[2]


def test_system_prompt_steers_sink_to_parent_pivot() -> None:
    # The strategy is only real if the guidance ships in the system prompt.
    assert "SINK LOOKS LOCALLY SAFE" in agentic._SYSTEM
    assert "arg_provenance" in agentic._SYSTEM
    assert "callers" in agentic._SYSTEM


def test_arg_provenance_pivot_still_terminates_and_guards() -> None:
    # A model that loops on arg_provenance must still hit the loop-guard, not spin.
    same = {
        "thought": "again",
        "action": "call",
        "tool": "arg_provenance",
        "args": {"function": "parse_tag", "sink_call": "read_u32", "arg_index": 1},
    }
    llm = ScriptedLLM([dict(same) for _ in range(10)])
    res = agentic.run_agent(_prov_meta(), "read_u32", llm, max_steps=8)
    assert res.stop_reason == "loop-guard"
    assert res.verdict is None
    assert "[repeat]" in res.steps[-1].observation


# --- retained reasoning + transcript bounding (issue #1705) -----------------


def test_thought_is_replayed_into_the_transcript() -> None:
    # The headline fix: the model's own reasoning re-enters its own context. Before
    # this the transcript grew with actions + observations only, so a 20-turn walk
    # re-derived its hypothesis from raw decompiler output every single turn.
    script = [
        {
            "thought": "nInputs at +8 is a count read from the file; check the array.",
            "action": "call",
            "tool": "find_structs_for_pointer",
            "args": {"function": "WriteCLUT", "pointer": "cVar2"},
        },
        {
            "thought": "nSamples is a FIXED uint[15]; the loop bound is unrelated.",
            "action": "verdict",
            "is_bug": True,
            "cwe": "CWE-125",
            "sink": "read of nSamples[uVar5]",
            "source": "nInputs from the profile",
            "explanation": "loop bounded by nInputs, array is 15 wide",
        },
    ]
    llm = ScriptedLLM(script)
    agentic.run_agent(_meta(), "WriteCLUT", llm, max_steps=8)

    # Turn 0's prompt is the bare header — nothing has been reasoned yet.
    assert "thought:" not in llm.prompts[0]
    # Turn 1 carries turn 0's reasoning verbatim, alongside the action and the
    # observation (which the loop already fed back before this change).
    assert "nInputs at +8 is a count read from the file" in llm.prompts[1]
    assert '"tool": "find_structs_for_pointer"' in llm.prompts[1]
    assert "observation:" in llm.prompts[1]


def test_empty_thought_adds_no_filler_line() -> None:
    script = [
        {"thought": "", "action": "call", "tool": "callers", "args": {"name": "WriteCLUT"}},
        {"action": "verdict", "is_bug": False, "explanation": "clean"},
    ]
    llm = ScriptedLLM(script)
    agentic.run_agent(_meta(), "WriteCLUT", llm, max_steps=8)
    assert "thought:" not in llm.prompts[1]


def test_suspicion_gate_reads_only_this_turn_not_the_replayed_transcript() -> None:
    # The behavioral confirm-gate greps THIS turn's thought. Replaying an earlier
    # suspicion into the transcript must not re-arm it once a proving tool has
    # cleared the flag — otherwise retained reasoning would perturb the gate.
    script = [
        {
            # suspicion language -> arms flagged_unproven
            "thought": "the loop reads a caller-owned pointer without a bounds check",
            "action": "call",
            "tool": "find_structs_for_pointer",  # a PROVING tool -> clears it
            "args": {"function": "WriteCLUT", "pointer": "cVar2"},
        },
        {
            # no suspicion language this turn; the earlier one is now in-context
            "thought": "nSamples is a fixed 15-wide array and the loop is bounded by it",
            "action": "verdict",
            "is_bug": False,
            "cwe": "",
            "sink": "",
            "source": "",
            "explanation": "the access is in range",
        },
    ]
    llm = ScriptedLLM(script)
    res = agentic.run_agent(_meta(), "WriteCLUT", llm, max_steps=8)

    # The suspicion IS visible in the turn-1 prompt...
    assert "without a bounds check" in llm.prompts[1]
    # ...and the gate still did not fire: the false verdict was accepted directly.
    assert [s.action for s in res.steps] == ["call", "verdict"]
    assert res.stop_reason == "verdict"
    assert res.verdict is not None and not res.verdict.is_bug


def test_middle_truncate_keeps_head_and_tail_and_marks_the_gap() -> None:
    text = "HEAD" + ("x" * 500) + "TAIL"
    out = agentic._middle_truncate(text, 100)
    assert out.startswith("HEAD")
    assert out.endswith("TAIL")
    assert "truncated from the middle" in out
    assert len(out) < len(text)
    # Under the limit is returned untouched.
    assert agentic._middle_truncate("short", 100) == "short"


def test_old_observations_are_truncated_but_recent_ones_stay_whole() -> None:
    turns = [
        agentic._Turn(text=f"\n[step {i}]\n", obs=f"OBS{i}-" + ("y" * 5000) + f"-END{i}")
        for i in range(6)
    ]
    rendered = agentic._render_transcript("HEADER", turns)

    # The header and every action record survive.
    assert rendered.startswith("HEADER")
    for i in range(6):
        assert f"[step {i}]" in rendered
    # The three most recent observations are verbatim...
    for i in (3, 4, 5):
        assert ("y" * 5000) in rendered.split(f"OBS{i}-")[1][:5001]
    # ...the older three are middle-truncated, head and tail both kept.
    assert rendered.count("truncated from the middle") == 3
    for i in range(6):
        assert f"OBS{i}-" in rendered and f"-END{i}" in rendered


def test_transcript_growth_is_bounded_across_a_long_walk() -> None:
    # The point of the cap: a 20-step walk re-sends the transcript in full every
    # turn, so the last prompt must not be ~20 whole function bodies.
    big = "z" * agentic._MAX_BODY_CHARS
    turns = [agentic._Turn(text=f"\n[step {i}]\n", obs=big) for i in range(20)]
    bounded = len(agentic._render_transcript("H", turns))
    unbounded = sum(len(t.text) + len(t.obs) for t in turns)
    assert bounded < unbounded / 2
    # Thoughts are cheap next to observations: even at the per-thought cap, 20
    # thoughts cost less than the bounded observation budget they buy their way
    # into (3 verbatim bodies + 17 truncated ones).
    thought_worst = 20 * agentic._THOUGHT_MAX_CHARS
    obs_worst = (
        agentic._OBS_KEEP_FULL * agentic._MAX_BODY_CHARS
        + (20 - agentic._OBS_KEEP_FULL) * agentic._OBS_TRUNC_CHARS
    )
    assert thought_worst < obs_worst


def test_turn_cap_drops_only_complete_oldest_records() -> None:
    turns = [
        agentic._Turn(
            text=f"\n[step {i}] thought: thought-{i}\naction: call-{i}\n",
            obs=f"observation-{i}",
        )
        for i in range(3)
    ]

    rendered = agentic._render_transcript("HEADER", turns, max_turns=2)

    assert rendered.startswith("HEADER")
    assert "[... 1 older turn(s) omitted ...]" in rendered
    assert "thought-0" not in rendered
    assert "call-0" not in rendered
    assert "observation-0" not in rendered
    for i in (1, 2):
        assert f"thought-{i}" in rendered
        assert f"call-{i}" in rendered
        assert f"observation-{i}" in rendered


def test_thought_is_capped_against_a_verbose_model() -> None:
    line = agentic._thought_line("q" * 100_000)
    assert len(line) < agentic._THOUGHT_MAX_CHARS + 200
    assert "truncated from the middle" in line
    assert agentic._thought_line("   ") == ""


def test_no_op_recency_keeps_full_records_below_cap() -> None:
    # When the number of observations is BELOW _OBS_KEEP_FULL, every
    # thought/action/observation record stays VERBATIM — no truncation,
    # no compaction notice injected by the renderer.
    full_observation = "x" * (agentic._OBS_TRUNC_CHARS + 100)
    turns = [
        agentic._Turn(
            text=f"\n[step {i}]\n"
            f"thought: deep reasoning {i}\n"
            f"action: call read_function\n",
            obs=f"full body #{i} — {full_observation} — end #{i}",
        )
        for i in range(agentic._OBS_KEEP_FULL - 1)  # below the cap
    ]
    rendered = agentic._render_transcript("HEADER\n", turns)

    assert rendered.startswith("HEADER")
    for i in range(agentic._OBS_KEEP_FULL - 1):
        assert f"deep reasoning {i}" in rendered
        assert f"full body #{i}" in rendered
        assert full_observation in rendered
    # No compaction notice anywhere — everything fit.
    assert "truncated from the middle" not in rendered


def test_verdict_gate_false_redirects_unproven_suspicion() -> None:
    # A model that flags an unchecked sink in its thought (arming
    # flagged_unproven) but never calls a proving tool, then returns
    # is_bug=false — the confirm-gate MUST fire with _CONFIRM_NUDGE,
    # redirecting the model to prove or refute instead of accepting
    # the dropped lead.
    script = [
        {
            "thought": "this sink reads a caller-owned pointer with no bounds check",
            "action": "call",
            "tool": "read_function",
            "args": {"name": "WriteCLUT"},
        },
        # Verdict with unproven suspicion — gate_false fires
        {
            "thought": "seems fine, dropping it",
            "action": "verdict",
            "is_bug": False,
            "cwe": "",
            "sink": "",
            "source": "",
            "explanation": "probably safe, moving on",
        },
        # After the nudge, model calls a proving tool to resolve
        {
            "thought": "proving the offset",
            "action": "call",
            "tool": "buffer_size",
            "args": {"function": "WriteCLUT", "pointer_var": "cVar2"},
        },
        # Second verdict — accepted because flagged_unproven was cleared
        {
            "thought": "the buffer is the right size",
            "action": "verdict",
            "is_bug": False,
            "cwe": "",
            "sink": "",
            "source": "",
            "explanation": "proved in-range",
        },
    ]
    llm = ScriptedLLM(script)
    res = agentic.run_agent(_meta(), "WriteCLUT", llm, max_steps=8)

    # The confirm-gate step is recorded between the call and the proving call
    assert [s.action for s in res.steps] == ["call", "confirm-gate", "call", "verdict"]
    assert res.stop_reason == "verdict"
    assert res.verdict is not None and not res.verdict.is_bug
    gate_index = next(i for i, step in enumerate(res.steps) if step.action == "confirm-gate")
    # The nudge appears in the gate observation and the next model prompt.
    assert "[confirmation required]" in res.steps[gate_index].observation
    assert "[confirmation required]" in llm.prompts[gate_index + 1]


def test_repeat_guard_redirects_to_confirm_gate_when_suspicion_unproven() -> None:
    # A model that repeats an identical call while flagged_unproven is set
    # (from a prior suspicious thought) and has never called a proving tool
    # should trigger the confirm-gate redirect via the repeat-guard path,
    # granting budget to prove rather than silently aborting with loop-guard.
    suspicion = {
        "thought": "this caller-owned pointer is unchecked",
        "action": "call",
        "tool": "callees",
        "args": {"name": "WriteCLUT"},
    }
    repeat = {
        "thought": "still looking",
        "action": "call",
        "tool": "callees",
        "args": {"name": "WriteCLUT"},
    }
    script = [
        suspicion,  # turn 0: arms flagged_unproven, key not cached yet
        repeat,  # turn 1: repeat_count=1 < _MAX_REPEAT=3
        repeat,  # turn 2: repeat_count=2 < 3
        repeat,  # turn 3: repeat_count=3 >= 3 → gate fires
        {
            "thought": "proving it now",
            "action": "call",
            "tool": "buffer_size",
            "args": {"function": "WriteCLUT", "pointer_var": "cVar2"},
        },
        {
            "thought": "confirmed",
            "action": "verdict",
            "is_bug": False,
            "cwe": "",
            "sink": "",
            "source": "",
            "explanation": "buffer is sized correctly",
        },
    ]
    llm = ScriptedLLM(script)
    res = agentic.run_agent(_meta(), "WriteCLUT", llm, max_steps=8)

    # Stop reason is verdict, NOT loop-guard: repeat-guard redirected.
    assert res.stop_reason == "verdict"
    # The confirm-gate step is present (the repeat-guard fired the gate).
    actions = [s.action for s in res.steps]
    assert "confirm-gate" in actions
    gate_idx = actions.index("confirm-gate")
    # The gate step carries the nudge observation.
    assert "[confirmation required]" in res.steps[gate_idx].observation
    # The nudge is in the transcript prompt fed to the next turn.
    assert "[confirmation required]" in llm.prompts[gate_idx + 1]
    # Verdict was reached with the proving tool's result in context.
    assert res.verdict is not None and not res.verdict.is_bug


# --- the skeptic gets the explorer's evidence, not its verdict --------------


def test_skeptic_header_carries_explorer_evidence_not_its_reasoning() -> None:
    steps = [
        agentic.TrajStep(
            0,
            "PERSUASIVE NARRATIVE the skeptic must not inherit",
            "call",
            "buffer_size",
            {"name": "nSamples"},
            "buffer nSamples: 60 bytes (uint[15])",
        ),
        agentic.TrajStep(1, "another narrative", "verdict"),
    ]
    block = "\n".join(agentic._explorer_evidence_block(["WriteCLUT", "write_u16"], steps))

    # Raw tool output and coverage are handed over...
    assert "buffer_size" in block and "60 bytes" in block
    assert "WriteCLUT" in block and "write_u16" in block
    # ...but the explorer's own reasoning prose is NOT.
    assert "PERSUASIVE NARRATIVE" not in block
    assert "another narrative" not in block
    # Framing is adversarial: evidence to re-check, plus the negative space.
    assert "evidence, NOT conclusions" in block
    assert "presumed WRONG" in block
    assert "never opened" in block


def test_skeptic_evidence_block_flags_a_zero_proving_explorer() -> None:
    steps = [agentic.TrajStep(0, "t", "call", "read_function", {"name": "WriteCLUT"}, "body")]
    block = "\n".join(agentic._explorer_evidence_block(["WriteCLUT"], steps))
    assert "ran NO proving tools" in block
    assert "asserted, not" in block


def test_skeptic_evidence_block_is_empty_without_explorer_context() -> None:
    # verify_finding is still callable standalone (it is a public entry point).
    assert agentic._explorer_evidence_block(None, None) == []
    assert agentic._explorer_evidence_block([], []) == []


def test_verify_finding_still_requires_a_concrete_guard_to_refute() -> None:
    # The adversarial wiring is what stops the skeptic rubber-stamping. Handing it
    # the explorer's observations must not weaken it: an is_bug=false with no named
    # guard still UPHOLDS the finding.
    v = agentic.AgentVerdict(True, "CWE-125", "read of nSamples[uVar5]", "file", "oob")
    evidence = [
        agentic.TrajStep(0, "t", "call", "buffer_size", {"name": "nSamples"}, "60 bytes")
    ]

    hand_wave = ScriptedLLM([
        {"thought": "looks fine", "action": "verdict", "is_bug": False,
         "sink": "", "explanation": "probably safe"}
    ])
    review = agentic.verify_finding(
        _meta(), v, hand_wave, explorer_visited=["WriteCLUT"], explorer_steps=evidence
    )
    assert review.upheld and not review.checked_guard

    cited = ScriptedLLM([
        {"thought": "found it", "action": "verdict", "is_bug": False,
         "sink": "if (uVar5 >= 15) return;", "explanation": "clamped above the read"}
    ])
    review2 = agentic.verify_finding(
        _meta(), v, cited, explorer_visited=["WriteCLUT"], explorer_steps=evidence
    )
    assert not review2.upheld and review2.checked_guard == "if (uVar5 >= 15) return;"
    # The evidence really did reach the skeptic's first prompt.
    assert "60 bytes" in cited.prompts[0]


def test_skeptic_toolbox_is_fresh_so_it_cannot_replay_explorer_answers() -> None:
    # Independence: the skeptic re-executes tools against the program. Seeding its
    # call cache with the explorer's results would destroy exactly that.
    v = agentic.AgentVerdict(True, "CWE-125", "read of nSamples[uVar5]", "file", "oob")
    poisoned = agentic.TrajStep(
        0, "t", "call", "buffer_size", {"name": "cVar2"}, "STALE-EXPLORER-ANSWER"
    )
    # The skeptic re-runs the EXACT same (tool, args) the explorer did.
    llm = ScriptedLLM([
        {"thought": "check it myself", "action": "call", "tool": "buffer_size",
         "args": {"name": "cVar2"}},
        {"thought": "done", "action": "verdict", "is_bug": True, "explanation": "stands"},
    ])
    review = agentic.verify_finding(
        _meta(), v, llm, explorer_visited=["WriteCLUT"], explorer_steps=[poisoned]
    )
    assert review.upheld
    # The explorer's answer is quoted ONCE, in the evidence header...
    assert llm.prompts[1].count("STALE-EXPLORER-ANSWER") == 1
    # ...and the observation fed back for the skeptic's own call is the ToolBox's
    # real result, not the replayed one: the call cache started empty.
    assert "observation:\nSTALE-EXPLORER-ANSWER" not in llm.prompts[1]
    assert "[repeat]" not in llm.prompts[1]
