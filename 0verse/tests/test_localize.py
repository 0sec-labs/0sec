"""Input-taint localization + inlined-region navigation, exercised on synthetic
call graphs and bodies — no Ghidra, no codex, no network.

The claim under test is the *inversion*: a function that parses attacker bytes
(indexes the input buffer, assembles multi-byte integers, loops to the size param)
must outrank a store/loop-heavy function that is NOT on the input path — the exact
failure of the old memop ranker (it chased a math kernel over the parser). We assert
that ordering directly, plus the graph propagation, the parse-signal components, the
inlined-blob surfacing, and the region-chunking tool.
"""

from __future__ import annotations

from zeroverse import agentic, localize
from zeroverse.backends.ghidra import ProgramMeta

# --- a synthetic program with a clear input path + a store-heavy distractor ----
#
# entry -> parse_header -> read_field   (the input path: these touch data/size)
# math_kernel / build_table are store/loop-heavy but NOT reachable from the entry.

_ENTRY = """
int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
  return parse_header(data, size);
}
"""

_PARSE_HEADER = """
int parse_header(uint8_t *p, ulong n)
{
  uint len = p[0] << 8 | p[1];
  ulong i = 0;
  while (i < n) {
    read_field(p + i, len);
    i = i + 1;
  }
  return len;
}
"""

_READ_FIELD = """
void read_field(uint8_t *q, uint cap)
{
  uint tag = q[0] << 8 | q[1] << 0x10;
  memcpy(g_out, q, cap);
  return;
}
"""

# store/loop heavy, high memop score, but NOT reachable from the fuzz entry and it
# never touches a parameter-as-buffer beyond its own local math.
_MATH_KERNEL = """
double math_kernel(double *a)
{
  int i;
  for (i = 0; i < 256; i = i + 1) {
    a[i] = a[i] * a[i] + a[i] * 2.0;
  }
  return a[0];
}
"""

_BUILD_TABLE = """
void build_table(void)
{
  int tbl [64];
  int i;
  for (i = 0; i < 64; i = i + 1) {
    tbl[i] = i * i;
  }
  return;
}
"""


def _meta() -> ProgramMeta:
    return ProgramMeta(
        decompiled_c={
            "LLVMFuzzerTestOneInput": _ENTRY,
            "parse_header": _PARSE_HEADER,
            "read_field": _READ_FIELD,
            "math_kernel": _MATH_KERNEL,
            "build_table": _BUILD_TABLE,
        },
        callgraph={
            "LLVMFuzzerTestOneInput": ["parse_header"],
            "parse_header": ["read_field"],
            "math_kernel": [],
            "build_table": [],
        },
    )


# --- the core inversion --------------------------------------------------------


def test_input_parsers_outrank_storeheavy_distractors():
    scored = localize.localize_scored(_meta())
    order = [item.function for item in scored]
    # both parsers rank above the store/loop-heavy non-tainted functions
    assert order.index("parse_header") < order.index("math_kernel")
    assert order.index("parse_header") < order.index("build_table")
    assert order.index("read_field") < order.index("math_kernel")
    assert order.index("read_field") < order.index("build_table")


def test_memop_ranker_would_rank_distractor_high():
    """Sanity: the OLD signal really does over-rank the distractor, so the inversion
    above is meaningful and not a tautology."""
    tb = agentic.ToolBox(_meta())
    memop_order = tb.rank_memops(limit=10)
    # math_kernel scores high on the pure memop heuristic (store in a loop) ...
    assert "math_kernel" in memop_order
    # ... yet the taint ranker puts the parsers ahead of it.
    taint_order = localize.localize_candidates(_meta(), limit=10)
    assert taint_order.index("parse_header") < taint_order.index("math_kernel")


def test_top_candidate_is_a_parser():
    cands = localize.localize_candidates(_meta(), limit=3)
    assert cands[0] in {"parse_header", "read_field"}


# --- entry detection -----------------------------------------------------------


def test_find_entry_prefers_libfuzzer():
    dc = {"LLVMFuzzerTestOneInput": _ENTRY, "main": "int main(int c, char **v){return 0;}"}
    assert localize.find_entry(dc, {}) == "LLVMFuzzerTestOneInput"


def test_find_entry_main_fallback():
    dc = {"main": "int main(int c, char **v){return 0;}", "helper": "void helper(void){}"}
    assert localize.find_entry(dc, {}) == "main"


def test_find_entry_none_when_absent():
    dc = {"some_func": "void some_func(void){}"}
    assert localize.find_entry(dc, {}) is None


def test_find_entry_from_callgraph_only():
    # entry present as a call-graph node even if not decompiled
    assert localize.find_entry({}, {"LLVMFuzzerTestOneInput": ["x"]}) == "LLVMFuzzerTestOneInput"


# --- taint propagation ---------------------------------------------------------


def test_taint_decays_with_depth():
    cg = {"LLVMFuzzerTestOneInput": ["a"], "a": ["b"], "b": ["c"]}
    params = {"a": frozenset({"p"}), "b": frozenset({"p"}), "c": frozenset({"p"})}
    dc = {k: f"void {k}(char *p){{ return; }}" for k in ("a", "b", "c")}
    dc["LLVMFuzzerTestOneInput"] = _ENTRY
    t = localize.propagate_taint(dc, cg, "LLVMFuzzerTestOneInput", params)
    assert t["LLVMFuzzerTestOneInput"] == 1.0
    assert t["a"] > t["b"] > t["c"] > 0


def test_taint_skips_parameterless_leaf():
    cg = {"LLVMFuzzerTestOneInput": ["leaf"]}
    # leaf has no parameters -> attacker data cannot flow into it
    params = {"leaf": frozenset()}
    dc = {"LLVMFuzzerTestOneInput": _ENTRY, "leaf": "void leaf(void){ return; }"}
    t = localize.propagate_taint(dc, cg, "LLVMFuzzerTestOneInput", params)
    assert "leaf" not in t


def test_taint_flows_to_undecompiled_callee():
    # an external/undecompiled callee has an unknown signature -> flow conservatively
    cg = {"LLVMFuzzerTestOneInput": ["ext_parse"]}
    t = localize.propagate_taint(
        {"LLVMFuzzerTestOneInput": _ENTRY}, cg, "LLVMFuzzerTestOneInput", {}
    )
    assert t.get("ext_parse", 0) > 0


def test_no_entry_no_taint():
    assert localize.propagate_taint({"f": "..."}, {}, None, {}) == {}


# --- parse signal components ---------------------------------------------------


def test_parse_signal_param_index():
    body = "void f(char *p){ int x = p[3]; }"
    assert localize._param_indexed(body, frozenset({"p"}))
    assert localize.parse_signal(body, frozenset({"p"})) >= 3.0


def test_parse_signal_byte_assembly():
    body = "int f(uchar *p){ return p[0] << 8 | p[1]; }"
    assert localize.parse_signal(body, frozenset({"p"})) > localize.parse_signal(
        "int f(uchar *p){ return p[0]; }", frozenset({"p"})
    )


def test_parse_signal_loop_on_param():
    body = "void f(char *p, uint n){ uint i=0; while (i < n) { p[i]=0; i++; } }"
    assert localize._loop_bounded_by_param(body, frozenset({"p", "n"}))


def test_parse_signal_param_to_sink():
    body = "void f(char *p, uint n){ memcpy(dst, p, n); }"
    assert localize._param_to_sink(body, frozenset({"p", "n"}))


def test_byte_assembly_weighted_down_without_param_index():
    """Local integer math that shifts by 8/16/24 (number formatting) must score lower
    than the same shift assembly reading FROM an indexed input buffer — otherwise STL
    helpers pollute the top of the ranking (the harfbuzz _Floating_to_chars case)."""
    off_buffer = "uint fmt(void){ uint x = 0; x = x << 8 | x << 0x10 | x << 0x18; return x; }"
    on_buffer = "uint parse(uchar *p){ return p[0] << 8 | p[1] << 0x10 | p[2] << 0x18; }"
    assert localize.parse_signal(on_buffer, frozenset({"p"})) > localize.parse_signal(
        off_buffer, frozenset()
    )


def test_parse_signal_zero_for_local_only():
    body = "void f(void){ int x[10]; int i; for(i=0;i<10;i++) x[i]=i; }"
    assert localize.parse_signal(body, frozenset()) == 0.0


# --- inlined-blob surfacing ----------------------------------------------------


def test_large_reachable_blob_surfaces():
    """A giant fuzz-reachable function (vuln inlined into it) must be admitted and
    float up even though its shape is diffuse — the libraw parseFujiMakernotes case."""
    blob = "void parseFuji(uchar *p, ulong n)\n{\n" + ("  do_stuff();\n" * 4000) + "  return;\n}\n"
    dc = {
        "LLVMFuzzerTestOneInput": _ENTRY.replace("parse_header", "parseFuji"),
        "parseFuji": blob,
    }
    cg = {"LLVMFuzzerTestOneInput": ["parseFuji"]}
    m = ProgramMeta(decompiled_c=dc, callgraph=cg)
    cands = localize.localize_candidates(m, limit=5)
    assert "parseFuji" in cands
    # and the size bonus is actually applied
    row = next(item for item in localize.localize_scored(m) if item.function == "parseFuji")
    assert row.size >= localize._INLINE_BYTES


def test_rank_of_reports_position_and_total():
    m = _meta()
    rank, total = localize.rank_of(m, "parse_header")
    assert 1 <= rank <= total
    # a filtered / absent function reports len+1 ("not ranked")
    missing_rank, total2 = localize.rank_of(m, "does_not_exist")
    assert missing_rank == total2 + 1


# --- region navigation ---------------------------------------------------------


def _big_body() -> str:
    lines = [f"  step_{i}(x);" for i in range(2000)]
    lines.insert(1500, "  memcpy(dst, src, attacker_len);  /* the sink */")
    return "void huge(char *src){\n" + "\n".join(lines) + "\n}\n"


def test_read_region_small_body_returned_whole():
    body = "void f(void){ return; }"
    assert localize.read_region(body) == body


def test_read_region_around_landmark_centers_and_annotates():
    body = _big_body()
    out = localize.read_region(body, around="memcpy")
    assert "memcpy(dst, src, attacker_len)" in out
    assert "chars before" in out  # there is context before the landmark
    assert "chars after" in out
    # the window is bounded, not the whole 30KB+ body
    assert len(out) < len(body)


def test_read_region_offset():
    body = _big_body()
    out = localize.read_region(body, offset=len(body) // 2)
    assert "char offset" in out


def test_read_region_landmark_miss_is_honest():
    body = _big_body()
    out = localize.read_region(body, around="no_such_token_here")
    assert "not found" in out


def test_read_region_snaps_to_lines():
    body = _big_body()
    out = localize.read_region(body, around="memcpy", window=400)
    # the shown slice should start at a line boundary (no partial leading token)
    shown = out.split("]\n", 1)[1]
    body_lines = {ln.strip() for ln in body.splitlines()}
    # every non-annotation line of the slice is a real, whole line of the body
    for ln in shown.splitlines():
        s = ln.strip()
        if s and not s.startswith("/*"):
            assert s in body_lines


# --- ToolBox / agent integration ----------------------------------------------


def test_toolbox_localize_candidates_text():
    tb = agentic.ToolBox(_meta())
    txt = tb.localize_candidates_text()
    assert "input-taint ranked" in txt
    assert "parse_header" in txt


def test_toolbox_read_region_dispatch():
    tb = agentic.ToolBox(_meta())
    out = tb.call("read_region", {"name": "read_field", "around": "memcpy"})
    assert "memcpy" in out


def test_read_region_unknown_function():
    tb = agentic.ToolBox(_meta())
    out = tb.call("read_region", {"name": "nope"})
    assert "not found" in out


def test_localize_candidates_in_catalog():
    tb = agentic.ToolBox(_meta())
    assert "localize_candidates" in tb.tool_names()
    assert "read_region" in tb.tool_names()


class _ColdLLM:
    """Verdicts immediately, recording which start function the loop chose."""

    def __init__(self) -> None:
        self.prompts: list[str] = []

    def complete_json(self, system, prompt, schema):
        self.prompts.append(prompt)
        return {"action": "verdict", "is_bug": False, "explanation": "done"}


def test_run_agent_cold_start_picks_top_candidate():
    llm = _ColdLLM()
    res = agentic.run_agent(_meta(), None, llm, max_steps=2)
    # cold start anchored on a taint-ranked parser, not a distractor
    assert res.start_function in {"parse_header", "read_field"}
    assert res.start_function in llm.prompts[0]
