"""Reachability gate on candidate selection — `localize.input_reachable` and its
application in the agentic ToolBox candidate surfaces. Engine-free: synthetic
`ProgramMeta` call graphs, no Ghidra/codex/network.

The claim under test: a function with NO path from the input entry
(`LLVMFuzzerTestOneInput`/`main`) in the augmented call graph AND not address-taken
cannot be an input-triggered bug, so it must be EXCLUDED from the candidate set — while
a reachable function stays. CONSERVATIVE escape: when no entry / no graph exists,
reachability can't be computed and NOTHING is filtered (an incomplete indirect-edge
graph must never over-filter a real candidate).
"""

from __future__ import annotations

from zeroverse import agentic
from zeroverse.backends._noise import LIBFUZZER_ENTRY
from zeroverse.backends.ghidra import ProgramMeta
from zeroverse.localize import input_reachable, input_reachable_set

# --- a program with a reachable parser + an island library helper -------------
#
#   LLVMFuzzerTestOneInput -> parse_input -> read_field   (the input path)
#   _Large_integer_to_chars                                (island: no caller edge,
#                                                           not address-taken)

_ENTRY = """
int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
  return parse_input(data, size);
}
"""
_PARSE = """
int parse_input(uint8_t *p, ulong n)
{
  uint len = p[0] << 8 | p[1];
  ulong i = 0;
  while (i < n) { read_field(p + i, len); i = i + 1; }
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
# a libc++-shaped number-formatting helper: real body, but no path from the entry and
# its address is never taken — the exact shape of the leak we exclude.
_ISLAND = """
ulong _Large_integer_to_chars(char *first, char *last, ulong value, int base)
{
  ulong x = value;
  do { *--last = "0123456789abcdef"[x % base]; x = x / base; } while (x != 0);
  return (ulong)last;
}
"""


def _meta() -> ProgramMeta:
    return ProgramMeta(
        decompiled_c={
            LIBFUZZER_ENTRY: _ENTRY,
            "parse_input": _PARSE,
            "read_field": _READ_FIELD,
            "_Large_integer_to_chars": _ISLAND,
        },
        callgraph={
            LIBFUZZER_ENTRY: ["parse_input"],
            "parse_input": ["read_field"],
        },
    )


# --- input_reachable / input_reachable_set ------------------------------------

def test_reachable_functions_are_reachable() -> None:
    m = _meta()
    assert input_reachable(m, LIBFUZZER_ENTRY) is True
    assert input_reachable(m, "parse_input") is True
    assert input_reachable(m, "read_field") is True


def test_island_helper_is_unreachable() -> None:
    m = _meta()
    # no path from the entry AND not address-taken -> confidently unreachable.
    assert input_reachable(m, "_Large_integer_to_chars") is False
    reach = input_reachable_set(m)
    assert reach is not None
    assert "_Large_integer_to_chars" not in reach
    assert {LIBFUZZER_ENTRY, "parse_input", "read_field"} <= reach


def test_address_taken_island_is_admitted() -> None:
    # same island, but now address-taken (a candidate indirect-call target whose real
    # edge the recovery may have missed) -> admitted, NOT excluded (recall over precision).
    m = _meta()
    m.address_taken = ["_Large_integer_to_chars"]
    assert input_reachable(m, "_Large_integer_to_chars") is True
    assert "_Large_integer_to_chars" in (input_reachable_set(m) or set())


# --- conservative escape: no entry / no graph => filter NOTHING ----------------

def test_no_entry_returns_none_and_filters_nothing() -> None:
    m = ProgramMeta(
        decompiled_c={
            "helper_a": "int helper_a(char *p){ return p[0]; }",
            "helper_b": "int helper_b(void){ return 0; }",
        },
        callgraph={"helper_a": ["helper_b"]},
    )
    # no LLVMFuzzerTestOneInput / main entry -> reachability uncomputable -> None.
    assert input_reachable_set(m) is None
    # ...so the gate keeps EVERYTHING (never over-filters).
    assert input_reachable(m, "helper_a") is True
    assert input_reachable(m, "helper_b") is True


def test_no_callgraph_returns_none() -> None:
    m = ProgramMeta(decompiled_c={LIBFUZZER_ENTRY: _ENTRY}, callgraph={})
    # entry present but no edges recovered -> can't compute reachability -> don't filter.
    assert input_reachable_set(m) is None
    assert input_reachable(m, "anything") is True


# --- application in the ToolBox candidate surfaces -----------------------------

def test_unreachable_island_excluded_from_candidates() -> None:
    tb = agentic.ToolBox(_meta())
    # the reachable parsers survive as candidates...
    localized = tb.localize_candidates(limit=20)
    assert "parse_input" in localized or "read_field" in localized
    # ...but the unreachable library helper is gone from BOTH candidate surfaces.
    assert "_Large_integer_to_chars" not in localized
    out = tb.list_candidates()
    assert "_Large_integer_to_chars" not in out


def test_reachable_candidate_survives_the_gate() -> None:
    tb = agentic.ToolBox(_meta())
    out = tb.list_candidates()
    # a reachable memory-op function still surfaces (the gate only drops unreachables).
    assert "read_field" in out or "parse_input" in out


def test_no_entry_toolbox_filters_nothing() -> None:
    # a program with no input entry: the gate is a no-op, so an island function is NOT
    # dropped (conservative — reachability couldn't be computed).
    m = ProgramMeta(
        decompiled_c={
            "transform_block": (
                "void transform_block(uchar *buf, uint n){ uint i; "
                "for (i=0;i<n;i++){ buf[i] = buf[i] ^ 0x5a; } }"
            ),
        },
        callgraph={},
    )
    tb = agentic.ToolBox(m)
    assert tb._input_reachable_set() is None
    assert tb._drop_input_unreachable(["transform_block"]) == ["transform_block"]
