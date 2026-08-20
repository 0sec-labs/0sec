"""Ranking internal (stripped) functions for the address-mode harness."""

from __future__ import annotations

from pathlib import Path

from zeroverse.fuzz.binary_targets import (
    exported_entries_of,
    infer_param_roles,
    rank_internal_targets,
    reachable_from_exports,
)
from zeroverse.fuzz.harness import HarnessSpec, recover_signature, template_harness

# A stripped .so as Ghidra sees it: the export keeps its name; internals are FUN_<entry>.
_FUNCS = ["fw_load", "FUN_00101170", "FUN_00101100", "FUN_001011c0", "FUN_00101020"]
_DECOMPILED = {
    # reachable parser: walks a pointer param in a loop bounded by a length param
    "FUN_00101170": (
        "uchar FUN_00101170(long d, int len)\n"
        "{ int i=0; while (i < len) { int l = *(char *)(d + i);"
        " for (int j=0;j<l;j++) acc ^= *(char *)(d + i + 1 + j); i += l + 1; } }"
    ),
    # UNREACHABLE parser-shaped helper (same shape, but no export reaches it)
    "FUN_00101100": (
        "int FUN_00101100(long d, int len)\n"
        "{ int s=0; for (int i=0;i<len;i++) s += *(char *)(d + i); return s; }"
    ),
    # reachable NON-parser (arithmetic only)
    "FUN_001011c0": "int FUN_001011c0(int a, int b)\n{ return a * b + 7; }",
    # noise stub
    "FUN_00101020": "void FUN_00101020(void)\n{ return; }",
}
_CALLGRAPH = {"fw_load": ["FUN_00101170", "FUN_001011c0"]}


def test_exported_entries_are_the_named_functions() -> None:
    assert exported_entries_of(_FUNCS) == ["fw_load"]


def test_reachable_from_exports_closure() -> None:
    reach = reachable_from_exports(_CALLGRAPH, ["fw_load"])
    assert "FUN_00101170" in reach and "FUN_001011c0" in reach
    assert "FUN_00101100" not in reach  # the dead parser is unreachable


def test_ranking_prioritizes_reachable_parser() -> None:
    ranked = rank_internal_targets(
        _FUNCS, _DECOMPILED, _CALLGRAPH,
        exported_entries=["fw_load"], image_base=0x100000,
    )
    order = [t.func for t in ranked]
    # the reachable parser is #1
    assert ranked[0].func == "FUN_00101170"
    assert ranked[0].reachable and ranked[0].offset == 0x1170  # entry - image_base
    # reachable parser ranks ABOVE the unreachable parser (reachability discriminates)
    assert order.index("FUN_00101170") < order.index("FUN_00101100")
    # ...and ABOVE the reachable non-parser (parser shape discriminates)
    assert order.index("FUN_00101170") < order.index("FUN_001011c0")
    # the noise stub is last / lowest
    assert ranked[-1].score == 0.0
    # only FUN_ internals are ranked, never the named export
    assert all(t.func.startswith("FUN_") for t in ranked)


def test_infer_param_roles_long_typed_buffer_is_drivable() -> None:
    """On stripped code Ghidra types the buffer pointer as `long`; role inference reads
    the body to mark the indexed param as the fuzz buffer (input) and the loop-bound
    param as length, so the addr-mode harness can actually DRIVE it."""
    body = ("uchar FUN_1(long d, int len)\n{ int i = 0; while (i < len)"
            " { uchar c = *(char *)(d + i); i = i + 1; } }")
    sig = recover_signature("FUN_1", body)
    assert not sig.is_fuzzable          # no pointer param -> the heuristic would fail
    roles = infer_param_roles(sig, body)
    assert roles == ["input", "length"]
    # the harness casts the fuzz pointer to the buffer param's type (long) — a pointer
    # and a 64-bit int share the arg register, so the callee gets the real address.
    spec = HarnessSpec(
        func="FUN_1",
        signature=sig,
        lib=Path("/s.so"),
        func_offset=0x1170,
        param_roles=roles,
    )
    src = template_harness(spec)
    assert "zeroverse_fn((long)buf, (int)len);" in src


def test_infer_param_roles_pointer_buffer() -> None:
    body = "int g(uchar *p, int n)\n{ int i; for (i = 0; i < n; i = i + 1) x = p[i]; }"
    sig = recover_signature("g", body)
    assert infer_param_roles(sig, body) == ["input", "length"]


def test_infer_param_roles_no_buffer_returns_none() -> None:
    body = "int h(int a, int b)\n{ return a + b; }"
    assert infer_param_roles(recover_signature("h", body), body) is None


def test_ranking_offset_uses_image_base() -> None:
    ranked = rank_internal_targets(
        ["FUN_00108000"],
        {
            "FUN_00108000": (
                "int FUN_00108000(long p, int n)\n"
                "{ return *(char*)(p+n); }"
            )
        },
        {},
        exported_entries=[],
        image_base=0x100000,
    )
    assert ranked[0].offset == 0x8000  # 0x108000 - 0x100000
