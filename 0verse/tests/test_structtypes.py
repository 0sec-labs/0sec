"""Struct-type context enrichment — offset-matching selection logic.

Pure/deterministic: no Ghidra, no codex. Uses a synthetic decompiled body plus a
hand-built struct list mirroring what ``harvest_structs`` pulls from the DWARF-populated
DataTypeManager, to prove the offset heuristic reattaches the right layout (the
ingredient that let codex flag the lcms ``WriteCLUT`` OOB read on the real target)."""

from __future__ import annotations

from typing import Any

from zeroverse.structtypes import (
    body_offsets,
    select_structs,
    struct_context,
)

# The lcms ``_cms_interp_struc`` layout as recovered from DWARF: nInputs at +8 is the
# attacker-controlled loop bound; nSamples is a FIXED 15-element array at +0x10.
INTERP = {
    "name": "_cms_interp_struc",
    "size": 204,
    "fields": [
        {"offset": 0x0, "type": "cmsContext", "name": "ContextID", "is_array": False, "count": 0},
        {
            "offset": 0x4,
            "type": "cmsUInt32Number",
            "name": "dwFlags",
            "is_array": False,
            "count": 0,
        },
        {
            "offset": 0x8,
            "type": "cmsUInt32Number",
            "name": "nInputs",
            "is_array": False,
            "count": 0,
        },
        {
            "offset": 0xC,
            "type": "cmsUInt32Number",
            "name": "nOutputs",
            "is_array": False,
            "count": 0,
        },
        {
            "offset": 0x10,
            "type": "cmsUInt32Number[15]",
            "name": "nSamples",
            "is_array": True,
            "count": 15,
        },
        {
            "offset": 0x4C,
            "type": "cmsUInt32Number[15]",
            "name": "Domain",
            "is_array": True,
            "count": 15,
        },
        {"offset": 0xC4, "type": "void *", "name": "Table", "is_array": False, "count": 0},
    ],
}

# A decoy struct: has a field at +8 (common) but nothing else relevant. Should not
# out-rank the real match, and should not qualify on a single trivial offset.
DECOY = {
    "name": "_io_marker",
    "size": 12,
    "fields": [
        {"offset": 0x0, "type": "void *", "name": "next", "is_array": False, "count": 0},
        {"offset": 0x8, "type": "int", "name": "pos", "is_array": False, "count": 0},
    ],
}

# The real WriteCLUT loop shape: bound read from (cVar2 + 8), array indexed at
# (cVar2 + 0x10 + uVar5 * 4). Offsets 8 and 0x10 both present.
WRITECLUT_LOOP = """
  cVar2 = pcVar1[1];
  if (*(int *)(cVar2 + 8) != 0) {
    uVar5 = 0;
    do {
      gridPoints[uVar5 - 4] = *(cmsUInt8Number *)(cVar2 + 0x10 + uVar5 * 4);
      uVar5 = uVar5 + 1;
      cVar2 = pcVar1[1];
    } while (uVar5 < *(uint *)(cVar2 + 8));
  }
"""


def test_body_offsets_extracts_additive_displacements() -> None:
    offs = body_offsets(WRITECLUT_LOOP)
    assert 0x8 in offs and 0x10 in offs
    # `uVar5 - 4` is a subtraction (stack temp), never a struct field displacement.
    assert 4 not in offs


def test_selects_matching_struct_by_offsets() -> None:
    picked = select_structs(WRITECLUT_LOOP, [DECOY, INTERP])
    assert [s["name"] for s in picked][:1] == ["_cms_interp_struc"]


def test_decoy_single_offset_does_not_qualify() -> None:
    # DECOY matches only +8 (one non-zero offset) -> below min_matches, not named.
    picked = select_structs(WRITECLUT_LOOP, [DECOY])
    assert picked == []


def test_context_names_bound_and_array_fields() -> None:
    ctx = struct_context(WRITECLUT_LOOP, [INTERP])
    assert "RECOVERED STRUCT TYPES" in ctx
    assert "nInputs" in ctx and "nSamples" in ctx
    assert "+0x8" in ctx and "+0x10" in ctx
    assert "FIXED-SIZE ARRAY" in ctx  # the OOB-target array is flagged


def test_noop_when_no_structs() -> None:
    assert struct_context(WRITECLUT_LOOP, None) == ""
    assert struct_context(WRITECLUT_LOOP, []) == ""


def test_noop_when_body_does_no_struct_access() -> None:
    # A function with no matching offset access -> no struct is attached.
    body = "int add(int a, int b) { return a + b; }"
    assert struct_context(body, [INTERP]) == ""


def test_named_struct_included_even_without_offset_match() -> None:
    # A typedef Ghidra kept in the signature -> included by name even with no offsets.
    body = "int f(_cms_interp_struc *p) { return g(p); }"
    picked = select_structs(body, [INTERP])
    assert [s["name"] for s in picked] == ["_cms_interp_struc"]


def test_selection_is_bounded_and_deterministic() -> None:
    # Many qualifying structs -> capped at max_structs, stable order.
    many: list[dict[str, Any]] = []
    for i in range(20):
        many.append(
            {
                "name": f"s{i:02d}",
                "size": 64,
                "fields": [
                    {"offset": 0x8, "type": "int", "name": "a", "is_array": False, "count": 0},
                    {"offset": 0x10, "type": "int", "name": "b", "is_array": False, "count": 0},
                ],
            }
        )
    picked = select_structs(WRITECLUT_LOOP, many, max_structs=5)
    assert len(picked) == 5
    assert select_structs(WRITECLUT_LOOP, many, max_structs=5) == picked  # deterministic
