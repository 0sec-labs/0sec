from __future__ import annotations

import importlib.util
from pathlib import Path

_SCRIPT = Path(__file__).parents[1] / "scripts/windows/rank-hvix-embedded-pointers.py"
_SPEC = importlib.util.spec_from_file_location("rank_hvix_embedded_pointers", _SCRIPT)
assert _SPEC and _SPEC.loader
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


def test_ranks_page_shaped_wide_input_consumer() -> None:
    descriptors = [
        {
            "call_code": 0x44,
            "handler_va": 0xFFFFF80000281234,
            "fixed_input_size": 16,
            "fixed_output_size": 0,
            "flags": 0,
        },
        {
            "call_code": 0x45,
            "handler_va": 0xFFFFF80000285678,
            "fixed_input_size": 4,
            "fixed_output_size": 0,
            "flags": 0,
        },
    ]
    decompiled = {
        "FUN_fffff80000281234": """
            uVar1 = *(ulonglong *)(param_1 + 8);
            if ((uVar1 & 0xfff) == 0) {
                FUN_fffff80000300000(ctx, param_1[1]);
            }
        """,
        "FUN_fffff80000285678": "return param_1[0];",
    }

    ranked = _MODULE.rank_handlers(descriptors, decompiled)

    assert [item["call_code"] for item in ranked] == [0x44]
    assert ranked[0]["signals"]["wide_loads"] == 1
    assert ranked[0]["signals"]["page_ops"] == 1


def test_ignores_missing_decompilation_and_low_signal_handlers() -> None:
    descriptors = [
        {
            "call_code": 1,
            "handler_va": 0x1000,
            "fixed_input_size": 8,
            "fixed_output_size": 8,
            "flags": 0,
        }
    ]

    assert _MODULE.rank_handlers(descriptors, {}) == []
    assert _MODULE.rank_handlers(descriptors, {"FUN_0000000000001000": "return *param_1;"}) == []


def test_does_not_treat_wide_hex_masks_as_page_constants() -> None:
    descriptors = [
        {
            "call_code": 0xC2,
            "handler_va": 0xFFFFF80000288450,
            "fixed_input_size": 32,
            "fixed_output_size": 8,
            "flags": 0,
        }
    ]
    decompiled = {
        "FUN_fffff80000288450": """
            flags = *(uint *)(param_1 + 0xc);
            if ((flags & 0xffffff80) != 0 ||
                (flags & 0xffffff9e) != 0) {
                return 5;
            }
            consume(param_1[2], param_1[3]);
        """
    }

    ranked = _MODULE.rank_handlers(descriptors, decompiled)

    assert len(ranked) == 1
    assert ranked[0]["signals"]["page_ops"] == 0
