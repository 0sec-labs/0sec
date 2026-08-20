from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path
from types import ModuleType

import pytest

import zeroverse.windows_afd_handler_cfg_ssa_ghidra as cfg_ssa


def _once(counts: dict[str, int], key: str, value: object) -> object:
    counts[key] = counts.get(key, 0) + 1
    if counts[key] > 1:
        raise RuntimeError(f"{key} called twice")
    return value


def _var(
    key: str,
    *,
    definition: str | None = None,
    storage: str = "unique",
    size: int = 8,
    constant: int | None = None,
    address: bool = False,
    opaque_location: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "key": key,
        "definition_op_key": definition,
        "storage_class": storage,
        "size": size,
        "constant": constant,
        "address": address,
        "opaque_location": opaque_location,
    }


def _value(value: dict[str, object]) -> dict[str, object]:
    return {"kind": "value", "value": value}


def _output(value: dict[str, object]) -> dict[str, object]:
    return {"kind": "value", "value": value}


def _target(block: str, target: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "kind": "block_target",
        "raw_block_key": block,
        "target": target or _var("raw-target", storage="ram", address=True),
    }


def _phi(predecessor: str, value: dict[str, object]) -> dict[str, object]:
    return {"kind": "phi_value", "raw_predecessor_key": predecessor, "value": value}


def _call_target(
    target_class: str = "internal_image_opaque",
    *,
    offset: int = 0x140001234,
    library: str | None = None,
    symbol: str | None = None,
) -> dict[str, object]:
    return {
        "kind": "call_target",
        "raw_space": "ram",
        "raw_offset": offset,
        "raw_size": 8,
        "raw_pointer_size": 8,
        "raw_address": True,
        "raw_constant": None,
        "raw_definition_op_key": None,
        "target_class": target_class,
        "library": library,
        "symbol": symbol,
    }


def _selector(selector: int) -> dict[str, object]:
    return _var(f"const-{selector}", storage="constant", size=4, constant=selector)


def _userop(selector: int = 0x11, name: str = "LOCK") -> dict[str, object]:
    return {
        "kind": "userop",
        "selector": _selector(selector),
        "userop_id": selector,
        "userop_name": name,
    }


def _memory_space(selector: int = 0x1B1) -> dict[str, object]:
    return {
        "kind": "memory_space",
        "selector": _selector(selector),
        "raw_space_id": selector,
        "space": "ram",
    }


def _effect_op(selector: int, key: str) -> dict[str, object]:
    return {
        "kind": "effect_op",
        "selector": _selector(selector),
        "raw_effect_op_key": key,
        "raw_effect_seq_time": selector,
    }


def _op_target(
    constant: int,
    *,
    size: int = 1,
    signed_delta: int | None = None,
    instruction_rva: int = 0x1010,
    pcode_order: int = 1,
) -> dict[str, object]:
    modulus = 1 << (size * 8)
    signed = constant - modulus if constant & (modulus >> 1) else constant
    return {
        "kind": "pcode_relative_target",
        "target": _var(
            f"const:{constant:x}:{size}:live",
            storage="constant",
            size=size,
            constant=constant,
        ),
        "raw_signed_delta": signed if signed_delta is None else signed_delta,
        "raw_instruction_rva": instruction_rva,
        "raw_pcode_order": pcode_order,
    }


def _native_target(
    *,
    offset: int = 0x140001020,
    rva: int = 0x1020,
    ordinal: int = 2,
    size: int = 8,
    key: str = "ram:140001020:8:live",
) -> dict[str, object]:
    return {
        "kind": "native_instruction_target",
        "target": _var(key, storage="ram", size=size, address=True),
        "raw_target_offset": offset,
        "raw_target_rva": rva,
        "native_instruction_ordinal": ordinal,
    }


def _opaque_location(offset: int, *, size: int = 8, space_id: int = 0x1B1) -> dict[str, object]:
    return {
        "raw_space": "ram",
        "raw_space_id": space_id,
        "raw_offset": offset,
        "raw_size": size,
        "raw_address": True,
    }


def _add_fallthrough(raw: dict[str, object], key: str = "fallthrough") -> None:
    raw["blocks"].append({"key": key, "predecessors": ["native-7"], "successors": []})
    raw["blocks"][0]["successors"].append(key)
    raw["ops"].append(
        {
            "key": f"{key}-op",
            "parent": key,
            "opcode": "COPY",
            "source_ref": {
                "function_rva": 0x1000,
                "instruction_rva": 0x1030 + len(raw["ops"]) * 0x10,
                "instruction_ordinal": 3 + len(raw["ops"]),
                "seq_time": 30 + len(raw["ops"]),
                "pcode_order": 0,
            },
            "output": _output(_var(f"{key}-value", definition=f"{key}-op")),
            "operands": [_value(_var(f"{key}-live", storage="register"))],
        }
    )


def _raw() -> dict[str, object]:
    return {
        "raw_schema_version": cfg_ssa.RAW_SCHEMA_VERSION,
        "entry_block": "native-7",
        "complete_block_enumeration": True,
        "complete_op_enumeration": True,
        "image_min": 0x140000000,
        "image_max": 0x140100000,
        "native_instruction_count": 100,
        "blocks": [
            {"key": "native-7", "predecessors": [], "successors": ["native-2"]},
            {"key": "native-2", "predecessors": ["native-7"], "successors": []},
        ],
        "ops": [
            {
                "key": "raw-op-a",
                "parent": "native-7",
                "opcode": "COPY",
                "source_ref": {
                    "function_rva": 0x1000,
                    "instruction_rva": 0x1010,
                    "instruction_ordinal": 1,
                    "seq_time": 10,
                    "pcode_order": 0,
                },
                "output": _output(_var("ssa-a", definition="raw-op-a")),
                "operands": [_value(_var("constant-4", storage="constant", size=4, constant=4))],
            },
            {
                "key": "raw-op-b",
                "parent": "native-2",
                "opcode": "INT_ADD",
                "source_ref": {
                    "function_rva": 0x1000,
                    "instruction_rva": 0x1020,
                    "instruction_ordinal": 2,
                    "seq_time": 20,
                    "pcode_order": 1,
                },
                "output": _output(_var("ssa-b", definition="raw-op-b")),
                "operands": [
                    _value(_var("ssa-a", definition="raw-op-a")),
                    _value(_var("live-register", storage="register")),
                ],
            },
        ],
    }


def test_normalizer_emits_local_cfg_ssa_and_strict_claim_boundaries() -> None:
    result = cfg_ssa.normalize_cfg_ssa(_raw())
    assert result["schema_version"].endswith("/v5")
    assert result["producer"].endswith("/v5")
    assert result["entry_block_id"] == "b0"
    assert result["blocks"] == [
        {"id": "b0", "predecessors": [], "successors": ["b1"]},
        {"id": "b1", "predecessors": ["b0"], "successors": []},
    ]
    assert result["edges"] == [{"source": "b0", "target": "b1"}]
    assert [op["id"] for op in result["ops"]] == ["o1_0", "o2_0"]
    assert result["def_use_edges"] == [
        {
            "def_op_id": "o1_0",
            "varnode_id": "v0",
            "use_op_id": "o2_0",
            "operand_index": 0,
        }
    ]
    assert result["candidate_count"] == 0
    assert result["semantic_equivalence_established"] is False
    assert result["source_sink_semantics_established"] is False
    assert result["constant_bit_patterns_width_normalized"] is True
    assert result["constant_signedness_semantics_established"] is False
    assert result["address_space_offsets_width_normalized"] is True
    assert result["address_space_offset_signedness_semantics_established"] is False
    assert result["image_bearing_constant_location_count"] == 0
    assert result["image_bearing_constant_varnode_count"] == 0
    assert result["image_bearing_constants_alpha_renamed"] is True
    assert result["image_bearing_constant_pointer_semantics_established"] is False
    assert result["image_bearing_constant_target_identity_established"] is False
    assert result["cross_build_image_bearing_constant_identity_established"] is False
    assert all(row["image_constant_id"] is None for row in result["varnodes"])
    assert result["runtime_performed"] is False


def test_varnode_rows_emit_numeric_contiguous_ids_beyond_ten() -> None:
    raw = _raw()
    raw["ops"][0]["operands"] = [
        _value(_var(f"constant-{value}", storage="constant", constant=value))
        for value in range(1, 10)
    ]
    result = cfg_ssa.normalize_cfg_ssa(raw)
    assert [row["id"] for row in result["varnodes"]] == [f"v{index}" for index in range(12)]

    reordered = _raw()
    reordered["ops"][0]["operands"] = [
        _value(_var(f"renamed-{value}", storage="constant", constant=value))
        for value in range(1, 10)
    ]
    reordered["ops"].reverse()
    replay = cfg_ssa.normalize_cfg_ssa(reordered)
    assert [row["id"] for row in replay["varnodes"]] == [f"v{index}" for index in range(12)]
    assert (
        replay["image_address_independent_fingerprint"]
        == result["image_address_independent_fingerprint"]
    )


def test_fingerprint_excludes_exact_source_rvas_but_artifact_retains_them() -> None:
    first = cfg_ssa.normalize_cfg_ssa(_raw())
    moved = _raw()
    for op in moved["ops"]:
        op["source_ref"]["function_rva"] += 0x50000
        op["source_ref"]["instruction_rva"] += 0x50000
    second = cfg_ssa.normalize_cfg_ssa(moved)
    assert (
        first["image_address_independent_fingerprint"]
        == second["image_address_independent_fingerprint"]
    )
    assert first["ops"] != second["ops"]


@pytest.mark.parametrize("version", [None, "0verse.windows-afd-handler-cfg-ssa-raw/v4", "wrong"])
def test_raw_schema_version_is_required_exactly(version: str | None) -> None:
    raw = _raw()
    if version is None:
        del raw["raw_schema_version"]
        match = "raw shape"
    else:
        raw["raw_schema_version"] = version
        match = "completeness marker"
    with pytest.raises(ValueError, match=match):
        cfg_ssa.normalize_cfg_ssa(raw)


def test_legacy_inputs_are_rejected_instead_of_dual_parsed() -> None:
    raw = _raw()
    raw["ops"][0]["inputs"] = raw["ops"][0].pop("operands")
    with pytest.raises(ValueError, match="operation shape"):
        cfg_ssa.normalize_cfg_ssa(raw)


def test_fingerprint_ignores_raw_block_op_and_temporary_names() -> None:
    first = cfg_ssa.normalize_cfg_ssa(_raw())
    renamed = _raw()
    renamed["entry_block"] = "entry-renamed"
    mapping = {"native-7": "entry-renamed", "native-2": "tail-renamed"}
    for block in renamed["blocks"]:
        block["key"] = mapping[block["key"]]
        block["predecessors"] = [mapping[key] for key in block["predecessors"]]
        block["successors"] = [mapping[key] for key in block["successors"]]
    renamed["blocks"].reverse()
    for index, op in enumerate(renamed["ops"]):
        old_key = op["key"]
        new_key = f"renamed-op-{index}"
        op["key"] = new_key
        op["parent"] = mapping[op["parent"]]
        values = [operand["value"] for operand in op["operands"] if "value" in operand]
        for varnode in ([op["output"]["value"]] if op["output"] else []) + values:
            varnode["key"] = "alpha-" + varnode["key"]
            if varnode["definition_op_key"] == old_key:
                varnode["definition_op_key"] = new_key
    definition_mapping = {"raw-op-a": "renamed-op-0", "raw-op-b": "renamed-op-1"}
    for op in renamed["ops"]:
        values = [operand["value"] for operand in op["operands"] if "value" in operand]
        for varnode in ([op["output"]["value"]] if op["output"] else []) + values:
            definition = varnode["definition_op_key"]
            if definition in definition_mapping:
                varnode["definition_op_key"] = definition_mapping[definition]
    renamed["ops"].reverse()
    second = cfg_ssa.normalize_cfg_ssa(renamed)
    assert (
        first["image_address_independent_fingerprint"]
        == second["image_address_independent_fingerprint"]
    )


def test_branch_target_changes_fingerprint_and_loop_terminates() -> None:
    left = _raw()
    _add_fallthrough(left)
    left["ops"][0]["opcode"] = "CBRANCH"
    left["ops"][0]["operands"] = [
        _target("native-2"),
        _value(_var("condition", storage="register")),
    ]
    right = _raw()
    _add_fallthrough(right)
    right["ops"][0]["opcode"] = "CBRANCH"
    right["ops"][0]["operands"] = [
        _target("native-7"),
        _value(_var("condition", storage="register")),
    ]
    assert cfg_ssa.normalize_cfg_ssa(left)["block_count"] == 3
    with pytest.raises(ValueError, match="not a CFG successor"):
        cfg_ssa.normalize_cfg_ssa(right)
    loop = _raw()
    loop["blocks"][1]["successors"] = ["native-2"]
    loop["blocks"][1]["predecessors"].append("native-2")
    assert cfg_ssa.normalize_cfg_ssa(loop)["block_count"] == 2


def test_raw_branch_target_provenance_is_validated_but_not_emitted_or_fingerprinted() -> None:
    first = _raw()
    first["ops"][0]["opcode"] = "BRANCH"
    first["ops"][0]["operands"] = [
        _target("native-2", _var("ram:140001020:8:live", storage="ram", address=True))
    ]
    moved = _raw()
    moved["ops"][0]["opcode"] = "BRANCH"
    moved["ops"][0]["operands"] = [
        _target("native-2", _var("ram:180009999:8:live", storage="ram", address=True))
    ]
    first_result = cfg_ssa.normalize_cfg_ssa(first)
    moved_result = cfg_ssa.normalize_cfg_ssa(moved)
    assert first_result["ops"][0]["operands"] == [{"kind": "block_target", "block_id": "b1"}]
    assert (
        first_result["image_address_independent_fingerprint"]
        == moved_result["image_address_independent_fingerprint"]
    )


def test_native_instruction_branch_target_is_structural_metadata_only() -> None:
    raw = _raw()
    raw["ops"][0]["opcode"] = "BRANCH"
    raw["ops"][0]["output"] = None
    raw["ops"][0]["operands"] = [_native_target()]
    raw["ops"][1]["operands"][0] = _value(_var("replacement-live", storage="register"))
    result = cfg_ssa.normalize_cfg_ssa(raw)
    branch = result["ops"][0]
    assert branch["operands"] == [
        {"kind": "native_instruction_target", "native_instruction_ordinal": 2}
    ]
    assert result["native_instruction_branch_target_count"] == 1
    assert result["native_instruction_branch_targets_preserved"] is True
    assert result["native_instruction_branch_semantics_established"] is False
    assert result["high_function_cfg_covers_all_native_branch_targets"] is False
    assert all(edge["use_op_id"] != branch["id"] for edge in result["def_use_edges"])
    assert all(edge["use_op_id"] != branch["id"] for edge in result["live_in_uses"])
    assert all(row["storage_class"] != "ram" for row in result["varnodes"])

    moved = _raw()
    moved["ops"][0]["opcode"] = "BRANCH"
    moved["ops"][0]["output"] = None
    moved["ops"][0]["operands"] = [
        _native_target(
            offset=0x140001030,
            rva=0x1030,
            ordinal=2,
            key="ram:140001030:8:live",
        )
    ]
    moved["ops"][1]["operands"][0] = _value(_var("replacement-live", storage="register"))
    assert (
        cfg_ssa.normalize_cfg_ssa(moved)["image_address_independent_fingerprint"]
        == result["image_address_independent_fingerprint"]
    )


def test_native_instruction_branch_target_width_does_not_bound_image_address() -> None:
    raw = _raw()
    raw["native_instruction_count"] = 655
    raw["ops"][0]["opcode"] = "BRANCH"
    raw["ops"][0]["output"] = None
    raw["ops"][0]["operands"] = [
        _native_target(
            offset=0x14002886F,
            rva=0x2886F,
            ordinal=96,
            size=1,
            key="ram:14002886f:1:live",
        )
    ]
    raw["ops"][1]["operands"][0] = _value(_var("replacement-live", storage="register"))
    result = cfg_ssa.normalize_cfg_ssa(raw)
    branch = result["ops"][0]
    assert branch["operands"] == [
        {"kind": "native_instruction_target", "native_instruction_ordinal": 96}
    ]


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        ("offset", "provenance"),
        ("rva", "provenance"),
        ("key", "provenance"),
        ("range", "provenance"),
        ("ordinal", "provenance"),
        ("bool", "provenance"),
    ],
)
def test_native_instruction_branch_target_rejects_forged_provenance(
    mutation: str, match: str
) -> None:
    raw = _raw()
    raw["ops"][0]["opcode"] = "BRANCH"
    raw["ops"][0]["output"] = None
    raw["ops"][1]["operands"][0] = _value(_var("replacement-live", storage="register"))
    operand = _native_target()
    raw["ops"][0]["operands"] = [operand]
    if mutation == "offset":
        operand["raw_target_offset"] = 0x140001021
    elif mutation == "rva":
        operand["raw_target_rva"] = 0x1021
    elif mutation == "key":
        operand["target"]["key"] = "ram:140001021:8:live"
    elif mutation == "range":
        operand["raw_target_offset"] = 0x150000000
        operand["raw_target_rva"] = 0x10000000
        operand["target"]["key"] = "ram:150000000:8:live"
    elif mutation == "ordinal":
        operand["native_instruction_ordinal"] = raw["native_instruction_count"]
    else:
        operand["native_instruction_ordinal"] = True
    with pytest.raises(ValueError, match=match):
        cfg_ssa.normalize_cfg_ssa(raw)


@pytest.mark.parametrize("count", [False, 0, cfg_ssa.MAX_NATIVE_INSTRUCTIONS + 1])
def test_native_instruction_count_is_exact_and_bounded(count: object) -> None:
    raw = _raw()
    raw["native_instruction_count"] = count
    with pytest.raises(ValueError, match="completeness marker"):
        cfg_ssa.normalize_cfg_ssa(raw)


def _relative_branch_raw(*, constant: int = 1, size: int = 1) -> dict[str, object]:
    raw = _raw()
    branch = {
        "key": "raw-relative-branch",
        "parent": "native-7",
        "opcode": "BRANCH",
        "source_ref": {
            "function_rva": 0x1000,
            "instruction_rva": 0x1010,
            "instruction_ordinal": 1,
            "seq_time": 11,
            "pcode_order": 1,
        },
        "output": None,
        "operands": [_op_target(constant, size=size)],
    }
    raw["ops"] = [raw["ops"][0], branch, raw["ops"][1]]
    return raw


def test_pcode_relative_branch_delta_is_structural_metadata_only() -> None:
    result = cfg_ssa.normalize_cfg_ssa(_relative_branch_raw())
    branch = next(op for op in result["ops"] if op["opcode"] == "BRANCH")
    assert branch["operands"] == [{"kind": "pcode_relative_delta_target", "signed_delta": 1}]
    assert result["pcode_relative_branch_delta_count"] == 1
    assert result["pcode_relative_branch_deltas_preserved"] is True
    assert result["pcode_relative_branch_target_resolution_established"] is False
    assert result["pcode_relative_branch_semantics_established"] is False
    assert all(edge["use_op_id"] != branch["id"] for edge in result["def_use_edges"])
    assert all(edge["use_op_id"] != branch["id"] for edge in result["live_in_uses"])
    assert all(row["constant"] != 1 for row in result["varnodes"])


@pytest.mark.parametrize(
    ("constant", "size", "signed_delta"),
    [(0, 1, 0), (1, 1, 1), (0xFF, 1, -1), (0x8000, 2, -32768)],
)
def test_pcode_relative_branch_delta_supports_exact_signed_widths_without_target_op(
    constant: int, size: int, signed_delta: int
) -> None:
    raw = _relative_branch_raw(constant=constant, size=size)
    result = cfg_ssa.normalize_cfg_ssa(raw)
    normalized = next(op for op in result["ops"] if op["opcode"] == "BRANCH")
    assert normalized["operands"] == [
        {"kind": "pcode_relative_delta_target", "signed_delta": signed_delta}
    ]


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        ("instruction", "provenance"),
        ("pcode-order", "provenance"),
        ("forged-signed", "provenance"),
        ("forged-key", "key"),
        ("forged-constant", "key"),
        ("extra", "shape"),
    ],
)
def test_pcode_relative_branch_rejects_forged_delta_provenance(mutation: str, match: str) -> None:
    raw = _relative_branch_raw()
    branch = raw["ops"][1]
    operand = branch["operands"][0]
    if mutation == "instruction":
        operand["raw_instruction_rva"] = 0x1020
    elif mutation == "pcode-order":
        operand["raw_pcode_order"] = 2
    elif mutation == "forged-signed":
        operand["raw_signed_delta"] = 2
    elif mutation == "forged-key":
        operand["target"]["key"] = "const:2:1:live"
    elif mutation == "forged-constant":
        operand["target"]["constant"] = 2
    else:
        operand["extra"] = True
    with pytest.raises(ValueError, match=match):
        cfg_ssa.normalize_cfg_ssa(raw)


def test_multiequal_binds_and_canonicalizes_predecessor_slots() -> None:
    raw = _raw()
    raw["ops"][1]["opcode"] = "MULTIEQUAL"
    raw["ops"][1]["operands"] = [_phi("native-7", raw["ops"][1]["operands"][0]["value"])]
    result = cfg_ssa.normalize_cfg_ssa(raw)
    assert result["ops"][1]["operands"][0]["block_id"] == "b0"

    raw["ops"][1]["output"] = None
    with pytest.raises(ValueError, match="definition does not bind"):
        cfg_ssa.normalize_cfg_ssa(raw)


@pytest.mark.parametrize(
    "operands,match",
    [
        ([_phi("native-7", _var("a")), _phi("native-7", _var("b"))], "exactly once"),
        ([_value(_var("a"))], "operand shape"),
        (
            [
                {
                    "kind": "phi_value",
                    "raw_predecessor_key": [],
                    "value": _var("a"),
                }
            ],
            "predecessor block",
        ),
    ],
)
def test_multiequal_predecessor_contract_fails_closed(
    operands: list[dict[str, object]], match: str
) -> None:
    raw = _raw()
    raw["ops"][1]["opcode"] = "MULTIEQUAL"
    raw["ops"][1]["operands"] = operands
    with pytest.raises(ValueError, match=match):
        cfg_ssa.normalize_cfg_ssa(raw)


def test_multiequal_reordered_predecessors_preserve_fingerprint_and_def_use() -> None:
    def diamond(predecessors: list[str]) -> dict[str, object]:
        inputs = {
            "left": _var("left-value", definition="left-op"),
            "right": _var("right-value", definition="right-op"),
        }
        return {
            "raw_schema_version": cfg_ssa.RAW_SCHEMA_VERSION,
            "entry_block": "entry",
            "complete_block_enumeration": True,
            "complete_op_enumeration": True,
            "image_min": 0x140000000,
            "image_max": 0x140100000,
            "native_instruction_count": 100,
            "blocks": [
                {"key": "entry", "predecessors": [], "successors": ["left", "right"]},
                {"key": "left", "predecessors": ["entry"], "successors": ["join"]},
                {"key": "right", "predecessors": ["entry"], "successors": ["join"]},
                {"key": "join", "predecessors": predecessors, "successors": []},
            ],
            "ops": [
                {
                    "key": "entry-op",
                    "parent": "entry",
                    "opcode": "COPY",
                    "source_ref": {
                        "function_rva": 0x1000,
                        "instruction_rva": 0x1010,
                        "instruction_ordinal": 1,
                        "seq_time": 1,
                        "pcode_order": 0,
                    },
                    "output": _output(_var("entry-value", definition="entry-op")),
                    "operands": [_value(_var("zero", storage="constant", constant=0))],
                },
                {
                    "key": "left-op",
                    "parent": "left",
                    "opcode": "COPY",
                    "source_ref": {
                        "function_rva": 0x1000,
                        "instruction_rva": 0x1020,
                        "instruction_ordinal": 2,
                        "seq_time": 2,
                        "pcode_order": 0,
                    },
                    "output": _output(_var("left-value", definition="left-op")),
                    "operands": [_value(_var("one", storage="constant", constant=1))],
                },
                {
                    "key": "right-op",
                    "parent": "right",
                    "opcode": "COPY",
                    "source_ref": {
                        "function_rva": 0x1000,
                        "instruction_rva": 0x1030,
                        "instruction_ordinal": 3,
                        "seq_time": 3,
                        "pcode_order": 0,
                    },
                    "output": _output(_var("right-value", definition="right-op")),
                    "operands": [_value(_var("two", storage="constant", constant=2))],
                },
                {
                    "key": "phi-op",
                    "parent": "join",
                    "opcode": "MULTIEQUAL",
                    "source_ref": {
                        "function_rva": 0x1000,
                        "instruction_rva": 0x1040,
                        "instruction_ordinal": 4,
                        "seq_time": 4,
                        "pcode_order": 0,
                    },
                    "output": _output(_var("phi-value", definition="phi-op")),
                    "operands": [_phi(key, inputs[key]) for key in predecessors],
                },
            ],
        }

    first = cfg_ssa.normalize_cfg_ssa(diamond(["left", "right"]))
    second = cfg_ssa.normalize_cfg_ssa(diamond(["right", "left"]))
    assert (
        first["image_address_independent_fingerprint"]
        == second["image_address_independent_fingerprint"]
    )
    assert [operand["block_id"] for operand in first["ops"][3]["operands"]] == [
        "b1",
        "b2",
    ]
    assert first["ops"][3]["operands"] == second["ops"][3]["operands"]
    assert [edge for edge in first["def_use_edges"] if edge["use_op_id"] == "o4_0"] == [
        {
            "def_op_id": "o2_0",
            "varnode_id": first["ops"][3]["operands"][0]["varnode_id"],
            "use_op_id": "o4_0",
            "operand_index": 0,
        },
        {
            "def_op_id": "o3_0",
            "varnode_id": first["ops"][3]["operands"][1]["varnode_id"],
            "use_op_id": "o4_0",
            "operand_index": 1,
        },
    ]


@pytest.mark.parametrize(
    "mutation,match",
    [
        (
            lambda raw: raw["blocks"][1].update({"predecessors": []}),
            "exactly one entry",
        ),
        (
            lambda raw: raw["blocks"][0].update({"successors": []}),
            "predecessor closure",
        ),
        (
            lambda raw: raw["ops"][0].update({"parent": "missing"}),
            "parent-bound",
        ),
        (
            lambda raw: raw["ops"][0]["source_ref"].update({"pcode_order": False}),
            "source reference",
        ),
    ],
)
def test_completeness_and_exact_source_refs_fail_closed(mutation: object, match: str) -> None:
    raw = _raw()
    mutation(raw)
    with pytest.raises(ValueError, match=match):
        cfg_ssa.normalize_cfg_ssa(raw)


def test_ssa_multiple_definition_and_conflicting_varnode_fail_closed() -> None:
    raw = _raw()
    raw["ops"][1]["output"] = _output(_var("ssa-a", definition="raw-op-a"))
    with pytest.raises(ValueError, match="owning operation"):
        cfg_ssa.normalize_cfg_ssa(raw)

    raw = _raw()
    raw["ops"][1]["operands"][0]["value"] = _var("ssa-a", definition="raw-op-a", size=4)
    with pytest.raises(ValueError, match="does not own its output"):
        cfg_ssa.normalize_cfg_ssa(raw)


def test_caps_are_exact_and_reject_bool_as_int(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _raw()
    raw["ops"][0]["output"]["value"]["size"] = False
    with pytest.raises(ValueError, match="size"):
        cfg_ssa.normalize_cfg_ssa(raw)

    monkeypatch.setattr(cfg_ssa, "MAX_OPS", 1)
    with pytest.raises(ValueError, match="extent"):
        cfg_ssa.normalize_cfg_ssa(_raw())


def test_completeness_markers_and_entry_reachability_fail_closed() -> None:
    raw = _raw()
    raw["complete_op_enumeration"] = False
    with pytest.raises(ValueError, match="completeness marker"):
        cfg_ssa.normalize_cfg_ssa(raw)

    raw = _raw()
    raw["blocks"].extend(
        [
            {"key": "cycle-a", "predecessors": ["cycle-b"], "successors": ["cycle-b"]},
            {"key": "cycle-b", "predecessors": ["cycle-a"], "successors": ["cycle-a"]},
        ]
    )
    for ordinal, key in ((3, "cycle-a"), (4, "cycle-b")):
        op_key = f"cycle-op-{ordinal}"
        raw["ops"].append(
            {
                "key": op_key,
                "parent": key,
                "opcode": "COPY",
                "source_ref": {
                    "function_rva": 0x1000,
                    "instruction_rva": 0x1000 + ordinal * 0x10,
                    "instruction_ordinal": ordinal,
                    "seq_time": ordinal,
                    "pcode_order": 0,
                },
                "output": _output(_var(f"cycle-{ordinal}", definition=op_key)),
                "operands": [_value(_var(f"live-{ordinal}", storage="register"))],
            }
        )
    with pytest.raises(ValueError, match="unreachable"):
        cfg_ssa.normalize_cfg_ssa(raw)


def test_definition_closure_rejects_missing_and_accepts_forward_definition() -> None:
    missing = _raw()
    missing["ops"][1]["operands"][0]["value"]["definition_op_key"] = "not-retained"
    with pytest.raises(ValueError, match="outside the retained operation set"):
        cfg_ssa.normalize_cfg_ssa(missing)

    forward = _raw()
    forward["ops"][0]["operands"][0] = _value(_var("future", definition="raw-op-b"))
    result = cfg_ssa.normalize_cfg_ssa(forward)
    assert any(
        edge["def_op_id"] == "o2_0" and edge["use_op_id"] == "o1_0"
        for edge in result["def_use_edges"]
    )


def test_call_forms_preserve_optional_outputs_and_address_independent_targets() -> None:
    direct = _raw()
    direct["ops"][1]["opcode"] = "CALL"
    direct["ops"][1]["operands"] = [
        _call_target(offset=0x140001234),
        _value(_var("ssa-a", definition="raw-op-a")),
    ]
    result = cfg_ssa.normalize_cfg_ssa(direct)
    assert result["ops"][1]["output"] is not None
    assert result["ops"][1]["operands"][0] == {
        "kind": "call_target",
        "target_class": "internal_image_opaque",
        "library": None,
        "symbol": None,
    }
    assert result["opaque_call_target_count"] == 1
    assert "opaque_address_count" not in result

    moved = _raw()
    moved["ops"][1]["opcode"] = "CALL"
    moved["ops"][1]["output"] = None
    moved["ops"][1]["operands"] = [
        _call_target(offset=0x180009999),
        _value(_var("ssa-a", definition="raw-op-a")),
    ]
    moved_result = cfg_ssa.normalize_cfg_ssa(moved)
    assert moved_result["ops"][1]["output"] is None
    assert (
        result["image_address_independent_fingerprint"]
        != moved_result["image_address_independent_fingerprint"]
    )
    direct["ops"][1]["output"] = None
    result_without_output = cfg_ssa.normalize_cfg_ssa(direct)
    assert (
        result_without_output["image_address_independent_fingerprint"]
        == moved_result["image_address_independent_fingerprint"]
    )

    indirect = _raw()
    indirect["ops"][1]["opcode"] = "CALLIND"
    indirect["ops"][1]["operands"] = [
        _value(_var("ssa-a", definition="raw-op-a")),
        _value(_var("argument", storage="register")),
    ]
    indirect_result = cfg_ssa.normalize_cfg_ssa(indirect)
    assert indirect_result["indirect_call_count"] == 1
    assert any(
        edge["use_op_id"] == "o2_0" and edge["operand_index"] == 0
        for edge in indirect_result["def_use_edges"]
    )
    indirect["ops"][1]["output"] = None
    assert cfg_ssa.normalize_cfg_ssa(indirect)["ops"][1]["output"] is None


def test_call_target_width_and_exact_entry_binding_fail_closed() -> None:
    valid_self = _raw()
    valid_self["ops"][1]["opcode"] = "CALL"
    valid_self["ops"][1]["operands"] = [_call_target("self", offset=0x140001000)]
    assert cfg_ssa.normalize_cfg_ssa(valid_self)["ops"][1]["operands"][0]["target_class"] == "self"

    forged_self = _raw()
    forged_self["ops"][1]["opcode"] = "CALL"
    forged_self["ops"][1]["operands"] = [_call_target("self")]
    with pytest.raises(ValueError, match="exact function entry"):
        cfg_ssa.normalize_cfg_ssa(forged_self)

    forged_nonself = _raw()
    forged_nonself["ops"][1]["opcode"] = "CALL"
    forged_nonself["ops"][1]["operands"] = [
        _call_target("internal_image_opaque", offset=0x140001000)
    ]
    with pytest.raises(ValueError, match="exact function entry"):
        cfg_ssa.normalize_cfg_ssa(forged_nonself)

    wrong_width = _raw()
    wrong_width["ops"][1]["opcode"] = "CALL"
    target = _call_target()
    target["raw_size"] = 4
    wrong_width["ops"][1]["operands"] = [target]
    with pytest.raises(ValueError, match="CALL target classification"):
        cfg_ssa.normalize_cfg_ssa(wrong_width)

    inconsistent_rva = _raw()
    inconsistent_rva["ops"][1]["source_ref"]["function_rva"] = 0x2000
    with pytest.raises(ValueError, match="one exact function RVA"):
        cfg_ssa.normalize_cfg_ssa(inconsistent_rva)

    outside = _raw()
    for op in outside["ops"]:
        op["source_ref"]["function_rva"] = 0x200000
    with pytest.raises(ValueError, match="outside its exact image"):
        cfg_ssa.normalize_cfg_ssa(outside)


def test_import_class_and_userop_identity_are_fingerprint_visible() -> None:
    first = _raw()
    first["ops"][1]["opcode"] = "CALL"
    first["ops"][1]["operands"] = [
        _call_target("external_import", library="NTOSKRNL.EXE", symbol="ExAllocatePool2")
    ]
    second = _raw()
    second["ops"][1]["opcode"] = "CALL"
    second["ops"][1]["operands"] = [
        _call_target("external_import", library="ntoskrnl.exe", symbol="ExFreePool")
    ]
    first_result = cfg_ssa.normalize_cfg_ssa(first)
    assert first_result["ops"][1]["operands"][0]["library"] == "ntoskrnl.exe"
    assert (
        first_result["image_address_independent_fingerprint"]
        != cfg_ssa.normalize_cfg_ssa(second)["image_address_independent_fingerprint"]
    )
    opaque = _raw()
    opaque["ops"][1]["opcode"] = "CALL"
    opaque["ops"][1]["operands"] = [_call_target("external_opaque")]
    assert (
        first_result["image_address_independent_fingerprint"]
        != cfg_ssa.normalize_cfg_ssa(opaque)["image_address_independent_fingerprint"]
    )

    userop = _raw()
    userop["ops"][1]["opcode"] = "CALLOTHER"
    userop["ops"][1]["operands"] = [
        _userop(),
        _value(_var("ssa-a", definition="raw-op-a")),
    ]
    userop_result = cfg_ssa.normalize_cfg_ssa(userop)
    assert userop_result["ops"][1]["operands"][0] == {
        "kind": "userop",
        "userop_id": 0x11,
        "userop_name": "LOCK",
    }
    assert userop_result["ops"][1]["output"] is not None
    userop["ops"][1]["output"] = None
    assert cfg_ssa.normalize_cfg_ssa(userop)["ops"][1]["output"] is None


def test_load_store_preserve_positions_and_exclude_raw_space_id() -> None:
    load = _raw()
    load["ops"][1]["opcode"] = "LOAD"
    load["ops"][1]["operands"] = [
        _memory_space(0x1B1),
        _value(_var("ssa-a", definition="raw-op-a")),
    ]
    load_result = cfg_ssa.normalize_cfg_ssa(load)
    assert load_result["memory_load_count"] == 1
    assert load_result["ops"][1]["operands"][0] == {"kind": "memory_space", "space": "ram"}
    assert any(
        edge["use_op_id"] == "o2_0" and edge["operand_index"] == 1
        for edge in load_result["def_use_edges"]
    )

    moved = _raw()
    moved["ops"][1]["opcode"] = "LOAD"
    moved["ops"][1]["operands"] = [
        _memory_space(0x2B2),
        _value(_var("ssa-a", definition="raw-op-a")),
    ]
    assert (
        load_result["image_address_independent_fingerprint"]
        == cfg_ssa.normalize_cfg_ssa(moved)["image_address_independent_fingerprint"]
    )

    store = _raw()
    store["ops"][1]["opcode"] = "STORE"
    store["ops"][1]["output"] = None
    store["ops"][1]["operands"] = [
        _memory_space(),
        _value(_var("ssa-a", definition="raw-op-a")),
        _value(_var("stored", storage="register")),
    ]
    store_result = cfg_ssa.normalize_cfg_ssa(store)
    assert store_result["memory_store_count"] == 1
    assert [
        edge["operand_index"]
        for edge in store_result["def_use_edges"]
        if edge["use_op_id"] == "o2_0"
    ] == [1]


def test_opaque_globals_alpha_rename_offsets_and_preserve_def_use() -> None:
    def facts(offset: int, space_id: int = 0x1B1) -> dict[str, object]:
        raw = _raw()
        raw["ops"][0]["output"] = _output(
            _var(
                "raw-global-output",
                definition="raw-op-a",
                storage="ram",
                address=True,
                opaque_location=_opaque_location(offset, space_id=space_id),
            )
        )
        raw["ops"][1]["operands"][0] = _value(
            _var(
                "raw-global-use",
                definition="raw-op-a",
                storage="ram",
                address=True,
                opaque_location=_opaque_location(offset, space_id=space_id),
            )
        )
        return raw

    first = cfg_ssa.normalize_cfg_ssa(facts(0x140010000))
    moved = cfg_ssa.normalize_cfg_ssa(facts(0x180090000))
    moved_space = cfg_ssa.normalize_cfg_ssa(facts(0x180090000, 0x2B2))
    assert (
        first["image_address_independent_fingerprint"]
        == moved["image_address_independent_fingerprint"]
    )
    assert (
        first["image_address_independent_fingerprint"]
        == moved_space["image_address_independent_fingerprint"]
    )
    assert first["opaque_global_location_count"] == 1
    assert first["opaque_global_varnode_count"] == 1
    global_row = next(row for row in first["varnodes"] if row["opaque_location_id"] == "a0")
    assert "raw_offset" not in global_row
    assert first["ops"][0]["output"] == {
        "kind": "value",
        "varnode_id": global_row["id"],
    }
    assert any(
        edge["def_op_id"] == "o1_0" and edge["use_op_id"] == "o2_0" and edge["operand_index"] == 0
        for edge in first["def_use_edges"]
    )
    assert first["opaque_global_identity_semantics_established"] is False
    assert first["opaque_global_locations_alpha_renamed"] is True
    assert first["global_symbol_identity_established"] is False
    assert first["cross_build_global_identity_established"] is False

    conflicting = facts(0x140010000)
    conflicting["ops"][1]["output"] = _output(
        _var(
            "other-space-output",
            definition="raw-op-b",
            storage="ram",
            address=True,
            opaque_location=_opaque_location(0x140020000, space_id=0x2B2),
        )
    )
    with pytest.raises(ValueError, match="conflicting raw RAM space IDs"):
        cfg_ssa.normalize_cfg_ssa(conflicting)


def test_opaque_global_equality_pattern_versions_and_output_first_ids() -> None:
    same = _raw()
    same["ops"][0]["operands"] = [
        _value(
            _var(
                "live-a",
                storage="ram",
                address=True,
                opaque_location=_opaque_location(0x140020000),
            )
        )
    ]
    same["ops"][1]["operands"] = [
        _value(
            _var(
                "live-b",
                storage="ram",
                address=True,
                opaque_location=_opaque_location(0x140020000),
            )
        )
    ]
    distinct = _raw()
    distinct["ops"][0]["operands"] = same["ops"][0]["operands"]
    distinct["ops"][1]["operands"] = [
        _value(
            _var(
                "live-c",
                storage="ram",
                address=True,
                opaque_location=_opaque_location(0x140030000),
            )
        )
    ]
    assert (
        cfg_ssa.normalize_cfg_ssa(same)["image_address_independent_fingerprint"]
        != cfg_ssa.normalize_cfg_ssa(distinct)["image_address_independent_fingerprint"]
    )

    versions = _raw()
    for index, op_key in enumerate(("raw-op-a", "raw-op-b")):
        versions["ops"][index]["output"] = _output(
            _var(
                f"version-{index}",
                definition=op_key,
                storage="ram",
                address=True,
                opaque_location=_opaque_location(0x140040000),
            )
        )
    versions["ops"][1]["operands"][0] = _value(
        _var(
            "version-0-use",
            definition="raw-op-a",
            storage="ram",
            address=True,
            opaque_location=_opaque_location(0x140040000),
        )
    )
    version_result = cfg_ssa.normalize_cfg_ssa(versions)
    version_rows = [row for row in version_result["varnodes"] if row["opaque_location_id"] == "a0"]
    assert len(version_rows) == 2
    assert version_result["opaque_global_location_count"] == 1
    assert version_result["opaque_global_varnode_count"] == 2

    output_first = _raw()
    output_first["ops"][0]["output"] = _output(
        _var(
            "output-location",
            definition="raw-op-a",
            storage="ram",
            address=True,
            opaque_location=_opaque_location(0x140050000),
        )
    )
    output_first["ops"][0]["operands"] = [
        _value(
            _var(
                "operand-location",
                storage="ram",
                address=True,
                opaque_location=_opaque_location(0x140060000),
            )
        )
    ]
    output_first["ops"][1]["operands"][0] = _value(
        _var(
            "output-location-use",
            definition="raw-op-a",
            storage="ram",
            address=True,
            opaque_location=_opaque_location(0x140050000),
        )
    )
    output_result = cfg_ssa.normalize_cfg_ssa(output_first)
    output_var_id = output_result["ops"][0]["output"]["varnode_id"]
    output_row = next(row for row in output_result["varnodes"] if row["id"] == output_var_id)
    assert output_row["opaque_location_id"] == "a0"
    assert output_result["ops"][0]["operands"][0]["varnode_id"] != output_var_id


@pytest.mark.parametrize("width", [1, 4, 8])
def test_indirect_effect_ref_widths_forward_refs_and_no_effect_def_use(width: int) -> None:
    raw = _raw()
    raw["ops"][0]["output"]["value"]["size"] = width
    raw["ops"][1]["opcode"] = "INDIRECT"
    raw["ops"][1]["output"]["value"]["size"] = width
    raw["ops"][1]["operands"] = [
        _value(_var("ssa-a", definition="raw-op-a", size=width)),
        _effect_op(10, "raw-op-a"),
    ]
    result = cfg_ssa.normalize_cfg_ssa(raw)
    assert result["ops"][1]["operands"][1] == {"kind": "effect_op", "op_id": "o1_0"}
    assert result["indirect_effect_count"] == 1
    assert result["indirect_effect_semantics_established"] is False
    assert result["indirect_effect_refs_preserved"] is True
    assert any(
        edge["use_op_id"] == "o2_0" and edge["operand_index"] == 0
        for edge in result["def_use_edges"]
    )
    assert all(
        edge["use_op_id"] != "o2_0" or edge["operand_index"] != 1
        for edge in result["def_use_edges"] + result["live_in_uses"]
    )

    forward = _raw()
    forward["ops"][0]["opcode"] = "INDIRECT"
    forward["ops"][0]["operands"] = [
        _value(_var("live-forward", storage="register")),
        _effect_op(20, "raw-op-b"),
    ]
    assert cfg_ssa.normalize_cfg_ssa(forward)["indirect_effect_count"] == 1


def test_synthetic_indirect_width_distribution_matches_38_case_probe_shape() -> None:
    observed: list[int] = []
    for width in [1] * 4 + [4] * 11 + [8] * 23:
        raw = _raw()
        raw["ops"][0]["output"]["value"]["size"] = width
        raw["ops"][1]["opcode"] = "INDIRECT"
        raw["ops"][1]["output"]["value"]["size"] = width
        raw["ops"][1]["operands"] = [
            _value(_var("ssa-a", definition="raw-op-a", size=width)),
            _effect_op(10, "raw-op-a"),
        ]
        result = cfg_ssa.normalize_cfg_ssa(raw)
        output_id = result["ops"][1]["output"]["varnode_id"]
        output_row = next(row for row in result["varnodes"] if row["id"] == output_id)
        observed.append(output_row["size"])
    assert observed.count(1) == 4
    assert observed.count(4) == 11
    assert observed.count(8) == 23


def test_indirect_effect_selector_relocation_and_reference_identity() -> None:
    first = _raw()
    first["ops"][1]["opcode"] = "INDIRECT"
    first["ops"][1]["operands"] = [
        _value(_var("ssa-a", definition="raw-op-a")),
        _effect_op(10, "raw-op-a"),
    ]
    moved = _raw()
    moved["ops"][0]["source_ref"]["seq_time"] = 11
    moved["ops"][1]["opcode"] = "INDIRECT"
    moved["ops"][1]["operands"] = [
        _value(_var("ssa-a", definition="raw-op-a")),
        _effect_op(11, "raw-op-a"),
    ]
    assert (
        cfg_ssa.normalize_cfg_ssa(first)["image_address_independent_fingerprint"]
        == cfg_ssa.normalize_cfg_ssa(moved)["image_address_independent_fingerprint"]
    )

    def with_third_reference(effect_key: str, selector: int) -> dict[str, object]:
        raw = _raw()
        raw["ops"].append(
            {
                "key": "raw-op-c",
                "parent": "native-2",
                "opcode": "COPY",
                "source_ref": {
                    "function_rva": 0x1000,
                    "instruction_rva": 0x1030,
                    "instruction_ordinal": 3,
                    "seq_time": 30,
                    "pcode_order": 0,
                },
                "output": _output(_var("ssa-c", definition="raw-op-c")),
                "operands": [_value(_var("live-c", storage="register"))],
            }
        )
        raw["ops"][1]["opcode"] = "INDIRECT"
        raw["ops"][1]["operands"] = [
            _value(_var("ssa-a", definition="raw-op-a")),
            _effect_op(selector, effect_key),
        ]
        return raw

    assert (
        cfg_ssa.normalize_cfg_ssa(with_third_reference("raw-op-a", 10))[
            "image_address_independent_fingerprint"
        ]
        != cfg_ssa.normalize_cfg_ssa(with_third_reference("raw-op-c", 30))[
            "image_address_independent_fingerprint"
        ]
    )

    self_ref = _raw()
    self_ref["ops"][1]["opcode"] = "INDIRECT"
    self_ref["ops"][1]["operands"] = [
        _value(_var("ssa-a", definition="raw-op-a")),
        _effect_op(20, "raw-op-b"),
    ]
    with pytest.raises(ValueError, match="self, foreign, or mismatched"):
        cfg_ssa.normalize_cfg_ssa(self_ref)

    missing = _raw()
    missing["ops"][1]["opcode"] = "INDIRECT"
    missing["ops"][1]["operands"] = [
        _value(_var("ssa-a", definition="raw-op-a")),
        _effect_op(10, "foreign-op"),
    ]
    with pytest.raises(ValueError, match="self, foreign, or mismatched"):
        cfg_ssa.normalize_cfg_ssa(missing)

    ambiguous = _raw()
    ambiguous["ops"].append(
        {
            "key": "raw-op-c",
            "parent": "native-2",
            "opcode": "COPY",
            "source_ref": {
                "function_rva": 0x1000,
                "instruction_rva": 0x1030,
                "instruction_ordinal": 3,
                "seq_time": 10,
                "pcode_order": 0,
            },
            "output": _output(_var("ssa-c", definition="raw-op-c")),
            "operands": [_value(_var("live-c", storage="register"))],
        }
    )
    ambiguous["ops"][1]["opcode"] = "INDIRECT"
    ambiguous["ops"][1]["operands"] = [
        _value(_var("ssa-a", definition="raw-op-a")),
        _effect_op(10, "raw-op-a"),
    ]
    with pytest.raises(ValueError, match="self, foreign, or mismatched"):
        cfg_ssa.normalize_cfg_ssa(ambiguous)

    bad_time = _raw()
    bad_time["ops"][1]["opcode"] = "INDIRECT"
    hostile = _effect_op(10, "raw-op-a")
    hostile["raw_effect_seq_time"] = 11
    bad_time["ops"][1]["operands"] = [
        _value(_var("ssa-a", definition="raw-op-a")),
        hostile,
    ]
    with pytest.raises(ValueError, match="self, foreign, or mismatched"):
        cfg_ssa.normalize_cfg_ssa(bad_time)


def test_v5_output_and_opaque_location_shapes_fail_closed() -> None:
    legacy_output = _raw()
    legacy_output["ops"][0]["output"] = legacy_output["ops"][0]["output"]["value"]
    with pytest.raises(ValueError, match="output shape"):
        cfg_ssa.normalize_cfg_ssa(legacy_output)

    missing_location = _raw()
    missing_location["ops"][0]["operands"] = [_value(_var("global", storage="ram", address=True))]
    with pytest.raises(ValueError, match="location shape"):
        cfg_ssa.normalize_cfg_ssa(missing_location)

    nonaddress_location = _raw()
    nonaddress_location["ops"][0]["operands"] = [
        _value(
            _var(
                "not-address",
                storage="ram",
                opaque_location=_opaque_location(0x140001000),
            )
        )
    ]
    with pytest.raises(ValueError, match="non-address"):
        cfg_ssa.normalize_cfg_ssa(nonaddress_location)

    wrong_size = _raw()
    wrong_size["ops"][0]["operands"] = [
        _value(
            _var(
                "wrong-size",
                storage="ram",
                size=4,
                address=True,
                opaque_location=_opaque_location(0x140001000, size=8),
            )
        )
    ]
    with pytest.raises(ValueError, match="location classification"):
        cfg_ssa.normalize_cfg_ssa(wrong_size)


def test_indirect_shape_selector_and_width_fail_closed() -> None:
    missing_output = _raw()
    missing_output["ops"][1]["opcode"] = "INDIRECT"
    missing_output["ops"][1]["output"] = None
    missing_output["ops"][1]["operands"] = [
        _value(_var("ssa-a", definition="raw-op-a")),
        _effect_op(10, "raw-op-a"),
    ]
    with pytest.raises(ValueError, match="requires value, effect op, and output"):
        cfg_ssa.normalize_cfg_ssa(missing_output)

    wrong_width = _raw()
    wrong_width["ops"][1]["opcode"] = "INDIRECT"
    wrong_width["ops"][1]["output"]["value"]["size"] = 4
    wrong_width["ops"][1]["operands"] = [
        _value(_var("ssa-a", definition="raw-op-a")),
        _effect_op(10, "raw-op-a"),
    ]
    with pytest.raises(ValueError, match="widths do not match"):
        cfg_ssa.normalize_cfg_ssa(wrong_width)

    bad_selector = _raw()
    bad_selector["ops"][1]["opcode"] = "INDIRECT"
    effect = _effect_op(10, "raw-op-a")
    effect["selector"] = _var("wide", storage="constant", size=8, constant=10)
    bad_selector["ops"][1]["operands"] = [
        _value(_var("ssa-a", definition="raw-op-a")),
        effect,
    ]
    with pytest.raises(ValueError, match="selector classification"):
        cfg_ssa.normalize_cfg_ssa(bad_selector)

    metadata_elsewhere = _raw()
    metadata_elsewhere["ops"][1]["operands"] = [_effect_op(10, "raw-op-a")]
    with pytest.raises(ValueError, match="metadata operands forbidden"):
        cfg_ssa.normalize_cfg_ssa(metadata_elsewhere)

    swapped = _raw()
    swapped["ops"][1]["opcode"] = "INDIRECT"
    swapped["ops"][1]["operands"] = [
        _effect_op(10, "raw-op-a"),
        _value(_var("ssa-a", definition="raw-op-a")),
    ]
    with pytest.raises(ValueError, match="requires value, effect op, and output"):
        cfg_ssa.normalize_cfg_ssa(swapped)

    extra = _raw()
    extra["ops"][1]["opcode"] = "INDIRECT"
    extra["ops"][1]["operands"] = [
        _value(_var("ssa-a", definition="raw-op-a")),
        _effect_op(10, "raw-op-a"),
        _value(_var("extra", storage="register")),
    ]
    with pytest.raises(ValueError, match="requires value, effect op, and output"):
        cfg_ssa.normalize_cfg_ssa(extra)


@pytest.mark.parametrize(
    "opcode,operands,output,match",
    [
        ("CALL", [], None, "CALL requires"),
        ("CALLIND", [], None, "CALLIND requires"),
        ("CALLOTHER", [_value(_var("bad"))], None, "CALLOTHER requires"),
        ("LOAD", [_memory_space(), _value(_var("address"))], None, "LOAD requires"),
        (
            "STORE",
            [_memory_space(), _value(_var("address")), _value(_var("value"))],
            _output(_var("ssa-b", definition="raw-op-b")),
            "STORE requires",
        ),
        ("COPY", [_memory_space()], None, "metadata operands forbidden"),
    ],
)
def test_call_userop_memory_opcode_matrix_fails_closed(
    opcode: str,
    operands: list[dict[str, object]],
    output: dict[str, object] | None,
    match: str,
) -> None:
    raw = _raw()
    raw["ops"][1]["opcode"] = opcode
    raw["ops"][1]["operands"] = operands
    raw["ops"][1]["output"] = output
    with pytest.raises(ValueError, match=match):
        cfg_ssa.normalize_cfg_ssa(raw)


def test_callind_address_target_and_selector_forgery_fail_closed() -> None:
    callind = _raw()
    callind["ops"][1]["opcode"] = "CALLIND"
    callind["ops"][1]["operands"] = [
        _value(
            _var(
                "address-target",
                storage="ram",
                address=True,
                opaque_location=_opaque_location(0x140002000),
            )
        )
    ]
    with pytest.raises(ValueError, match="opaque address global"):
        cfg_ssa.normalize_cfg_ssa(callind)

    bad_userop = _raw()
    bad_userop["ops"][1]["opcode"] = "CALLOTHER"
    bad_userop["ops"][1]["operands"] = [_userop(0x11)]
    bad_userop["ops"][1]["operands"][0]["userop_id"] = 0x12
    with pytest.raises(ValueError, match="does not match"):
        cfg_ssa.normalize_cfg_ssa(bad_userop)

    bad_memory = _raw()
    bad_memory["ops"][1]["opcode"] = "LOAD"
    bad_memory["ops"][1]["operands"] = [
        _memory_space(),
        _value(_var("address")),
    ]
    bad_memory["ops"][1]["operands"][0]["space"] = "register"
    with pytest.raises(ValueError, match="memory-space selector"):
        cfg_ssa.normalize_cfg_ssa(bad_memory)

    for field, value in (
        ("raw_space", "register"),
        ("raw_address", False),
        ("raw_constant", 1),
        ("raw_definition_op_key", "raw-op-a"),
        ("raw_size", 0),
    ):
        bad_call = _raw()
        bad_call["ops"][1]["opcode"] = "CALL"
        target = _call_target()
        target[field] = value
        bad_call["ops"][1]["operands"] = [target]
        with pytest.raises(ValueError, match="CALL target classification"):
            cfg_ssa.normalize_cfg_ssa(bad_call)


@pytest.mark.parametrize(
    "selector",
    [
        _var("wrong-size", storage="constant", size=8, constant=0x11),
        _var(
            "defined-selector",
            definition="raw-op-a",
            storage="constant",
            size=4,
            constant=0x11,
        ),
        _var("not-constant", storage="register", size=4),
        _var("address-selector", storage="constant", size=4, constant=0x11, address=True),
    ],
)
def test_userop_selector_classification_fails_closed(selector: dict[str, object]) -> None:
    raw = _raw()
    raw["ops"][1]["opcode"] = "CALLOTHER"
    operand = _userop()
    operand["selector"] = selector
    raw["ops"][1]["operands"] = [operand]
    with pytest.raises(ValueError, match="selector classification"):
        cfg_ssa.normalize_cfg_ssa(raw)


@pytest.mark.parametrize(
    "first,second,match",
    [
        (_userop(0x11, "LOCK"), _userop(0x11, "UNLOCK"), "conflicting names"),
        (_userop(0x11, "LOCK"), _userop(0x12, "LOCK"), "conflicting IDs"),
    ],
)
def test_userop_mapping_is_bijective_across_complete_function(
    first: dict[str, object], second: dict[str, object], match: str
) -> None:
    raw = _raw()
    raw["ops"][0]["opcode"] = "CALLOTHER"
    raw["ops"][0]["operands"] = [first]
    raw["ops"][1]["opcode"] = "CALLOTHER"
    raw["ops"][1]["operands"] = [second]
    with pytest.raises(ValueError, match=match):
        cfg_ssa.normalize_cfg_ssa(raw)


@pytest.mark.parametrize(
    "opcode",
    ["BRANCHIND"],
)
def test_unsupported_address_memory_and_phi_operations_fail_closed(opcode: str) -> None:
    raw = _raw()
    raw["ops"][1]["opcode"] = opcode
    with pytest.raises(ValueError, match="does not support"):
        cfg_ssa.normalize_cfg_ssa(raw)


def test_constant_width_and_edge_caps_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    overflow = _raw()
    overflow["ops"][0]["operands"][0] = _value(
        _var("overflow", storage="constant", size=1, constant=0x100)
    )
    with pytest.raises(ValueError, match="declared width"):
        cfg_ssa.normalize_cfg_ssa(overflow)

    monkeypatch.setattr(cfg_ssa, "MAX_EDGES", 0)
    with pytest.raises(ValueError, match="edge extent"):
        cfg_ssa.normalize_cfg_ssa(_raw())


def test_image_bearing_constants_are_deterministically_alpha_renamed() -> None:
    raw = _raw()
    first = 0x140086D80
    second = 0x140086DA0
    raw["ops"][0]["operands"] = [
        _value(_var("first-observation", storage="constant", size=8, constant=first))
    ]
    raw["ops"][1]["operands"] = [
        _value(_var("second", storage="constant", size=8, constant=second)),
        _value(_var("same-first", storage="constant", size=8, constant=first)),
    ]
    result = cfg_ssa.normalize_cfg_ssa(raw)
    image_rows = [row for row in result["varnodes"] if row["image_constant_id"] is not None]
    assert image_rows == [
        {
            "id": "v1",
            "storage_class": "constant",
            "size": 8,
            "constant": None,
            "image_constant_id": "i0",
            "definition_op_id": None,
            "opaque_location_id": None,
        },
        {
            "id": "v3",
            "storage_class": "constant",
            "size": 8,
            "constant": None,
            "image_constant_id": "i1",
            "definition_op_id": None,
            "opaque_location_id": None,
        },
    ]
    assert result["ops"][0]["operands"] == [{"kind": "value", "varnode_id": "v1"}]
    assert result["ops"][1]["operands"] == [
        {"kind": "value", "varnode_id": "v3"},
        {"kind": "value", "varnode_id": "v1"},
    ]
    assert result["image_bearing_constant_location_count"] == 2
    assert result["image_bearing_constant_varnode_count"] == 2
    assert all("0x140086" not in str(row) for row in image_rows)

    moved = _raw()
    moved["image_min"] += 0x10000000
    moved["image_max"] += 0x10000000
    moved["ops"][0]["operands"] = [
        _value(
            _var(
                "moved-first",
                storage="constant",
                size=8,
                constant=first + 0x10000000,
            )
        )
    ]
    moved["ops"][1]["operands"] = [
        _value(
            _var(
                "moved-second",
                storage="constant",
                size=8,
                constant=second + 0x10000000,
            )
        ),
        _value(
            _var(
                "moved-first-again",
                storage="constant",
                size=8,
                constant=first + 0x10000000,
            )
        ),
    ]
    assert (
        cfg_ssa.normalize_cfg_ssa(moved)["image_address_independent_fingerprint"]
        == result["image_address_independent_fingerprint"]
    )


def test_image_bearing_constant_identity_includes_exact_raw_width() -> None:
    raw = _raw()
    value = 0x140086D80
    raw["ops"][0]["operands"] = [
        _value(_var("wide-8", storage="constant", size=8, constant=value)),
        _value(_var("wide-16", storage="constant", size=16, constant=value)),
    ]
    result = cfg_ssa.normalize_cfg_ssa(raw)
    ids = [
        row["image_constant_id"]
        for row in result["varnodes"]
        if row["image_constant_id"] is not None
    ]
    assert ids == ["i0", "i1"]
    assert result["image_bearing_constant_location_count"] == 2


def test_branch_arity_position_and_nonbranch_target_fail_closed() -> None:
    wrong_position = _raw()
    wrong_position["ops"][0]["opcode"] = "CBRANCH"
    wrong_position["ops"][0]["operands"] = [
        _value(_var("condition", storage="register")),
        _target("native-2"),
    ]
    with pytest.raises(ValueError, match="target input 0"):
        cfg_ssa.normalize_cfg_ssa(wrong_position)

    nonbranch = _raw()
    nonbranch["ops"][0]["operands"] = [_target("native-2")]
    with pytest.raises(ValueError, match="non-branch"):
        cfg_ssa.normalize_cfg_ssa(nonbranch)

    extra_successor = _raw()
    extra_successor["ops"][0]["opcode"] = "BRANCH"
    extra_successor["ops"][0]["operands"] = [_target("native-2")]
    extra_successor["blocks"].append(
        {"key": "other", "predecessors": ["native-7"], "successors": []}
    )
    extra_successor["blocks"][0]["successors"].append("other")
    extra_successor["ops"].append(
        {
            "key": "other-op",
            "parent": "other",
            "opcode": "COPY",
            "source_ref": {
                "function_rva": 0x1000,
                "instruction_rva": 0x1030,
                "instruction_ordinal": 3,
                "seq_time": 30,
                "pcode_order": 0,
            },
            "output": _output(_var("other-value", definition="other-op")),
            "operands": [_value(_var("other-live", storage="register"))],
        }
    )
    with pytest.raises(ValueError, match="exactly close"):
        cfg_ssa.normalize_cfg_ssa(extra_successor)

    one_successor = _raw()
    one_successor["ops"][0]["opcode"] = "CBRANCH"
    one_successor["ops"][0]["operands"] = [
        _target("native-2"),
        _value(_var("condition", storage="register")),
    ]
    with pytest.raises(ValueError, match="exactly two distinct"):
        cfg_ssa.normalize_cfg_ssa(one_successor)

    three_successors = _raw()
    _add_fallthrough(three_successors, "fallthrough-a")
    _add_fallthrough(three_successors, "fallthrough-b")
    three_successors["ops"][0]["opcode"] = "CBRANCH"
    three_successors["ops"][0]["operands"] = [
        _target("native-2"),
        _value(_var("condition", storage="register")),
    ]
    with pytest.raises(ValueError, match="exactly two distinct"):
        cfg_ssa.normalize_cfg_ssa(three_successors)


def test_target_and_constant_classification_fail_closed() -> None:
    not_address = _raw()
    not_address["ops"][0]["opcode"] = "BRANCH"
    not_address["ops"][0]["operands"] = [
        {
            "kind": "block_target",
            "raw_block_key": "native-2",
            "target": _var("bad", storage="ram", address=True),
            "extra": True,
        }
    ]
    with pytest.raises(ValueError, match="operand shape"):
        cfg_ssa.normalize_cfg_ssa(not_address)

    target_constant = _raw()
    target_constant["ops"][0]["opcode"] = "BRANCH"
    target_constant["ops"][0]["operands"] = [_target(1)]
    with pytest.raises(ValueError, match="target block"):
        cfg_ssa.normalize_cfg_ssa(target_constant)

    defined_constant = _raw()
    defined_constant["ops"][0]["operands"][0] = _value(
        _var("defined", definition="raw-op-a", storage="constant", constant=4)
    )
    with pytest.raises(ValueError, match="constant must not have a definition"):
        cfg_ssa.normalize_cfg_ssa(defined_constant)

    unknown_space = _raw()
    unknown_space["ops"][0]["operands"][0] = _value(_var("unknown", storage="other"))
    with pytest.raises(ValueError, match="constant/storage class"):
        cfg_ssa.normalize_cfg_ssa(unknown_space)


@pytest.mark.parametrize(
    "target",
    [
        _var("non-ram", storage="register", address=True),
        _var("defined", definition="raw-op-a", storage="ram", address=True),
        _var("zero", storage="ram", size=0, address=True),
        _var("oversized", storage="ram", size=cfg_ssa.MAX_VARNODE_BYTES + 1, address=True),
        _var("not-address", storage="ram"),
        _var("constant", storage="constant", constant=1, address=True),
    ],
)
def test_raw_direct_branch_target_varnode_forgery_fails_closed(
    target: dict[str, object],
) -> None:
    raw = _raw()
    raw["ops"][0]["opcode"] = "BRANCH"
    raw["ops"][0]["operands"] = [_target("native-2", target)]
    with pytest.raises(ValueError, match="target varnode"):
        cfg_ssa.normalize_cfg_ssa(raw)


class _Address:
    def __init__(
        self,
        offset: int,
        space: str = "unique",
        *,
        pointer_size: int = 8,
        overlay: str | None = None,
    ) -> None:
        self.offset = offset
        self.space = space
        self.pointer_size = pointer_size
        self.overlay = overlay

    def getOffset(self) -> int:
        return self.offset

    def getAddressSpace(self) -> object:
        value = type(
            "Space",
            (),
            {
                "getName": lambda self: self.name,
                "getSize": lambda self: self.size,
                "getPointerSize": lambda self: self.pointer_size,
            },
        )()
        value.name = self.space
        value.size = self.pointer_size * 8
        value.pointer_size = self.pointer_size
        return value

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, _Address)
            and self.offset == other.offset
            and self.space == other.space
            and self.overlay == other.overlay
        )


class _Program:
    pass


_PROGRAM = _Program()


class _Memory:
    def __init__(self, internal_offsets: set[int] | None = None) -> None:
        self.internal_offsets = internal_offsets or set()

    def getBlock(self, address: _Address) -> object | None:
        return object() if address.offset in self.internal_offsets else None


class _FunctionManager:
    def __init__(self, functions: dict[int, object] | None = None) -> None:
        self.functions = functions or {}

    def getFunctionAt(self, address: _Address) -> object | None:
        return self.functions.get(address.offset)


class _Language:
    def __init__(self, userops: dict[int, str] | None = None) -> None:
        self.userops = userops or {}

    def getUserDefinedOpName(self, selector: int) -> str | None:
        return self.userops.get(selector)


class _RamSpace:
    def __init__(
        self,
        *,
        name: str = "ram",
        loaded: bool = True,
        overlay: bool = False,
        physical: object | None = None,
        space_id: int = 0x1B1,
    ) -> None:
        self.name = name
        self.loaded = loaded
        self.overlay = overlay
        self.physical = physical
        self.space_id = space_id

    def getName(self) -> str:
        return self.name

    def getSize(self) -> int:
        return 64

    def isLoadedMemorySpace(self) -> bool:
        return self.loaded

    def isOverlaySpace(self) -> bool:
        return self.overlay

    def getPhysicalSpace(self) -> object:
        return self if self.physical is None else self.physical

    def getSpaceID(self) -> int:
        return self.space_id


class _AddressFactory:
    def __init__(self, spaces: dict[int, _RamSpace], default: _RamSpace) -> None:
        self.spaces = spaces
        self.default = default

    def getAddressSpace(self, selector: int) -> _RamSpace | None:
        return self.spaces.get(selector)

    def getDefaultAddressSpace(self) -> _RamSpace:
        return self.default


class _RichProgram:
    def __init__(
        self,
        *,
        functions: dict[int, object] | None = None,
        internal_offsets: set[int] | None = None,
        userops: dict[int, str] | None = None,
        factory: _AddressFactory | None = None,
    ) -> None:
        self.manager = _FunctionManager(functions)
        self.memory = _Memory(internal_offsets)
        self.language = _Language(userops)
        self.factory = factory

    def getFunctionManager(self) -> _FunctionManager:
        return self.manager

    def getMemory(self) -> _Memory:
        return self.memory

    def getLanguage(self) -> _Language:
        return self.language

    def getAddressFactory(self) -> _AddressFactory | None:
        return self.factory


class _Sequence:
    def __init__(self, target: int, order: int) -> None:
        self.target = _Address(target)
        self.order = order

    def getTarget(self) -> _Address:
        return self.target

    def getOrder(self) -> int:
        return self.order

    def getTime(self) -> int:
        return self.order + 100

    def __str__(self) -> str:
        return f"seq-{self.target.offset:x}-{self.order}"


class _Varnode:
    def __init__(
        self, offset: int, *, definition: object | None = None, space: str = "unique"
    ) -> None:
        self.address = _Address(offset, space)
        self.definition = definition

    def getAddress(self) -> _Address:
        return self.address

    def getOffset(self) -> int:
        return self.address.offset

    def getSize(self) -> int:
        return 8

    def getDef(self) -> object | None:
        return self.definition

    def isConstant(self) -> bool:
        return False

    def isAddress(self) -> bool:
        return False


class _Block:
    def __init__(self, index: int, incoming: list[object], outgoing: list[object]) -> None:
        self.index, self.incoming, self.outgoing = index, incoming, outgoing

    def getIndex(self) -> int:
        return self.index

    def getInSize(self) -> int:
        return len(self.incoming)

    def getOutSize(self) -> int:
        return len(self.outgoing)

    def getIn(self, index: int) -> object:
        return self.incoming[index]

    def getOut(self, index: int) -> object:
        return self.outgoing[index]

    def getStart(self) -> _Address:
        return _Address(0x140001000 + self.index * 0x10)


class _Iterator:
    def __init__(self, values: list[object]) -> None:
        self.values = values

    def hasNext(self) -> bool:
        return bool(self.values)

    def next(self) -> object:
        return self.values.pop(0)


def _open_fixture(*, input_space: str = "unique") -> tuple[object, object]:
    entry = _Block(7, [], [])
    sequence = _Sequence(0x140001010, 3)
    output = _Varnode(0x100)
    op = type(
        "Op",
        (),
        {
            "getParent": lambda self: entry,
            "getSeqnum": lambda self: sequence,
            "getMnemonic": lambda self: "COPY",
            "getOutput": lambda self: output,
            "getNumInputs": lambda self: 1,
            "getInput": lambda self, index: _Varnode(0x200, space=input_space),
        },
    )()
    output.definition = op
    high = type(
        "High",
        (),
        {"getBasicBlocks": lambda self: [entry], "getPcodeOps": lambda self: _Iterator([op])},
    )()
    function = type(
        "Function",
        (),
        {
            "getEntryPoint": lambda self: _Address(0x140001000),
            "getProgram": lambda self: _PROGRAM,
        },
    )()
    return function, high


def test_open_function_acquisition_preserves_exact_refs_and_normalizes() -> None:
    function, high = _open_fixture()
    result = cfg_ssa.acquire_open_function_cfg_ssa(
        function,
        high,
        image_base=0x140000000,
        image_max=0x140100000,
        instruction_ordinals={0x1000: 0, 0x1010: 1},
    )
    assert result["ops"][0]["source_ref"] == {
        "function_rva": 0x1000,
        "instruction_rva": 0x1010,
        "instruction_ordinal": 1,
        "seq_time": 103,
        "pcode_order": 3,
    }


def test_varnode_snapshot_uses_each_api_once_and_branch_reuses_offset() -> None:
    sequence = _Sequence(0x140001010, 3)
    counts: dict[str, int] = {}
    definition = type(
        "Definition",
        (),
        {"getSeqnum": lambda self: _once(counts, "definition_sequence", sequence)},
    )()
    node = _Varnode(0x222, definition=definition)
    space = type(
        "Space",
        (),
        {
            "getName": lambda self: _once(counts, "space_name", "unique"),
            "getSize": lambda self: _once(counts, "space_size", 64),
        },
    )()
    address = node.address
    address.getAddressSpace = lambda: _once(counts, "address_space", space)  # type: ignore[method-assign]
    node.getAddress = lambda: _once(counts, "address", address)  # type: ignore[method-assign]
    node.getOffset = lambda: _once(counts, "offset", 0x222)  # type: ignore[method-assign]
    node.getSize = lambda: _once(counts, "size", 8)  # type: ignore[method-assign]
    node.getDef = lambda: _once(counts, "definition", definition)  # type: ignore[method-assign]
    node.isConstant = lambda: _once(counts, "constant", False)  # type: ignore[method-assign]
    node.isAddress = lambda: _once(counts, "is_address", False)  # type: ignore[method-assign]
    observed = cfg_ssa._acquire_varnode(node, _PROGRAM)
    assert observed is not None and observed["definition_op_key"] == str(sequence)
    assert set(counts.values()) == {1}

    throwing = _Varnode(1)
    throwing.getAddress = lambda: (_ for _ in ()).throw(RuntimeError("boom"))  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="varnode address API failed"):
        cfg_ssa._acquire_varnode(throwing, _PROGRAM)

    output_throwing = _Varnode(2, definition=definition)
    output_throwing.getSize = lambda: (_ for _ in ()).throw(RuntimeError("boom"))  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="varnode size API failed"):
        cfg_ssa._acquire_varnode(output_throwing, _PROGRAM)

    branch = _Varnode(0x140001000, space="ram")
    branch.isAddress = lambda: True  # type: ignore[method-assign]
    offset_calls = 0

    def branch_offset_once() -> int:
        nonlocal offset_calls
        offset_calls += 1
        if offset_calls > 1:
            raise RuntimeError("offset called twice")
        return 0x140001000

    branch.getOffset = branch_offset_once  # type: ignore[method-assign]
    key, _raw = cfg_ssa._acquire_branch_target(
        branch,
        {0x140001000: ["target"]},
        allowed_targets={"target"},
    )
    assert key == "target"
    assert offset_calls == 1

    branch_throwing = _Varnode(0x140001000, space="ram")
    branch_throwing.isAddress = lambda: True  # type: ignore[method-assign]
    branch_throwing.getOffset = lambda: (_ for _ in ()).throw(RuntimeError("boom"))  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="varnode offset API failed"):
        cfg_ssa._acquire_branch_target(
            branch_throwing,
            {0x140001000: ["target"]},
            allowed_targets={"target"},
        )


@pytest.mark.parametrize(
    ("offset", "size", "expected"),
    [
        (-296, 8, (1 << 64) - 296),
        (-1, 1, 0xFF),
        (-128, 1, 0x80),
        (4, 8, 4),
    ],
)
def test_constant_acquisition_normalizes_declared_width_bit_pattern(
    offset: int, size: int, expected: int
) -> None:
    node = _Varnode(offset, space="const")
    node.isConstant = lambda: True  # type: ignore[method-assign]
    node.getSize = lambda: size  # type: ignore[method-assign]
    acquired = cfg_ssa._acquire_varnode(node, _PROGRAM)
    assert acquired is not None
    assert acquired["key"] == f"const:{expected:x}:{size}:live"
    assert acquired["constant"] == expected


def test_constant_width_normalization_feeds_image_constant_alpha_identity() -> None:
    image_constant = 0x140086D80
    impossible = _Varnode(image_constant - (1 << 64), space="const")
    impossible.isConstant = lambda: True  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="offset is outside its declared-width range"):
        cfg_ssa._acquire_varnode(impossible, _PROGRAM)

    node = _Varnode(image_constant, space="const")
    node.isConstant = lambda: True  # type: ignore[method-assign]
    acquired = cfg_ssa._acquire_varnode(node, _PROGRAM)
    assert acquired is not None and acquired["constant"] == image_constant
    assert acquired["key"] == "const:140086d80:8:live"
    raw = _raw()
    raw["ops"][0]["operands"] = [_value(acquired)]
    result = cfg_ssa.normalize_cfg_ssa(raw)
    row = next(item for item in result["varnodes"] if item["image_constant_id"] == "i0")
    assert row["constant"] is None
    assert row["size"] == 8


@pytest.mark.parametrize(
    ("offset", "expected"),
    [
        (-176, (1 << 64) - 176),
        (0x222, 0x222),
    ],
)
def test_nonconstant_address_space_offset_normalizes_declared_width(
    offset: int, expected: int
) -> None:
    node = _Varnode(offset, space="stack")
    acquired = cfg_ssa._acquire_varnode(node, _PROGRAM)
    assert acquired is not None
    assert acquired["key"] == f"stack:{expected:x}:8:live"
    assert acquired["constant"] is None


def test_varnode_offset_and_address_space_width_fail_closed() -> None:
    for offset in (-(1 << 63) - 1, 1 << 64):
        with pytest.raises(ValueError, match="offset is outside its declared-width range"):
            cfg_ssa._acquire_varnode(_Varnode(offset, space="stack"), _PROGRAM)

    constant = _Varnode(-129, space="const")
    constant.isConstant = lambda: True  # type: ignore[method-assign]
    constant.getSize = lambda: 1  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="offset is outside its declared-width range"):
        cfg_ssa._acquire_varnode(constant, _PROGRAM)

    for width in (0, cfg_ssa.MAX_ADDRESS_SPACE_BITS + 1):
        node = _Varnode(1)
        space = node.address.getAddressSpace()
        space.getSize = lambda width=width: width  # type: ignore[attr-defined]
        node.address.getAddressSpace = lambda space=space: space  # type: ignore[method-assign]
        with pytest.raises(ValueError, match="address-space size is outside"):
            cfg_ssa._acquire_varnode(node, _PROGRAM)


def test_varnode_address_space_size_api_is_exact_once_and_contextual() -> None:
    node = _Varnode(-176, space="stack")
    space = node.address.getAddressSpace()
    calls = 0

    def size_once() -> int:
        nonlocal calls
        calls += 1
        if calls > 1:
            raise RuntimeError("getSize called twice")
        return 64

    space.getSize = size_once  # type: ignore[attr-defined]
    node.address.getAddressSpace = lambda: space  # type: ignore[method-assign]
    acquired = cfg_ssa._acquire_varnode(node, _PROGRAM)
    assert acquired is not None and acquired["key"] == f"stack:{(1 << 64) - 176:x}:8:live"
    assert calls == 1

    throwing = _Varnode(1)
    throwing_space = throwing.address.getAddressSpace()
    throwing_space.getSize = lambda: (_ for _ in ()).throw(RuntimeError("boom"))  # type: ignore[attr-defined]
    throwing.address.getAddressSpace = lambda: throwing_space  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="varnode address-space size API failed") as raised:
        cfg_ssa._acquire_varnode(throwing, _PROGRAM)
    assert isinstance(raised.value.__cause__, RuntimeError)


def test_pcode_relative_branch_acquisition_preserves_exact_signed_target() -> None:
    positive = _Varnode(4, space="const")
    positive.isConstant = lambda: True  # type: ignore[method-assign]
    positive.getSize = lambda: 1  # type: ignore[method-assign]
    assert cfg_ssa._acquire_branch_operand(
        positive,
        {},
        allowed_targets=set(),
        instruction_rva=0x1010,
        pcode_order=3,
        image_base=0x140000000,
        image_max=0x140100000,
        instruction_ordinals={0x1010: 0},
    ) == {
        "kind": "pcode_relative_target",
        "target": {
            "key": "const:4:1:live",
            "definition_op_key": None,
            "storage_class": "constant",
            "size": 1,
            "constant": 4,
            "address": False,
            "opaque_location": None,
        },
        "raw_signed_delta": 4,
        "raw_instruction_rva": 0x1010,
        "raw_pcode_order": 3,
    }

    negative = _Varnode(-1, space="const")
    negative.isConstant = lambda: True  # type: ignore[method-assign]
    negative.getSize = lambda: 1  # type: ignore[method-assign]
    acquired = cfg_ssa._acquire_branch_operand(
        negative,
        {},
        allowed_targets=set(),
        instruction_rva=0x1010,
        pcode_order=3,
        image_base=0x140000000,
        image_max=0x140100000,
        instruction_ordinals={0x1010: 0},
    )
    assert acquired["raw_signed_delta"] == -1
    assert acquired["raw_pcode_order"] == 3
    assert acquired["target"]["constant"] == 0xFF
    assert acquired["target"]["key"] == "const:ff:1:live"


def test_absolute_branch_acquisition_falls_back_to_exact_native_instruction() -> None:
    target = _Varnode(0x140001020, space="ram")
    target.isAddress = lambda: True  # type: ignore[method-assign]
    acquired = cfg_ssa._acquire_branch_operand(
        target,
        {0x140001000: ["successor"]},
        allowed_targets={"successor"},
        instruction_rva=0x1010,
        pcode_order=0,
        image_base=0x140000000,
        image_max=0x140100000,
        instruction_ordinals={0x1000: 0, 0x1020: 1},
    )
    assert acquired == {
        "kind": "native_instruction_target",
        "target": {
            "key": "ram:140001020:8:live",
            "definition_op_key": None,
            "storage_class": "ram",
            "size": 8,
            "constant": None,
            "address": True,
            "opaque_location": None,
        },
        "raw_target_offset": 0x140001020,
        "raw_target_rva": 0x1020,
        "native_instruction_ordinal": 1,
    }

    with pytest.raises(ValueError, match="structurally ambiguous"):
        cfg_ssa._acquire_branch_operand(
            target,
            {0x140001020: ["left", "right"]},
            allowed_targets={"left", "right"},
            instruction_rva=0x1010,
            pcode_order=0,
            image_base=0x140000000,
            image_max=0x140100000,
            instruction_ordinals={0x1000: 0, 0x1020: 1},
        )

    missing = _Varnode(0x140001030, space="ram")
    missing.isAddress = lambda: True  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="neither an allowed CFG successor nor a retained"):
        cfg_ssa._acquire_branch_operand(
            missing,
            {},
            allowed_targets=set(),
            instruction_rva=0x1010,
            pcode_order=0,
            image_base=0x140000000,
            image_max=0x140100000,
            instruction_ordinals={0x1000: 0, 0x1020: 1},
        )

    outside = _Varnode(0x150000000, space="ram")
    outside.isAddress = lambda: True  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="outside the exact image"):
        cfg_ssa._acquire_branch_operand(
            outside,
            {},
            allowed_targets=set(),
            instruction_rva=0x1010,
            pcode_order=0,
            image_base=0x140000000,
            image_max=0x140100000,
            instruction_ordinals={0x1000: 0, 0x1020: 1},
        )


def test_open_function_acquisition_requires_exact_nonnull_program() -> None:
    function, high = _open_fixture()
    function.getProgram = lambda: None  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="exact program"):
        cfg_ssa.acquire_open_function_cfg_ssa(
            function,
            high,
            image_base=0x140000000,
            image_max=0x140100000,
            instruction_ordinals={0x1000: 0, 0x1010: 1},
        )


@pytest.mark.parametrize(
    "instruction_ordinals",
    [
        {0x1010: 1},
        {0x1000: 0, 0x1010: 0},
        {0x1000: False, 0x1010: 1},
        {0x100000: 0},
    ],
)
def test_open_function_requires_exact_contiguous_native_instruction_map(
    instruction_ordinals: dict[int, int],
) -> None:
    function, high = _open_fixture()
    with pytest.raises(ValueError, match="native instruction ordinal map"):
        cfg_ssa.acquire_open_function_cfg_ssa(
            function,
            high,
            image_base=0x140000000,
            image_max=0x140100000,
            instruction_ordinals=instruction_ordinals,
        )
    function, high = _open_fixture()
    function.getProgram = lambda: (_ for _ in ()).throw(RuntimeError("boom"))  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="function program API failed"):
        cfg_ssa.acquire_open_function_cfg_ssa(
            function,
            high,
            image_base=0x140000000,
            image_max=0x140100000,
            instruction_ordinals={0x1000: 0, 0x1010: 1},
        )


def test_call_target_acquisition_classifies_self_import_thunk_and_opaque() -> None:
    class _Location:
        def __init__(
            self,
            library: str | None,
            original: str | None,
            label: str | None = None,
            source: str = "DEFAULT",
        ) -> None:
            self.library = library
            self.original = original
            self.label = label
            self.source = source

        def getLibraryName(self) -> str | None:
            return self.library

        def getOriginalImportedName(self) -> str | None:
            return self.original

        def getLabel(self) -> str | None:
            return self.label

        def getSource(self) -> str:
            return self.source

    class _Resolved:
        def __init__(
            self,
            *,
            external: bool = False,
            location: _Location | None = None,
            thunk: object | None = None,
        ) -> None:
            self.external = external
            self.location = location
            self.thunk = thunk

        def isThunk(self) -> bool:
            return self.thunk is not None

        def getThunkedFunction(self, recursive: bool) -> object | None:
            assert recursive is True
            return self.thunk

        def isExternal(self) -> bool:
            return self.external

        def getExternalLocation(self) -> _Location | None:
            return self.location

    imported = _Resolved(
        external=True,
        location=_Location("NTOSKRNL.EXE", "ExAllocatePool2"),
    )
    label_import = _Resolved(
        external=True,
        location=_Location("HAL.DLL", None, "HalQuerySystemInformation", "IMPORTED"),
    )
    program = _RichProgram(
        functions={0x180001000: imported, 0x180002000: _Resolved(thunk=label_import)},
        internal_offsets={0x140003000, 0x180004000},
    )
    caller = type(
        "Caller",
        (),
        {
            "getEntryPoint": lambda self: _Address(0x140001000, "ram"),
            "getProgram": lambda self: program,
        },
    )()

    def target(offset: int) -> _Varnode:
        node = _Varnode(offset, space="ram")
        node.isAddress = lambda: True  # type: ignore[method-assign]
        return node

    assert (
        cfg_ssa._acquire_call_target(target(0x140001000), caller, program)["target_class"] == "self"
    )
    overlay_caller = type(
        "OverlayCaller",
        (),
        {"getEntryPoint": lambda self: _Address(0x140001000, "ram", overlay="overlay")},
    )()
    assert (
        cfg_ssa._acquire_call_target(target(0x140001000), overlay_caller, program)["target_class"]
        != "self"
    )
    assert (
        cfg_ssa._acquire_call_target(target(0x140003000), caller, program)["target_class"]
        == "internal_image_opaque"
    )
    assert (
        cfg_ssa._acquire_call_target(target(0x180009000), caller, program)["target_class"]
        == "external_opaque"
    )
    stateful = target(0x180009001)
    address_calls = 0

    def one_address_classification() -> bool:
        nonlocal address_calls
        address_calls += 1
        if address_calls > 1:
            raise RuntimeError("isAddress called twice")
        return True

    stateful.isAddress = one_address_classification  # type: ignore[method-assign]
    stateful_row = cfg_ssa._acquire_call_target(stateful, caller, program)
    assert stateful_row["raw_address"] is True
    assert address_calls == 1

    class JavaInteger:
        def __init__(self, value: int) -> None:
            self.value = value

        def __int__(self) -> int:
            return self.value

    wrapped = target(0x180009002)
    size_calls = 0
    pointer_calls = 0

    def one_wrapped_size() -> JavaInteger:
        nonlocal size_calls
        size_calls += 1
        if size_calls > 1:
            raise RuntimeError("getSize called twice")
        return JavaInteger(8)

    def one_wrapped_pointer_size() -> JavaInteger:
        nonlocal pointer_calls
        pointer_calls += 1
        if pointer_calls > 1:
            raise RuntimeError("getPointerSize called twice")
        return JavaInteger(8)

    wrapped_space = type(
        "WrappedSpace",
        (),
        {
            "getName": lambda self: "ram",
            "getPointerSize": lambda self: one_wrapped_pointer_size(),
        },
    )()
    wrapped.getSize = one_wrapped_size  # type: ignore[method-assign]
    wrapped.address.getAddressSpace = lambda: wrapped_space  # type: ignore[method-assign]
    wrapped_row = cfg_ssa._acquire_call_target(wrapped, caller, program)
    assert wrapped_row["raw_size"] == 8
    assert wrapped_row["raw_pointer_size"] == 8
    assert size_calls == pointer_calls == 1

    class ThrowingJavaInteger:
        def __int__(self) -> int:
            raise RuntimeError("conversion failed")

    throwing_size = target(0x180009003)
    throwing_size.getSize = lambda: ThrowingJavaInteger()  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="CALL target size API failed") as raised_size:
        cfg_ssa._acquire_call_target(throwing_size, caller, program)
    assert isinstance(raised_size.value.__cause__, RuntimeError)

    throwing_pointer_conversion = target(0x180009004)
    conversion_space = type(
        "ConversionSpace",
        (),
        {
            "getName": lambda self: "ram",
            "getPointerSize": lambda self: ThrowingJavaInteger(),
        },
    )()
    throwing_pointer_conversion.address.getAddressSpace = lambda: conversion_space  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="CALL target pointer size API failed") as raised_pointer:
        cfg_ssa._acquire_call_target(throwing_pointer_conversion, caller, program)
    assert isinstance(raised_pointer.value.__cause__, RuntimeError)

    imported_row = cfg_ssa._acquire_call_target(target(0x180001000), caller, program)
    assert imported_row["library"] == "ntoskrnl.exe"
    assert imported_row["symbol"] == "ExAllocatePool2"
    thunk_row = cfg_ssa._acquire_call_target(target(0x180002000), caller, program)
    assert thunk_row["library"] == "hal.dll"
    assert thunk_row["symbol"] == "HalQuerySystemInformation"

    incomplete = _Resolved(
        external=True,
        location=_Location("HAL.DLL", None, "generated_name", "DEFAULT"),
    )
    program.manager.functions[0x180004000] = incomplete
    assert (
        cfg_ssa._acquire_call_target(target(0x180004000), caller, program)["target_class"]
        == "internal_image_opaque"
    )

    wrong_width = target(0x180009000)
    wrong_width.getSize = lambda: 4  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="CALL target classification"):
        cfg_ssa._acquire_call_target(wrong_width, caller, program)
    for pointer_size in (0, cfg_ssa.MAX_VARNODE_BYTES + 1, False):
        invalid_pointer = target(0x180009000)
        invalid_pointer.address.pointer_size = pointer_size
        with pytest.raises(ValueError, match=r"CALL target width|classification"):
            cfg_ssa._acquire_call_target(invalid_pointer, caller, program)

    throwing_pointer = target(0x180009000)
    space = type(
        "ThrowingSpace",
        (),
        {
            "getName": lambda self: "ram",
            "getPointerSize": lambda self: (_ for _ in ()).throw(RuntimeError("boom")),
        },
    )()
    throwing_pointer.address.getAddressSpace = lambda: space  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="pointer size API failed"):
        cfg_ssa._acquire_call_target(throwing_pointer, caller, program)

    missing_manager = _RichProgram()
    missing_manager.getFunctionManager = lambda: None  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="function manager is absent"):
        cfg_ssa._acquire_call_target(target(0x180009000), caller, missing_manager)
    throwing_manager = _RichProgram()
    throwing_manager.getFunctionManager = lambda: (_ for _ in ()).throw(  # type: ignore[method-assign]
        RuntimeError("boom")
    )
    with pytest.raises(ValueError, match="function manager API failed"):
        cfg_ssa._acquire_call_target(target(0x180009000), caller, throwing_manager)
    value_error_manager = _RichProgram()
    value_error_manager.getFunctionManager = lambda: (_ for _ in ()).throw(  # type: ignore[method-assign]
        ValueError("upstream value error")
    )
    with pytest.raises(ValueError, match="AFD Program function manager API failed") as raised:
        cfg_ssa._acquire_call_target(target(0x180009000), caller, value_error_manager)
    assert isinstance(raised.value.__cause__, ValueError)
    assert str(raised.value.__cause__) == "upstream value error"
    throwing_lookup = _RichProgram()
    throwing_lookup.manager.getFunctionAt = lambda address: (_ for _ in ()).throw(  # type: ignore[method-assign]
        RuntimeError("boom")
    )
    with pytest.raises(ValueError, match="getFunctionAt API failed"):
        cfg_ssa._acquire_call_target(target(0x180009000), caller, throwing_lookup)
    missing_memory = _RichProgram()
    missing_memory.getMemory = lambda: None  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="Program memory is absent"):
        cfg_ssa._acquire_call_target(target(0x180009000), caller, missing_memory)
    throwing_block = _RichProgram()
    throwing_block.memory.getBlock = lambda address: (_ for _ in ()).throw(  # type: ignore[method-assign]
        RuntimeError("boom")
    )
    with pytest.raises(ValueError, match="memory getBlock API failed"):
        cfg_ssa._acquire_call_target(target(0x180009000), caller, throwing_block)


def test_userop_and_memory_space_acquisition_use_exact_program_apis() -> None:
    ram = _RamSpace()
    factory = _AddressFactory({0x1B1: ram}, ram)
    program = _RichProgram(userops={0x11: "LOCK"}, factory=factory)

    def selector(value: int) -> _Varnode:
        node = _Varnode(value, space="const")
        node.isConstant = lambda: True  # type: ignore[method-assign]
        node.getSize = lambda: 4  # type: ignore[method-assign]
        return node

    assert cfg_ssa._acquire_userop(selector(0x11), program)["userop_name"] == "LOCK"
    memory_row = cfg_ssa._acquire_memory_space(selector(0x1B1), program)
    assert memory_row["space"] == "ram"
    assert memory_row["raw_space_id"] == 0x1B1

    with pytest.raises(ValueError, match="userop name"):
        cfg_ssa._acquire_userop(selector(0x12), program)
    missing_language = _RichProgram()
    missing_language.getLanguage = lambda: None  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="Program language is absent"):
        cfg_ssa._acquire_userop(selector(0x11), missing_language)
    throwing_language = _RichProgram()
    throwing_language.getLanguage = lambda: (_ for _ in ()).throw(  # type: ignore[method-assign]
        RuntimeError("boom")
    )
    with pytest.raises(ValueError, match="Program language API failed"):
        cfg_ssa._acquire_userop(selector(0x11), throwing_language)
    throwing_userop = _RichProgram()
    throwing_userop.language.getUserDefinedOpName = lambda selector: (  # type: ignore[method-assign]
        _ for _ in ()
    ).throw(RuntimeError("boom"))
    with pytest.raises(ValueError, match="userop lookup API failed"):
        cfg_ssa._acquire_userop(selector(0x11), throwing_userop)
    with pytest.raises(ValueError, match="address factory is absent"):
        cfg_ssa._acquire_memory_space(selector(0x1B1), _RichProgram(factory=None))
    throwing_factory_program = _RichProgram(factory=factory)
    throwing_factory_program.getAddressFactory = lambda: (_ for _ in ()).throw(  # type: ignore[method-assign]
        RuntimeError("boom")
    )
    with pytest.raises(ValueError, match="address factory API failed"):
        cfg_ssa._acquire_memory_space(selector(0x1B1), throwing_factory_program)
    with pytest.raises(ValueError, match="no exact address space"):
        cfg_ssa._acquire_memory_space(
            selector(0x1B1), _RichProgram(factory=_AddressFactory({}, ram))
        )
    throwing_lookup = _AddressFactory({0x1B1: ram}, ram)
    throwing_lookup.getAddressSpace = lambda selector: (_ for _ in ()).throw(  # type: ignore[method-assign]
        RuntimeError("boom")
    )
    with pytest.raises(ValueError, match="getAddressSpace API failed"):
        cfg_ssa._acquire_memory_space(selector(0x1B1), _RichProgram(factory=throwing_lookup))
    mismatched = _RamSpace(space_id=0x999)
    with pytest.raises(ValueError, match="physical default RAM"):
        cfg_ssa._acquire_memory_space(
            selector(0x1B1),
            _RichProgram(factory=_AddressFactory({0x1B1: mismatched}, mismatched)),
        )
    throwing_id = _RamSpace()
    throwing_id.getSpaceID = lambda: (_ for _ in ()).throw(RuntimeError("boom"))  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="getSpaceID API failed"):
        cfg_ssa._acquire_memory_space(
            selector(0x1B1),
            _RichProgram(factory=_AddressFactory({0x1B1: throwing_id}, throwing_id)),
        )
    for bad_space in (
        _RamSpace(name="register"),
        _RamSpace(loaded=False),
        _RamSpace(overlay=True),
        _RamSpace(physical=object()),
    ):
        bad_factory = _AddressFactory({0x1B1: bad_space}, bad_space)
        with pytest.raises(ValueError, match="physical default RAM"):
            cfg_ssa._acquire_memory_space(selector(0x1B1), _RichProgram(factory=bad_factory))
    other_default = _RamSpace()
    with pytest.raises(ValueError, match="physical default RAM"):
        cfg_ssa._acquire_memory_space(
            selector(0x1B1),
            _RichProgram(factory=_AddressFactory({0x1B1: ram}, other_default)),
        )


def test_opaque_global_and_effect_op_acquisition_preserve_exact_facts() -> None:
    ram = _RamSpace()
    factory = _AddressFactory({0x1B1: ram}, ram)
    program = _RichProgram(factory=factory)
    global_node = _Varnode(0x140070000, space="ram")
    global_node.address.getAddressSpace = lambda: ram  # type: ignore[method-assign]
    global_node.isAddress = lambda: True  # type: ignore[method-assign]
    acquired = cfg_ssa._acquire_varnode(global_node, program)
    assert acquired is not None
    assert acquired["opaque_location"] == {
        "raw_space": "ram",
        "raw_space_id": 0x1B1,
        "raw_offset": 0x140070000,
        "raw_size": 8,
        "raw_address": True,
    }

    mismatched = _RamSpace(space_id=0x999)
    mismatched_node = _Varnode(0x140070000, space="ram")
    mismatched_node.address.getAddressSpace = lambda: mismatched  # type: ignore[method-assign]
    mismatched_node.isAddress = lambda: True  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="exact physical default RAM"):
        cfg_ssa._acquire_varnode(
            mismatched_node,
            _RichProgram(factory=_AddressFactory({0x999: ram}, ram)),
        )

    with pytest.raises(ValueError, match="address factory is absent"):
        cfg_ssa._acquire_varnode(global_node, _RichProgram(factory=None))
    throwing_factory = _RichProgram(factory=factory)
    throwing_factory.getAddressFactory = lambda: (_ for _ in ()).throw(  # type: ignore[method-assign]
        RuntimeError("boom")
    )
    with pytest.raises(ValueError, match="address factory API failed"):
        cfg_ssa._acquire_varnode(global_node, throwing_factory)

    def global_for(space: _RamSpace) -> _Varnode:
        value = _Varnode(0x140080000, space="ram")
        value.address.getAddressSpace = lambda: space  # type: ignore[method-assign]
        value.isAddress = lambda: True  # type: ignore[method-assign]
        return value

    for bad_space in (
        _RamSpace(loaded=False),
        _RamSpace(overlay=True),
        _RamSpace(physical=object()),
    ):
        with pytest.raises(ValueError, match="exact physical default RAM"):
            cfg_ssa._acquire_varnode(
                global_for(bad_space),
                _RichProgram(factory=_AddressFactory({0x1B1: bad_space}, bad_space)),
            )
    nondefault = _RamSpace()
    with pytest.raises(ValueError, match="exact physical default RAM"):
        cfg_ssa._acquire_varnode(
            global_for(ram),
            _RichProgram(factory=_AddressFactory({0x1B1: ram}, nondefault)),
        )

    selector = _Varnode(103, space="const")
    selector.isConstant = lambda: True  # type: ignore[method-assign]
    selector.getSize = lambda: 4  # type: ignore[method-assign]
    referenced_sequence = _Sequence(0x140001010, 3)
    referenced = type("Referenced", (), {"getSeqnum": lambda self: referenced_sequence})()
    high = type("High", (), {"getOpRef": lambda self, effect_id: referenced})()
    effect = cfg_ssa._acquire_effect_op(selector, high, _PROGRAM)
    assert effect["raw_effect_op_key"] == str(referenced_sequence)
    assert effect["raw_effect_seq_time"] == 103

    null_high = type("High", (), {"getOpRef": lambda self, effect_id: None})()
    with pytest.raises(ValueError, match="returned no operation"):
        cfg_ssa._acquire_effect_op(selector, null_high, _PROGRAM)
    throwing_high = type(
        "High",
        (),
        {"getOpRef": lambda self, effect_id: (_ for _ in ()).throw(RuntimeError("boom"))},
    )()
    with pytest.raises(ValueError, match="getOpRef API failed"):
        cfg_ssa._acquire_effect_op(selector, throwing_high, _PROGRAM)
    wrong_sequence = _Sequence(0x140001010, 4)
    wrong_ref = type("Referenced", (), {"getSeqnum": lambda self: wrong_sequence})()
    wrong_high = type("High", (), {"getOpRef": lambda self, effect_id: wrong_ref})()
    with pytest.raises(ValueError, match="time does not match"):
        cfg_ssa._acquire_effect_op(selector, wrong_high, _PROGRAM)

    overflow = _Varnode(0x80000000, space="const")
    overflow.isConstant = lambda: True  # type: ignore[method-assign]
    overflow.getSize = lambda: 4  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="nonnegative Java int"):
        cfg_ssa._acquire_effect_op(overflow, high, _PROGRAM)


def test_open_function_acquisition_tags_and_canonicalizes_phi_operands() -> None:
    entry = _Block(1, [], [])
    left = _Block(2, [entry], [])
    right = _Block(3, [entry], [])
    join = _Block(4, [right, left], [])
    entry.outgoing = [left, right]
    left.outgoing = [join]
    right.outgoing = [join]

    class _Op:
        def __init__(
            self,
            parent: _Block,
            ordinal: int,
            inputs: list[_Varnode],
            opcode: str = "COPY",
        ) -> None:
            self.parent = parent
            self.sequence = _Sequence(0x140001100 + ordinal * 0x10, ordinal)
            self.inputs = inputs
            self.opcode = opcode
            self.output = _Varnode(0x100 + ordinal)
            self.output.definition = self

        def getParent(self) -> _Block:
            return self.parent

        def getSeqnum(self) -> _Sequence:
            return self.sequence

        def getMnemonic(self) -> str:
            return self.opcode

        def getOutput(self) -> _Varnode:
            return self.output

        def getNumInputs(self) -> int:
            return len(self.inputs)

        def getInput(self, index: int) -> _Varnode:
            return self.inputs[index]

    entry_op = _Op(entry, 1, [_Varnode(0x201)])
    left_op = _Op(left, 2, [_Varnode(0x202)])
    right_op = _Op(right, 3, [_Varnode(0x203)])
    phi_op = _Op(
        join,
        4,
        [
            _Varnode(0x103, definition=right_op),
            _Varnode(0x102, definition=left_op),
        ],
        "MULTIEQUAL",
    )
    high = type(
        "High",
        (),
        {
            "getBasicBlocks": lambda self: [join, right, left, entry],
            "getPcodeOps": lambda self: _Iterator([entry_op, left_op, right_op, phi_op]),
        },
    )()
    function = type(
        "Function",
        (),
        {
            "getEntryPoint": lambda self: _Address(0x140001000),
            "getProgram": lambda self: _PROGRAM,
        },
    )()
    result = cfg_ssa.acquire_open_function_cfg_ssa(
        function,
        high,
        image_base=0x140000000,
        image_max=0x140100000,
        instruction_ordinals={
            0x1100: 0,
            0x1110: 1,
            0x1120: 2,
            0x1130: 3,
            0x1140: 4,
        },
    )
    assert result["ops"][3]["operands"] == [
        {"kind": "phi_value", "block_id": "b1", "varnode_id": "v2"},
        {"kind": "phi_value", "block_id": "b2", "varnode_id": "v4"},
    ]
    assert [
        edge["operand_index"] for edge in result["def_use_edges"] if edge["use_op_id"] == "o4_0"
    ] == [0, 1]


def test_acquisition_disambiguates_duplicate_start_branch_by_parent_successors() -> None:
    entry = _Block(1, [], [])
    selected = _Block(2, [entry], [])
    bridge = _Block(3, [entry], [])
    duplicate = _Block(4, [bridge], [])
    entry.outgoing = [selected, bridge]
    bridge.outgoing = [duplicate]
    selected.getStart = lambda: _Address(0x140002000)  # type: ignore[method-assign]
    duplicate.getStart = lambda: _Address(0x140002000)  # type: ignore[method-assign]

    class _Op:
        def __init__(self, parent: _Block, ordinal: int, opcode: str = "COPY") -> None:
            self.parent = parent
            self.sequence = _Sequence(0x140001100 + ordinal * 0x10, ordinal)
            self.opcode = opcode
            self.output = None if opcode == "CBRANCH" else _Varnode(0x100 + ordinal)
            if self.output is not None:
                self.output.definition = self
            if opcode == "CBRANCH":
                target = _Varnode(0x140002000, space="ram")
                target.isAddress = lambda: True  # type: ignore[method-assign]
                self.inputs = [target, _Varnode(0x200 + ordinal)]
            else:
                self.inputs = [_Varnode(0x200 + ordinal)]

        def getParent(self) -> _Block:
            return self.parent

        def getSeqnum(self) -> _Sequence:
            return self.sequence

        def getMnemonic(self) -> str:
            return self.opcode

        def getOutput(self) -> _Varnode | None:
            return self.output

        def getNumInputs(self) -> int:
            return len(self.inputs)

        def getInput(self, index: int) -> _Varnode:
            return self.inputs[index]

    ops = [
        _Op(entry, 1, "CBRANCH"),
        _Op(selected, 2),
        _Op(bridge, 3),
        _Op(duplicate, 4),
    ]
    high = type(
        "High",
        (),
        {
            "getBasicBlocks": lambda self: [duplicate, bridge, selected, entry],
            "getPcodeOps": lambda self: _Iterator(list(ops)),
        },
    )()
    function = type(
        "Function",
        (),
        {
            "getEntryPoint": lambda self: _Address(0x140001000),
            "getProgram": lambda self: _PROGRAM,
        },
    )()
    result = cfg_ssa.acquire_open_function_cfg_ssa(
        function,
        high,
        image_base=0x140000000,
        image_max=0x140100000,
        instruction_ordinals={
            0x1100: 0,
            0x1110: 1,
            0x1120: 2,
            0x1130: 3,
            0x1140: 4,
        },
    )
    assert result["ops"][0]["operands"][0] == {"kind": "block_target", "block_id": "b1"}
    assert all("block_target_id" not in row for row in result["varnodes"])
    assert all(
        edge["use_op_id"] != result["ops"][0]["id"] or edge["operand_index"] != 0
        for edge in result["live_in_uses"]
    )


def test_acquisition_rejects_duplicate_block_starts_unknown_spaces_and_operand_caps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _Block(1, [], [])
    second = _Block(2, [first], [])
    first.outgoing = [second]
    first.getStart = lambda: _Address(0x140001000)  # type: ignore[method-assign]
    second.getStart = lambda: _Address(0x140001000)  # type: ignore[method-assign]
    high = type(
        "High",
        (),
        {"getBasicBlocks": lambda self: [second, first], "getPcodeOps": lambda self: _Iterator([])},
    )()
    function = type(
        "Function",
        (),
        {
            "getEntryPoint": lambda self: _Address(0x140001000),
            "getProgram": lambda self: _PROGRAM,
        },
    )()
    with pytest.raises(ValueError, match="extent"):
        cfg_ssa.acquire_open_function_cfg_ssa(
            function,
            high,
            image_base=0x140000000,
            image_max=0x140100000,
            instruction_ordinals={},
        )

    target = _Varnode(0x140001000, space="ram")
    target.isAddress = lambda: True  # type: ignore[method-assign]
    observed = cfg_ssa._acquire_branch_target(
        target,
        {0x140001000: ["left", "right"]},
        allowed_targets={"right"},
    )
    assert observed[0] == "right"
    assert observed[1]["storage_class"] == "ram"
    with pytest.raises(ValueError, match="structurally ambiguous"):
        cfg_ssa._acquire_branch_target(
            target,
            {0x140001000: ["left", "right"]},
            allowed_targets={"left", "right"},
        )

    invalid_targets: list[tuple[_Varnode, str]] = []
    unknown = _Varnode(0x140001000, space="fspec")
    unknown.isAddress = lambda: True  # type: ignore[method-assign]
    invalid_targets.append((unknown, "outside the reviewed prototype"))
    non_ram = _Varnode(0x140001000)
    non_ram.isAddress = lambda: True  # type: ignore[method-assign]
    invalid_targets.append((non_ram, "classification is inconsistent"))
    definition = type(
        "Definition",
        (),
        {"getSeqnum": lambda self: _Sequence(0x140001010, 1)},
    )()
    defined = _Varnode(0x140001000, definition=definition, space="ram")
    defined.isAddress = lambda: True  # type: ignore[method-assign]
    invalid_targets.append((defined, "classification is inconsistent"))
    zero = _Varnode(0x140001000, space="ram")
    zero.isAddress = lambda: True  # type: ignore[method-assign]
    zero.getSize = lambda: 0  # type: ignore[method-assign]
    invalid_targets.append((zero, "varnode size is outside the reviewed bound"))
    oversized = _Varnode(0x140001000, space="ram")
    oversized.isAddress = lambda: True  # type: ignore[method-assign]
    oversized.getSize = lambda: cfg_ssa.MAX_VARNODE_BYTES + 1  # type: ignore[method-assign]
    invalid_targets.append((oversized, "varnode size is outside the reviewed bound"))
    nonaddress = _Varnode(0x140001000, space="ram")
    invalid_targets.append((nonaddress, "classification is inconsistent"))
    constant = _Varnode(0x140001000, space="ram")
    constant.isAddress = lambda: True  # type: ignore[method-assign]
    constant.isConstant = lambda: True  # type: ignore[method-assign]
    invalid_targets.append((constant, "classification is inconsistent"))
    for invalid, match in invalid_targets:
        with pytest.raises(ValueError, match=match):
            cfg_ssa._acquire_branch_target(
                invalid,
                {0x140001000: ["right"]},
                allowed_targets={"right"},
            )

    function, high = _open_fixture(input_space="fspec")
    with pytest.raises(ValueError, match="outside the reviewed prototype"):
        cfg_ssa.acquire_open_function_cfg_ssa(
            function,
            high,
            image_base=0x140000000,
            image_max=0x140100000,
            instruction_ordinals={0x1000: 0, 0x1010: 1},
        )

    function, high = _open_fixture()
    monkeypatch.setattr(cfg_ssa, "MAX_INPUTS_PER_OP", 0)
    with pytest.raises(ValueError, match="operand extent"):
        cfg_ssa.acquire_open_function_cfg_ssa(
            function,
            high,
            image_base=0x140000000,
            image_max=0x140100000,
            instruction_ordinals={0x1000: 0, 0x1010: 1},
        )


def _minimal_pe(path: Path, *, image_base: int = 0x140000000, image_size: int = 0x20000) -> None:
    raw = bytearray(0x200)
    raw[:2] = b"MZ"
    struct.pack_into("<I", raw, 0x3C, 0x80)
    raw[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", raw, 0x84 + 16, 0x70)
    optional = 0x84 + 20
    struct.pack_into("<H", raw, optional, 0x20B)
    struct.pack_into("<Q", raw, optional + 24, image_base)
    struct.pack_into("<I", raw, optional + 56, image_size)
    path.write_bytes(raw)


def _native_side(binary: Path, pdb: Path) -> dict[str, object]:
    functions = []
    for index in range(cfg_ssa.MAX_FUNCTIONS):
        entry = 0x1000 + index * 0x10
        functions.append(
            {
                "hypothesis_id": f"hypothesis-{index}",
                "row_indices": [index],
                "ioctl_keys": [f"0x{index:x}"],
                "entry_rva": f"0x{entry:x}",
                "instructions": [{"rva": f"0x{entry:x}"}],
            }
        )
    return {
        "side": "side_a",
        "driver_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "pdb_sha256": hashlib.sha256(pdb.read_bytes()).hexdigest(),
        "image_base": "0x140000000",
        "architecture": "x86_64",
        "tool": {"name": "ghidra", "version": "12.1.2"},
        "functions": functions,
    }


def _install_side_ghidra_fakes(
    monkeypatch: pytest.MonkeyPatch,
    native: dict[str, object],
    *,
    completed: bool = True,
    high_function: object | None = object(),
) -> tuple[list[tuple[object, int]], object]:
    image_base = 0x140000000

    class Function:
        def __init__(self, entry: int) -> None:
            self.entry = entry

        def isExternal(self) -> bool:
            return False

        def isThunk(self) -> bool:
            return False

        def getEntryPoint(self) -> _Address:
            return _Address(self.entry)

    functions = {
        image_base + int(str(item["entry_rva"]), 16): Function(
            image_base + int(str(item["entry_rva"]), 16)
        )
        for item in native["functions"]
    }

    class Factory:
        def getDefaultAddressSpace(self) -> object:
            return type("Space", (), {"getAddress": lambda self, offset: _Address(offset)})()

    program = type(
        "Program",
        (),
        {
            "getFunctionManager": lambda self: _FunctionManager(functions),
            "getAddressFactory": lambda self: Factory(),
        },
    )()
    flat = type("Flat", (), {"getCurrentProgram": lambda self: program})()

    class OpenProgram:
        def __enter__(self) -> object:
            return flat

        def __exit__(self, *args: object) -> None:
            return None

    pyghidra = ModuleType("pyghidra")
    pyghidra.start = lambda **kwargs: None  # type: ignore[attr-defined]
    pyghidra.open_program = lambda path: OpenProgram()  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "pyghidra", pyghidra)

    calls: list[tuple[object, int]] = []

    class Result:
        def decompileCompleted(self) -> bool:
            return completed

        def getHighFunction(self) -> object | None:
            return high_function

    class Decompiler:
        disposed = False

        def openProgram(self, opened: object) -> bool:
            return opened is program

        def decompileFunction(self, function: object, timeout: int, monitor: object) -> Result:
            calls.append((function, timeout))
            return Result()

        def dispose(self) -> None:
            type(self).disposed = True

    decompiler_module = ModuleType("ghidra.app.decompiler")
    decompiler_module.DecompInterface = Decompiler  # type: ignore[attr-defined]
    framework_module = ModuleType("ghidra.framework")
    framework_module.Application = type(  # type: ignore[attr-defined]
        "Application", (), {"getApplicationVersion": staticmethod(lambda: "12.1.2")}
    )
    task_module = ModuleType("ghidra.util.task")
    task_module.ConsoleTaskMonitor = type("ConsoleTaskMonitor", (), {})  # type: ignore[attr-defined]
    for name, module in (
        ("ghidra", ModuleType("ghidra")),
        ("ghidra.app", ModuleType("ghidra.app")),
        ("ghidra.app.decompiler", decompiler_module),
        ("ghidra.framework", framework_module),
        ("ghidra.util", ModuleType("ghidra.util")),
        ("ghidra.util.task", task_module),
    ):
        monkeypatch.setitem(sys.modules, name, module)
    return calls, Decompiler


def test_side_acquisition_opens_once_and_binds_all_exact_native_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "afd.sys"
    pdb = tmp_path / "afd.pdb"
    _minimal_pe(binary)
    pdb.write_bytes(b"pdb")
    native = _native_side(binary, pdb)
    calls, decompiler = _install_side_ghidra_fakes(monkeypatch, native)
    observed: list[tuple[int, int, dict[int, int]]] = []

    def acquire(
        function: object,
        high: object,
        *,
        image_base: int,
        image_max: int,
        instruction_ordinals: dict[int, int],
    ) -> dict[str, object]:
        observed.append((image_base, image_max, instruction_ordinals))
        return {"block_count": 1, "op_count": 2, "edges": [{}]}

    monkeypatch.setattr(cfg_ssa, "_requested_ghidra_version", lambda home: "12.1.2")
    monkeypatch.setattr(cfg_ssa, "_pe_machine", lambda path: (0x140000000, "x86_64", 8))
    monkeypatch.setattr(cfg_ssa, "_require_active_ghidra_version", lambda active, wanted: None)
    monkeypatch.setattr(cfg_ssa, "acquire_open_function_cfg_ssa", acquire)
    result = cfg_ssa.acquire_afd_handler_cfg_ssa_side(binary, pdb, tmp_path, native, side="side_a")
    assert len(calls) == cfg_ssa.MAX_FUNCTIONS
    assert all(0 < timeout <= cfg_ssa.SIDE_WALL_CLOCK_SECONDS for _function, timeout in calls)
    assert observed[0] == (0x140000000, 0x140020000, {0x1000: 0})
    assert observed[-1][2] == {0x1200: 0}
    assert result["schema_version"] == cfg_ssa.SIDE_SCHEMA_VERSION
    assert result["producer"] == cfg_ssa.SIDE_PRODUCER
    assert result["accounting"] == {
        "functions_requested": 33,
        "functions_observed": 33,
        "blocks_total": 33,
        "ops_total": 66,
        "edges_total": 33,
        "limits_hit": [],
    }
    assert result["static_only"] is True
    assert result["device_ioctl_attempts"] == 0
    assert decompiler.disposed is True


@pytest.mark.parametrize(
    ("completed", "high_function", "match"),
    [(False, object(), "decompilation failed"), (True, None, "no HighFunction")],
)
def test_side_acquisition_fails_closed_and_disposes_decompiler(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    completed: bool,
    high_function: object | None,
    match: str,
) -> None:
    binary = tmp_path / "afd.sys"
    pdb = tmp_path / "afd.pdb"
    _minimal_pe(binary)
    pdb.write_bytes(b"pdb")
    native = _native_side(binary, pdb)
    _calls, decompiler = _install_side_ghidra_fakes(
        monkeypatch, native, completed=completed, high_function=high_function
    )
    monkeypatch.setattr(cfg_ssa, "_requested_ghidra_version", lambda home: "12.1.2")
    monkeypatch.setattr(cfg_ssa, "_pe_machine", lambda path: (0x140000000, "x86_64", 8))
    monkeypatch.setattr(cfg_ssa, "_require_active_ghidra_version", lambda active, wanted: None)
    with pytest.raises(ValueError, match=match):
        cfg_ssa.acquire_afd_handler_cfg_ssa_side(binary, pdb, tmp_path, native, side="side_a")
    assert decompiler.disposed is True


def test_side_acquisition_enforces_total_wall_and_aggregate_bounds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "afd.sys"
    pdb = tmp_path / "afd.pdb"
    _minimal_pe(binary)
    pdb.write_bytes(b"pdb")
    native = _native_side(binary, pdb)
    _install_side_ghidra_fakes(monkeypatch, native)
    monkeypatch.setattr(cfg_ssa, "_requested_ghidra_version", lambda home: "12.1.2")
    monkeypatch.setattr(cfg_ssa, "_pe_machine", lambda path: (0x140000000, "x86_64", 8))
    monkeypatch.setattr(cfg_ssa, "_require_active_ghidra_version", lambda active, wanted: None)
    moments = iter((0.0, 301.0))
    monkeypatch.setattr(cfg_ssa.time, "monotonic", lambda: next(moments))
    with pytest.raises(ValueError, match="wall-clock cap"):
        cfg_ssa.acquire_afd_handler_cfg_ssa_side(binary, pdb, tmp_path, native, side="side_a")

    _install_side_ghidra_fakes(monkeypatch, native)
    monkeypatch.setattr(cfg_ssa.time, "monotonic", lambda: 0.0)
    monkeypatch.setattr(
        cfg_ssa,
        "acquire_open_function_cfg_ssa",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("inner failure")),
    )
    with pytest.raises(
        ValueError,
        match=r"side=side_a order=1 hypothesis=hypothesis-0 entry=0x1000: inner failure",
    ):
        cfg_ssa.acquire_afd_handler_cfg_ssa_side(binary, pdb, tmp_path, native, side="side_a")

    _install_side_ghidra_fakes(monkeypatch, native)
    monkeypatch.setattr(cfg_ssa, "MAX_TOTAL_OPS", 0)
    monkeypatch.setattr(
        cfg_ssa,
        "acquire_open_function_cfg_ssa",
        lambda *args, **kwargs: {"block_count": 1, "op_count": 1, "edges": []},
    )
    with pytest.raises(ValueError, match="aggregate extent"):
        cfg_ssa.acquire_afd_handler_cfg_ssa_side(binary, pdb, tmp_path, native, side="side_a")


def test_pe_image_bounds_uses_exact_size_of_image(tmp_path: Path) -> None:
    binary = tmp_path / "afd.sys"
    _minimal_pe(binary, image_base=0x180000000, image_size=0x345000)
    assert cfg_ssa._pe_image_bounds(binary) == (0x180000000, 0x180345000)
    binary.write_bytes(b"MZ")
    with pytest.raises(ValueError, match="exact PE"):
        cfg_ssa._pe_image_bounds(binary)
