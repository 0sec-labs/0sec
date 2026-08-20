from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

import zeroverse.windows_afd_handler_cfg_ssa as bundle
import zeroverse.windows_afd_handler_cfg_ssa_ghidra as ghidra_cfg


def _support(filename: str, name: str) -> ModuleType:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _native() -> dict[str, object]:
    return _support("test_windows_afd_handler_semantics.py", "_native_semantics_support")._compile()


def _cfg(entry_rva: str) -> dict[str, object]:
    rva = int(entry_rva, 16)
    return ghidra_cfg.normalize_cfg_ssa(
        {
            "raw_schema_version": ghidra_cfg.RAW_SCHEMA_VERSION,
            "entry_block": "entry",
            "blocks": [{"key": "entry", "predecessors": [], "successors": []}],
            "ops": [
                {
                    "key": "copy",
                    "parent": "entry",
                    "opcode": "COPY",
                    "source_ref": {
                        "function_rva": rva,
                        "instruction_rva": rva,
                        "instruction_ordinal": 0,
                        "seq_time": 1,
                        "pcode_order": 0,
                    },
                    "output": {
                        "kind": "value",
                        "value": {
                            "key": "out",
                            "definition_op_key": "copy",
                            "storage_class": "unique",
                            "size": 8,
                            "constant": None,
                            "address": False,
                            "opaque_location": None,
                        },
                    },
                    "operands": [
                        {
                            "kind": "value",
                            "value": {
                                "key": "one",
                                "definition_op_key": None,
                                "storage_class": "constant",
                                "size": 8,
                                "constant": 1,
                                "address": False,
                                "opaque_location": None,
                            },
                        }
                    ],
                }
            ],
            "complete_block_enumeration": True,
            "complete_op_enumeration": True,
            "image_min": 0x140000000,
            "image_max": 0x140200000,
            "native_instruction_count": 1,
        }
    )


def _refresh_cfg_fingerprint(cfg: dict[str, object]) -> None:
    projection = {
        "entry_block_id": cfg["entry_block_id"],
        "blocks": cfg["blocks"],
        "edges": cfg["edges"],
        "ops": [
            {key: value for key, value in op.items() if key != "source_ref"} for op in cfg["ops"]
        ],
        "varnodes": cfg["varnodes"],
        "def_use_edges": cfg["def_use_edges"],
        "live_in_uses": cfg["live_in_uses"],
    }
    cfg["image_address_independent_fingerprint"] = bundle._canonical_hash(projection)


def _make_first_constant_image_bearing(cfg: dict[str, object], identifier: str = "i0") -> None:
    constant = next(row for row in cfg["varnodes"] if row["constant"] is not None)
    constant["constant"] = None
    constant["image_constant_id"] = identifier
    cfg["image_bearing_constant_location_count"] = 1
    cfg["image_bearing_constant_varnode_count"] = 1
    _refresh_cfg_fingerprint(cfg)


def _acquisition(native: dict[str, object], side: str) -> dict[str, object]:
    native_side = native["sides"][side]
    functions = native_side["functions"]
    rows = [
        {
            "enumeration_order": order,
            "hypothesis_id": function["hypothesis_id"],
            "row_indices": function["row_indices"],
            "ioctl_keys": function["ioctl_keys"],
            "entry_rva": function["entry_rva"],
            "cfg_ssa": _cfg(function["entry_rva"]),
        }
        for order, function in enumerate(functions, 1)
    ]
    return {
        "schema_version": bundle.ACQUISITION_VERSION,
        "producer": ghidra_cfg.SIDE_PRODUCER,
        "side": side,
        "driver_sha256": native_side["driver_sha256"],
        "pdb_sha256": native_side["pdb_sha256"],
        "image_base": native_side["image_base"],
        "image_size": 0x200000,
        "architecture": "x86_64",
        "tool": native_side["tool"],
        "functions": rows,
        "accounting": {
            "functions_requested": 33,
            "functions_observed": 33,
            "blocks_total": 33,
            "ops_total": 33,
            "edges_total": 0,
            "limits_hit": [],
        },
        "static_only": True,
        "execution_authorized": False,
        "driver_load_attempts": 0,
        "device_open_attempts": 0,
        "device_ioctl_attempts": 0,
        "runtime_attempts": 0,
    }


def _compile() -> dict[str, object]:
    native = _native()
    return bundle.compile_windows_afd_handler_cfg_ssa(
        native, _acquisition(native, "side_a"), _acquisition(native, "side_b")
    )


def test_compiler_binds_all_functions_and_native_pairs() -> None:
    result = _compile()
    assert result["pair_count"] == 33
    assert result["native_semantics_bound"] is True
    assert result["complete_high_function_blocks_captured"] is True
    assert result["complete_high_pcode_ops_captured"] is True
    assert result["function_local_cfg_complete"] is False
    assert result["function_local_high_pcode_complete"] is False
    assert result["native_control_flow_complete"] is False
    first_cfg = result["sides"]["side_a"]["functions"][0]["cfg_ssa"]
    assert first_cfg["constant_bit_patterns_width_normalized"] is True
    assert first_cfg["constant_signedness_semantics_established"] is False
    assert first_cfg["address_space_offsets_width_normalized"] is True
    assert first_cfg["address_space_offset_signedness_semantics_established"] is False
    assert result["source_sink_semantics_established"] is False
    assert result["candidate_count"] == 0
    assert all(
        pair["image_address_independent_fingerprints_equal"] is True for pair in result["pairs"]
    )
    assert all(pair["factual_fingerprint_comparison_only"] is True for pair in result["pairs"])
    assert (
        result["sides"]["side_a"]["functions"][0]["native_evidence_id"]
        == (result["native_semantics_commitment"]["side_a_evidence_id"])
    )


def test_canonical_validator_recomputes_cfg_fingerprint_and_function_id() -> None:
    raw = _compile()
    raw["sides"]["side_a"]["functions"][0]["cfg_ssa"]["ops"][0]["opcode"] = "INT_ADD"
    with pytest.raises(ValueError, match="fingerprint recomputation"):
        bundle.canonical_handler_cfg_ssa_bytes(raw)

    raw = _compile()
    raw["sides"]["side_a"]["functions"][0]["native_body_addressed_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="function identity"):
        bundle.canonical_handler_cfg_ssa_bytes(raw)


def test_validator_requires_unsigned_declared_width_constant_bit_patterns() -> None:
    cfg = _cfg("0x1000")
    constant = next(row for row in cfg["varnodes"] if row["constant"] is not None)
    constant["constant"] = -1
    with pytest.raises(ValueError, match="varnode observation"):
        bundle._validate_cfg_ssa(cfg)

    cfg = _cfg("0x1000")
    constant = next(row for row in cfg["varnodes"] if row["constant"] is not None)
    constant["constant"] = 1 << (constant["size"] * 8)
    with pytest.raises(ValueError, match="constant varnode"):
        bundle._validate_cfg_ssa(cfg)


def test_image_bearing_constant_alpha_namespace_and_pair_fingerprint() -> None:
    ordinary = _cfg("0x1000")
    image_bearing = copy.deepcopy(ordinary)
    _make_first_constant_image_bearing(image_bearing)
    validated = bundle._validate_cfg_ssa(image_bearing)
    assert validated["image_bearing_constant_location_count"] == 1
    assert validated["image_bearing_constant_varnode_count"] == 1
    assert validated["image_bearing_constants_alpha_renamed"] is True
    assert validated["image_bearing_constant_pointer_semantics_established"] is False
    assert (
        image_bearing["image_address_independent_fingerprint"]
        != ordinary["image_address_independent_fingerprint"]
    )

    forged = copy.deepcopy(image_bearing)
    next(row for row in forged["varnodes"] if row["image_constant_id"] is not None)[
        "image_constant_id"
    ] = "i1"
    _refresh_cfg_fingerprint(forged)
    with pytest.raises(ValueError, match="namespace"):
        bundle._validate_cfg_ssa(forged)

    native = _native()
    side_a = _acquisition(native, "side_a")
    side_b = _acquisition(native, "side_b")
    _make_first_constant_image_bearing(side_a["functions"][0]["cfg_ssa"])
    result = bundle.compile_windows_afd_handler_cfg_ssa(native, side_a, side_b)
    assert result["pairs"][0]["image_address_independent_fingerprints_equal"] is False
    assert result["semantic_difference_established"] is False


def test_validator_rejects_lexicographic_vnode_permutation_above_ten_rows() -> None:
    raw = {
        "raw_schema_version": ghidra_cfg.RAW_SCHEMA_VERSION,
        "entry_block": "entry",
        "blocks": [{"key": "entry", "predecessors": [], "successors": []}],
        "ops": [
            {
                "key": "many-inputs",
                "parent": "entry",
                "opcode": "CUSTOM",
                "source_ref": {
                    "function_rva": 0x1000,
                    "instruction_rva": 0x1000,
                    "instruction_ordinal": 0,
                    "seq_time": 1,
                    "pcode_order": 0,
                },
                "output": None,
                "operands": [
                    {
                        "kind": "value",
                        "value": {
                            "key": f"constant-{value}",
                            "definition_op_key": None,
                            "storage_class": "constant",
                            "size": 8,
                            "constant": value,
                            "address": False,
                            "opaque_location": None,
                        },
                    }
                    for value in range(12)
                ],
            }
        ],
        "complete_block_enumeration": True,
        "complete_op_enumeration": True,
        "image_min": 0x140000000,
        "image_max": 0x140200000,
        "native_instruction_count": 1,
    }
    cfg = ghidra_cfg.normalize_cfg_ssa(raw)
    cfg["varnodes"] = sorted(cfg["varnodes"], key=lambda row: int(row["id"][1:]))
    _refresh_cfg_fingerprint(cfg)
    bundle._validate_cfg_ssa(cfg)

    lexicographic = copy.deepcopy(cfg)
    lexicographic["varnodes"] = sorted(lexicographic["varnodes"], key=lambda row: row["id"])
    assert [row["id"] for row in lexicographic["varnodes"][:4]] == [
        "v0",
        "v1",
        "v10",
        "v11",
    ]
    _refresh_cfg_fingerprint(lexicographic)
    with pytest.raises(ValueError, match="varnode observation"):
        bundle._validate_cfg_ssa(lexicographic)


def test_opaque_location_namespace_and_ram_provenance_are_exact() -> None:
    cfg = _cfg("0x1000")
    row = cfg["varnodes"][0]
    row["storage_class"] = "ram"
    row["opaque_location_id"] = "a0"
    cfg["opaque_global_location_count"] = 1
    cfg["opaque_global_varnode_count"] = 1
    _refresh_cfg_fingerprint(cfg)
    bundle._validate_cfg_ssa(cfg)

    address_like = copy.deepcopy(cfg)
    address_like["varnodes"][0]["opaque_location_id"] = "a0x140001000"
    _refresh_cfg_fingerprint(address_like)
    with pytest.raises(ValueError, match="opaque location namespace"):
        bundle._validate_cfg_ssa(address_like)

    wrong_storage = copy.deepcopy(cfg)
    wrong_storage["varnodes"][0]["storage_class"] = "unique"
    _refresh_cfg_fingerprint(wrong_storage)
    with pytest.raises(ValueError, match="opaque location identity"):
        bundle._validate_cfg_ssa(wrong_storage)


@pytest.mark.parametrize("extra_predecessor", ["b1", "b999"])
def test_cfg_rejects_unbacked_self_or_unknown_predecessor(extra_predecessor: str) -> None:
    support = _support("test_windows_afd_handler_cfg_ssa_ghidra.py", "_cfg_ssa_ghidra_support")
    cfg = ghidra_cfg.normalize_cfg_ssa(support._raw())
    cfg["blocks"][1]["predecessors"].append(extra_predecessor)
    _refresh_cfg_fingerprint(cfg)
    with pytest.raises(ValueError, match="predecessor/successor closure"):
        bundle._validate_cfg_ssa(cfg)


def test_call_target_identity_types_and_address_leakage_are_rejected() -> None:
    support = _support("test_windows_afd_handler_cfg_ssa_ghidra.py", "_cfg_ssa_ghidra_support")
    raw = support._raw()
    raw["ops"][0]["opcode"] = "CALL"
    raw["ops"][0]["operands"].insert(
        0,
        support._call_target(
            "external_import",
            library="KERNEL32.DLL",
            symbol="CreateFileW",
        ),
    )
    cfg = ghidra_cfg.normalize_cfg_ssa(raw)
    bundle._validate_cfg_ssa(cfg)
    target = cfg["ops"][0]["operands"][0]
    assert target["library"] == "kernel32.dll"

    dict_payload = copy.deepcopy(cfg)
    dict_payload["ops"][0]["operands"][0]["library"] = {"address": "0x140001000"}
    _refresh_cfg_fingerprint(dict_payload)
    with pytest.raises(ValueError, match="external import identity"):
        bundle._validate_cfg_ssa(dict_payload)

    address_string = copy.deepcopy(cfg)
    address_string["ops"][0]["operands"][0]["symbol"] = "0x140001000"
    _refresh_cfg_fingerprint(address_string)
    with pytest.raises(ValueError, match="external import identity"):
        bundle._validate_cfg_ssa(address_string)

    opaque_leak = copy.deepcopy(cfg)
    opaque_target = opaque_leak["ops"][0]["operands"][0]
    opaque_target["target_class"] = "internal_image_opaque"
    opaque_leak["opaque_call_target_count"] = 1
    _refresh_cfg_fingerprint(opaque_leak)
    with pytest.raises(ValueError, match="leaked identity"):
        bundle._validate_cfg_ssa(opaque_leak)


@pytest.mark.parametrize("opcode", ["BRANCH", "CBRANCH"])
def test_absolute_branch_target_must_be_an_exact_parent_successor(opcode: str) -> None:
    support = _support("test_windows_afd_handler_cfg_ssa_ghidra.py", "_cfg_ssa_ghidra_support")
    raw = support._raw()
    if opcode == "CBRANCH":
        support._add_fallthrough(raw)
    operands = [support._target("native-2")]
    if opcode == "CBRANCH":
        operands.append(
            support._value(support._var("branch-condition", storage="constant", size=1, constant=1))
        )
    raw["ops"].append(
        {
            "key": f"absolute-{opcode.lower()}",
            "parent": "native-7",
            "opcode": opcode,
            "source_ref": {
                "function_rva": 0x1000,
                "instruction_rva": 0x1040,
                "instruction_ordinal": 3,
                "seq_time": 90,
                "pcode_order": 0,
            },
            "output": None,
            "operands": operands,
        }
    )
    cfg = ghidra_cfg.normalize_cfg_ssa(raw)
    bundle._validate_cfg_ssa(cfg)

    forged = copy.deepcopy(cfg)
    branch = next(op for op in forged["ops"] if op["opcode"] == opcode)
    branch["operands"][0]["block_id"] = "b0"
    _refresh_cfg_fingerprint(forged)
    with pytest.raises(ValueError, match="target/successor closure"):
        bundle._validate_cfg_ssa(forged)


def test_compiler_rejects_wrong_native_function_and_source_binding() -> None:
    native = _native()
    side_a = _acquisition(native, "side_a")
    side_b = _acquisition(native, "side_b")
    side_a["functions"][0]["hypothesis_id"] = "wrong"
    with pytest.raises(ValueError, match="identity binding"):
        bundle.compile_windows_afd_handler_cfg_ssa(native, side_a, side_b)

    side_a = _acquisition(native, "side_a")
    side_a["functions"][0]["cfg_ssa"]["ops"][0]["source_ref"]["instruction_rva"] += 1
    with pytest.raises(ValueError, match="source/native instruction"):
        bundle.compile_windows_afd_handler_cfg_ssa(native, side_a, side_b)


@pytest.mark.parametrize("forged", [False, 33.0, -1, 34])
def test_exact_pair_count_and_zero_counts_reject_bool_or_nonzero(forged: object) -> None:
    raw = _compile()
    raw["pair_count"] = forged
    with pytest.raises(ValueError, match="contract"):
        bundle.canonical_handler_cfg_ssa_bytes(raw)

    raw = _compile()
    raw["runtime_attempts"] = True
    with pytest.raises(ValueError, match="contract"):
        bundle.canonical_handler_cfg_ssa_bytes(raw)


def test_pair_comparison_is_recomputed_not_interpreted() -> None:
    raw = _compile()
    raw["pairs"][0]["image_address_independent_fingerprints_equal"] = False
    with pytest.raises(ValueError, match="pair comparison"):
        bundle.canonical_handler_cfg_ssa_bytes(raw)

    unequal = copy.deepcopy(raw)
    assert unequal["semantic_difference_established"] is False
    assert unequal["cfg_semantic_difference_established"] is False


def test_v5_pcode_relative_delta_is_validated_as_non_ssa_metadata() -> None:
    support = _support("test_windows_afd_handler_cfg_ssa_ghidra.py", "_cfg_ssa_ghidra_support")
    relative_raw = support._raw()
    relative_raw.setdefault("native_instruction_count", 8)
    relative_raw["ops"].append(
        {
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
            "operands": [support._op_target(1)],
        }
    )
    cfg = ghidra_cfg.normalize_cfg_ssa(relative_raw)
    validated = bundle._validate_cfg_ssa(cfg)
    assert validated["pcode_relative_branch_delta_count"] == 1
    assert validated["pcode_relative_branch_deltas_preserved"] is True
    assert validated["pcode_relative_branch_target_resolution_established"] is False

    forged = copy.deepcopy(cfg)
    branch = next(op for op in forged["ops"] if op["opcode"] == "BRANCH")
    branch["operands"][0]["signed_delta"] = True
    with pytest.raises(ValueError, match="P-Code-relative delta"):
        bundle._validate_cfg_ssa(forged)

    forged = copy.deepcopy(cfg)
    branch = next(op for op in forged["ops"] if op["opcode"] == "BRANCH")
    branch["operands"][0]["signed_delta"] = 1 << (ghidra_cfg.MAX_VARNODE_BYTES * 8 - 1)
    with pytest.raises(ValueError, match="P-Code-relative delta"):
        bundle._validate_cfg_ssa(forged)


def test_v5_native_instruction_target_is_bounded_by_native_evidence() -> None:
    support = _support("test_windows_afd_handler_cfg_ssa_ghidra.py", "_cfg_ssa_ghidra_support")
    raw = support._raw()
    raw["native_instruction_count"] = 3
    branch = raw["ops"][1]
    branch["opcode"] = "BRANCH"
    branch["output"] = None
    branch["operands"] = [
        {
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
            "native_instruction_ordinal": 2,
        }
    ]
    cfg = ghidra_cfg.normalize_cfg_ssa(raw)
    native_function = {
        "entry_rva": "0x1000",
        "instructions": [
            {"rva": "0x1000"},
            {"rva": "0x1010"},
            {"rva": "0x1020"},
        ],
    }
    validated = bundle._validate_cfg_ssa(cfg, native_function=native_function)
    assert validated["native_instruction_branch_target_count"] == 1
    assert validated["high_function_cfg_covers_all_native_branch_targets"] is False

    forged = copy.deepcopy(cfg)
    forged_branch = next(op for op in forged["ops"] if op["opcode"] == "BRANCH")
    forged_branch["operands"][0]["native_instruction_ordinal"] = 3
    with pytest.raises(ValueError, match="outside native evidence"):
        bundle._validate_cfg_ssa(forged, native_function=native_function)
