"""Bounded, address-independent CFG/SSA normalization for one open Ghidra function."""

from __future__ import annotations

import hashlib
import json
import shutil
import struct
import tempfile
import time
from pathlib import Path
from typing import Any, cast

from .windows_ioctl_ghidra_export import (
    _pe_machine,
    _requested_ghidra_version,
    _require_active_ghidra_version,
)

MAX_FUNCTIONS = 33
MAX_BLOCKS = 4096
MAX_OPS = 100000
MAX_EDGES = 32768
MAX_NATIVE_INSTRUCTIONS = 20000
MAX_VARNODE_BYTES = 256
MAX_ADDRESS_SPACE_BITS = 64
MAX_INPUTS_PER_OP = 256
MAX_TOTAL_BLOCKS = MAX_FUNCTIONS * MAX_BLOCKS
MAX_TOTAL_OPS = MAX_FUNCTIONS * MAX_OPS
MAX_TOTAL_EDGES = MAX_FUNCTIONS * MAX_EDGES
SIDE_WALL_CLOCK_SECONDS = 300
SCHEMA_VERSION = "0verse.windows-afd-handler-cfg-ssa-facts/v5"
PRODUCER = "zeroverse.windows-afd-handler-cfg-ssa-ghidra/v5"
RAW_SCHEMA_VERSION = "0verse.windows-afd-handler-cfg-ssa-raw/v5"
SIDE_SCHEMA_VERSION = "0verse.windows-afd-handler-cfg-ssa-side-facts/v1"
SIDE_PRODUCER = "zeroverse.windows-afd-handler-cfg-ssa-side-ghidra/v1"
_REJECTED_OPCODES = {
    "BRANCHIND",
}
_CALL_TARGET_CLASSES = {"self", "external_import", "internal_image_opaque", "external_opaque"}
_STORAGE_CLASSES = {"constant", "join", "ram", "register", "stack", "unique"}


def acquire_afd_handler_cfg_ssa_side(
    binary: Path,
    pdb: Path,
    ghidra_home: Path,
    native_side: object,
    *,
    side: str,
) -> dict[str, object]:
    """Acquire normalized CFG/SSA facts for one exact native-evidence side."""
    try:
        import pyghidra
    except ImportError as exc:  # pragma: no cover - environment contract
        raise RuntimeError("PyGhidra is unavailable for AFD CFG/SSA acquisition") from exc
    if side not in {"side_a", "side_b"} or not isinstance(native_side, dict):
        raise ValueError("AFD CFG/SSA side identity is invalid")
    functions = native_side.get("functions")
    tool = native_side.get("tool")
    if (
        native_side.get("side") != side
        or native_side.get("architecture") != "x86_64"
        or not isinstance(functions, list)
        or len(functions) != MAX_FUNCTIONS
        or not isinstance(tool, dict)
        or tool.get("name") != "ghidra"
    ):
        raise ValueError("AFD CFG/SSA requires one exact 33-function native side")
    if _sha_file(binary) != native_side.get("driver_sha256") or _sha_file(pdb) != native_side.get(
        "pdb_sha256"
    ):
        raise ValueError("AFD CFG/SSA native-side artifact commitment mismatch")

    requested = _requested_ghidra_version(ghidra_home)
    if tool.get("version") != requested:
        raise ValueError("AFD CFG/SSA native-side Ghidra version mismatch")
    image_base, architecture, pointer_size = _pe_machine(binary)
    pe_image_base, image_max = _pe_image_bounds(binary)
    if (
        architecture != "x86_64"
        or pointer_size != 8
        or pe_image_base != image_base
        or native_side.get("image_base") != f"0x{image_base:x}"
    ):
        raise ValueError("AFD CFG/SSA native-side PE identity mismatch")

    requested_rows: list[tuple[dict[str, object], int, dict[int, int]]] = []
    seen_entries: set[int] = set()
    for raw_function in functions:
        if not isinstance(raw_function, dict):
            raise ValueError("AFD CFG/SSA native-side function shape mismatch")
        try:
            entry_rva = int(str(raw_function["entry_rva"]), 16)
        except (KeyError, ValueError) as exc:
            raise ValueError("AFD CFG/SSA native-side entry RVA is invalid") from exc
        instructions = raw_function.get("instructions")
        if entry_rva <= 0 or entry_rva in seen_entries or not isinstance(instructions, list):
            raise ValueError("AFD CFG/SSA native-side entries are not exact and unique")
        ordinals: dict[int, int] = {}
        for ordinal, raw_instruction in enumerate(instructions):
            if not isinstance(raw_instruction, dict):
                raise ValueError("AFD CFG/SSA native instruction shape mismatch")
            try:
                instruction_rva = int(str(raw_instruction["rva"]), 16)
            except (KeyError, ValueError) as exc:
                raise ValueError("AFD CFG/SSA native instruction RVA is invalid") from exc
            if instruction_rva in ordinals:
                raise ValueError("AFD CFG/SSA native instruction RVAs are duplicated")
            ordinals[instruction_rva] = ordinal
        if not ordinals or next(iter(ordinals)) != entry_rva:
            raise ValueError("AFD CFG/SSA native instructions do not start at the exact entry")
        seen_entries.add(entry_rva)
        requested_rows.append((raw_function, entry_rva, ordinals))

    started = time.monotonic()
    pyghidra.start(install_dir=ghidra_home)
    from ghidra.app.decompiler import DecompInterface
    from ghidra.framework import Application
    from ghidra.util.task import ConsoleTaskMonitor

    _require_active_ghidra_version(str(Application.getApplicationVersion()), requested)
    with tempfile.TemporaryDirectory(prefix=f"zeroverse-afd-cfg-ssa-{side}-") as temporary:
        target = Path(temporary) / "target.sys"
        shutil.copyfile(binary, target)
        shutil.copyfile(pdb, Path(temporary) / "target.pdb")
        with pyghidra.open_program(str(target)) as flat:
            program = flat.getCurrentProgram()
            manager = program.getFunctionManager()
            space = program.getAddressFactory().getDefaultAddressSpace()
            decompiler = DecompInterface()
            side_functions: list[dict[str, object]] = []
            blocks_total = 0
            ops_total = 0
            edges_total = 0
            try:
                if not bool(decompiler.openProgram(program)):
                    raise ValueError("AFD CFG/SSA decompiler rejected the exact program")
                for enumeration_order, (native, entry_rva, ordinals) in enumerate(
                    requested_rows, 1
                ):
                    remaining = SIDE_WALL_CLOCK_SECONDS - (time.monotonic() - started)
                    if remaining <= 0:
                        raise ValueError("AFD CFG/SSA side acquisition exceeded its wall-clock cap")
                    function = manager.getFunctionAt(space.getAddress(image_base + entry_rva))
                    if (
                        function is None
                        or bool(function.isExternal())
                        or bool(function.isThunk())
                        or int(function.getEntryPoint().getOffset()) != image_base + entry_rva
                    ):
                        raise ValueError(
                            "AFD CFG/SSA target is not one exact executable non-thunk function"
                        )
                    decompile = decompiler.decompileFunction(
                        function,
                        max(1, int(remaining)),
                        ConsoleTaskMonitor(),
                    )
                    if not bool(decompile.decompileCompleted()):
                        raise ValueError("AFD CFG/SSA exact function decompilation failed")
                    high_function = decompile.getHighFunction()
                    if high_function is None:
                        raise ValueError("AFD CFG/SSA decompilation returned no HighFunction")
                    try:
                        cfg_ssa = acquire_open_function_cfg_ssa(
                            function,
                            high_function,
                            image_base=image_base,
                            image_max=image_max,
                            instruction_ordinals=ordinals,
                        )
                    except ValueError as exc:
                        raise ValueError(
                            "AFD CFG/SSA side function acquisition failed: "
                            f"side={side} order={enumeration_order} "
                            f"hypothesis={native.get('hypothesis_id')} "
                            f"entry={native.get('entry_rva')}: {exc}"
                        ) from exc
                    blocks_total += _exact_nonnegative_int(
                        cfg_ssa.get("block_count"), "block count"
                    )
                    ops_total += _exact_nonnegative_int(cfg_ssa.get("op_count"), "operation count")
                    edges = cfg_ssa.get("edges")
                    if not isinstance(edges, list):
                        raise ValueError("AFD CFG/SSA edge accounting is invalid")
                    edges_total += len(edges)
                    if (
                        blocks_total > MAX_TOTAL_BLOCKS
                        or ops_total > MAX_TOTAL_OPS
                        or edges_total > MAX_TOTAL_EDGES
                    ):
                        raise ValueError("AFD CFG/SSA side aggregate extent exceeds its bound")
                    side_functions.append(
                        {
                            "enumeration_order": enumeration_order,
                            "hypothesis_id": native.get("hypothesis_id"),
                            "row_indices": native.get("row_indices"),
                            "ioctl_keys": native.get("ioctl_keys"),
                            "entry_rva": native.get("entry_rva"),
                            "cfg_ssa": cfg_ssa,
                        }
                    )
                if time.monotonic() - started > SIDE_WALL_CLOCK_SECONDS:
                    raise ValueError("AFD CFG/SSA side acquisition exceeded its wall-clock cap")
            finally:
                decompiler.dispose()
    return {
        "schema_version": SIDE_SCHEMA_VERSION,
        "producer": SIDE_PRODUCER,
        "side": side,
        "driver_sha256": native_side["driver_sha256"],
        "pdb_sha256": native_side["pdb_sha256"],
        "image_base": f"0x{image_base:x}",
        "image_size": image_max - image_base,
        "architecture": "x86_64",
        "tool": {"name": "ghidra", "version": requested},
        "functions": side_functions,
        "accounting": {
            "functions_requested": MAX_FUNCTIONS,
            "functions_observed": len(side_functions),
            "blocks_total": blocks_total,
            "ops_total": ops_total,
            "edges_total": edges_total,
            "limits_hit": [],
        },
        "static_only": True,
        "execution_authorized": False,
        "driver_load_attempts": 0,
        "device_open_attempts": 0,
        "device_ioctl_attempts": 0,
        "runtime_attempts": 0,
    }


def _pe_image_bounds(path: Path) -> tuple[int, int]:
    raw = path.read_bytes()
    if len(raw) < 0x40 or raw[:2] != b"MZ":
        raise ValueError("AFD CFG/SSA input is not an exact PE image")
    pe_offset = struct.unpack_from("<I", raw, 0x3C)[0]
    if pe_offset + 4 + 20 > len(raw) or raw[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("AFD CFG/SSA input has an invalid PE header")
    coff = pe_offset + 4
    optional_size = struct.unpack_from("<H", raw, coff + 16)[0]
    optional = coff + 20
    if optional_size < 64 or optional + optional_size > len(raw):
        raise ValueError("AFD CFG/SSA input has a truncated PE32+ header")
    if struct.unpack_from("<H", raw, optional)[0] != 0x20B:
        raise ValueError("AFD CFG/SSA input is not PE32+")
    image_base = struct.unpack_from("<Q", raw, optional + 24)[0]
    image_size = struct.unpack_from("<I", raw, optional + 56)[0]
    image_max = image_base + image_size
    if image_base <= 0 or image_size <= 0 or image_max > 1 << 64:
        raise ValueError("AFD CFG/SSA PE image extent is invalid")
    return image_base, image_max


def _exact_nonnegative_int(raw: object, label: str) -> int:
    if type(raw) is not int or raw < 0:
        raise ValueError(f"AFD CFG/SSA {label} is invalid")
    return raw


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_instruction_ordinals(
    instruction_ordinals: object, *, image_base: int, image_max: int
) -> int:
    if (
        not isinstance(instruction_ordinals, dict)
        or not 1 <= len(instruction_ordinals) <= MAX_NATIVE_INSTRUCTIONS
    ):
        raise ValueError("AFD native instruction ordinal map extent is invalid")
    rows = list(instruction_ordinals.items())
    if any(
        type(rva) is not int
        or rva < 0
        or image_base + rva >= image_max
        or type(ordinal) is not int
        or ordinal < 0
        for rva, ordinal in rows
    ):
        raise ValueError("AFD native instruction ordinal map entry is invalid")
    if sorted(ordinal for _rva, ordinal in rows) != list(range(len(rows))):
        raise ValueError("AFD native instruction ordinal map is not exact contiguous 0-based")
    return len(rows)


def normalize_cfg_ssa(raw: object) -> dict[str, object]:
    """Normalize already acquired facts without importing or invoking Ghidra."""
    if not isinstance(raw, dict) or set(raw) != {
        "raw_schema_version",
        "entry_block",
        "blocks",
        "ops",
        "complete_block_enumeration",
        "complete_op_enumeration",
        "image_min",
        "image_max",
        "native_instruction_count",
    }:
        raise ValueError("AFD CFG/SSA raw shape mismatch")
    if (
        raw["raw_schema_version"] != RAW_SCHEMA_VERSION
        or raw["complete_block_enumeration"] is not True
        or raw["complete_op_enumeration"] is not True
        or type(raw["image_min"]) is not int
        or type(raw["image_max"]) is not int
        or raw["image_min"] < 0
        or raw["image_max"] <= raw["image_min"]
        or type(raw["native_instruction_count"]) is not int
        or not 1 <= raw["native_instruction_count"] <= MAX_NATIVE_INSTRUCTIONS
    ):
        raise ValueError("AFD CFG/SSA acquisition completeness marker mismatch")
    image_min, image_max = raw["image_min"], raw["image_max"]
    native_instruction_count = raw["native_instruction_count"]
    blocks_raw, ops_raw = raw["blocks"], raw["ops"]
    if (
        not isinstance(blocks_raw, list)
        or not 1 <= len(blocks_raw) <= MAX_BLOCKS
        or not isinstance(ops_raw, list)
        or not 1 <= len(ops_raw) <= MAX_OPS
    ):
        raise ValueError("AFD CFG/SSA extent exceeds its complete bound")

    blocks: dict[str, dict[str, object]] = {}
    edge_count = 0
    for item in blocks_raw:
        if not isinstance(item, dict) or set(item) != {"key", "predecessors", "successors"}:
            raise ValueError("AFD CFG block shape mismatch")
        key = _token(item["key"], "block key")
        predecessors = _token_list(item["predecessors"], "block predecessors")
        successors = _token_list(item["successors"], "block successors")
        if (
            key in blocks
            or len(predecessors) != len(set(predecessors))
            or len(successors) != len(set(successors))
        ):
            raise ValueError("AFD CFG block identity or edge multiplicity mismatch")
        edge_count += len(successors)
        if edge_count > MAX_EDGES:
            raise ValueError("AFD CFG edge extent exceeds its complete bound")
        blocks[key] = {"predecessors": predecessors, "successors": successors}
    entry = _token(raw["entry_block"], "entry block")
    if entry not in blocks or blocks[entry]["predecessors"] != []:
        raise ValueError("AFD CFG requires one declared predecessor-free entry")
    if sum(value["predecessors"] == [] for value in blocks.values()) != 1:
        raise ValueError("AFD CFG does not have exactly one entry")
    for key, block in blocks.items():
        for successor in cast(list[str], block["successors"]):
            if successor not in blocks or key not in cast(
                list[str], blocks[successor]["predecessors"]
            ):
                raise ValueError("AFD CFG successor closure mismatch")
        for predecessor in cast(list[str], block["predecessors"]):
            if predecessor not in blocks or key not in cast(
                list[str], blocks[predecessor]["successors"]
            ):
                raise ValueError("AFD CFG predecessor closure mismatch")
    reachable = {entry}
    pending = [entry]
    while pending:
        current = pending.pop()
        for successor in cast(list[str], blocks[current]["successors"]):
            if successor not in reachable:
                reachable.add(successor)
                pending.append(successor)
    if reachable != set(blocks):
        raise ValueError("AFD CFG contains blocks unreachable from its entry")

    op_sites: dict[str, tuple[int, int]] = {}
    seen_sites: set[tuple[int, int]] = set()
    function_rvas: set[int] = set()
    for item in ops_raw:
        if not isinstance(item, dict) or "parent" not in item or "source_ref" not in item:
            raise ValueError("AFD High-P-Code operation shape mismatch")
        parent = _token(item["parent"], "operation parent")
        source = _source_ref(item["source_ref"])
        if source["instruction_ordinal"] >= native_instruction_count:
            raise ValueError("AFD High-P-Code source exceeds the retained native instruction map")
        function_rvas.add(source["function_rva"])
        site = (source["instruction_ordinal"], source["seq_time"])
        if parent not in blocks:
            raise ValueError("AFD High-P-Code operation is not parent-bound")
        if site in seen_sites:
            raise ValueError("AFD High-P-Code normalized operation site is ambiguous")
        seen_sites.add(site)
        op_sites[parent] = min(op_sites.get(parent, site), site)
    if set(op_sites) != set(blocks):
        raise ValueError("AFD CFG v5 requires at least one normalized operation per block")
    if len(function_rvas) != 1:
        raise ValueError("AFD High-P-Code operations do not share one exact function RVA")
    expected_entry = image_min + next(iter(function_rvas))
    if not image_min <= expected_entry < image_max:
        raise ValueError("AFD function entry is outside its exact image")
    block_order = sorted(blocks, key=lambda key: op_sites[key])
    block_ids = {key: f"b{index}" for index, key in enumerate(block_order)}

    ordered_ops = sorted(
        ops_raw,
        key=lambda item: (
            _source_ref(cast(dict[str, object], item)["source_ref"])["instruction_ordinal"],
            _source_ref(cast(dict[str, object], item)["source_ref"])["seq_time"],
        ),
    )
    op_key_to_id: dict[str, str] = {}
    op_key_to_seq_time: dict[str, int] = {}
    seq_time_to_keys: dict[int, list[str]] = {}
    local_orders: dict[int, int] = {}
    for item in ordered_ops:
        if not isinstance(item, dict) or set(item) != {
            "key",
            "parent",
            "opcode",
            "source_ref",
            "output",
            "operands",
        }:
            raise ValueError("AFD High-P-Code operation shape mismatch")
        op_key = _token(item["key"], "operation key")
        if op_key in op_key_to_id:
            raise ValueError("AFD High-P-Code operation identity is duplicated")
        instruction_ordinal = _source_ref(item["source_ref"])["instruction_ordinal"]
        local_order = local_orders.get(instruction_ordinal, 0)
        local_orders[instruction_ordinal] = local_order + 1
        op_key_to_id[op_key] = f"o{instruction_ordinal}_{local_order}"
        seq_time = _source_ref(item["source_ref"])["seq_time"]
        op_key_to_seq_time[op_key] = seq_time
        seq_time_to_keys.setdefault(seq_time, []).append(op_key)

    normalized_ops: list[dict[str, object]] = []
    var_ids: dict[str, str] = {}
    var_rows: dict[str, dict[str, object]] = {}
    definitions: dict[str, str] = {}
    pending_inputs: list[tuple[str, int, str]] = []
    opaque_ids: dict[tuple[str, int, int, int], str] = {}
    image_constant_ids: dict[tuple[int, int], str] = {}
    userop_names: dict[int, str] = {}
    userop_ids: dict[str, int] = {}
    opaque_call_target_count = 0
    direct_call_target_count = 0
    indirect_call_count = 0
    userop_count = 0
    memory_load_count = 0
    memory_store_count = 0
    indirect_effect_count = 0
    pcode_relative_branch_delta_count = 0
    native_instruction_branch_target_count = 0
    for item in ordered_ops:
        if not isinstance(item, dict):
            raise AssertionError("operation prevalidation was not preserved")
        op_key = _token(item["key"], "operation key")
        parent = _token(item["parent"], "operation parent")
        opcode = _token(item["opcode"], "operation opcode")
        if opcode in _REJECTED_OPCODES:
            raise ValueError(f"AFD CFG/SSA v5 does not support {opcode}")
        if parent not in blocks:
            raise ValueError("AFD High-P-Code operation is not parent-bound")
        source_ref = _source_ref(item["source_ref"])
        operands = item["operands"]
        if not isinstance(operands, list) or len(operands) > MAX_INPUTS_PER_OP:
            raise ValueError("AFD High-P-Code operands are not complete")
        op_id = op_key_to_id[op_key]
        output: dict[str, object] | None = None
        output_key: str | None = None
        if item["output"] is not None:
            raw_output = item["output"]
            if not isinstance(raw_output, dict) or set(raw_output) != {"kind", "value"}:
                raise ValueError("AFD High-P-Code output shape mismatch")
            if raw_output["kind"] != "value":
                raise ValueError("AFD High-P-Code output must be a tagged value")
            output_key, output_id, output_definition = _intern_varnode(
                raw_output["value"],
                var_ids,
                var_rows,
                opaque_ids,
                image_constant_ids,
                op_key_to_id,
                image_min=image_min,
                image_max=image_max,
            )
            if output_definition != op_id:
                raise ValueError("AFD SSA output does not bind to its owning operation")
            if var_rows[output_key]["storage_class"] == "constant":
                raise ValueError("AFD SSA operation cannot define a constant")
            if output_key in definitions:
                raise ValueError("AFD SSA varnode has multiple definitions")
            definitions[output_key] = op_id
            output = {"kind": "value", "varnode_id": output_id}
        if opcode == "MULTIEQUAL":
            parent_predecessors = cast(list[str], blocks[parent]["predecessors"])
            phi_operands: list[dict[str, object]] = []
            raw_predecessors: list[str] = []
            for operand in operands:
                if (
                    not isinstance(operand, dict)
                    or set(operand)
                    != {
                        "kind",
                        "raw_predecessor_key",
                        "value",
                    }
                    or operand.get("kind") != "phi_value"
                ):
                    raise ValueError("AFD MULTIEQUAL operand shape mismatch")
                predecessor = _token(operand["raw_predecessor_key"], "MULTIEQUAL predecessor block")
                phi_operands.append(operand)
                raw_predecessors.append(predecessor)
            if (
                item["output"] is None
                or len(raw_predecessors) != len(parent_predecessors)
                or len(set(raw_predecessors)) != len(raw_predecessors)
                or set(raw_predecessors) != set(parent_predecessors)
            ):
                raise ValueError(
                    "AFD MULTIEQUAL definition does not bind predecessors exactly once"
                )
            operands = sorted(
                phi_operands,
                key=lambda operand: block_ids[
                    _token(
                        cast(dict[str, object], operand)["raw_predecessor_key"],
                        "MULTIEQUAL predecessor block",
                    )
                ],
            )
        elif any(
            isinstance(operand, dict) and operand.get("kind") == "phi_value" for operand in operands
        ):
            raise ValueError("AFD non-MULTIEQUAL operation has a phi operand")

        normalized_operands: list[dict[str, object]] = []
        target_positions: list[int] = []
        delta_target_positions: list[int] = []
        native_target_positions: list[int] = []
        metadata_positions: dict[str, list[int]] = {
            "call_target": [],
            "userop": [],
            "memory_space": [],
            "effect_op": [],
        }
        for operand_index, operand in enumerate(operands):
            if not isinstance(operand, dict) or "kind" not in operand:
                raise ValueError("AFD High-P-Code operand shape mismatch")
            kind = operand["kind"]
            if kind == "value" and set(operand) == {"kind", "value"}:
                input_key, input_id, _definition = _intern_varnode(
                    operand["value"],
                    var_ids,
                    var_rows,
                    opaque_ids,
                    image_constant_ids,
                    op_key_to_id,
                    image_min=image_min,
                    image_max=image_max,
                )
                normalized_operands.append({"kind": "value", "varnode_id": input_id})
                pending_inputs.append((op_id, operand_index, input_key))
            elif kind == "block_target" and set(operand) == {
                "kind",
                "raw_block_key",
                "target",
            }:
                _validate_raw_branch_varnode(operand["target"])
                target_key = _token(operand["raw_block_key"], "branch target block")
                if target_key not in block_ids:
                    raise ValueError("AFD branch target is outside the complete CFG")
                normalized_operands.append(
                    {"kind": "block_target", "block_id": block_ids[target_key]}
                )
                target_positions.append(operand_index)
            elif kind == "pcode_relative_target":
                signed_delta = _validate_raw_relative_branch_target(
                    operand,
                    current_source_ref=source_ref,
                )
                normalized_operands.append(
                    {"kind": "pcode_relative_delta_target", "signed_delta": signed_delta}
                )
                delta_target_positions.append(operand_index)
                pcode_relative_branch_delta_count += 1
            elif kind == "native_instruction_target":
                native_ordinal = _validate_raw_native_instruction_target(
                    operand,
                    image_min=image_min,
                    image_max=image_max,
                    native_instruction_count=native_instruction_count,
                )
                normalized_operands.append(
                    {
                        "kind": "native_instruction_target",
                        "native_instruction_ordinal": native_ordinal,
                    }
                )
                native_target_positions.append(operand_index)
                native_instruction_branch_target_count += 1
            elif kind == "phi_value" and set(operand) == {
                "kind",
                "raw_predecessor_key",
                "value",
            }:
                predecessor = _token(operand["raw_predecessor_key"], "MULTIEQUAL predecessor block")
                if predecessor not in block_ids:
                    raise ValueError("AFD MULTIEQUAL predecessor is outside the complete CFG")
                input_key, input_id, _definition = _intern_varnode(
                    operand["value"],
                    var_ids,
                    var_rows,
                    opaque_ids,
                    image_constant_ids,
                    op_key_to_id,
                    image_min=image_min,
                    image_max=image_max,
                )
                normalized_operands.append(
                    {
                        "kind": "phi_value",
                        "block_id": block_ids[predecessor],
                        "varnode_id": input_id,
                    }
                )
                pending_inputs.append((op_id, operand_index, input_key))
            elif kind == "call_target":
                target = _normalize_call_target(operand, expected_entry=expected_entry)
                normalized_operands.append(target)
                metadata_positions["call_target"].append(operand_index)
                direct_call_target_count += 1
                if target["target_class"] in {"internal_image_opaque", "external_opaque"}:
                    opaque_call_target_count += 1
            elif kind == "userop":
                userop_id, userop_name = _validate_raw_userop(operand)
                if userop_id in userop_names and userop_names[userop_id] != userop_name:
                    raise ValueError("AFD CALLOTHER userop ID has conflicting names")
                if userop_name in userop_ids and userop_ids[userop_name] != userop_id:
                    raise ValueError("AFD CALLOTHER userop name has conflicting IDs")
                userop_names[userop_id] = userop_name
                userop_ids[userop_name] = userop_id
                normalized_operands.append(
                    {"kind": "userop", "userop_id": userop_id, "userop_name": userop_name}
                )
                metadata_positions["userop"].append(operand_index)
                userop_count += 1
            elif kind == "memory_space":
                _validate_raw_memory_space(operand)
                normalized_operands.append({"kind": "memory_space", "space": "ram"})
                metadata_positions["memory_space"].append(operand_index)
            elif kind == "effect_op":
                effect_key = _validate_raw_effect_op(
                    operand,
                    current_op_key=op_key,
                    op_key_to_id=op_key_to_id,
                    op_key_to_seq_time=op_key_to_seq_time,
                    seq_time_to_keys=seq_time_to_keys,
                )
                normalized_operands.append({"kind": "effect_op", "op_id": op_key_to_id[effect_key]})
                metadata_positions["effect_op"].append(operand_index)
            else:
                raise ValueError("AFD High-P-Code operand shape mismatch")
        if opcode == "BRANCH":
            if len(operands) != 1 or sorted(
                target_positions + delta_target_positions + native_target_positions
            ) != [0]:
                raise ValueError(
                    "AFD BRANCH requires one positional block, p-code-relative, or native "
                    "instruction target"
                )
        elif opcode == "CBRANCH":
            if (
                len(operands) != 2
                or sorted(target_positions + delta_target_positions + native_target_positions)
                != [0]
                or normalized_operands[1]["kind"] != "value"
            ):
                raise ValueError(
                    "AFD CBRANCH requires block, p-code-relative, or native instruction target "
                    "input 0 and condition input 1"
                )
        elif opcode == "CALL":
            if (
                not operands
                or metadata_positions["call_target"] != [0]
                or any(operand["kind"] != "value" for operand in normalized_operands[1:])
            ):
                raise ValueError("AFD CALL requires call target input 0 followed by values")
        elif opcode == "CALLIND":
            if not operands or any(operand["kind"] != "value" for operand in normalized_operands):
                raise ValueError("AFD CALLIND requires an indirect target followed by values")
            callind_target = normalized_operands[0]["varnode_id"]
            if any(
                row["id"] == callind_target and row["opaque_location_id"] is not None
                for row in var_rows.values()
            ):
                raise ValueError("AFD CALLIND target cannot be an opaque address global")
            indirect_call_count += 1
        elif opcode == "CALLOTHER":
            if (
                not operands
                or metadata_positions["userop"] != [0]
                or any(operand["kind"] != "value" for operand in normalized_operands[1:])
            ):
                raise ValueError("AFD CALLOTHER requires userop input 0 followed by values")
        elif opcode == "LOAD":
            if (
                item["output"] is None
                or len(operands) != 2
                or metadata_positions["memory_space"] != [0]
                or normalized_operands[1]["kind"] != "value"
            ):
                raise ValueError("AFD LOAD requires memory space, address value, and output")
            memory_load_count += 1
        elif opcode == "STORE":
            if (
                item["output"] is not None
                or len(operands) != 3
                or metadata_positions["memory_space"] != [0]
                or any(operand["kind"] != "value" for operand in normalized_operands[1:])
            ):
                raise ValueError(
                    "AFD STORE requires memory space, address value, value, and no output"
                )
            memory_store_count += 1
        elif opcode == "INDIRECT":
            if (
                output is None
                or output_key is None
                or len(operands) != 2
                or normalized_operands[0]["kind"] != "value"
                or metadata_positions["effect_op"] != [1]
            ):
                raise ValueError("AFD INDIRECT requires value, effect op, and output")
            indirect_input_id = _token(
                normalized_operands[0]["varnode_id"], "INDIRECT input varnode ID"
            )
            input_row = next(row for row in var_rows.values() if row["id"] == indirect_input_id)
            if var_rows[output_key]["size"] != input_row["size"]:
                raise ValueError("AFD INDIRECT input/output widths do not match")
            indirect_effect_count += 1
        elif target_positions or delta_target_positions or native_target_positions:
            raise ValueError("AFD non-branch operation contains a branch target")
        elif any(metadata_positions.values()):
            raise ValueError("AFD operation contains metadata operands forbidden for its opcode")
        if target_positions:
            target_id = normalized_operands[0]["block_id"]
            successor_ids = {
                block_ids[key] for key in cast(list[str], blocks[parent]["successors"])
            }
            if target_id not in successor_ids:
                raise ValueError("AFD direct branch target is not a CFG successor")
            if opcode == "BRANCH" and successor_ids != {target_id}:
                raise ValueError("AFD BRANCH target does not exactly close its CFG successors")
            if opcode == "CBRANCH" and len(successor_ids) != 2:
                raise ValueError("AFD CBRANCH requires exactly two distinct CFG successors")
        normalized_ops.append(
            {
                "id": op_id,
                "block_id": block_ids[parent],
                "opcode": opcode,
                "output": output,
                "operands": normalized_operands,
                "source_ref": source_ref,
            }
        )

    def_use = []
    live_ins = []
    opaque_space_ids = {location[1] for location in opaque_ids}
    if len(opaque_space_ids) > 1:
        raise ValueError("AFD opaque globals use conflicting raw RAM space IDs")
    for use_op, input_index, var_key in pending_inputs:
        edge = {
            "varnode_id": var_ids[var_key],
            "use_op_id": use_op,
            "operand_index": input_index,
        }
        definition_id = var_rows[var_key]["definition_op_id"]
        if definition_id is None:
            live_ins.append(edge)
        elif definitions.get(var_key) != definition_id:
            raise ValueError("AFD SSA definition is absent or does not own its output")
        else:
            def_use.append({"def_op_id": definition_id, **edge})

    normalized_blocks = [
        {
            "id": block_ids[key],
            "predecessors": sorted(
                block_ids[item] for item in cast(list[str], blocks[key]["predecessors"])
            ),
            "successors": sorted(
                block_ids[item] for item in cast(list[str], blocks[key]["successors"])
            ),
        }
        for key in block_order
    ]
    edges = [
        {"source": block["id"], "target": target}
        for block in normalized_blocks
        for target in block["successors"]
    ]
    varnodes = []
    for index, key in enumerate(var_ids):
        expected_id = f"v{index}"
        if var_ids[key] != expected_id or var_rows[key].get("id") != expected_id:
            raise ValueError("AFD normalized varnode identities are not contiguous")
        varnodes.append(var_rows[key])
    fingerprint_projection = {
        "entry_block_id": block_ids[entry],
        "blocks": normalized_blocks,
        "edges": edges,
        "ops": [
            {key: value for key, value in op.items() if key != "source_ref"}
            for op in normalized_ops
        ],
        "varnodes": varnodes,
        "def_use_edges": def_use,
        "live_in_uses": live_ins,
    }
    fingerprint = hashlib.sha256(_canonical(fingerprint_projection)).hexdigest()
    return {
        "schema_version": SCHEMA_VERSION,
        "producer": PRODUCER,
        **fingerprint_projection,
        "ops": normalized_ops,
        "block_count": len(normalized_blocks),
        "op_count": len(normalized_ops),
        "direct_call_target_count": direct_call_target_count,
        "indirect_call_count": indirect_call_count,
        "userop_count": userop_count,
        "memory_load_count": memory_load_count,
        "memory_store_count": memory_store_count,
        "indirect_effect_count": indirect_effect_count,
        "pcode_relative_branch_delta_count": pcode_relative_branch_delta_count,
        "native_instruction_branch_target_count": native_instruction_branch_target_count,
        "opaque_global_location_count": len(opaque_ids),
        "opaque_global_varnode_count": sum(
            row["opaque_location_id"] is not None for row in var_rows.values()
        ),
        "image_bearing_constant_location_count": len(image_constant_ids),
        "image_bearing_constant_varnode_count": sum(
            row["image_constant_id"] is not None for row in var_rows.values()
        ),
        "opaque_global_locations_alpha_renamed": True,
        "image_bearing_constants_alpha_renamed": True,
        "indirect_effect_refs_preserved": True,
        "pcode_relative_branch_deltas_preserved": True,
        "native_instruction_branch_targets_preserved": True,
        "high_function_cfg_covers_all_native_branch_targets": False,
        "opaque_call_target_count": opaque_call_target_count,
        "call_targets_preserved": True,
        "userops_preserved": True,
        "memory_operations_preserved": True,
        "constant_bit_patterns_width_normalized": True,
        "address_space_offsets_width_normalized": True,
        "complete_high_function_blocks": True,
        "complete_high_pcode_ops": True,
        "all_ops_parent_bound": True,
        "cfg_predecessor_successor_closure": True,
        "exact_source_refs_captured": True,
        "address_independent_encoding_applied": True,
        "normalization_lossless": False,
        "image_address_independent_fingerprint": fingerprint,
        "opaque_global_identity_semantics_established": False,
        "global_symbol_identity_established": False,
        "cross_build_global_identity_established": False,
        "image_bearing_constant_pointer_semantics_established": False,
        "image_bearing_constant_target_identity_established": False,
        "cross_build_image_bearing_constant_identity_established": False,
        "indirect_effect_semantics_established": False,
        "pcode_relative_branch_semantics_established": False,
        "pcode_relative_branch_target_resolution_established": False,
        "native_instruction_branch_semantics_established": False,
        "cfg_semantic_equivalence_established": False,
        "cfg_semantic_difference_established": False,
        "ssa_semantic_equivalence_established": False,
        "ssa_semantic_difference_established": False,
        "semantic_equivalence_established": False,
        "semantic_difference_established": False,
        "source_sink_semantics_established": False,
        "guard_delta_established": False,
        "memory_alias_proof_established": False,
        "memory_ssa_established": False,
        "call_semantics_established": False,
        "userop_semantics_established": False,
        "constant_signedness_semantics_established": False,
        "address_space_offset_signedness_semantics_established": False,
        "call_graph_complete": False,
        "cross_build_handler_identity_established": False,
        "handler_body_change_established": False,
        "servicing_lineage_established": False,
        "servicing_adjacency_established": False,
        "vulnerable_fixed_roles_established": False,
        "patch_causality_established": False,
        "ranking_performed": False,
        "candidate_count": 0,
        "candidate_established": False,
        "labels_consumed": False,
        "ground_truth_consumed": False,
        "model_invocations": 0,
        "network_attempts": 0,
        "network_performed": False,
        "driver_load_attempts": 0,
        "device_open_attempts": 0,
        "device_ioctl_attempts": 0,
        "runtime_attempts": 0,
        "runtime_performed": False,
        "runtime_consumable": False,
        "execution_authorized": False,
        "runtime_reachability_established": False,
        "unprivileged_reachability_established": False,
        "crash_established": False,
        "vulnerability_established": False,
        "lpe_established": False,
        "exploitability_established": False,
        "novelty_established": False,
        "claim_eligible": False,
        "bounty_eligible": False,
        "weaponization": False,
        "automatic_disclosure": False,
    }


def acquire_open_function_cfg_ssa(
    function: Any,
    high_function: Any,
    *,
    image_base: int,
    image_max: int,
    instruction_ordinals: dict[int, int],
) -> dict[str, object]:
    """Acquire complete facts for one already-open exact function and normalize them."""
    if (
        function is None
        or high_function is None
        or type(image_base) is not int
        or type(image_max) is not int
        or image_base < 0
        or image_max <= image_base
    ):
        raise ValueError("AFD CFG/SSA acquisition requires one exact open function")
    entry_point = _api("function entry point", lambda: function.getEntryPoint())
    if entry_point is None:
        raise ValueError("AFD CFG/SSA acquisition requires the function's exact entry point")
    entry_offset = int(_api("function entry offset", lambda: entry_point.getOffset()))
    program = _api("function program", lambda: function.getProgram())
    if program is None:
        raise ValueError("AFD CFG/SSA acquisition requires the function's exact program")
    if entry_offset < image_base:
        raise ValueError("AFD function entry precedes its image base")
    native_instruction_count = _validate_instruction_ordinals(
        instruction_ordinals,
        image_base=image_base,
        image_max=image_max,
    )
    blocks: list[Any] = []
    for block in high_function.getBasicBlocks():
        if len(blocks) >= MAX_BLOCKS:
            raise ValueError("AFD HighFunction block extent exceeds its complete bound")
        blocks.append(block)
    if not blocks:
        raise ValueError("AFD HighFunction block extent exceeds its complete bound")
    block_keys = {str(int(block.getIndex())): block for block in blocks}
    if len(block_keys) != len(blocks):
        raise ValueError("AFD HighFunction block IDs are ambiguous")
    entry_keys = [key for key, block in block_keys.items() if int(block.getInSize()) == 0]
    if len(entry_keys) != 1:
        raise ValueError("AFD HighFunction requires one entry block")
    block_rows = []
    block_targets: dict[int, list[str]] = {}
    edge_count = 0
    predecessor_count = 0
    for key, block in block_keys.items():
        start = _api("HighFunction block start", lambda block=block: block.getStart())
        if start is None:
            raise ValueError("AFD HighFunction block start is absent")
        start_offset = _api(
            "HighFunction block start offset", lambda start=start: int(start.getOffset())
        )
        if not image_base <= start_offset < image_max:
            raise ValueError("AFD HighFunction block start is outside the image")
        block_targets.setdefault(start_offset, []).append(key)
        incoming = []
        for index in range(block.getInSize()):
            if predecessor_count >= MAX_EDGES:
                raise ValueError("AFD HighFunction predecessor extent exceeds its complete bound")
            incoming.append(str(int(block.getIn(index).getIndex())))
            predecessor_count += 1
        outgoing = []
        for index in range(block.getOutSize()):
            if edge_count >= MAX_EDGES:
                raise ValueError("AFD HighFunction edge extent exceeds its complete bound")
            outgoing.append(str(int(block.getOut(index).getIndex())))
            edge_count += 1
        block_rows.append(
            {
                "key": key,
                "predecessors": incoming,
                "successors": outgoing,
            }
        )
    iterator = high_function.getPcodeOps()
    operations: list[dict[str, object]] = []
    while iterator.hasNext():
        if len(operations) >= MAX_OPS:
            raise ValueError("AFD High-P-Code operation extent exceeds its complete bound")
        op = iterator.next()
        parent = op.getParent()
        if parent is None:
            raise ValueError("AFD High-P-Code operation lacks a parent block")
        sequence = op.getSeqnum()
        target = int(sequence.getTarget().getOffset())
        if target < image_base:
            raise ValueError("AFD High-P-Code source precedes its image base")
        instruction_rva = target - image_base
        if instruction_rva not in instruction_ordinals:
            raise ValueError("AFD High-P-Code source lacks an exact native instruction ordinal")
        sequence_time = int(sequence.getTime())
        sequence_order = int(sequence.getOrder())
        if sequence_time < 0 or sequence_order < 0:
            raise ValueError("AFD High-P-Code sequence identity is invalid")
        input_count = int(op.getNumInputs())
        if not 0 <= input_count <= MAX_INPUTS_PER_OP:
            raise ValueError("AFD High-P-Code operand extent exceeds its complete bound")
        opcode = str(op.getMnemonic())
        parent_successors = {
            str(int(parent.getOut(index).getIndex())) for index in range(parent.getOutSize())
        }
        operands: list[dict[str, object]] = []
        for index in range(input_count):
            node = op.getInput(index)
            if opcode in {"BRANCH", "CBRANCH"} and index == 0:
                operands.append(
                    _acquire_branch_operand(
                        node,
                        block_targets,
                        allowed_targets=parent_successors,
                        instruction_rva=instruction_rva,
                        pcode_order=sequence_order,
                        image_base=image_base,
                        image_max=image_max,
                        instruction_ordinals=instruction_ordinals,
                    )
                )
            elif opcode == "CALL" and index == 0:
                operands.append(_acquire_call_target(node, function, program))
            elif opcode == "CALLOTHER" and index == 0:
                operands.append(_acquire_userop(node, program))
            elif opcode in {"LOAD", "STORE"} and index == 0:
                operands.append(_acquire_memory_space(node, program))
            elif opcode == "INDIRECT" and index == 1:
                operands.append(_acquire_effect_op(node, high_function, program))
            elif opcode == "MULTIEQUAL":
                if input_count != int(parent.getInSize()):
                    raise ValueError("AFD MULTIEQUAL input/predecessor extent mismatch")
                operands.append(
                    {
                        "kind": "phi_value",
                        "raw_predecessor_key": str(int(parent.getIn(index).getIndex())),
                        "value": _acquire_varnode(node, program),
                    }
                )
            else:
                operands.append({"kind": "value", "value": _acquire_varnode(node, program)})
        raw_output = _acquire_varnode(op.getOutput(), program)
        operations.append(
            {
                "key": str(sequence),
                "parent": str(int(parent.getIndex())),
                "opcode": opcode,
                "source_ref": {
                    "function_rva": entry_offset - image_base,
                    "instruction_rva": instruction_rva,
                    "instruction_ordinal": instruction_ordinals[instruction_rva],
                    "seq_time": sequence_time,
                    "pcode_order": sequence_order,
                },
                "output": None if raw_output is None else {"kind": "value", "value": raw_output},
                "operands": operands,
            }
        )
    return normalize_cfg_ssa(
        {
            "raw_schema_version": RAW_SCHEMA_VERSION,
            "entry_block": entry_keys[0],
            "blocks": block_rows,
            "ops": operations,
            "complete_block_enumeration": True,
            "complete_op_enumeration": True,
            "image_min": image_base,
            "image_max": image_max,
            "native_instruction_count": native_instruction_count,
        }
    )


def _acquire_varnode(
    node: Any,
    program: Any,
    *,
    capture_opaque: bool = True,
) -> dict[str, object] | None:
    row, _offset = _acquire_varnode_snapshot(node, program, capture_opaque=capture_opaque)
    return row


def _acquire_varnode_snapshot(
    node: Any,
    program: Any,
    *,
    capture_opaque: bool,
) -> tuple[dict[str, object] | None, int | None]:
    if node is None:
        return None, None
    address = _api("varnode address", lambda: node.getAddress())
    if address is None:
        raise ValueError("AFD varnode address is absent")
    address_space = _api("varnode address space", lambda: address.getAddressSpace())
    if address_space is None:
        raise ValueError("AFD varnode address space is absent")
    space = str(_api("varnode address-space name", lambda: address_space.getName()))
    address_space_bits = _api("varnode address-space size", lambda: int(address_space.getSize()))
    offset = _api("varnode offset", lambda: int(node.getOffset()))
    size = _api("varnode size", lambda: int(node.getSize()))
    definition = _api("varnode definition", lambda: node.getDef())
    definition_key = None
    if definition is not None:
        definition_sequence = _api("varnode definition sequence", lambda: definition.getSeqnum())
        if definition_sequence is None:
            raise ValueError("AFD varnode definition sequence is absent")
        definition_key = _api("varnode definition key", lambda: str(definition_sequence))
    is_constant = bool(_api("varnode constant classification", lambda: node.isConstant()))
    is_address = bool(_api("varnode address classification", lambda: node.isAddress()))
    if not 1 <= size <= MAX_VARNODE_BYTES:
        raise ValueError("AFD varnode size is outside the reviewed bound")
    if not 1 <= address_space_bits <= MAX_ADDRESS_SPACE_BITS:
        raise ValueError("AFD varnode address-space size is outside the reviewed bound")
    normalization_width = size * 8 if is_constant else address_space_bits
    if not -(1 << (normalization_width - 1)) <= offset < 1 << normalization_width:
        raise ValueError("AFD varnode offset is outside its declared-width range")
    offset %= 1 << normalization_width
    key = f"{space}:{offset:x}:{size}:{definition_key or 'live'}"
    storage_class = "constant" if is_constant else _storage_class(space)
    opaque_location = None
    if is_address and capture_opaque:
        opaque_location = _acquire_opaque_location(
            address_space,
            space,
            offset,
            size,
            program,
        )
    return {
        "key": key,
        "definition_op_key": definition_key,
        "storage_class": storage_class,
        "size": size,
        "constant": offset if is_constant else None,
        "address": is_address,
        "opaque_location": opaque_location,
    }, offset


def _acquire_opaque_location(
    space: Any,
    space_name: str,
    raw_offset: int,
    raw_size: int,
    program: Any,
) -> dict[str, object]:
    factory = _api("Program address factory", lambda: program.getAddressFactory())
    if factory is None:
        raise ValueError("AFD Program address factory is absent")
    raw_space_id = _api("opaque global getSpaceID", lambda: int(space.getSpaceID()))
    exact_space = _api(
        "AddressFactory opaque getAddressSpace",
        lambda: factory.getAddressSpace(raw_space_id),
    )
    loaded = _api("opaque global loaded classification", lambda: space.isLoadedMemorySpace())
    overlay = _api("opaque global overlay classification", lambda: space.isOverlaySpace())
    physical = _api("opaque global physical space", lambda: space.getPhysicalSpace())
    default = _api("AddressFactory default address space", lambda: factory.getDefaultAddressSpace())
    if (
        exact_space is None
        or exact_space != space
        or space_name.lower() != "ram"
        or not bool(loaded)
        or bool(overlay)
        or physical != space
        or default != space
        or raw_offset < 0
        or not 1 <= raw_size <= MAX_VARNODE_BYTES
    ):
        raise ValueError("AFD opaque global is not exact physical default RAM")
    return {
        "raw_space": "ram",
        "raw_space_id": raw_space_id,
        "raw_offset": raw_offset,
        "raw_size": raw_size,
        "raw_address": True,
    }


def _acquire_call_target(node: Any, function: Any, program: Any) -> dict[str, object]:
    if node is None:
        raise ValueError("AFD CALL target is absent")
    address = _api("CALL target address", lambda: node.getAddress())
    if address is None:
        raise ValueError("AFD CALL target address is absent")
    address_space = _api("CALL target address space", lambda: address.getAddressSpace())
    if address_space is None:
        raise ValueError("AFD CALL target address space is absent")
    raw_space = str(_api("CALL target address-space name", lambda: address_space.getName())).lower()
    raw_offset = int(_api("CALL target offset", lambda: node.getOffset()))
    raw_size = _api("CALL target size", lambda: int(node.getSize()))
    pointer_size = _api("CALL target pointer size", lambda: int(address_space.getPointerSize()))
    raw_address = bool(_api("CALL target address classification", lambda: node.isAddress()))
    if (
        raw_space != "ram"
        or raw_offset < 0
        or not 1 <= pointer_size <= MAX_VARNODE_BYTES
        or raw_size != pointer_size
        or raw_offset >= 1 << (raw_size * 8)
        or not raw_address
        or bool(_api("CALL target constant classification", lambda: node.isConstant()))
        or _api("CALL target definition", lambda: node.getDef()) is not None
    ):
        raise ValueError("AFD CALL target classification is inconsistent")
    target_class = "external_opaque"
    library: str | None = None
    symbol: str | None = None
    function_entry = _api("CALL owner entry point", lambda: function.getEntryPoint())
    if function_entry is None:
        raise ValueError("AFD CALL owner entry point is absent")
    if address == function_entry:
        target_class = "self"
    else:
        manager = _api("Program function manager", lambda: program.getFunctionManager())
        if manager is None:
            raise ValueError("AFD Program function manager is absent")
        resolved = _api("FunctionManager getFunctionAt", lambda: manager.getFunctionAt(address))
        if resolved is not None and bool(
            _api("CALL target thunk classification", lambda: resolved.isThunk())
        ):
            resolved = _api(
                "CALL target thunk resolution", lambda: resolved.getThunkedFunction(True)
            )
        if resolved is not None and bool(
            _api("CALL target external classification", lambda: resolved.isExternal())
        ):
            location = _api("CALL target external location", lambda: resolved.getExternalLocation())
            if location is not None:
                raw_library = _api("external import library", lambda: location.getLibraryName())
                raw_symbol = _api(
                    "external import original name",
                    lambda: location.getOriginalImportedName(),
                )
                if not raw_symbol:
                    source = _api("external import source", lambda: location.getSource())
                    if source is not None and str(source).upper() == "IMPORTED":
                        raw_symbol = _api("external import label", lambda: location.getLabel())
                if raw_library and raw_symbol:
                    library = _token(str(raw_library), "CALL import library").casefold()
                    symbol = _token(str(raw_symbol), "CALL import symbol")
                    target_class = "external_import"
        if target_class != "external_import":
            memory = _api("Program memory", lambda: program.getMemory())
            if memory is None:
                raise ValueError("AFD Program memory is absent")
            block = _api("Program memory getBlock", lambda: memory.getBlock(address))
            target_class = "internal_image_opaque" if block is not None else "external_opaque"
    return {
        "kind": "call_target",
        "raw_space": raw_space,
        "raw_offset": raw_offset,
        "raw_size": raw_size,
        "raw_pointer_size": pointer_size,
        "raw_address": raw_address,
        "raw_constant": None,
        "raw_definition_op_key": None,
        "target_class": target_class,
        "library": library,
        "symbol": symbol,
    }


def _acquire_userop(node: Any, program: Any) -> dict[str, object]:
    selector = _acquire_varnode(node, program)
    userop_id, _row = _validate_selector(selector, "CALLOTHER userop")
    language = _api("Program language", lambda: program.getLanguage())
    if language is None:
        raise ValueError("AFD Program language is absent")
    name = _api("Language userop lookup", lambda: language.getUserDefinedOpName(userop_id))
    return {
        "kind": "userop",
        "selector": selector,
        "userop_id": userop_id,
        "userop_name": _token(str(name) if name is not None else None, "CALLOTHER userop name"),
    }


def _acquire_memory_space(node: Any, program: Any) -> dict[str, object]:
    selector = _acquire_varnode(node, program)
    space_id, _row = _validate_selector(selector, "memory-space")
    factory = _api("Program address factory", lambda: program.getAddressFactory())
    if factory is None:
        raise ValueError("AFD Program address factory is absent")
    space = _api("AddressFactory getAddressSpace", lambda: factory.getAddressSpace(space_id))
    if space is None:
        raise ValueError("AFD memory-space selector has no exact address space")
    actual_space_id = _api("memory-space getSpaceID", lambda: int(space.getSpaceID()))
    name = _api("memory-space name", lambda: space.getName())
    loaded = _api("memory-space loaded classification", lambda: space.isLoadedMemorySpace())
    overlay = _api("memory-space overlay classification", lambda: space.isOverlaySpace())
    physical = _api("memory-space physical space", lambda: space.getPhysicalSpace())
    default = _api("AddressFactory default address space", lambda: factory.getDefaultAddressSpace())
    if (
        actual_space_id != space_id
        or str(name).lower() != "ram"
        or not bool(loaded)
        or bool(overlay)
        or physical != space
        or default != space
    ):
        raise ValueError("AFD memory-space selector is not the reviewed physical default RAM")
    return {
        "kind": "memory_space",
        "selector": selector,
        "raw_space_id": space_id,
        "space": "ram",
    }


def _acquire_effect_op(node: Any, high_function: Any, program: Any) -> dict[str, object]:
    selector = _acquire_varnode(node, program)
    selector_id, _row = _validate_selector(selector, "INDIRECT effect-op")
    if selector_id > 0x7FFFFFFF:
        raise ValueError("AFD INDIRECT effect-op selector is not a nonnegative Java int")
    referenced = _api("HighFunction getOpRef", lambda: high_function.getOpRef(selector_id))
    if referenced is None:
        raise ValueError("AFD INDIRECT effect operation lookup returned no operation")
    sequence = _api("INDIRECT effect operation sequence", lambda: referenced.getSeqnum())
    if sequence is None:
        raise ValueError("AFD INDIRECT effect operation sequence is absent")
    sequence_time = _api("INDIRECT effect operation time", lambda: int(sequence.getTime()))
    if sequence_time != selector_id:
        raise ValueError("AFD INDIRECT effect operation time does not match its selector")
    return {
        "kind": "effect_op",
        "selector": selector,
        "raw_effect_op_key": str(sequence),
        "raw_effect_seq_time": sequence_time,
    }


def _api(label: str, callback: Any) -> Any:
    try:
        return callback()
    except Exception as exc:
        raise ValueError(f"AFD {label} API failed") from exc


def _acquire_branch_operand(
    node: Any,
    block_targets: dict[int, list[str]],
    *,
    allowed_targets: set[str],
    instruction_rva: int,
    pcode_order: int,
    image_base: int,
    image_max: int,
    instruction_ordinals: dict[int, int],
) -> dict[str, object]:
    raw_target, raw_offset = _acquire_varnode_snapshot(node, None, capture_opaque=False)
    if isinstance(raw_target, dict) and raw_target.get("storage_class") == "constant":
        signed_delta = _relative_branch_signed_delta(raw_target)
        return {
            "kind": "pcode_relative_target",
            "target": raw_target,
            "raw_signed_delta": signed_delta,
            "raw_instruction_rva": instruction_rva,
            "raw_pcode_order": pcode_order,
        }
    _validate_raw_branch_varnode(raw_target)
    if raw_offset is None:
        raise ValueError("AFD direct branch target offset is absent")
    candidates = [key for key in block_targets.get(raw_offset, []) if key in allowed_targets]
    if len(candidates) > 1:
        raise ValueError("AFD direct branch target block is structurally ambiguous")
    if candidates:
        return {
            "kind": "block_target",
            "raw_block_key": candidates[0],
            "target": raw_target,
        }
    if not image_base <= raw_offset < image_max:
        raise ValueError("AFD absolute branch target is outside the exact image")
    target_rva = raw_offset - image_base
    native_ordinal = instruction_ordinals.get(target_rva)
    if type(native_ordinal) is not int:
        raise ValueError(
            "AFD absolute branch target is neither an allowed CFG successor nor a retained "
            "native instruction"
        )
    raw_size = cast(dict[str, object], raw_target)["size"]
    expected_key = f"ram:{raw_offset:x}:{raw_size}:live"
    if cast(dict[str, object], raw_target)["key"] != expected_key:
        raise ValueError("AFD native instruction branch target key is inconsistent")
    return {
        "kind": "native_instruction_target",
        "target": raw_target,
        "raw_target_offset": raw_offset,
        "raw_target_rva": target_rva,
        "native_instruction_ordinal": native_ordinal,
    }


def _acquire_branch_target(
    node: Any,
    block_targets: dict[int, list[str]],
    *,
    allowed_targets: set[str],
) -> tuple[str, dict[str, object]]:
    raw_target, raw_offset = _acquire_varnode_snapshot(node, None, capture_opaque=False)
    _validate_raw_branch_varnode(raw_target)
    if raw_offset is None:
        raise ValueError("AFD direct branch target offset is absent")
    candidates = [key for key in block_targets.get(raw_offset, []) if key in allowed_targets]
    if len(candidates) != 1:
        raise ValueError("AFD direct branch target block is structurally ambiguous")
    return candidates[0], cast(dict[str, object], raw_target)


def _relative_branch_signed_delta(raw: object) -> int:
    if not isinstance(raw, dict) or set(raw) != {
        "key",
        "definition_op_key",
        "storage_class",
        "size",
        "constant",
        "address",
        "opaque_location",
    }:
        raise ValueError("AFD p-code-relative branch target varnode shape mismatch")
    key = _token(raw["key"], "p-code-relative branch target varnode key")
    size = raw["size"]
    constant = raw["constant"]
    if (
        raw["storage_class"] != "constant"
        or type(size) is not int
        or not 1 <= size <= MAX_VARNODE_BYTES
        or type(constant) is not int
        or constant < 0
        or constant >= 1 << (size * 8)
        or raw["address"] is not False
        or raw["definition_op_key"] is not None
        or raw["opaque_location"] is not None
    ):
        raise ValueError("AFD p-code-relative branch target classification is inconsistent")
    if key != f"const:{constant:x}:{size}:live":
        raise ValueError("AFD p-code-relative branch target key is inconsistent")
    sign_bit = 1 << (size * 8 - 1)
    modulus = 1 << (size * 8)
    return constant - modulus if constant & sign_bit else constant


def _validate_raw_relative_branch_target(
    raw: object,
    *,
    current_source_ref: dict[str, int],
) -> int:
    if (
        not isinstance(raw, dict)
        or set(raw)
        != {
            "kind",
            "target",
            "raw_signed_delta",
            "raw_instruction_rva",
            "raw_pcode_order",
        }
        or raw.get("kind") != "pcode_relative_target"
    ):
        raise ValueError("AFD p-code-relative branch target shape mismatch")
    signed_delta = _relative_branch_signed_delta(raw["target"])
    if (
        type(raw["raw_signed_delta"]) is not int
        or raw["raw_signed_delta"] != signed_delta
        or type(raw["raw_instruction_rva"]) is not int
        or raw["raw_instruction_rva"] != current_source_ref["instruction_rva"]
        or type(raw["raw_pcode_order"]) is not int
        or raw["raw_pcode_order"] != current_source_ref["pcode_order"]
    ):
        raise ValueError("AFD p-code-relative branch target provenance is inconsistent")
    return signed_delta


def _validate_raw_native_instruction_target(
    raw: object,
    *,
    image_min: int,
    image_max: int,
    native_instruction_count: int,
) -> int:
    if (
        not isinstance(raw, dict)
        or set(raw)
        != {
            "kind",
            "target",
            "raw_target_offset",
            "raw_target_rva",
            "native_instruction_ordinal",
        }
        or raw.get("kind") != "native_instruction_target"
    ):
        raise ValueError("AFD native instruction branch target shape mismatch")
    _validate_raw_branch_varnode(raw["target"])
    target = cast(dict[str, object], raw["target"])
    raw_offset = raw["raw_target_offset"]
    raw_rva = raw["raw_target_rva"]
    ordinal = raw["native_instruction_ordinal"]
    size = target["size"]
    if (
        type(raw_offset) is not int
        or not image_min <= raw_offset < image_max
        or type(raw_rva) is not int
        or raw_rva < 0
        or raw_offset != image_min + raw_rva
        or type(ordinal) is not int
        or not 0 <= ordinal < native_instruction_count
        or target["key"] != f"ram:{raw_offset:x}:{size}:live"
    ):
        raise ValueError("AFD native instruction branch target provenance is inconsistent")
    return ordinal


def _validate_raw_branch_varnode(raw: object) -> None:
    if not isinstance(raw, dict) or set(raw) != {
        "key",
        "definition_op_key",
        "storage_class",
        "size",
        "constant",
        "address",
        "opaque_location",
    }:
        raise ValueError("AFD direct branch target varnode shape mismatch")
    _token(raw["key"], "direct branch target varnode key")
    if (
        raw["storage_class"] != "ram"
        or type(raw["size"]) is not int
        or not 1 <= raw["size"] <= MAX_VARNODE_BYTES
        or raw["constant"] is not None
        or raw["address"] is not True
        or raw["definition_op_key"] is not None
        or raw["opaque_location"] is not None
    ):
        raise ValueError("AFD direct branch target varnode classification is inconsistent")


def _normalize_call_target(raw: object, *, expected_entry: int) -> dict[str, object]:
    if not isinstance(raw, dict) or set(raw) != {
        "kind",
        "raw_space",
        "raw_offset",
        "raw_size",
        "raw_pointer_size",
        "raw_address",
        "raw_constant",
        "raw_definition_op_key",
        "target_class",
        "library",
        "symbol",
    }:
        raise ValueError("AFD CALL target shape mismatch")
    target_class = _token(raw["target_class"], "CALL target class")
    if (
        raw["kind"] != "call_target"
        or raw["raw_space"] != "ram"
        or type(raw["raw_offset"]) is not int
        or raw["raw_offset"] < 0
        or type(raw["raw_size"]) is not int
        or type(raw["raw_pointer_size"]) is not int
        or not 1 <= raw["raw_pointer_size"] <= MAX_VARNODE_BYTES
        or raw["raw_size"] != raw["raw_pointer_size"]
        or raw["raw_offset"] >= 1 << (raw["raw_size"] * 8)
        or raw["raw_address"] is not True
        or raw["raw_constant"] is not None
        or raw["raw_definition_op_key"] is not None
        or target_class not in _CALL_TARGET_CLASSES
    ):
        raise ValueError("AFD CALL target classification is inconsistent")
    if (target_class == "self") != (raw["raw_offset"] == expected_entry):
        raise ValueError("AFD CALL self classification does not match the exact function entry")
    library = raw["library"]
    symbol = raw["symbol"]
    if target_class == "external_import":
        library = _token(library, "CALL import library").casefold()
        symbol = _token(symbol, "CALL import symbol")
    elif library is not None or symbol is not None:
        raise ValueError("AFD opaque/self CALL target cannot carry import identity")
    return {
        "kind": "call_target",
        "target_class": target_class,
        "library": library,
        "symbol": symbol,
    }


def _validate_selector(raw: object, label: str) -> tuple[int, dict[str, object]]:
    if not isinstance(raw, dict) or set(raw) != {
        "key",
        "definition_op_key",
        "storage_class",
        "size",
        "constant",
        "address",
        "opaque_location",
    }:
        raise ValueError(f"AFD {label} selector shape mismatch")
    _token(raw["key"], f"{label} selector key")
    selector = raw["constant"]
    if (
        raw["storage_class"] != "constant"
        or raw["size"] != 4
        or type(selector) is not int
        or not 0 <= selector <= 0xFFFFFFFF
        or raw["address"] is not False
        or raw["definition_op_key"] is not None
        or raw["opaque_location"] is not None
    ):
        raise ValueError(f"AFD {label} selector classification is inconsistent")
    return selector, raw


def _validate_raw_userop(raw: object) -> tuple[int, str]:
    if (
        not isinstance(raw, dict)
        or set(raw)
        != {
            "kind",
            "selector",
            "userop_id",
            "userop_name",
        }
        or raw.get("kind") != "userop"
    ):
        raise ValueError("AFD CALLOTHER userop shape mismatch")
    selector, _row = _validate_selector(raw["selector"], "CALLOTHER userop")
    userop_id = raw["userop_id"]
    if type(userop_id) is not int or userop_id != selector:
        raise ValueError("AFD CALLOTHER userop ID does not match its selector")
    name = _token(raw["userop_name"], "CALLOTHER userop name")
    return userop_id, name


def _validate_raw_memory_space(raw: object) -> None:
    if (
        not isinstance(raw, dict)
        or set(raw)
        != {
            "kind",
            "selector",
            "raw_space_id",
            "space",
        }
        or raw.get("kind") != "memory_space"
    ):
        raise ValueError("AFD memory-space operand shape mismatch")
    selector, _row = _validate_selector(raw["selector"], "memory-space")
    if (
        type(raw["raw_space_id"]) is not int
        or raw["raw_space_id"] != selector
        or raw["space"] != "ram"
    ):
        raise ValueError("AFD memory-space selector classification is inconsistent")


def _validate_raw_opaque_location(
    raw: object, *, storage: str, size: int, constant: object
) -> tuple[str, int, int, int]:
    if not isinstance(raw, dict) or set(raw) != {
        "raw_space",
        "raw_space_id",
        "raw_offset",
        "raw_size",
        "raw_address",
    }:
        raise ValueError("AFD opaque global location shape mismatch")
    if (
        raw["raw_space"] != "ram"
        or type(raw["raw_space_id"]) is not int
        or raw["raw_space_id"] < 0
        or type(raw["raw_offset"]) is not int
        or raw["raw_offset"] < 0
        or type(raw["raw_size"]) is not int
        or raw["raw_size"] != size
        or raw["raw_address"] is not True
        or storage != "ram"
        or constant is not None
    ):
        raise ValueError("AFD opaque global location classification is inconsistent")
    return "ram", raw["raw_space_id"], raw["raw_offset"], raw["raw_size"]


def _validate_raw_effect_op(
    raw: object,
    *,
    current_op_key: str,
    op_key_to_id: dict[str, str],
    op_key_to_seq_time: dict[str, int],
    seq_time_to_keys: dict[int, list[str]],
) -> str:
    if (
        not isinstance(raw, dict)
        or set(raw)
        != {
            "kind",
            "selector",
            "raw_effect_op_key",
            "raw_effect_seq_time",
        }
        or raw.get("kind") != "effect_op"
    ):
        raise ValueError("AFD INDIRECT effect-op shape mismatch")
    selector_raw = raw["selector"]
    selector, _row = _validate_selector(selector_raw, "INDIRECT effect-op")
    if selector > 0x7FFFFFFF:
        raise ValueError("AFD INDIRECT effect-op selector is not a nonnegative Java int")
    effect_key = _token(raw["raw_effect_op_key"], "INDIRECT effect operation")
    effect_time = raw["raw_effect_seq_time"]
    if (
        type(effect_time) is not int
        or effect_time != selector
        or effect_key == current_op_key
        or effect_key not in op_key_to_id
        or op_key_to_seq_time[effect_key] != selector
        or seq_time_to_keys.get(selector) != [effect_key]
    ):
        raise ValueError("AFD INDIRECT effect operation is missing, self, foreign, or mismatched")
    return effect_key


def _intern_varnode(
    raw: object,
    ids: dict[str, str],
    rows: dict[str, dict[str, object]],
    opaque_ids: dict[tuple[str, int, int, int], str],
    image_constant_ids: dict[tuple[int, int], str],
    op_key_to_id: dict[str, str],
    *,
    image_min: int,
    image_max: int,
) -> tuple[str, str, str | None]:
    if not isinstance(raw, dict) or set(raw) != {
        "key",
        "definition_op_key",
        "storage_class",
        "size",
        "constant",
        "address",
        "opaque_location",
    }:
        raise ValueError("AFD SSA varnode shape mismatch")
    key = _token(raw["key"], "varnode key")
    storage = _token(raw["storage_class"], "varnode storage class")
    size = raw["size"]
    constant = raw["constant"]
    address = raw["address"]
    definition_key = raw["definition_op_key"]
    opaque_raw = raw["opaque_location"]
    if type(size) is not int or not 1 <= size <= MAX_VARNODE_BYTES:
        raise ValueError("AFD SSA varnode size is invalid")
    if constant is not None and (type(constant) is not int or constant < 0):
        raise ValueError("AFD SSA constant is invalid")
    if (
        storage not in _STORAGE_CLASSES
        or type(address) is not bool
        or (storage == "constant") != (constant is not None)
    ):
        raise ValueError("AFD SSA constant/storage class mismatch")
    if constant is not None and constant >= 1 << (size * 8):
        raise ValueError("AFD SSA constant exceeds its declared width")
    image_constant_id = None
    if constant is not None and image_min <= constant < image_max:
        image_constant_key = (constant, size)
        if image_constant_key not in image_constant_ids:
            image_constant_ids[image_constant_key] = f"i{len(image_constant_ids)}"
        image_constant_id = image_constant_ids[image_constant_key]
    definition_id = None
    if definition_key is not None:
        definition_token = _token(definition_key, "varnode definition operation")
        if definition_token not in op_key_to_id:
            raise ValueError("AFD SSA varnode definition is outside the retained operation set")
        definition_id = op_key_to_id[definition_token]
    if constant is not None and definition_id is not None:
        raise ValueError("AFD SSA constant must not have a definition")
    opaque_id = None
    if address:
        location_key = _validate_raw_opaque_location(
            opaque_raw, storage=storage, size=size, constant=constant
        )
        if location_key not in opaque_ids:
            opaque_ids[location_key] = f"a{len(opaque_ids)}"
        opaque_id = opaque_ids[location_key]
    elif opaque_raw is not None:
        raise ValueError("AFD non-address SSA varnode has opaque location provenance")
    if image_constant_id is not None:
        key = f"image-constant:{image_constant_id}"
    elif constant is not None:
        key = f"constant:{size}:{constant}"
    elif definition_id is not None:
        key = f"definition:{definition_id}:{size}"
    elif opaque_id is not None:
        key = f"opaque-live:{opaque_id}:{size}"
    observation = {
        "storage_class": storage,
        "size": size,
        "constant": None if image_constant_id is not None else constant,
        "image_constant_id": image_constant_id,
        "definition_op_id": definition_id,
        "opaque_location_id": opaque_id,
    }
    if key in rows and {name: rows[key][name] for name in observation} != observation:
        raise ValueError("AFD SSA varnode identity has conflicting observations")
    if key not in ids:
        identifier = f"v{len(ids)}"
        ids[key] = identifier
        rows[key] = {"id": identifier, **observation}
    return key, ids[key], definition_id


def _storage_class(raw: str) -> str:
    normalized = raw.lower()
    if normalized not in _STORAGE_CLASSES - {"constant"}:
        raise ValueError("AFD SSA address space is outside the reviewed prototype")
    return normalized


def _source_ref(raw: object) -> dict[str, int]:
    if not isinstance(raw, dict) or set(raw) != {
        "function_rva",
        "instruction_rva",
        "instruction_ordinal",
        "seq_time",
        "pcode_order",
    }:
        raise ValueError("AFD High-P-Code source reference shape mismatch")
    if any(type(raw[name]) is not int or raw[name] < 0 for name in raw):
        raise ValueError("AFD High-P-Code source reference is invalid")
    return cast(dict[str, int], dict(raw))


def _token(raw: object, label: str) -> str:
    if not isinstance(raw, str) or not raw or len(raw) > 1024:
        raise ValueError(f"AFD {label} is invalid")
    return raw


def _token_list(raw: object, label: str) -> list[str]:
    if not isinstance(raw, list):
        raise ValueError(f"AFD {label} is invalid")
    return [_token(item, label) for item in raw]


def _canonical(raw: object) -> bytes:
    return json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
