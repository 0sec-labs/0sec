"""Pure custody binding for the complete two-side AFD CFG/SSA row set."""

from __future__ import annotations

import hashlib
import json
from typing import Any, cast

from . import windows_afd_handler_cfg_ssa_ghidra as ghidra_cfg
from . import windows_afd_handler_semantics as native_semantics

EXPORT_VERSION = "0verse.windows-afd-handler-cfg-ssa/v1"
ACQUISITION_VERSION = ghidra_cfg.SIDE_SCHEMA_VERSION
PRODUCER = "zeroverse.windows-afd-handler-cfg-ssa/v1"
EXPECTED_FUNCTIONS_PER_SIDE = 33
MAX_TOTAL_BLOCKS_PER_SIDE = EXPECTED_FUNCTIONS_PER_SIDE * ghidra_cfg.MAX_BLOCKS
MAX_TOTAL_OPS_PER_SIDE = EXPECTED_FUNCTIONS_PER_SIDE * ghidra_cfg.MAX_OPS
MAX_TOTAL_EDGES_PER_SIDE = EXPECTED_FUNCTIONS_PER_SIDE * ghidra_cfg.MAX_EDGES

_TRUE_CLAIMS = {
    "native_semantics_bound",
    "complete_function_set_bound",
    "complete_high_function_blocks_captured",
    "complete_high_pcode_ops_captured",
    "address_independent_fingerprints_compared",
    "factual_fingerprint_comparison_only",
    "human_promotion_gate",
}
_FALSE_CLAIMS = {
    "function_local_cfg_complete",
    "function_local_high_pcode_complete",
    "native_control_flow_complete",
    "cross_build_handler_identity_established",
    "handler_body_change_established",
    "cfg_semantic_equivalence_established",
    "cfg_semantic_difference_established",
    "ssa_semantic_equivalence_established",
    "ssa_semantic_difference_established",
    "semantic_equivalence_established",
    "semantic_difference_established",
    "source_sink_semantics_established",
    "guard_delta_established",
    "memory_alias_proof_established",
    "memory_ssa_established",
    "call_semantics_established",
    "call_graph_complete",
    "ranking_performed",
    "candidate_established",
    "labels_consumed",
    "ground_truth_consumed",
    "network_performed",
    "runtime_performed",
    "runtime_consumable",
    "execution_authorized",
    "runtime_reachability_established",
    "unprivileged_reachability_established",
    "crash_established",
    "vulnerability_established",
    "lpe_established",
    "exploitability_established",
    "novelty_established",
    "claim_eligible",
    "bounty_eligible",
    "weaponization",
    "automatic_disclosure",
}
_ZERO_COUNTS = {
    "candidate_count",
    "model_invocations",
    "network_attempts",
    "driver_load_attempts",
    "device_open_attempts",
    "device_ioctl_attempts",
    "runtime_attempts",
}
_PROOF_LIMIT = (
    "Exact native evidence commitments and complete bounded enumeration of retained Ghidra "
    "HighFunction blocks and High P-Code operations for the same 33 hypothesis rows on each "
    "side. This is not a complete native control-flow graph or semantic-completeness claim. "
    "Constants preserve unsigned declared-width bit patterns without establishing signedness "
    "semantics. Address-space offsets are width-normalized without establishing offset "
    "signedness semantics. P-Code-relative branches preserve only a signed delta and do not "
    "establish a resolved target or branch semantics. Image-bearing constants preserve only "
    "within-function alpha-renamed equality, not pointer semantics, target identity, or "
    "cross-build identity. "
    "Fingerprint equality is a factual equality "
    "under the committed address-independent normalization only. It establishes no handler "
    "identity, semantic equivalence or difference, source/sink flow, guard delta, ranking, "
    "candidate, vulnerability, LPE, exploitability, novelty, runtime reachability, claim or "
    "bounty eligibility."
)


def compile_windows_afd_handler_cfg_ssa(
    native_semantics_raw: object,
    side_a_facts_raw: object,
    side_b_facts_raw: object,
) -> dict[str, object]:
    """Bind 66 normalized function facts to one validated native artifact."""
    native = native_semantics._validate(native_semantics_raw)
    sides = cast(dict[str, Any], native["sides"])
    hypotheses_commitment = cast(dict[str, Any], native["hypotheses_commitment"])
    compiled_sides: dict[str, object] = {}
    for side, raw in (("side_a", side_a_facts_raw), ("side_b", side_b_facts_raw)):
        compiled_sides[side] = _compile_side(raw, side, sides[side])

    native_pairs = cast(list[dict[str, Any]], native["pairs"])
    left_functions = cast(dict[str, Any], compiled_sides["side_a"])["functions"]
    right_functions = cast(dict[str, Any], compiled_sides["side_b"])["functions"]
    pairs: list[dict[str, object]] = []
    for order, (native_pair, left, right) in enumerate(
        zip(native_pairs, left_functions, right_functions, strict=True), 1
    ):
        if (
            left["hypothesis_id"] != native_pair["hypothesis_id"]
            or right["hypothesis_id"] != native_pair["hypothesis_id"]
        ):
            raise ValueError("AFD CFG/SSA pair/native hypothesis binding mismatch")
        pair: dict[str, object] = {
            "enumeration_order": order,
            "native_pair_id": native_pair["pair_id"],
            "hypothesis_id": native_pair["hypothesis_id"],
            "side_a_function_id": left["function_id"],
            "side_b_function_id": right["function_id"],
            "image_address_independent_fingerprints_equal": left[
                "image_address_independent_fingerprint"
            ]
            == right["image_address_independent_fingerprint"],
            "factual_fingerprint_comparison_only": True,
        }
        pair["comparison_id"] = _domain_hash("0verse-afd-cfg-ssa-pair-v1", pair)
        pairs.append(pair)
    result: dict[str, object] = {
        "schema_version": EXPORT_VERSION,
        "producer": PRODUCER,
        "native_semantics_commitment": {
            "schema_version": native_semantics.EXPORT_VERSION,
            "artifact_sha256": _canonical_hash(native),
            "hypotheses_artifact_sha256": hypotheses_commitment["artifact_sha256"],
            "side_a_evidence_id": sides["side_a"]["evidence_id"],
            "side_b_evidence_id": sides["side_b"]["evidence_id"],
        },
        "sides": compiled_sides,
        "pair_count": EXPECTED_FUNCTIONS_PER_SIDE,
        "pairs": pairs,
        **dict.fromkeys(_TRUE_CLAIMS, True),
        **dict.fromkeys(_FALSE_CLAIMS, False),
        **dict.fromkeys(_ZERO_COUNTS, 0),
        "proof_limit": _PROOF_LIMIT,
    }
    return _validate(result)


def canonical_handler_cfg_ssa_bytes(raw: object) -> bytes:
    """Return exact canonical bytes after standalone structural validation."""
    return _canonical(_validate(raw)) + b"\n"


def _compile_side(raw: object, side: str, native_side: dict[str, Any]) -> dict[str, object]:
    value = _obj(raw, f"{side} CFG/SSA acquisition")
    _exact(
        value,
        {
            "schema_version",
            "producer",
            "side",
            "driver_sha256",
            "pdb_sha256",
            "image_base",
            "image_size",
            "architecture",
            "tool",
            "functions",
            "accounting",
            "static_only",
            "execution_authorized",
            "driver_load_attempts",
            "device_open_attempts",
            "device_ioctl_attempts",
            "runtime_attempts",
        },
        f"{side} CFG/SSA acquisition",
    )
    functions = value["functions"]
    if (
        value["schema_version"] != ACQUISITION_VERSION
        or value["producer"] != ghidra_cfg.SIDE_PRODUCER
        or value["side"] != side
        or value["driver_sha256"] != native_side["driver_sha256"]
        or value["pdb_sha256"] != native_side["pdb_sha256"]
        or value["image_base"] != native_side["image_base"]
        or value["architecture"] != "x86_64"
        or type(value["image_size"]) is not int
        or value["image_size"] <= 0
        or value["tool"] != native_side["tool"]
        or not isinstance(functions, list)
        or len(functions) != EXPECTED_FUNCTIONS_PER_SIDE
        or value["static_only"] is not True
        or value["execution_authorized"] is not False
        or any(
            type(value[name]) is not int or value[name] != 0
            for name in (
                "driver_load_attempts",
                "device_open_attempts",
                "device_ioctl_attempts",
                "runtime_attempts",
            )
        )
    ):
        raise ValueError("AFD CFG/SSA acquisition side contract mismatch")
    native_functions = cast(list[dict[str, Any]], native_side["functions"])
    rows: list[dict[str, object]] = []
    for order, (raw_function, native_function) in enumerate(
        zip(functions, native_functions, strict=True), 1
    ):
        acquired = _obj(raw_function, f"{side} CFG/SSA function {order}")
        _exact(
            acquired,
            {
                "enumeration_order",
                "hypothesis_id",
                "row_indices",
                "ioctl_keys",
                "entry_rva",
                "cfg_ssa",
            },
            "CFG/SSA function",
        )
        if (
            acquired["enumeration_order"] != order
            or acquired["hypothesis_id"] != native_function["hypothesis_id"]
            or acquired["row_indices"] != native_function["row_indices"]
            or acquired["ioctl_keys"] != native_function["ioctl_keys"]
            or acquired["entry_rva"] != native_function["entry_rva"]
        ):
            raise ValueError("AFD CFG/SSA function/native identity binding mismatch")
        cfg = _validate_cfg_ssa(acquired["cfg_ssa"], native_function=native_function)
        native_function_sha = _canonical_hash(native_function)
        row: dict[str, object] = {
            "enumeration_order": order,
            "native_evidence_id": native_side["evidence_id"],
            "hypothesis_id": native_function["hypothesis_id"],
            "entry_rva": native_function["entry_rva"],
            "native_function_sha256": native_function_sha,
            "native_body_addressed_sha256": native_function["body"]["addressed_sha256"],
            "native_instructions_sha256": _canonical_hash(native_function["instructions"]),
            "image_address_independent_fingerprint": cfg["image_address_independent_fingerprint"],
            "cfg_ssa": cfg,
        }
        row["function_id"] = _domain_hash("0verse-afd-cfg-ssa-function-v1", {"side": side, **row})
        rows.append(row)
    cfg_rows = [cast(dict[str, object], row["cfg_ssa"]) for row in rows]
    block_total = sum(cast(int, cfg["block_count"]) for cfg in cfg_rows)
    op_total = sum(cast(int, cfg["op_count"]) for cfg in cfg_rows)
    edge_total = sum(len(cast(list[object], cfg["edges"])) for cfg in cfg_rows)
    if (
        block_total > MAX_TOTAL_BLOCKS_PER_SIDE
        or op_total > MAX_TOTAL_OPS_PER_SIDE
        or edge_total > MAX_TOTAL_EDGES_PER_SIDE
    ):
        raise ValueError("AFD CFG/SSA side aggregate bound exceeded")
    acquisition_accounting = _obj(value["accounting"], "CFG/SSA acquisition accounting")
    if acquisition_accounting != {
        "functions_requested": EXPECTED_FUNCTIONS_PER_SIDE,
        "functions_observed": EXPECTED_FUNCTIONS_PER_SIDE,
        "blocks_total": block_total,
        "ops_total": op_total,
        "edges_total": edge_total,
        "limits_hit": [],
    }:
        raise ValueError("AFD CFG/SSA acquisition accounting mismatch")
    return {
        "side": side,
        "native_evidence_id": native_side["evidence_id"],
        "function_count": EXPECTED_FUNCTIONS_PER_SIDE,
        "functions": rows,
        "accounting": {
            "block_count_total": block_total,
            "op_count_total": op_total,
            "edge_count_total": edge_total,
            "limits_hit": [],
        },
    }


def _validate_cfg_ssa(
    raw: object, *, native_function: dict[str, Any] | None = None
) -> dict[str, object]:
    value = _obj(json.loads(json.dumps(raw)), "normalized CFG/SSA")
    projection_fields = {
        "entry_block_id",
        "blocks",
        "edges",
        "ops",
        "varnodes",
        "def_use_edges",
        "live_in_uses",
    }
    count_fields = {
        "block_count",
        "op_count",
        "direct_call_target_count",
        "indirect_call_count",
        "userop_count",
        "memory_load_count",
        "memory_store_count",
        "indirect_effect_count",
        "opaque_global_location_count",
        "opaque_global_varnode_count",
        "image_bearing_constant_location_count",
        "image_bearing_constant_varnode_count",
        "opaque_call_target_count",
        "candidate_count",
        "model_invocations",
        "network_attempts",
        "driver_load_attempts",
        "device_open_attempts",
        "device_ioctl_attempts",
        "runtime_attempts",
    }
    true_fields = {
        "opaque_global_locations_alpha_renamed",
        "indirect_effect_refs_preserved",
        "call_targets_preserved",
        "userops_preserved",
        "memory_operations_preserved",
        "complete_high_function_blocks",
        "complete_high_pcode_ops",
        "all_ops_parent_bound",
        "cfg_predecessor_successor_closure",
        "exact_source_refs_captured",
        "address_independent_encoding_applied",
        "constant_bit_patterns_width_normalized",
        "address_space_offsets_width_normalized",
        "image_bearing_constants_alpha_renamed",
    }
    false_fields = {
        "normalization_lossless",
        "constant_signedness_semantics_established",
        "address_space_offset_signedness_semantics_established",
        "image_bearing_constant_pointer_semantics_established",
        "image_bearing_constant_target_identity_established",
        "cross_build_image_bearing_constant_identity_established",
        "opaque_global_identity_semantics_established",
        "global_symbol_identity_established",
        "cross_build_global_identity_established",
        "indirect_effect_semantics_established",
        "cfg_semantic_equivalence_established",
        "cfg_semantic_difference_established",
        "ssa_semantic_equivalence_established",
        "ssa_semantic_difference_established",
        "semantic_equivalence_established",
        "semantic_difference_established",
        "source_sink_semantics_established",
        "guard_delta_established",
        "memory_alias_proof_established",
        "memory_ssa_established",
        "call_semantics_established",
        "userop_semantics_established",
        "call_graph_complete",
        "cross_build_handler_identity_established",
        "handler_body_change_established",
        "servicing_lineage_established",
        "servicing_adjacency_established",
        "vulnerable_fixed_roles_established",
        "patch_causality_established",
        "ranking_performed",
        "candidate_established",
        "labels_consumed",
        "ground_truth_consumed",
        "network_performed",
        "runtime_performed",
        "runtime_consumable",
        "execution_authorized",
        "runtime_reachability_established",
        "unprivileged_reachability_established",
        "crash_established",
        "vulnerability_established",
        "lpe_established",
        "exploitability_established",
        "novelty_established",
        "claim_eligible",
        "bounty_eligible",
        "weaponization",
        "automatic_disclosure",
    }
    count_fields.update(
        {
            "pcode_relative_branch_delta_count",
            "native_instruction_branch_target_count",
        }
    )
    true_fields.update(
        {
            "pcode_relative_branch_deltas_preserved",
            "native_instruction_branch_targets_preserved",
        }
    )
    false_fields.update(
        {
            "pcode_relative_branch_semantics_established",
            "pcode_relative_branch_target_resolution_established",
            "native_instruction_branch_semantics_established",
            "high_function_cfg_covers_all_native_branch_targets",
        }
    )
    expected = {
        "schema_version",
        "producer",
        "image_address_independent_fingerprint",
        *projection_fields,
        *count_fields,
        *true_fields,
        *false_fields,
    }
    _exact(value, expected, "normalized CFG/SSA")
    if (
        value["schema_version"] != ghidra_cfg.SCHEMA_VERSION
        or value["producer"] != ghidra_cfg.PRODUCER
    ):
        raise ValueError("AFD normalized CFG/SSA version mismatch")
    if any(value[name] is not True for name in true_fields) or any(
        value[name] is not False for name in false_fields
    ):
        raise ValueError("AFD normalized CFG/SSA claim boundary mismatch")
    for name in count_fields:
        if type(value[name]) is not int or value[name] < 0:
            raise ValueError("AFD normalized CFG/SSA counter mismatch")
    for name in count_fields & _ZERO_COUNTS:
        if value[name] != 0:
            raise ValueError("AFD normalized CFG/SSA zero counter mismatch")
    blocks = _list_of_objects(value["blocks"], "CFG blocks")
    ops = _list_of_objects(value["ops"], "CFG operations")
    edges = _list_of_objects(value["edges"], "CFG edges")
    if not 1 <= len(blocks) <= ghidra_cfg.MAX_BLOCKS or not 1 <= len(ops) <= ghidra_cfg.MAX_OPS:
        raise ValueError("AFD normalized CFG/SSA function bound mismatch")
    if (
        len(edges) > ghidra_cfg.MAX_EDGES
        or value["block_count"] != len(blocks)
        or value["op_count"] != len(ops)
    ):
        raise ValueError("AFD normalized CFG/SSA accounting mismatch")
    block_ids = []
    block_rows: dict[str, dict[str, Any]] = {}
    expected_edges: list[dict[str, object]] = []
    for index, block in enumerate(blocks):
        _exact(block, {"id", "predecessors", "successors"}, "CFG block")
        if block["id"] != f"b{index}":
            raise ValueError("AFD normalized CFG block identity mismatch")
        predecessors = _id_list(block["predecessors"], "block predecessor")
        successors = _id_list(block["successors"], "block successor")
        if len(predecessors) != len(set(predecessors)) or len(successors) != len(set(successors)):
            raise ValueError("AFD normalized CFG edge multiplicity mismatch")
        block_ids.append(block["id"])
        block_rows[block["id"]] = block
        expected_edges.extend({"source": block["id"], "target": target} for target in successors)
    entry = value["entry_block_id"]
    if (
        entry not in block_ids
        or block_rows[entry]["predecessors"] != []
        or sum(row["predecessors"] == [] for row in blocks) != 1
        or edges != expected_edges
    ):
        raise ValueError("AFD normalized CFG edge projection mismatch")
    for edge in edges:
        _exact(edge, {"source", "target"}, "CFG edge")
        if edge["source"] not in block_ids or edge["target"] not in block_ids:
            raise ValueError("AFD normalized CFG edge closure mismatch")
        if edge["source"] not in block_rows[edge["target"]]["predecessors"]:
            raise ValueError("AFD normalized CFG predecessor closure mismatch")
    for block_id, block in block_rows.items():
        for predecessor in block["predecessors"]:
            if (
                predecessor not in block_rows
                or block_id not in block_rows[predecessor]["successors"]
            ):
                raise ValueError("AFD normalized CFG predecessor/successor closure mismatch")
    reachable = {entry}
    pending = [entry]
    while pending:
        current = pending.pop()
        for successor in block_rows[current]["successors"]:
            if successor not in reachable:
                reachable.add(successor)
                pending.append(successor)
    if reachable != set(block_ids):
        raise ValueError("AFD normalized CFG contains unreachable blocks")
    op_ids: set[str] = set()
    op_parents: set[str] = set()
    source_sites: set[tuple[int, int]] = set()
    local_orders: dict[int, int] = {}
    native_rvas = None
    expected_function_rva = None
    if native_function is not None:
        native_rvas = [int(item["rva"], 16) for item in native_function["instructions"]]
        expected_function_rva = int(native_function["entry_rva"], 16)
    for op in ops:
        if set(op) != {"id", "block_id", "opcode", "source_ref", "output", "operands"}:
            raise ValueError("AFD normalized operation shape mismatch")
        if not isinstance(op["id"], str) or op["id"] in op_ids or op["block_id"] not in block_ids:
            raise ValueError("AFD normalized operation identity mismatch")
        op_ids.add(op["id"])
        op_parents.add(op["block_id"])
        source = _obj(op["source_ref"], "operation source reference")
        _exact(
            source,
            {"function_rva", "instruction_rva", "instruction_ordinal", "seq_time", "pcode_order"},
            "operation source reference",
        )
        if any(type(source[name]) is not int or source[name] < 0 for name in source):
            raise ValueError("AFD normalized operation source reference mismatch")
        site = (source["instruction_ordinal"], source["seq_time"])
        local_order = local_orders.get(source["instruction_ordinal"], 0)
        local_orders[source["instruction_ordinal"]] = local_order + 1
        if site in source_sites or op["id"] != f"o{source['instruction_ordinal']}_{local_order}":
            raise ValueError("AFD normalized operation site/identity mismatch")
        source_sites.add(site)
        if native_rvas is not None and (
            source["function_rva"] != expected_function_rva
            or source["instruction_ordinal"] >= len(native_rvas)
            or native_rvas[source["instruction_ordinal"]] != source["instruction_rva"]
        ):
            raise ValueError("AFD CFG/SSA source/native instruction binding mismatch")
        if op["output"] is not None:
            output = _obj(op["output"], "operation output")
            _exact(output, {"kind", "varnode_id"}, "operation output")
            if output["kind"] != "value":
                raise ValueError("AFD normalized operation output mismatch")
        if (
            not isinstance(op["operands"], list)
            or len(op["operands"]) > ghidra_cfg.MAX_INPUTS_PER_OP
        ):
            raise ValueError("AFD normalized operation operand bound mismatch")
    if op_parents != set(block_ids):
        raise ValueError("AFD normalized CFG block lacks a retained operation")
    varnodes = _list_of_objects(value["varnodes"], "CFG varnodes")
    varnode_ids = {row.get("id") for row in varnodes}
    if len(varnode_ids) != len(varnodes) or None in varnode_ids:
        raise ValueError("AFD normalized varnode identity mismatch")
    varnode_rows: dict[str, dict[str, Any]] = {}
    opaque_locations: list[str] = []
    opaque_location_sizes: dict[str, int] = {}
    for index, row in enumerate(varnodes):
        _exact(
            row,
            {
                "id",
                "storage_class",
                "size",
                "constant",
                "definition_op_id",
                "opaque_location_id",
                "image_constant_id",
            },
            "CFG varnode",
        )
        if (
            row["id"] != f"v{index}"
            or row["storage_class"]
            not in {"constant", "join", "ram", "register", "stack", "unique"}
            or type(row["size"]) is not int
            or not 1 <= row["size"] <= ghidra_cfg.MAX_VARNODE_BYTES
            or (
                row["constant"] is not None
                and (type(row["constant"]) is not int or row["constant"] < 0)
            )
            or (row["definition_op_id"] is not None and row["definition_op_id"] not in op_ids)
        ):
            raise ValueError("AFD normalized varnode observation mismatch")
        image_constant_id = row["image_constant_id"]
        if image_constant_id is not None and (
            not isinstance(image_constant_id, str)
            or row["storage_class"] != "constant"
            or row["constant"] is not None
            or row["definition_op_id"] is not None
            or row["opaque_location_id"] is not None
        ):
            raise ValueError("AFD normalized image-bearing constant varnode mismatch")
        if row["constant"] is not None and (
            row["storage_class"] != "constant"
            or row["definition_op_id"] is not None
            or image_constant_id is not None
            or row["constant"] >= 1 << (row["size"] * 8)
        ):
            raise ValueError("AFD normalized constant varnode mismatch")
        if row["storage_class"] == "constant" and (
            (row["constant"] is None) == (image_constant_id is None)
        ):
            raise ValueError("AFD normalized constant classification mismatch")
        if row["storage_class"] != "constant" and image_constant_id is not None:
            raise ValueError("AFD normalized image-bearing constant storage mismatch")
        opaque = row["opaque_location_id"]
        if opaque is not None:
            if (
                not isinstance(opaque, str)
                or row["storage_class"] != "ram"
                or row["constant"] is not None
                or image_constant_id is not None
            ):
                raise ValueError("AFD normalized opaque location identity mismatch")
            if opaque not in opaque_locations:
                if opaque != f"a{len(opaque_locations)}":
                    raise ValueError("AFD normalized opaque location namespace mismatch")
                opaque_locations.append(opaque)
                opaque_location_sizes[opaque] = row["size"]
            elif opaque_location_sizes[opaque] != row["size"]:
                raise ValueError("AFD normalized opaque location width mismatch")
        varnode_rows[row["id"]] = row
    image_constant_ids: list[str] = []
    for row in varnodes:
        image_constant_id = row["image_constant_id"]
        if image_constant_id is not None and image_constant_id not in image_constant_ids:
            if image_constant_id != f"i{len(image_constant_ids)}":
                raise ValueError("AFD normalized image-bearing constant namespace mismatch")
            image_constant_ids.append(image_constant_id)

    expected_def_use: list[dict[str, object]] = []
    expected_live: list[dict[str, object]] = []
    direct_calls = indirect_calls = userops = loads = stores = indirects = opaque_calls = 0
    relative_deltas = 0
    native_instruction_targets = 0
    userop_names: dict[int, str] = {}
    userop_ids: dict[str, int] = {}
    defined_outputs: set[str] = set()
    for op in ops:
        output = op["output"]
        if output is not None:
            output_id = output["varnode_id"]
            if (
                output_id not in varnode_rows
                or varnode_rows[output_id]["definition_op_id"] != op["id"]
                or output_id in defined_outputs
            ):
                raise ValueError("AFD normalized operation/SSA output binding mismatch")
            defined_outputs.add(output_id)
        opcode = op["opcode"]
        if not isinstance(opcode, str) or not opcode:
            raise ValueError("AFD normalized operation opcode mismatch")
        indirect_calls += opcode == "CALLIND"
        loads += opcode == "LOAD"
        stores += opcode == "STORE"
        indirects += opcode == "INDIRECT"
        operand_kinds: list[object] = []
        for operand_index, operand_raw in enumerate(op["operands"]):
            operand = _obj(operand_raw, "normalized operation operand")
            kind = operand.get("kind")
            operand_kinds.append(kind)
            if kind == "value":
                _exact(operand, {"kind", "varnode_id"}, "value operand")
            elif kind == "phi_value":
                _exact(operand, {"kind", "block_id", "varnode_id"}, "PHI operand")
                if operand["block_id"] not in block_ids:
                    raise ValueError("AFD normalized PHI predecessor mismatch")
            elif kind == "block_target":
                _exact(operand, {"kind", "block_id"}, "block target operand")
                if operand["block_id"] not in block_ids:
                    raise ValueError("AFD normalized branch target mismatch")
                continue
            elif kind == "pcode_relative_delta_target":
                _exact(
                    operand,
                    {"kind", "signed_delta"},
                    "P-Code-relative delta operand",
                )
                signed_delta = operand["signed_delta"]
                signed_limit = 1 << (ghidra_cfg.MAX_VARNODE_BYTES * 8 - 1)
                if (
                    type(signed_delta) is not int
                    or not -signed_limit <= signed_delta < signed_limit
                ):
                    raise ValueError("AFD normalized P-Code-relative delta mismatch")
                relative_deltas += 1
                continue
            elif kind == "native_instruction_target":
                _exact(
                    operand,
                    {"kind", "native_instruction_ordinal"},
                    "native-instruction target operand",
                )
                ordinal = operand["native_instruction_ordinal"]
                if type(ordinal) is not int or ordinal < 0:
                    raise ValueError("AFD normalized native-instruction target mismatch")
                if native_rvas is not None and ordinal >= len(native_rvas):
                    raise ValueError(
                        "AFD CFG/SSA native-instruction target is outside native evidence"
                    )
                native_instruction_targets += 1
                continue
            elif kind == "call_target":
                _exact(
                    operand,
                    {"kind", "target_class", "library", "symbol"},
                    "call target operand",
                )
                target_class = operand["target_class"]
                library = operand["library"]
                symbol = operand["symbol"]
                if target_class not in {
                    "self",
                    "external_import",
                    "internal_image_opaque",
                    "external_opaque",
                }:
                    raise ValueError("AFD normalized call target mismatch")
                if target_class == "external_import":
                    if (
                        not isinstance(library, str)
                        or not 1 <= len(library) <= 1024
                        or library != library.casefold()
                        or not isinstance(symbol, str)
                        or not 1 <= len(symbol) <= 1024
                        or _looks_address_like(library)
                        or _looks_address_like(symbol)
                    ):
                        raise ValueError("AFD normalized external import identity mismatch")
                elif library is not None or symbol is not None:
                    raise ValueError("AFD normalized opaque/self call target leaked identity")
                direct_calls += 1
                opaque_calls += target_class in {
                    "internal_image_opaque",
                    "external_opaque",
                }
                continue
            elif kind == "userop":
                _exact(operand, {"kind", "userop_id", "userop_name"}, "userop operand")
                if (
                    type(operand["userop_id"]) is not int
                    or operand["userop_id"] < 0
                    or not isinstance(operand["userop_name"], str)
                    or not operand["userop_name"]
                    or userop_names.get(operand["userop_id"], operand["userop_name"])
                    != operand["userop_name"]
                    or userop_ids.get(operand["userop_name"], operand["userop_id"])
                    != operand["userop_id"]
                ):
                    raise ValueError("AFD normalized userop identity mismatch")
                userop_names[operand["userop_id"]] = operand["userop_name"]
                userop_ids[operand["userop_name"]] = operand["userop_id"]
                userops += 1
                continue
            elif kind == "memory_space":
                _exact(operand, {"kind", "space"}, "memory-space operand")
                if operand["space"] != "ram":
                    raise ValueError("AFD normalized memory-space mismatch")
                continue
            elif kind == "effect_op":
                _exact(operand, {"kind", "op_id"}, "effect-operation operand")
                if operand["op_id"] not in op_ids or operand["op_id"] == op["id"]:
                    raise ValueError("AFD normalized effect-operation reference mismatch")
                continue
            else:
                raise ValueError("AFD normalized operation operand shape mismatch")
            varnode_id = operand["varnode_id"]
            if varnode_id not in varnode_rows:
                raise ValueError("AFD normalized operand varnode closure mismatch")
            edge = {
                "varnode_id": varnode_id,
                "use_op_id": op["id"],
                "operand_index": operand_index,
            }
            definition = varnode_rows[varnode_id]["definition_op_id"]
            if definition is None:
                expected_live.append(edge)
            else:
                expected_def_use.append({"def_op_id": definition, **edge})
        target_kinds = {
            "block_target",
            "pcode_relative_delta_target",
            "native_instruction_target",
        }
        if opcode == "BRANCH":
            if len(operand_kinds) != 1 or operand_kinds[0] not in target_kinds:
                raise ValueError("AFD normalized BRANCH operand matrix mismatch")
            if operand_kinds[0] == "block_target":
                target = op["operands"][0]["block_id"]
                if block_rows[op["block_id"]]["successors"] != [target]:
                    raise ValueError("AFD normalized BRANCH target/successor closure mismatch")
        elif opcode == "CBRANCH":
            if (
                len(operand_kinds) != 2
                or operand_kinds[0] not in target_kinds
                or operand_kinds[1] != "value"
            ):
                raise ValueError("AFD normalized CBRANCH operand matrix mismatch")
            if operand_kinds[0] == "block_target":
                target = op["operands"][0]["block_id"]
                successors = block_rows[op["block_id"]]["successors"]
                if len(successors) != 2 or target not in successors:
                    raise ValueError("AFD normalized CBRANCH target/successor closure mismatch")
        elif opcode == "CALL":
            if (
                not operand_kinds
                or operand_kinds[0] != "call_target"
                or any(kind != "value" for kind in operand_kinds[1:])
            ):
                raise ValueError("AFD normalized CALL operand matrix mismatch")
        elif opcode == "CALLIND":
            if not operand_kinds or any(kind != "value" for kind in operand_kinds):
                raise ValueError("AFD normalized CALLIND operand matrix mismatch")
            target_id = op["operands"][0]["varnode_id"]
            if varnode_rows[target_id]["opaque_location_id"] is not None:
                raise ValueError("AFD normalized CALLIND opaque target mismatch")
        elif opcode == "CALLOTHER":
            if (
                not operand_kinds
                or operand_kinds[0] != "userop"
                or any(kind != "value" for kind in operand_kinds[1:])
            ):
                raise ValueError("AFD normalized CALLOTHER operand matrix mismatch")
        elif opcode == "LOAD":
            if operand_kinds != ["memory_space", "value"] or output is None:
                raise ValueError("AFD normalized LOAD operand matrix mismatch")
        elif opcode == "STORE":
            if operand_kinds != ["memory_space", "value", "value"] or output is not None:
                raise ValueError("AFD normalized STORE operand matrix mismatch")
        elif opcode == "INDIRECT":
            if operand_kinds != ["value", "effect_op"] or output is None:
                raise ValueError("AFD normalized INDIRECT operand matrix mismatch")
            input_id = op["operands"][0]["varnode_id"]
            if varnode_rows[input_id]["size"] != varnode_rows[output["varnode_id"]]["size"]:
                raise ValueError("AFD normalized INDIRECT width mismatch")
        elif opcode == "MULTIEQUAL":
            if output is None or any(kind != "phi_value" for kind in operand_kinds):
                raise ValueError("AFD normalized MULTIEQUAL operand matrix mismatch")
            if [operand["block_id"] for operand in op["operands"]] != block_rows[op["block_id"]][
                "predecessors"
            ]:
                raise ValueError("AFD normalized MULTIEQUAL predecessor mismatch")
        elif any(
            kind
            in {
                "phi_value",
                "block_target",
                "pcode_relative_delta_target",
                "native_instruction_target",
                "call_target",
                "userop",
                "memory_space",
                "effect_op",
            }
            for kind in operand_kinds
        ):
            raise ValueError("AFD normalized opcode contains forbidden metadata operand")
    if defined_outputs != {row["id"] for row in varnodes if row["definition_op_id"] is not None}:
        raise ValueError("AFD normalized SSA definition closure mismatch")
    if value["def_use_edges"] != expected_def_use or value["live_in_uses"] != expected_live:
        raise ValueError("AFD normalized SSA edge recomputation mismatch")
    expected_counts = {
        "direct_call_target_count": direct_calls,
        "indirect_call_count": indirect_calls,
        "userop_count": userops,
        "memory_load_count": loads,
        "memory_store_count": stores,
        "indirect_effect_count": indirects,
        "opaque_global_location_count": len(opaque_locations),
        "opaque_global_varnode_count": sum(
            row["opaque_location_id"] is not None for row in varnodes
        ),
        "image_bearing_constant_location_count": len(image_constant_ids),
        "image_bearing_constant_varnode_count": sum(
            row["image_constant_id"] is not None for row in varnodes
        ),
        "opaque_call_target_count": opaque_calls,
    }
    expected_counts["pcode_relative_branch_delta_count"] = relative_deltas
    expected_counts["native_instruction_branch_target_count"] = native_instruction_targets
    if any(value[name] != count for name, count in expected_counts.items()):
        raise ValueError("AFD normalized CFG/SSA factual counter mismatch")
    projection = {
        "entry_block_id": value["entry_block_id"],
        "blocks": blocks,
        "edges": edges,
        "ops": [{key: item for key, item in op.items() if key != "source_ref"} for op in ops],
        "varnodes": varnodes,
        "def_use_edges": value["def_use_edges"],
        "live_in_uses": value["live_in_uses"],
    }
    if _canonical_hash(projection) != value["image_address_independent_fingerprint"]:
        raise ValueError("AFD normalized CFG/SSA fingerprint recomputation mismatch")
    return cast(dict[str, object], json.loads(json.dumps(value, sort_keys=True)))


def _validate(raw: object) -> dict[str, object]:
    value = _obj(json.loads(json.dumps(raw)), "AFD CFG/SSA artifact")
    fields = {
        "schema_version",
        "producer",
        "native_semantics_commitment",
        "sides",
        "pair_count",
        "pairs",
        "proof_limit",
        *_TRUE_CLAIMS,
        *_FALSE_CLAIMS,
        *_ZERO_COUNTS,
    }
    _exact(value, fields, "AFD CFG/SSA artifact")
    if (
        value["schema_version"] != EXPORT_VERSION
        or value["producer"] != PRODUCER
        or value["proof_limit"] != _PROOF_LIMIT
        or type(value["pair_count"]) is not int
        or value["pair_count"] != EXPECTED_FUNCTIONS_PER_SIDE
        or any(value[name] is not True for name in _TRUE_CLAIMS)
        or any(value[name] is not False for name in _FALSE_CLAIMS)
        or any(type(value[name]) is not int or value[name] != 0 for name in _ZERO_COUNTS)
    ):
        raise ValueError("AFD CFG/SSA artifact contract mismatch")
    commitment = _obj(value["native_semantics_commitment"], "native semantics commitment")
    _exact(
        commitment,
        {
            "schema_version",
            "artifact_sha256",
            "hypotheses_artifact_sha256",
            "side_a_evidence_id",
            "side_b_evidence_id",
        },
        "native semantics commitment",
    )
    if commitment["schema_version"] != native_semantics.EXPORT_VERSION:
        raise ValueError("AFD CFG/SSA native semantics version mismatch")
    for name in set(commitment) - {"schema_version"}:
        _sha(commitment[name], name)
    sides = _obj(value["sides"], "CFG/SSA sides")
    _exact(sides, {"side_a", "side_b"}, "CFG/SSA sides")
    side_rows: dict[str, list[dict[str, Any]]] = {}
    for side in ("side_a", "side_b"):
        side_value = _obj(sides[side], side)
        _exact(
            side_value,
            {"side", "native_evidence_id", "function_count", "functions", "accounting"},
            side,
        )
        functions = _list_of_objects(side_value["functions"], f"{side} functions")
        if (
            side_value["side"] != side
            or side_value["native_evidence_id"] != commitment[f"{side}_evidence_id"]
            or type(side_value["function_count"]) is not int
            or side_value["function_count"] != EXPECTED_FUNCTIONS_PER_SIDE
            or len(functions) != EXPECTED_FUNCTIONS_PER_SIDE
        ):
            raise ValueError("AFD CFG/SSA side contract mismatch")
        block_total = op_total = edge_total = 0
        for order, row in enumerate(functions, 1):
            _exact(
                row,
                {
                    "enumeration_order",
                    "function_id",
                    "native_evidence_id",
                    "hypothesis_id",
                    "entry_rva",
                    "native_function_sha256",
                    "native_body_addressed_sha256",
                    "native_instructions_sha256",
                    "image_address_independent_fingerprint",
                    "cfg_ssa",
                },
                "CFG/SSA function",
            )
            if (
                row["enumeration_order"] != order
                or row["native_evidence_id"] != side_value["native_evidence_id"]
                or not isinstance(row["hypothesis_id"], str)
                or not row["hypothesis_id"]
            ):
                raise ValueError("AFD CFG/SSA function order/evidence binding mismatch")
            _canonical_hex(row["entry_rva"], "CFG/SSA function entry RVA")
            for name in (
                "native_function_sha256",
                "native_body_addressed_sha256",
                "native_instructions_sha256",
                "image_address_independent_fingerprint",
                "function_id",
            ):
                _sha(row[name], name)
            cfg = _validate_cfg_ssa(row["cfg_ssa"])
            if (
                cfg["image_address_independent_fingerprint"]
                != row["image_address_independent_fingerprint"]
            ):
                raise ValueError("AFD CFG/SSA function fingerprint binding mismatch")
            material = dict(row)
            function_id = material.pop("function_id")
            if function_id != _domain_hash(
                "0verse-afd-cfg-ssa-function-v1", {"side": side, **material}
            ):
                raise ValueError("AFD CFG/SSA function identity mismatch")
            block_total += cast(int, cfg["block_count"])
            op_total += cast(int, cfg["op_count"])
            edge_total += len(cast(list[object], cfg["edges"]))
        accounting = _obj(side_value["accounting"], "CFG/SSA accounting")
        expected_accounting = {
            "block_count_total": block_total,
            "op_count_total": op_total,
            "edge_count_total": edge_total,
            "limits_hit": [],
        }
        if (
            accounting != expected_accounting
            or block_total > MAX_TOTAL_BLOCKS_PER_SIDE
            or op_total > MAX_TOTAL_OPS_PER_SIDE
            or edge_total > MAX_TOTAL_EDGES_PER_SIDE
        ):
            raise ValueError("AFD CFG/SSA aggregate accounting mismatch")
        side_rows[side] = functions
    pairs = _list_of_objects(value["pairs"], "CFG/SSA pairs")
    if len(pairs) != EXPECTED_FUNCTIONS_PER_SIDE:
        raise ValueError("AFD CFG/SSA pair extent mismatch")
    for order, pair in enumerate(pairs, 1):
        _exact(
            pair,
            {
                "enumeration_order",
                "comparison_id",
                "native_pair_id",
                "hypothesis_id",
                "side_a_function_id",
                "side_b_function_id",
                "image_address_independent_fingerprints_equal",
                "factual_fingerprint_comparison_only",
            },
            "CFG/SSA pair",
        )
        left, right = side_rows["side_a"][order - 1], side_rows["side_b"][order - 1]
        comparison_material = dict(pair)
        comparison_id = comparison_material.pop("comparison_id")
        if (
            pair["enumeration_order"] != order
            or pair["hypothesis_id"] != left["hypothesis_id"]
            or pair["hypothesis_id"] != right["hypothesis_id"]
            or pair["side_a_function_id"] != left["function_id"]
            or pair["side_b_function_id"] != right["function_id"]
            or pair["factual_fingerprint_comparison_only"] is not True
            or type(pair["image_address_independent_fingerprints_equal"]) is not bool
            or pair["image_address_independent_fingerprints_equal"]
            != (
                left["image_address_independent_fingerprint"]
                == right["image_address_independent_fingerprint"]
            )
        ):
            raise ValueError("AFD CFG/SSA pair comparison mismatch")
        if comparison_id != _domain_hash("0verse-afd-cfg-ssa-pair-v1", comparison_material):
            raise ValueError("AFD CFG/SSA pair identity mismatch")
        _sha(comparison_id, "comparison ID")
        _sha(pair["native_pair_id"], "native pair ID")
    return cast(dict[str, object], json.loads(json.dumps(value, sort_keys=True)))


def _obj(raw: object, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError(f"AFD {label} must be an object")
    return cast(dict[str, Any], raw)


def _list_of_objects(raw: object, label: str) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or any(not isinstance(item, dict) for item in raw):
        raise ValueError(f"AFD {label} must be an object list")
    return cast(list[dict[str, Any]], raw)


def _exact(raw: dict[str, Any], fields: set[str], label: str) -> None:
    if set(raw) != fields:
        raise ValueError(f"AFD {label} shape mismatch")


def _id_list(raw: object, label: str) -> list[str]:
    if not isinstance(raw, list) or any(not isinstance(item, str) or not item for item in raw):
        raise ValueError(f"AFD {label} list mismatch")
    return cast(list[str], raw)


def _sha(raw: object, label: str) -> str:
    if not isinstance(raw, str) or len(raw) != 64:
        raise ValueError(f"AFD {label} SHA-256 mismatch")
    try:
        int(raw, 16)
    except ValueError as error:
        raise ValueError(f"AFD {label} SHA-256 mismatch") from error
    return raw


def _canonical_hex(raw: object, label: str) -> int:
    if not isinstance(raw, str) or not raw.startswith("0x"):
        raise ValueError(f"AFD {label} hexadecimal mismatch")
    try:
        value = int(raw, 16)
    except ValueError as error:
        raise ValueError(f"AFD {label} hexadecimal mismatch") from error
    if value < 0 or raw != f"0x{value:x}":
        raise ValueError(f"AFD {label} hexadecimal mismatch")
    return value


def _looks_address_like(raw: str) -> bool:
    if not raw.casefold().startswith("0x") or len(raw) <= 2:
        return False
    return all(character in "0123456789abcdef" for character in raw[2:].casefold())


def _canonical(raw: object) -> bytes:
    return json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()


def _canonical_hash(raw: object) -> str:
    return hashlib.sha256(_canonical(raw)).hexdigest()


def _domain_hash(domain: str, raw: object) -> str:
    digest = hashlib.sha256(domain.encode() + b"\0")
    digest.update(_canonical(raw))
    return digest.hexdigest()
