from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from zeroverse import windows_ioctl_ghidra_export as exporter
from zeroverse.windows_ioctl_ghidra_export import (
    EXPORT_VERSION_V3,
    EXTRACTOR_CONFIG_SHA256,
    EXTRACTOR_PROFILE,
    RAW_FACT_VERSION,
    analyze_windows_ioctl_driver,
    canonical_export_bytes,
    compile_windows_ioctl_high_pcode_facts,
    validate_windows_ioctl_high_pcode_export,
)


def _ref(order: int, opcode: str, instruction: int | None = None) -> dict[str, object]:
    return {
        "function_rva": "0x1200",
        "instruction_rva": f"0x{instruction or 0x1200 + order:x}",
        "pcode_order": order,
        "opcode": opcode,
    }


def _facts() -> dict[str, Any]:
    store = _ref(1, "STORE", 0x1100)
    registration_address = _ref(10, "PTRADD", 0x10F0)
    registration_target = _ref(11, "COPY", 0x10F8)
    ioctl_load = _ref(2, "LOAD")
    ioctl_compare = _ref(3, "INT_EQUAL")
    ioctl_branch = _ref(4, "CBRANCH")
    source = _ref(5, "LOAD")
    length = _ref(6, "LOAD")
    guard_compare = _ref(7, "INT_LESS")
    guard_branch = _ref(8, "CBRANCH")
    sink = _ref(9, "CALL", 0x1280)
    reject_return = _ref(12, "RETURN", 0x1290)
    ops = [
        {"ref": registration_address, "input_refs": []},
        {"ref": registration_target, "input_refs": []},
        {"ref": store, "input_refs": [registration_address, registration_target]},
        {"ref": ioctl_load, "input_refs": []},
        {"ref": ioctl_compare, "input_refs": [ioctl_load]},
        {"ref": ioctl_branch, "input_refs": [ioctl_compare]},
        {"ref": source, "input_refs": []},
        {"ref": length, "input_refs": []},
        {"ref": guard_compare, "input_refs": [length]},
        {"ref": guard_branch, "input_refs": [guard_compare]},
        {"ref": sink, "input_refs": [source]},
        {"ref": reject_return, "input_refs": []},
    ]
    return {
        "schema_version": RAW_FACT_VERSION,
        "driver_sha256": "1" * 64,
        "pdb_sha256": "2" * 64,
        "pdb_codeview_identity": "00112233445566778899AABBCCDDEEFF:1:driver.pdb",
        "architecture": "x86_64",
        "pointer_size": 8,
        "image_base": "0x140000000",
        "coverage": {
            "framework": "wdm",
            "truncated": False,
            "dynamic_dispatch": False,
            "unresolved_edges": [],
        },
        "dispatches": [
            {
                "ioctl_code": 0x222004,
                "device_type": 0x22,
                "function": 0x801,
                "method": 0,
                "access": 0,
                "handler_name": "DispatchDeviceControl",
                "handler_rva": "0x1200",
                "registration_rva": "0x1100",
                "dispatch_resolved": True,
                "unresolved_edges": [],
                "registration_evidence": {
                    "major_function_index": 14,
                    "target_rva": "0x1200",
                    "store_ref": store,
                    "address_dependency_refs": [registration_address],
                    "target_dependency_refs": [registration_target],
                },
                "ioctl_match_evidence": {
                    "ioctl_code": 0x222004,
                    "comparison_ref": ioctl_compare,
                    "branch_ref": ioctl_branch,
                    "dominates_handler": True,
                    "match_successor_ref": sink,
                    "reject_return_ref": reject_return,
                    "match_comparison_result": True,
                    "entry_reachable": True,
                    "unique_match_successor": True,
                    "reject_successor_reaches_sink": False,
                },
                "ops": ops,
                "fields": [
                    {
                        "offset": 8,
                        "width": 4,
                        "kind": "length",
                        "source": "SystemBuffer",
                        "source_root": "irp.system_buffer",
                        "source_ref": source,
                        "sink_kind": "copy",
                        "sink_function": "memcpy",
                        "sink_address": "0x1280",
                        "sink_ref": sink,
                        "sink_argument_index": 2,
                        "taint_path": [source, sink],
                        "safety_proofs": [
                            {
                                "proof_kind": "input-field-readable",
                                "comparison_ref": guard_compare,
                                "branch_ref": guard_branch,
                                "sink_successor_ref": sink,
                                "reject_return_ref": reject_return,
                                "sink_comparison_result": False,
                                "dominates_sink": True,
                                "entry_reachable": True,
                                "unique_sink_successor": True,
                                "reject_successor_reaches_sink": False,
                                "input_buffer_length_ref": length,
                                "field_end": 12,
                            }
                        ],
                    }
                ],
            }
        ],
    }


def test_compiles_rich_facts_and_derives_exact_legacy_summary() -> None:
    export = compile_windows_ioctl_high_pcode_facts(_facts())
    assert export["schema_version"] == EXPORT_VERSION_V3
    assert export["extractor_profile"] == EXTRACTOR_PROFILE
    assert export["extractor_config_sha256"] == EXTRACTOR_CONFIG_SHA256
    assert export["facts"]["schema_version"] == RAW_FACT_VERSION
    dispatch = export["dispatches"][0]
    assert set(dispatch) == {
        "ioctl_code",
        "device_type",
        "function",
        "method",
        "access",
        "handler_name",
        "handler_rva",
        "registration_rva",
        "dispatch_resolved",
        "unresolved_edges",
        "fields",
    }
    field = dispatch["fields"][0]
    assert field["guards"] == ["field-within-input", "input-buffer-length"]
    assert isinstance(field["source_inst_id"], int)
    assert isinstance(field["sink_inst_id"], int)
    validate_windows_ioctl_high_pcode_export(export)
    assert canonical_export_bytes(export).endswith(b"\n")


def test_compilation_is_deterministic_under_dispatch_op_and_guard_permutations() -> None:
    one = _facts()
    two = copy.deepcopy(one)
    two["dispatches"][0]["ops"].reverse()
    assert compile_windows_ioctl_high_pcode_facts(one) == compile_windows_ioctl_high_pcode_facts(
        two
    )


def test_source_span_accepts_one_unsigned_widening_and_rejects_copy_substitution() -> None:
    raw = _facts()
    dispatch = raw["dispatches"][0]
    field = dispatch["fields"][0]
    source = field["source_ref"]
    length = field["safety_proofs"][0]["input_buffer_length_ref"]
    sink = field["sink_ref"]
    reject_return = field["safety_proofs"][0]["reject_return_ref"]
    widening = _ref(13, "INT_ZEXT")
    remaining = _ref(14, "INT_SUB")
    comparison = _ref(15, "INT_LESSEQUAL")
    branch = _ref(16, "CBRANCH")
    dispatch["ops"].extend(
        [
            {"ref": widening, "input_refs": [length]},
            {"ref": remaining, "input_refs": [widening]},
            {"ref": comparison, "input_refs": [source, remaining]},
            {"ref": branch, "input_refs": [comparison]},
        ]
    )
    field["safety_proofs"] = [
        {
            "proof_kind": "source-copy-span",
            "comparison_ref": comparison,
            "branch_ref": branch,
            "sink_successor_ref": sink,
            "reject_return_ref": reject_return,
            "sink_comparison_result": True,
            "dominates_sink": True,
            "entry_reachable": True,
            "unique_sink_successor": True,
            "reject_successor_reaches_sink": False,
            "attacker_length_path": [source],
            "input_buffer_length_ref": length,
            "remaining_length_ref": remaining,
            "field_end": 12,
        }
    ]
    assert compile_windows_ioctl_high_pcode_facts(raw)["dispatches"][0]["fields"][0][
        "guards"
    ] == []

    widening["opcode"] = "COPY"
    with pytest.raises(ValueError, match="unsigned widening"):
        compile_windows_ioctl_high_pcode_facts(raw)


def test_destination_span_accepts_only_exact_exclusive_capacity_bound() -> None:
    class Node:
        def __init__(
            self, *, definition: Operation | None = None, constant: int | None = None
        ) -> None:
            self.definition = definition
            self.constant = constant

        def getDef(self) -> Operation | None:
            return self.definition

        def isConstant(self) -> bool:
            return self.constant is not None

        def getOffset(self) -> int:
            assert self.constant is not None
            return self.constant

    class Operation:
        def __init__(self, mnemonic: str, sequence: str, inputs: list[Node]) -> None:
            self.mnemonic = mnemonic
            self.sequence = sequence
            self.inputs = inputs

        def getMnemonic(self) -> str:
            return self.mnemonic

        def getSeqnum(self) -> str:
            return self.sequence

        def getNumInputs(self) -> int:
            return len(self.inputs)

        def getInput(self, index: int) -> Node:
            return self.inputs[index]

    source = Operation("LOAD", "source", [])
    attacker = Node(definition=source)
    exact = Operation("INT_LESS", "comparison", [attacker, Node(constant=65)])
    path, safe_result = exporter._exact_destination_span_guard(
        exact, source, capacity=64
    )
    assert path == [source]
    assert safe_result is True

    too_large = Operation("INT_LESS", "comparison", [attacker, Node(constant=66)])
    with pytest.raises(ValueError, match="destination-span"):
        exporter._exact_destination_span_guard(too_large, source, capacity=64)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda raw: raw["coverage"].__setitem__("truncated", True), "truncated"),
        (lambda raw: raw["coverage"].__setitem__("dynamic_dispatch", True), "dynamic"),
        (lambda raw: raw["coverage"].__setitem__("framework", "kmdf"), "KMDF"),
        (lambda raw: raw["coverage"]["unresolved_edges"].append("CALLIND"), "unresolved"),
        (lambda raw: raw["dispatches"][0].__setitem__("method", 3), "METHOD_NEITHER"),
        (
            lambda raw: raw["dispatches"][0]["registration_evidence"].__setitem__(
                "major_function_index", 13
            ),
            "registration",
        ),
        (
            lambda raw: raw["dispatches"][0]["fields"][0]["safety_proofs"][0].__setitem__(
                "dominates_sink", False
            ),
            "dominate",
        ),
        (
            lambda raw: raw["dispatches"][0]["ioctl_match_evidence"].__setitem__(
                "match_comparison_result", False
            ),
            "polarity",
        ),
        (lambda raw: raw["dispatches"][0]["fields"][0]["taint_path"].reverse(), "endpoints"),
    ],
)
def test_rejects_incomplete_dynamic_or_inconsistent_facts(mutate: Any, message: str) -> None:
    raw = _facts()
    mutate(raw)
    with pytest.raises(ValueError, match=message):
        compile_windows_ioctl_high_pcode_facts(raw)


def test_validator_rejects_independently_tampered_legacy_projection() -> None:
    export = compile_windows_ioctl_high_pcode_facts(_facts())
    export["dispatches"][0]["fields"][0]["guards"] = []
    with pytest.raises(ValueError, match="canonical"):
        validate_windows_ioctl_high_pcode_export(export)


def test_rejects_extra_fields_and_noncanonical_rvas() -> None:
    raw = _facts()
    raw["extra"] = False
    with pytest.raises(ValueError, match="fields mismatch"):
        compile_windows_ioctl_high_pcode_facts(raw)
    raw = _facts()
    raw["dispatches"][0]["handler_rva"] = "0x01200"
    with pytest.raises(ValueError, match="canonical"):
        compile_windows_ioctl_high_pcode_facts(raw)


def test_live_entrypoint_rejects_unavailable_typed_acquisition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary, pdb, home = tmp_path / "driver.sys", tmp_path / "driver.pdb", tmp_path / "ghidra"
    binary.write_bytes(b"MZ")
    pdb.write_bytes(b"PDB")
    home.mkdir()
    monkeypatch.setattr(
        "zeroverse.windows_ioctl_ghidra_export._acquire_normalized_high_pcode_facts",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("typed facts unavailable")),
    )
    with pytest.raises(RuntimeError, match="typed facts unavailable"):
        analyze_windows_ioctl_driver(binary, pdb, ghidra_home=home)


def test_export_json_has_no_runtime_or_execution_surface() -> None:
    text = json.dumps(compile_windows_ioctl_high_pcode_facts(_facts())).lower()
    for forbidden in ("device_path", "deviceiocontrol", "poc", "weapon", "execute_command"):
        assert forbidden not in text


def test_generic_compiler_cannot_mint_the_exact_vid_live_profile() -> None:
    with pytest.raises(ValueError, match="Vid extractor profile artifact identity"):
        exporter._compile_windows_ioctl_high_pcode_facts(
            _facts(),
            exporter.VID_EXTRACTOR_PROFILE,
            exporter.VID_EXTRACTOR_CONFIG_SHA256,
        )


def test_generic_compiler_rejects_vid_only_schema_and_opcodes() -> None:
    facts = _facts()
    facts["coverage"] = {
        "framework": "kmdf-wdm-preprocess",
        "scope": {
            "kind": "ioctl-allowlist",
            "ioctl_codes": [exporter.VID_IOCTL],
            "exhaustive": True,
        },
        "truncated": False,
        "dynamic_dispatch": False,
        "unresolved_edges": [],
    }
    with pytest.raises(ValueError):
        exporter.compile_windows_ioctl_high_pcode_facts(facts)

    facts = _facts()
    facts["dispatches"][0]["ops"][0]["ref"]["opcode"] = "CALLIND"
    with pytest.raises(ValueError, match="generic WDM profile"):
        exporter.compile_windows_ioctl_high_pcode_facts(facts)


def test_vid_profile_rejects_hash_only_synthetic_fact_forgery() -> None:
    facts = _facts()
    facts.update(
        {
            "driver_sha256": exporter.VID_DRIVER_SHA256,
            "pdb_sha256": exporter.VID_PDB_SHA256,
            "pdb_codeview_identity": exporter.VID_CODEVIEW,
            "coverage": {
                "framework": "kmdf-wdm-preprocess",
                "scope": {
                    "kind": "ioctl-allowlist",
                    "ioctl_codes": [exporter.VID_IOCTL],
                    "exhaustive": True,
                },
                "truncated": False,
                "dynamic_dispatch": False,
                "unresolved_edges": [],
            },
        }
    )
    dispatch = facts["dispatches"][0]
    dispatch.update(
        {
            "ioctl_code": exporter.VID_IOCTL,
            "device_type": 0x22,
            "function": 0x15,
            "method": 0,
            "access": 0,
            "handler_name": "VidIoControlDriver",
            "handler_rva": "0x31ea8",
            "registration_rva": "0x60314",
        }
    )
    field = dispatch["fields"][0]
    field.update(
        {
            "offset": 4,
            "width": 4,
            "kind": "length",
            "source": "SystemBuffer",
            "source_root": "irp.system_buffer",
            "sink_kind": "copy",
            "sink_function": "VidInformationIoctlGetSystemInformation",
            "sink_address": "0xc5c78",
            "sink_argument_index": 2,
        }
    )
    facts["schema_version"] = exporter.RAW_FACT_VERSION_V1
    semantic = field.pop("safety_proofs")[0]
    field["guard_evidence"] = [
        {
            "kind": "input-buffer-length",
            "comparison_ref": semantic["comparison_ref"],
            "branch_ref": semantic["branch_ref"],
            "checked_ref": semantic["input_buffer_length_ref"],
            "dominates_sink": True,
            "target_ref": semantic["sink_successor_ref"],
            "target_reaches_sink": False,
            "entry_reachable": True,
            "unique_sink_successor": True,
        }
    ]
    second_guard = dict(field["guard_evidence"][0])
    second_guard["kind"] = "field-within-input"
    field["guard_evidence"].append(second_guard)
    with pytest.raises(ValueError, match=r"operation (?:set|graph) mismatch"):
        exporter._compile_windows_ioctl_high_pcode_facts(
            facts,
            exporter.VID_EXTRACTOR_PROFILE,
            exporter.VID_EXTRACTOR_CONFIG_SHA256,
        )


def test_vid_branch_gate_binds_taken_target_polarity_and_entry_reachability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Address:
        def __init__(self, offset: int) -> None:
            self.offset = offset

        def getOffset(self) -> int:
            return self.offset

    class Target:
        def __init__(self, offset: int) -> None:
            self.address = Address(offset)

        def getAddress(self) -> Address:
            return self.address

    class Block:
        def __init__(self, index: int, start: int) -> None:
            self.index = index
            self.start = Address(start)
            self.out: list[Block] = []

        def getIndex(self) -> int:
            return self.index

        def getStart(self) -> Address:
            return self.start

        def getStop(self) -> Address:
            return self.start

        def getOutSize(self) -> int:
            return len(self.out)

        def getOut(self, index: int) -> Block:
            return self.out[index]

    class Operation:
        def __init__(self, block: Block, target: int = 0) -> None:
            self.block = block
            self.target = Target(target)

        def getParent(self) -> Block:
            return self.block

        def getInput(self, _index: int) -> Target:
            return self.target

        def getNumInputs(self) -> int:
            return 1

    class High:
        def __init__(self, blocks: list[Block]) -> None:
            self.blocks = blocks

        def getBasicBlocks(self) -> list[Block]:
            return self.blocks

    entry, taken, fallthrough = Block(0, 0x1000), Block(1, 0x2000), Block(2, 0x3000)
    entry.out = [taken, fallthrough]
    branch, sink = Operation(entry, 0x2000), Operation(taken)
    target_marker = Operation(taken)
    monkeypatch.setattr(exporter, "_dominates", lambda *_args: True)
    exporter._vid_branch_gate(
        High([entry, taken, fallthrough]),
        branch,
        target_marker,
        sink,
        target_reaches_sink=True,
    )
    with pytest.raises(ValueError, match="polarity"):
        exporter._vid_branch_gate(
            High([entry, taken, fallthrough]),
            branch,
            target_marker,
            sink,
            target_reaches_sink=False,
        )

    disconnected = Block(3, 0x4000)
    disconnected.out = [taken, fallthrough]
    with pytest.raises(ValueError, match="disconnected"):
        exporter._vid_branch_gate(
            High([entry, taken, fallthrough, disconnected]),
            Operation(disconnected, 0x2000),
            target_marker,
            sink,
            target_reaches_sink=True,
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda raw: raw["dispatches"][0]["ops"][5].__setitem__("input_refs", []),
            "CBRANCH",
        ),
        (
            lambda raw: raw["dispatches"][0]["ops"][8].__setitem__("input_refs", []),
            "input-field proof",
        ),
        (
            lambda raw: raw["dispatches"][0]["ops"][9].__setitem__("input_refs", []),
            "semantic safety CBRANCH",
        ),
        (
            lambda raw: raw["dispatches"][0]["ops"][2].__setitem__("input_refs", []),
            "registration STORE",
        ),
    ],
)
def test_rejects_unbound_branch_guard_and_registration_relations(
    mutation: Any, message: str
) -> None:
    raw = _facts()
    mutation(raw)
    with pytest.raises(ValueError, match=message):
        compile_windows_ioctl_high_pcode_facts(raw)


class _FakeSequence:
    def __init__(self, value: str) -> None:
        self.value = value

    def __str__(self) -> str:
        return self.value


class _FakeNode:
    def __init__(
        self,
        definition: Any = None,
        *,
        register: bool = False,
        size: int = 8,
        address: str = "register:0x10",
        constant: int | None = None,
    ) -> None:
        self.definition = definition
        self.register = register
        self.size = size
        self.address = address
        self.constant = constant

    def getDef(self) -> Any:
        return self.definition

    def isRegister(self) -> bool:
        return self.register

    def getSize(self) -> int:
        return self.size

    def getAddress(self) -> str:
        return self.address

    def isConstant(self) -> bool:
        return self.constant is not None

    def isAddress(self) -> bool:
        return False

    def getOffset(self) -> int:
        return 0 if self.constant is None else self.constant


class _FakeOp:
    def __init__(self, mnemonic: str, inputs: list[_FakeNode], sequence: str) -> None:
        self.mnemonic = mnemonic
        self.inputs = inputs
        self.sequence = _FakeSequence(sequence)

    def getMnemonic(self) -> str:
        return self.mnemonic

    def getNumInputs(self) -> int:
        return len(self.inputs)

    def getInput(self, index: int) -> _FakeNode:
        return self.inputs[index]

    def getSeqnum(self) -> _FakeSequence:
        return self.sequence


class _FakeRegister:
    def __init__(self, name: str) -> None:
        self.name = name

    def getName(self) -> str:
        return self.name


class _FakeComponent:
    def __init__(self, name: str, offset: int, data_type: Any = None) -> None:
        self.name = name
        self.offset = offset
        self.data_type = data_type

    def getFieldName(self) -> str:
        return self.name

    def getOffset(self) -> int:
        return self.offset

    def getDataType(self) -> Any:
        return self.data_type


class _FakeStructure:
    def __init__(self, name: str, components: list[_FakeComponent]) -> None:
        self.name = name
        self.components = components

    def getName(self) -> str:
        return self.name

    def getComponents(self) -> list[_FakeComponent]:
        return self.components


class _FakeIterator:
    def __init__(self, values: list[Any]) -> None:
        self.values = iter(values)
        self.next_value: Any = None
        self.ready = False

    def hasNext(self) -> bool:
        if not self.ready:
            try:
                self.next_value = next(self.values)
                self.ready = True
            except StopIteration:
                return False
        return True

    def next(self) -> Any:
        assert self.hasNext()
        self.ready = False
        return self.next_value


class _FakeDataTypes:
    def __init__(self, offset: int) -> None:
        self.offset = offset

    def getAllStructures(self) -> _FakeIterator:
        device_control = _FakeStructure(
            "DeviceIoControl",
            [
                _FakeComponent("OutputBufferLength", 0),
                _FakeComponent("InputBufferLength", 4),
            ],
        )
        parameters = _FakeStructure(
            "Parameters",
            [_FakeComponent("DeviceIoControl", 0, device_control)],
        )
        return _FakeIterator(
            [
                _FakeStructure(
                    "_IRP",
                    [
                        _FakeComponent("SystemBuffer", self.offset),
                        _FakeComponent("CurrentStackLocation", 8),
                    ],
                ),
                _FakeStructure(
                    "_IO_STACK_LOCATION",
                    [_FakeComponent("Parameters", 8, parameters)],
                ),
            ]
        )


class _FakeProgram:
    def __init__(self, register: str = "RDX", offset: int = 0) -> None:
        self.register = register
        self.offset = offset

    def getRegister(self, *_args: Any) -> _FakeRegister:
        return _FakeRegister(self.register)

    def getDataTypeManager(self) -> _FakeDataTypes:
        return _FakeDataTypes(self.offset)


def _system_buffer_load(
    *, register: str = "RDX", root_operation: str | None = None
) -> tuple[_FakeOp, _FakeProgram]:
    root = _FakeNode(register=True)
    if root_operation == "PTRSUB_ZERO":
        root = _FakeNode(
            _FakeOp(
                "PTRSUB", [_FakeNode(register=True), _FakeNode(constant=0)], "root"
            )
        )
    elif root_operation is not None:
        root = _FakeNode(_FakeOp(root_operation, [_FakeNode(register=True)], "root"))
    pointer_load = _FakeOp("LOAD", [_FakeNode(), root], "pointer-load")
    pointer_value = _FakeNode(pointer_load)
    value_load = _FakeOp("LOAD", [_FakeNode(), pointer_value], "value-load")
    return value_load, _FakeProgram(register=register)


def test_direct_system_buffer_binding_requires_rdx_and_exact_pdb_offset() -> None:
    value_load, program = _system_buffer_load()
    assert exporter._direct_irp_system_buffer_offset(value_load, program) == 0
    value_load, program = _system_buffer_load(root_operation="PTRSUB_ZERO")
    assert exporter._direct_irp_system_buffer_offset(value_load, program) == 0
    value_load, program = _system_buffer_load(register="RAX")
    with pytest.raises(ValueError, match="RDX"):
        exporter._direct_irp_system_buffer_offset(value_load, program)
    value_load, program = _system_buffer_load()
    program.offset = 8
    with pytest.raises(ValueError, match="wrong offset"):
        exporter._direct_irp_system_buffer_offset(value_load, program)


@pytest.mark.parametrize("operation", ["PTRADD", "INT_ADD", "MULTIEQUAL"])
def test_direct_system_buffer_binding_rejects_arithmetic_and_phi(operation: str) -> None:
    value_load, program = _system_buffer_load(root_operation=operation)
    with pytest.raises(ValueError, match="arithmetic or PHI"):
        exporter._direct_irp_system_buffer_offset(value_load, program)


class _FakeEntryPoint:
    def __init__(self, offset: int) -> None:
        self.offset = offset

    def getOffset(self) -> int:
        return self.offset


class _FakeFunction:
    def __init__(self, offset: int) -> None:
        self.entry = _FakeEntryPoint(offset)

    def getEntryPoint(self) -> _FakeEntryPoint:
        return self.entry


def _coverage_surface() -> tuple[
    dict[int, tuple[Any, Any, str, list[Any]]],
    _FakeFunction,
    _FakeFunction,
    _FakeOp,
    _FakeOp,
    _FakeOp,
]:
    driver = _FakeFunction(0x1000)
    handler = _FakeFunction(0x1200)
    address = _FakeOp("PTRADD", [], "address")
    registration = _FakeOp(
        "STORE", [_FakeNode(), _FakeNode(address), _FakeNode()], "registration"
    )
    comparison = _FakeOp("INT_EQUAL", [_FakeNode(constant=0x222004)], "comparison")
    branch = _FakeOp("CBRANCH", [], "branch")
    surface = {
        0x1000: (
            driver,
            object(),
            "driver->MajorFunction[14] = DispatchDeviceControl;",
            [registration],
        ),
        0x1200: (
            handler,
            object(),
            "if (stack->Parameters.DeviceIoControl.IoControlCode == 0x222004) {}",
            [comparison, branch],
        ),
    }
    return surface, driver, handler, registration, comparison, branch


def test_complete_surface_accepts_only_one_registration_and_ioctl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    surface, driver, handler, registration, comparison, branch = _coverage_surface()
    monkeypatch.setattr(exporter, "_dependency_constants", lambda _op: {8, 14})
    exporter._audit_complete_ioctl_surface(
        surface, driver, handler, registration, comparison, branch, 0x1200
    )


def test_complete_surface_accepts_one_explicitly_recovered_input_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    surface, driver, handler, registration, comparison, branch = _coverage_surface()
    checked = _FakeOp("LOAD", [], "guard-checked")
    guard_comparison = _FakeOp(
        "INT_LESS", [_FakeNode(constant=3), _FakeNode(checked)], "guard-comparison"
    )
    guard_branch = _FakeOp(
        "CBRANCH", [_FakeNode(), _FakeNode(guard_comparison)], "guard-branch"
    )
    handler_record = list(surface[0x1200])
    handler_record[2] += " if (stack->InputBufferLength < 4) return 0;"
    handler_record[3] = [
        comparison,
        branch,
        checked,
        guard_comparison,
        guard_branch,
    ]
    surface[0x1200] = tuple(handler_record)  # type: ignore[assignment]
    monkeypatch.setattr(exporter, "_dependency_constants", lambda _op: {8, 14})
    exporter._audit_complete_ioctl_surface(
        surface,
        driver,
        handler,
        registration,
        comparison,
        branch,
        0x1200,
        guard_facts=[
            (
                guard_comparison,
                guard_branch,
                checked,
                ("field-within-input", "input-buffer-length"),
            )
        ],
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda surface: surface[0x1000].__setitem__(
            2,
            "driver->MajorFunction[14] = DispatchDeviceControl; "
            "driver->MajorFunction[index] = Other;",
        ),
        lambda surface: surface.__setitem__(
            0x1400,
            (
                _FakeFunction(0x1400),
                object(),
                "return stack->Parameters.DeviceIoControl.IoControlCode;",
                [],
            ),
        ),
        lambda surface: surface[0x1200][3].append(
            _FakeOp("INT_EQUAL", [_FakeNode(constant=0x333004)], "extra-comparison")
        ),
        lambda surface: surface[0x1200][3].append(_FakeOp("CBRANCH", [], "extra-branch")),
    ],
)
def test_complete_surface_rejects_hidden_registration_ioctl_or_guard(
    monkeypatch: pytest.MonkeyPatch, mutation: Any
) -> None:
    surface, driver, handler, registration, comparison, branch = _coverage_surface()
    # Tuples model immutable surface records; use lists only for body mutation.
    surface = {key: list(value) for key, value in surface.items()}  # type: ignore[assignment]
    monkeypatch.setattr(exporter, "_dependency_constants", lambda _op: {8, 14})
    mutation(surface)
    with pytest.raises(ValueError):
        exporter._audit_complete_ioctl_surface(
            surface, driver, handler, registration, comparison, branch, 0x1200  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("guard", ["OutputBufferLength", "PreviousMode"])
def test_live_profile_rejects_unimplemented_guard_sources(guard: str) -> None:
    with pytest.raises(ValueError, match="unimplemented guard"):
        exporter._require_no_unsupported_live_guard_sources(f"if (irp->{guard}) return 0;")


def _input_buffer_length_comparison(
    *, constant: int = 4, mnemonic: str = "INT_LESS", register: str = "RDX"
) -> tuple[_FakeOp, _FakeOp, _FakeProgram]:
    root = _FakeNode(register=True)
    current_stack_address = _FakeNode(
        _FakeOp("PTRSUB", [root, _FakeNode(constant=8)], "irp-stack-address")
    )
    current_stack_load = _FakeOp(
        "LOAD", [_FakeNode(), current_stack_address], "current-stack-load"
    )
    parameters_address = _FakeNode(
        _FakeOp(
            "PTRSUB",
            [_FakeNode(current_stack_load), _FakeNode(constant=8)],
            "parameters-address",
        )
    )
    device_control_address = _FakeNode(
        _FakeOp(
            "PTRSUB",
            [parameters_address, _FakeNode(constant=0)],
            "device-control-address",
        )
    )
    input_length_address = _FakeNode(
        _FakeOp(
            "PTRSUB",
            [device_control_address, _FakeNode(constant=4)],
            "input-length-address",
        )
    )
    input_length_load = _FakeOp(
        "LOAD", [_FakeNode(), input_length_address], "input-length-load"
    )
    comparison = _FakeOp(
        mnemonic,
        [_FakeNode(input_length_load), _FakeNode(constant=constant)],
        "input-length-comparison",
    )
    return comparison, input_length_load, _FakeProgram(register=register)


def test_exact_input_buffer_length_guard_binds_raw_load_and_pdb_path() -> None:
    comparison, checked, program = _input_buffer_length_comparison()
    assert exporter._exact_input_buffer_length_guard(
        comparison, program, minimum_length=4
    ) == (checked, False)
    exporter._require_no_unsupported_live_guard_sources(
        "if (stack->Parameters.DeviceIoControl.InputBufferLength < 4) return 0;"
    )


@pytest.mark.parametrize(
    ("constant", "mnemonic", "register", "message"),
    [
        (5, "INT_LESS", "RDX", "exact PDB-backed"),
        (4, "INT_EQUAL", "RDX", "unsupported"),
        (4, "INT_LESS", "RAX", "exact PDB-backed"),
    ],
)
def test_exact_input_buffer_length_guard_rejects_wrong_bound_opcode_or_root(
    constant: int, mnemonic: str, register: str, message: str
) -> None:
    comparison, _checked, program = _input_buffer_length_comparison(
        constant=constant, mnemonic=mnemonic, register=register
    )
    with pytest.raises(ValueError, match=message):
        exporter._exact_input_buffer_length_guard(
            comparison, program, minimum_length=4
        )


def test_high_pcode_caps_apply_before_materializing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(exporter._CONFIG, "max_ops_per_function", 1)

    class High:
        def getPcodeOps(self) -> _FakeIterator:
            return _FakeIterator([object(), object()])

    with pytest.raises(ValueError, match="operation cap"):
        exporter._high_ops(High())


def test_function_cap_applies_before_materializing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(exporter._CONFIG, "max_internal_functions", 1)
    with pytest.raises(ValueError, match="function surface"):
        exporter._bounded_functions(_FakeIterator([object(), object()]))


def test_active_pyghidra_version_must_match_requested_home() -> None:
    exporter._require_active_ghidra_version("11.4.2", "11.4.2")
    with pytest.raises(ValueError, match="does not match"):
        exporter._require_active_ghidra_version("11.3", "11.4.2")
