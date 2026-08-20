from __future__ import annotations

import copy
import hashlib
import json

import pytest

import zeroverse.windows_driver_entry_bridge as bridge
import zeroverse.windows_driver_entry_bridge_ghidra as bridge_ghidra
from zeroverse.cli import main
from zeroverse.pe_symbols import PdbFunctionRecord


def _ref(order: int, opcode: str) -> dict[str, object]:
    return {
        "function_rva": "0x95010",
        "instruction_rva": f"0x{0x95010 + order:x}",
        "pcode_order": order,
        "opcode": opcode,
    }


def _facts(driver_entry: str = "0x4fa14") -> dict[str, object]:
    return {
        "schema_version": bridge.RAW_VERSION,
        "driver_sha256": "1" * 64,
        "pdb_sha256": "2" * 64,
        "pdb_identity": "GUID:4:stripped",
        "pe_codeview_identity": "GUID:1:afd.pdb",
        "architecture": "x86_64",
        "image_base": "0x140000000",
        "pe_entry_point_rva": "0x95010",
        "tool": {"name": "ghidra", "version": "11.4.2"},
        "pdb_driver_entry": {
            "name": "DriverEntry",
            "record_kind": "public-function",
            "function_flag": True,
            "segment": 1,
            "offset": int(driver_entry, 16) - 0x1000,
            "rva": driver_entry,
            "executable_section": True,
            "unique_exact_record": True,
        },
        "wrapper": {
            "function_rva": "0x95010",
            "exact_pe_entry": True,
            "non_thunk": True,
            "pre_bridge_call": {
                "ref": _ref(1, "CALL"),
                "target_rva": "0x94000",
                "direct": True,
                "internal_executable": True,
            },
            "bridge_call": {
                "ref": _ref(2, "CALL"),
                "target_rva": driver_entry,
                "direct": True,
                "internal_executable": True,
            },
            "rcx_path": [_ref(3, "COPY")],
            "rdx_path": [_ref(4, "CAST")],
            "bridge_dominates_all_returns": True,
            "return_value_propagated": True,
            "return_refs": [_ref(5, "RETURN")],
            "bounded_control_transfers": [
                _ref(1, "CALL"),
                _ref(2, "CALL"),
                _ref(5, "RETURN"),
            ],
        },
        "accounting": {
            "wrapper_pcode_ops": 12,
            "control_transfers": 3,
            "direct_calls": 2,
            "indirect_calls": 0,
            "returns": 1,
            "limits_hit": [],
        },
    }


@pytest.mark.parametrize("driver_entry", ["0x4fa14", "0x50654"])
def test_compiles_only_narrow_neutral_entry_bridge(driver_entry: str) -> None:
    result = bridge.compile_windows_driver_entry_bridge(_facts(driver_entry))
    assert result["pdb_driver_entry"]["rva"] == driver_entry
    assert result["outcome"] == "entry-bridge-proven"
    assert result["registration_claims"] == 0
    assert result["selector_claims"] == 0
    assert result["table_claims"] == 0
    assert result["candidate_count"] == 0
    assert result["vulnerability_established"] is False
    assert result["runtime_reachability_established"] is False


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda raw: raw["wrapper"]["bridge_call"].update({"target_rva": "0x4fa15"}),
            "exact unique",
        ),
        (lambda raw: raw["pdb_driver_entry"].update({"function_flag": False}), "record contract"),
        (lambda raw: raw["wrapper"].update({"bridge_dominates_all_returns": False}), "dominance"),
        (lambda raw: raw["wrapper"].update({"return_value_propagated": False}), "dominance"),
        (lambda raw: raw["accounting"].update({"indirect_calls": 1}), "accounting"),
        (lambda raw: raw["accounting"].update({"limits_hit": ["ops"]}), "accounting"),
    ],
)
def test_tamper_rejection(mutation: object, message: str) -> None:
    raw = _facts()
    mutation(raw)
    with pytest.raises(ValueError, match=message):
        bridge.compile_windows_driver_entry_bridge(raw)


def test_export_rejects_claim_escalation_and_unknown_fields() -> None:
    export = bridge.compile_windows_driver_entry_bridge(_facts())
    export["candidate_count"] = 1
    with pytest.raises(ValueError, match="claim boundary"):
        bridge.canonical_bridge_bytes(export)
    export = bridge.compile_windows_driver_entry_bridge(_facts())
    export["registrations"] = []
    with pytest.raises(ValueError, match="unknown or missing"):
        bridge.canonical_bridge_bytes(export)


def test_verify_cli_requires_replay_tool(tmp_path, capsys) -> None:
    assert main(["windows-driver-entry-bridge-verify", str(tmp_path)]) == 2
    assert "GHIDRA" in capsys.readouterr().err


def test_canonical_export_is_deterministic() -> None:
    first = bridge.compile_windows_driver_entry_bridge(_facts())
    second = json.loads(json.dumps(first))
    assert bridge.canonical_bridge_bytes(first) == bridge.canonical_bridge_bytes(second)


def test_v3_ssa_lane_is_additive_and_abi_bound() -> None:
    raw = _facts()
    raw["schema_version"] = bridge.RAW_VERSION_V3
    raw["abi_authority"] = bridge._abi_authority()
    raw["wrapper"]["return_channel"] = {"kind": "high-pcode-ssa/v1"}
    result = bridge.compile_windows_driver_entry_bridge_v3(raw)
    assert result["schema_version"] == bridge.EXPORT_VERSION_V3
    assert result["abi_authority"]["manifest_sha256"] == bridge.ABI_MANIFEST_SHA256
    assert result["candidate_count"] == 0


def test_v3_native_return_channel_rejects_instruction_tamper() -> None:
    raw = _facts()
    raw["schema_version"] = bridge.RAW_VERSION_V3
    raw["abi_authority"] = bridge._abi_authority()
    instruction_bytes = ["488b5c2430", "4883c420", "5f", "c3"]
    start = 0x95030
    rows = []
    cursor = start
    for index, encoded in enumerate(instruction_bytes):
        size = len(encoded) // 2
        rows.append(
            {
                "rva": f"0x{cursor:x}",
                "size": size,
                "bytes": encoded,
                "flow": "return" if index == 3 else "fallthrough",
                "successors": [] if index == 3 else [f"0x{cursor + size:x}"],
                "low_pcode_sha256": str(index + 3) * 64,
                "resolved_writes": [],
            }
        )
        cursor += size
    suffix = bytes.fromhex("".join(instruction_bytes))
    raw["wrapper"]["bridge_call"]["ref"]["instruction_rva"] = "0x9502b"
    raw["wrapper"]["return_channel"] = {
        "kind": "windows-x64-rax-preserved/v1",
        "conclusion": "DriverEntry NTSTATUS return channel preserved across wrapper suffix",
        "bridge": {
            "rva": "0x9502b",
            "size": 5,
            "bytes": "e8e4a9fbff",
            "sha256": "3e1ad3af8a196a4428776bc53f4a71da8177beeb11d1cc3279a7ed87df92564c",
            "computed_target_rva": "0x4fa14",
        },
        "suffix": {
            "start_rva": "0x95030",
            "end_rva": f"0x{cursor:x}",
            "sha256": hashlib.sha256(suffix).hexdigest(),
            "instructions": rows,
            "instruction_count": 4,
            "byte_count": len(suffix),
            "all_paths_return": True,
            "later_calls": 0,
            "rax_alias_writes": [],
            "limits_hit": [],
        },
    }
    assert bridge.compile_windows_driver_entry_bridge_v3(raw)["candidate_count"] == 0
    mutations = []
    displacement = copy.deepcopy(raw)
    displacement["wrapper"]["return_channel"]["bridge"]["bytes"] = "e8e5a9fbff"
    displacement["wrapper"]["return_channel"]["bridge"]["sha256"] = hashlib.sha256(
        bytes.fromhex("e8e5a9fbff")
    ).hexdigest()
    mutations.append(displacement)
    wrong_size = copy.deepcopy(raw)
    wrong_size["wrapper"]["return_channel"]["suffix"]["instructions"][0]["size"] = 99
    mutations.append(wrong_size)
    detached_start = copy.deepcopy(raw)
    detached_start["wrapper"]["return_channel"]["suffix"]["start_rva"] = "0x95031"
    mutations.append(detached_start)
    detached_end = copy.deepcopy(raw)
    detached_end["wrapper"]["return_channel"]["suffix"]["end_rva"] = "0x9503c"
    mutations.append(detached_end)
    eax_write = copy.deepcopy(raw)
    eax_write["wrapper"]["return_channel"]["suffix"]["instructions"][0][
        "resolved_writes"
    ] = [{"kind": "register", "name": "EAX", "base": "RAX"}]
    mutations.append(eax_write)
    base_rax = copy.deepcopy(raw)
    base_rax["wrapper"]["return_channel"]["suffix"]["instructions"][0][
        "resolved_writes"
    ] = [{"kind": "register", "name": "R15", "base": "RAX"}]
    mutations.append(base_rax)
    for mutated in mutations:
        with pytest.raises(ValueError):
            bridge.compile_windows_driver_entry_bridge_v3(mutated)


def test_producer_is_no_replace_and_cleans_staging(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "afd.sys"
    pdb = tmp_path / "afd.pdb"
    binary.write_bytes(b"MZ-driver")
    pdb.write_bytes(b"pdb")
    ghidra = tmp_path / "ghidra"
    ghidra.mkdir()
    monkeypatch.setattr(bridge, "_require_exact_full_identity", lambda *args: None)
    monkeypatch.setattr(bridge, "pe_codeview_identity", lambda path: ("GUID", 1, "afd.pdb"))
    monkeypatch.setattr(bridge, "pdb_codeview_identity", lambda path: ("GUID", 4, True))
    monkeypatch.setattr(bridge, "_pe_entry_rva", lambda path: 0x95010)
    monkeypatch.setattr(
        bridge,
        "pdb_function_records",
        lambda *args: [PdbFunctionRecord("DriverEntry", "public-function", 1, 0x4EA14, 0x4FA14)],
    )
    monkeypatch.setattr(bridge, "_toolchain_fingerprint", lambda home: {"fixed": True})
    monkeypatch.setattr(bridge, "_ghidra_version", lambda home: "11.4.2")

    def acquire(*args, **kwargs):
        facts = _facts()
        facts["driver_sha256"] = bridge._identity(args[0])
        facts["pdb_sha256"] = bridge._identity(args[1])
        return facts

    monkeypatch.setattr(bridge, "_acquire_entry_bridge_facts", acquire)
    output = tmp_path / "bundle"
    bridge.produce_windows_driver_entry_bridge(binary, pdb, output, ghidra_home=ghidra)
    assert (output / "entry-bridge.json").is_file()
    assert bridge.verify_windows_driver_entry_bridge_bundle(
        output, ghidra_home=ghidra
    )["candidate_count"] == 0
    original_acquire = bridge._acquire_entry_bridge_facts

    def changed_replay(*args, **kwargs):
        changed = original_acquire(*args, **kwargs)
        changed["wrapper"]["rcx_path"] = []
        return changed

    monkeypatch.setattr(bridge, "_acquire_entry_bridge_facts", changed_replay)
    with pytest.raises(ValueError, match="replay mismatch"):
        bridge.verify_windows_driver_entry_bridge_bundle(output, ghidra_home=ghidra)
    monkeypatch.setattr(bridge, "_acquire_entry_bridge_facts", original_acquire)
    sentinel = (output / "receipt.json").read_bytes()
    with pytest.raises((FileExistsError, ValueError)):
        bridge.produce_windows_driver_entry_bridge(binary, pdb, output, ghidra_home=ghidra)
    assert (output / "receipt.json").read_bytes() == sentinel
    assert not list(tmp_path.glob(".bundle.tmp-*"))


def test_parent_identity_race_fails_closed_and_cleans(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "afd.sys"
    pdb = tmp_path / "afd.pdb"
    binary.write_bytes(b"MZ-driver")
    pdb.write_bytes(b"pdb")
    monkeypatch.setattr(bridge, "_require_exact_full_identity", lambda *args: None)
    calls = 0

    def identity(*args):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ValueError("simulated parent identity race")

    monkeypatch.setattr(bridge, "_require_directory_path_identity", identity)
    monkeypatch.setattr(bridge, "_toolchain_fingerprint", lambda home: {"fixed": True})
    monkeypatch.setattr(bridge, "_ghidra_version", lambda home: "11.4.2")

    def acquire(*args, **kwargs):
        facts = _facts()
        facts["driver_sha256"] = bridge._identity(args[0])
        facts["pdb_sha256"] = bridge._identity(args[1])
        return facts

    monkeypatch.setattr(bridge, "_acquire_entry_bridge_facts", acquire)
    monkeypatch.setattr(bridge, "pe_codeview_identity", lambda path: ("GUID", 1, "afd.pdb"))
    monkeypatch.setattr(bridge, "pdb_codeview_identity", lambda path: ("GUID", 4, True))
    monkeypatch.setattr(bridge, "_pe_entry_rva", lambda path: 0x95010)
    monkeypatch.setattr(
        bridge,
        "pdb_function_records",
        lambda *args: [PdbFunctionRecord("DriverEntry", "public-function", 1, 0x4EA14, 0x4FA14)],
    )
    with pytest.raises(ValueError, match="identity race"):
        bridge.produce_windows_driver_entry_bridge(
            binary, pdb, tmp_path / "raced", ghidra_home=tmp_path
        )
    assert not (tmp_path / "raced").exists()
    assert not list(tmp_path.glob(".raced.tmp-*"))


class _Symbol:
    def __init__(self, parameter: bool, index: int):
        self.parameter = parameter
        self.index = index

    def isParameter(self):
        return self.parameter

    def getCategoryIndex(self):
        return self.index


class _High:
    def __init__(self, symbol):
        self.symbol = symbol

    def getSymbol(self):
        return self.symbol


class _Node:
    def __init__(self, name="RCX", size=8, definition=None, symbol=None):
        self.name = name
        self.size = size
        self.definition = definition
        self.symbol = symbol

    def __str__(self):
        return f"{self.name}-{id(self)}"

    def getSize(self):
        return self.size

    def getDef(self):
        return self.definition

    def getAddress(self):
        return self

    def getHigh(self):
        return _High(self.symbol) if self.symbol is not None else None


class _Call:
    def __init__(self, argument):
        self.inputs = [None, argument]

    def getNumInputs(self):
        return len(self.inputs)

    def getInput(self, index):
        return self.inputs[index]


class _Register:
    def __init__(self, name):
        self.name = name

    def getName(self):
        return self.name


class _Program:
    def getRegister(self, address, size):
        return _Register(address.name)


class _Definition:
    def __init__(self, opcode, source, output):
        self.opcode = opcode
        self.source = source
        self.output = output

    def getMnemonic(self):
        return self.opcode

    def getNumInputs(self):
        return 1

    def getInput(self, index):
        assert index == 0
        return self.source

    def getOutput(self):
        return self.output


@pytest.mark.parametrize(
    ("node", "message"),
    [
        (_Node(symbol=None), "formal input"),
        (_Node(name="R8", symbol=_Symbol(True, 0)), "original RCX"),
        (_Node(symbol=_Symbol(True, 1)), "formal input"),
        (_Node(size=4, symbol=_Symbol(True, 0)), "not 8 bytes"),
    ],
)
def test_argument_proof_rejects_undefined_wrong_register_index_and_width(
    node, message
) -> None:
    with pytest.raises(ValueError, match=message):
        bridge_ghidra._preserved_argument_path(
            _Call(node), 1, "RCX", 0, _Program(), object(), 0x140000000
        )


def test_return_derivation_rejects_width_change_and_unrelated_value() -> None:
    source = _Node(size=4)
    unrelated = _Node(size=4)
    assert bridge_ghidra._derives_through_copy_cast(source, source) == (True, 0)
    assert bridge_ghidra._derives_through_copy_cast(unrelated, source)[0] is False
    widened = _Node(size=8)
    widened.definition = _Definition("CAST", source, widened)
    assert bridge_ghidra._derives_through_copy_cast(widened, source)[0] is False


def test_same_block_dominance_requires_operation_order() -> None:
    class Seq:
        def __init__(self, order):
            self.order = order

        def getTarget(self):
            return self

        def getOffset(self):
            return 0x1000

        def getOrder(self):
            return self.order

    class Op:
        def __init__(self, block, order):
            self.block = block
            self.sequence = Seq(order)

        def getParent(self):
            return self.block

        def getSeqnum(self):
            return self.sequence

    block = object()
    before, after = Op(block, 1), Op(block, 2)
    assert bridge_ghidra._dominates_op(None, before, after)
    assert not bridge_ghidra._dominates_op(None, after, before)


def test_dominator_entry_uses_generic_address_api() -> None:
    class Address:
        def getOffset(self):
            return 0x140095010

    class Function:
        def getEntryPoint(self):
            return Address()

    class Block:
        def getStart(self):
            return Address()

        def getInSize(self):
            return 0

    class High:
        def __init__(self):
            self.block = Block()

        def getBasicBlocks(self):
            return [self.block]

        def getFunction(self):
            return Function()

    high = High()
    blocks, dominators = bridge_ghidra._dominators(high)
    assert blocks == [high.block]
    assert dominators[high.block] == {high.block}


def test_native_low_pcode_rejects_eax_and_callother() -> None:
    class Register(_Register):
        def getBaseRegister(self):
            return _Register("RAX")

    class Output:
        def isRegister(self):
            return True

        def getAddress(self):
            return self

        def getSize(self):
            return 4

    class Program:
        def getRegister(self, address, size):
            return Register("EAX")

    class Op:
        def __init__(self, opcode, output=None):
            self.opcode = opcode
            self.output = output

        def getMnemonic(self):
            return self.opcode

        def getOutput(self):
            return self.output

        def getNumInputs(self):
            return 0

    assert bridge_ghidra._native_low_pcode_writes([Op("COPY", Output())], Program()) is None
    assert bridge_ghidra._native_low_pcode_writes([Op("CALLOTHER")], Program()) is None
