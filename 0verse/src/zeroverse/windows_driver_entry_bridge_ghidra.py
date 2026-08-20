"""Reviewed High-P-Code adapter for the narrow DriverEntry bridge profile."""

from __future__ import annotations

import hashlib
import shutil
import struct
import tempfile
from pathlib import Path
from typing import Any

from .pe_symbols import PdbFunctionRecord, pdb_codeview_identity, pe_codeview_identity
from .windows_ioctl_ghidra_export import (
    _pe_machine,
    _requested_ghidra_version,
    _require_active_ghidra_version,
)
from .windows_ioctl_surface_inventory import _pe_entry_rva

_MAX_OPS = 4096
_MAX_TRANSFERS = 64
_FLOW_OPS = {"CALL", "CALLIND", "BRANCH", "CBRANCH", "BRANCHIND", "RETURN"}
_V3_SUFFIX = (
    (bytes.fromhex("488b5c2430"), "MOV"),
    (bytes.fromhex("4883c420"), "ADD"),
    (bytes.fromhex("5f"), "POP"),
    (bytes.fromhex("c3"), "RET"),
)
_V3_FORBIDDEN_LOW = {
    "BRANCH",
    "BRANCHIND",
    "CALL",
    "CALLIND",
    "CALLOTHER",
    "CBRANCH",
}


def acquire_entry_bridge_high_pcode(
    binary: Path,
    pdb: Path,
    ghidra_home: Path,
    records: list[PdbFunctionRecord],
    *,
    profile_version: str = "v2",
) -> dict[str, object]:
    """Prove the wrapper using control flow and data flow, never symbol selection."""
    try:
        import pyghidra
    except ImportError as exc:
        raise RuntimeError("PyGhidra is unavailable for entry bridge extraction") from exc
    requested = _requested_ghidra_version(ghidra_home)
    pyghidra.start(install_dir=ghidra_home)
    from ghidra.app.decompiler import DecompInterface
    from ghidra.framework import Application
    from ghidra.util.task import ConsoleTaskMonitor

    _require_active_ghidra_version(str(Application.getApplicationVersion()), requested)
    image_base, architecture, pointer_size = _pe_machine(binary)
    if architecture != "x86_64" or pointer_size != 8:
        raise ValueError("entry bridge profile requires an x86_64 PE")
    entry_rva = _pe_entry_rva(binary)
    with tempfile.TemporaryDirectory(prefix="zeroverse-entry-bridge-") as temporary:
        target = Path(temporary) / "target.sys"
        shutil.copyfile(binary, target)
        shutil.copyfile(pdb, Path(temporary) / "target.pdb")
        with pyghidra.open_program(str(target)) as flat:
            program = flat.getCurrentProgram()
            manager = program.getFunctionManager()
            space = program.getAddressFactory().getDefaultAddressSpace()
            wrapper = manager.getFunctionAt(space.getAddress(image_base + entry_rva))
            if (
                wrapper is None
                or bool(wrapper.isThunk())
                or int(wrapper.getEntryPoint().getOffset()) != image_base + entry_rva
            ):
                raise ValueError("PE entry is not one exact non-thunk wrapper")
            monitor = ConsoleTaskMonitor()
            decompiler = DecompInterface()
            decompiler.openProgram(program)
            result = decompiler.decompileFunction(wrapper, 60, monitor)
            if not result.decompileCompleted():
                raise ValueError("PE entry wrapper decompilation failed")
            high = result.getHighFunction()
            ops = list(high.getPcodeOps())
            if not 1 <= len(ops) <= _MAX_OPS:
                raise ValueError("PE entry wrapper High-P-Code exceeds its bound")
            transfers = [op for op in ops if str(op.getMnemonic()) in _FLOW_OPS]
            if not 2 <= len(transfers) <= _MAX_TRANSFERS:
                raise ValueError("PE entry wrapper control transfers exceed their bound")
            if any(str(op.getMnemonic()) in {"CALLIND", "BRANCHIND"} for op in transfers):
                raise ValueError("PE entry wrapper contains an indirect control transfer")
            calls = [op for op in transfers if str(op.getMnemonic()) == "CALL"]
            if len(calls) != 2:
                raise ValueError("PE entry wrapper must contain exactly two direct calls")
            targets = [_direct_target_rva(op, program, image_base) for op in calls]
            returns = [op for op in transfers if str(op.getMnemonic()) == "RETURN"]
            if not returns:
                raise ValueError("PE entry wrapper contains no return")
            if profile_version not in {"v2", "v3"}:
                raise ValueError("entry bridge profile version is unsupported")
            candidates: list[
                tuple[Any, list[dict[str, object]], list[dict[str, object]], dict[str, object]]
            ] = []
            for call in calls:
                try:
                    rcx = _preserved_argument_path(call, 1, "RCX", 0, program, wrapper, image_base)
                    rdx = _preserved_argument_path(call, 2, "RDX", 1, program, wrapper, image_base)
                except ValueError:
                    continue
                output = call.getOutput()
                propagated = output is not None and all(
                    ret.getNumInputs() > 1
                    and _derives_through_copy_cast(ret.getInput(1), output)[0]
                    for ret in returns
                )
                return_channel: dict[str, object] | None = (
                    {"kind": "high-pcode-ssa/v1"} if propagated else None
                )
                if (
                    return_channel is None
                    and profile_version == "v3"
                    and output is None
                    and all(ret.getNumInputs() == 1 for ret in returns)
                ):
                    return_channel = _native_v3_rax_suffix_proof(
                        binary, program, wrapper, call, targets[calls.index(call)], image_base
                    )
                if (
                    _dominates_returns(high, call, returns)
                    and all(_dominates_op(high, call, ret) for ret in returns)
                    and return_channel is not None
                ):
                    candidates.append((call, rcx, rdx, return_channel))
            if len(candidates) != 1:
                raise ValueError(
                    "wrapper does not have one unique structural entry-bridge candidate"
                )
            bridge, rcx_path, rdx_path, return_channel = candidates[0]
            bridge_index = calls.index(bridge)
            if bridge_index != 1:
                raise ValueError("structural entry bridge must follow the direct cookie call")
            cookie = calls[0]
            if not _dominates_op(high, cookie, bridge):
                raise ValueError("the unnamed direct pre-bridge call does not dominate the bridge")
            record_matches = [
                item
                for item in records
                if item.name == "DriverEntry" and item.rva == targets[bridge_index]
            ]
            if len(record_matches) != 1:
                raise ValueError("structural bridge target lacks one exact PDB DriverEntry record")
            record = record_matches[0]
            callee = manager.getFunctionAt(space.getAddress(image_base + record.rva))
            if (
                callee is None
                or bool(callee.isThunk())
                or int(callee.getEntryPoint().getOffset()) != image_base + record.rva
            ):
                raise ValueError(
                    "structural bridge target is not an exact non-thunk internal function"
                )
            pe_identity = pe_codeview_identity(binary)
            pdb_identity = pdb_codeview_identity(pdb)
            if pe_identity is None or pdb_identity is None:
                raise ValueError("entry bridge identities are unavailable")
            wrapper_facts: dict[str, object] = {
                "function_rva": f"0x{entry_rva:x}",
                "exact_pe_entry": True,
                "non_thunk": True,
                "pre_bridge_call": _call_fact(cookie, targets[0], wrapper, program, image_base),
                "bridge_call": _call_fact(
                    bridge, targets[bridge_index], wrapper, program, image_base
                ),
                "rcx_path": rcx_path,
                "rdx_path": rdx_path,
                "bridge_dominates_all_returns": True,
                "return_value_propagated": True,
                "return_refs": [_ref(op, wrapper, image_base) for op in returns],
                "bounded_control_transfers": [_ref(op, wrapper, image_base) for op in transfers],
            }
            if profile_version == "v3":
                wrapper_facts["return_channel"] = return_channel
            return {
                "schema_version": f"0verse.windows-driver-entry-bridge-facts/{profile_version}",
                "driver_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "pdb_sha256": hashlib.sha256(pdb.read_bytes()).hexdigest(),
                "pdb_identity": (
                    f"{pdb_identity[0]}:{pdb_identity[1]}:"
                    f"{'stripped' if pdb_identity[2] else 'full'}"
                ),
                "pe_codeview_identity": f"{pe_identity[0]}:{pe_identity[1]}:{pe_identity[2]}",
                "architecture": architecture,
                "image_base": f"0x{image_base:x}",
                "pe_entry_point_rva": f"0x{entry_rva:x}",
                "tool": {"name": "ghidra", "version": requested},
                "pdb_driver_entry": {
                    "name": record.name,
                    "record_kind": record.kind,
                    "function_flag": True,
                    "segment": record.segment,
                    "offset": record.offset,
                    "rva": f"0x{record.rva:x}",
                    "executable_section": True,
                    "unique_exact_record": True,
                },
                "wrapper": wrapper_facts,
                "accounting": {
                    "wrapper_pcode_ops": len(ops),
                    "control_transfers": len(transfers),
                    "direct_calls": len(calls),
                    "indirect_calls": 0,
                    "returns": len(returns),
                    "limits_hit": [],
                },
            }


def _direct_target_rva(op: Any, program: Any, image_base: int) -> int:
    target = op.getInput(0)
    if target is None or not bool(target.isAddress()):
        raise ValueError("wrapper CALL target is not direct")
    absolute = int(target.getAddress().getOffset())
    function = program.getFunctionManager().getFunctionAt(target.getAddress())
    block = program.getMemory().getBlock(target.getAddress())
    if (
        function is None
        or bool(function.isThunk())
        or block is None
        or not bool(block.isExecute())
        or absolute < image_base
    ):
        raise ValueError("wrapper CALL target is not an internal executable function")
    return absolute - image_base


def _native_v3_rax_suffix_proof(
    binary: Path,
    program: Any,
    wrapper: Any,
    bridge: Any,
    bridge_target_rva: int,
    image_base: int,
) -> dict[str, object] | None:
    """Prove the single reviewed AFD x64 native return suffix, or return None."""
    if bridge.getOutput() is not None:
        return None
    bridge_address = int(bridge.getSeqnum().getTarget().getOffset())
    listing = program.getListing()
    instruction = listing.getInstructionAt(
        program.getAddressFactory().getDefaultAddressSpace().getAddress(bridge_address)
    )
    if instruction is None:
        return None
    bridge_bytes = _instruction_bytes(instruction)
    if len(bridge_bytes) != 5 or bridge_bytes[0] != 0xE8:
        return None
    bridge_end = program.getAddressFactory().getDefaultAddressSpace().getAddress(
        bridge_address + len(bridge_bytes) - 1
    )
    if not bool(wrapper.getBody().contains(instruction.getAddress())) or not bool(
        wrapper.getBody().contains(bridge_end)
    ):
        return None
    computed_target = bridge_address + 5 + struct.unpack("<i", bridge_bytes[1:])[0]
    if computed_target != image_base + bridge_target_rva:
        return None
    if _pe_bytes_at_rva(binary, bridge_address - image_base, 5) != bridge_bytes:
        return None
    bridge_block = program.getMemory().getBlock(instruction.getAddress())
    if bridge_block is None or not bool(bridge_block.isExecute()):
        return None
    rows: list[dict[str, object]] = []
    cursor = bridge_address + 5
    suffix = bytearray()
    for expected_bytes, expected_mnemonic in _V3_SUFFIX:
        address = program.getAddressFactory().getDefaultAddressSpace().getAddress(cursor)
        current = listing.getInstructionAt(address)
        if current is None or not bool(wrapper.getBody().contains(address)):
            return None
        observed = _instruction_bytes(current)
        end_address = program.getAddressFactory().getDefaultAddressSpace().getAddress(
            cursor + len(observed) - 1
        )
        if not observed or not bool(wrapper.getBody().contains(end_address)):
            return None
        if (
            observed != expected_bytes
            or str(current.getMnemonicString()).upper() != expected_mnemonic
        ):
            return None
        flow_type = current.getFlowType()
        terminal = expected_bytes == b"\xc3"
        if (
            bool(flow_type.isCall())
            or bool(flow_type.isJump())
            or bool(flow_type.isComputed())
            or bool(flow_type.isConditional())
            or bool(flow_type.isTerminal()) != terminal
        ):
            return None
        fallthrough = current.getFallThrough()
        if terminal:
            if fallthrough is not None:
                return None
        elif fallthrough is None or int(fallthrough.getOffset()) != cursor + len(observed):
            return None
        block = program.getMemory().getBlock(address)
        if block != bridge_block or not bool(block.isExecute()):
            return None
        if _pe_bytes_at_rva(binary, cursor - image_base, len(observed)) != observed:
            return None
        pcode = list(current.getPcode())
        if not pcode or len(pcode) > 64:
            return None
        low = _native_low_pcode_writes(pcode, program)
        if low is None:
            return None
        writes, normalized = low
        rows.append(
            {
                "rva": f"0x{cursor - image_base:x}",
                "size": len(observed),
                "bytes": observed.hex(),
                "flow": "return" if observed == b"\xc3" else "fallthrough",
                "successors": []
                if observed == b"\xc3"
                else [f"0x{cursor + len(observed) - image_base:x}"],
                "low_pcode_sha256": hashlib.sha256("\n".join(normalized).encode()).hexdigest(),
                "resolved_writes": writes,
            }
        )
        suffix.extend(observed)
        cursor += len(observed)
    if len(rows) > 16 or len(suffix) > 64:
        return None
    return {
        "kind": "windows-x64-rax-preserved/v1",
        "conclusion": "DriverEntry NTSTATUS return channel preserved across wrapper suffix",
        "bridge": {
            "rva": f"0x{bridge_address - image_base:x}",
            "size": 5,
            "bytes": bridge_bytes.hex(),
            "sha256": hashlib.sha256(bridge_bytes).hexdigest(),
            "computed_target_rva": f"0x{bridge_target_rva:x}",
        },
        "suffix": {
            "start_rva": rows[0]["rva"],
            "end_rva": f"0x{cursor - image_base:x}",
            "sha256": hashlib.sha256(suffix).hexdigest(),
            "instructions": rows,
            "instruction_count": len(rows),
            "byte_count": len(suffix),
            "all_paths_return": True,
            "later_calls": 0,
            "rax_alias_writes": [],
            "limits_hit": [],
        },
    }


def _instruction_bytes(instruction: Any) -> bytes:
    return bytes(int(value) & 0xFF for value in instruction.getBytes())


def _normalized_low_op(op: Any) -> str:
    output = op.getOutput()
    inputs = [str(op.getInput(index)) for index in range(op.getNumInputs())]
    return "|".join((str(op.getMnemonic()), str(output), *inputs))


def _native_low_pcode_writes(
    pcode: list[Any], program: Any
) -> tuple[list[dict[str, object]], list[str]] | None:
    writes: list[dict[str, object]] = []
    normalized: list[str] = []
    for op in pcode:
        opcode = str(op.getMnemonic())
        if opcode in _V3_FORBIDDEN_LOW:
            return None
        normalized.append(_normalized_low_op(op))
        output = op.getOutput()
        if output is None:
            continue
        if bool(output.isRegister()):
            register = program.getRegister(output.getAddress(), output.getSize())
            if register is None:
                return None
            base = register.getBaseRegister()
            base_name = str((base if base is not None else register).getName()).upper()
            name = str(register.getName()).upper()
            if base_name == "RAX" or name in {"RAX", "EAX", "AX", "AL", "AH"}:
                return None
            writes.append({"kind": "register", "name": name, "base": base_name})
        else:
            writes.append(
                {
                    "kind": "storage",
                    "space": str(output.getAddress().getAddressSpace().getName()),
                    "offset": f"0x{int(output.getAddress().getOffset()):x}",
                    "size": int(output.getSize()),
                }
            )
    return writes, normalized


def _pe_bytes_at_rva(binary: Path, rva: int, size: int) -> bytes | None:
    data = binary.read_bytes()
    try:
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        count = struct.unpack_from("<H", data, pe + 6)[0]
        optional_size = struct.unpack_from("<H", data, pe + 20)[0]
        sections = pe + 24 + optional_size
        matches: list[int] = []
        for index in range(count):
            row = sections + index * 40
            virtual_size, start, raw_size, raw = struct.unpack_from("<IIII", data, row + 8)
            chars = struct.unpack_from("<I", data, row + 36)[0]
            delta = rva - start
            if (
                chars & 0x20000000
                and delta >= 0
                and delta + size <= raw_size
                and delta < max(virtual_size, raw_size)
            ):
                matches.append(raw + delta)
        if len(matches) != 1:
            return None
        offset = matches[0]
        return data[offset : offset + size] if offset + size <= len(data) else None
    except (IndexError, struct.error):
        return None


def _preserved_argument_path(
    op: Any,
    index: int,
    register: str,
    parameter_index: int,
    program: Any,
    wrapper: Any,
    image_base: int,
) -> list[dict[str, object]]:
    if op.getNumInputs() <= index:
        raise ValueError(f"DriverEntry bridge is missing {register}")
    current = op.getInput(index)
    if current.getSize() != 8:
        raise ValueError(f"DriverEntry {register} argument is not 8 bytes")
    path: list[dict[str, object]] = []
    seen: set[str] = set()
    while True:
        key = str(current)
        if key in seen or len(path) > 64:
            raise ValueError(f"DriverEntry {register} path is cyclic or unbounded")
        seen.add(key)
        definition = current.getDef()
        if definition is None:
            address = current.getAddress()
            observed = (
                program.getRegister(address, current.getSize()) if address is not None else None
            )
            if observed is None or str(observed.getName()).upper() != register:
                raise ValueError(f"DriverEntry {register} does not derive from original {register}")
            if current.getSize() != 8:
                raise ValueError(f"DriverEntry {register} formal input is not 8 bytes")
            high = current.getHigh()
            symbol = high.getSymbol() if high is not None else None
            if (
                symbol is None
                or not bool(symbol.isParameter())
                or int(symbol.getCategoryIndex()) != parameter_index
            ):
                raise ValueError(
                    f"DriverEntry {register} terminal is not the original formal input"
                )
            return list(reversed(path))
        if str(definition.getMnemonic()) not in {"COPY", "CAST"} or definition.getNumInputs() != 1:
            raise ValueError(f"DriverEntry {register} path contains a non-COPY/CAST operation")
        if (
            definition.getOutput() is None
            or definition.getOutput().getSize() != definition.getInput(0).getSize()
        ):
            raise ValueError(f"DriverEntry {register} path contains a width-changing operation")
        path.append(_ref(definition, wrapper, image_base))
        current = definition.getInput(0)


def _derives_through_copy_cast(value: Any, source: Any) -> tuple[bool, int]:
    current = value
    seen: set[str] = set()
    count = 0
    while current is not None and str(current) not in seen and count <= 64:
        if current == source:
            return True, count
        seen.add(str(current))
        definition = current.getDef()
        if (
            definition is None
            or str(definition.getMnemonic()) not in {"COPY", "CAST"}
            or definition.getNumInputs() != 1
        ):
            return False, count
        if (
            definition.getOutput() is None
            or definition.getOutput().getSize() != definition.getInput(0).getSize()
        ):
            return False, count
        current = definition.getInput(0)
        count += 1
    return False, count


def _dominates_returns(high: Any, bridge: Any, returns: list[Any]) -> bool:
    dominators = _dominators(high)
    if dominators is None:
        return False
    blocks, table = dominators
    bridge_block = bridge.getParent()
    if not all(bridge_block in table[ret.getParent()] for ret in returns):
        return False
    terminal_blocks = [block for block in blocks if block.getOutSize() == 0]
    return bool(terminal_blocks) and all(
        any(ret.getParent() == block for ret in returns) for block in terminal_blocks
    )


def _dominators(high: Any) -> tuple[list[Any], dict[Any, set[Any]]] | None:
    blocks = list(high.getBasicBlocks())
    if not blocks:
        return None
    entry_candidates = [
        block
        for block in blocks
        if block.getStart() is not None
        and int(block.getStart().getOffset()) == int(high.getFunction().getEntryPoint().getOffset())
    ]
    if len(entry_candidates) != 1:
        return None
    entry = entry_candidates[0]
    predecessors: dict[Any, set[Any]] = {}
    for block in blocks:
        predecessors[block] = {block.getIn(index) for index in range(block.getInSize())}
    dominators: dict[Any, set[Any]] = {
        block: ({block} if block == entry else set(blocks)) for block in blocks
    }
    changed = True
    rounds = 0
    while changed and rounds <= len(blocks) * 2:
        changed = False
        rounds += 1
        for block in blocks:
            if block == entry:
                continue
            incoming = predecessors[block]
            new = {block} | (
                set.intersection(*(dominators[parent] for parent in incoming))
                if incoming
                else set()
            )
            if new != dominators[block]:
                dominators[block] = new
                changed = True
    return None if changed else (blocks, dominators)


def _dominates_op(high: Any, first: Any, second: Any) -> bool:
    if first.getParent() == second.getParent():
        return _op_key(first) < _op_key(second)
    result = _dominators(high)
    return result is not None and first.getParent() in result[1][second.getParent()]


def _call_fact(
    op: Any, target_rva: int, wrapper: Any, program: Any, image_base: int
) -> dict[str, object]:
    address = (
        program.getAddressFactory().getDefaultAddressSpace().getAddress(image_base + target_rva)
    )
    block = program.getMemory().getBlock(address)
    return {
        "ref": _ref(op, wrapper, image_base),
        "target_rva": f"0x{target_rva:x}",
        "direct": True,
        "internal_executable": bool(block is not None and block.isExecute()),
    }


def _ref(op: Any, wrapper: Any, image_base: int) -> dict[str, object]:
    sequence = op.getSeqnum()
    return {
        "function_rva": f"0x{int(wrapper.getEntryPoint().getOffset()) - image_base:x}",
        "instruction_rva": f"0x{int(sequence.getTarget().getOffset()) - image_base:x}",
        "pcode_order": int(sequence.getOrder()),
        "opcode": str(op.getMnemonic()),
    }


def _op_key(op: Any) -> tuple[int, int]:
    sequence = op.getSeqnum()
    return int(sequence.getTarget().getOffset()), int(sequence.getOrder())
