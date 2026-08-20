"""Ghidra adapter for the bounded AFD projected-registration profile."""

from __future__ import annotations

import hashlib
import shutil
import struct
import tempfile
from pathlib import Path
from typing import Any, cast

from .pe_symbols import PdbFunctionRecord
from .windows_ioctl_ghidra_export import (
    _operation_ref,
    _pe_machine,
    _requested_ghidra_version,
    _require_active_ghidra_version,
)


def acquire_projected_registration_facts(
    binary: Path,
    pdb: Path,
    ghidra_home: Path,
    *,
    driver_entry_rva: int,
    records: list[PdbFunctionRecord],
) -> dict[str, object]:
    """Prove the one reviewed projected assignment, or fail closed."""
    try:
        import pyghidra
    except ImportError as exc:
        raise RuntimeError("PyGhidra is unavailable for registration extraction") from exc

    requested = _requested_ghidra_version(ghidra_home)
    pyghidra.start(install_dir=ghidra_home)
    from ghidra.app.decompiler import DecompInterface
    from ghidra.framework import Application
    from ghidra.util.task import ConsoleTaskMonitor

    _require_active_ghidra_version(str(Application.getApplicationVersion()), requested)
    image_base, architecture, pointer_size = _pe_machine(binary)
    if architecture != "x86_64" or pointer_size != 8:
        raise ValueError("registration profile requires an x86_64 PE")
    with tempfile.TemporaryDirectory(prefix="zeroverse-registration-") as temporary:
        target = Path(temporary) / "target.sys"
        shutil.copyfile(binary, target)
        shutil.copyfile(pdb, Path(temporary) / "target.pdb")
        with pyghidra.open_program(str(target)) as flat:
            program = flat.getCurrentProgram()
            manager = program.getFunctionManager()
            space = program.getAddressFactory().getDefaultAddressSpace()
            function = manager.getFunctionAt(space.getAddress(image_base + driver_entry_rva))
            if (
                function is None
                or bool(function.isThunk())
                or int(function.getEntryPoint().getOffset()) != image_base + driver_entry_rva
            ):
                raise ValueError("DriverEntry is not one exact non-thunk function")
            monitor = ConsoleTaskMonitor()
            decompiler = DecompInterface()
            decompiler.openProgram(program)
            result = decompiler.decompileFunction(function, 60, monitor)
            if not result.decompileCompleted():
                raise ValueError("DriverEntry decompilation failed")
            ops = list(result.getHighFunction().getPcodeOps())
            if not 1 <= len(ops) <= 16384:
                raise ValueError("DriverEntry High-P-Code exceeds its bound")

            listing = program.getListing()
            instructions = list(listing.getInstructions(function.getBody(), True))
            aliases = [item for item in instructions if _instruction_bytes(item) == b"\x48\x8b\xd9"]
            if len(aliases) != 1:
                raise ValueError("DriverEntry lacks one exact native RCX-to-RBX alias")
            alias = aliases[0]
            alias_rva = int(alias.getAddress().getOffset()) - image_base
            _require_entry_fallthrough_alias(instructions, alias, function)

            candidates: list[tuple[Any, Any, int, bytes]] = []
            for instruction in instructions:
                encoded = _instruction_bytes(instruction)
                if encoded != b"\x48\x89\x83\xe0\x00\x00\x00":
                    continue
                previous = instruction.getPrevious()
                if previous is None:
                    continue
                lea = _instruction_bytes(previous)
                if len(lea) != 7 or lea[:3] != b"\x48\x8d\x05":
                    continue
                lea_rva = int(previous.getAddress().getOffset()) - image_base
                computed = lea_rva + 7 + struct.unpack("<i", lea[3:])[0]
                candidates.append((instruction, previous, computed, lea))
            if len(candidates) != 1:
                raise ValueError("registration has no unique direct qword assignment")
            store, target_lea, target_rva, target_lea_bytes = candidates[0]
            store_offset = int(store.getAddress().getOffset())
            if store_offset <= int(alias.getAddress().getOffset()):
                raise ValueError("registration assignment precedes the DriverObject alias")
            _audit_rbx_preserved(
                instructions,
                program,
                alias_offset=int(alias.getAddress().getOffset()),
                store_offset=store_offset,
            )

            record_matches = [
                item
                for item in records
                if item.name == "AfdDispatchDeviceControl" and item.rva == target_rva
            ]
            if len(record_matches) != 1:
                raise ValueError(
                    "registration target lacks one exact AfdDispatchDeviceControl record"
                )
            record = record_matches[0]
            callee = manager.getFunctionAt(space.getAddress(image_base + target_rva))
            block = program.getMemory().getBlock(space.getAddress(image_base + target_rva))
            if (
                callee is None
                or bool(callee.isThunk())
                or int(callee.getEntryPoint().getOffset()) != image_base + target_rva
                or block is None
                or not bool(block.isExecute())
            ):
                raise ValueError("registration target is not an exact internal executable function")

            store_rva = store_offset - image_base
            store_ops = [
                op
                for op in ops
                if str(op.getMnemonic()) == "STORE"
                and int(op.getSeqnum().getTarget().getOffset()) == store_offset
            ]
            if len(store_ops) != 1:
                raise ValueError("registration lacks one exact High-P-Code STORE corroboration")
            store_op = store_ops[0]
            if not _entry_reaches(result.getHighFunction(), store_op):
                raise ValueError("registration STORE is unreachable from DriverEntry")
            if not _reaches_unclassified_or_nonnegative_return(
                result.getHighFunction(), ops, store_op
            ):
                raise ValueError("registration STORE reaches only statically negative returns")
            if store_op.getNumInputs() < 3:
                raise ValueError("registration High-P-Code STORE is malformed")
            address_def = store_op.getInput(1).getDef()
            if address_def is None:
                raise ValueError("registration High-P-Code address is unresolved")
            address_path = _exact_address_path(store_op.getInput(1), program)
            target_path = _exact_target_path(store_op.getInput(2), image_base + target_rva)
            reachable_projected_stores = [
                op
                for op in ops
                if str(op.getMnemonic()) == "STORE"
                and _entry_reaches(result.getHighFunction(), op)
                and _is_exact_projected_store(op, program)
            ]
            later_projected_stores = [
                op
                for op in reachable_projected_stores
                if op is not store_op
                and _operation_can_follow(result.getHighFunction(), store_op, op)
            ]
            if later_projected_stores:
                raise ValueError(
                    "registration has a later reachable High-P-Code store to projected slot"
                )

            def refs(path: list[Any]) -> list[dict[str, object]]:
                rows = [_operation_ref(op, function, image_base) for op in path]
                return sorted(
                    {str(row): row for row in rows}.values(),
                    key=lambda row: (
                        str(row["instruction_rva"]),
                        int(cast(int, row["pcode_order"])),
                        str(row["opcode"]),
                    ),
                )

            store_bytes = _instruction_bytes(store)
            return {
                "driver_object_alias": {
                    "kind": "windows-x64-native-rcx-to-rbx/v1",
                    "rva": f"0x{alias_rva:x}",
                    "bytes": "488bd9",
                    "sha256": hashlib.sha256(b"\x48\x8b\xd9").hexdigest(),
                    "original_argument": "RCX",
                    "alias_register": "RBX",
                    "width": 8,
                    "unique_in_function": True,
                    "entry_fallthrough_dominates_registration": True,
                },
                "registration": {
                    "owner_function_rva": f"0x{driver_entry_rva:x}",
                    "projected_path": "_DRIVER_OBJECT.MajorFunction[14]",
                    "projected_offset": "0xe0",
                    "store_width": 8,
                    "high_pcode_base_register": "RCX",
                    "store": {
                        "rva": f"0x{store_rva:x}",
                        "bytes": store_bytes.hex(),
                        "sha256": hashlib.sha256(store_bytes).hexdigest(),
                        "high_pcode_ref": _operation_ref(store_op, function, image_base),
                    },
                    "address_dependency_refs": refs(address_path),
                    "target_dependency_refs": refs(target_path),
                    "target": {
                        "name": record.name,
                        "record_kind": record.kind,
                        "segment": record.segment,
                        "offset": record.offset,
                        "rva": f"0x{record.rva:x}",
                        "target_lea_rva": (
                            f"0x{int(target_lea.getAddress().getOffset()) - image_base:x}"
                        ),
                        "target_lea_bytes": target_lea_bytes.hex(),
                        "direct": True,
                        "internal_executable": True,
                        "non_thunk": True,
                        "unique_exact_record": True,
                    },
                    "unique_direct_assignment": True,
                    "later_reachable_projected_stores": 0,
                    "no_later_reachable_exact_projected_store": True,
                    "transitive_finality": False,
                    "entry_reachable": True,
                    "return_scope": "reachable-terminal-return-without-status-classification",
                },
                "accounting": {
                    "driver_entry_pcode_ops": len(ops),
                    "reachable_projected_stores": len(reachable_projected_stores),
                    "matching_assignments": len(candidates),
                    "later_reachable_projected_stores": 0,
                    "limits_hit": [],
                },
            }


def _instruction_bytes(instruction: Any) -> bytes:
    return bytes((int(value) & 0xFF) for value in instruction.getBytes())


def _native_register_writes(instruction: Any, program: Any) -> set[str]:
    writes: set[str] = set()
    pcode = list(instruction.getPcode())
    if not pcode or len(pcode) > 64:
        raise ValueError("native instruction has unavailable or excessive low P-Code")
    for op in pcode:
        output = op.getOutput()
        if output is None or not bool(output.isRegister()):
            continue
        register = program.getRegister(output.getAddress(), output.getSize())
        if register is None:
            raise ValueError("native register write cannot be resolved")
        base = register.getBaseRegister()
        writes.add(str((base if base is not None else register).getName()).upper())
    return writes


def _audit_rbx_preserved(
    instructions: list[Any], program: Any, *, alias_offset: int, store_offset: int
) -> None:
    for instruction in instructions:
        address = int(instruction.getAddress().getOffset())
        if alias_offset < address < store_offset and "RBX" in _native_register_writes(
            instruction, program
        ):
            raise ValueError("DriverObject RBX alias is redefined before registration")


def _require_entry_fallthrough_alias(instructions: list[Any], alias: Any, function: Any) -> None:
    if not instructions or int(instructions[0].getAddress().getOffset()) != int(
        function.getEntryPoint().getOffset()
    ):
        raise ValueError("DriverEntry native listing does not begin at its exact entry")
    alias_offset = int(alias.getAddress().getOffset())
    for index, instruction in enumerate(instructions):
        address = int(instruction.getAddress().getOffset())
        if address == alias_offset:
            return
        flow = instruction.getFlowType()
        fallthrough = instruction.getFallThrough()
        if (
            bool(flow.isCall())
            or bool(flow.isJump())
            or bool(flow.isConditional())
            or bool(flow.isComputed())
            or bool(flow.isTerminal())
            or fallthrough is None
            or index + 1 >= len(instructions)
            or int(fallthrough.getOffset()) != int(instructions[index + 1].getAddress().getOffset())
        ):
            raise ValueError("DriverObject alias is not on the entry fallthrough prefix")
    raise ValueError("DriverObject alias is absent from the entry fallthrough prefix")


def _exact_address_path(node: Any, program: Any) -> list[Any]:
    path: list[Any] = []
    current = node
    while current.getDef() is not None and str(current.getDef().getMnemonic()) in {"COPY", "CAST"}:
        wrapper = current.getDef()
        if wrapper.getNumInputs() != 1:
            raise ValueError("registration address wrapper has an unexpected arity")
        path.append(wrapper)
        current = wrapper.getInput(0)
    definition = current.getDef()
    if definition is None or str(definition.getMnemonic()) not in {"INT_ADD", "PTRSUB"}:
        raise ValueError("registration address is not one exact base-plus-0xe0 operation")
    if definition.getNumInputs() != 2:
        raise ValueError("registration address arithmetic has an unexpected arity")
    constants = [
        definition.getInput(index)
        for index in range(2)
        if bool(definition.getInput(index).isConstant())
    ]
    others = [
        definition.getInput(index)
        for index in range(2)
        if not bool(definition.getInput(index).isConstant())
    ]
    if len(constants) != 1 or int(constants[0].getOffset()) != 0xE0 or len(others) != 1:
        raise ValueError("registration address arithmetic is not exact +0xe0")
    path.append(definition)
    current = others[0]
    while current.getDef() is not None:
        operation = current.getDef()
        if str(operation.getMnemonic()) not in {"COPY", "CAST"} or operation.getNumInputs() != 1:
            raise ValueError("registration address base contains extra arithmetic")
        path.append(operation)
        current = operation.getInput(0)
    if not bool(current.isRegister()) or int(current.getSize()) != 8:
        raise ValueError("registration address base is not one raw 8-byte register")
    register = program.getRegister(current.getAddress(), current.getSize())
    base = register.getBaseRegister() if register is not None else None
    name = str((base if base is not None else register).getName()).upper() if register else ""
    if name != "RCX":
        raise ValueError("registration High-P-Code address base is not raw RCX")
    return path


def _exact_target_path(node: Any, target: int) -> list[Any]:
    path: list[Any] = []
    current = node
    seen: set[str] = set()
    while True:
        marker = str(current)
        if marker in seen:
            raise ValueError("registration target dependency is cyclic")
        seen.add(marker)
        if bool(current.isAddress()) or bool(current.isConstant()):
            if int(current.getOffset()) != target:
                raise ValueError("registration target dependency resolves to the wrong address")
            return path
        operation = current.getDef()
        if operation is not None and str(operation.getMnemonic()) == "PTRSUB":
            if operation.getNumInputs() != 2:
                raise ValueError("registration target PTRSUB has an unexpected arity")
            inputs = [operation.getInput(index) for index in range(2)]
            if not all(bool(item.isConstant()) for item in inputs) or {
                int(item.getOffset()) for item in inputs
            } != {0, target}:
                raise ValueError("registration target PTRSUB is not exact zero plus target")
            path.append(operation)
            return path
        if (
            operation is None
            or str(operation.getMnemonic())
            not in {
                "COPY",
                "CAST",
            }
            or operation.getNumInputs() != 1
        ):
            raise ValueError(
                "registration target contains extra arithmetic or an unknown operation"
            )
        path.append(operation)
        current = operation.getInput(0)


def _cfg(high: Any) -> tuple[dict[int, set[int]], int]:
    blocks = list(high.getBasicBlocks())
    if not blocks:
        raise ValueError("DriverEntry High-P-Code CFG is empty")
    edges = {
        int(block.getIndex()): {
            int(block.getOut(index).getIndex()) for index in range(block.getOutSize())
        }
        for block in blocks
    }
    entries = [int(block.getIndex()) for block in blocks if int(block.getInSize()) == 0]
    if len(entries) != 1:
        raise ValueError("DriverEntry CFG lacks one unique entry block")
    return edges, entries[0]


def _reachable(edges: dict[int, set[int]], start: int, target: int) -> bool:
    pending = [start]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if current == target:
            return True
        if current not in seen:
            seen.add(current)
            pending.extend(edges.get(current, set()) - seen)
    return False


def _entry_reaches(high: Any, operation: Any) -> bool:
    edges, entry = _cfg(high)
    return _reachable(edges, entry, int(operation.getParent().getIndex()))


def _is_exact_projected_store(operation: Any, program: Any) -> bool:
    if operation.getNumInputs() < 3:
        return False
    try:
        _exact_address_path(operation.getInput(1), program)
    except ValueError:
        return False
    return True


def _operation_can_follow(high: Any, earlier: Any, later: Any) -> bool:
    """Return whether ``later`` can execute after ``earlier`` in the High CFG."""
    edges, _entry = _cfg(high)
    earlier_block = int(earlier.getParent().getIndex())
    later_block = int(later.getParent().getIndex())
    if earlier_block != later_block:
        return _reachable(edges, earlier_block, later_block)
    earlier_order = int(earlier.getSeqnum().getOrder())
    later_order = int(later.getSeqnum().getOrder())
    if later_order > earlier_order:
        return True
    return any(_reachable(edges, successor, earlier_block) for successor in edges[earlier_block])


def _reaches_unclassified_or_nonnegative_return(
    high: Any, operations: list[Any], store: Any
) -> bool:
    edges, _entry = _cfg(high)
    start = int(store.getParent().getIndex())
    for operation in operations:
        if str(operation.getMnemonic()) != "RETURN":
            continue
        if not _reachable(edges, start, int(operation.getParent().getIndex())):
            continue
        if operation.getNumInputs() <= 1:
            return True
        value = operation.getInput(1)
        if not bool(value.isConstant()):
            return True
        width = int(value.getSize()) * 8
        raw = int(value.getOffset()) & ((1 << width) - 1)
        if raw < (1 << (width - 1)):
            return True
    return False
