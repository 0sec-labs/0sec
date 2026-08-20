"""Ghidra adapter for the bounded AFD local selector profile."""

from __future__ import annotations

import hashlib
import shutil
import struct
import tempfile
from pathlib import Path
from typing import Any

from .windows_ioctl_ghidra_export import (
    _pe_machine,
    _requested_ghidra_version,
    _require_active_ghidra_version,
)


def acquire_afd_selector_facts(
    binary: Path, pdb: Path, ghidra_home: Path, *, handler_rva: int
) -> dict[str, object]:
    """Extract only the reviewed non-tracker AFD selector branch."""
    try:
        import pyghidra
    except ImportError as exc:  # pragma: no cover - environment contract
        raise RuntimeError("PyGhidra is unavailable for selector extraction") from exc

    requested = _requested_ghidra_version(ghidra_home)
    pyghidra.start(install_dir=ghidra_home)
    from ghidra.app.decompiler import DecompInterface
    from ghidra.framework import Application
    from ghidra.util.task import ConsoleTaskMonitor

    _require_active_ghidra_version(str(Application.getApplicationVersion()), requested)
    image_base, architecture, pointer_size = _pe_machine(binary)
    if architecture != "x86_64" or pointer_size != 8:
        raise ValueError("AFD selector profile requires an x86_64 PE")
    pe = _PeImage(binary)
    if pe.image_base != image_base:
        raise ValueError("PE image-base parsers disagree")

    with tempfile.TemporaryDirectory(prefix="zeroverse-afd-selector-") as temporary:
        target = Path(temporary) / "target.sys"
        shutil.copyfile(binary, target)
        shutil.copyfile(pdb, Path(temporary) / "target.pdb")
        with pyghidra.open_program(str(target)) as flat:
            program = flat.getCurrentProgram()
            manager = program.getFunctionManager()
            space = program.getAddressFactory().getDefaultAddressSpace()
            function = manager.getFunctionAt(space.getAddress(image_base + handler_rva))
            if (
                function is None
                or bool(function.isThunk())
                or int(function.getEntryPoint().getOffset()) != image_base + handler_rva
            ):
                raise ValueError("registered handler is not one exact non-thunk function")
            listing = program.getListing()
            instructions = {
                int(item.getAddress().getOffset()) - image_base: item
                for item in listing.getInstructions(function.getBody(), True)
            }
            decompiler = DecompInterface()
            decompiler.openProgram(program)
            decompile = decompiler.decompileFunction(function, 60, ConsoleTaskMonitor())
            if not decompile.decompileCompleted():
                raise ValueError("AFD selector handler decompilation failed")
            high_ops = list(decompile.getHighFunction().getPcodeOps())
            if not 1 <= len(high_ops) <= 4096:
                raise ValueError("AFD selector High-P-Code exceeds its bound")

            def exact(relative: int, encoded: bytes, label: str) -> Any:
                item = instructions.get(handler_rva + relative)
                if item is None or _bytes(item) != encoded:
                    raise ValueError(f"selector {label} native instruction mismatch")
                return item

            current = exact(0x0F, bytes.fromhex("488b9ab8000000"), "IRP stack load")
            tracker = _match_ff15(instructions, handler_rva + 0x1C, "tracker call")
            tracker_test = exact(0x28, bytes.fromhex("84c0"), "tracker result test")
            tracker_branch = exact(0x2A, bytes.fromhex("7551"), "tracker alternate branch")
            ioctl = exact(0x2C, bytes.fromhex("448b4318"), "IOCTL load")
            selector_copy = exact(0x30, bytes.fromhex("418bc0"), "selector copy")
            selector_shift = exact(0x33, bytes.fromhex("c1e802"), "selector shift")
            selector_mask = exact(0x36, bytes.fromhex("25ff030000"), "selector mask")
            selector_bound = exact(0x3B, bytes.fromhex("83f84a"), "selector bound")
            selector_reject = exact(0x3E, bytes.fromhex("7378"), "unsigned selector reject")
            base_item = instructions.get(handler_rva + 0x40)
            base_bytes = _bytes(base_item)
            if len(base_bytes) != 7 or base_bytes[:3] != bytes.fromhex("488d15"):
                raise ValueError("selector image-base LEA mismatch")
            base_rva = handler_rva + 0x40 + 7 + struct.unpack("<i", base_bytes[3:])[0]
            if base_rva != 0:
                raise ValueError("selector table base is not the exact PE image base")
            key_item = instructions.get(handler_rva + 0x47)
            key_bytes = _bytes(key_item)
            if len(key_bytes) != 8 or key_bytes[:4] != bytes.fromhex("44398482"):
                raise ValueError("selector key comparison mismatch")
            key_rva = struct.unpack("<i", key_bytes[4:])[0]
            if key_rva < 0:
                raise ValueError("selector key-table displacement is negative")
            key_reject = exact(0x4F, bytes.fromhex("7567"), "key mismatch reject")
            index_store = exact(0x51, bytes.fromhex("884301"), "selected index store")
            function_item = instructions.get(handler_rva + 0x54)
            function_bytes = _bytes(function_item)
            if len(function_bytes) != 8 or function_bytes[:4] != bytes.fromhex("488b84c2"):
                raise ValueError("selector function-table load mismatch")
            function_rva = struct.unpack("<i", function_bytes[4:])[0]
            if function_rva < 0:
                raise ValueError("selector function-table displacement is negative")
            target_test = exact(0x5C, bytes.fromhex("4885c0"), "null target test")
            null_reject = exact(0x5F, bytes.fromhex("7457"), "null target reject")
            stack_move = exact(0x61, bytes.fromhex("488bd3"), "stack argument move")
            irp_move = exact(0x64, bytes.fromhex("488bcf"), "IRP argument move")
            dispatch_call = instructions.get(handler_rva + 0x67)
            dispatch_bytes = _bytes(dispatch_call)
            if len(dispatch_bytes) != 5 or dispatch_bytes[0] != 0xE8:
                raise ValueError("selector CFG dispatch call mismatch")
            thunk_rva = handler_rva + 0x67 + 5 + struct.unpack("<i", dispatch_bytes[1:])[0]
            thunk = manager.getFunctionAt(space.getAddress(image_base + thunk_rva))
            if thunk is None or int(thunk.getEntryPoint().getOffset()) != image_base + thunk_rva:
                raise ValueError("selector dispatch thunk is not an exact function")
            thunk_name = str(thunk.getName())
            if thunk_name not in {"_guard_dispatch_icall", "guard_dispatch_icall"}:
                raise ValueError("selector dispatch call target is not _guard_dispatch_icall")
            thunk_first = listing.getInstructionAt(space.getAddress(image_base + thunk_rva))
            thunk_bytes = _bytes(thunk_first)
            if len(thunk_bytes) != 6 or thunk_bytes[:2] != bytes.fromhex("ff25"):
                raise ValueError("selector dispatch thunk is not an exact RIP-relative tail jump")
            slot_rva = thunk_rva + 6 + struct.unpack("<i", thunk_bytes[2:])[0]
            if image_base + slot_rva != pe.guard_cf_dispatch_pointer:
                raise ValueError("selector thunk is not bound to GuardCFDispatchFunctionPointer")
            if pe.guard_cf_check_pointer == pe.guard_cf_dispatch_pointer:
                raise ValueError("PE CFG check and dispatch pointer fields are indistinguishable")

            alternate = _match_ff15(instructions, handler_rva + 0x83, "tracker dispatch call")
            if _symbol_at(program, image_base + tracker[1]) != "NetioNrtIsTrackerDevice":
                raise ValueError("selector partition is not NetioNrtIsTrackerDevice")
            if _symbol_at(program, image_base + alternate[1]) != "NetioNrtDispatch":
                raise ValueError("selector alternate branch is not NetioNrtDispatch")

            key_raw, key_section = pe.read_extent(key_rva, 74 * 4)
            function_raw, function_section = pe.read_extent(function_rva, 74 * 8)
            if key_section != ".rdata" or function_section != ".rdata":
                raise ValueError("selector tables are not wholly contained in .rdata")
            keys = struct.unpack("<74I", key_raw)
            pointers = struct.unpack("<74Q", function_raw)
            rows: list[dict[str, object]] = []
            for index, (key, pointer) in enumerate(zip(keys, pointers, strict=True)):
                if ((key >> 2) & 0x3FF) != index:
                    raise ValueError("selector key does not map to its exact row")
                if pointer == 0 or pointer < image_base:
                    raise ValueError("selector table contains a null or non-image target")
                target_rva = pointer - image_base
                target_function = manager.getFunctionAt(space.getAddress(pointer))
                block = program.getMemory().getBlock(space.getAddress(pointer))
                if (
                    target_function is None
                    or bool(target_function.isThunk())
                    or int(target_function.getEntryPoint().getOffset()) != pointer
                    or block is None
                    or not bool(block.isExecute())
                ):
                    raise ValueError("selector row target is not an exact executable non-thunk")
                rows.append(
                    {
                        "index": index,
                        "key": f"0x{key:x}",
                        "target_rva": f"0x{target_rva:x}",
                        "target_section": str(block.getName()),
                        "exact_function_entry": True,
                        "executable": True,
                        "non_thunk": True,
                    }
                )

            return {
                "handler": {
                    "name": "AfdDispatchDeviceControl",
                    "rva": f"0x{handler_rva:x}",
                    "exact_function_entry": True,
                    "executable": True,
                    "non_thunk": True,
                },
                "irp_projection": {
                    "argument_register": "RDX",
                    "argument_width": 8,
                    "current_stack_location_offset": "0xb8",
                    "current_stack_location_width": 8,
                    "current_stack_location_load": _native(current, image_base),
                    "io_control_code_offset": "0x18",
                    "io_control_code_width": 4,
                    "io_control_code_load": _native(ioctl, image_base),
                },
                "partition": {
                    "predicate_import": "NetioNrtIsTrackerDevice",
                    "predicate_iat_rva": f"0x{tracker[1]:x}",
                    "predicate_call": _native(tracker[0], image_base),
                    "tested_register": "AL",
                    "local_branch": "AL==0",
                    "alternate_branch": "AL!=0",
                    "alternate_import": "NetioNrtDispatch",
                    "alternate_iat_rva": f"0x{alternate[1]:x}",
                    "alternate_call": _native(alternate[0], image_base),
                    "alternate_resolved": False,
                },
                "selector": {
                    "source_register": "R8D",
                    "width": 4,
                    "shift_right": 2,
                    "mask": "0x3ff",
                    "unsigned_upper_exclusive": 74,
                    "reject_condition": "index>=74",
                    "key_comparison_width": 4,
                    "key_equality_required": True,
                },
                "native_selector": {
                    "tracker_result_test": _native(tracker_test, image_base),
                    "tracker_alternate_branch": _native(tracker_branch, image_base),
                    "selector_copy": _native(selector_copy, image_base),
                    "selector_shift": _native(selector_shift, image_base),
                    "selector_mask": _native(selector_mask, image_base),
                    "selector_bound": _native(selector_bound, image_base),
                    "unsigned_reject_branch": _native(selector_reject, image_base),
                    "image_base_lea": _native(base_item, image_base),
                    "key_compare": _native(key_item, image_base),
                    "key_mismatch_branch": _native(key_reject, image_base),
                    "selected_index_store": _native(index_store, image_base),
                    "function_table_load": _native(function_item, image_base),
                    "target_test": _native(target_test, image_base),
                    "null_reject_branch": _native(null_reject, image_base),
                    "stack_argument_move": _native(stack_move, image_base),
                    "irp_argument_move": _native(irp_move, image_base),
                },
                "key_table": _table(key_rva, 4, key_raw, key_section),
                "function_table": {
                    **_table(function_rva, 8, function_raw, function_section),
                    "all_entries_non_null": True,
                    "all_targets_exact_executable_non_thunk": True,
                },
                "rows": rows,
                "dispatch": {
                    "target_register": "RAX",
                    "target_load_width": 8,
                    "non_null_required": True,
                    "call": _native(dispatch_call, image_base),
                    "thunk_rva": f"0x{thunk_rva:x}",
                    "thunk_bytes": thunk_bytes.hex(),
                    "thunk_sha256": hashlib.sha256(thunk_bytes).hexdigest(),
                    "load_config_field": "GuardCFDispatchFunctionPointer",
                    "pointer_slot_rva": f"0x{slot_rva:x}",
                    "check_pointer_slot_rva": f"0x{pe.guard_cf_check_pointer - image_base:x}",
                    "tail_jump": True,
                    "rax_preserved_to_thunk": True,
                    "helper_name": "_guard_dispatch_icall",
                    "handler_transfer_opcode": "CALL",
                },
                "high_pcode": _high_pcode_corroboration(
                    high_ops, image_base=image_base, handler_rva=handler_rva
                ),
                "accounting": {
                    "addressed_rows": 74,
                    "unique_targets": len(set(pointers)),
                    "null_targets": 0,
                    "limits_hit": [],
                },
            }


def _bytes(instruction: Any) -> bytes:
    if instruction is None:
        return b""
    return bytes((int(value) & 0xFF) for value in instruction.getBytes())


def _native(instruction: Any, image_base: int) -> dict[str, object]:
    raw = _bytes(instruction)
    return {
        "rva": f"0x{int(instruction.getAddress().getOffset()) - image_base:x}",
        "bytes": raw.hex(),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _match_ff15(instructions: dict[int, Any], rva: int, label: str) -> tuple[Any, int]:
    instruction = instructions.get(rva)
    raw = _bytes(instruction)
    if len(raw) != 7 or raw[:3] != bytes.fromhex("48ff15"):
        raise ValueError(f"selector {label} mismatch")
    return instruction, rva + 7 + struct.unpack("<i", raw[3:])[0]


def _symbol_at(program: Any, address: int) -> str:
    space = program.getAddressFactory().getDefaultAddressSpace()
    symbol = program.getSymbolTable().getPrimarySymbol(space.getAddress(address))
    if symbol is None:
        raise ValueError("selector import has no primary symbol")
    name = str(symbol.getName())
    return name.removeprefix("__imp_")


def _table(rva: int, width: int, raw: bytes, section: str) -> dict[str, object]:
    return {
        "rva": f"0x{rva:x}",
        "section": section,
        "entry_width": width,
        "addressed_count": 74,
        "addressed_size": len(raw),
        "addressed_bytes": raw.hex(),
        "addressed_sha256": hashlib.sha256(raw).hexdigest(),
        "addressed_extent_complete": True,
        "pdb_declared_allocation_extent": False,
        "preferred_base_absolute_pointers": width == 8,
        "runtime_relocation_claimed": False,
    }


def _high_pcode_corroboration(
    ops: list[Any], *, image_base: int, handler_rva: int
) -> dict[str, object]:
    """Require strict optimized-pcode corroboration at the reviewed native sites."""
    forbidden = {"MULTIEQUAL", "SUBPIECE", "PIECE", "CALLOTHER"}

    def stage(
        name: str,
        relatives: set[int],
        required: set[str],
        *,
        output_size: int | None = None,
        constant: int | None = None,
    ) -> list[dict[str, object]]:
        selected = [
            op
            for op in ops
            if int(op.getSeqnum().getTarget().getOffset()) - image_base - handler_rva in relatives
        ]
        if not selected or any(str(op.getMnemonic()) in forbidden for op in selected):
            raise ValueError(f"selector {name} High-P-Code is absent or ambiguous")
        matching = [op for op in selected if str(op.getMnemonic()) in required]
        if len(matching) != 1:
            raise ValueError(f"selector {name} lacks one exact High-P-Code operation")
        operation = matching[0]
        output = operation.getOutput()
        if output_size is not None and (output is None or int(output.getSize()) != output_size):
            raise ValueError(f"selector {name} High-P-Code width mismatch")
        constants = sorted(
            int(operation.getInput(index).getOffset())
            for index in range(operation.getNumInputs())
            if bool(operation.getInput(index).isConstant())
        )
        if constant is not None and constants.count(constant) != 1:
            raise ValueError(f"selector {name} High-P-Code constant mismatch")
        return [_high_ref(operation, image_base)]

    return {
        "forbidden_opcodes": sorted(forbidden),
        "irp_current_stack_load": stage("IRP stack load", {0x0F}, {"LOAD"}, output_size=8),
        "ioctl_load": stage("IOCTL load", {0x2C}, {"LOAD"}, output_size=4),
        "shift": stage("selector shift", {0x33}, {"INT_RIGHT"}, output_size=4, constant=2),
        "mask": stage("selector mask", {0x36}, {"INT_AND"}, output_size=4, constant=0x3FF),
        "unsigned_bound": stage(
            "unsigned selector bound", {0x3B, 0x3E}, {"INT_LESS"}, output_size=1, constant=74
        ),
        "key_load": stage("key-table load", {0x47}, {"LOAD"}, output_size=4),
        "key_equality": stage(
            "full key equality", {0x47, 0x4F}, {"INT_EQUAL", "INT_NOTEQUAL"}, output_size=1
        ),
        "target_load": stage("function-table load", {0x54}, {"LOAD"}, output_size=8),
        "null_guard": stage(
            "null target guard",
            {0x5C, 0x5F},
            {"INT_EQUAL", "INT_NOTEQUAL"},
            output_size=1,
            constant=0,
        ),
        # Optimized p-code collapses the native direct guard helper into the
        # guarded indirect transfer.  Native code separately binds the direct
        # CALL to the named _guard_dispatch_icall function and its FF25 thunk.
        "guard_dispatch_call": stage("guard dispatch call", {0x67}, {"CALLIND"}, output_size=8),
        "reviewed_sites_corroborated": True,
        "descendant_closure_established": False,
        "global_extra_transforms_excluded": False,
    }


def _high_ref(operation: Any, image_base: int) -> dict[str, object]:
    output = operation.getOutput()
    constants = sorted(
        int(operation.getInput(index).getOffset())
        for index in range(operation.getNumInputs())
        if bool(operation.getInput(index).isConstant())
    )
    return {
        "instruction_rva": (
            f"0x{int(operation.getSeqnum().getTarget().getOffset()) - image_base:x}"
        ),
        "pcode_order": int(operation.getSeqnum().getOrder()),
        "opcode": str(operation.getMnemonic()),
        "output_size": None if output is None else int(output.getSize()),
        "input_sizes": [
            int(operation.getInput(index).getSize()) for index in range(operation.getNumInputs())
        ],
        "constants": constants,
    }


class _PeImage:
    def __init__(self, path: Path):
        self.raw = path.read_bytes()
        pe = struct.unpack_from("<I", self.raw, 0x3C)[0]
        if self.raw[pe : pe + 4] != b"PE\0\0":
            raise ValueError("selector input is not a PE")
        coff = pe + 4
        count = struct.unpack_from("<H", self.raw, coff + 2)[0]
        optional_size = struct.unpack_from("<H", self.raw, coff + 16)[0]
        optional = coff + 20
        if struct.unpack_from("<H", self.raw, optional)[0] != 0x20B:
            raise ValueError("selector input is not PE32+")
        self.image_base = struct.unpack_from("<Q", self.raw, optional + 24)[0]
        directory = optional + 112
        load_rva, load_size = struct.unpack_from("<II", self.raw, directory + 10 * 8)
        section_table = optional + optional_size
        self.sections: list[tuple[str, int, int, int, int, int]] = []
        for index in range(count):
            offset = section_table + index * 40
            name = self.raw[offset : offset + 8].split(b"\0", 1)[0].decode("ascii")
            virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
                "<IIII", self.raw, offset + 8
            )
            characteristics = struct.unpack_from("<I", self.raw, offset + 36)[0]
            self.sections.append(
                (
                    name,
                    virtual_address,
                    max(virtual_size, raw_size),
                    raw_pointer,
                    raw_size,
                    characteristics,
                )
            )
        load_offset, _ = self._offset(load_rva, load_size)
        if load_size < 0x80 or struct.unpack_from("<I", self.raw, load_offset)[0] < 0x80:
            raise ValueError("selector PE load config is too small for CFG fields")
        self.guard_cf_check_pointer = struct.unpack_from("<Q", self.raw, load_offset + 0x70)[0]
        self.guard_cf_dispatch_pointer = struct.unpack_from("<Q", self.raw, load_offset + 0x78)[0]

    def _offset(self, rva: int, size: int) -> tuple[int, str]:
        if rva < 0 or size < 0 or rva + size < rva:
            raise ValueError("selector PE extent overflows")
        for name, start, extent, raw_pointer, raw_size, characteristics in self.sections:
            if start <= rva and rva + size <= start + min(extent, raw_size):
                if name == ".rdata" and (
                    characteristics & 0x80000000 or not characteristics & 0x40000000
                ):
                    raise ValueError("selector .rdata extent is writable or unreadable")
                return raw_pointer + rva - start, name
        raise ValueError("selector PE extent is not wholly backed by one section")

    def read_extent(self, rva: int, size: int) -> tuple[bytes, str]:
        offset, section = self._offset(rva, size)
        return self.raw[offset : offset + size], section
