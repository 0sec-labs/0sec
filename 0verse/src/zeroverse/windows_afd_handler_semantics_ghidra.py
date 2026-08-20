"""Exact bounded Ghidra facts for AFD hypothesis-selected handler entries."""

from __future__ import annotations

import hashlib
import shutil
import tempfile
import time
from itertools import pairwise
from pathlib import Path
from typing import Any, cast

from .windows_ioctl_ghidra_export import (
    _pe_machine,
    _requested_ghidra_version,
    _require_active_ghidra_version,
)

MAX_FUNCTIONS = 33
MAX_TOTAL_BODY_BYTES = MAX_FUNCTIONS * 65536
MAX_TOTAL_INSTRUCTIONS = MAX_FUNCTIONS * 20000


def acquire_afd_handler_semantic_facts(
    binary: Path,
    pdb: Path,
    ghidra_home: Path,
    plans: list[dict[str, object]],
    *,
    side: str,
) -> dict[str, object]:
    """Extract all exact side-local entries named by the 33 inert plans."""
    try:
        import pyghidra
    except ImportError as exc:  # pragma: no cover - environment contract
        raise RuntimeError("PyGhidra is unavailable for AFD handler semantics") from exc
    if side not in {"side_a", "side_b"} or len(plans) != MAX_FUNCTIONS:
        raise ValueError("AFD handler semantics requires one exact 33-plan side")
    wall_cap = 300
    if any(
        _positive_exact_int(
            cast(dict[str, object], plan["static_limits"]).get(
                "max_wall_clock_seconds_per_side"
            ),
            wall_cap,
            "wall-clock cap",
        )
        != wall_cap
        for plan in plans
    ):
        raise ValueError("AFD plans disagree on the side wall-clock cap")
    started = time.monotonic()
    requested = _requested_ghidra_version(ghidra_home)
    pyghidra.start(install_dir=ghidra_home)
    from ghidra.framework import Application

    _require_active_ghidra_version(str(Application.getApplicationVersion()), requested)
    image_base, architecture, pointer_size = _pe_machine(binary)
    if architecture != "x86_64" or pointer_size != 8:
        raise ValueError("AFD handler semantics requires an x86_64 PE")
    requested_rows: list[tuple[str, int, list[int], list[str]]] = []
    seen_rvas: set[int] = set()
    for plan in plans:
        hypothesis_id = str(plan["hypothesis_id"])
        rva = int(str(plan[f"{side}_target_rva"]), 16)
        indices = list(cast(list[int], plan["row_indices"]))
        keys = list(cast(list[str], plan["ioctl_keys"]))
        if rva <= 0 or rva in seen_rvas:
            raise ValueError("AFD plans do not select 33 unique positive function RVAs")
        seen_rvas.add(rva)
        requested_rows.append((hypothesis_id, rva, indices, keys))

    with tempfile.TemporaryDirectory(prefix=f"zeroverse-afd-handler-{side}-") as temporary:
        target = Path(temporary) / "target.sys"
        shutil.copyfile(binary, target)
        shutil.copyfile(pdb, Path(temporary) / "target.pdb")
        with pyghidra.open_program(str(target)) as flat:
            program = flat.getCurrentProgram()
            manager = program.getFunctionManager()
            listing = program.getListing()
            memory = program.getMemory()
            space = program.getAddressFactory().getDefaultAddressSpace()
            functions: list[dict[str, object]] = []
            total_body = 0
            total_instructions = 0
            for plan, (hypothesis_id, rva, indices, keys) in zip(
                plans, requested_rows, strict=True
            ):
                _require_elapsed_within(started, wall_cap)
                limits = cast(dict[str, object], plan["static_limits"])
                body_cap = _positive_exact_int(
                    limits.get("max_function_bytes_per_side"), 65536, "function byte cap"
                )
                instruction_cap = _positive_exact_int(
                    limits.get("max_instructions_per_side"), 20000, "instruction cap"
                )
                function = manager.getFunctionAt(space.getAddress(image_base + rva))
                block = program.getMemory().getBlock(space.getAddress(image_base + rva))
                if (
                    function is None
                    or bool(function.isExternal())
                    or bool(function.isThunk())
                    or int(function.getEntryPoint().getOffset()) != image_base + rva
                    or block is None
                    or not bool(block.isExecute())
                ):
                    raise ValueError("AFD plan target is not one exact executable non-thunk")
                ranges, body_size, body_sha = _body_ranges(
                    function, memory, image_base, body_cap
                )
                total_body += body_size
                if total_body > MAX_TOTAL_BODY_BYTES:
                    raise ValueError("AFD selected body bytes exceed the total cap")
                instructions = _instructions(
                    listing, function, image_base, instruction_cap
                )
                if int(str(instructions[0]["rva"]), 16) != rva:
                    raise ValueError("AFD native listing does not begin at the exact plan entry")
                _bind_instruction_coverage(ranges, instructions)
                total_instructions += len(instructions)
                if total_instructions > MAX_TOTAL_INSTRUCTIONS:
                    raise ValueError("AFD selected instructions exceed the total cap")
                functions.append(
                    {
                        "hypothesis_id": hypothesis_id,
                        "row_indices": indices,
                        "ioctl_keys": keys,
                        "entry_rva": f"0x{rva:x}",
                        "exact_plan_entry_observed": True,
                        "executable": True,
                        "non_thunk": True,
                        "body": {
                            "ranges": ranges,
                            "gaps": _range_gaps(ranges),
                            "range_count": len(ranges),
                            "addressed_size": body_size,
                            "addressed_sha256": body_sha,
                            "disjoint_ranges_preserved": True,
                            "complete_ghidra_address_set_captured": True,
                        },
                        "instructions": instructions,
                        "instruction_count": len(instructions),
                        "inherited_limits": {
                            "max_function_bytes_per_side": body_cap,
                            "max_instructions_per_side": instruction_cap,
                            "max_wall_clock_seconds_per_side": wall_cap,
                        },
                    }
                )
            _require_elapsed_within(started, wall_cap)
            return {
                "side": side,
                "driver_sha256": _sha_file(binary),
                "pdb_sha256": _sha_file(pdb),
                "image_base": f"0x{image_base:x}",
                "architecture": architecture,
                "tool": {"name": "ghidra", "version": requested},
                "functions": functions,
                "accounting": {
                    "functions_requested": MAX_FUNCTIONS,
                    "functions_observed": len(functions),
                    "body_bytes_total": total_body,
                    "instructions_total": total_instructions,
                    "limits_hit": [],
                },
            }


def _body_ranges(
    function: Any, memory: Any, image_base: int, body_cap: int
) -> tuple[list[dict[str, object]], int, str]:
    iterator = function.getBody().getAddressRanges()
    ranges: list[dict[str, object]] = []
    digest = hashlib.sha256(b"0verse-afd-function-body-ranges-v1\0")
    total = 0
    while iterator.hasNext():
        item = iterator.next()
        start = int(item.getMinAddress().getOffset())
        end = int(item.getMaxAddress().getOffset())
        size = end - start + 1
        if start < image_base or size <= 0 or total + size > body_cap:
            raise ValueError("AFD function body range exceeds its bound")
        block = memory.getBlock(item.getMinAddress())
        end_block = memory.getBlock(item.getMaxAddress())
        if block is None or block != end_block or not bool(block.isExecute()):
            raise ValueError("AFD function body range is not wholly executable")
        try:
            from jpype import JArray, JByte
        except ImportError as exc:  # pragma: no cover - PyGhidra runtime contract
            raise RuntimeError("JPype is unavailable for exact Ghidra memory reads") from exc
        raw = JArray(JByte)(size)
        if int(memory.getBytes(item.getMinAddress(), raw)) != size:
            raise ValueError("AFD function body range is not fully readable")
        encoded = bytes((int(value) & 0xFF) for value in raw)
        rva = start - image_base
        digest.update(rva.to_bytes(8, "little"))
        digest.update(size.to_bytes(8, "little"))
        digest.update(encoded)
        ranges.append(
            {
                "start_rva": f"0x{rva:x}",
                "size": size,
                "bytes": encoded.hex(),
                "sha256": hashlib.sha256(encoded).hexdigest(),
                "executable": True,
                "uncovered_byte_intervals": [],
            }
        )
        total += size
    if not ranges:
        raise ValueError("AFD function body has no address ranges")
    return ranges, total, digest.hexdigest()


def _instructions(
    listing: Any, function: Any, image_base: int, instruction_cap: int
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for item in listing.getInstructions(function.getBody(), True):
        if len(rows) >= instruction_cap:
            raise ValueError("AFD function instruction count exceeds its cap")
        raw = bytes((int(value) & 0xFF) for value in item.getBytes())
        rows.append(
            {
                "rva": f"0x{int(item.getAddress().getOffset()) - image_base:x}",
                "bytes": raw.hex(),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "mnemonic": str(item.getMnemonicString()),
                "operands": str(item),
            }
        )
    if not rows:
        raise ValueError("AFD function has no native instructions")
    return rows


def _positive_exact_int(raw: object, expected: int, label: str) -> int:
    if type(raw) is not int or raw != expected:
        raise ValueError(f"AFD {label} differs from the inherited reviewed cap")
    return raw


def _range_gaps(ranges: list[dict[str, object]]) -> list[dict[str, object]]:
    gaps: list[dict[str, object]] = []
    for left, right in pairwise(ranges):
        left_end = int(str(left["start_rva"]), 16) + cast(int, left["size"])
        right_start = int(str(right["start_rva"]), 16)
        if right_start <= left_end:
            raise ValueError("AFD function body ranges overlap or are unordered")
        gaps.append({"start_rva": f"0x{left_end:x}", "size": right_start - left_end})
    return gaps


def _bind_instruction_coverage(
    ranges: list[dict[str, object]], instructions: list[dict[str, object]]
) -> None:
    for body_range in ranges:
        start = int(str(body_range["start_rva"]), 16)
        size = cast(int, body_range["size"])
        end = start + size
        covered = []
        for instruction in instructions:
            instruction_start = int(str(instruction["rva"]), 16)
            instruction_end = instruction_start + len(bytes.fromhex(str(instruction["bytes"])))
            if start <= instruction_start and instruction_end <= end:
                covered.append((instruction_start, instruction_end))
        cursor = start
        uncovered: list[dict[str, object]] = []
        for instruction_start, instruction_end in covered:
            if instruction_start < cursor:
                raise ValueError("AFD native instructions overlap")
            if instruction_start > cursor:
                uncovered.append(
                    {"start_rva": f"0x{cursor:x}", "size": instruction_start - cursor}
                )
            cursor = instruction_end
        if cursor < end:
            uncovered.append({"start_rva": f"0x{cursor:x}", "size": end - cursor})
        body_range["uncovered_byte_intervals"] = uncovered


def _require_elapsed_within(started: float, cap_seconds: int) -> None:
    if time.monotonic() - started > cap_seconds:
        raise ValueError("AFD side extraction exceeded its inherited wall-clock cap")


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
