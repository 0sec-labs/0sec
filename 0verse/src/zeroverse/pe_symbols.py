"""Small dependency-free PE/COFF symbol resolver for Windows crash frames."""

from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
import uuid
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any, NamedTuple

_IMAGE_RVA_RE = re.compile(r"(?:image[0-9a-f_]*|[^!\s]+)\+0x([0-9a-fA-F]+)$", re.I)
_PDB_PROC_RE = re.compile(
    r"S_(?:L|G)PROC32[^`]*`([^`]+)`\s*\n"
    r"\s*parent\s*=.*?addr\s*=\s*([0-9A-Fa-f]{4}):([0-9]+)",
    re.S,
)
_PDB_PUBLIC_RE = re.compile(
    r"S_PUB32[^`]*`([^`]+)`\s*\n"
    r"\s*flags\s*=\s*([^\n]*),\s*addr\s*=\s*([0-9A-Fa-f]{4}):([0-9]+)",
    re.S,
)
_DEFAULT_GHIDRA_RE = re.compile(r"^(?:FUN_|sub_)([0-9A-Fa-f]+)$")
_DEFAULT_IN_BODY_RE = re.compile(r"\b(?:FUN_|sub_)[0-9A-Fa-f]+\b")
_PDB_GUID_RE = re.compile(r"^\s*GUID:\s*\{([^}]+)\}\s*$", re.M)
_PDB_AGE_RE = re.compile(r"^\s*Age:\s*(\d+)\s*$", re.M)
_PDB_STRIPPED_RE = re.compile(r"^\s*Is stripped:\s*true\s*$", re.M | re.I)


class PdbFunctionRecord(NamedTuple):
    """One executable, function-flagged record retained from a PDB dump."""

    name: str
    kind: str
    segment: int
    offset: int
    rva: int


def _pe_layout(binary: str | Path) -> tuple[int, dict[int, tuple[int, bool]]]:
    """Return image base and section-number -> (RVA, executable) for a PE."""
    blob = Path(binary).read_bytes()
    pe = struct.unpack_from("<I", blob, 0x3C)[0]
    if blob[pe:pe + 4] != b"PE\0\0":
        raise ValueError("not a PE")
    header = pe + 4
    sections_count = struct.unpack_from("<H", blob, header + 2)[0]
    optional_size = struct.unpack_from("<H", blob, header + 16)[0]
    optional = header + 20
    magic = struct.unpack_from("<H", blob, optional)[0]
    if magic == 0x20B:
        image_base = struct.unpack_from("<Q", blob, optional + 24)[0]
    elif magic == 0x10B:
        image_base = struct.unpack_from("<I", blob, optional + 28)[0]
    else:
        raise ValueError("unsupported PE optional header")
    section_offset = optional + optional_size
    sections: dict[int, tuple[int, bool]] = {}
    for index in range(sections_count):
        entry = section_offset + index * 40
        rva = struct.unpack_from("<I", blob, entry + 12)[0]
        chars = struct.unpack_from("<I", blob, entry + 36)[0]
        sections[index + 1] = (rva, bool(chars & 0x20000000))
    return image_base, sections


def pe_codeview_identity(binary: str | Path) -> tuple[str, int, str] | None:
    """Return canonical RSDS GUID, age, and recorded PDB name from a PE."""
    try:
        blob = Path(binary).read_bytes()
        pe = struct.unpack_from("<I", blob, 0x3C)[0]
        if blob[pe:pe + 4] != b"PE\0\0":
            return None
        header = pe + 4
        count = struct.unpack_from("<H", blob, header + 2)[0]
        optional_size = struct.unpack_from("<H", blob, header + 16)[0]
        optional = header + 20
        magic = struct.unpack_from("<H", blob, optional)[0]
        directory = optional + (112 if magic == 0x20B else 96 if magic == 0x10B else -1)
        if directory < optional:
            return None
        debug_rva, debug_size = struct.unpack_from("<II", blob, directory + 6 * 8)
        section_offset = optional + optional_size
        sections: list[tuple[int, int, int, int]] = []
        for index in range(count):
            entry = section_offset + index * 40
            virtual_size, rva, raw_size, raw = struct.unpack_from("<IIII", blob, entry + 8)
            sections.append((rva, max(virtual_size, raw_size), raw, raw_size))

        def raw_offset(rva: int) -> int | None:
            for start, span, raw, raw_size in sections:
                delta = rva - start
                if 0 <= delta < span and delta < raw_size:
                    return raw + delta
            return None

        table = raw_offset(debug_rva)
        if table is None:
            return None
        for offset in range(table, table + debug_size, 28):
            kind = struct.unpack_from("<I", blob, offset + 12)[0]
            size, data_rva, data_raw = struct.unpack_from("<III", blob, offset + 16)
            if kind != 2 or size < 24:
                continue
            data = data_raw or raw_offset(data_rva)
            if data is None or blob[data:data + 4] != b"RSDS":
                continue
            guid = str(uuid.UUID(bytes_le=bytes(blob[data + 4:data + 20]))).upper()
            age = struct.unpack_from("<I", blob, data + 20)[0]
            end = blob.find(b"\0", data + 24, data + size)
            if end < 0:
                end = data + size
            name = blob[data + 24:end].decode("utf-8", "replace")
            return guid, age, name
        return None
    except (OSError, IndexError, struct.error, ValueError):
        return None


def _pdb_summary_identity(output: str) -> tuple[str, int, bool] | None:
    guid_match = _PDB_GUID_RE.search(output)
    age_match = _PDB_AGE_RE.search(output)
    if not guid_match or not age_match:
        return None
    try:
        guid = str(uuid.UUID(guid_match.group(1))).upper()
    except ValueError:
        return None
    return guid, int(age_match.group(1)), bool(_PDB_STRIPPED_RE.search(output))


def pdb_codeview_identity(
    pdb: str | Path,
    *,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[str, int, bool] | None:
    """Return GUID, age, and stripped state from an actual PDB summary.

    This is fail-closed and intentionally requires ``llvm-pdbutil``.  Callers
    that need provenance must not substitute the PE's recorded PDB name for an
    identity recovered from the PDB artifact itself.
    """
    tool = shutil.which("llvm-pdbutil")
    path = Path(pdb)
    if not tool or path.is_symlink() or not path.is_file():
        return None
    try:
        proc = run(
            [tool, "dump", "-summary", str(path)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return _pdb_summary_identity(proc.stdout)


def adjacent_pdb(binary: str | Path) -> Path | None:
    """Find an unambiguous adjacent PDB, with an explicit env override."""
    path = Path(binary)
    override = os.environ.get("ZEROVERSE_PDB")
    if override:
        candidate = Path(override)
        return candidate if candidate.is_file() else None
    exact = path.with_suffix(".pdb")
    if exact.is_file():
        return exact
    prefixed = sorted(path.parent.glob(f"{path.stem}-*.pdb"))
    if len(prefixed) == 1:
        return prefixed[0]
    all_pdbs = sorted(path.parent.glob("*.pdb"))
    return all_pdbs[0] if len(all_pdbs) == 1 else None


def pdb_functions(
    binary: str | Path,
    pdb: str | Path | None = None,
    *,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[int, str]:
    """Return executable function RVA -> name from a matching adjacent PDB.

    Parsing is deliberately fail-soft: absent tools, ambiguous PDB discovery,
    malformed output, timeouts, and out-of-range sections all return no symbols.
    """
    pdb_path = Path(pdb) if pdb is not None else adjacent_pdb(binary)
    tool = shutil.which("llvm-pdbutil")
    if pdb_path is None or not pdb_path.is_file() or not tool:
        return {}
    try:
        pe_identity = pe_codeview_identity(binary)
        if pe_identity is None:
            return {}
        _, sections = _pe_layout(binary)
        proc = run(
            [tool, "dump", "-summary", "-symbols", "-publics", str(pdb_path)],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        if proc.returncode != 0:
            return {}
        pdb_identity = _pdb_summary_identity(proc.stdout)
        if pdb_identity is None or pdb_identity[0] != pe_identity[0]:
            return {}
        if pdb_identity[1] != pe_identity[1] and not pdb_identity[2]:
            return {}
        found: dict[int, str] = {}
        for name, segment_text, offset_text in _PDB_PROC_RE.findall(proc.stdout):
            segment = int(segment_text, 16)
            section = sections.get(segment)
            if section is None or not section[1]:
                continue
            clean = name.lstrip("_")
            if clean:
                found[section[0] + int(offset_text)] = clean
        for name, flags, segment_text, offset_text in _PDB_PUBLIC_RE.findall(proc.stdout):
            if "function" not in flags.lower():
                continue
            segment = int(segment_text, 16)
            section = sections.get(segment)
            if section is None or not section[1]:
                continue
            clean = name.lstrip("_")
            if clean:
                found.setdefault(section[0] + int(offset_text), clean)
        return found
    except (OSError, ValueError, IndexError, struct.error, subprocess.SubprocessError):
        return {}


def pdb_function_records(
    binary: str | Path,
    pdb: str | Path,
    *,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[PdbFunctionRecord]:
    """Return exact executable PDB function records with segment/offset custody.

    Records are not collapsed by RVA, so callers can reject ambiguity before
    corroborating a structurally selected function.
    """
    tool = shutil.which("llvm-pdbutil")
    pdb_path = Path(pdb)
    if not tool or pdb_path.is_symlink() or not pdb_path.is_file():
        return []
    try:
        pe_identity = pe_codeview_identity(binary)
        if pe_identity is None:
            return []
        _, sections = _pe_layout(binary)
        proc = run(
            [tool, "dump", "-summary", "-symbols", "-publics", str(pdb_path)],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        if proc.returncode != 0:
            return []
        identity = _pdb_summary_identity(proc.stdout)
        if identity is None or identity[0] != pe_identity[0]:
            return []
        if identity[1] != pe_identity[1] and not identity[2]:
            return []
        records: list[PdbFunctionRecord] = []
        for name, segment_text, offset_text in _PDB_PROC_RE.findall(proc.stdout):
            segment = int(segment_text, 16)
            section = sections.get(segment)
            if section is not None and section[1] and name.lstrip("_"):
                offset = int(offset_text)
                records.append(
                    PdbFunctionRecord(
                        name.lstrip("_"), "procedure", segment, offset, section[0] + offset
                    )
                )
        for name, flags, segment_text, offset_text in _PDB_PUBLIC_RE.findall(proc.stdout):
            if "function" not in flags.lower():
                continue
            segment = int(segment_text, 16)
            section = sections.get(segment)
            if section is not None and section[1] and name.lstrip("_"):
                offset = int(offset_text)
                records.append(
                    PdbFunctionRecord(
                        name.lstrip("_"),
                        "public-function",
                        segment,
                        offset,
                        section[0] + offset,
                    )
                )
        return records
    except (OSError, ValueError, IndexError, struct.error, subprocess.SubprocessError):
        return []


def enrich_ghidra_symbols(adapter: Any, binary: str | Path) -> int:
    """Rename generic Ghidra functions from PDB RVAs throughout an adapter.

    Returns the number of renamed functions. The function is duck-typed so the
    PE helper stays independent of the heavy Ghidra backend.
    """
    try:
        image_base, _ = _pe_layout(binary)
    except (OSError, ValueError, IndexError, struct.error):
        return 0
    symbols = pdb_functions(binary)
    if not symbols:
        return 0
    meta = getattr(adapter, "meta", None)
    if meta is None:
        return 0
    decompiled = getattr(meta, "decompiled_c", None)
    if not isinstance(decompiled, dict):
        return 0
    rename: dict[str, str] = {}
    symbol_counts = Counter(symbols.values())
    for old in decompiled:
        match = _DEFAULT_GHIDRA_RE.match(old)
        if not match:
            continue
        rva = int(match.group(1), 16) - image_base
        new = symbols.get(rva)
        if new and symbol_counts[new] == 1 and new not in decompiled:
            rename[old] = new
    if not rename:
        return 0

    def renamed(name: str) -> str:
        return rename.get(name, name)

    def rewrite_body(text: str) -> str:
        return _DEFAULT_IN_BODY_RE.sub(lambda m: renamed(m.group(0)), text)

    meta.decompiled_c = {
        renamed(name): rewrite_body(body) for name, body in decompiled.items()
    }
    meta.exports = [renamed(name) for name in meta.exports]
    meta.callgraph = {
        renamed(caller): [renamed(callee) for callee in callees]
        for caller, callees in meta.callgraph.items()
    }
    meta.address_taken = [renamed(name) for name in meta.address_taken]
    for table in meta.ptr_tables:
        table["members"] = [renamed(str(name)) for name in table.get("members", [])]
        table["loaders"] = [renamed(str(name)) for name in table.get("loaders", [])]
    for edge in meta.unresolved_edges:
        if "func" in edge:
            edge["func"] = renamed(str(edge["func"]))

    for inst in getattr(adapter, "_by_id", {}).values():
        inst.func = renamed(inst.func)
        if inst.dest:
            inst.dest = renamed(inst.dest)
    adapter._defs = {
        (var, renamed(func)): value for (var, func), value in adapter._defs.items()
    }
    adapter._callers = {
        (renamed(func), index): value
        for (func, index), value in adapter._callers.items()
    }
    return len(rename)


def coff_functions(binary: str | Path) -> dict[int, str]:
    """Return function RVA -> name from a PE's optional COFF symbol table."""
    try:
        blob = Path(binary).read_bytes()
        pe = struct.unpack_from("<I", blob, 0x3C)[0]
        if blob[pe:pe + 4] != b"PE\0\0":
            return {}
        file_header = pe + 4
        sections_count = struct.unpack_from("<H", blob, file_header + 2)[0]
        symbol_offset, symbol_count = struct.unpack_from("<II", blob, file_header + 8)
        optional_size = struct.unpack_from("<H", blob, file_header + 16)[0]
        section_offset = file_header + 20 + optional_size
        sections: dict[int, int] = {}
        for index in range(sections_count):
            entry = section_offset + index * 40
            sections[index + 1] = struct.unpack_from("<I", blob, entry + 12)[0]
        if not symbol_offset or not symbol_count:
            return {}
        strings = symbol_offset + symbol_count * 18
        functions: dict[int, str] = {}
        index = 0
        while index < symbol_count:
            entry = symbol_offset + index * 18
            raw_name = blob[entry:entry + 8]
            value = struct.unpack_from("<I", blob, entry + 8)[0]
            section, symbol_type = struct.unpack_from("<hH", blob, entry + 12)
            aux = blob[entry + 17]
            if raw_name[:4] == b"\0\0\0\0":
                name_offset = struct.unpack_from("<I", raw_name, 4)[0]
                start = strings + name_offset
                end = blob.find(b"\0", start)
                name = blob[start:end].decode("utf-8", "replace") if end >= start else ""
            else:
                name = raw_name.rstrip(b"\0").decode("utf-8", "replace")
            if section > 0 and symbol_type == 0x20 and name and section in sections:
                functions[sections[section] + value] = name.lstrip("_")
            index += 1 + aux
        return functions
    except (OSError, IndexError, struct.error):
        return {}


def resolve_crash_frame(binary: str | Path, frames: list[str]) -> str:
    """Resolve the first image+RVA frame to its nearest preceding COFF function."""
    symbols = coff_functions(binary)
    if not symbols:
        return ""
    for frame in frames:
        match = _IMAGE_RVA_RE.search(frame)
        if not match:
            continue
        rva = int(match.group(1), 16)
        candidates = [address for address in symbols if address <= rva]
        if not candidates:
            continue
        address = max(candidates)
        if rva - address <= 0x100000:
            return symbols[address]
    return ""
