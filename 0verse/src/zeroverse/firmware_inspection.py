"""Deterministic, hardware-free inspection of opaque firmware bytes.

The inspector reports observations and bounded heuristics. It does not unpack,
execute, decompile, transmit, or mutate firmware. Only explicit evidence earns a
candidate, and unsupported architecture or layout questions remain unknown.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import struct
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

from .acquisition import AcquisitionManifest, MemoryRegion, RegionRole
from .acquisition_bundle import AcquisitionBundle, ValidatedAcquisitionArtifact

FIRMWARE_INSPECTION_VERSION = "0verse.firmware-inspection/v1"
FIRMWARE_INSPECTOR_PROFILE = "zeroverse.firmware-inspection/deterministic-v1"

LoadAddressBasis = Literal["user-supplied", "inferred", "unknown"]
StringEncoding = Literal["ascii", "utf-16le"]
Endian = Literal["little", "big", "unknown"]

_MAX_FIRMWARE_BYTES = 512 * 1024 * 1024
_MAX_ENTROPY_WINDOWS = 4096
_MAX_STRINGS = 4096
_MAX_STRING_CHARS = 256
_MAX_PADDING_RUNS = 4096
_MAX_REPEAT_BLOCKS = 65536
_MAX_REPEAT_GROUPS = 1024
_MAX_REPEAT_OFFSETS = 64
_MAX_CONTAINER_CANDIDATES = 1024
_MAX_VECTOR_OFFSETS = 65536
_MIN_STRING_LENGTH = 4
_MIN_PADDING_LENGTH = 64
_MIN_REGION_LENGTH = 16

_ASCII_STRING = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16LE_STRING = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
_CALIBRATION_MARKERS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("calibration", re.compile(rb"calibrat(?:e|ed|ion)", re.I)),
    ("fuel-map", re.compile(rb"fuel[ _-]{0,8}map", re.I)),
    ("ignition-map", re.compile(rb"ignition[ _-]{0,8}map", re.I)),
    ("torque-map", re.compile(rb"torque[ _-]{0,8}map", re.I)),
)

_ELF_MACHINES: dict[int, tuple[str, int]] = {
    0x03: ("x86", 32),
    0x08: ("mips", 32),
    0x14: ("powerpc", 32),
    0x15: ("powerpc", 64),
    0x28: ("arm", 32),
    0x3E: ("x86-64", 64),
    0xB7: ("aarch64", 64),
    0xF3: ("risc-v", 0),
}
_PE_MACHINES: dict[int, tuple[str, int]] = {
    0x014C: ("x86", 32),
    0x0166: ("mips", 32),
    0x01C0: ("arm", 32),
    0x01C4: ("arm", 32),
    0x8664: ("x86-64", 64),
    0xAA64: ("aarch64", 64),
}
_MACHO_CPUS: dict[int, tuple[str, int]] = {
    7: ("x86", 32),
    12: ("arm", 32),
    18: ("powerpc", 32),
    0x01000007: ("x86-64", 64),
    0x0100000C: ("aarch64", 64),
    0x01000012: ("powerpc", 64),
}

_COMMON_CORTEX_M_LOAD_BASES = (
    0x00000000,
    0x08000000,
    0x10000000,
    0x1A000000,
    0x1C000000,
)


def _bounded_int(value: int | None, label: str, *, maximum: int = (1 << 64) - 1) -> None:
    if value is not None and (isinstance(value, bool) or value < 0 or value > maximum):
        raise ValueError(f"{label} must be a non-negative integer no larger than {maximum}")


def _confidence(value: int) -> int:
    if value < 0 or value > 100:
        raise ValueError("confidence must be between 0 and 100")
    return value


@dataclass(frozen=True)
class EntropyWindow:
    offset: int
    length: int
    entropy: float

    def to_dict(self) -> dict[str, object]:
        return {"offset": self.offset, "length": self.length, "entropy": self.entropy}


@dataclass(frozen=True)
class StringObservation:
    offset: int
    length: int
    encoding: StringEncoding
    value: str
    value_truncated: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "offset": self.offset,
            "length": self.length,
            "encoding": self.encoding,
            "value": self.value,
            "value_truncated": self.value_truncated,
        }


@dataclass(frozen=True)
class PaddingRun:
    offset: int
    length: int
    byte_value: int

    def to_dict(self) -> dict[str, object]:
        return {
            "offset": self.offset,
            "length": self.length,
            "byte_value": self.byte_value,
        }


@dataclass(frozen=True)
class RepeatedRegion:
    block_size: int
    sha256: str
    occurrence_count: int
    offsets: tuple[int, ...]
    offsets_truncated: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "block_size": self.block_size,
            "sha256": self.sha256,
            "occurrence_count": self.occurrence_count,
            "offsets": list(self.offsets),
            "offsets_truncated": self.offsets_truncated,
        }


@dataclass(frozen=True)
class ContainerCandidate:
    kind: str
    offset: int
    length: int | None
    confidence: int
    evidence: tuple[str, ...]
    load_address_hint: int | None = None

    def __post_init__(self) -> None:
        _confidence(self.confidence)

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "offset": self.offset,
            "length": self.length,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "load_address_hint": self.load_address_hint,
        }


@dataclass(frozen=True)
class ArchitectureCandidate:
    architecture: str
    bits: int
    endian: Endian
    confidence: int
    source: str
    offset: int
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        _confidence(self.confidence)

    def to_dict(self) -> dict[str, object]:
        return {
            "architecture": self.architecture,
            "bits": self.bits,
            "endian": self.endian,
            "confidence": self.confidence,
            "source": self.source,
            "offset": self.offset,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class VectorTableCandidate:
    architecture: str
    offset: int
    entry_count: int
    initial_stack_pointer: int
    reset_handler: int
    confidence: int
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        _confidence(self.confidence)

    def to_dict(self) -> dict[str, object]:
        return {
            "architecture": self.architecture,
            "offset": self.offset,
            "entry_count": self.entry_count,
            "initial_stack_pointer": self.initial_stack_pointer,
            "reset_handler": self.reset_handler,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class RegionCandidate:
    region_id: str
    artifact_offset: int
    length: int
    start: int | None
    role: RegionRole
    permissions: tuple[str, ...]
    confidence: int
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        _confidence(self.confidence)

    def to_dict(self) -> dict[str, object]:
        return {
            "region_id": self.region_id,
            "artifact_offset": self.artifact_offset,
            "length": self.length,
            "start": self.start,
            "role": self.role,
            "permissions": list(self.permissions),
            "confidence": self.confidence,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class FirmwareInspectionReport:
    """Canonical evidence report for one immutable firmware byte sequence."""

    artifact_id: str
    size: int
    sha256: str
    load_address: int | None
    load_address_basis: LoadAddressBasis
    load_address_evidence: tuple[str, ...]
    overall_entropy: float
    entropy_window_size: int
    entropy_windows: tuple[EntropyWindow, ...]
    string_count: int
    strings: tuple[StringObservation, ...]
    strings_truncated: bool
    padding_run_count: int
    padding_runs: tuple[PaddingRun, ...]
    padding_runs_truncated: bool
    repeat_block_size: int
    repeated_region_count: int
    repeated_regions: tuple[RepeatedRegion, ...]
    repeated_regions_truncated: bool
    container_candidate_count: int
    containers: tuple[ContainerCandidate, ...]
    containers_truncated: bool
    architectures: tuple[ArchitectureCandidate, ...]
    vector_tables: tuple[VectorTableCandidate, ...]
    regions: tuple[RegionCandidate, ...]
    unknowns: tuple[str, ...]
    schema_version: str = FIRMWARE_INSPECTION_VERSION
    inspector_profile: str = FIRMWARE_INSPECTOR_PROFILE

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "inspector_profile": self.inspector_profile,
            "artifact_id": self.artifact_id,
            "size": self.size,
            "sha256": self.sha256,
            "load_address": self.load_address,
            "load_address_basis": self.load_address_basis,
            "load_address_evidence": list(self.load_address_evidence),
            "overall_entropy": self.overall_entropy,
            "entropy_window_size": self.entropy_window_size,
            "entropy_windows": [item.to_dict() for item in self.entropy_windows],
            "string_count": self.string_count,
            "strings": [item.to_dict() for item in self.strings],
            "strings_truncated": self.strings_truncated,
            "padding_run_count": self.padding_run_count,
            "padding_runs": [item.to_dict() for item in self.padding_runs],
            "padding_runs_truncated": self.padding_runs_truncated,
            "repeat_block_size": self.repeat_block_size,
            "repeated_region_count": self.repeated_region_count,
            "repeated_regions": [item.to_dict() for item in self.repeated_regions],
            "repeated_regions_truncated": self.repeated_regions_truncated,
            "container_candidate_count": self.container_candidate_count,
            "containers": [item.to_dict() for item in self.containers],
            "containers_truncated": self.containers_truncated,
            "architectures": [item.to_dict() for item in self.architectures],
            "vector_tables": [item.to_dict() for item in self.vector_tables],
            "regions": [item.to_dict() for item in self.regions],
            "unknowns": list(self.unknowns),
        }

    def canonical_bytes(self) -> bytes:
        return (
            json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n"
        ).encode("ascii")


@dataclass(frozen=True)
class _Snapshot:
    data: bytes
    size: int
    sha256: str


@dataclass(frozen=True)
class _ContainerScan:
    candidate_count: int
    containers: tuple[ContainerCandidate, ...]
    architectures: tuple[ArchitectureCandidate, ...]
    truncated: bool


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_firmware_snapshot(path: Path) -> _Snapshot:
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise ValueError("firmware input must be a readable regular file") from exc
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("firmware input must be a regular non-symlink file")
    if before.st_size > _MAX_FIRMWARE_BYTES:
        raise ValueError(f"firmware input exceeds the {_MAX_FIRMWARE_BYTES}-byte inspection limit")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError("firmware input could not be opened") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise ValueError("firmware input path changed while it was opened")
        if opened.st_size > _MAX_FIRMWARE_BYTES:
            raise ValueError(
                f"firmware input exceeds the {_MAX_FIRMWARE_BYTES}-byte inspection limit"
            )

        chunks: list[bytes] = []
        digest = hashlib.sha256()
        count = 0
        try:
            while True:
                chunk = os.read(descriptor, min(1024 * 1024, _MAX_FIRMWARE_BYTES + 1 - count))
                if not chunk:
                    break
                chunks.append(chunk)
                digest.update(chunk)
                count += len(chunk)
                if count > _MAX_FIRMWARE_BYTES:
                    raise ValueError(
                        f"firmware input exceeds the {_MAX_FIRMWARE_BYTES}-byte inspection limit"
                    )
        except OSError as exc:
            raise ValueError("firmware input could not be read") from exc

        after = os.fstat(descriptor)
        try:
            path_after = os.lstat(path)
        except OSError as exc:
            raise ValueError("firmware input path changed while it was read") from exc
        if (
            count != opened.st_size
            or _stat_identity(after) != _stat_identity(opened)
            or not stat.S_ISREG(path_after.st_mode)
            or (path_after.st_dev, path_after.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise ValueError("firmware input bytes or path identity changed while read")
        return _Snapshot(b"".join(chunks), count, digest.hexdigest())
    finally:
        os.close(descriptor)


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    size = len(data)
    value = -sum(
        (count / size) * math.log2(count / size) for count in Counter(data).values()
    )
    return round(value, 6)


def _power_of_two_at_least(value: int, minimum: int) -> int:
    result = minimum
    while result < value:
        result *= 2
    return result


def _entropy_windows(data: bytes) -> tuple[int, tuple[EntropyWindow, ...]]:
    desired = max(256, math.ceil(len(data) / _MAX_ENTROPY_WINDOWS)) if data else 256
    window_size = _power_of_two_at_least(desired, 256)
    windows = tuple(
        EntropyWindow(offset, len(chunk), _shannon_entropy(chunk))
        for offset in range(0, len(data), window_size)
        if (chunk := data[offset : offset + window_size])
    )
    return window_size, windows


def _extract_strings(
    data: bytes,
) -> tuple[int, tuple[StringObservation, ...], bool]:
    found: list[StringObservation] = []
    total = 0
    patterns: tuple[tuple[StringEncoding, re.Pattern[bytes]], ...] = (
        ("ascii", _ASCII_STRING),
        ("utf-16le", _UTF16LE_STRING),
    )
    for encoding, pattern in patterns:
        for match in pattern.finditer(data):
            total += 1
            if len(found) >= _MAX_STRINGS:
                continue
            raw = match.group()
            value = raw.decode("ascii" if encoding == "ascii" else "utf-16le")
            truncated = len(value) > _MAX_STRING_CHARS
            found.append(
                StringObservation(
                    offset=match.start(),
                    length=len(raw),
                    encoding=encoding,
                    value=value[:_MAX_STRING_CHARS],
                    value_truncated=truncated,
                )
            )
    found.sort(key=lambda item: (item.offset, item.encoding, item.value))
    return total, tuple(found[:_MAX_STRINGS]), total > _MAX_STRINGS


def _scan_padding(data: bytes) -> tuple[int, tuple[PaddingRun, ...], bool]:
    found: list[PaddingRun] = []
    total = 0
    offset = 0
    while offset < len(data):
        value = data[offset]
        if value not in {0x00, 0xFF}:
            offset += 1
            continue
        end = offset + 1
        while end < len(data) and data[end] == value:
            end += 1
        length = end - offset
        if length >= _MIN_PADDING_LENGTH:
            total += 1
            if len(found) < _MAX_PADDING_RUNS:
                found.append(PaddingRun(offset, length, value))
        offset = end
    return total, tuple(found), total > len(found)


def _repeat_block_size(size: int) -> int:
    desired = max(64, math.ceil(size / _MAX_REPEAT_BLOCKS)) if size else 64
    return _power_of_two_at_least(desired, 64)


def _scan_repeated_regions(
    data: bytes,
) -> tuple[int, int, tuple[RepeatedRegion, ...], bool]:
    block_size = _repeat_block_size(len(data))
    offsets_by_digest: dict[str, list[int]] = defaultdict(list)
    for offset in range(0, len(data) - block_size + 1, block_size):
        block = data[offset : offset + block_size]
        if block.count(block[:1]) == block_size:
            continue
        offsets_by_digest[hashlib.sha256(block).hexdigest()].append(offset)

    groups: list[RepeatedRegion] = []
    total = 0
    for digest, offsets in offsets_by_digest.items():
        if len(offsets) < 2:
            continue
        total += 1
        if len(groups) >= _MAX_REPEAT_GROUPS:
            continue
        kept = tuple(offsets[:_MAX_REPEAT_OFFSETS])
        groups.append(
            RepeatedRegion(
                block_size=block_size,
                sha256=digest,
                occurrence_count=len(offsets),
                offsets=kept,
                offsets_truncated=len(kept) != len(offsets),
            )
        )
    groups.sort(key=lambda item: (item.offsets[0], item.sha256))
    return block_size, total, tuple(groups), total > len(groups)


def _find_offsets(data: bytes, magic: bytes) -> Iterable[int]:
    start = 0
    while len(data) - start >= len(magic):
        offset = data.find(magic, start)
        if offset < 0:
            return
        yield offset
        start = offset + 1


def _elf_candidate(
    data: bytes, offset: int
) -> tuple[ContainerCandidate, ArchitectureCandidate | None]:
    if offset + 20 > len(data):
        return (
            ContainerCandidate("elf", offset, None, 45, ("elf-magic", "truncated-header")),
            None,
        )
    elf_class, elf_data = data[offset + 4], data[offset + 5]
    bits = {1: 32, 2: 64}.get(elf_class, 0)
    endian: Endian
    if elf_data == 1:
        endian = "little"
    elif elf_data == 2:
        endian = "big"
    else:
        endian = "unknown"
    if bits == 0 or endian == "unknown":
        return (
            ContainerCandidate(
                "elf", offset, None, 50, ("elf-magic", "invalid-class-or-endian")
            ),
            None,
        )
    order = "<" if endian == "little" else ">"
    machine = struct.unpack_from(order + "H", data, offset + 18)[0]
    arch, default_bits = _ELF_MACHINES.get(machine, (f"elf-machine-0x{machine:x}", bits))
    resolved_bits = bits or default_bits
    load_hint = _elf_load_address_hint(data, offset, bits, order)
    evidence = (
        "elf-header-valid",
        f"elf-class:{bits}",
        f"elf-endian:{endian}",
        f"elf-machine:0x{machine:x}",
    )
    container = ContainerCandidate("elf", offset, None, 98, evidence, load_hint)
    architecture = ArchitectureCandidate(
        arch,
        resolved_bits,
        endian,
        98 if machine in _ELF_MACHINES else 72,
        "elf-header",
        offset,
        evidence,
    )
    return container, architecture


def _elf_load_address_hint(data: bytes, offset: int, bits: int, order: str) -> int | None:
    header_size = 64 if bits == 64 else 52
    if offset + header_size > len(data):
        return None
    if bits == 64:
        phoff = struct.unpack_from(order + "Q", data, offset + 32)[0]
        phentsize, phnum = struct.unpack_from(order + "HH", data, offset + 54)
    else:
        phoff = struct.unpack_from(order + "I", data, offset + 28)[0]
        phentsize, phnum = struct.unpack_from(order + "HH", data, offset + 42)
    if phnum > 4096 or phentsize < (56 if bits == 64 else 32):
        return None
    hints: set[int] = set()
    for index in range(phnum):
        base = offset + phoff + index * phentsize
        if base + phentsize > len(data):
            return None
        p_type = struct.unpack_from(order + "I", data, base)[0]
        if p_type != 1:
            continue
        if bits == 64:
            file_offset = struct.unpack_from(order + "Q", data, base + 8)[0]
            virtual = struct.unpack_from(order + "Q", data, base + 16)[0]
        else:
            file_offset = struct.unpack_from(order + "I", data, base + 4)[0]
            virtual = struct.unpack_from(order + "I", data, base + 8)[0]
        if virtual >= file_offset:
            hints.add(int(virtual - file_offset))
    return next(iter(hints)) if len(hints) == 1 else None


def _pe_candidate(
    data: bytes, offset: int
) -> tuple[ContainerCandidate, ArchitectureCandidate | None]:
    if offset + 0x40 > len(data):
        return ContainerCandidate("pe", offset, None, 40, ("mz-magic", "truncated-dos")), None
    pe_relative = struct.unpack_from("<I", data, offset + 0x3C)[0]
    pe = offset + pe_relative
    if pe + 26 > len(data) or data[pe : pe + 4] != b"PE\x00\x00":
        return ContainerCandidate("pe", offset, None, 40, ("mz-magic", "pe-header-absent")), None
    machine = struct.unpack_from("<H", data, pe + 4)[0]
    optional = pe + 24
    optional_magic = struct.unpack_from("<H", data, optional)[0]
    bits = {0x10B: 32, 0x20B: 64}.get(optional_magic, 0)
    arch, default_bits = _PE_MACHINES.get(machine, (f"pe-machine-0x{machine:x}", bits))
    resolved_bits = bits or default_bits
    image_base: int | None = None
    if bits == 32 and optional + 32 <= len(data):
        image_base = struct.unpack_from("<I", data, optional + 28)[0]
    elif bits == 64 and optional + 32 <= len(data):
        image_base = struct.unpack_from("<Q", data, optional + 24)[0]
    evidence = (
        "mz-magic",
        "pe-signature-valid",
        f"pe-machine:0x{machine:x}",
        f"pe-optional-class:{bits or 'unknown'}",
    )
    container = ContainerCandidate("pe", offset, None, 98, evidence, image_base)
    architecture = ArchitectureCandidate(
        arch,
        resolved_bits,
        "little",
        98 if machine in _PE_MACHINES else 72,
        "pe-header",
        offset,
        evidence,
    )
    return container, architecture


def _macho_candidate(
    data: bytes, offset: int, magic: bytes
) -> tuple[ContainerCandidate, ArchitectureCandidate | None]:
    little = magic in {b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}
    bits = 64 if magic in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"} else 32
    endian: Endian = "little" if little else "big"
    if offset + 8 > len(data):
        return (
            ContainerCandidate("mach-o", offset, None, 45, ("mach-o-magic", "truncated")),
            None,
        )
    order = "<" if little else ">"
    cpu = struct.unpack_from(order + "I", data, offset + 4)[0]
    arch, default_bits = _MACHO_CPUS.get(cpu, (f"mach-o-cpu-0x{cpu:x}", bits))
    evidence = ("mach-o-header-valid", f"mach-o-cpu:0x{cpu:x}", f"mach-o-class:{bits}")
    return (
        ContainerCandidate("mach-o", offset, None, 96, evidence),
        ArchitectureCandidate(
            arch,
            bits or default_bits,
            endian,
            96 if cpu in _MACHO_CPUS else 70,
            "mach-o-header",
            offset,
            evidence,
        ),
    )


def _bounded_container(
    kind: str,
    data: bytes,
    offset: int,
    header_size: int,
    payload_size: int,
    evidence: tuple[str, ...],
) -> ContainerCandidate:
    length = header_size + payload_size
    bounded = payload_size >= 0 and offset + length <= len(data)
    return ContainerCandidate(
        kind,
        offset,
        length if bounded else None,
        95 if bounded else 60,
        (*evidence, "declared-length-bounded" if bounded else "declared-length-out-of-range"),
    )


def _scan_containers(data: bytes) -> _ContainerScan:
    containers: list[ContainerCandidate] = []
    architectures: list[ArchitectureCandidate] = []
    candidate_count = 0

    def add(
        candidate: ContainerCandidate,
        architecture: ArchitectureCandidate | None = None,
    ) -> None:
        nonlocal candidate_count
        candidate_count += 1
        if len(containers) >= _MAX_CONTAINER_CANDIDATES:
            return
        containers.append(candidate)
        if architecture is not None:
            architectures.append(architecture)

    for offset in _find_offsets(data, b"\x7fELF"):
        add(*_elf_candidate(data, offset))
    for offset in _find_offsets(data, b"MZ"):
        add(*_pe_candidate(data, offset))
    for magic in (
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
    ):
        for offset in _find_offsets(data, magic):
            add(*_macho_candidate(data, offset, magic))

    signatures: tuple[tuple[str, bytes, int, tuple[str, ...]], ...] = (
        ("squashfs", b"hsqs", 82, ("squashfs-little-endian-magic",)),
        ("squashfs", b"sqsh", 78, ("squashfs-big-endian-magic",)),
        ("gzip", b"\x1f\x8b\x08", 82, ("gzip-deflate-header",)),
        ("xz", b"\xfd7zXZ\x00", 90, ("xz-stream-header",)),
        ("zip", b"PK\x03\x04", 78, ("zip-local-header",)),
        ("ubi", b"UBI#", 76, ("ubi-erase-counter-header",)),
        ("jffs2", b"\x85\x19", 58, ("jffs2-node-magic-little-endian",)),
        ("cramfs", b"E=\xcd(", 82, ("cramfs-little-endian-magic",)),
    )
    for kind, magic, confidence, evidence in signatures:
        for offset in _find_offsets(data, magic):
            add(ContainerCandidate(kind, offset, None, confidence, evidence))

    for offset in _find_offsets(data, b"'\x05\x19V"):
        if offset + 64 <= len(data):
            payload_size = struct.unpack_from(">I", data, offset + 12)[0]
            add(
                _bounded_container(
                    "uimage", data, offset, 64, payload_size, ("uimage-header-magic",)
                )
            )
        else:
            add(ContainerCandidate("uimage", offset, None, 55, ("uimage-magic", "truncated")))

    for offset in _find_offsets(data, b"\xd0\r\xfe\xed"):
        if offset + 8 <= len(data):
            total_size = struct.unpack_from(">I", data, offset + 4)[0]
            bounded = total_size >= 40 and offset + total_size <= len(data)
            add(
                ContainerCandidate(
                    "fdt",
                    offset,
                    total_size if bounded else None,
                    95 if bounded else 60,
                    (
                        "fdt-magic",
                        "declared-length-bounded" if bounded else "declared-length-out-of-range",
                    ),
                )
            )
        else:
            add(ContainerCandidate("fdt", offset, None, 55, ("fdt-magic", "truncated")))

    containers.sort(key=lambda item: (item.offset, item.kind, -item.confidence))
    architectures.sort(
        key=lambda item: (item.offset, item.architecture, item.bits, item.endian, item.source)
    )
    return _ContainerScan(
        candidate_count,
        tuple(containers),
        tuple(architectures),
        candidate_count > len(containers),
    )


def _candidate_vector_offsets(data_size: int, padding: tuple[PaddingRun, ...]) -> tuple[int, ...]:
    offsets = {0}
    for run in padding:
        offsets.add((run.offset + run.length + 3) & ~3)
    stride = _power_of_two_at_least(max(0x100, math.ceil(data_size / _MAX_VECTOR_OFFSETS)), 0x100)
    offsets.update(range(0, max(0, data_size - 31), stride))
    return tuple(sorted(offset for offset in offsets if offset + 32 <= data_size))


def _is_common_ram_pointer(value: int) -> bool:
    return 0x10000000 <= value < 0x40000000 and value % 4 == 0


def _scan_cortex_m_vectors(
    data: bytes,
    padding: tuple[PaddingRun, ...],
    load_address: int | None,
) -> tuple[VectorTableCandidate, ...]:
    candidates: list[VectorTableCandidate] = []
    for offset in _candidate_vector_offsets(len(data), padding):
        words = struct.unpack_from("<8I", data, offset)
        stack, reset = words[0], words[1]
        if not _is_common_ram_pointer(stack) or reset in {0, 0xFFFFFFFF} or reset & 1 == 0:
            continue
        handler_words = [word for word in words[2:] if word not in {0, 0xFFFFFFFF}]
        odd_handlers = [word for word in handler_words if word & 1]
        if len(odd_handlers) < 2:
            continue
        reset_target = reset & ~1
        neighborhood = max(len(data) * 2, 1024 * 1024)
        nearby = [word for word in odd_handlers if abs((word & ~1) - reset_target) <= neighborhood]
        if load_address is None and len(nearby) < 2:
            continue

        evidence = [
            f"initial-sp-common-ram:0x{stack:08x}",
            f"thumb-reset-handler:0x{reset:08x}",
            f"odd-handler-entries:{len(odd_handlers)}/6",
        ]
        score = 65 + min(15, len(odd_handlers) * 3)
        if load_address is not None:
            image_end = load_address + len(data)
            mapped = load_address <= reset_target < image_end
            mapped_handlers = sum(
                load_address <= (word & ~1) < image_end for word in odd_handlers
            )
            evidence.append(
                "load-range-reset:"
                f"{'inside' if mapped else 'outside'}:0x{load_address:x}-0x{image_end:x}"
            )
            evidence.append(f"load-range-handlers:{mapped_handlers}/{len(odd_handlers)}")
            score += 18 if mapped and mapped_handlers >= 2 else -10
        candidates.append(
            VectorTableCandidate(
                architecture="arm-cortex-m",
                offset=offset,
                entry_count=8,
                initial_stack_pointer=stack,
                reset_handler=reset,
                confidence=max(0, min(99, score)),
                evidence=tuple(evidence),
            )
        )
    return tuple(sorted(candidates, key=lambda item: (item.offset, -item.confidence)))


def _infer_load_address(
    size: int,
    vectors: tuple[VectorTableCandidate, ...],
    containers: tuple[ContainerCandidate, ...],
) -> tuple[int | None, tuple[str, ...]]:
    hints: dict[int, set[str]] = defaultdict(set)
    for container in containers:
        if (
            container.offset == 0
            and container.load_address_hint is not None
            and container.load_address_hint <= (1 << 64) - 1 - size
        ):
            hints[container.load_address_hint].add(
                f"{container.kind}-header@0x{container.offset:x}"
            )
    for vector in vectors:
        target = vector.reset_handler & ~1
        matching = [base for base in _COMMON_CORTEX_M_LOAD_BASES if base <= target < base + size]
        if len(matching) == 1:
            hints[matching[0]].add(f"cortex-m-reset@0x{vector.offset:x}:0x{target:x}")
    if len(hints) != 1:
        return None, ()
    value = next(iter(hints))
    return value, tuple(sorted(hints[value]))


def _architecture_candidates(
    container_architectures: tuple[ArchitectureCandidate, ...],
    vectors: tuple[VectorTableCandidate, ...],
) -> tuple[ArchitectureCandidate, ...]:
    candidates = list(container_architectures)
    candidates.extend(
        ArchitectureCandidate(
            architecture=vector.architecture,
            bits=32,
            endian="little",
            confidence=vector.confidence,
            source="vector-table",
            offset=vector.offset,
            evidence=vector.evidence,
        )
        for vector in vectors
    )
    candidates.sort(
        key=lambda item: (item.offset, item.source, item.architecture, item.bits, item.endian)
    )
    return tuple(candidates)


def _non_padding_spans(size: int, padding: tuple[PaddingRun, ...]) -> tuple[tuple[int, int], ...]:
    spans: list[tuple[int, int]] = []
    cursor = 0
    for run in padding:
        if run.offset > cursor and run.offset - cursor >= _MIN_REGION_LENGTH:
            spans.append((cursor, run.offset))
        cursor = max(cursor, run.offset + run.length)
    if size > cursor and size - cursor >= _MIN_REGION_LENGTH:
        spans.append((cursor, size))
    return tuple(spans)


def _calibration_evidence(data: bytes) -> tuple[str, ...]:
    return tuple(name for name, pattern in _CALIBRATION_MARKERS if pattern.search(data))


def _region_candidates(
    data: bytes,
    sha256: str,
    load_address: int | None,
    load_basis: LoadAddressBasis,
    padding: tuple[PaddingRun, ...],
    containers: tuple[ContainerCandidate, ...],
    vectors: tuple[VectorTableCandidate, ...],
) -> tuple[RegionCandidate, ...]:
    spans = _non_padding_spans(len(data), padding)
    vector_offsets = [item.offset for item in vectors]
    multiple_vectors = len(vector_offsets) >= 2
    candidates: list[RegionCandidate] = []
    for start_offset, end_offset in spans:
        span_vectors = [item for item in vectors if start_offset <= item.offset < end_offset]
        span_containers = [
            item for item in containers if start_offset <= item.offset < end_offset
        ]
        calibration = _calibration_evidence(data[start_offset:end_offset])
        role: RegionRole
        confidence: int
        evidence: list[str] = ["bounded-by-padding-or-artifact-edge"]
        if span_vectors:
            first = span_vectors[0]
            if multiple_vectors and first.offset == min(vector_offsets):
                role = "bootloader"
                confidence = min(95, first.confidence)
                evidence.extend(
                    (f"first-vector-table@0x{first.offset:x}", "multiple-vector-tables")
                )
            else:
                role = "code"
                confidence = first.confidence
                evidence.append(f"vector-table@0x{first.offset:x}")
        elif any(item.kind in {"elf", "pe", "mach-o"} for item in span_containers):
            executable = next(
                item for item in span_containers if item.kind in {"elf", "pe", "mach-o"}
            )
            role = "code"
            confidence = executable.confidence
            evidence.append(f"embedded-{executable.kind}@0x{executable.offset:x}")
        elif calibration:
            role = "calibration"
            confidence = min(88, 62 + len(calibration) * 6)
            evidence.extend(f"marker:{item}" for item in calibration)
        else:
            role = "data"
            confidence = 35
            evidence.append("no-supported-executable-or-calibration-evidence")
        if load_address is not None:
            region_start = load_address + start_offset
            evidence.append(f"load-address:{load_basis}")
        else:
            region_start = None
            evidence.append("load-address:unknown")
        length = end_offset - start_offset
        region_id = f"fw-{sha256[:12]}-{role}-{start_offset:08x}"
        candidates.append(
            RegionCandidate(
                region_id=region_id,
                artifact_offset=start_offset,
                length=length,
                start=region_start,
                role=role,
                permissions=("read", "execute") if role in {"bootloader", "code"} else ("read",),
                confidence=confidence,
                evidence=tuple(evidence),
            )
        )
    return tuple(candidates)


def inspect_firmware_bytes(
    data: bytes,
    *,
    artifact_id: str = "firmware",
    load_address: int | None = None,
    expected_size: int | None = None,
    expected_sha256: str | None = None,
) -> FirmwareInspectionReport:
    """Inspect an immutable byte sequence and return a canonical evidence report."""

    if not artifact_id or "\x00" in artifact_id:
        raise ValueError("artifact id must be non-empty text without NUL")
    _bounded_int(load_address, "load address")
    _bounded_int(expected_size, "expected size", maximum=_MAX_FIRMWARE_BYTES)
    immutable = bytes(data)
    if len(immutable) > _MAX_FIRMWARE_BYTES:
        raise ValueError(f"firmware input exceeds the {_MAX_FIRMWARE_BYTES}-byte inspection limit")
    if load_address is not None and load_address > (1 << 64) - 1 - len(immutable):
        raise ValueError("load address plus firmware size exceeds the 64-bit address space")
    digest = hashlib.sha256(immutable).hexdigest()
    if expected_size is not None and len(immutable) != expected_size:
        raise ValueError(
            f"firmware size mismatch: expected {expected_size}, found {len(immutable)}"
        )
    if expected_sha256 is not None and digest != expected_sha256:
        raise ValueError(f"firmware SHA-256 mismatch: expected {expected_sha256}, found {digest}")

    overall_entropy = _shannon_entropy(immutable)
    entropy_window_size, entropy_windows = _entropy_windows(immutable)
    string_count, strings, strings_truncated = _extract_strings(immutable)
    padding_count, padding, padding_truncated = _scan_padding(immutable)
    repeat_size, repeat_count, repeats, repeats_truncated = _scan_repeated_regions(immutable)
    container_scan = _scan_containers(immutable)

    initial_vectors = _scan_cortex_m_vectors(immutable, padding, None)
    inferred_load, inferred_evidence = _infer_load_address(
        len(immutable), initial_vectors, container_scan.containers
    )
    if load_address is not None:
        effective_load = load_address
        load_basis: LoadAddressBasis = "user-supplied"
        load_evidence: tuple[str, ...] = (f"caller-supplied:0x{load_address:x}",)
    elif inferred_load is not None:
        effective_load = inferred_load
        load_basis = "inferred"
        load_evidence = inferred_evidence
    else:
        effective_load = None
        load_basis = "unknown"
        load_evidence = ()
    vectors = _scan_cortex_m_vectors(immutable, padding, effective_load)
    architectures = _architecture_candidates(container_scan.architectures, vectors)
    regions = _region_candidates(
        immutable,
        digest,
        effective_load,
        load_basis,
        padding,
        container_scan.containers,
        vectors,
    )

    unknowns: list[str] = []
    if not container_scan.containers:
        unknowns.append("container-structure-not-recognized")
    if not architectures:
        unknowns.append("architecture-not-established")
    if not vectors:
        unknowns.append("vector-table-not-established")
    if effective_load is None:
        unknowns.append("load-address-not-established")
    if padding_truncated:
        unknowns.append("padding-observations-truncated")
    if strings_truncated:
        unknowns.append("string-observations-truncated")
    if repeats_truncated:
        unknowns.append("repeated-region-observations-truncated")
    if container_scan.truncated:
        unknowns.append("container-observations-truncated")
    if not regions:
        unknowns.append("candidate-regions-not-established")

    return FirmwareInspectionReport(
        artifact_id=artifact_id,
        size=len(immutable),
        sha256=digest,
        load_address=effective_load,
        load_address_basis=load_basis,
        load_address_evidence=load_evidence,
        overall_entropy=overall_entropy,
        entropy_window_size=entropy_window_size,
        entropy_windows=entropy_windows,
        string_count=string_count,
        strings=strings,
        strings_truncated=strings_truncated,
        padding_run_count=padding_count,
        padding_runs=padding,
        padding_runs_truncated=padding_truncated,
        repeat_block_size=repeat_size,
        repeated_region_count=repeat_count,
        repeated_regions=repeats,
        repeated_regions_truncated=repeats_truncated,
        container_candidate_count=container_scan.candidate_count,
        containers=container_scan.containers,
        containers_truncated=container_scan.truncated,
        architectures=architectures,
        vector_tables=vectors,
        regions=regions,
        unknowns=tuple(unknowns),
    )


def inspect_firmware(
    path: str | Path,
    *,
    artifact_id: str = "firmware",
    load_address: int | None = None,
    expected_size: int | None = None,
    expected_sha256: str | None = None,
) -> FirmwareInspectionReport:
    """Snapshot and inspect one regular file without following its final symlink."""

    snapshot = _read_firmware_snapshot(Path(path))
    if expected_size is not None and snapshot.size != expected_size:
        raise ValueError(f"firmware size mismatch: expected {expected_size}, found {snapshot.size}")
    if expected_sha256 is not None and snapshot.sha256 != expected_sha256:
        raise ValueError(
            f"firmware SHA-256 mismatch: expected {expected_sha256}, found {snapshot.sha256}"
        )
    return inspect_firmware_bytes(
        snapshot.data,
        artifact_id=artifact_id,
        load_address=load_address,
        expected_size=snapshot.size,
        expected_sha256=snapshot.sha256,
    )


def inspect_bundle_artifact(
    bundle: AcquisitionBundle,
    artifact_id: str,
    *,
    load_address: int | None = None,
) -> FirmwareInspectionReport:
    """Inspect one verified, offline-safe artifact from a validated bundle."""

    eligible = {item.artifact.artifact_id: item for item in bundle.analysis_artifacts()}
    artifact = eligible.get(artifact_id)
    if artifact is None:
        raise ValueError(
            f"artifact {artifact_id!r} is not a verified offline firmware analysis input"
        )
    if artifact.observed_size is None or artifact.observed_sha256 is None:
        raise AssertionError("validated analysis artifact lacks an observed identity")
    return inspect_firmware(
        artifact.path,
        artifact_id=artifact_id,
        load_address=load_address,
        expected_size=artifact.observed_size,
        expected_sha256=artifact.observed_sha256,
    )


def inspect_bundle(
    bundle: AcquisitionBundle,
    *,
    load_addresses: dict[str, int] | None = None,
) -> tuple[FirmwareInspectionReport, ...]:
    """Inspect every analysis-eligible artifact in manifest order."""

    overrides = load_addresses or {}
    eligible_ids = {item.artifact.artifact_id for item in bundle.analysis_artifacts()}
    unknown_overrides = sorted(overrides.keys() - eligible_ids)
    if unknown_overrides:
        raise ValueError(
            f"load-address overrides reference ineligible artifacts: {unknown_overrides}"
        )
    return tuple(
        inspect_bundle_artifact(
            bundle,
            item.artifact.artifact_id,
            load_address=overrides.get(item.artifact.artifact_id),
        )
        for item in bundle.artifacts
        if item.artifact.artifact_id in eligible_ids
    )


def _selected_regions(
    report: FirmwareInspectionReport, candidate_ids: Iterable[str] | None
) -> tuple[RegionCandidate, ...]:
    by_id = {item.region_id: item for item in report.regions}
    if candidate_ids is None:
        return report.regions
    requested = tuple(candidate_ids)
    if len(requested) != len(set(requested)):
        raise ValueError("candidate region ids must be unique")
    unknown = sorted(set(requested) - by_id.keys())
    if unknown:
        raise ValueError(f"unknown candidate region ids: {unknown}")
    requested_set = set(requested)
    return tuple(item for item in report.regions if item.region_id in requested_set)


def with_inspection_regions(
    manifest: AcquisitionManifest,
    report: FirmwareInspectionReport,
    *,
    candidate_ids: Iterable[str] | None = None,
) -> AcquisitionManifest:
    """Return a new manifest with selected inferred regions linked reciprocally.

    The source manifest and artifact are frozen and remain unchanged. Confidence
    and per-field evidence stay in the inspection report; the manifest records the
    conservative ``inferred`` basis required by AcquisitionManifest v1.
    """

    artifacts = {item.artifact_id: item for item in manifest.artifacts}
    artifact = artifacts.get(report.artifact_id)
    if artifact is None:
        raise ValueError(f"inspection artifact is absent from manifest: {report.artifact_id}")
    if (
        artifact.kind not in {"firmware-image", "memory-region"}
        or artifact.availability != "present"
        or artifact.integrity != "verified"
        or artifact.content == "encrypted"
    ):
        raise ValueError("inspection regions require a verified offline firmware artifact")
    if artifact.size != report.size or artifact.sha256 != report.sha256:
        raise ValueError("inspection report identity does not match the manifest artifact")

    selected = _selected_regions(report, candidate_ids)
    existing = {item.region_id: item for item in manifest.regions}
    additions: list[MemoryRegion] = []
    for candidate in selected:
        if candidate.artifact_offset + candidate.length > report.size:
            raise ValueError(
                f"candidate region exceeds the inspected artifact: {candidate.region_id}"
            )
        region = MemoryRegion(
            region_id=candidate.region_id,
            address_space="firmware-load" if candidate.start is not None else "artifact-offset",
            start=candidate.start,
            length=candidate.length,
            role=candidate.role,
            basis="inferred",
            permissions=candidate.permissions,
            artifact_id=artifact.artifact_id,
            artifact_offset=candidate.artifact_offset,
        )
        prior = existing.get(region.region_id)
        if prior is not None and prior != region:
            raise ValueError(f"candidate region id conflicts with the manifest: {region.region_id}")
        if prior is None:
            additions.append(region)

    linked_ids = tuple(
        dict.fromkeys((*artifact.region_ids, *(item.region_id for item in selected)))
    )
    updated_artifact = replace(artifact, region_ids=linked_ids)
    updated_artifacts = tuple(
        updated_artifact if item.artifact_id == artifact.artifact_id else item
        for item in manifest.artifacts
    )
    return replace(
        manifest,
        regions=(*manifest.regions, *additions),
        artifacts=updated_artifacts,
    )


def inspect_validated_artifact(
    artifact: ValidatedAcquisitionArtifact,
    *,
    load_address: int | None = None,
) -> FirmwareInspectionReport:
    """Inspect a standalone validated artifact when its analysis status is known."""

    item = artifact.artifact
    if (
        item.kind not in {"firmware-image", "memory-region"}
        or item.availability != "present"
        or item.integrity != "verified"
        or item.content == "encrypted"
        or artifact.observed_size is None
        or artifact.observed_sha256 is None
    ):
        raise ValueError("artifact is not a verified offline firmware analysis input")
    return inspect_firmware(
        artifact.path,
        artifact_id=item.artifact_id,
        load_address=load_address,
        expected_size=artifact.observed_size,
        expected_sha256=artifact.observed_sha256,
    )
