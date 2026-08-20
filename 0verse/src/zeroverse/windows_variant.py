"""Deterministic guard-delta variant ranking for Windows binary exports.

This stage is deliberately static and non-weaponizing.  It transfers the guard
added between a known vulnerable/fixed pair to sibling functions in a current
Ghidra export. Output is hypothesis evidence only: ``candidate``. Reachability
and dynamic proof remain separate, independently gated stages.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import sys
import tempfile
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from ctypes import CDLL, c_char_p, c_int, get_errno
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .pe_symbols import pdb_codeview_identity, pe_codeview_identity
from .windows_public_pdb import PublicPdbReceipt

SCHEMA_VERSION = "0verse.windows-variant-campaign/v1"
RESULT_VERSION = "0verse.windows-variant/v1"
LABEL_VERSION = "0verse.windows-variant-labels/v1"
EVAL_VERSION = "0verse.windows-variant-eval/v1"
ANALYSIS_RECEIPT_VERSION = "0verse.ghidra-analysis-receipt/v1"
ANALYSIS_RECEIPT_VERSION_V2 = "0verse.ghidra-analysis-receipt/v2"
ANALYSIS_RECEIPT_VERSION_V3 = "0verse.ghidra-analysis-receipt/v3"
ANALYSIS_RECEIPT_VERSION_V4 = "0verse.ghidra-analysis-receipt/v4"
ANALYSIS_PRODUCER = "zeroverse.windows-analysis/v1"
ANALYSIS_FIXTURE_PRODUCER = "zeroverse.windows-analysis/fixture-v1"
IOCTL_ANALYSIS_PRODUCER = "zeroverse.windows-ioctl-analysis/v1"
_IOCTL_ANALYSIS_CACHE_DOMAIN = b"0verse-windows-ioctl-analysis-cache-v1\0"
_PUBLIC_IOCTL_ANALYSIS_CACHE_DOMAIN = b"0verse-windows-public-ioctl-analysis-cache-v1\0"
_BINARY_SIZE_CAP = 512 * 1024 * 1024
_PDB_SIZE_CAP = 2 * 1024 * 1024 * 1024
# Measured 2026-08-12: a full P-Code export of the 2.4 MB inbox vmswitch.sys is
# 312 MB (1,010,889 instructions; decompiled_c alone is 9.2 MB). The cap bounds
# loader memory, not trust; a slim projection export for this lane is the
# documented next boundary in docs/WINDOWS-VARIANT-RANK.md.
_EXPORT_SIZE_CAP = 512 * 1024 * 1024
_RECEIPT_SIZE_CAP = 1024 * 1024
_COPY_CHUNK_SIZE = 1024 * 1024
_ANALYSIS_CWD_LOCK = threading.RLock()
_DRIVER_BASENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.sys", re.I)

_ARTIFACT_FIELDS = frozenset(
    {
        "binary_path",
        "ghidra_export_path",
        "binary_sha256",
        "ghidra_export_sha256",
        "analysis_receipt_path",
        "analysis_receipt_sha256",
    }
)
_REACHABILITY_GRADES = frozenset(
    {"unknown", "unprivileged-ioctl", "ordinary-child", "root-only", "internal-only"}
)
_SINKS: dict[str, re.Pattern[str]] = {
    "copy": re.compile(
        r"\b(?:memcpy|memmove|__movsb|RtlCopyMemory|RtlMoveMemory|RtlCopyBytes)\s*\(",
        re.I,
    ),
    "fill": re.compile(r"\b(?:memset|RtlFillMemory|RtlZeroMemory)\s*\(", re.I),
    "indexed-store": re.compile(r"\b[A-Za-z_]\w*\s*\[[^\]]+\]\s*=", re.I),
    # CWE-59 link-following family: privileged path-resolution sinks. These are
    # the operations a service performs on an attacker-influenced path where an
    # Object Manager symlink / junction / CFAPI placeholder can redirect the
    # resolution between check and use (the RoguePlanet/ShieldBreak class).
    "file-open": re.compile(
        r"\b(?:CreateFileW|CreateFileA|CreateFile2|CreateFileTransactedW|NtCreateFile"
        r"|NtOpenFile|ZwCreateFile|ZwOpenFile|OpenFileById)\s*\(",
        re.I,
    ),
    "file-mutate": re.compile(
        r"\b(?:DeleteFileW|DeleteFileA|MoveFileW|MoveFileExW|MoveFileWithProgressW"
        r"|CopyFileW|CopyFileExW|CreateHardLinkW|ReplaceFileW|SetFileSecurityW"
        r"|SetNamedSecurityInfoW|NtSetInformationFile|ZwSetInformationFile)\s*\(",
        re.I,
    ),
    "registry-hive": re.compile(
        r"\b(?:RegLoadKeyW|RegLoadKeyA|RegRestoreKeyW|RegRestoreKeyA|RegReplaceKeyW"
        r"|RegLoadAppKeyW|RegUnLoadKeyW|RegUnLoadKeyA)\s*\(",
        re.I,
    ),
    "image-load": re.compile(
        r"\b(?:LoadLibraryW|LoadLibraryA|LoadLibraryExW|LoadLibraryExA|LdrLoadDll"
        r"|NtCreateSection|ZwCreateSection|CreateProcessW|CreateProcessA"
        r"|CreateProcessAsUserW|CreateProcessWithLogonW|CreateProcessWithTokenW)\s*\(",
        re.I,
    ),
}
# Sinks whose attacker-controlled operand is the path argument itself (arg 0),
# not a post-destination operand like the copy/fill length.
_PATH_SINKS = frozenset({"file-open", "file-mutate", "registry-hive", "image-load"})
_GUARDS: dict[str, re.Pattern[str]] = {
    "bounds": re.compile(
        r"\bif\s*\([^)]*\b(?:len(?:gth)?|size|count|index|offset|number|entries|elements)"
        r"\b[^)]*(?:<=|>=|<|>)",
        re.I | re.S,
    ),
    "checked-arithmetic": re.compile(
        r"\bRtl(?:SizeT|ULong|ULongLong)(?:Add|Sub|Mult)\s*\(", re.I
    ),
    "probe-read": re.compile(r"\b(?:ProbeForRead|MmProbeAndLockPages)\s*\(", re.I),
    "probe-write": re.compile(r"\bProbeForWrite\s*\(", re.I),
    "previous-mode": re.compile(r"\b(?:PreviousMode|ExGetPreviousMode)\b", re.I),
    "privilege": re.compile(r"\b(?:SeSinglePrivilegeCheck|SeAccessCheck)\s*\(", re.I),
    "partition-capability": re.compile(
        r"\bif\s*\([^)]*\b(?:root\s*partition|partition\s*type|capability|feature\s*bit)\b",
        re.I | re.S,
    ),
    # CWE-59 link-resolution guards. Unlike the memory-safety guards above,
    # their evidence legitimately appears AT or AFTER the sink (open-with-
    # no-reparse flags travel inside the open call; final-path verification
    # runs after the handle exists), so they are matched across the whole
    # sink window, not just the prefix. Symbolic names only: a decompiler
    # that renders flags as bare hex defeats this lens by design.
    "no-reparse-open": re.compile(
        r"\b(?:FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_OPEN_NO_RECALL"
        r"|FILE_OPEN_REPARSE_POINT|FILE_OPEN_NO_RECALL|OBJ_DONT_REPARSE)\b"
    ),
    "reparse-check": re.compile(
        r"\b(?:FSCTL_GET_REPARSE_POINT|FILE_ATTRIBUTE_REPARSE_POINT"
        r"|IO_REPARSE_TAG_SYMLINK|IO_REPARSE_TAG_MOUNT_POINT|IO_REPARSE_TAG_JUNCTION"
        r"|GetFileAttributesW|GetFileAttributesExW|FindFirstFileW|FindFirstFileExW"
        r"|NtQueryAttributesFile|NtQueryFullAttributesFile)\b",
        re.I,
    ),
    "final-path-verify": re.compile(
        r"\b(?:GetFinalPathNameByHandleW|GetFinalPathNameByHandleA|NtQueryObject"
        r"|NtQueryInformationFile|ZwQueryInformationFile|GetFileInformationByHandleEx"
        r"|GetFileInformationByName)\s*\(",
        re.I,
    ),
    "client-impersonation": re.compile(
        r"\b(?:ImpersonateLoggedOnUser|ImpersonateNamedPipeClient"
        r"|ImpersonateAnonymousToken|RpcImpersonateClient|CoImpersonateClient"
        r"|SetThreadToken)\s*\(",
        re.I,
    ),
}
# Guards whose evidence window spans the sink itself and the post-open region.
_POST_OPEN_GUARDS = frozenset(
    {"no-reparse-open", "reparse-check", "final-path-verify", "client-impersonation"}
)
# Hex-literal fallback for decompiler output that renders open flags as numbers:
# FILE_FLAG_OPEN_REPARSE_POINT / FILE_OPEN_REPARSE_POINT (0x00200000) and
# FILE_FLAG_OPEN_NO_RECALL / FILE_OPEN_NO_RECALL (0x00100000).
_NO_REPARSE_FLAG_BITS = 0x00200000 | 0x00100000
_HEX_LITERAL = re.compile(r"\b0x[0-9a-fA-F]+\b")
# Flags/create-options operand index per path-open callee (0-based). Everything
# else (DesiredAccess, share mode, disposition) can carry the same bit values
# for unrelated reasons and is deliberately not scanned.
_FLAG_ARG_INDEX = {
    "createfilew": 5,
    "createfilea": 5,
    "createfiletransactedw": 5,
    "ntcreatefile": 8,
    "zwcreatefile": 8,
    "ntopenfile": 5,
    "zwopenfile": 5,
}
_SIGNATURE = re.compile(r"^[^{;]+?\b[A-Za-z_]\w*\s*\(([^)]*)\)\s*\{", re.S)
_PARAM = re.compile(r"(?:\*|\s)([A-Za-z_]\w*)\s*(?:\[[^]]*\])?$")
_IF_CONDITION = re.compile(r"\bif\s*\(([^)]*)\)", re.I | re.S)
_IDENTIFIER = re.compile(r"\b[A-Za-z_]\w*\b")


@dataclass(frozen=True)
class Artifact:
    binary_path: Path
    export_path: Path
    binary_sha256: str
    export_sha256: str
    pdb_identity: str
    pdb_sha256: str
    analysis_receipt_sha256: str
    ghidra_version: str
    cache_key: str
    synthetic_fixture: bool
    export: dict[str, Any]
    public_pdb_receipt_sha256: str = ""
    public_pdb_requested_url: str = ""
    public_pdb_exact_age_match: bool | None = None
    public_pdb_pe_guid: str = ""
    public_pdb_pe_age: int | None = None
    public_pdb_pdb_guid: str = ""
    public_pdb_pdb_age: int | None = None
    pe_codeview_identity: str = ""


@dataclass(frozen=True)
class Reachability:
    grade: str = "unknown"
    evidence: str = ""


@dataclass(frozen=True)
class FunctionShape:
    name: str
    body: str
    rva: int
    sinks: frozenset[str]
    guards: frozenset[str]
    parameter_flow: tuple[str, str] | None
    toctou_window: bool = False


def rank_windows_variants(manifest_path: str | Path) -> dict[str, object]:
    """Load, validate, and rank one vulnerable/fixed/current campaign."""
    manifest_file = Path(manifest_path)
    manifest_bytes = manifest_file.read_bytes()
    raw = json.loads(manifest_bytes)
    if not isinstance(raw, dict):
        raise ValueError("Windows variant campaign must be a JSON object")
    _exact_fields(raw, {"schema_version", "seed", "current", "reachability"}, "campaign")
    if raw["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"unsupported Windows variant campaign schema: {raw['schema_version']}")
    seed = raw["seed"]
    if not isinstance(seed, dict):
        raise ValueError("seed must be an object")
    _exact_fields(seed, {"vulnerable", "fixed", "function", "reference"}, "seed")
    seed_function = _nonempty(seed["function"], "seed.function")
    reference = _nonempty(seed["reference"], "seed.reference")
    base = manifest_file.parent
    vulnerable = _load_artifact(seed["vulnerable"], base, "seed.vulnerable")
    fixed = _load_artifact(seed["fixed"], base, "seed.fixed")
    current = _load_artifact(raw["current"], base, "current")
    reachability = _load_reachability(raw["reachability"])

    vulnerable_shapes = _function_shapes(vulnerable.export)
    fixed_shapes = _function_shapes(fixed.export)
    current_shapes = _function_shapes(current.export)
    if seed_function not in vulnerable_shapes or seed_function not in fixed_shapes:
        raise ValueError("seed.function must exist in both vulnerable and fixed exports")
    vulnerable_seed = vulnerable_shapes[seed_function]
    fixed_seed = fixed_shapes[seed_function]
    if not vulnerable_seed.sinks:
        raise ValueError("seed vulnerable function has no supported sensitive sink geometry")
    guard_delta = fixed_seed.guards - vulnerable_seed.guards
    if not guard_delta:
        raise ValueError("seed pair has no supported security guard delta")

    candidates: list[dict[str, object]] = []
    for name, shape in current_shapes.items():
        if name == seed_function:
            continue
        matched_sinks = shape.sinks & vulnerable_seed.sinks
        if not matched_sinks:
            continue
        missing_guards = guard_delta - shape.guards
        if not missing_guards:
            continue
        boundary = reachability.get(name, Reachability())
        score = _score(
            shape,
            matched_sinks,
            vulnerable_seed.sinks,
            missing_guards,
            guard_delta,
        )
        status = "candidate"
        source_path = (
            [f"parameter:{shape.parameter_flow[0]}", f"sink:{shape.parameter_flow[1]}"]
            if shape.parameter_flow
            else []
        )
        candidates.append(
            {
                "function": name,
                "function_address": f"0x{shape.rva:x}" if shape.rva else "",
                "status": status,
                "score": score,
                "matched_sinks": sorted(matched_sinks),
                "missing_seed_guards": sorted(missing_guards),
                "present_guards": sorted(shape.guards),
                "lexical_parameter_sink_hint": source_path,
                "reachability_grade": boundary.grade,
                "reachability_evidence": boundary.evidence,
                "required_next_validator": _next_validator(boundary.grade),
            }
        )
    candidates.sort(
        key=lambda row: (
            -(row["score"] if isinstance(row["score"], int) else 0),
            str(row["function"]),
        )
    )
    for rank, row in enumerate(candidates, 1):
        row["rank"] = rank

    return {
        "schema_version": RESULT_VERSION,
        "campaign_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "seed": {
            "function": seed_function,
            "reference": reference,
            "guard_delta": sorted(guard_delta),
            "sink_geometry": sorted(vulnerable_seed.sinks),
            "vulnerable": _artifact_record(vulnerable),
            "fixed": _artifact_record(fixed),
        },
        "current": _artifact_record(current),
        "candidate_count": len(candidates),
        "candidates": candidates,
        "proof_limit": (
            "Static lexical guard-delta evidence only. This result cannot establish a crash, "
            "security impact, exploitability, novelty, or bounty eligibility."
        ),
        "all_results_are_candidates": True,
        "weaponization": False,
        "automatic_disclosure": False,
    }


def produce_windows_analysis_bundle(
    binary_path: str | Path,
    pdb_path: str | Path,
    output_dir: str | Path,
    *,
    ghidra_home: str | Path,
    analyzer: Callable[[Path, Path], dict[str, Any]] | None = None,
) -> dict[str, str]:
    """Produce an exclusive binary/PDB/export/receipt bundle in one rename.

    The default path invokes Ghidra against a fresh cache directory, enriches
    symbols from the exact PDB, then writes the export and provenance receipt.
    ``analyzer`` exists only as a test seam for the producer-to-ranker contract.
    """
    source_binary = Path(binary_path)
    source_pdb = Path(pdb_path)
    destination = Path(output_dir)
    home = Path(ghidra_home)
    for path, label in ((source_binary, "binary"), (source_pdb, "PDB")):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"analysis {label} must be a regular non-symlink file")
    if destination.exists() or destination.is_symlink():
        raise ValueError("analysis output directory already exists")
    if not destination.parent.is_dir():
        raise ValueError("analysis output parent directory does not exist")
    codeview = pe_codeview_identity(source_binary)
    actual_pdb = pdb_codeview_identity(source_pdb)
    if codeview is None or actual_pdb is None:
        raise ValueError("analysis bundle requires a real PE and inspectable matching PDB")
    if actual_pdb[0] != codeview[0] or (actual_pdb[1] != codeview[1] and not actual_pdb[2]):
        raise ValueError("analysis PDB identity does not match PE CodeView")
    version = _ghidra_version(home)

    temporary = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent)
    )
    try:
        bundled_binary = temporary / f"target{source_binary.suffix.lower()}"
        bundled_pdb = temporary / "target.pdb"
        export_path = temporary / "ghidra-export.json"
        receipt_path = temporary / "analysis-receipt.json"
        shutil.copyfile(source_binary, bundled_binary)
        shutil.copyfile(source_pdb, bundled_pdb)
        if analyzer is None:
            from .backends.ghidra import GhidraAdapter
            from .pe_symbols import enrich_ghidra_symbols

            adapter = GhidraAdapter.analyze(
                bundled_binary,
                ghidra_home=str(home),
                cache_dir=temporary / "fresh-cache",
            )
            enrich_ghidra_symbols(adapter, bundled_binary)
            export_raw = json.loads(adapter.to_json())
        else:
            export_raw = analyzer(bundled_binary, bundled_pdb)
        if not isinstance(export_raw, dict):
            raise ValueError("Ghidra analyzer did not return an export object")
        with export_path.open("x", encoding="utf-8") as output:
            json.dump(export_raw, output, indent=2, sort_keys=True)
            output.write("\n")
        binary_digest = _digest(bundled_binary)
        pdb_digest = _digest(bundled_pdb)
        export_digest = _digest(export_path)
        identity = f"{codeview[0]}:{codeview[1]}:{codeview[2]}"
        receipt = {
            "schema_version": ANALYSIS_RECEIPT_VERSION,
            "producer": ANALYSIS_PRODUCER,
            "binary_path": bundled_binary.name,
            "binary_sha256": binary_digest,
            "ghidra_export_path": export_path.name,
            "ghidra_export_sha256": export_digest,
            "tool": "ghidra",
            "tool_version": version,
            "cache_key": binary_digest[:16],
            "synthetic_fixture": False,
            "pdb": {
                "path": bundled_pdb.name,
                "sha256": pdb_digest,
                "codeview_identity": identity,
            },
        }
        with receipt_path.open("x", encoding="utf-8") as output:
            json.dump(receipt, output, indent=2, sort_keys=True)
            output.write("\n")
        temporary.replace(destination)
        # The returned descriptor is directly insertable into a campaign
        # manifest stored beside output_dir, regardless of whether output_dir
        # was passed as an absolute or relative path.
        descriptor_base = destination.parent.resolve()

        def descriptor_path(name: str) -> str:
            return str((destination / name).resolve().relative_to(descriptor_base))

        return {
            "binary_path": descriptor_path(bundled_binary.name),
            "binary_sha256": binary_digest,
            "ghidra_export_path": descriptor_path(export_path.name),
            "ghidra_export_sha256": export_digest,
            "analysis_receipt_path": descriptor_path(receipt_path.name),
            "analysis_receipt_sha256": hashlib.sha256(
                (destination / receipt_path.name).read_bytes()
            ).hexdigest(),
        }
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _regular_nofollow_fd(path: Path, label: str, size_cap: int) -> tuple[int, os.stat_result]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise RuntimeError("stable no-follow snapshots are unavailable on this platform")
    try:
        path_before = os.lstat(path)
    except OSError as exc:
        raise ValueError(f"{label} must be a readable regular non-symlink file") from exc
    flags = (
        os.O_RDONLY
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{label} must be a readable regular non-symlink file") from exc
    try:
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISREG(observed.st_mode)
            or not stat.S_ISREG(path_before.st_mode)
            or (path_before.st_dev, path_before.st_ino) != (observed.st_dev, observed.st_ino)
        ):
            raise ValueError(f"{label} must be a regular file")
        if observed.st_size > size_cap:
            raise ValueError(f"{label} exceeds size cap")
        return descriptor, observed
    except Exception:
        os.close(descriptor)
        raise


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _path_still_names(path: Path, observed: os.stat_result, label: str) -> None:
    try:
        current = os.lstat(path)
    except OSError as exc:
        raise ValueError(f"{label} path changed while it was being read") from exc
    if (
        not stat.S_ISREG(current.st_mode)
        or (current.st_dev, current.st_ino) != (observed.st_dev, observed.st_ino)
    ):
        raise ValueError(f"{label} path changed while it was being read")


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write while retaining analysis artifact")
        view = view[written:]


def _snapshot_file(source: Path, destination: Path, label: str, size_cap: int) -> str:
    source_fd, before = _regular_nofollow_fd(source, label, size_cap)
    destination_fd = -1
    digest = hashlib.sha256()
    count = 0
    completed = False
    try:
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        while True:
            chunk = os.read(source_fd, _COPY_CHUNK_SIZE)
            if not chunk:
                break
            count += len(chunk)
            if count > size_cap:
                raise ValueError(f"{label} exceeds size cap")
            digest.update(chunk)
            _write_all(destination_fd, chunk)
        after = os.fstat(source_fd)
        if count != before.st_size or _stat_identity(after) != _stat_identity(before):
            raise ValueError(f"{label} changed while it was being retained")
        _path_still_names(source, after, label)
        os.fsync(destination_fd)
        completed = True
        return digest.hexdigest()
    finally:
        os.close(source_fd)
        if destination_fd >= 0:
            os.close(destination_fd)
        if not completed:
            destination.unlink(missing_ok=True)


def _digest_nofollow(path: Path, label: str, size_cap: int) -> str:
    descriptor, before = _regular_nofollow_fd(path, label, size_cap)
    digest = hashlib.sha256()
    count = 0
    try:
        while True:
            chunk = os.read(descriptor, _COPY_CHUNK_SIZE)
            if not chunk:
                break
            count += len(chunk)
            if count > size_cap:
                raise ValueError(f"{label} exceeds size cap")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if count != before.st_size or _stat_identity(after) != _stat_identity(before):
            raise ValueError(f"{label} changed while it was being read")
        _path_still_names(path, after, label)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _retained_identity(path: Path, label: str) -> tuple[int, int, int, int, int, int]:
    try:
        observed = os.lstat(path)
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if not stat.S_ISREG(observed.st_mode):
        raise ValueError(f"{label} must remain a regular non-symlink file")
    return _stat_identity(observed)


def _write_new_file_at(directory_fd: int, name: str, content: bytes) -> str:
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
        dir_fd=directory_fd,
    )
    try:
        _write_all(descriptor, content)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return hashlib.sha256(content).hexdigest()


def _publish_directory_no_replace(
    parent_fd: int, source_name: str, destination_name: str
) -> None:
    library = CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source_name)
    destination_bytes = os.fsencode(destination_name)
    if sys.platform.startswith("linux"):
        try:
            rename = library.renameat2
        except AttributeError as exc:
            raise RuntimeError("native no-replace directory rename is unavailable") from exc
        rename.argtypes = (c_int, c_char_p, c_int, c_char_p, c_int)
        rename.restype = c_int
        result = rename(parent_fd, source_bytes, parent_fd, destination_bytes, 1)
    elif sys.platform == "darwin":
        try:
            rename = library.renameatx_np
        except AttributeError as exc:
            raise RuntimeError("native no-replace directory rename is unavailable") from exc
        rename.argtypes = (c_int, c_char_p, c_int, c_char_p, c_int)
        rename.restype = c_int
        result = rename(parent_fd, source_bytes, parent_fd, destination_bytes, 0x00000004)
    else:
        raise RuntimeError("native no-replace bundle publication requires Darwin or Linux")
    if result != 0:
        error = get_errno()
        if error in {errno.EEXIST, errno.ENOTEMPTY}:
            raise FileExistsError(
                error, "analysis output directory already exists", destination_name
            )
        raise OSError(error, os.strerror(error), destination_name)


def _open_directory_ancestry(path: Path, label: str) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise RuntimeError("stable no-follow directory custody is unavailable")
    absolute = Path(os.path.abspath(path))  # noqa: PTH100 - must not resolve symlinks
    flags = os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(absolute.anchor, flags)
    try:
        for component in absolute.parts[1:]:
            try:
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
            except OSError as exc:
                raise ValueError(
                    f"{label} ancestry must contain only real non-symlink directories"
                ) from exc
            os.close(descriptor)
            descriptor = next_descriptor
        observed = os.fstat(descriptor)
        if not stat.S_ISDIR(observed.st_mode):
            raise ValueError(f"{label} must be a real non-symlink directory")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _require_directory_path_identity(path: Path, descriptor: int, label: str) -> None:
    current = _open_directory_ancestry(path, label)
    try:
        expected_stat = os.fstat(descriptor)
        current_stat = os.fstat(current)
        if (expected_stat.st_dev, expected_stat.st_ino) != (
            current_stat.st_dev,
            current_stat.st_ino,
        ):
            raise ValueError(f"{label} changed during bundle publication")
    finally:
        os.close(current)


def _create_staging_directory(parent_fd: int, prefix: str) -> tuple[str, int]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    for _attempt in range(128):
        name = f"{prefix}{secrets.token_hex(8)}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        try:
            return name, os.open(name, flags, dir_fd=parent_fd)
        except Exception:
            os.rmdir(name, dir_fd=parent_fd)
            raise
    raise RuntimeError("could not reserve a private analysis staging directory")


def _snapshot_file_at(
    source: Path, directory_fd: int, name: str, label: str, size_cap: int
) -> str:
    source_fd, before = _regular_nofollow_fd(source, label, size_cap)
    destination_fd = -1
    digest = hashlib.sha256()
    count = 0
    try:
        destination_fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=directory_fd,
        )
        while True:
            chunk = os.read(source_fd, _COPY_CHUNK_SIZE)
            if not chunk:
                break
            count += len(chunk)
            if count > size_cap:
                raise ValueError(f"{label} exceeds size cap")
            digest.update(chunk)
            _write_all(destination_fd, chunk)
        after = os.fstat(source_fd)
        if count != before.st_size or _stat_identity(after) != _stat_identity(before):
            raise ValueError(f"{label} changed while it was being retained")
        _path_still_names(source, after, label)
        os.fsync(destination_fd)
        return digest.hexdigest()
    finally:
        os.close(source_fd)
        if destination_fd >= 0:
            os.close(destination_fd)


def _digest_file_at(directory_fd: int, name: str, label: str, size_cap: int) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    digest = hashlib.sha256()
    count = 0
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > size_cap:
            raise ValueError(f"{label} must be a bounded regular file")
        while True:
            chunk = os.read(descriptor, _COPY_CHUNK_SIZE)
            if not chunk:
                break
            count += len(chunk)
            if count > size_cap:
                raise ValueError(f"{label} exceeds size cap")
            digest.update(chunk)
        if count != before.st_size or _stat_identity(os.fstat(descriptor)) != _stat_identity(
            before
        ):
            raise ValueError(f"{label} changed while it was being read")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _file_identity_at(directory_fd: int, name: str, label: str) -> tuple[int, ...]:
    observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if not stat.S_ISREG(observed.st_mode):
        raise ValueError(f"{label} must remain a regular non-symlink file")
    return _stat_identity(observed)


@contextmanager
def _anchored_working_directory(directory_fd: int) -> Iterator[None]:
    """Expose descriptor-custodied files to pathname-only analysis tools."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    with _ANALYSIS_CWD_LOCK:
        previous = os.open(".", flags)
        try:
            os.fchdir(directory_fd)
            yield
        finally:
            os.fchdir(previous)
            os.close(previous)


def _remove_staging_at(parent_fd: int, name: str, binary_name: str) -> None:
    """Remove only producer-owned literal files from a held private staging dir.

    Unknown entries are never traversed or deleted. In that fail-closed case the
    final ``rmdir`` fails and the private staging directory is retained.
    """
    if (
        Path(binary_name).name != binary_name
        or "\\" in binary_name
        or _DRIVER_BASENAME.fullmatch(binary_name) is None
    ):
        raise ValueError("staged analysis binary name is not a safe .sys component basename")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        directory_fd = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        return
    try:
        with suppress(FileNotFoundError):
            os.unlink("analysis-receipt.json", dir_fd=directory_fd)
        with suppress(FileNotFoundError):
            os.unlink("ghidra-export.json", dir_fd=directory_fd)
        with suppress(FileNotFoundError):
            os.unlink("target.pdb", dir_fd=directory_fd)
        with suppress(FileNotFoundError):
            public_fd = os.open(
                "public-pdb",
                flags,
                dir_fd=directory_fd,
            )
            try:
                entries = os.listdir(  # noqa: PTH208  # foxguard: ignore[py/no-path-traversal]
                    public_fd
                )
                if len(entries) != 1 or re.fullmatch(r"[0-9a-f]{64}", entries[0]) is None:
                    raise ValueError("staged public-PDB CAS directory is malformed")
                cas_name = entries[0]
                cas_fd = os.open(cas_name, flags, dir_fd=public_fd)
                try:
                    with suppress(FileNotFoundError):
                        os.unlink("artifact", dir_fd=cas_fd)
                    with suppress(FileNotFoundError):
                        os.unlink("receipt.json", dir_fd=cas_fd)
                finally:
                    os.close(cas_fd)
                os.rmdir(cas_name, dir_fd=public_fd)
            finally:
                os.close(public_fd)
            os.rmdir("public-pdb", dir_fd=directory_fd)
        with suppress(FileNotFoundError):
            # ``binary_name`` passed the strict driver-basename grammar before the
            # private directory was created; the held directory fd prevents escape.
            os.unlink(  # foxguard: ignore[py/no-path-traversal]
                binary_name, dir_fd=directory_fd
            )
    finally:
        os.close(directory_fd)
    os.rmdir(name, dir_fd=parent_fd)


def produce_windows_ioctl_analysis_bundle(
    binary_path: str | Path,
    pdb_path: str | Path,
    output_dir: str | Path,
    *,
    ghidra_home: str | Path,
) -> dict[str, str]:
    """Produce an atomic, provenance-bound Windows IOCTL analysis bundle.

    Unlike :func:`produce_windows_analysis_bundle`, this producer invokes the
    dedicated x64 WDM High-P-Code extractor and records its immutable export
    contract in an additive v2 analysis receipt. The analyzer is fixed and is
    not caller-selectable through either the API or CLI.
    """
    return _produce_windows_ioctl_analysis_bundle(
        binary_path,
        pdb_path,
        output_dir,
        ghidra_home=ghidra_home,
        public_pdb_bundle_path=None,
    )


def produce_windows_public_ioctl_analysis_bundle(
    binary_path: str | Path,
    public_pdb_bundle_path: str | Path,
    output_dir: str | Path,
    *,
    ghidra_home: str | Path,
) -> dict[str, str]:
    """Produce a semantic-v3 bundle from a verified Microsoft public-PDB route.

    The complete content-addressed acquisition bundle is retained inside the
    analysis bundle.  A stripped PDB age mismatch is authorized only by the
    route receipt verifier and is never represented as an exact private pair.
    """
    return _produce_windows_ioctl_analysis_bundle(
        binary_path,
        None,
        output_dir,
        ghidra_home=ghidra_home,
        public_pdb_bundle_path=public_pdb_bundle_path,
    )


def _produce_windows_ioctl_analysis_bundle(
    binary_path: str | Path,
    pdb_path: str | Path | None,
    output_dir: str | Path,
    *,
    ghidra_home: str | Path,
    public_pdb_bundle_path: str | Path | None,
) -> dict[str, str]:
    from .windows_ioctl_ghidra_export import (
        EXPORT_VERSION_V2,
        EXPORT_VERSION_V3,
        EXTRACTOR_CONFIG_SHA256,
        EXTRACTOR_PROFILE,
        VID_DRIVER_SHA256,
        VID_EXTRACTOR_CONFIG_SHA256,
        VID_EXTRACTOR_PROFILE,
        VID_PDB_SHA256,
        canonical_export_bytes,
    )

    source_binary = Path(os.path.abspath(binary_path))  # noqa: PTH100 - lexical only
    source_pdb = (
        Path(os.path.abspath(pdb_path))  # noqa: PTH100 - lexical only
        if pdb_path is not None
        else None
    )
    source_public_bundle = (
        Path(os.path.abspath(public_pdb_bundle_path))  # noqa: PTH100 - lexical only
        if public_pdb_bundle_path is not None
        else None
    )
    if (source_pdb is None) is (source_public_bundle is None):
        raise ValueError("analysis requires exactly one private PDB or public-PDB bundle")
    source_public_receipt: PublicPdbReceipt | None = None
    if source_public_bundle is not None:
        from .windows_public_pdb import verify_public_pdb_receipt

        source_public_receipt = verify_public_pdb_receipt(
            source_binary, source_public_bundle
        )
    destination = Path(output_dir)
    home = Path(os.path.abspath(ghidra_home))  # noqa: PTH100 - lexical only
    if destination.name in {"", ".", ".."}:
        raise ValueError("analysis output directory name is invalid")
    bundled_binary_name = source_binary.name
    if (
        Path(bundled_binary_name).name != bundled_binary_name
        or "\\" in bundled_binary_name
        or _DRIVER_BASENAME.fullmatch(bundled_binary_name) is None
    ):
        raise ValueError("analysis binary must have a safe .sys component basename")
    version = _ghidra_version(home)

    parent_path = Path(os.path.abspath(destination.parent))  # noqa: PTH100 - no links
    parent_fd = _open_directory_ancestry(parent_path, "analysis output parent")
    try:
        os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    except Exception:
        os.close(parent_fd)
        raise
    else:
        os.close(parent_fd)
        raise ValueError("analysis output directory already exists")
    try:
        temporary_name, temporary_fd = _create_staging_directory(
            parent_fd, f".{destination.name}.tmp-"
        )
    except Exception:
        os.close(parent_fd)
        raise
    published = False
    try:
        bundled_pdb_name = "target.pdb"
        public_bundle_relative: Path | None = None
        export_name = "ghidra-export.json"
        receipt_name = "analysis-receipt.json"
        binary_digest = _snapshot_file_at(
            source_binary,
            temporary_fd,
            bundled_binary_name,
            "analysis binary",
            _BINARY_SIZE_CAP,
        )
        if source_public_receipt is None:
            if source_pdb is None:
                raise AssertionError("private PDB source unexpectedly absent")
            pdb_digest = _snapshot_file_at(
                source_pdb,
                temporary_fd,
                bundled_pdb_name,
                "analysis PDB",
                _PDB_SIZE_CAP,
            )
        else:
            public_root_name = "public-pdb"
            cas_name = source_public_receipt.artifact_sha256
            os.mkdir(public_root_name, mode=0o700, dir_fd=temporary_fd)
            directory_flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            public_root_fd = os.open(public_root_name, directory_flags, dir_fd=temporary_fd)
            try:
                os.mkdir(cas_name, mode=0o700, dir_fd=public_root_fd)
                cas_fd = os.open(cas_name, directory_flags, dir_fd=public_root_fd)
            finally:
                os.close(public_root_fd)
            try:
                pdb_digest = _snapshot_file_at(
                    source_public_receipt.artifact_path,
                    cas_fd,
                    "artifact",
                    "public analysis PDB",
                    _PDB_SIZE_CAP,
                )
                route_receipt_digest = _snapshot_file_at(
                    source_public_receipt.bundle_path / "receipt.json",
                    cas_fd,
                    "receipt.json",
                    "public PDB route receipt",
                    _RECEIPT_SIZE_CAP,
                )
                os.fsync(cas_fd)
            finally:
                os.close(cas_fd)
            if (
                pdb_digest != source_public_receipt.artifact_sha256
                or route_receipt_digest != source_public_receipt.receipt_sha256
            ):
                raise ValueError("retained public-PDB bundle differs from verified source")
            public_bundle_relative = Path(public_root_name) / cas_name
            bundled_pdb_name = (public_bundle_relative / "artifact").as_posix()
        if (
            _digest_file_at(
                temporary_fd,
                bundled_binary_name,
                "retained analysis binary",
                _BINARY_SIZE_CAP,
            )
            != binary_digest
            or _digest_file_at(
                temporary_fd,
                bundled_pdb_name,
                "retained analysis PDB",
                _PDB_SIZE_CAP,
            )
            != pdb_digest
        ):
            raise ValueError("retained PE/PDB changed during identity validation")
        binary_identity = _file_identity_at(
            temporary_fd, bundled_binary_name, "retained analysis binary"
        )
        pdb_identity = _file_identity_at(
            temporary_fd, bundled_pdb_name, "retained analysis PDB"
        )
        with _anchored_working_directory(temporary_fd):
            bundled_binary = Path(bundled_binary_name)
            bundled_pdb = Path(bundled_pdb_name)
            codeview = pe_codeview_identity(bundled_binary)
            actual_pdb = pdb_codeview_identity(bundled_pdb)
            if codeview is None or actual_pdb is None:
                raise ValueError(
                    "analysis bundle requires a real PE and inspectable matching PDB"
                )
            is_vid = binary_digest == VID_DRIVER_SHA256 and pdb_digest == VID_PDB_SHA256
            retained_public_receipt: PublicPdbReceipt | None = None
            if public_bundle_relative is not None:
                from .windows_public_pdb import verify_public_pdb_receipt

                retained_public_receipt = verify_public_pdb_receipt(
                    bundled_binary, public_bundle_relative
                )
                if _public_receipt_binding(retained_public_receipt) != _public_receipt_binding(
                    source_public_receipt
                ):
                    raise ValueError("retained public-PDB route binding changed during custody")
            if actual_pdb[2] is not False and not is_vid and retained_public_receipt is None:
                raise ValueError("dedicated IOCTL analysis requires a full non-stripped PDB")
            if actual_pdb[0] != codeview[0] or (
                actual_pdb[1] != codeview[1]
                and not (
                    (is_vid and actual_pdb[2])
                    or (retained_public_receipt is not None and actual_pdb[2])
                )
            ):
                raise ValueError("analysis PDB GUID and age do not exactly match PE CodeView")
            identity = f"{codeview[0]}:{codeview[1]}:{codeview[2]}"
            if public_bundle_relative is None:
                from .windows_ioctl_ghidra_export import analyze_windows_ioctl_driver

                export_raw = analyze_windows_ioctl_driver(
                    bundled_binary, bundled_pdb, ghidra_home=home
                )
            else:
                from .windows_ioctl_ghidra_export import (
                    analyze_windows_public_ioctl_driver,
                )

                export_raw = analyze_windows_public_ioctl_driver(
                    bundled_binary,
                    bundled_pdb,
                    public_bundle_relative,
                    ghidra_home=home,
                )
        if not isinstance(export_raw, dict):
            raise ValueError("Windows IOCTL Ghidra analyzer did not return an export object")
        if (
            _file_identity_at(
                temporary_fd, bundled_binary_name, "retained analysis binary"
            )
            != binary_identity
            or _file_identity_at(
                temporary_fd, bundled_pdb_name, "retained analysis PDB"
            )
            != pdb_identity
            or _digest_file_at(
                temporary_fd,
                bundled_binary_name,
                "retained analysis binary",
                _BINARY_SIZE_CAP,
            )
            != binary_digest
            or _digest_file_at(
                temporary_fd,
                bundled_pdb_name,
                "retained analysis PDB",
                _PDB_SIZE_CAP,
            )
            != pdb_digest
        ):
            raise ValueError("Windows IOCTL Ghidra analyzer mutated its immutable inputs")
        post_public_receipt: PublicPdbReceipt | None = None
        if public_bundle_relative is not None:
            from .windows_public_pdb import verify_public_pdb_receipt

            with _anchored_working_directory(temporary_fd):
                post_public_receipt = verify_public_pdb_receipt(
                    Path(bundled_binary_name), public_bundle_relative
                )
            if source_public_receipt is None or retained_public_receipt is None:
                raise AssertionError("public-PDB verification state is incomplete")
            bindings = {
                _public_receipt_binding(receipt)
                for receipt in (
                    source_public_receipt,
                    retained_public_receipt,
                    post_public_receipt,
                )
            }
            if len(bindings) != 1:
                raise ValueError("public-PDB route binding changed during analysis")
        expected_profile, expected_config = (
            (VID_EXTRACTOR_PROFILE, VID_EXTRACTOR_CONFIG_SHA256)
            if binary_digest == VID_DRIVER_SHA256
            else (EXTRACTOR_PROFILE, EXTRACTOR_CONFIG_SHA256)
        )
        export_version = EXPORT_VERSION_V2 if is_vid else EXPORT_VERSION_V3
        receipt_version = (
            ANALYSIS_RECEIPT_VERSION_V4
            if source_public_receipt is not None
            else (ANALYSIS_RECEIPT_VERSION_V2 if is_vid else ANALYSIS_RECEIPT_VERSION_V3)
        )
        expected_export_binding = {
            "schema_version": export_version,
            "extractor_profile": expected_profile,
            "extractor_config_sha256": expected_config,
            "driver_sha256": binary_digest,
            "pdb_sha256": pdb_digest,
            "pdb_codeview_identity": (
                f"{actual_pdb[0]}:{actual_pdb[1]}:stripped"
                if post_public_receipt is not None
                else identity
            ),
        }
        for field, expected in expected_export_binding.items():
            if export_raw.get(field) != expected:
                raise ValueError(f"Windows IOCTL Ghidra export {field} mismatch")
        export_bytes = canonical_export_bytes(export_raw)
        if len(export_bytes) > _EXPORT_SIZE_CAP:
            raise ValueError("Windows IOCTL Ghidra export exceeds size cap")
        export_digest = _write_new_file_at(temporary_fd, export_name, export_bytes)
        public_receipt_for_output = post_public_receipt
        cache_key = (
            _public_ioctl_analysis_cache_key(
                binary_digest,
                pdb_digest,
                version,
                expected_profile,
                expected_config,
                public_receipt_for_output.receipt_sha256,
            )
            if public_receipt_for_output is not None
            else _ioctl_analysis_cache_key(
                binary_digest,
                pdb_digest,
                version,
                expected_profile,
                expected_config,
            )
        )
        receipt: dict[str, object] = {
            "schema_version": receipt_version,
            "producer": IOCTL_ANALYSIS_PRODUCER,
            "binary_path": bundled_binary_name,
            "binary_sha256": binary_digest,
            "ghidra_export_path": export_name,
            "ghidra_export_sha256": export_digest,
            "tool": "ghidra",
            "tool_version": version,
            "cache_key": cache_key,
            "synthetic_fixture": False,
            "pdb": (
                {
                    "path": bundled_pdb_name,
                    "sha256": pdb_digest,
                    "identity": {
                        "guid": actual_pdb[0],
                        "age": actual_pdb[1],
                        "stripped": actual_pdb[2],
                    },
                    "pe_route_codeview_identity": identity,
                }
                if public_receipt_for_output is not None
                else {
                    "path": bundled_pdb_name,
                    "sha256": pdb_digest,
                    "codeview_identity": identity,
                }
            ),
            "export_schema_version": export_version,
            "extractor_profile": expected_profile,
            "extractor_config_sha256": expected_config,
        }
        if public_receipt_for_output is not None:
            if public_bundle_relative is None:
                raise AssertionError("retained public-PDB path unexpectedly absent")
            receipt["public_pdb"] = {
                "bundle_path": public_bundle_relative.as_posix(),
                "receipt_sha256": public_receipt_for_output.receipt_sha256,
                "requested_url": public_receipt_for_output.requested_url,
                "pe_guid": public_receipt_for_output.pe_guid,
                "pe_age": public_receipt_for_output.pe_age,
                "pdb_guid": public_receipt_for_output.pdb_guid,
                "pdb_age": public_receipt_for_output.pdb_age,
                "exact_age_match": public_receipt_for_output.exact_age_match,
            }
        receipt_bytes = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
        if len(receipt_bytes) > _RECEIPT_SIZE_CAP:
            raise ValueError("Windows IOCTL analysis receipt exceeds size cap")
        receipt_digest = _write_new_file_at(temporary_fd, receipt_name, receipt_bytes)
        os.fsync(temporary_fd)
        os.fsync(parent_fd)
        _require_directory_path_identity(
            parent_path, parent_fd, "analysis output parent"
        )
        _publish_directory_no_replace(parent_fd, temporary_name, destination.name)
        published = True
        os.fsync(parent_fd)
        _require_directory_path_identity(
            parent_path, parent_fd, "analysis output parent"
        )

        def descriptor_path(name: str) -> str:
            return str(Path(destination.name) / name)

        return {
            "binary_path": descriptor_path(bundled_binary_name),
            "binary_sha256": binary_digest,
            "ghidra_export_path": descriptor_path(export_name),
            "ghidra_export_sha256": export_digest,
            "analysis_receipt_path": descriptor_path(receipt_name),
            "analysis_receipt_sha256": receipt_digest,
        }
    finally:
        os.close(temporary_fd)
        if not published:
            with suppress(OSError):
                _remove_staging_at(parent_fd, temporary_name, bundled_binary_name)
        os.close(parent_fd)


def evaluate_windows_variants(
    manifest_path: str | Path, labels_path: str | Path
) -> dict[str, object]:
    """Evaluate one labeled campaign and prove deterministic replay."""
    label_file = Path(labels_path)
    label_bytes = label_file.read_bytes()
    raw = json.loads(label_bytes)
    if not isinstance(raw, dict):
        raise ValueError("Windows variant labels must be a JSON object")
    _exact_fields(
        raw,
        {
            "schema_version",
            "campaign_sha256",
            "current_binary_sha256",
            "current_export_sha256",
            "expected_sites",
            "patched_control_sites",
            "rank_cutoff",
            "minimum_recall_at_cutoff",
            "minimum_patched_control_suppression",
            "maximum_unsupported_at_cutoff",
        },
        "labels",
    )
    if raw["schema_version"] != LABEL_VERSION:
        raise ValueError(f"unsupported Windows variant label schema: {raw['schema_version']}")
    expected = _site_set(raw["expected_sites"], "expected_sites")
    controls = _site_set(raw["patched_control_sites"], "patched_control_sites")
    if expected & controls:
        raise ValueError("expected_sites and patched_control_sites must be disjoint")
    cutoff = _positive_int(raw["rank_cutoff"], "rank_cutoff")
    minimum_recall = _ratio(raw["minimum_recall_at_cutoff"], "minimum_recall_at_cutoff")
    minimum_suppression = _ratio(
        raw["minimum_patched_control_suppression"],
        "minimum_patched_control_suppression",
    )
    maximum_unsupported = _nonnegative_int(
        raw["maximum_unsupported_at_cutoff"], "maximum_unsupported_at_cutoff"
    )
    first = rank_windows_variants(manifest_path)
    second = rank_windows_variants(manifest_path)
    deterministic = first == second
    current = first["current"]
    if not isinstance(current, dict):
        raise ValueError("ranker returned malformed current artifact")
    if (
        raw["campaign_sha256"] != first["campaign_sha256"]
        or raw["current_binary_sha256"] != current.get("binary_sha256")
        or raw["current_export_sha256"] != current.get("ghidra_export_sha256")
    ):
        raise ValueError("labels are not bound to this campaign/current artifact")
    candidates = first["candidates"]
    if not isinstance(candidates, list):
        raise ValueError("ranker returned malformed candidates")
    top = candidates[:cutoff]
    top_sites = {
        (str(row.get("function", "")), str(row.get("function_address", "")))
        for row in top
        if isinstance(row, dict)
    }
    all_sites = {
        (str(row.get("function", "")), str(row.get("function_address", "")))
        for row in candidates
        if isinstance(row, dict)
    }
    recall = len(expected & top_sites) / len(expected)
    suppression = 1.0 - len(controls & all_sites) / len(controls)
    unsupported = sum(
        1 for row in top if isinstance(row, dict) and row.get("status") != "reachable"
    )
    gates = {
        "deterministic": deterministic,
        "recall_at_cutoff": recall >= minimum_recall,
        "patched_control_suppression": suppression >= minimum_suppression,
        "unsupported_at_cutoff": unsupported <= maximum_unsupported,
        "static_results_remain_candidates": all(
            isinstance(row, dict) and row.get("status") == "candidate"
            for row in candidates
        ),
    }
    return {
        "schema_version": EVAL_VERSION,
        "campaign_sha256": first["campaign_sha256"],
        "labels_sha256": hashlib.sha256(label_bytes).hexdigest(),
        "rank_cutoff": cutoff,
        "expected_count": len(expected),
        "expected_found_at_cutoff": _site_records(expected & top_sites),
        "recall_at_cutoff": round(recall, 6),
        "patched_control_count": len(controls),
        "patched_controls_emitted": _site_records(controls & all_sites),
        "patched_control_suppression": round(suppression, 6),
        "unsupported_at_cutoff": unsupported,
        "gates": gates,
        "passed": all(gates.values()),
        "capability_measure": False,
        "note": (
            "A single labeled campaign is a regression contract, not a Windows "
            "vulnerability-discovery capability claim."
        ),
    }


def _load_artifact(raw: object, base: Path, label: str) -> Artifact:
    if not isinstance(raw, dict):
        raise ValueError(f"{label} must be an object")
    _exact_fields(raw, set(_ARTIFACT_FIELDS), label)
    binary = _relative_file(base, raw["binary_path"], f"{label}.binary_path")
    export = _relative_file(base, raw["ghidra_export_path"], f"{label}.ghidra_export_path")
    receipt_path = _relative_file(
        base, raw["analysis_receipt_path"], f"{label}.analysis_receipt_path"
    )
    public_pdb_receipt_sha256 = ""
    public_pdb_requested_url = ""
    public_pdb_exact_age_match: bool | None = None
    public_pdb_pe_guid = ""
    public_pdb_pe_age: int | None = None
    public_pdb_pdb_guid = ""
    public_pdb_pdb_age: int | None = None
    with tempfile.TemporaryDirectory(prefix="zeroverse-artifact-snapshot-") as temporary:
        private = Path(temporary)
        binary_copy = private / "binary.snapshot"
        export_copy = private / "export.snapshot"
        receipt_copy = private / "receipt.snapshot"
        binary_digest = _snapshot_file(
            binary, binary_copy, f"{label} binary", _BINARY_SIZE_CAP
        )
        export_digest = _snapshot_file(
            export, export_copy, f"{label} Ghidra export", _EXPORT_SIZE_CAP
        )
        receipt_digest = _snapshot_file(
            receipt_path,
            receipt_copy,
            f"{label} analysis receipt",
            _RECEIPT_SIZE_CAP,
        )
        if binary_digest != _sha256(raw["binary_sha256"], f"{label}.binary_sha256"):
            raise ValueError(f"{label} binary SHA-256 mismatch")
        if export_digest != _sha256(
            raw["ghidra_export_sha256"], f"{label}.ghidra_export_sha256"
        ):
            raise ValueError(f"{label} Ghidra export SHA-256 mismatch")
        if receipt_digest != _sha256(
            raw["analysis_receipt_sha256"], f"{label}.analysis_receipt_sha256"
        ):
            raise ValueError(f"{label} analysis receipt SHA-256 mismatch")
        export_raw = json.loads(export_copy.read_bytes())
        if not isinstance(export_raw, dict):
            raise ValueError(f"{label} Ghidra export must be a JSON object")
        receipt = json.loads(receipt_copy.read_bytes())
        if not isinstance(receipt, dict):
            raise ValueError(f"{label} analysis receipt must be a JSON object")
        receipt_fields = {
            "schema_version",
            "producer",
            "binary_path",
            "binary_sha256",
            "ghidra_export_path",
            "ghidra_export_sha256",
            "tool",
            "tool_version",
            "cache_key",
            "synthetic_fixture",
            "pdb",
        }
        receipt_version = receipt.get("schema_version")
        from .windows_ioctl_ghidra_export import VID_DRIVER_SHA256

        if (
            binary_digest == VID_DRIVER_SHA256
            and receipt_version != ANALYSIS_RECEIPT_VERSION_V2
        ):
            raise ValueError(f"{label} exact Vid analysis requires a v2 receipt")
        if receipt_version in {
            ANALYSIS_RECEIPT_VERSION_V2,
            ANALYSIS_RECEIPT_VERSION_V3,
            ANALYSIS_RECEIPT_VERSION_V4,
        }:
            receipt_fields.update(
                {
                    "export_schema_version",
                    "extractor_profile",
                    "extractor_config_sha256",
                }
            )
        if receipt_version == ANALYSIS_RECEIPT_VERSION_V4:
            receipt_fields.add("public_pdb")
        _exact_fields(receipt, receipt_fields, f"{label}.analysis_receipt")
        if receipt_version not in {
            ANALYSIS_RECEIPT_VERSION,
            ANALYSIS_RECEIPT_VERSION_V2,
            ANALYSIS_RECEIPT_VERSION_V3,
            ANALYSIS_RECEIPT_VERSION_V4,
        } or receipt["tool"] != "ghidra":
            raise ValueError(f"{label} analysis receipt schema/tool mismatch")
        receipt_binary = _relative_file(
            receipt_path.parent,
            receipt["binary_path"],
            f"{label}.analysis_receipt.binary_path",
        )
        receipt_export = _relative_file(
            receipt_path.parent,
            receipt["ghidra_export_path"],
            f"{label}.analysis_receipt.ghidra_export_path",
        )
        if _lexical_absolute(receipt_binary) != _lexical_absolute(binary) or _lexical_absolute(
            receipt_export
        ) != _lexical_absolute(export):
            raise ValueError(f"{label} analysis receipt path binding mismatch")
        if (
            receipt["binary_sha256"] != binary_digest
            or receipt["ghidra_export_sha256"] != export_digest
        ):
            raise ValueError(f"{label} analysis receipt artifact binding mismatch")
        tool_version = _nonempty(receipt["tool_version"], f"{label}.tool_version")
        cache_key = _nonempty(receipt["cache_key"], f"{label}.cache_key")
        if receipt_version == ANALYSIS_RECEIPT_VERSION and cache_key != binary_digest[:16]:
            raise ValueError(f"{label} analysis receipt cache key mismatch")
        synthetic = receipt["synthetic_fixture"]
        if not isinstance(synthetic, bool):
            raise ValueError(f"{label} synthetic_fixture must be a boolean")
        expected_producer = (
            IOCTL_ANALYSIS_PRODUCER
            if receipt_version
            in {
                ANALYSIS_RECEIPT_VERSION_V2,
                ANALYSIS_RECEIPT_VERSION_V3,
                ANALYSIS_RECEIPT_VERSION_V4,
            }
            else (ANALYSIS_FIXTURE_PRODUCER if synthetic else ANALYSIS_PRODUCER)
        )
        if receipt["producer"] != expected_producer:
            raise ValueError(f"{label} analysis receipt producer mismatch")
        if receipt_version in {
            ANALYSIS_RECEIPT_VERSION_V2,
            ANALYSIS_RECEIPT_VERSION_V3,
            ANALYSIS_RECEIPT_VERSION_V4,
        }:
            if synthetic:
                raise ValueError(f"{label} IOCTL analysis receipt cannot be synthetic")
            from .windows_ioctl_ghidra_export import (
                EXPORT_VERSION_V2,
                EXPORT_VERSION_V3,
                EXTRACTOR_CONFIG_SHA256,
                EXTRACTOR_CONFIG_SHA256_V2,
                EXTRACTOR_PROFILE,
                EXTRACTOR_PROFILE_V2,
                VID_EXTRACTOR_CONFIG_SHA256,
                VID_EXTRACTOR_PROFILE,
                VID_PDB_SHA256,
                canonical_export_bytes,
            )

            profile_configs = {
                EXTRACTOR_PROFILE: EXTRACTOR_CONFIG_SHA256,
                EXTRACTOR_PROFILE_V2: EXTRACTOR_CONFIG_SHA256_V2,
                VID_EXTRACTOR_PROFILE: VID_EXTRACTOR_CONFIG_SHA256,
            }
            expected_export_binding = {
                "export_schema_version": (
                    EXPORT_VERSION_V3
                    if receipt_version
                    in {ANALYSIS_RECEIPT_VERSION_V3, ANALYSIS_RECEIPT_VERSION_V4}
                    else EXPORT_VERSION_V2
                ),
            }
            for receipt_field, expected in expected_export_binding.items():
                if receipt[receipt_field] != expected:
                    raise ValueError(f"{label} analysis receipt {receipt_field} mismatch")
            profile = receipt["extractor_profile"]
            if profile not in profile_configs:
                raise ValueError(f"{label} analysis receipt extractor_profile mismatch")
            is_vid_binary = binary_digest == VID_DRIVER_SHA256
            if (profile == VID_EXTRACTOR_PROFILE) is not is_vid_binary:
                raise ValueError(f"{label} analysis receipt Vid profile binding mismatch")
            if (
                receipt_version in {ANALYSIS_RECEIPT_VERSION_V3, ANALYSIS_RECEIPT_VERSION_V4}
                and profile != EXTRACTOR_PROFILE
            ):
                raise ValueError(
                    f"{label} v3/v4 receipt requires the semantic-proof profile"
                )
            if (
                receipt_version == ANALYSIS_RECEIPT_VERSION_V2
                and profile not in {EXTRACTOR_PROFILE_V2, VID_EXTRACTOR_PROFILE}
            ):
                raise ValueError(f"{label} v2 receipt requires a frozen v2 profile")
            if is_vid_binary and tool_version != "11.3.2":
                raise ValueError(f"{label} Vid analysis requires Ghidra 11.3.2")
            if receipt["extractor_config_sha256"] != profile_configs[profile]:
                raise ValueError(
                    f"{label} analysis receipt extractor_config_sha256 mismatch"
                )
            if (
                export_raw.get("schema_version") != receipt["export_schema_version"]
                or export_raw.get("extractor_profile") != receipt["extractor_profile"]
                or export_raw.get("extractor_config_sha256")
                != receipt["extractor_config_sha256"]
            ):
                raise ValueError(f"{label} analysis receipt export contract binding mismatch")
            if canonical_export_bytes(export_raw) != export_copy.read_bytes():
                raise ValueError(f"{label} High-P-Code export is not canonical")
        verified_public_receipt: PublicPdbReceipt | None = None
        if receipt_version == ANALYSIS_RECEIPT_VERSION_V4:
            from .windows_public_pdb import verify_public_pdb_receipt

            public = receipt["public_pdb"]
            if not isinstance(public, dict):
                raise ValueError(f"{label} analysis receipt public_pdb must be an object")
            _exact_fields(
                public,
                {
                    "bundle_path",
                    "receipt_sha256",
                    "requested_url",
                    "pe_guid",
                    "pe_age",
                    "pdb_guid",
                    "pdb_age",
                    "exact_age_match",
                },
                f"{label}.public_pdb",
            )
            public_bundle = _relative_directory(
                receipt_path.parent,
                public["bundle_path"],
                f"{label}.public_pdb.bundle_path",
            )
            verified_public_receipt = verify_public_pdb_receipt(binary_copy, public_bundle)
            expected_public = {
                "bundle_path": str(public["bundle_path"]),
                "receipt_sha256": verified_public_receipt.receipt_sha256,
                "requested_url": verified_public_receipt.requested_url,
                "pe_guid": verified_public_receipt.pe_guid,
                "pe_age": verified_public_receipt.pe_age,
                "pdb_guid": verified_public_receipt.pdb_guid,
                "pdb_age": verified_public_receipt.pdb_age,
                "exact_age_match": verified_public_receipt.exact_age_match,
            }
            if public != expected_public:
                raise ValueError(f"{label} public-PDB route binding mismatch")
            public_pdb_receipt_sha256 = verified_public_receipt.receipt_sha256
            public_pdb_requested_url = verified_public_receipt.requested_url
            public_pdb_exact_age_match = verified_public_receipt.exact_age_match
            public_pdb_pe_guid = verified_public_receipt.pe_guid
            public_pdb_pe_age = verified_public_receipt.pe_age
            public_pdb_pdb_guid = verified_public_receipt.pdb_guid
            public_pdb_pdb_age = verified_public_receipt.pdb_age
        pdb = receipt["pdb"]
        if not isinstance(pdb, dict):
            raise ValueError(f"{label} analysis receipt pdb must be an object")
        if receipt_version == ANALYSIS_RECEIPT_VERSION_V4:
            _exact_fields(
                pdb,
                {"path", "sha256", "identity", "pe_route_codeview_identity"},
                f"{label}.pdb",
            )
        else:
            _exact_fields(pdb, {"path", "sha256", "codeview_identity"}, f"{label}.pdb")
        codeview = pe_codeview_identity(binary_copy)
        observed_pe = f"{codeview[0]}:{codeview[1]}:{codeview[2]}" if codeview else ""
        observed_pdb = observed_pe
        pdb_digest = ""
        if synthetic:
            if codeview is not None or any(str(pdb[field]) for field in pdb):
                raise ValueError(f"{label} synthetic fixture must not carry real PE/PDB identity")
        else:
            receipt_pe_identity = (
                pdb["pe_route_codeview_identity"]
                if receipt_version == ANALYSIS_RECEIPT_VERSION_V4
                else pdb["codeview_identity"]
            )
            if codeview is None or receipt_pe_identity != observed_pe:
                raise ValueError(f"{label} PE/PDB CodeView identity mismatch")
            pdb_path = _relative_file(receipt_path.parent, pdb["path"], f"{label}.pdb.path")
            if (
                verified_public_receipt is not None
                and _lexical_absolute(pdb_path)
                != _lexical_absolute(verified_public_receipt.artifact_path)
            ):
                raise ValueError(f"{label} public-PDB artifact path binding mismatch")
            pdb_copy = private / "pdb.snapshot"
            pdb_digest = _snapshot_file(pdb_path, pdb_copy, f"{label} PDB", _PDB_SIZE_CAP)
            if pdb_digest != _sha256(pdb["sha256"], f"{label}.pdb.sha256"):
                raise ValueError(f"{label} PDB SHA-256 mismatch")
            actual_pdb = pdb_codeview_identity(pdb_copy)
            if receipt_version == ANALYSIS_RECEIPT_VERSION_V4:
                actual_identity = pdb["identity"]
                if not isinstance(actual_identity, dict):
                    raise ValueError(f"{label} public PDB identity must be an object")
                _exact_fields(
                    actual_identity, {"guid", "age", "stripped"}, f"{label}.pdb.identity"
                )
                if actual_pdb is None or actual_identity != {
                    "guid": actual_pdb[0],
                    "age": actual_pdb[1],
                    "stripped": actual_pdb[2],
                }:
                    raise ValueError(f"{label} actual public PDB identity mismatch")
                if verified_public_receipt is None or actual_identity != {
                    "guid": verified_public_receipt.pdb_guid,
                    "age": verified_public_receipt.pdb_age,
                    "stripped": True,
                }:
                    raise ValueError(f"{label} public PDB identity differs from route")
                observed_pdb = (
                    f"{actual_pdb[0]}:{actual_pdb[1]}:"
                    f"{'stripped' if actual_pdb[2] else 'full'}"
                )
            if receipt_version in {
                ANALYSIS_RECEIPT_VERSION_V2,
                ANALYSIS_RECEIPT_VERSION_V3,
                ANALYSIS_RECEIPT_VERSION_V4,
            }:
                vid_profile = receipt["extractor_profile"] == VID_EXTRACTOR_PROFILE
                if vid_profile and pdb_digest != VID_PDB_SHA256:
                    raise ValueError(f"{label} Vid PDB SHA-256 mismatch")
                if actual_pdb is None or (
                    actual_pdb[2] is not False
                    and not vid_profile
                    and verified_public_receipt is None
                ):
                    raise ValueError(f"{label} dedicated IOCTL analysis requires full PDB")
                if actual_pdb[0] != codeview[0] or (
                    actual_pdb[1] != codeview[1]
                    and not (
                        (vid_profile and actual_pdb[2])
                        or (verified_public_receipt is not None and actual_pdb[2])
                    )
                ):
                    raise ValueError(f"{label} actual PDB GUID and age do not match PE CodeView")
            elif actual_pdb is None or actual_pdb[0] != codeview[0] or (
                actual_pdb[1] != codeview[1] and not actual_pdb[2]
            ):
                raise ValueError(f"{label} actual PDB identity does not match PE CodeView")
        if receipt_version in {
            ANALYSIS_RECEIPT_VERSION_V2,
            ANALYSIS_RECEIPT_VERSION_V3,
            ANALYSIS_RECEIPT_VERSION_V4,
        }:
            expected_cache_key = (
                _public_ioctl_analysis_cache_key(
                    binary_digest,
                    pdb_digest,
                    tool_version,
                    str(receipt["extractor_profile"]),
                    str(receipt["extractor_config_sha256"]),
                    public_pdb_receipt_sha256,
                )
                if receipt_version == ANALYSIS_RECEIPT_VERSION_V4
                else _ioctl_analysis_cache_key(
                    binary_digest,
                    pdb_digest,
                    tool_version,
                    str(receipt["extractor_profile"]),
                    str(receipt["extractor_config_sha256"]),
                )
            )
            if cache_key != expected_cache_key:
                raise ValueError(f"{label} analysis receipt cache key mismatch")
    return Artifact(
        binary,
        export,
        binary_digest,
        export_digest,
        observed_pdb,
        pdb_digest,
        receipt_digest,
        tool_version,
        cache_key,
        synthetic,
        export_raw,
        public_pdb_receipt_sha256,
        public_pdb_requested_url,
        public_pdb_exact_age_match,
        public_pdb_pe_guid,
        public_pdb_pe_age,
        public_pdb_pdb_guid,
        public_pdb_pdb_age,
        observed_pe,
    )


def _ioctl_analysis_cache_key(
    binary_sha256: str,
    pdb_sha256: str,
    tool_version: str,
    extractor_profile: str,
    extractor_config_sha256: str,
) -> str:
    material = b"\0".join(
        value.encode("utf-8")
        for value in (
            binary_sha256,
            pdb_sha256,
            tool_version,
            extractor_profile,
            extractor_config_sha256,
        )
    )
    return hashlib.sha256(_IOCTL_ANALYSIS_CACHE_DOMAIN + material).hexdigest()


def _public_ioctl_analysis_cache_key(
    binary_sha256: str,
    pdb_sha256: str,
    tool_version: str,
    extractor_profile: str,
    extractor_config_sha256: str,
    public_pdb_receipt_sha256: str,
) -> str:
    material = b"\0".join(
        value.encode("utf-8")
        for value in (
            binary_sha256,
            pdb_sha256,
            tool_version,
            extractor_profile,
            extractor_config_sha256,
            public_pdb_receipt_sha256,
        )
    )
    return hashlib.sha256(_PUBLIC_IOCTL_ANALYSIS_CACHE_DOMAIN + material).hexdigest()


def _public_receipt_binding(receipt: object) -> tuple[object, ...]:
    return tuple(
        getattr(receipt, name)
        for name in (
            "artifact_sha256",
            "artifact_size_bytes",
            "receipt_sha256",
            "requested_url",
            "pe_guid",
            "pe_age",
            "pdb_guid",
            "pdb_age",
            "exact_age_match",
        )
    )


def _load_reachability(raw: object) -> dict[str, Reachability]:
    if not isinstance(raw, dict):
        raise ValueError("reachability must be an object keyed by function")
    out: dict[str, Reachability] = {}
    for function, value in raw.items():
        if not isinstance(function, str) or not function.strip() or not isinstance(value, dict):
            raise ValueError("reachability entries must map function names to objects")
        _exact_fields(value, {"grade", "evidence"}, f"reachability.{function}")
        grade = str(value["grade"])
        evidence = str(value["evidence"])
        if grade not in _REACHABILITY_GRADES:
            raise ValueError(f"unsupported reachability grade for {function}: {grade}")
        if grade != "unknown" and not evidence.strip():
            raise ValueError(f"reachability evidence is required for {function}")
        out[function] = Reachability(grade, evidence)
    return out


def _function_shapes(export: dict[str, Any]) -> dict[str, FunctionShape]:
    meta = export.get("meta", {})
    if not isinstance(meta, dict) or not isinstance(meta.get("decompiled_c"), dict):
        raise ValueError("Ghidra export has no meta.decompiled_c object")
    addresses: dict[str, int] = {}
    insts = export.get("insts", [])
    if isinstance(insts, list):
        for inst in insts:
            if not isinstance(inst, dict):
                continue
            function = str(inst.get("func", ""))
            try:
                address = int(inst.get("addr", 0))
            except (TypeError, ValueError):
                continue
            if (
                function
                and address
                and (function not in addresses or address < addresses[function])
            ):
                addresses[function] = address
    return {
        str(name): _shape(str(name), str(body), addresses.get(str(name), 0))
        for name, body in meta["decompiled_c"].items()
    }


def _shape(name: str, body: str, rva: int) -> FunctionShape:
    sinks = frozenset(kind for kind, pattern in _SINKS.items() if pattern.search(body))
    guards = _sink_guard_hints(body)
    flow = _lexical_parameter_sink_hint(body)
    toctou = _double_resolution_window(body)
    return FunctionShape(name, body, rva, sinks, guards, flow, toctou)


def _double_resolution_window(body: str) -> bool:
    """True when one identifier is the path operand of two or more distinct
    path-resolution sink calls — the check-then-act re-resolution window that
    makes a link-following bug exploitable (scan-then-clean, verify-then-open).
    Lexical only: loop re-entry and handle-shaped first arguments can match;
    this feeds ranking, never a verdict."""
    seen: set[str] = set()
    for sink, pattern in _SINKS.items():
        if sink not in _PATH_SINKS:
            continue
        for match in pattern.finditer(body):
            end = body.find(")", match.end())
            if end < 0:
                continue
            first = body[match.end() : end].split(",", 1)[0]
            identifiers = _IDENTIFIER.findall(first)
            if not identifiers:
                continue
            operand = identifiers[-1]
            if operand in seen:
                return True
            seen.add(operand)
    return False


def _lexical_parameter_sink_hint(body: str) -> tuple[str, str] | None:
    params = _parameters(body)
    aliases = _param_aliases(body, params)
    for sink, pattern in _SINKS.items():
        for match in pattern.finditer(body):
            relevant = _sink_relevant_text(body, sink, match)
            for param in params:
                if re.search(rf"\b{re.escape(param)}\b", relevant):
                    return param, sink
            for identifier in set(_IDENTIFIER.findall(relevant)):
                bound = aliases.get(identifier)
                if bound is not None:
                    return bound, sink
    return None


_ALIAS_ASSIGN = re.compile(r"\b([A-Za-z_]\w*)\s*=\s*(?:\([^()]*\)\s*)?&?\s*([A-Za-z_]\w*)\s*;")


def _param_aliases(body: str, params: tuple[str, ...]) -> dict[str, str]:
    """One-hop parameter aliases from simple assignments (``local = param;``,
    optionally cast/address-of). Decompiler output splits parameters into
    locals constantly; this recovers the direct-alias case only. Struct-field
    indirection (an OBJECT_ATTRIBUTES built field-by-field) stays unresolved
    by design — that needs the grounded IR, not another regex."""
    out: dict[str, str] = {}
    for lhs, rhs in _ALIAS_ASSIGN.findall(body):
        if rhs in params and lhs not in params:
            out.setdefault(lhs, rhs)
    return out


def _sink_guard_hints(body: str) -> frozenset[str]:
    """Return lexical guard hints present around every recognized sink.

    Bounds hints must name an identifier used by that sink.  Other boundary
    checks must occur in the preceding local window.  Link-resolution guards
    (``_POST_OPEN_GUARDS``) may appear in the sink call itself (open flags) or
    in the post-open window (tag/final-path verification), so they search a
    symmetric window around the sink.  This is intentionally not represented
    as dominance or proof; it only controls candidate ranking.
    """
    per_sink: list[frozenset[str]] = []
    for sink, pattern in _SINKS.items():
        for match in pattern.finditer(body):
            relevant = _sink_relevant_text(body, sink, match)
            relevant_ids = set(_IDENTIFIER.findall(relevant))
            prefix = body[max(0, match.start() - 2000) : match.start()]
            window = body[max(0, match.start() - 2000) : match.start() + 2000]
            hints: set[str] = set()
            for condition in _IF_CONDITION.findall(prefix):
                if (
                    relevant_ids & set(_IDENTIFIER.findall(condition))
                    and re.search(r"<=|>=|<|>", condition)
                ):
                    hints.add("bounds")
            for guard, guard_pattern in _GUARDS.items():
                if guard == "bounds":
                    continue
                region = window if guard in _POST_OPEN_GUARDS else prefix
                if guard_pattern.search(region):
                    hints.add(guard)
            if (
                sink in _PATH_SINKS
                and "no-reparse-open" not in hints
                and _numeric_no_reparse(match.group(0), relevant)
            ):
                hints.add("no-reparse-open")
            per_sink.append(frozenset(hints))
    if not per_sink:
        return frozenset()
    shared = set(per_sink[0])
    for sink_hints in per_sink[1:]:
        shared.intersection_update(sink_hints)
    return frozenset(shared)


def _sink_relevant_text(body: str, sink: str, match: re.Match[str]) -> str:
    if sink == "indexed-store":
        end = body.find(";", match.start())
        return body[match.start() : end if end >= 0 else len(body)]
    end = body.find(")", match.end())
    if end < 0:
        return ""
    args = body[match.end() : end].split(",")
    if sink in _PATH_SINKS:
        # Path-resolution sinks are attacker-influenced at argument 0 (the
        # path itself); mutation helpers carry source and destination paths.
        return ",".join(args)
    # The destination itself is not attacker-controlled dataflow. Copy/fill
    # source, value, and length operands begin at argument 1.
    return ",".join(args[1:])


def _numeric_no_reparse(call: str, call_args: str) -> bool:
    """Hex-literal fallback when the decompiler renders open flags as numbers:
    True when the call's flags/create-options operand carries the no-reparse /
    no-recall bits. Scoped to the flags argument only — testing every argument
    false-fires on NT-native opens whose DesiredAccess carries SYNCHRONIZE
    (0x00100000), measured on vmswitch!VmsProxyOpenDevice 2026-08-12."""
    index = _FLAG_ARG_INDEX.get(call.rstrip("(").strip().lower())
    if index is None:
        return False
    args = call_args.split(",")
    if len(args) <= index:
        return False
    for literal in _HEX_LITERAL.findall(args[index]):
        try:
            value = int(literal, 16)
        except ValueError:
            continue
        if value & _NO_REPARSE_FLAG_BITS:
            return True
    return False


def _parameters(body: str) -> tuple[str, ...]:
    match = _SIGNATURE.search(body.strip())
    if match is None:
        return ()
    out: list[str] = []
    for raw in match.group(1).split(","):
        part = raw.strip()
        found = _PARAM.search(part)
        if found and found.group(1) != "void":
            out.append(found.group(1))
    return tuple(out)


def _score(
    shape: FunctionShape,
    matched_sinks: frozenset[str],
    seed_sinks: frozenset[str],
    missing_guards: frozenset[str],
    guard_delta: frozenset[str],
) -> int:
    score = round(40 * len(matched_sinks) / len(seed_sinks))
    score += round(30 * len(missing_guards) / len(guard_delta))
    if shape.parameter_flow:
        score += 15
    if shape.toctou_window:
        score += 10
    return max(0, min(100, score))


def _ghidra_version(home: Path) -> str:
    if home.is_symlink() or not home.is_dir():
        raise ValueError("Ghidra home must be a regular non-symlink directory")
    candidates = (home / "Ghidra" / "application.properties", home / "application.properties")
    for properties in candidates:
        if properties.is_symlink() or not properties.is_file():
            continue
        for line in properties.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator and key.strip() == "application.version" and value.strip():
                return value.strip()
    raise ValueError("Ghidra application.version was not found under Ghidra home")


def _next_validator(grade: str) -> str:
    if grade in {"root-only", "internal-only"}:
        return "do not dynamically test unless a supported non-root caller is established"
    return "establish a supported unprivileged or ordinary-child caller before dynamic testing"


def _artifact_record(artifact: Artifact) -> dict[str, object]:
    record: dict[str, object] = {
        "binary_sha256": artifact.binary_sha256,
        "ghidra_export_sha256": artifact.export_sha256,
        "pdb_identity": artifact.pdb_identity,
        "pdb_sha256": artifact.pdb_sha256,
        "analysis_receipt_sha256": artifact.analysis_receipt_sha256,
        "ghidra_version": artifact.ghidra_version,
        "cache_key": artifact.cache_key,
        "synthetic_fixture": artifact.synthetic_fixture,
    }
    if artifact.public_pdb_receipt_sha256:
        record["public_pdb"] = {
            "receipt_sha256": artifact.public_pdb_receipt_sha256,
            "requested_url": artifact.public_pdb_requested_url,
            "pe_guid": artifact.public_pdb_pe_guid,
            "pe_age": artifact.public_pdb_pe_age,
            "pdb_guid": artifact.public_pdb_pdb_guid,
            "pdb_age": artifact.public_pdb_pdb_age,
            "exact_age_match": artifact.public_pdb_exact_age_match,
            "pe_route_codeview_identity": artifact.pe_codeview_identity,
        }
    return record


def _relative_file(base: Path, raw: object, label: str) -> Path:
    value = _nonempty(raw, label)
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"{label} must be relative to the campaign manifest")
    path = base / candidate
    cursor = base
    for part in candidate.parts:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError(f"{label} must be a regular non-symlink file")
    try:
        resolved_base = base.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{label} must be a regular non-symlink file") from exc
    if (
        path.is_symlink()
        or not path.is_file()
        or not resolved_path.is_relative_to(resolved_base)
    ):
        raise ValueError(f"{label} must be a regular non-symlink file")
    return path


def _relative_directory(base: Path, raw: object, label: str) -> Path:
    value = _nonempty(raw, label)
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts or "\\" in value:
        raise ValueError(f"{label} must be relative to the analysis receipt")
    path = base / candidate
    cursor = base
    for part in candidate.parts:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError(f"{label} must be a regular non-symlink directory")
    try:
        resolved_base = base.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{label} must be a regular non-symlink directory") from exc
    if (
        path.is_symlink()
        or not path.is_dir()
        or not resolved_path.is_relative_to(resolved_base)
    ):
        raise ValueError(f"{label} must be a regular non-symlink directory")
    return path


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(path))  # noqa: PTH100 - comparison must not follow links


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256(raw: object, label: str) -> str:
    value = str(raw)
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _nonempty(raw: object, label: str) -> str:
    value = str(raw)
    if not value.strip() or "\x00" in value:
        raise ValueError(f"{label} must be a nonempty string without NUL bytes")
    return value


def _exact_fields(raw: dict[str, object], expected: set[str], label: str) -> None:
    missing = sorted(expected - raw.keys())
    unknown = sorted(raw.keys() - expected)
    if missing or unknown:
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if unknown:
            details.append(f"unknown {', '.join(unknown)}")
        raise ValueError(f"{label} fields invalid: {'; '.join(details)}")


def _site_set(raw: object, label: str) -> frozenset[tuple[str, str]]:
    if not isinstance(raw, list) or not raw:
        raise ValueError(f"{label} must be a nonempty array")
    sites: set[tuple[str, str]] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"{label}[{index}] must be an object")
        _exact_fields(item, {"function", "function_address"}, f"{label}[{index}]")
        function = _nonempty(item["function"], f"{label}[{index}].function")
        address = str(item["function_address"])
        if re.fullmatch(r"0x[0-9a-f]+", address) is None:
            raise ValueError(f"{label}[{index}].function_address must be lowercase hex")
        sites.add((function, address))
    return frozenset(sites)


def _site_records(sites: frozenset[tuple[str, str]] | set[tuple[str, str]]) -> list[dict[str, str]]:
    return [
        {"function": function, "function_address": address}
        for function, address in sorted(sites)
    ]


def _positive_int(raw: object, label: str) -> int:
    if not isinstance(raw, int) or isinstance(raw, bool) or raw <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return raw


def _nonnegative_int(raw: object, label: str) -> int:
    if not isinstance(raw, int) or isinstance(raw, bool) or raw < 0:
        raise ValueError(f"{label} must be a nonnegative integer")
    return raw


def _ratio(raw: object, label: str) -> float:
    if not isinstance(raw, (int, float)) or isinstance(raw, bool):
        raise ValueError(f"{label} must be a number from 0 to 1")
    value = float(raw)
    if not 0 <= value <= 1:
        raise ValueError(f"{label} must be a number from 0 to 1")
    return value
