"""Strict, portable precommitment for a Windows candidate/control pair."""

from __future__ import annotations

import hashlib
import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .windows_lpe_opaque_content import WindowsLpeOpaqueContent
from .windows_provenance import (
    verify_official_download_receipt,
    verify_official_download_receipt_prehashed,
)

PAIR_PLAN_SCHEMA = "0verse.windows-pair-plan/v1"
PAIR_PLAN_PRODUCER = "zeroverse.windows-pair-plan/v1"
PAIR_PLAN_CLAIMS = [
    "plan-referenced-content-sha256",
    "official-download-receipts-verified",
    "candidate-control-identities-bound",
]
PAIR_PLAN_PROOF_LIMIT = (
    "Plan binding only; CVE/KB/build association, Microsoft authenticity, servicing "
    "derivation, vulnerable/fixed status, reachability, reproducibility, and redistribution "
    "rights are unproven."
)

_SHA256 = re.compile(r"[0-9a-f]{64}")
_CVE = re.compile(r"CVE-(?:19|20)\d{2}-[1-9]\d{3,}")
_KB = re.compile(r"KB[1-9]\d{5,9}")
_BUILD_LAB_EX = re.compile(
    r"[1-9]\d{3,5}\.\d{1,7}\.(amd64fre|arm64fre)\.[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"
)
_ARCH_MACHINES = {"amd64": 0x8664, "arm64": 0xAA64}


@dataclass(frozen=True)
class VerifiedWindowsPairPlan:
    plan_path: Path
    plan_sha256: str
    cve_id: str
    component: str
    architecture: str
    candidate_sha256: str
    control_sha256: str
    candidate_kb_id: str
    control_kb_id: str
    candidate_build_lab_ex: str
    control_build_lab_ex: str
    candidate_acquisition_artifact_sha256s: tuple[str, ...]
    control_acquisition_artifact_sha256s: tuple[str, ...]
    candidate_acquisition_receipt_sha256s: tuple[str, ...]
    control_acquisition_receipt_sha256s: tuple[str, ...]
    acquisition_receipt_sha256s: tuple[str, ...]
    recipe_sha256: str
    tools: tuple[tuple[str, str], ...]
    tool_sha256s: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "plan_path": str(self.plan_path),
            "plan_sha256": self.plan_sha256,
            "cve_id": self.cve_id,
            "component": self.component,
            "architecture": self.architecture,
            "candidate_sha256": self.candidate_sha256,
            "control_sha256": self.control_sha256,
            "candidate_kb_id": self.candidate_kb_id,
            "control_kb_id": self.control_kb_id,
            "candidate_build_lab_ex": self.candidate_build_lab_ex,
            "control_build_lab_ex": self.control_build_lab_ex,
            "candidate_acquisition_artifact_sha256s": list(
                self.candidate_acquisition_artifact_sha256s
            ),
            "control_acquisition_artifact_sha256s": list(
                self.control_acquisition_artifact_sha256s
            ),
            "candidate_acquisition_receipt_sha256s": list(
                self.candidate_acquisition_receipt_sha256s
            ),
            "control_acquisition_receipt_sha256s": list(
                self.control_acquisition_receipt_sha256s
            ),
            "acquisition_receipt_sha256s": list(self.acquisition_receipt_sha256s),
            "recipe_sha256": self.recipe_sha256,
            "tools": [
                {"name": name, "sha256": digest} for name, digest in self.tools
            ],
            "tool_sha256s": list(self.tool_sha256s),
        }


@dataclass(frozen=True)
class _PairSide:
    kb_id: str
    build_lab_ex: str
    artifact_sha256: str
    acquisition_artifact_sha256s: tuple[str, ...]
    acquisition_receipt_sha256s: tuple[str, ...]


def verify_windows_pair_plan(
    plan_path: str | Path, *, opaque_content: WindowsLpeOpaqueContent | None = None
) -> VerifiedWindowsPairPlan:
    """Re-derive every claim a pair plan is allowed to make."""
    plan_file = _regular_file(Path(plan_path), "pair plan")
    if plan_file.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("Windows pair plan exceeds the 4 MiB limit")
    plan_bytes = plan_file.read_bytes()
    raw = json.loads(plan_bytes, object_pairs_hook=_unique_object)
    if not isinstance(raw, dict):
        raise ValueError("Windows pair plan must be a JSON object")
    _exact(
        raw,
        {
            "schema_version",
            "producer",
            "declared_context",
            "candidate",
            "control",
            "reproduction",
            "verified_claims",
            "proof_limit",
        },
        "plan",
    )
    if raw["schema_version"] != PAIR_PLAN_SCHEMA or raw["producer"] != PAIR_PLAN_PRODUCER:
        raise ValueError("Windows pair plan schema/producer mismatch")

    context = _object(raw["declared_context"], "declared_context")
    _exact(context, {"cve_id", "component", "architecture"}, "declared_context")
    cve_id = _match(context["cve_id"], _CVE, "declared_context.cve_id")
    component = _basename(context["component"], "declared_context.component")
    architecture = str(context["architecture"])
    if architecture not in _ARCH_MACHINES:
        raise ValueError("pair plan architecture must be amd64 or arm64")

    base = plan_file.parent.resolve()
    candidate = _side(
        raw["candidate"], "candidate", base, component, architecture, opaque_content
    )
    control = _side(
        raw["control"], "control", base, component, architecture, opaque_content
    )
    if candidate.artifact_sha256 == control.artifact_sha256:
        raise ValueError("pair plan candidate/control artifact SHA-256 must differ")
    if candidate.kb_id == control.kb_id:
        raise ValueError("pair plan candidate/control KB IDs must differ")
    if candidate.build_lab_ex == control.build_lab_ex:
        raise ValueError("pair plan candidate/control BuildLabEx values must differ")
    if candidate.acquisition_artifact_sha256s[0] != control.acquisition_artifact_sha256s[0]:
        raise ValueError("pair plan candidate/control base media must match")
    if candidate.acquisition_receipt_sha256s[0] != control.acquisition_receipt_sha256s[0]:
        raise ValueError("pair plan candidate/control base receipt must match")
    if candidate.acquisition_receipt_sha256s[1:] == control.acquisition_receipt_sha256s[1:]:
        raise ValueError("pair plan candidate/control servicing receipts must differ")
    if candidate.acquisition_artifact_sha256s[1:] == control.acquisition_artifact_sha256s[1:]:
        raise ValueError("pair plan candidate/control servicing artifacts must differ")

    reproduction = _object(raw["reproduction"], "reproduction")
    _exact(reproduction, {"recipe", "tools"}, "reproduction")
    recipe = _file_reference_or_opaque(
        reproduction["recipe"], base, "reproduction.recipe", opaque_content
    )
    tools_raw = reproduction["tools"]
    if not isinstance(tools_raw, list) or not tools_raw:
        raise ValueError("pair plan reproduction.tools must be a nonempty array")
    tool_names: list[str] = []
    tool_paths: list[Path] = []
    tool_hashes: list[str] = []
    for index, raw_tool in enumerate(tools_raw):
        tool = _object(raw_tool, f"reproduction.tools[{index}]")
        _exact(tool, {"name", "path", "sha256", "size_bytes"}, f"reproduction.tools[{index}]")
        name = _nonempty(tool["name"], f"reproduction.tools[{index}].name")
        path, digest = _file_reference_or_opaque(
            {field: tool[field] for field in ("path", "sha256", "size_bytes")},
            base,
            f"reproduction.tools[{index}]",
            opaque_content,
        )
        tool_names.append(name)
        tool_paths.append(path)
        tool_hashes.append(digest)
    if tool_names != sorted(tool_names):
        raise ValueError("pair plan reproduction.tools must be sorted by name")
    if len(set(tool_names)) != len(tool_names) or len(set(tool_paths)) != len(tool_paths):
        raise ValueError("pair plan reproduction.tools names and paths must be unique")

    if raw["verified_claims"] != PAIR_PLAN_CLAIMS:
        raise ValueError("pair plan verified_claims mismatch")
    if raw["proof_limit"] != PAIR_PLAN_PROOF_LIMIT:
        raise ValueError("pair plan proof_limit mismatch")
    receipt_hashes = (
        candidate.acquisition_receipt_sha256s + control.acquisition_receipt_sha256s
    )
    return VerifiedWindowsPairPlan(
        plan_file.resolve(),
        hashlib.sha256(plan_bytes).hexdigest(),
        cve_id,
        component,
        architecture,
        candidate.artifact_sha256,
        control.artifact_sha256,
        candidate.kb_id,
        control.kb_id,
        candidate.build_lab_ex,
        control.build_lab_ex,
        candidate.acquisition_artifact_sha256s,
        control.acquisition_artifact_sha256s,
        candidate.acquisition_receipt_sha256s,
        control.acquisition_receipt_sha256s,
        receipt_hashes,
        recipe[1],
        tuple(zip(tool_names, tool_hashes, strict=True)),
        tuple(tool_hashes),
    )


def _side(
    raw: object,
    label: str,
    base: Path,
    component: str,
    architecture: str,
    opaque_content: WindowsLpeOpaqueContent | None,
) -> _PairSide:
    side = _object(raw, label)
    _exact(side, {"kb_id", "build_lab_ex", "artifact", "acquisition_receipts"}, label)
    kb_id = _match(side["kb_id"], _KB, f"{label}.kb_id")
    build = _build_lab_ex(side["build_lab_ex"], architecture, f"{label}.build_lab_ex")
    artifact_path, artifact_digest = _file_reference(side["artifact"], base, f"{label}.artifact")
    if artifact_path.name != component:
        raise ValueError(f"pair plan {label} artifact basename must equal component")
    observed_machine = _pe_machine(artifact_path)
    if observed_machine != _ARCH_MACHINES[architecture]:
        raise ValueError(f"pair plan {label} PE machine does not match architecture")

    acquisitions = side["acquisition_receipts"]
    if not isinstance(acquisitions, list) or len(acquisitions) < 2:
        raise ValueError(f"pair plan {label} needs base media and servicing receipts")
    artifact_hashes: list[str] = []
    receipt_hashes: list[str] = []
    bundle_paths: list[Path] = []
    for index, raw_acquisition in enumerate(acquisitions):
        acquisition = _object(raw_acquisition, f"{label}.acquisition_receipts[{index}]")
        _exact(
            acquisition,
            {"purpose", "bundle_path", "artifact_sha256", "receipt_sha256"},
            f"{label}.acquisition_receipts[{index}]",
        )
        expected_purpose = "base-media" if index == 0 else "servicing-package"
        if acquisition["purpose"] != expected_purpose:
            raise ValueError(f"pair plan {label} acquisition receipt order/purpose is invalid")
        bundle = _relative_path(base, acquisition["bundle_path"], f"{label}.bundle_path")
        if bundle.is_symlink() or not bundle.is_dir():
            raise ValueError(f"pair plan {label} acquisition bundle must be a directory")
        if opaque_content is None:
            verified = verify_official_download_receipt(bundle)
        else:
            artifact_ref = opaque_content.consume(
                f"{acquisition['bundle_path']}/artifact"
            )
            verified = verify_official_download_receipt_prehashed(
                bundle,
                artifact_sha256=artifact_ref.sha256,
                artifact_size_bytes=artifact_ref.size_bytes,
            )
        artifact_sha = _sha256(acquisition["artifact_sha256"], f"{label}.artifact_sha256")
        receipt_sha = _sha256(acquisition["receipt_sha256"], f"{label}.receipt_sha256")
        if verified.artifact_sha256 != artifact_sha or verified.receipt_sha256 != receipt_sha:
            raise ValueError(f"pair plan {label} acquisition receipt binding mismatch")
        if index == 0 and verified.kind != "iso":
            raise ValueError(f"pair plan {label} base media must be an ISO")
        if index > 0 and verified.kind not in {"msu", "cab"}:
            raise ValueError(f"pair plan {label} servicing package must be an MSU or CAB")
        bundle_paths.append(bundle)
        artifact_hashes.append(artifact_sha)
        receipt_hashes.append(receipt_sha)
    if len(set(bundle_paths)) != len(bundle_paths):
        raise ValueError(f"pair plan {label} acquisition bundles must be unique")
    return _PairSide(kb_id, build, artifact_digest, tuple(artifact_hashes), tuple(receipt_hashes))


def _file_reference_or_opaque(
    raw: object,
    base: Path,
    label: str,
    opaque_content: WindowsLpeOpaqueContent | None,
) -> tuple[Path, str]:
    if opaque_content is None:
        return _file_reference(raw, base, label)
    reference = _object(raw, label)
    _exact(reference, {"path", "sha256", "size_bytes"}, label)
    relative = reference["path"]
    if not isinstance(relative, str):
        raise ValueError(f"pair plan {label}.path must be a portable relative path")
    expected = _sha256(reference["sha256"], f"{label}.sha256")
    size = reference["size_bytes"]
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise ValueError(f"pair plan {label} size mismatch")
    opaque_content.require(relative, expected, size)
    path = _portable_unresolved_path(base, relative, f"{label}.path")
    return path, expected


def _portable_unresolved_path(base: Path, raw: str, label: str) -> Path:
    if not raw or "\\" in raw or "\x00" in raw:
        raise ValueError(f"pair plan {label} must be a portable relative path")
    pure = PurePosixPath(raw)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError(f"pair plan {label} must be a portable relative path")
    return base.joinpath(*pure.parts)


def _file_reference(raw: object, base: Path, label: str) -> tuple[Path, str]:
    reference = _object(raw, label)
    _exact(reference, {"path", "sha256", "size_bytes"}, label)
    path = _relative_path(base, reference["path"], f"{label}.path")
    file_path = _regular_file(path, label)
    expected = _sha256(reference["sha256"], f"{label}.sha256")
    observed, size = _hash_file(file_path)
    if observed != expected:
        raise ValueError(f"pair plan {label} SHA-256 mismatch")
    declared_size = reference["size_bytes"]
    if (
        not isinstance(declared_size, int)
        or isinstance(declared_size, bool)
        or declared_size <= 0
        or declared_size != size
    ):
        raise ValueError(f"pair plan {label} size mismatch")
    return file_path.resolve(), observed


def _pe_machine(path: Path) -> int:
    size = path.stat().st_size
    with path.open("rb") as source:
        dos_header = source.read(0x40)
        if len(dos_header) < 0x40 or dos_header[:2] != b"MZ":
            raise ValueError("pair plan artifact must be a PE file")
        pe_offset = struct.unpack_from("<I", dos_header, 0x3C)[0]
        if pe_offset > size - 24:
            raise ValueError("pair plan artifact has an invalid PE header")
        source.seek(pe_offset)
        headers = source.read(24)
        if len(headers) != 24 or headers[:4] != b"PE\0\0":
            raise ValueError("pair plan artifact has an invalid PE header")
        machine, section_count = struct.unpack_from("<HH", headers, 4)
        optional_size = int(struct.unpack_from("<H", headers, 20)[0])
        characteristics = int(struct.unpack_from("<H", headers, 22)[0])
        if not 1 <= section_count <= 96 or not 112 <= optional_size <= 4096:
            raise ValueError("pair plan artifact has invalid PE header dimensions")
        optional = source.read(optional_size)
        if len(optional) != optional_size or struct.unpack_from("<H", optional, 0)[0] != 0x20B:
            raise ValueError("pair plan artifact must be a coherent PE32+ image")
        section_alignment, file_alignment = struct.unpack_from("<II", optional, 32)
        size_of_image, size_of_headers = struct.unpack_from("<II", optional, 56)
        if (
            file_alignment < 512
            or file_alignment > 65536
            or file_alignment & (file_alignment - 1)
            or section_alignment < file_alignment
            or size_of_image == 0
            or size_of_headers == 0
            or size_of_headers > size
            or not characteristics & 0x0002
        ):
            raise ValueError("pair plan artifact PE32+ layout is invalid")
        section_table_end = pe_offset + 24 + optional_size + section_count * 40
        if section_table_end > size_of_headers or section_table_end > size:
            raise ValueError("pair plan artifact section table is out of bounds")
        section_table = source.read(section_count * 40)
    if len(section_table) != section_count * 40:
        raise ValueError("pair plan artifact section table is truncated")
    for index in range(section_count):
        entry = index * 40
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", section_table, entry + 8
        )
        mapped_size = max(virtual_size, raw_size)
        if mapped_size == 0 or virtual_address + mapped_size > size_of_image:
            raise ValueError("pair plan artifact section virtual range is invalid")
        if raw_size and (raw_offset < size_of_headers or raw_offset + raw_size > size):
            raise ValueError("pair plan artifact section raw range is invalid")
    if machine not in _ARCH_MACHINES.values():
        raise ValueError("pair plan artifact has an invalid PE header")
    return int(machine)


def _relative_path(base: Path, raw: object, label: str) -> Path:
    if not isinstance(raw, str) or not raw or "\\" in raw or "\x00" in raw:
        raise ValueError(f"pair plan {label} must be a portable relative path")
    pure = PurePosixPath(raw)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError(f"pair plan {label} must be a portable relative path")
    current = base
    for part in pure.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"pair plan {label} must not traverse a symlink")
    try:
        resolved = current.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"pair plan {label} does not exist") from exc
    if not resolved.is_relative_to(base):
        raise ValueError(f"pair plan {label} escapes the plan directory")
    return resolved


def _regular_file(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"pair plan {label} must be a regular non-symlink file")
    return path


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _object(raw: object, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict) or not all(isinstance(key, str) for key in raw):
        raise ValueError(f"pair plan {label} must be an object")
    return raw


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _exact(raw: dict[str, Any], expected: set[str], label: str) -> None:
    missing = sorted(expected - raw.keys())
    unknown = sorted(raw.keys() - expected)
    if missing or unknown:
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if unknown:
            details.append(f"unknown {', '.join(unknown)}")
        raise ValueError(f"pair plan {label} fields invalid: {'; '.join(details)}")


def _match(raw: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(raw, str):
        raise ValueError(f"pair plan {label} must be a string")
    value = raw
    if pattern.fullmatch(value) is None:
        raise ValueError(f"pair plan {label} is invalid")
    return value


def _sha256(raw: object, label: str) -> str:
    return _match(raw, _SHA256, label)


def _basename(raw: object, label: str) -> str:
    value = _nonempty(raw, label)
    if PurePosixPath(value).name != value or "\\" in value:
        raise ValueError(f"pair plan {label} must be a basename")
    return value


def _build_lab_ex(raw: object, architecture: str, label: str) -> str:
    if not isinstance(raw, str):
        raise ValueError(f"pair plan {label} must be a string")
    match = _BUILD_LAB_EX.fullmatch(raw)
    if match is None:
        raise ValueError(f"pair plan {label} is invalid")
    expected_token = "amd64fre" if architecture == "amd64" else "arm64fre"
    if match.group(1) != expected_token:
        raise ValueError(f"pair plan {label} architecture token mismatch")
    return raw


def _nonempty(raw: object, label: str) -> str:
    if not isinstance(raw, str) or not raw.strip() or "\x00" in raw or len(raw) > 512:
        raise ValueError(f"pair plan {label} must be a nonempty string")
    return raw
