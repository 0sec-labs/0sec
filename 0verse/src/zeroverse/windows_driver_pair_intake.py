"""Offline intake for role-neutral Windows driver build pairs.

The intake reuses the production Windows analysis-bundle verifier, then checks
the ordered local series declared by two independently retained snapshot
manifests. It has no acquisition, network, execution, labeling, or reporting
surface and makes no servicing-lineage or adjacency claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .windows_ioctl_ghidra_export import (
    EXPORT_VERSION_V3,
    EXTRACTOR_CONFIG_SHA256,
    EXTRACTOR_PROFILE,
    validate_windows_ioctl_high_pcode_export,
)
from .windows_variant import Artifact, _load_artifact

INTAKE_VERSION = "0verse.windows-driver-pair-intake/v2"
INTAKE_VERSION_V3 = "0verse.windows-driver-pair-intake/v3"
SNAPSHOT_VERSION = "0verse.windows-local-driver-export/v2"
SNAPSHOT_VERSION_V3 = "0verse.windows-local-driver-export/v3"
SERVICING_EVIDENCE_VERSION = "0verse.windows-retained-driver-servicing-evidence/v1"
RESULT_VERSION = "0verse.windows-driver-local-pair-input/v2"
RESULT_VERSION_V3 = "0verse.windows-driver-local-pair-input/v3"
PRODUCER = "zeroverse.windows-driver-pair-intake/v2"
PRODUCER_V3 = "zeroverse.windows-driver-pair-intake/v3"
PROOF_LIMIT = (
    "Local static intake only. The result verifies retained manifest and analysis-bundle "
    "bytes, real semantic-v3 PE/PDB identity, component, architecture, retained Windows "
    "CurrentBuild/UBR/file-version evidence, and compatible "
    "analysis tooling. It preserves a consecutive producer-declared local series only. It "
    "does not verify servicing derivation, build lineage or adjacency, artifact authenticity, "
    "redistribution rights, reachability, vulnerability, impact, novelty, exploitability, or "
    "bounty eligibility."
)
PROOF_LIMIT_V3 = (
    "Local static public-artifact intake only. The result re-verifies each complete "
    "content-addressed Microsoft public-PDB route bundle through its semantic-v3 analysis "
    "receipt, including stripped GUID-preserving transformations and any recorded age "
    "mismatch. It also verifies retained manifests, analysis bytes, component, architecture, "
    "Windows servicing evidence, and compatible analysis tooling. It does not prove "
    "Microsoft binary authenticity, servicing derivation or adjacency, redistribution "
    "rights, reachability, vulnerability, impact, novelty, exploitability, or bounty eligibility."
)

_SHA256 = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.sys", re.I)
_BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_STAMP = re.compile(r"\d{6}-\d{4}")
_MAX_MANIFEST_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class _Build:
    text: str
    base: int
    architecture: str
    branch: str


@dataclass(frozen=True)
class _ServicingEvidence:
    path: Path
    sha256: str
    current_build: int
    ubr: int
    file_version: str
    file_version_parts: tuple[int, int, int, int]


@dataclass(frozen=True)
class _Snapshot:
    manifest_path: Path
    manifest_sha256: str
    snapshot_id: str
    producer_series_id: str
    producer_series_ordinal: int
    source_kind: str
    component: str
    architecture: str
    build: _Build
    servicing: _ServicingEvidence
    artifact: Artifact
    descriptor: dict[str, str]


def plan_windows_driver_pair_intake(manifest_path: str | Path) -> dict[str, object]:
    """Verify two local snapshot exports and emit a neutral discovery input."""
    intake_path = Path(os.path.abspath(manifest_path))  # noqa: PTH100 - reject links below
    intake_bytes = _read_regular(intake_path, "intake manifest")
    raw = _object(_json(intake_bytes, "intake manifest"), "intake manifest")
    _exact(raw, {"schema_version", "campaign_id", "snapshot_manifests", "policy"}, "intake")
    intake_version = raw["schema_version"]
    if intake_version not in {INTAKE_VERSION, INTAKE_VERSION_V3}:
        raise ValueError("unsupported Windows driver pair intake schema")
    public_lane = intake_version == INTAKE_VERSION_V3
    campaign_id = _identifier(raw["campaign_id"], "campaign_id")
    _policy(raw["policy"])
    references = raw["snapshot_manifests"]
    if not isinstance(references, list) or len(references) != 2:
        raise ValueError("snapshot_manifests must contain exactly two local references")
    snapshots = [
        _load_snapshot(
            reference,
            intake_path.parent,
            f"snapshot_manifests[{index}]",
            snapshot_version=SNAPSHOT_VERSION_V3 if public_lane else SNAPSHOT_VERSION,
            public_lane=public_lane,
        )
        for index, reference in enumerate(references)
    ]
    snapshots.sort(key=lambda row: row.producer_series_ordinal)
    earlier, later = snapshots
    if earlier.producer_series_id != later.producer_series_id:
        raise ValueError("snapshot producer_series_id mismatch")
    if later.producer_series_ordinal != earlier.producer_series_ordinal + 1:
        raise ValueError("snapshot producer series ordinals must be consecutive")
    if earlier.component.casefold() != later.component.casefold():
        raise ValueError("snapshot component mismatch")
    if earlier.architecture != later.architecture:
        raise ValueError("snapshot architecture mismatch")
    if earlier.source_kind != later.source_kind:
        raise ValueError("snapshot source_kind mismatch")
    if earlier.build.text != later.build.text:
        raise ValueError("snapshot BuildLabEx identity mismatch")
    if earlier.servicing.current_build != later.servicing.current_build:
        raise ValueError("snapshot CurrentBuild mismatch")
    if earlier.servicing.ubr >= later.servicing.ubr:
        raise ValueError("snapshot UBR must increase with producer series order")
    if earlier.servicing.file_version_parts[:3] != later.servicing.file_version_parts[:3]:
        raise ValueError("snapshot driver file-version family mismatch")
    if earlier.servicing.file_version_parts[3] >= later.servicing.file_version_parts[3]:
        raise ValueError(
            "snapshot driver file-version revision must increase with producer series order"
        )
    if earlier.artifact.binary_sha256 == later.artifact.binary_sha256:
        raise ValueError("local pair snapshots must retain distinct driver bytes")
    if earlier.artifact.pdb_identity == later.artifact.pdb_identity:
        raise ValueError("local pair snapshots must retain distinct PE/PDB identities")
    if earlier.artifact.ghidra_version != later.artifact.ghidra_version:
        raise ValueError("snapshot analysis bundles must use the same Ghidra version")

    intake_sha256 = hashlib.sha256(intake_bytes).hexdigest()
    pair_material = {
        "intake_sha256": intake_sha256,
        "snapshot_manifest_sha256s": [row.manifest_sha256 for row in snapshots],
        "binary_sha256s": [row.artifact.binary_sha256 for row in snapshots],
    }
    pair_id = hashlib.sha256(
        (
            b"0verse-windows-driver-discovery-pair-v3\0"
            if public_lane
            else b"0verse-windows-driver-discovery-pair-v2\0"
        )
        + _canonical(pair_material)
    ).hexdigest()
    return {
        "schema_version": RESULT_VERSION_V3 if public_lane else RESULT_VERSION,
        "producer": PRODUCER_V3 if public_lane else PRODUCER,
        "campaign_id": campaign_id,
        "intake_manifest_sha256": intake_sha256,
        "pair_id": pair_id,
        "declared_local_series": {
            "producer_series_id": earlier.producer_series_id,
            "component": earlier.component.casefold(),
            "architecture": earlier.architecture,
            "base_build": earlier.build.base,
            "branch": earlier.build.branch,
            "current_build": earlier.servicing.current_build,
            "ubr_increases": True,
            "driver_file_version_increases": True,
            "retained_servicing_evidence_bound": True,
            "producer_series_ordinals_consecutive": True,
            "servicing_lineage_verified": False,
            "servicing_adjacency_verified": False,
        },
        "snapshots": [
            {
                "slot": f"snapshot-{index}",
                "snapshot_id": row.snapshot_id,
                "source_kind": row.source_kind,
                "producer_series_ordinal": row.producer_series_ordinal,
                "build_lab_ex": row.build.text,
                "current_build": row.servicing.current_build,
                "ubr": row.servicing.ubr,
                "file_version": row.servicing.file_version,
                "servicing_evidence_path": row.servicing.path.relative_to(
                    intake_path.parent
                ).as_posix(),
                "servicing_evidence_sha256": row.servicing.sha256,
                "manifest_path": row.manifest_path.relative_to(intake_path.parent).as_posix(),
                "manifest_sha256": row.manifest_sha256,
                "binary_sha256": row.artifact.binary_sha256,
                "pdb_sha256": row.artifact.pdb_sha256,
                "pdb_codeview_identity": row.artifact.pdb_identity,
                "ghidra_export_sha256": row.artifact.export_sha256,
                "analysis_receipt_sha256": row.artifact.analysis_receipt_sha256,
                "ghidra_version": row.artifact.ghidra_version,
                "extractor_profile": EXTRACTOR_PROFILE,
                "extractor_config_sha256": EXTRACTOR_CONFIG_SHA256,
                "discovery_artifact": row.descriptor,
                **(
                    {
                        "public_pdb": {
                            "receipt_sha256": row.artifact.public_pdb_receipt_sha256,
                            "requested_url": row.artifact.public_pdb_requested_url,
                            "pe_guid": row.artifact.public_pdb_pe_guid,
                            "pe_age": row.artifact.public_pdb_pe_age,
                            "pdb_guid": row.artifact.public_pdb_pdb_guid,
                            "pdb_age": row.artifact.public_pdb_pdb_age,
                            "exact_age_match": row.artifact.public_pdb_exact_age_match,
                        }
                    }
                    if public_lane
                    else {}
                ),
            }
            for index, row in enumerate(snapshots)
        ],
        "role_neutral": True,
        "labels_consumed": False,
        "network_performed": False,
        "execution_performed": False,
        "device_ioctl_attempts": 0,
        "all_outputs_are_discovery_inputs": True,
        "capability_measure": False,
        "reachability_established": False,
        "vulnerability_established": False,
        "novelty_established": False,
        "claim_eligible": False,
        "bounty_eligible": False,
        "weaponization": False,
        "automatic_disclosure": False,
        "human_promotion_gate": True,
        "windows_discovery_campaign": {
            "schema_version": "0verse.windows-discovery-campaign/v1",
            "source_declaration": {
                "kind": earlier.source_kind,
                "description": "verified ordered local semantic-v3 snapshot pair",
            },
            "previous": earlier.descriptor,
            "current": later.descriptor,
        },
        "proof_limit": PROOF_LIMIT_V3 if public_lane else PROOF_LIMIT,
    }


def _load_snapshot(
    raw: object,
    base: Path,
    label: str,
    *,
    snapshot_version: str = SNAPSHOT_VERSION,
    public_lane: bool = False,
) -> _Snapshot:
    reference = _object(raw, label)
    _exact(reference, {"path", "sha256"}, label)
    path = _relative_file(base, reference["path"], f"{label}.path")
    payload = _read_regular(path, f"{label} manifest")
    digest = hashlib.sha256(payload).hexdigest()
    if digest != _sha256(reference["sha256"], f"{label}.sha256"):
        raise ValueError(f"{label} manifest SHA-256 mismatch")
    snapshot = _object(_json(payload, f"{label} manifest"), f"{label} manifest")
    _exact(
        snapshot,
        {
            "schema_version",
            "snapshot_id",
            "producer_series_id",
            "producer_series_ordinal",
            "source_kind",
            "component",
            "architecture",
            "build_lab_ex",
            "servicing_evidence",
            "analysis",
        },
        f"{label} manifest",
    )
    if snapshot["schema_version"] != snapshot_version:
        raise ValueError(f"{label} has unsupported snapshot schema")
    component = _text(snapshot["component"], f"{label}.component", 132)
    if _COMPONENT.fullmatch(component) is None or Path(component).name != component:
        raise ValueError(f"{label}.component must be a driver basename")
    architecture = _text(snapshot["architecture"], f"{label}.architecture", 16)
    if architecture != "amd64":
        raise ValueError(f"{label}.architecture must be amd64 for the semantic-v3 profile")
    build = _build_lab_ex(snapshot["build_lab_ex"], architecture, f"{label}.build_lab_ex")
    ordinal = _integer(
        snapshot["producer_series_ordinal"],
        f"{label}.producer_series_ordinal",
        0,
        1_000_000,
    )
    source_kind = _text(snapshot["source_kind"], f"{label}.source_kind", 32)
    if source_kind not in {"owned-fixture", "public-artifact"}:
        raise ValueError(f"{label}.source_kind is unsupported")
    if source_kind == "public-artifact" and not public_lane:
        raise ValueError(
            f"{label} public-artifact semantic-v3 intake is not yet supported: "
            "acquire and verify the PE-keyed PDB with windows-public-pdb-download, "
            "but do not relabel stripped public symbols as an exact private PE/PDB pair"
        )
    if public_lane and source_kind != "public-artifact":
        raise ValueError(f"{label} v3 intake requires source_kind public-artifact")
    artifact = _load_artifact(snapshot["analysis"], path.parent, f"{label}.analysis")
    if artifact.synthetic_fixture:
        raise ValueError(f"{label} must use a real PE/PDB analysis bundle")
    if public_lane and (
        not artifact.public_pdb_receipt_sha256
        or not artifact.public_pdb_requested_url
        or artifact.public_pdb_exact_age_match is None
    ):
        raise ValueError(f"{label} public-artifact requires a verified v4 analysis receipt")
    if artifact.binary_path.name.casefold() != component.casefold():
        raise ValueError(f"{label} component does not match retained binary basename")
    servicing = _load_servicing_evidence(
        snapshot["servicing_evidence"],
        path.parent,
        component,
        architecture,
        build,
        artifact.binary_sha256,
        f"{label}.servicing_evidence",
    )
    _require_semantic_v3(artifact, label)
    analysis = _object(snapshot["analysis"], f"{label}.analysis")
    receipt_path = _relative_file(
        path.parent,
        analysis["analysis_receipt_path"],
        f"{label}.analysis.analysis_receipt_path",
    )
    descriptor = {
        "binary_path": _output_path(artifact.binary_path, base, f"{label} binary"),
        "binary_sha256": artifact.binary_sha256,
        "ghidra_export_path": _output_path(artifact.export_path, base, f"{label} export"),
        "ghidra_export_sha256": artifact.export_sha256,
        "analysis_receipt_path": _output_path(receipt_path, base, f"{label} receipt"),
        "analysis_receipt_sha256": artifact.analysis_receipt_sha256,
    }
    return _Snapshot(
        path.resolve(),
        digest,
        _identifier(snapshot["snapshot_id"], f"{label}.snapshot_id"),
        _identifier(snapshot["producer_series_id"], f"{label}.producer_series_id"),
        ordinal,
        source_kind,
        component,
        architecture,
        build,
        servicing,
        artifact,
        descriptor,
    )


def _require_semantic_v3(artifact: Artifact, label: str) -> None:
    export = artifact.export
    facts = export.get("facts")
    if (
        export.get("schema_version") != EXPORT_VERSION_V3
        or export.get("extractor_profile") != EXTRACTOR_PROFILE
        or export.get("extractor_config_sha256") != EXTRACTOR_CONFIG_SHA256
    ):
        raise ValueError(f"{label} must use the supported semantic High-P-Code v3 profile")
    validate_windows_ioctl_high_pcode_export(export)
    if (
        export.get("driver_sha256") != artifact.binary_sha256
        or export.get("pdb_sha256") != artifact.pdb_sha256
        or export.get("pdb_codeview_identity") != artifact.pdb_identity
        or not isinstance(facts, dict)
        or facts.get("architecture") != "x86_64"
        or facts.get("pointer_size") != 8
    ):
        raise ValueError(f"{label} semantic-v3 export is not bound to its amd64 PE/PDB")


def _output_path(path: Path, base: Path, label: str) -> str:
    absolute = path.absolute()
    if path.resolve() != absolute:
        raise ValueError(f"{label} path traverses a symlink")
    try:
        return absolute.relative_to(base.absolute()).as_posix()
    except ValueError as exc:
        raise ValueError(f"{label} must remain beneath the intake directory") from exc


def _policy(raw: object) -> None:
    policy = _object(raw, "policy")
    expected = {
        "local_files_only": True,
        "network_allowed": False,
        "execution_allowed": False,
        "labels_allowed": False,
        "role_neutral": True,
    }
    _exact(policy, set(expected), "policy")
    if policy != expected:
        raise ValueError("intake policy must be the fixed offline role-neutral policy")


def _build_lab_ex(raw: object, architecture: str, label: str) -> _Build:
    value = _text(raw, label, 256)
    fields = value.split(".")
    if len(fields) < 4 or not fields[0].isdigit() or not fields[1].isdigit():
        raise ValueError(f"{label} is not a canonical BuildLabEx value")
    if fields[2] != f"{architecture}fre":
        raise ValueError(f"{label} architecture token mismatch")
    branch_fields = fields[3:]
    if branch_fields and _STAMP.fullmatch(branch_fields[-1]):
        branch_fields = branch_fields[:-1]
    branch = ".".join(branch_fields)
    if not branch or _BRANCH.fullmatch(branch) is None:
        raise ValueError(f"{label} branch is invalid")
    base, build_lab_revision = int(fields[0]), int(fields[1])
    if not (1 <= base <= 999_999 and 0 <= build_lab_revision <= 99_999_999):
        raise ValueError(f"{label} build numbers are out of range")
    return _Build(value, base, architecture, branch)


def _load_servicing_evidence(
    raw: object,
    base: Path,
    component: str,
    architecture: str,
    build: _Build,
    binary_sha256: str,
    label: str,
) -> _ServicingEvidence:
    reference = _object(raw, label)
    _exact(reference, {"path", "sha256"}, label)
    path = _relative_file(base, reference["path"], f"{label}.path")
    payload = _read_regular(path, f"{label} record")
    digest = hashlib.sha256(payload).hexdigest()
    if digest != _sha256(reference["sha256"], f"{label}.sha256"):
        raise ValueError(f"{label} SHA-256 mismatch")
    evidence = _object(_json(payload, f"{label} record"), f"{label} record")
    _exact(
        evidence,
        {
            "schema_version",
            "source",
            "component",
            "architecture",
            "current_build",
            "ubr",
            "build_lab_ex",
            "file_version",
            "binary_sha256",
        },
        f"{label} record",
    )
    if evidence["schema_version"] != SERVICING_EVIDENCE_VERSION:
        raise ValueError(f"{label} has unsupported evidence schema")
    if _text(evidence["source"], f"{label}.source", 64) != "retained-windows-servicing-export":
        raise ValueError(f"{label}.source is unsupported")
    evidence_component = _text(evidence["component"], f"{label}.component", 132)
    if (
        _COMPONENT.fullmatch(evidence_component) is None
        or Path(evidence_component).name != evidence_component
        or evidence_component.casefold() != component.casefold()
    ):
        raise ValueError(f"{label} component mismatch")
    if _text(evidence["architecture"], f"{label}.architecture", 16) != architecture:
        raise ValueError(f"{label} architecture mismatch")
    if _text(evidence["build_lab_ex"], f"{label}.build_lab_ex", 256) != build.text:
        raise ValueError(f"{label} BuildLabEx mismatch")
    if _sha256(evidence["binary_sha256"], f"{label}.binary_sha256") != binary_sha256:
        raise ValueError(f"{label} binary SHA-256 mismatch")
    current_build_text = _text(evidence["current_build"], f"{label}.current_build", 6)
    if not current_build_text.isdigit() or str(int(current_build_text)) != current_build_text:
        raise ValueError(f"{label}.current_build must be a canonical decimal string")
    current_build = int(current_build_text)
    if current_build != build.base:
        raise ValueError(f"{label} CurrentBuild/BuildLabEx mismatch")
    ubr = _integer(evidence["ubr"], f"{label}.ubr", 0, 2**32 - 1)
    file_version = _text(evidence["file_version"], f"{label}.file_version", 64)
    version_fields = file_version.split(".")
    if (
        len(version_fields) != 4
        or any(not field.isdigit() or str(int(field)) != field for field in version_fields)
    ):
        raise ValueError(f"{label}.file_version must contain four canonical integers")
    version_parts = (
        int(version_fields[0]),
        int(version_fields[1]),
        int(version_fields[2]),
        int(version_fields[3]),
    )
    if any(field >= 2**32 for field in version_parts) or version_parts[2] != current_build:
        raise ValueError(f"{label}.file_version does not match CurrentBuild")
    return _ServicingEvidence(
        path.resolve(), digest, current_build, ubr, file_version, version_parts
    )


def _relative_file(base: Path, raw: object, label: str) -> Path:
    text = _text(raw, label, 1024)
    candidate = Path(text)
    if (
        candidate.is_absolute()
        or "\\" in text
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise ValueError(f"{label} must be a normalized relative path")
    path = base / candidate
    try:
        path.relative_to(base)
    except ValueError as exc:
        raise ValueError(f"{label} escapes its manifest directory") from exc
    if path.resolve() != path.absolute() or path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must name a regular non-symlink file")
    return path


def _read_regular(path: Path, label: str) -> bytes:
    if path.resolve() != path.absolute() or path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_MANIFEST_BYTES:
            raise ValueError(f"{label} must be a bounded regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_MANIFEST_BYTES:
                raise ValueError(f"{label} exceeds size cap")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) or total != before.st_size:
            raise ValueError(f"{label} changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _json(payload: bytes, label: str) -> object:
    try:
        return json.loads(payload, object_pairs_hook=_unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid JSON") from exc


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON field: {key}")
        out[key] = value
    return out


def _object(raw: object, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError(f"{label} must be an object")
    return raw


def _exact(raw: dict[str, Any], fields: set[str], label: str) -> None:
    if set(raw) != fields:
        raise ValueError(f"{label} has unknown or missing fields")


def _text(raw: object, label: str, maximum: int) -> str:
    if (
        not isinstance(raw, str)
        or not raw
        or len(raw) > maximum
        or "\0" in raw
        or raw != raw.strip()
    ):
        raise ValueError(f"{label} must be bounded nonempty text")
    return raw


def _identifier(raw: object, label: str) -> str:
    value = _text(raw, label, 128)
    if _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")
    return value


def _sha256(raw: object, label: str) -> str:
    if not isinstance(raw, str) or _SHA256.fullmatch(raw) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return raw


def _integer(raw: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int) or not minimum <= raw <= maximum:
        raise ValueError(f"{label} must be an integer in [{minimum}, {maximum}]")
    return raw


def _canonical(raw: object) -> bytes:
    return json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", help="offline pair-intake manifest")
    parser.add_argument("--output", help="write canonical result to this new file")
    parser.add_argument(
        "--discovery-campaign-output",
        help="write the exact windows-discover campaign to this new file",
    )
    args = parser.parse_args(argv)
    result = plan_windows_driver_pair_intake(args.manifest)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        _write_new_json(Path(args.output), result, "output")
    else:
        print(rendered, end="")
    if args.discovery_campaign_output:
        campaign_path = Path(args.discovery_campaign_output)
        manifest_parent = Path(os.path.abspath(args.manifest)).parent  # noqa: PTH100
        output_parent = Path(os.path.abspath(campaign_path.parent))  # noqa: PTH100
        if output_parent.resolve() != output_parent or output_parent != manifest_parent:
            raise ValueError(
                "discovery campaign output must be beside the intake manifest so its "
                "hash-pinned relative paths remain directly consumable"
            )
        _write_new_json(
            campaign_path,
            result["windows_discovery_campaign"],
            "discovery campaign output",
        )
    return 0


def _write_new_json(path: Path, value: object, label: str) -> None:
    try:
        with path.open("x", encoding="utf-8") as destination:
            json.dump(value, destination, indent=2, sort_keys=True)
            destination.write("\n")
    except FileExistsError as exc:
        raise ValueError(f"{label} path already exists") from exc


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
