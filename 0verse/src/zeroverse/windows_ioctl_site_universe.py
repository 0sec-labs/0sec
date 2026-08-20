"""Produce and verify a ranking-neutral Windows IOCTL site-universe precommit."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .ssh_authority_commitment import ssh_authority_key_commitment
from .ssh_authorization import verify_ssh_signature
from .windows_ioctl_ghidra_export import (
    EXPORT_VERSION_V2,
    EXPORT_VERSION_V3,
    validate_windows_ioctl_high_pcode_export,
)
from .windows_ioctl_site_identity import ioctl_site_id, site_universe_sha256
from .windows_variant import _load_artifact

REQUEST_VERSION = "0verse.windows-ioctl-site-universe-request/v1"
UNIVERSE_VERSION = "0verse.windows-ioctl-site-universe/v1"
PRODUCER = "zeroverse.windows-ioctl-site-universe/v1"
SIGNATURE_NAMESPACE = "0verse-windows-ioctl-site-universe-v1"
SIGNER_IDENTITY = "windows-ioctl-site-universe@0verse"
DEFAULT_ALLOWED_SIGNERS = Path("/etc/0verse/windows-ioctl-site-universe.allowed_signers")
PROOF_LIMIT = (
    "Signed enumeration of every normalized site in one complete static export-v2/v3; "
    "no guard assessment, ranking, label, reachability, vulnerability, impact, novelty, "
    "claim, bounty eligibility, execution authority, disclosure, or weaponization is "
    "established."
)

_SHA256 = re.compile(r"[0-9a-f]{64}")
_NONCE = re.compile(r"[A-Za-z0-9_-]{32,128}")
_MAX_REQUEST_BYTES = 1024 * 1024
_MAX_MANIFEST_BYTES = 4 * 1024 * 1024
_MAX_POLICY_BYTES = 1024 * 1024
_MAX_SIGNATURE_BYTES = 64 * 1024
_ARTIFACT_FIELDS = {
    "binary_path",
    "ghidra_export_path",
    "binary_sha256",
    "ghidra_export_sha256",
    "analysis_receipt_path",
    "analysis_receipt_sha256",
}
_SITE_FIELDS = {
    "ioctl_code",
    "registration_rva",
    "handler_name",
    "handler_rva",
    "source",
    "source_inst_id",
    "field_offset",
    "field_width",
    "field_kind",
    "sink_kind",
    "sink_function",
    "sink_address",
    "sink_inst_id",
}
_SAFETY_FLAGS: dict[str, object] = {
    "complete_export_site_universe": True,
    "ranker_invoked": False,
    "labels_loaded": False,
    "guard_state_present": False,
    "ranking_scores_present": False,
    "candidate_classification_present": False,
    "static_only": True,
    "runtime_consumable": False,
    "execution_authorized": False,
    "device_ioctl_attempts": 0,
    "network_access_performed": False,
    "capability_measure": False,
    "reachability_established": False,
    "vulnerability_established": False,
    "impact_established": False,
    "novelty_established": False,
    "claim_eligible": False,
    "bounty_eligible": False,
    "redistribution": False,
    "weaponization": False,
    "automatic_disclosure": False,
    "human_label_gate": True,
    "human_report_gate": True,
}


def build_windows_ioctl_site_universe(
    request_path: str | Path,
    *,
    allowed_signers: str | Path | None = None,
    now: datetime | None = None,
) -> dict[str, object]:
    """Enumerate all export-v2/v3 sites without importing or invoking ranking code."""
    request_file = Path(request_path)
    request_bytes = _read_bounded(request_file, _MAX_REQUEST_BYTES, "site request")
    request = _load_object(request_bytes, "site request")
    _exact(
        request,
        {"schema_version", "universe_nonce", "declared_frozen_at", "artifact"},
        "site request",
    )
    if request["schema_version"] != REQUEST_VERSION:
        raise ValueError("unsupported Windows IOCTL site-universe request")
    nonce = _match(request["universe_nonce"], _NONCE, "universe_nonce")
    frozen_at = _freeze_time(request["declared_frozen_at"], now=now)
    artifact_record = _object(request["artifact"], "artifact")
    _exact(artifact_record, _ARTIFACT_FIELDS, "artifact")
    artifact = _load_artifact(artifact_record, request_file.parent, "artifact")
    if artifact.synthetic_fixture:
        raise ValueError("site-universe precommit requires a real analysis bundle")
    export = artifact.export
    validate_windows_ioctl_high_pcode_export(export)
    if (
        export["schema_version"] not in {EXPORT_VERSION_V2, EXPORT_VERSION_V3}
        or export["driver_sha256"] != artifact.binary_sha256
        or export["pdb_sha256"] != artifact.pdb_sha256
        or export["pdb_codeview_identity"] != artifact.pdb_identity
    ):
        raise ValueError("site-universe export is not bound to the analysis bundle")

    sites = _enumerate_sites(export, artifact.binary_sha256, artifact.export_sha256)
    universe_digest = site_universe_sha256(sites)
    policy_path = Path(allowed_signers) if allowed_signers is not None else DEFAULT_ALLOWED_SIGNERS
    policy_bytes = _read_policy(policy_path, production=allowed_signers is None)
    principal = _singleton_policy_principal(policy_bytes)
    if principal != SIGNER_IDENTITY:
        raise ValueError("site-universe policy must use the dedicated signer identity")
    policy_sha256 = hashlib.sha256(policy_bytes).hexdigest()
    authority_key_commitment = _policy_key_commitment(policy_bytes)
    universe_id = hashlib.sha256(
        b"0verse-windows-ioctl-site-universe-id-v1\0"
        + nonce.encode("ascii")
        + b"\0"
        + universe_digest.encode("ascii")
        + b"\0"
        + artifact.analysis_receipt_sha256.encode("ascii")
    ).hexdigest()
    manifest: dict[str, object] = {
        "schema_version": UNIVERSE_VERSION,
        "producer": PRODUCER,
        "universe_id": universe_id,
        "universe_nonce": nonce,
        "declared_frozen_at": frozen_at,
        "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
        "driver_sha256": artifact.binary_sha256,
        "pdb_sha256": artifact.pdb_sha256,
        "pdb_codeview_identity": artifact.pdb_identity,
        "analysis_sha256": artifact.export_sha256,
        "analysis_receipt_sha256": artifact.analysis_receipt_sha256,
        "export_schema_version": export["schema_version"],
        "site_count": len(sites),
        "sites": sites,
        "site_universe_sha256": universe_digest,
        "authority": {
            "manifest_signer_identity": principal,
            "allowed_signers_sha256": policy_sha256,
            "authority_key_commitment_sha256": authority_key_commitment,
        },
        **_SAFETY_FLAGS,
        "proof_limit": PROOF_LIMIT,
    }
    if len(canonical_site_universe_bytes(manifest)) > _MAX_MANIFEST_BYTES:
        raise ValueError("complete site-universe manifest exceeds the signing size limit")
    return manifest


def verify_windows_ioctl_site_universe(
    manifest_path: str | Path,
    *,
    allowed_signers: str | Path | None = None,
    verification_ssh_keygen: str | Path = "ssh-keygen",
    verification_inherit_environment: bool = True,
) -> dict[str, object]:
    """Verify one canonical manifest and its detached, role-separated signature."""
    manifest_file = Path(manifest_path)
    manifest_bytes = _read_bounded(manifest_file, _MAX_MANIFEST_BYTES, "site universe")
    signature_bytes = _read_bounded(
        Path(f"{manifest_file}.sig"), _MAX_SIGNATURE_BYTES, "site-universe signature"
    )
    manifest = _load_object(manifest_bytes, "site universe")
    _validate_manifest(manifest)
    if canonical_site_universe_bytes(manifest) != manifest_bytes:
        raise ValueError("site-universe manifest must use its canonical encoding")
    policy_path = Path(allowed_signers) if allowed_signers is not None else DEFAULT_ALLOWED_SIGNERS
    policy_bytes = _read_policy(policy_path, production=allowed_signers is None)
    principal = _singleton_policy_principal(policy_bytes)
    authority = _object(manifest["authority"], "authority")
    if (
        principal != SIGNER_IDENTITY
        or authority["manifest_signer_identity"] != principal
        or authority["allowed_signers_sha256"] != hashlib.sha256(policy_bytes).hexdigest()
        or authority["authority_key_commitment_sha256"] != _policy_key_commitment(policy_bytes)
    ):
        raise ValueError("site-universe authority binding mismatch")
    try:
        signature_text = signature_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("site-universe signature must be UTF-8") from exc
    with tempfile.TemporaryDirectory(prefix="0verse-ioctl-sites-policy-") as temporary:
        policy_snapshot = Path(temporary) / "allowed_signers"
        policy_snapshot.write_bytes(policy_bytes)
        verify_ssh_signature(
            manifest_bytes,
            signature_text,
            identity=SIGNER_IDENTITY,
            namespace=SIGNATURE_NAMESPACE,
            allowed_signers=policy_snapshot,
            label="Windows IOCTL site universe",
            require_trusted_policy=False,
            ssh_keygen=verification_ssh_keygen,
            inherit_environment=verification_inherit_environment,
        )
    return {
        **manifest,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "signature_sha256": hashlib.sha256(signature_bytes).hexdigest(),
        "signature_verified": True,
    }


def canonical_site_universe_bytes(manifest: dict[str, object]) -> bytes:
    """Return the sole signed encoding for a validated site universe."""
    _validate_manifest(manifest)
    return (
        json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _enumerate_sites(
    export: dict[str, Any], driver_sha256: str, analysis_sha256: str
) -> list[dict[str, object]]:
    facts = _object(export["facts"], "facts")
    dispatches = facts["dispatches"]
    assert isinstance(dispatches, list)
    sites: list[dict[str, object]] = []
    seen: set[str] = set()
    for dispatch_raw in dispatches:
        dispatch = _object(dispatch_raw, "dispatch")
        fields = dispatch["fields"]
        assert isinstance(fields, list)
        for field_raw in fields:
            field = _object(field_raw, "field")
            record: dict[str, object] = {
                "ioctl_code": f"0x{int(dispatch['ioctl_code']):08x}",
                "registration_rva": dispatch["registration_rva"],
                "handler_name": dispatch["handler_name"],
                "handler_rva": dispatch["handler_rva"],
                "source": field["source"],
                "source_inst_id": field["source_inst_id"],
                "field_offset": field["offset"],
                "field_width": field["width"],
                "field_kind": field["kind"],
                "sink_kind": field["sink_kind"],
                "sink_function": field["sink_function"],
                "sink_address": field["sink_address"],
                "sink_inst_id": field["sink_inst_id"],
            }
            site_id = ioctl_site_id(driver_sha256, analysis_sha256, record)
            if site_id in seen:
                raise ValueError("duplicate site identity in complete export")
            seen.add(site_id)
            sites.append({"site_id": site_id, **record})
    sites.sort(key=lambda row: str(row["site_id"]))
    if not sites:
        raise ValueError("site-universe export contains no sites")
    return sites


def _validate_manifest(raw: dict[str, Any]) -> None:
    expected = {
        "schema_version",
        "producer",
        "universe_id",
        "universe_nonce",
        "declared_frozen_at",
        "request_sha256",
        "driver_sha256",
        "pdb_sha256",
        "pdb_codeview_identity",
        "analysis_sha256",
        "analysis_receipt_sha256",
        "export_schema_version",
        "site_count",
        "sites",
        "site_universe_sha256",
        "authority",
        *list(_SAFETY_FLAGS),
        "proof_limit",
    }
    _exact(raw, expected, "site universe")
    if raw["schema_version"] != UNIVERSE_VERSION or raw["producer"] != PRODUCER:
        raise ValueError("site-universe schema/producer mismatch")
    if raw["export_schema_version"] not in {
        EXPORT_VERSION_V2,
        EXPORT_VERSION_V3,
    } or raw["proof_limit"] != PROOF_LIMIT:
        raise ValueError("site-universe contract mismatch")
    _match(raw["universe_id"], _SHA256, "universe_id")
    _match(raw["universe_nonce"], _NONCE, "universe_nonce")
    if (
        _freeze_time(raw["declared_frozen_at"], now=None, check_fresh=False)
        != raw["declared_frozen_at"]
    ):
        raise ValueError("declared_frozen_at must use normalized UTC encoding")
    for name in (
        "request_sha256",
        "driver_sha256",
        "pdb_sha256",
        "analysis_sha256",
        "analysis_receipt_sha256",
        "site_universe_sha256",
    ):
        _match(raw[name], _SHA256, name)
    codeview = raw["pdb_codeview_identity"]
    if (
        not isinstance(codeview, str)
        or not codeview
        or codeview != codeview.strip()
        or len(codeview) > 512
        or "\x00" in codeview
    ):
        raise ValueError("pdb_codeview_identity is invalid")
    sites = raw["sites"]
    if not isinstance(sites, list) or not 1 <= len(sites) <= 8192:
        raise ValueError("site universe must contain a bounded nonempty site array")
    if type(raw["site_count"]) is not int or raw["site_count"] != len(sites):
        raise ValueError("site_count does not match sites")
    normalized: list[dict[str, object]] = []
    for index, item in enumerate(sites):
        site = _object(item, f"sites[{index}]")
        _exact(site, {"site_id", *_SITE_FIELDS}, f"sites[{index}]")
        site_id = _match(site["site_id"], _SHA256, "site_id")
        _validate_site_record(site)
        record = {name: site[name] for name in _SITE_FIELDS}
        if site_id != ioctl_site_id(str(raw["driver_sha256"]), str(raw["analysis_sha256"]), record):
            raise ValueError("site identity does not bind the artifact and record")
        normalized.append(dict(site))
    if normalized != sorted(normalized, key=lambda row: str(row["site_id"])):
        raise ValueError("sites must be sorted by site_id")
    if len({str(row["site_id"]) for row in normalized}) != len(normalized):
        raise ValueError("site universe contains duplicate identities")
    if site_universe_sha256(normalized) != raw["site_universe_sha256"]:
        raise ValueError("site-universe digest mismatch")
    expected_universe_id = hashlib.sha256(
        b"0verse-windows-ioctl-site-universe-id-v1\0"
        + str(raw["universe_nonce"]).encode("ascii")
        + b"\0"
        + str(raw["site_universe_sha256"]).encode("ascii")
        + b"\0"
        + str(raw["analysis_receipt_sha256"]).encode("ascii")
    ).hexdigest()
    if raw["universe_id"] != expected_universe_id:
        raise ValueError("universe_id does not bind the nonce, universe, and receipt")
    authority = _object(raw["authority"], "authority")
    _exact(
        authority,
        {"manifest_signer_identity", "allowed_signers_sha256", "authority_key_commitment_sha256"},
        "authority",
    )
    if authority["manifest_signer_identity"] != SIGNER_IDENTITY:
        raise ValueError("site-universe signer role mismatch")
    for name in ("allowed_signers_sha256", "authority_key_commitment_sha256"):
        _match(authority[name], _SHA256, name)
    for name, expected_value in _SAFETY_FLAGS.items():
        if raw[name] != expected_value or type(raw[name]) is not type(expected_value):
            raise ValueError("site-universe safety flags mismatch")


def _freeze_time(raw: object, *, now: datetime | None, check_fresh: bool = True) -> str:
    if not isinstance(raw, str):
        raise ValueError("declared_frozen_at must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("declared_frozen_at must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("declared_frozen_at must include a timezone")
    parsed = parsed.astimezone(UTC)
    current = (now or datetime.now(UTC)).astimezone(UTC)
    if check_fresh and (
        parsed > current + timedelta(minutes=5) or current - parsed > timedelta(hours=24)
    ):
        raise ValueError("declared_frozen_at must be within the 24-hour build window")
    return parsed.isoformat()


def _singleton_policy_principal(policy_bytes: bytes) -> str:
    try:
        lines = [
            line.strip()
            for line in policy_bytes.decode("utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except UnicodeDecodeError as exc:
        raise ValueError("site-universe policy must be UTF-8") from exc
    if len(lines) != 1:
        raise ValueError("site-universe policy must contain exactly one signer")
    fields = lines[0].split()
    if len(fields) < 3 or fields[1] != "ssh-ed25519" or "," in fields[0]:
        raise ValueError("site-universe policy must contain one literal Ed25519 principal")
    return fields[0]


def _validate_site_record(site: dict[str, Any]) -> None:
    if re.fullmatch(r"0x[0-9a-f]{8}", str(site["ioctl_code"])) is None:
        raise ValueError("site ioctl_code is invalid")
    for name in ("registration_rva", "handler_rva", "sink_address"):
        value = str(site[name])
        if re.fullmatch(r"0x[0-9a-f]+", value) is None or int(value, 16) == 0:
            raise ValueError(f"site {name} is invalid")
    for name in ("handler_name", "sink_function"):
        value = site[name]
        if (
            not isinstance(value, str)
            or not value
            or len(value) > 256
            or any(char in value for char in "\x00\r\n")
        ):
            raise ValueError(f"site {name} is invalid")
    if site["source"] not in {"SystemBuffer", "InputBufferLength", "OutputBufferLength"}:
        raise ValueError("site source is invalid")
    if site["field_kind"] not in {"length", "count", "offset", "flags"}:
        raise ValueError("site field_kind is invalid")
    if site["sink_kind"] not in {"copy", "fill", "indexed-store", "allocation"}:
        raise ValueError("site sink_kind is invalid")
    integer_bounds = {
        "source_inst_id": (1, 1 << 63),
        "field_offset": (0, 1 << 20),
        "field_width": (1, 8),
        "sink_inst_id": (1, 1 << 63),
    }
    for name, (minimum, maximum) in integer_bounds.items():
        value = site[name]
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError(f"site {name} is invalid")


def _policy_key_commitment(policy_bytes: bytes) -> str:
    with tempfile.TemporaryDirectory(prefix="0verse-ioctl-sites-key-") as temporary:
        snapshot = Path(temporary) / "allowed_signers"
        snapshot.write_bytes(policy_bytes)
        return ssh_authority_key_commitment(snapshot)


def _read_policy(path: Path, *, production: bool) -> bytes:
    data, metadata = _read_bounded_with_metadata(
        path, _MAX_POLICY_BYTES, "site-universe policy"
    )
    if production and (
        metadata.st_uid != 0 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ValueError("site-universe policy must be root-owned and not group/world writable")
    return data


def _read_bounded(path: Path, maximum: int, label: str) -> bytes:
    data, _metadata = _read_bounded_with_metadata(path, maximum, label)
    return data


def _read_bounded_with_metadata(
    path: Path, maximum: int, label: str
) -> tuple[bytes, os.stat_result]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ValueError(f"{label} cannot be read with no-follow custody on this platform")
    flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{label} must be a regular non-symlink file") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise ValueError(f"{label} is empty or exceeds its size limit")
        chunks: list[bytes] = []
        count = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum - count + 1))
            if not chunk:
                break
            count += len(chunk)
            if count > maximum:
                raise ValueError(f"{label} exceeds its size limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if count != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ValueError(f"{label} changed while it was read")
        current = os.lstat(path)
        if not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != (
            after.st_dev,
            after.st_ino,
        ):
            raise ValueError(f"{label} path changed while it was read")
        return b"".join(chunks), after
    finally:
        os.close(descriptor)


def _load_object(data: bytes, label: str) -> dict[str, Any]:
    try:
        raw = json.loads(data, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"{label} must be valid UTF-8 JSON") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"{label} must be a JSON object")
    return raw


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _object(raw: object, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError(f"{label} must be an object")
    return raw


def _exact(raw: dict[str, Any], fields: set[str], label: str) -> None:
    if set(raw) != fields:
        raise ValueError(f"{label} fields mismatch")


def _match(raw: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(raw, str) or pattern.fullmatch(raw) is None:
        raise ValueError(f"{label} is invalid")
    return raw
