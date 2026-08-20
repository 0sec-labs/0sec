"""Verify Windows-native Authenticode observation receipts against retained bytes."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

AUTHENTICITY_SCHEMA = "0verse.windows-authenticity-observation/v1"
AUTHENTICITY_PRODUCER = "zeroverse.windows-authenticity/powershell-v1"
AUTHENTICITY_PROOF_LIMIT = (
    "Producer-observed Windows trust result only; Microsoft root pinning, explicit catalog "
    "membership, package-to-output provenance, servicing replay, vulnerability status, and "
    "redistribution rights are unproven."
)

_SHA256 = re.compile(r"[0-9a-f]{64}")
_SHA1 = re.compile(r"[0-9A-F]{40}")


@dataclass(frozen=True)
class AuthenticityReceipt:
    artifact_path: Path
    artifact_sha256: str
    artifact_size_bytes: int
    receipt_path: Path
    receipt_sha256: str
    signature_type: str
    signer_subject: str
    signer_certificate_sha256: str
    verified_at_utc: str
    network_mode: str

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_path": str(self.artifact_path),
            "artifact_sha256": self.artifact_sha256,
            "artifact_size_bytes": self.artifact_size_bytes,
            "receipt_path": str(self.receipt_path),
            "receipt_sha256": self.receipt_sha256,
            "signature_type": self.signature_type,
            "signer_subject": self.signer_subject,
            "signer_certificate_sha256": self.signer_certificate_sha256,
            "verified_at_utc": self.verified_at_utc,
            "network_mode": self.network_mode,
        }


def verify_windows_authenticity_receipt(
    artifact_path: str | Path, receipt_path: str | Path
) -> AuthenticityReceipt:
    """Validate a producer receipt and rehash the exact retained artifact."""
    artifact_file = _regular_file(Path(artifact_path), "authenticity artifact")
    receipt_file = _regular_file(Path(receipt_path), "authenticity receipt")
    raw = json.loads(receipt_file.read_bytes(), object_pairs_hook=_unique_object)
    if not isinstance(raw, dict):
        raise ValueError("authenticity receipt must be a JSON object")
    _exact(
        raw,
        {
            "schema_version",
            "producer",
            "artifact",
            "verification",
            "verified_claims",
            "proof_limit",
        },
        "receipt",
    )
    if (
        raw["schema_version"] != AUTHENTICITY_SCHEMA
        or raw["producer"] != AUTHENTICITY_PRODUCER
    ):
        raise ValueError("authenticity receipt schema/producer mismatch")
    artifact = _object(raw["artifact"], "artifact")
    _exact(artifact, {"path", "sha256", "size_bytes"}, "artifact")
    if artifact["path"] != artifact_file.name:
        raise ValueError("authenticity receipt artifact path mismatch")
    expected_digest = _sha256(artifact["sha256"], "artifact.sha256")
    observed_digest, observed_size = _hash_file(artifact_file)
    if observed_digest != expected_digest:
        raise ValueError("authenticity artifact SHA-256 mismatch")
    _positive_size(artifact["size_bytes"], observed_size, "artifact.size_bytes")

    verification = _object(raw["verification"], "verification")
    _exact(
        verification,
        {
            "status",
            "status_message",
            "signature_type",
            "is_os_binary",
            "verified_at_utc",
            "trust_mode",
            "revocation_mode",
            "network_mode",
            "signer_certificate",
            "timestamper_certificate",
            "verifier",
        },
        "verification",
    )
    if verification["status"] != "Valid":
        raise ValueError("authenticity signature status must be Valid")
    status_message = verification["status_message"]
    if not isinstance(status_message, str) or "\x00" in status_message:
        raise ValueError("authenticity status_message must be a string without NUL bytes")
    signature_type = str(verification["signature_type"])
    if signature_type not in {"Authenticode", "Catalog"}:
        raise ValueError("authenticity signature_type must be Authenticode or Catalog")
    if not isinstance(verification["is_os_binary"], bool):
        raise ValueError("authenticity is_os_binary must be a boolean")
    verified_at = _utc_timestamp(verification["verified_at_utc"], "verified_at_utc")
    if verification["trust_mode"] != "windows-local-machine":
        raise ValueError("authenticity trust_mode mismatch")
    if verification["revocation_mode"] != "get-authenticode-signature-default":
        raise ValueError("authenticity revocation_mode mismatch")
    network_mode = str(verification["network_mode"])
    if network_mode not in {"network-isolated", "network-enabled"}:
        raise ValueError("authenticity network_mode mismatch")
    signer = _certificate(verification["signer_certificate"], "signer_certificate")
    if "microsoft" not in signer["subject"].lower():
        raise ValueError("authenticity signer is not Microsoft")
    timestamper_raw = verification["timestamper_certificate"]
    if timestamper_raw is not None:
        _certificate(timestamper_raw, "timestamper_certificate")
    verifier = _object(verification["verifier"], "verifier")
    _exact(verifier, {"powershell_version", "os_build_lab_ex"}, "verifier")
    for field in ("powershell_version", "os_build_lab_ex"):
        value = verifier[field]
        if not isinstance(value, str) or not value.strip() or "\x00" in value:
            raise ValueError(f"authenticity verifier.{field} must be nonempty")
    if raw["verified_claims"] != [
        "producer-observed-windows-valid-signature",
        "retained-content-sha256",
    ]:
        raise ValueError("authenticity verified_claims mismatch")
    if raw["proof_limit"] != AUTHENTICITY_PROOF_LIMIT:
        raise ValueError("authenticity proof_limit mismatch")
    return AuthenticityReceipt(
        artifact_file.resolve(),
        observed_digest,
        observed_size,
        receipt_file.resolve(),
        hashlib.sha256(receipt_file.read_bytes()).hexdigest(),
        signature_type,
        signer["subject"],
        signer["cert_sha256"],
        verified_at.isoformat(),
        network_mode,
    )


def _certificate(raw: object, label: str) -> dict[str, str]:
    cert = _object(raw, label)
    _exact(
        cert,
        {
            "subject",
            "issuer",
            "serial_number",
            "thumbprint_sha1",
            "cert_sha256",
            "not_before_utc",
            "not_after_utc",
        },
        label,
    )
    values: dict[str, str] = {}
    for field in ("subject", "issuer", "serial_number"):
        value = cert[field]
        if not isinstance(value, str) or not value.strip() or "\x00" in value:
            raise ValueError(f"authenticity {label}.{field} must be nonempty")
        values[field] = value
    thumbprint = str(cert["thumbprint_sha1"])
    if _SHA1.fullmatch(thumbprint) is None:
        raise ValueError(f"authenticity {label}.thumbprint_sha1 must be uppercase SHA-1")
    values["thumbprint_sha1"] = thumbprint
    values["cert_sha256"] = _sha256(cert["cert_sha256"], f"{label}.cert_sha256")
    not_before = _utc_timestamp(cert["not_before_utc"], f"{label}.not_before_utc")
    not_after = _utc_timestamp(cert["not_after_utc"], f"{label}.not_after_utc")
    if not_before >= not_after:
        raise ValueError(f"authenticity {label} validity interval is invalid")
    values["not_before_utc"] = not_before.isoformat()
    values["not_after_utc"] = not_after.isoformat()
    return values


def _regular_file(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    return path


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def _object(raw: object, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict) or not all(isinstance(key, str) for key in raw):
        raise ValueError(f"authenticity {label} must be an object")
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
        raise ValueError(f"authenticity {label} fields invalid: {'; '.join(details)}")


def _sha256(raw: object, label: str) -> str:
    value = str(raw)
    if _SHA256.fullmatch(value) is None:
        raise ValueError(f"authenticity {label} must be a lowercase SHA-256")
    return value


def _positive_size(raw: object, observed: int, label: str) -> None:
    if (
        not isinstance(raw, int)
        or isinstance(raw, bool)
        or raw <= 0
        or raw != observed
    ):
        raise ValueError(f"authenticity {label} mismatch")


def _utc_timestamp(raw: object, label: str) -> datetime:
    if not isinstance(raw, str):
        raise ValueError(f"authenticity {label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"authenticity {label} must be a UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError(f"authenticity {label} must be a UTC timestamp")
    return parsed
