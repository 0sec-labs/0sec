"""Verify Windows SignTool policy receipts against retained inputs and policy bytes."""

from __future__ import annotations

import hashlib
import json
import ntpath
import re
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

TRUST_POLICY_SCHEMA = "0verse.windows-trust-root-policy/v1"
TRUST_RECEIPT_SCHEMA = "0verse.windows-signtool-policy-receipt/v1"
TRUST_RECEIPT_PRODUCER = "zeroverse.windows-signtool-policy/powershell-v1"
TRUST_RECEIPT_SIGNATURE_NAMESPACE = "0verse-windows-trust-receipt-v1"
TRUST_POLICY_PROOF_LIMIT = (
    "Out-of-band terminal-root and SignTool allowlists only; policy authenticity and "
    "authorization depend on the operator-supplied retained policy bytes."
)
TRUST_RECEIPT_PROOF_LIMIT = (
    "Worker-signed producer observation of SignTool policy result, explicit catalog "
    "membership when declared, pinned terminal root, and retained-byte integrity only; "
    "servicing provenance, package or build identity, vulnerability status, bounty "
    "eligibility, and redistribution rights are unproven."
)

_SHA256 = re.compile(r"[0-9a-f]{64}")
_SHA1 = re.compile(r"[0-9A-F]{40}")


@dataclass(frozen=True)
class WindowsTrustReceipt:
    artifact_path: Path
    artifact_sha256: str
    catalog_path: Path | None
    catalog_sha256: str | None
    receipt_path: Path
    receipt_sha256: str
    receipt_signature_path: Path
    receipt_signature_sha256: str
    receipt_signer_identity: str
    allowed_signers_path: Path
    allowed_signers_sha256: str
    root_policy_path: Path
    root_policy_sha256: str
    policy_id: str
    signtool_path: Path
    signtool_sha256: str
    mode: str
    signer_certificate_sha256: str
    terminal_root_cert_sha256: str
    verified_at_utc: str

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_path": str(self.artifact_path),
            "artifact_sha256": self.artifact_sha256,
            "catalog_path": None if self.catalog_path is None else str(self.catalog_path),
            "catalog_sha256": self.catalog_sha256,
            "receipt_path": str(self.receipt_path),
            "receipt_sha256": self.receipt_sha256,
            "receipt_signature_path": str(self.receipt_signature_path),
            "receipt_signature_sha256": self.receipt_signature_sha256,
            "receipt_signer_identity": self.receipt_signer_identity,
            "allowed_signers_path": str(self.allowed_signers_path),
            "allowed_signers_sha256": self.allowed_signers_sha256,
            "root_policy_path": str(self.root_policy_path),
            "root_policy_sha256": self.root_policy_sha256,
            "policy_id": self.policy_id,
            "signtool_path": str(self.signtool_path),
            "signtool_sha256": self.signtool_sha256,
            "mode": self.mode,
            "signer_certificate_sha256": self.signer_certificate_sha256,
            "terminal_root_cert_sha256": self.terminal_root_cert_sha256,
            "verified_at_utc": self.verified_at_utc,
        }


def verify_windows_trust_receipt(
    artifact_path: str | Path,
    receipt_path: str | Path,
    root_policy_path: str | Path,
    signtool_path: str | Path,
    allowed_signers_path: str | Path,
    *,
    catalog_path: str | Path | None = None,
) -> WindowsTrustReceipt:
    """Strictly verify a SignTool receipt and every retained input it references."""
    artifact_file = _regular_file(Path(artifact_path), "artifact")
    receipt_file = _regular_file(Path(receipt_path), "receipt")
    policy_file = _regular_file(Path(root_policy_path), "root policy")
    signtool_file = _regular_file(Path(signtool_path), "SignTool")
    allowed_signers_file = _regular_file(Path(allowed_signers_path), "allowed signers")
    catalog_file = (
        None
        if catalog_path is None
        else _regular_file(Path(catalog_path), "catalog")
    )

    policy_raw, _, policy_digest, policy_size = _load_document(
        policy_file, "root policy", max_bytes=1024 * 1024
    )
    _exact(
        policy_raw,
        {
            "schema_version",
            "policy_id",
            "allowed_root_cert_sha256",
            "allowed_signtool_sha256",
            "proof_limit",
        },
        "root policy",
    )
    if policy_raw["schema_version"] != TRUST_POLICY_SCHEMA:
        raise ValueError("trust root policy schema mismatch")
    policy_id = _nonempty(policy_raw["policy_id"], "root policy.policy_id")
    roots_raw = policy_raw["allowed_root_cert_sha256"]
    if not isinstance(roots_raw, list) or not roots_raw:
        raise ValueError("trust root policy allowlist must be a nonempty array")
    allowed_roots = [_sha256(value, "allowed root") for value in roots_raw]
    if len(set(allowed_roots)) != len(allowed_roots):
        raise ValueError("trust root policy allowlist contains duplicates")
    tools_raw = policy_raw["allowed_signtool_sha256"]
    if not isinstance(tools_raw, list) or not tools_raw:
        raise ValueError("trust SignTool allowlist must be a nonempty array")
    allowed_tools = [_sha256(value, "allowed SignTool") for value in tools_raw]
    if len(set(allowed_tools)) != len(allowed_tools):
        raise ValueError("trust SignTool allowlist contains duplicates")
    if policy_raw["proof_limit"] != TRUST_POLICY_PROOF_LIMIT:
        raise ValueError("trust root policy proof_limit mismatch")

    raw, receipt_bytes, receipt_digest, _ = _load_document(
        receipt_file, "receipt", max_bytes=4 * 1024 * 1024
    )
    _exact(
        raw,
        {
            "schema_version",
            "producer",
            "receipt_signer_identity",
            "artifact",
            "catalog",
            "root_policy",
            "signtool",
            "verification",
            "verified_claims",
            "proof_limit",
        },
        "receipt",
    )
    if (
        raw["schema_version"] != TRUST_RECEIPT_SCHEMA
        or raw["producer"] != TRUST_RECEIPT_PRODUCER
    ):
        raise ValueError("trust receipt schema/producer mismatch")
    signer_identity = _nonempty(
        raw["receipt_signer_identity"], "receipt_signer_identity"
    )
    signature_file = _regular_file(
        receipt_file.parent / f"{receipt_file.name}.sig", "receipt signature"
    )
    if signature_file.stat().st_size > 64 * 1024:
        raise ValueError("trust receipt signature exceeds the 64 KiB limit")
    signature_bytes = signature_file.read_bytes()
    try:
        signature_text = signature_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("trust receipt signature must be UTF-8") from exc
    from .ssh_authorization import verify_ssh_signature

    allowed_signers_bytes = _read_once(
        allowed_signers_file, "allowed signers", max_bytes=1024 * 1024
    )
    with tempfile.TemporaryDirectory(prefix="0verse-trust-signers-") as temporary:
        policy_snapshot = Path(temporary) / "allowed_signers"
        policy_snapshot.write_bytes(allowed_signers_bytes)
        verify_ssh_signature(
            receipt_bytes,
            signature_text,
            identity=signer_identity,
            namespace=TRUST_RECEIPT_SIGNATURE_NAMESPACE,
            allowed_signers=policy_snapshot,
            label="Windows trust receipt",
            require_trusted_policy=False,
        )

    artifact_digest, _ = _bound_file(raw["artifact"], artifact_file, "artifact")
    _bound_observed_file(
        raw["root_policy"],
        policy_file,
        "root_policy",
        policy_digest,
        policy_size,
        extra={"policy_id"},
    )
    policy_ref = _object(raw["root_policy"], "root_policy")
    if policy_ref["policy_id"] != policy_id:
        raise ValueError("trust receipt policy_id mismatch")
    signtool_digest, _ = _bound_file(
        raw["signtool"], signtool_file, "signtool", extra={"file_version"}
    )
    signtool_ref = _object(raw["signtool"], "signtool")
    _nonempty(signtool_ref["file_version"], "signtool.file_version")
    if signtool_digest not in allowed_tools:
        raise ValueError("trust SignTool is not allowed by root policy")

    verification = _object(raw["verification"], "verification")
    _exact(
        verification,
        {
            "mode",
            "argv",
            "exit_code",
            "stdout",
            "stderr",
            "signature_status",
            "signature_type",
            "signer_certificate",
            "certificate_chain",
            "terminal_root_cert_sha256",
            "chain_build_succeeded",
            "verified_at_utc",
            "declared_network_mode",
            "os_build_lab_ex",
        },
        "verification",
    )
    mode = str(verification["mode"])
    if mode not in {"embedded", "catalog"}:
        raise ValueError("trust verification mode must be embedded or catalog")

    catalog_digest: str | None = None
    if mode == "embedded":
        if raw["catalog"] is not None or catalog_file is not None:
            raise ValueError("embedded trust receipt must not bind a catalog")
    else:
        if catalog_file is None or raw["catalog"] is None:
            raise ValueError("catalog trust receipt requires the explicit catalog")
        catalog_digest, _ = _bound_file(raw["catalog"], catalog_file, "catalog")

    _verify_argv(verification["argv"], mode, artifact_file, catalog_file)
    if (
        not isinstance(verification["exit_code"], int)
        or isinstance(verification["exit_code"], bool)
        or verification["exit_code"] != 0
    ):
        raise ValueError("SignTool exit_code must be exactly zero")
    _bound_sidecar(
        verification["stdout"],
        receipt_file.parent,
        "stdout",
        f"{receipt_file.name}.stdout.bin",
    )
    _bound_sidecar(
        verification["stderr"],
        receipt_file.parent,
        "stderr",
        f"{receipt_file.name}.stderr.bin",
    )
    if verification["signature_status"] != "Valid":
        raise ValueError("trust signature_status must be Valid")
    expected_type = "Authenticode" if mode == "embedded" else "Catalog"
    if verification["signature_type"] != expected_type:
        raise ValueError("trust signature_type does not match mode")
    if verification["chain_build_succeeded"] is not True:
        raise ValueError("certificate chain must have built successfully")

    signer = _certificate(verification["signer_certificate"], "signer_certificate")
    chain_raw = verification["certificate_chain"]
    if not isinstance(chain_raw, list) or not chain_raw:
        raise ValueError("trust certificate_chain must be nonempty")
    chain = [
        _certificate(value, f"certificate_chain[{index}]")
        for index, value in enumerate(chain_raw)
    ]
    chain_hashes = [cert["cert_sha256"] for cert in chain]
    if len(set(chain_hashes)) != len(chain_hashes):
        raise ValueError("trust certificate_chain contains duplicate certificates")
    if chain[0] != signer:
        raise ValueError("trust signer_certificate must equal the chain leaf")
    root = chain[-1]
    if root["subject"] != root["issuer"]:
        raise ValueError("trust certificate_chain terminal certificate is not a root")
    terminal_root = _sha256(
        verification["terminal_root_cert_sha256"], "terminal_root_cert_sha256"
    )
    if terminal_root != root["cert_sha256"]:
        raise ValueError("trust terminal root does not match certificate_chain")
    if terminal_root not in allowed_roots:
        raise ValueError("trust terminal root is not allowed by root policy")

    verified_at = _utc_timestamp(verification["verified_at_utc"], "verified_at_utc")
    if verification["declared_network_mode"] not in {
        "network-isolated",
        "network-enabled",
    }:
        raise ValueError("trust declared_network_mode mismatch")
    _nonempty(verification["os_build_lab_ex"], "os_build_lab_ex")
    claims = [
        "signtool-authenticode-policy-valid",
        "pinned-terminal-root",
        "retained-content-sha256",
    ]
    if mode == "catalog":
        claims.append("explicit-catalog-membership")
    if raw["verified_claims"] != claims:
        raise ValueError("trust verified_claims mismatch")
    if raw["proof_limit"] != TRUST_RECEIPT_PROOF_LIMIT:
        raise ValueError("trust receipt proof_limit mismatch")

    return WindowsTrustReceipt(
        artifact_file.resolve(),
        artifact_digest,
        None if catalog_file is None else catalog_file.resolve(),
        catalog_digest,
        receipt_file.resolve(),
        receipt_digest,
        signature_file.resolve(),
        hashlib.sha256(signature_bytes).hexdigest(),
        signer_identity,
        allowed_signers_file.resolve(),
        hashlib.sha256(allowed_signers_bytes).hexdigest(),
        policy_file.resolve(),
        policy_digest,
        policy_id,
        signtool_file.resolve(),
        signtool_digest,
        mode,
        signer["cert_sha256"],
        terminal_root,
        verified_at.isoformat(),
    )


def _verify_argv(
    raw: object, mode: str, artifact: Path, catalog: Path | None
) -> None:
    if not isinstance(raw, list) or not all(isinstance(value, str) for value in raw):
        raise ValueError("trust verification.argv must be a string array")
    if any(not value or "\x00" in value for value in raw):
        raise ValueError("trust verification.argv contains an invalid argument")
    if mode == "embedded":
        if len(raw) != 4 or raw[:3] != ["verify", "/v", "/pa"]:
            raise ValueError("trust embedded SignTool argv mismatch")
        if _argument_name(raw[3]) != artifact.name:
            raise ValueError("trust SignTool artifact argument mismatch")
    else:
        if len(raw) != 6 or raw[:4] != ["verify", "/v", "/pa", "/c"]:
            raise ValueError("trust catalog SignTool argv mismatch")
        if catalog is None or _argument_name(raw[4]) != catalog.name:
            raise ValueError("trust SignTool catalog argument mismatch")
        if _argument_name(raw[5]) != artifact.name:
            raise ValueError("trust SignTool artifact argument mismatch")


def _argument_name(value: str) -> str:
    return ntpath.basename(value.replace("/", "\\"))


def _bound_sidecar(raw: object, parent: Path, label: str, expected_name: str) -> None:
    ref = _object(raw, label)
    _exact(ref, {"path", "sha256", "size_bytes"}, label)
    name = _safe_name(ref["path"], f"{label}.path")
    if name != expected_name:
        raise ValueError(f"trust {label} path mismatch")
    file = _regular_file(parent / name, label)
    digest, size = _hash_file(file)
    if digest != _sha256(ref["sha256"], f"{label}.sha256"):
        raise ValueError(f"trust {label} SHA-256 mismatch")
    _size(ref["size_bytes"], size, f"{label}.size_bytes", allow_zero=True)


def _bound_file(
    raw: object, path: Path, label: str, *, extra: set[str] | None = None
) -> tuple[str, int]:
    ref = _object(raw, label)
    expected = {"path", "sha256", "size_bytes"} | (extra or set())
    _exact(ref, expected, label)
    if _safe_name(ref["path"], f"{label}.path") != path.name:
        raise ValueError(f"trust {label} path mismatch")
    expected_digest = _sha256(ref["sha256"], f"{label}.sha256")
    digest, size = _hash_file(path)
    if digest != expected_digest:
        raise ValueError(f"trust {label} SHA-256 mismatch")
    _size(ref["size_bytes"], size, f"{label}.size_bytes")
    return digest, size


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
    result = {
        field: _nonempty(cert[field], f"{label}.{field}")
        for field in ("subject", "issuer", "serial_number")
    }
    thumbprint = cert["thumbprint_sha1"]
    if not isinstance(thumbprint, str):
        raise ValueError(f"trust {label}.thumbprint_sha1 must be uppercase SHA-1")
    if _SHA1.fullmatch(thumbprint) is None:
        raise ValueError(f"trust {label}.thumbprint_sha1 must be uppercase SHA-1")
    result["thumbprint_sha1"] = thumbprint
    result["cert_sha256"] = _sha256(cert["cert_sha256"], f"{label}.cert_sha256")
    not_before = _utc_timestamp(cert["not_before_utc"], f"{label}.not_before_utc")
    not_after = _utc_timestamp(cert["not_after_utc"], f"{label}.not_after_utc")
    if not_before >= not_after:
        raise ValueError(f"trust {label} validity interval is invalid")
    result["not_before_utc"] = not_before.isoformat()
    result["not_after_utc"] = not_after.isoformat()
    return result


def _load_document(
    path: Path, label: str, *, max_bytes: int
) -> tuple[dict[str, Any], bytes, str, int]:
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise ValueError(f"trust {label} has an invalid size")
    payload = path.read_bytes()
    if len(payload) != size:
        raise ValueError(f"trust {label} changed while being read")
    raw = json.loads(payload, object_pairs_hook=_unique_object)
    return _object(raw, label), payload, hashlib.sha256(payload).hexdigest(), size


def _read_once(path: Path, label: str, *, max_bytes: int) -> bytes:
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise ValueError(f"trust {label} has an invalid size")
    payload = path.read_bytes()
    if len(payload) != size:
        raise ValueError(f"trust {label} changed while being read")
    return payload


def _bound_observed_file(
    raw: object,
    path: Path,
    label: str,
    digest: str,
    size: int,
    *,
    extra: set[str] | None = None,
) -> None:
    ref = _object(raw, label)
    expected = {"path", "sha256", "size_bytes"} | (extra or set())
    _exact(ref, expected, label)
    if _safe_name(ref["path"], f"{label}.path") != path.name:
        raise ValueError(f"trust {label} path mismatch")
    if _sha256(ref["sha256"], f"{label}.sha256") != digest:
        raise ValueError(f"trust {label} SHA-256 mismatch")
    _size(ref["size_bytes"], size, f"{label}.size_bytes")


def _regular_file(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"trust {label} must be a regular non-symlink file")
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
        raise ValueError(f"trust {label} must be an object")
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
        raise ValueError(f"trust {label} fields invalid: {'; '.join(details)}")


def _safe_name(raw: object, label: str) -> str:
    value = _nonempty(raw, label)
    if value in {".", ".."} or Path(value).name != value or ntpath.basename(value) != value:
        raise ValueError(f"trust {label} must be a safe basename")
    return value


def _sha256(raw: object, label: str) -> str:
    if not isinstance(raw, str) or _SHA256.fullmatch(raw) is None:
        raise ValueError(f"trust {label} must be a lowercase SHA-256")
    return raw


def _size(raw: object, observed: int, label: str, *, allow_zero: bool = False) -> None:
    minimum = 0 if allow_zero else 1
    if (
        not isinstance(raw, int)
        or isinstance(raw, bool)
        or raw < minimum
        or raw != observed
    ):
        raise ValueError(f"trust {label} mismatch")


def _nonempty(raw: object, label: str) -> str:
    if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
        raise ValueError(f"trust {label} must be a nonempty string without NUL bytes")
    return raw


def _utc_timestamp(raw: object, label: str) -> datetime:
    if not isinstance(raw, str):
        raise ValueError(f"trust {label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"trust {label} must be a UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError(f"trust {label} must be a UTC timestamp")
    return parsed
