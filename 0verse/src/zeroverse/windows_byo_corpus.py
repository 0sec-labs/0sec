"""Verify signed, label-blinded Windows BYO corpus commitments."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .ssh_authority_commitment import ssh_authority_key_commitment
from .ssh_authorization import verify_ssh_signature

BYO_CORPUS_SCHEMA = "0verse.windows-byo-corpus-inventory/v1"
BYO_CORPUS_PRODUCER = "zeroverse.windows-byo-corpus-curation/v1"
BYO_CORPUS_SIGNATURE_NAMESPACE = "0verse-windows-byo-corpus-inventory-v1"
BYO_CORPUS_COMMITMENT_SCHEME = "hmac-sha256-private-256-bit-key/v1"
DEFAULT_ALLOWED_SIGNERS = Path("/etc/0verse/windows-byo-corpus.allowed_signers")
BYO_CORPUS_CLAIMS = [
    "inventory-signature-and-curator-authority-bound",
    "declared-hmac-item-and-private-bundle-commitments-bound",
    "declared-freeze-time-and-nonce-bound",
    "metadata-only-no-network-no-execution-policy-bound",
]
BYO_CORPUS_PROOF_LIMIT = (
    "Signature verification authenticates the curator's blinded declarations only. The private "
    "HMAC key, source index, label map, pair map, binaries, and evidence bundles are not loaded "
    "or verified, so commitment construction, key entropy, freeze chronology, labels, patch "
    "direction, provenance, authenticity, admission, reachability, vulnerability, impact, "
    "novelty, bounty eligibility, and redistribution rights remain unproven."
)

_SHA256 = re.compile(r"[0-9a-f]{64}")
_INVENTORY_ID = re.compile(r"inventory-[0-9a-f]{64}")
_NONCE = re.compile(r"[A-Za-z0-9_-]{32,128}")
_SAFETY_FLAGS = {
    "metadata_only": True,
    "runtime_consumable": False,
    "automatic_download": False,
    "network_access_performed": False,
    "private_evidence_verified": False,
    "source_provenance_verified": False,
    "blinding_verified": False,
    "freeze_chronology_verified": False,
    "static_evaluation_admitted": False,
    "capability_verified": False,
    "reachability_verified": False,
    "vulnerability_verified": False,
    "impact_verified": False,
    "novelty_verified": False,
    "claim_eligible": False,
    "bounty_eligible": False,
    "execution_authorized": False,
    "redistribution_authorized": False,
    "disclosure_authorized": False,
    "automatic_disclosure": False,
    "weaponization_authorized": False,
    "human_source_review_required": True,
    "human_private_admission_required": True,
    "human_label_unblinding_required": True,
}


@dataclass(frozen=True)
class SignatureVerifiedWindowsByoCorpusInventory:
    inventory_path: Path
    inventory_sha256: str
    signature_path: Path
    signature_sha256: str
    inventory_id: str
    inventory_nonce: str
    declared_frozen_at: str
    manifest_signer_identity: str
    allowed_signers_sha256: str
    authority_key_commitment_sha256: str
    blinding_key_commitment_sha256: str
    declared_source_index_commitment_sha256: str
    item_commitment_sha256s: tuple[str, ...]
    private_bundle_commitment_sha256s: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": BYO_CORPUS_SCHEMA,
            "producer": BYO_CORPUS_PRODUCER,
            "commitment_scheme": BYO_CORPUS_COMMITMENT_SCHEME,
            "signature_verified": True,
            "verified_claims": list(BYO_CORPUS_CLAIMS),
            "proof_limit": BYO_CORPUS_PROOF_LIMIT,
            "inventory_path": str(self.inventory_path),
            "inventory_sha256": self.inventory_sha256,
            "signature_path": str(self.signature_path),
            "signature_sha256": self.signature_sha256,
            "inventory_id": self.inventory_id,
            "inventory_nonce": self.inventory_nonce,
            "declared_frozen_at": self.declared_frozen_at,
            "manifest_signer_identity": self.manifest_signer_identity,
            "allowed_signers_sha256": self.allowed_signers_sha256,
            "authority_key_commitment_sha256": self.authority_key_commitment_sha256,
            "blinding_key_commitment_sha256": self.blinding_key_commitment_sha256,
            "declared_source_index_commitment_sha256": (
                self.declared_source_index_commitment_sha256
            ),
            "item_commitment_sha256s": list(self.item_commitment_sha256s),
            "private_bundle_commitment_sha256s": list(
                self.private_bundle_commitment_sha256s
            ),
            **_SAFETY_FLAGS,
        }


def verify_windows_byo_corpus_manifest(
    manifest_path: str | Path,
    *,
    now: datetime | None = None,
    verification_ssh_keygen: str | Path = "ssh-keygen",
    verification_inherit_environment: bool = True,
) -> SignatureVerifiedWindowsByoCorpusInventory:
    """Authenticate a blinded declaration under the fixed production policy."""
    inventory = _regular_file(Path(manifest_path), "BYO corpus inventory", 4 * 1024 * 1024)
    policy = _regular_file(
        DEFAULT_ALLOWED_SIGNERS, "BYO corpus production allowed-signers policy", 1024 * 1024
    )
    signature = _regular_file(
        Path(f"{inventory}.sig"), "BYO corpus inventory signature", 64 * 1024
    )
    inventory_bytes = _read_once(inventory, 4 * 1024 * 1024)
    policy_bytes = _read_once(policy, 1024 * 1024)
    signature_bytes = _read_once(signature, 64 * 1024)
    try:
        raw = json.loads(inventory_bytes, object_pairs_hook=_unique_object)
        signature_text = signature_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("BYO corpus signature must be UTF-8") from exc
    if not isinstance(raw, dict):
        raise ValueError("BYO corpus inventory must be a JSON object")
    _exact(
        raw,
        {
            "schema_version",
            "producer",
            "inventory_id",
            "inventory_nonce",
            "declared_frozen_at",
            "artifact_policy",
            "authority",
            "commitment_scheme",
            "blinding_key_commitment_sha256",
            "declared_source_index_commitment_sha256",
            "items",
            "safety_flags",
            "verified_claims",
            "proof_limit",
        },
        "inventory",
    )
    if raw["schema_version"] != BYO_CORPUS_SCHEMA or raw["producer"] != BYO_CORPUS_PRODUCER:
        raise ValueError("BYO corpus inventory schema/producer mismatch")
    if raw["commitment_scheme"] != BYO_CORPUS_COMMITMENT_SCHEME:
        raise ValueError("BYO corpus inventory commitment scheme mismatch")
    inventory_id = _match(raw["inventory_id"], _INVENTORY_ID, "inventory_id")
    nonce = _match(raw["inventory_nonce"], _NONCE, "inventory_nonce")
    frozen_at = _declared_freeze_time(raw["declared_frozen_at"], now=now)
    blinding_key_commitment = _nonplaceholder_sha256(
        raw["blinding_key_commitment_sha256"], "blinding_key_commitment_sha256"
    )
    source_index_commitment = _nonplaceholder_sha256(
        raw["declared_source_index_commitment_sha256"],
        "declared_source_index_commitment_sha256",
    )
    _artifact_policy(raw["artifact_policy"])
    safety = _object(raw["safety_flags"], "safety_flags")
    if safety != _SAFETY_FLAGS:
        raise ValueError("BYO corpus safety flags must match the exhaustive safety gate set")

    authority = _object(raw["authority"], "authority")
    _exact(
        authority,
        {
            "manifest_signer_identity",
            "allowed_signers_sha256",
            "authority_key_commitment_sha256",
        },
        "authority",
    )
    identity = _safe_text(authority["manifest_signer_identity"], "manifest signer identity")
    policy_identity = _validate_production_policy(policy, policy_bytes)
    if policy_identity != identity:
        raise ValueError("BYO corpus signer identity does not match the production policy")
    policy_sha256 = hashlib.sha256(policy_bytes).hexdigest()
    if _sha256(authority["allowed_signers_sha256"], "allowed_signers_sha256") != policy_sha256:
        raise ValueError("BYO corpus production policy SHA-256 mismatch")
    with tempfile.TemporaryDirectory(prefix="0verse-byo-corpus-signers-") as temporary:
        snapshot = Path(temporary) / "allowed_signers"
        snapshot.write_bytes(policy_bytes)
        key_commitment = ssh_authority_key_commitment(snapshot)
        if (
            _sha256(
                authority["authority_key_commitment_sha256"],
                "authority_key_commitment_sha256",
            )
            != key_commitment
        ):
            raise ValueError("BYO corpus curator authority key commitment mismatch")
        verify_ssh_signature(
            inventory_bytes,
            signature_text,
            identity=identity,
            namespace=BYO_CORPUS_SIGNATURE_NAMESPACE,
            allowed_signers=snapshot,
            label="Windows BYO corpus inventory",
            require_trusted_policy=False,
            ssh_keygen=verification_ssh_keygen,
            inherit_environment=verification_inherit_environment,
        )

    items = raw["items"]
    if not isinstance(items, list) or not items:
        raise ValueError("BYO corpus items must be a nonempty array")
    item_commitments: list[str] = []
    bundle_commitments: list[str] = []
    for index, value in enumerate(items):
        item, bundle = _item(value, index)
        item_commitments.append(item)
        bundle_commitments.append(bundle)
    if item_commitments != sorted(item_commitments):
        raise ValueError("BYO corpus item commitments must be canonically sorted")
    all_commitments = [
        blinding_key_commitment,
        source_index_commitment,
        *item_commitments,
        *bundle_commitments,
    ]
    if len(set(all_commitments)) != len(all_commitments):
        raise ValueError("BYO corpus commitments must be globally unique")
    if raw["verified_claims"] != BYO_CORPUS_CLAIMS:
        raise ValueError("BYO corpus verified_claims mismatch")
    if raw["proof_limit"] != BYO_CORPUS_PROOF_LIMIT:
        raise ValueError("BYO corpus proof_limit mismatch")
    return SignatureVerifiedWindowsByoCorpusInventory(
        inventory.resolve(),
        hashlib.sha256(inventory_bytes).hexdigest(),
        signature.resolve(),
        hashlib.sha256(signature_bytes).hexdigest(),
        inventory_id,
        nonce,
        frozen_at.isoformat(),
        identity,
        policy_sha256,
        key_commitment,
        blinding_key_commitment,
        source_index_commitment,
        tuple(item_commitments),
        tuple(bundle_commitments),
    )


def _artifact_policy(raw: object) -> None:
    policy = _object(raw, "artifact_policy")
    _exact(
        policy,
        {"distribution", "retained_bytes", "permitted_analysis", "execution", "network"},
        "artifact_policy",
    )
    if policy != {
        "distribution": "commitments-only",
        "retained_bytes": "private-content-addressed-store",
        "permitted_analysis": "offline-static-only-after-separate-admission",
        "execution": "prohibited",
        "network": "prohibited",
    }:
        raise ValueError("BYO corpus inventory policy must remain blinded and non-executing")


def _item(raw: object, index: int) -> tuple[str, str]:
    label = f"items[{index}]"
    item = _object(raw, label)
    _exact(
        item,
        {"item_commitment_sha256", "private_evidence_bundle_commitment_sha256"},
        label,
    )
    return (
        _nonplaceholder_sha256(item["item_commitment_sha256"], f"{label}.item_commitment"),
        _nonplaceholder_sha256(
            item["private_evidence_bundle_commitment_sha256"],
            f"{label}.private_evidence_bundle_commitment",
        ),
    )


def _declared_freeze_time(raw: object, *, now: datetime | None) -> datetime:
    try:
        value = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("declared_frozen_at must be an ISO-8601 timestamp") from exc
    if value.tzinfo is None:
        raise ValueError("declared_frozen_at must include a timezone")
    value = value.astimezone(UTC)
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    if value > current.astimezone(UTC) + timedelta(minutes=5):
        raise ValueError("declared_frozen_at is too far in the future")
    return value


def _validate_production_policy(path: Path, data: bytes) -> str:
    _require_production_policy_permissions(path)
    try:
        lines = [
            line.strip()
            for line in data.decode("utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except UnicodeDecodeError as exc:
        raise ValueError("BYO corpus production policy must be UTF-8") from exc
    if len(lines) != 1:
        raise ValueError("BYO corpus production policy must contain exactly one signer line")
    fields = lines[0].split()
    if len(fields) not in {3, 4} or fields[1] != "ssh-ed25519":
        raise ValueError(
            "BYO corpus production policy must contain one literal identity and ssh-ed25519 key"
        )
    identity = fields[0]
    if (
        not identity
        or any(character in identity for character in "*,!,\x00\r\n")
        or identity.startswith("-")
    ):
        raise ValueError("BYO corpus production policy requires one literal identity")
    try:
        key = base64.b64decode(fields[2], validate=True)
    except ValueError as exc:
        raise ValueError("BYO corpus production policy key is invalid") from exc
    if not key:
        raise ValueError("BYO corpus production policy key is empty")
    return identity


def _require_production_policy_permissions(path: Path) -> None:
    metadata = path.stat()
    if metadata.st_uid != 0 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError(
            "BYO corpus production policy must be root-owned and not group/world writable"
        )


def _regular_file(path: Path, label: str, max_bytes: int) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0 or metadata.st_size > max_bytes:
        raise ValueError(f"{label} is empty or exceeds its size limit")
    return path.resolve()


def _read_once(path: Path, max_bytes: int) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > max_bytes
        ):
            raise ValueError(f"{path.name} is not a bounded regular file")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    if not data or len(data) > max_bytes:
        raise ValueError(f"{path.name} is empty or exceeds its size limit")
    return data


def _object(raw: object, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError(f"{label} must be a JSON object")
    return raw


def _exact(raw: dict[str, Any], expected: set[str], label: str) -> None:
    if set(raw) != expected:
        raise ValueError(f"{label} fields mismatch")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _match(raw: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(raw, str) or pattern.fullmatch(raw) is None:
        raise ValueError(f"{label} is invalid")
    return raw


def _sha256(raw: object, label: str) -> str:
    return _match(raw, _SHA256, label)


def _nonplaceholder_sha256(raw: object, label: str) -> str:
    value = _sha256(raw, label)
    if len(set(value)) == 1:
        raise ValueError(f"{label} must not be a placeholder digest")
    return value


def _safe_text(raw: object, label: str) -> str:
    if (
        not isinstance(raw, str)
        or not raw.strip()
        or len(raw.encode("utf-8")) > 512
        or any(character in raw for character in "\x00\r\n")
    ):
        raise ValueError(f"{label} is empty or unsafe")
    return raw
