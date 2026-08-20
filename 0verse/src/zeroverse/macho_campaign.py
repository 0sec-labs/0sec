"""Fail-closed evidence contracts for authorized Apple Mach-O research.

This module validates evidence only.  It cannot provision a Darwin worker,
execute a Mach-O, collect a crash, contact Apple, or disclose a report.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from .elf_campaign import _open_regular_nofollow
from .ssh_authority_commitment import ssh_authority_key_commitment
from .ssh_authorization import canonical_signed_material, verify_ssh_signature

CAMPAIGN_SCHEMA_VERSION = "0verse.macho-campaign/v1"
ACCEPTANCE_SCHEMA_VERSION = "0verse.macho-worker-acceptance/v1"
RECEIPT_SCHEMA_VERSION = "0verse.macho-campaign-receipt/v1"

AUTHORIZATION_SIGNATURE_NAMESPACE = "0verse-macho-authorization-v1"
ACCEPTANCE_SIGNATURE_NAMESPACE = "0verse-macho-worker-acceptance-v1"
TARGET_OBSERVATION_SIGNATURE_NAMESPACE = "0verse-macho-target-observation-v1"
CONTROL_OBSERVATION_SIGNATURE_NAMESPACE = "0verse-macho-control-observation-v1"

AUTHORIZATION_ALLOWED_SIGNERS = Path("/etc/0verse/macho-authorization.allowed_signers")
ACCEPTANCE_ALLOWED_SIGNERS = Path("/etc/0verse/macho-worker-acceptance.allowed_signers")
TARGET_ALLOWED_SIGNERS = Path("/etc/0verse/macho-target-observation.allowed_signers")
CONTROL_ALLOWED_SIGNERS = Path("/etc/0verse/macho-control-observation.allowed_signers")
SSH_KEYGEN = Path("/usr/bin/ssh-keygen")
TRUSTED_POLICY_UID = 0
TRUSTED_POLICY_GID = 0
TRUSTED_POLICY_MODE = 0o644
TRUSTED_SSH_KEYGEN_MODE = 0o755
TRUSTED_POLICIES = {
    "authorization": (
        AUTHORIZATION_ALLOWED_SIGNERS,
        "b3a1061bb9b8f45ccec982ed546aa683566dbbda98363dacecbb534b81ef68a4",
        "6cff86dbdf962cf9f1c93e2cb75e7aab6719c4c59387bbbb95f8a6521473b221",
    ),
    "acceptance": (
        ACCEPTANCE_ALLOWED_SIGNERS,
        "a29e663c9728ec450c20beca46e42f15ad802ec2c2c6c191d79a9d057c19c28a",
        "cfb3827bd30f7acef14929a350e0e8ef9b927f315298796203afaff9e5edc8e8",
    ),
    "target": (
        TARGET_ALLOWED_SIGNERS,
        "76f65fb3509eef9de0d3cffe15de5ccd98d329b36353e9fe61e5f89a4fc63f70",
        "94882050fa0ca7d68897eb0030ba7c837bc5f55fbc41c1fbfbee57da0013f403",
    ),
    "control": (
        CONTROL_ALLOWED_SIGNERS,
        "ddd45b9044e4291decc939ac71e8ff59a0f8f5d11a56651f65300db4d949af82",
        "31e4d842199cc649d26a8bd320d9b6d234eb7af5bfb0eeb888db254e28d82ded",
    ),
}
# Tests may replace this private map only with fixture-prefixed identities.  Production
# loaders expose no policy or verifier override and reject fixture mode's artifacts otherwise.
_FIXTURE_TRUST: dict[str, tuple[Path, str, str]] | None = None

OUTCOMES = frozenset({"CLEAN", "CRASH", "ERROR", "TIMEOUT"})
CLASSIFICATIONS = frozenset(
    {"CLEAN", "TARGET_ONLY_CRASH", "CONTROL_ONLY_CRASH", "BOTH_CRASH", "ERROR", "TIMEOUT"}
)
ARCHITECTURES = frozenset({"arm64", "arm64e", "x86_64"})
AUTHORIZATION_KINDS = frozenset({"published-bounty", "written-authorization", "owned-lab"})
CAPABILITIES = frozenset(
    {"native-macho", "crash-log-capture", "sysdiagnose-capture", "process-attribution"}
)

_DIGEST = re.compile(r"[0-9a-f]{64}")
_CDHASH = re.compile(r"[0-9a-f]{40}")
_UUID = re.compile(r"[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
_HARDWARE_MODEL = re.compile(r"[A-Za-z]+[0-9]+,[0-9]+")
_BUILD = re.compile(r"[0-9]{2}[A-Z][0-9]{2,4}[a-z]?")
_RFC3339 = re.compile(
    r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"[Tt](?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.[0-9]+)?(?:[Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)
_MAX_JSON_BYTES = 1024 * 1024
_SCOPE_MAX_AGE = timedelta(hours=24)
_ACCEPTANCE_MAX_AGE = timedelta(days=7)


def _duplicate_guard(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read(path: Path, label: str, maximum: int | None = None) -> bytes:
    descriptor, size = _open_regular_nofollow(path, label)
    try:
        if maximum is not None and (size < 2 or size > maximum):
            raise ValueError(f"{label} must be a bounded JSON document")
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise ValueError(f"{label} changed while read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError(f"{label} changed while read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _json(path: Path, label: str) -> tuple[dict[str, object], str]:
    data = _read(path, label, _MAX_JSON_BYTES)
    try:
        raw = json.loads(data, object_pairs_hook=_duplicate_guard)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"{label} must be a JSON object")
    return raw, hashlib.sha256(data).hexdigest()


def _identity(path: Path, label: str) -> tuple[str, int]:
    descriptor, expected = _open_regular_nofollow(path, label)
    digest = hashlib.sha256()
    observed = 0
    try:
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            observed += len(chunk)
    finally:
        os.close(descriptor)
    if observed != expected:
        raise ValueError(f"{label} changed while hashed")
    return digest.hexdigest(), observed


def _exact(raw: Mapping[str, object], fields: frozenset[str], label: str) -> None:
    missing, extra = sorted(fields - raw.keys()), sorted(raw.keys() - fields)
    if missing or extra:
        raise ValueError(f"{label} fields differ: missing={missing}, unexpected={extra}")


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ValueError(f"{name} must be non-empty text without NUL")
    return value


def _optional_text(value: object, name: str) -> str | None:
    return None if value is None else _text(value, name)


def _sha(value: object, name: str) -> str:
    result = _text(value, name)
    if _DIGEST.fullmatch(result) is None or result == "0" * 64:
        raise ValueError(f"{name} must be a nonzero lowercase SHA-256")
    return result


def _uuid(value: object, name: str) -> str:
    result = _text(value, name)
    if _UUID.fullmatch(result) is None or result == "00000000-0000-0000-0000-000000000000":
        raise ValueError(f"{name} must be a canonical nonzero Mach-O UUID")
    return result


def _identifier(value: object, name: str) -> str:
    result = _text(value, name)
    if _IDENTIFIER.fullmatch(result) is None:
        raise ValueError(f"{name} is not a valid identifier")
    return result


def _hardware_model(value: object, name: str) -> str:
    result = _text(value, name)
    if _HARDWARE_MODEL.fullmatch(result) is None:
        raise ValueError(f"{name} is not a canonical Apple hardware model")
    return result


def _timestamp(value: object, name: str) -> datetime:
    text = _text(value, name)
    if _RFC3339.fullmatch(text) is None:
        raise ValueError(f"{name} must be RFC3339 date-time")
    normalized = text.replace("t", "T")
    if normalized.endswith(("z", "Z")):
        normalized = normalized[:-1] + "+00:00"
    return datetime.fromisoformat(normalized).astimezone(UTC)


def _relative(value: object, name: str) -> str:
    result = _text(value, name)
    path = PurePosixPath(result)
    if (
        path.is_absolute()
        or result in {".", ".."}
        or ".." in path.parts
        or path.as_posix() != result
    ):
        raise ValueError(f"{name} must be a canonical bundle-relative path")
    return result


def _absolute(value: object, name: str) -> str:
    result = _text(value, name)
    path = PurePosixPath(result)
    if not path.is_absolute() or ".." in path.parts or path.as_posix() != result:
        raise ValueError(f"{name} must be a canonical absolute worker path")
    return result


def _strings(value: object, name: str) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(f"{name} must be an array")
    result = tuple(_text(item, f"{name} item") for item in value)
    if not result or len(set(result)) != len(result):
        raise ValueError(f"{name} must contain unique values")
    return result


def _trusted_policy(role: str) -> tuple[Path, str, bool]:
    fixture = _FIXTURE_TRUST
    if fixture is not None:
        try:
            path, _raw_sha256, key_commitment = fixture[role]
        except KeyError as exc:
            raise ValueError("fixture trust map is incomplete") from exc
        return path, key_commitment, True
    path, expected_raw_sha256, expected_key_commitment = TRUSTED_POLICIES[role]
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != TRUSTED_POLICY_UID
            or metadata.st_gid != TRUSTED_POLICY_GID
            or stat.S_IMODE(metadata.st_mode) != TRUSTED_POLICY_MODE
            or metadata.st_size < 1
            or metadata.st_size > _MAX_JSON_BYTES
        ):
            raise ValueError(f"Mach-O {role} signer policy ownership or mode is unsafe")
        raw = os.pread(descriptor, metadata.st_size, 0)
    finally:
        os.close(descriptor)
    if len(raw) != metadata.st_size or hashlib.sha256(raw).hexdigest() != expected_raw_sha256:
        raise ValueError(f"Mach-O {role} signer policy raw commitment differs")
    if ssh_authority_key_commitment(path) != expected_key_commitment:
        raise ValueError(f"Mach-O {role} signer policy key commitment differs")
    return path, expected_key_commitment, False


def _require_fixed_ssh_keygen() -> None:
    metadata = SSH_KEYGEN.lstat()
    if (
        SSH_KEYGEN.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != TRUSTED_SSH_KEYGEN_MODE
    ):
        raise ValueError("fixed Mach-O ssh-keygen executable is unsafe")


def _verify(
    raw: Mapping[str, object],
    identity: str,
    namespace: str,
    policy: Path,
    fixture: bool,
    label: str,
) -> None:
    signature = raw.get("signature_ssh")
    if not isinstance(signature, str):
        raise ValueError(f"{label}.signature_ssh must be text")
    verify_ssh_signature(
        canonical_signed_material(raw),
        signature,
        identity=identity,
        namespace=namespace,
        allowed_signers=policy,
        label=label,
        require_trusted_policy=not fixture,
        ssh_keygen=SSH_KEYGEN,
        inherit_environment=False,
    )


def _require_fixture_identities(*identities: str) -> None:
    if _FIXTURE_TRUST is not None and any(
        not identity.startswith("fixture-") for identity in identities
    ):
        raise ValueError("fixture trust can verify only fixture-prefixed identities")


@dataclass(frozen=True)
class EvidenceArtifact:
    path: str
    sha256: str
    size: int

    FIELDS = frozenset({"path", "sha256", "size"})

    @classmethod
    def from_mapping(cls, raw: object, name: str) -> EvidenceArtifact:
        if not isinstance(raw, Mapping):
            raise ValueError(f"{name} must be an object")
        _exact(raw, cls.FIELDS, name)
        size = raw["size"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError(f"{name}.size must be nonnegative")
        return cls(
            _relative(raw["path"], f"{name}.path"), _sha(raw["sha256"], f"{name}.sha256"), size
        )


@dataclass(frozen=True)
class MachOIdentity:
    path: str
    sha256: str
    macho_uuid: str
    code_signature_sha256: str
    cdhash: str
    signing_identifier: str
    team_identifier: str
    architecture: str
    product_name: str
    product_version: str
    product_build: str

    FIELDS = frozenset(
        {
            "path",
            "sha256",
            "macho_uuid",
            "code_signature_sha256",
            "cdhash",
            "signing_identifier",
            "team_identifier",
            "architecture",
            "product_name",
            "product_version",
            "product_build",
        }
    )

    @classmethod
    def from_mapping(cls, raw: object, name: str) -> MachOIdentity:
        if not isinstance(raw, Mapping):
            raise ValueError(f"{name} must be an object")
        _exact(raw, cls.FIELDS, name)
        architecture = _text(raw["architecture"], f"{name}.architecture")
        if architecture not in ARCHITECTURES:
            raise ValueError(f"{name}.architecture is unsupported")
        cdhash = _text(raw["cdhash"], f"{name}.cdhash")
        if _CDHASH.fullmatch(cdhash) is None:
            raise ValueError(f"{name}.cdhash must be lowercase SHA-1 CDHash")
        build = _text(raw["product_build"], f"{name}.product_build")
        if _BUILD.fullmatch(build) is None:
            raise ValueError(f"{name}.product_build is not an Apple build")
        return cls(
            _absolute(raw["path"], f"{name}.path"),
            _sha(raw["sha256"], f"{name}.sha256"),
            _uuid(raw["macho_uuid"], f"{name}.macho_uuid"),
            _sha(raw["code_signature_sha256"], f"{name}.code_signature_sha256"),
            cdhash,
            _text(raw["signing_identifier"], f"{name}.signing_identifier"),
            _text(raw["team_identifier"], f"{name}.team_identifier"),
            architecture,
            _text(raw["product_name"], f"{name}.product_name"),
            _text(raw["product_version"], f"{name}.product_version"),
            build,
        )


def macho_identity_commitment(identity: MachOIdentity) -> str:
    """Bind every exact Mach-O, code-signature, product, and build field."""
    material = json.dumps(
        asdict(identity), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(b"0verse-macho-identity-v1\0" + material).hexdigest()


@dataclass(frozen=True)
class MachOAuthorization:
    campaign_id: str
    target_sha256: str
    target_uuid: str
    control_sha256: str
    control_uuid: str
    target_identity_sha256: str
    control_identity_sha256: str
    coordinator: str
    worker: str
    hardware_model: str
    input_model: str
    kind: str
    scope_url: str
    scope_evidence: EvidenceArtifact
    scope_checked_at: str
    expires_at: str
    statement: str
    authorized_by: str
    authority_key_sha256: str
    signature_ssh: str

    FIELDS = frozenset(
        {
            "campaign_id",
            "target_sha256",
            "target_uuid",
            "control_sha256",
            "control_uuid",
            "target_identity_sha256",
            "control_identity_sha256",
            "coordinator",
            "worker",
            "hardware_model",
            "input_model",
            "kind",
            "scope_url",
            "scope_evidence",
            "scope_checked_at",
            "expires_at",
            "statement",
            "authorized_by",
            "authority_key_sha256",
            "signature_ssh",
        }
    )

    @classmethod
    def from_mapping(cls, raw: object, now: datetime | None = None) -> MachOAuthorization:
        if not isinstance(raw, Mapping):
            raise ValueError("authorization must be an object")
        _exact(raw, cls.FIELDS, "authorization")
        kind = _text(raw["kind"], "authorization.kind")
        if kind not in AUTHORIZATION_KINDS:
            raise ValueError("unsupported Mach-O authorization kind")
        url = _text(raw["scope_url"], "authorization.scope_url")
        parsed = urlparse(url)
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("public scope URL has an invalid port") from exc
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or port not in {None, 443}
            or (kind == "published-bounty" and parsed.hostname != "security.apple.com")
        ):
            raise ValueError("public scope URL must use https")
        value = cls(
            _identifier(raw["campaign_id"], "authorization.campaign_id"),
            _sha(raw["target_sha256"], "authorization.target_sha256"),
            _uuid(raw["target_uuid"], "authorization.target_uuid"),
            _sha(raw["control_sha256"], "authorization.control_sha256"),
            _uuid(raw["control_uuid"], "authorization.control_uuid"),
            _sha(raw["target_identity_sha256"], "authorization.target_identity_sha256"),
            _sha(raw["control_identity_sha256"], "authorization.control_identity_sha256"),
            _identifier(raw["coordinator"], "authorization.coordinator"),
            _identifier(raw["worker"], "authorization.worker"),
            _hardware_model(raw["hardware_model"], "authorization.hardware_model"),
            _text(raw["input_model"], "authorization.input_model"),
            kind,
            url,
            EvidenceArtifact.from_mapping(raw["scope_evidence"], "authorization.scope_evidence"),
            _text(raw["scope_checked_at"], "authorization.scope_checked_at"),
            _text(raw["expires_at"], "authorization.expires_at"),
            _text(raw["statement"], "authorization.statement"),
            _identifier(raw["authorized_by"], "authorization.authorized_by"),
            _sha(raw["authority_key_sha256"], "authorization.authority_key_sha256"),
            _text(raw["signature_ssh"], "authorization.signature_ssh"),
        )
        value.validate(now=now)
        return value

    def validate(self, now: datetime | None = None) -> None:
        current = (now or datetime.now(UTC)).astimezone(UTC)
        checked, expires = (
            _timestamp(self.scope_checked_at, "scope_checked_at"),
            _timestamp(self.expires_at, "expires_at"),
        )
        if checked > current + timedelta(minutes=5) or current - checked > _SCOPE_MAX_AGE:
            raise ValueError("public scope evidence must be checked within 24 hours")
        if expires <= current or expires <= checked:
            raise ValueError("Mach-O authorization is expired or inverted")
        if expires - checked > _SCOPE_MAX_AGE:
            raise ValueError("public-scope authorization window cannot exceed 24 hours")


@dataclass(frozen=True)
class MachOCampaign:
    schema_version: str
    campaign_id: str
    target: MachOIdentity
    control: MachOIdentity
    coordinator: str
    worker: str
    hardware_model: str
    worker_acceptance_path: str
    worker_acceptance_sha256: str
    input_model: str
    authorization: MachOAuthorization

    FIELDS = frozenset(
        {
            "schema_version",
            "campaign_id",
            "target",
            "control",
            "coordinator",
            "worker",
            "hardware_model",
            "worker_acceptance_path",
            "worker_acceptance_sha256",
            "input_model",
            "authorization",
        }
    )

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object], now: datetime | None = None) -> MachOCampaign:
        _exact(raw, cls.FIELDS, "Mach-O campaign")
        if raw["schema_version"] != CAMPAIGN_SCHEMA_VERSION:
            raise ValueError("unsupported Mach-O campaign schema")
        value = cls(
            CAMPAIGN_SCHEMA_VERSION,
            _identifier(raw["campaign_id"], "campaign_id"),
            MachOIdentity.from_mapping(raw["target"], "target"),
            MachOIdentity.from_mapping(raw["control"], "control"),
            _identifier(raw["coordinator"], "coordinator"),
            _identifier(raw["worker"], "worker"),
            _hardware_model(raw["hardware_model"], "hardware_model"),
            _relative(raw["worker_acceptance_path"], "worker_acceptance_path"),
            _sha(raw["worker_acceptance_sha256"], "worker_acceptance_sha256"),
            _text(raw["input_model"], "input_model"),
            MachOAuthorization.from_mapping(raw["authorization"], now),
        )
        if (
            value.target.sha256 == value.control.sha256
            or value.target.macho_uuid == value.control.macho_uuid
        ):
            raise ValueError("target/control hashes and Mach-O UUIDs must differ")
        if value.target.path == value.control.path:
            raise ValueError("target/control paths must differ")
        if value.target.signing_identifier != value.control.signing_identifier:
            raise ValueError("target/control signing identifiers must match")
        if (
            value.target.architecture != value.control.architecture
            or value.target.product_name != value.control.product_name
            or value.target.team_identifier != value.control.team_identifier
        ):
            raise ValueError("target/control platform, product, and signer must match")
        a = value.authorization
        if (
            a.campaign_id,
            a.target_sha256,
            a.target_uuid,
            a.control_sha256,
            a.control_uuid,
            a.target_identity_sha256,
            a.control_identity_sha256,
            a.coordinator,
            a.worker,
            a.hardware_model,
            a.input_model,
        ) != (
            value.campaign_id,
            value.target.sha256,
            value.target.macho_uuid,
            value.control.sha256,
            value.control.macho_uuid,
            macho_identity_commitment(value.target),
            macho_identity_commitment(value.control),
            value.coordinator,
            value.worker,
            value.hardware_model,
            value.input_model,
        ):
            raise ValueError("authorization is not bound to exact campaign artifacts and worker")
        if len({value.coordinator, value.worker, a.authorized_by}) != 3:
            raise ValueError("coordinator, worker, and authorization identities must differ")
        return value

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class DarwinWorkerAcceptance:
    schema_version: str
    acceptance_id: str
    campaign_id: str
    coordinator: str
    worker: str
    role: str
    hardware_model: str
    architecture: str
    os_product_version: str
    os_build: str
    kernel_uuid: str
    target_sha256: str
    target_uuid: str
    control_sha256: str
    control_uuid: str
    target_identity_sha256: str
    control_identity_sha256: str
    input_model: str
    capabilities: tuple[str, ...]
    network_isolated: bool
    coordinator_is_worker: bool
    accepted_at: str
    expires_at: str
    accepted_by: str
    authority_key_sha256: str
    signature_ssh: str

    FIELDS = frozenset(
        {
            "schema_version",
            "acceptance_id",
            "campaign_id",
            "coordinator",
            "worker",
            "role",
            "hardware_model",
            "architecture",
            "os_product_version",
            "os_build",
            "kernel_uuid",
            "target_sha256",
            "target_uuid",
            "control_sha256",
            "control_uuid",
            "target_identity_sha256",
            "control_identity_sha256",
            "input_model",
            "capabilities",
            "network_isolated",
            "coordinator_is_worker",
            "accepted_at",
            "expires_at",
            "accepted_by",
            "authority_key_sha256",
            "signature_ssh",
        }
    )

    @classmethod
    def from_mapping(
        cls, raw: Mapping[str, object], now: datetime | None = None
    ) -> DarwinWorkerAcceptance:
        _exact(raw, cls.FIELDS, "Darwin worker acceptance")
        if raw["schema_version"] != ACCEPTANCE_SCHEMA_VERSION:
            raise ValueError("unsupported Darwin worker acceptance schema")
        capabilities = _strings(raw["capabilities"], "capabilities")
        if set(capabilities) != CAPABILITIES:
            raise ValueError("Darwin worker acceptance capabilities are incomplete")
        architecture = _text(raw["architecture"], "architecture")
        if architecture not in ARCHITECTURES:
            raise ValueError("unsupported Darwin worker architecture")
        build = _text(raw["os_build"], "os_build")
        if _BUILD.fullmatch(build) is None:
            raise ValueError("os_build is not an Apple build")
        value = cls(
            ACCEPTANCE_SCHEMA_VERSION,
            _identifier(raw["acceptance_id"], "acceptance_id"),
            _identifier(raw["campaign_id"], "campaign_id"),
            _identifier(raw["coordinator"], "coordinator"),
            _identifier(raw["worker"], "worker"),
            _text(raw["role"], "role"),
            _hardware_model(raw["hardware_model"], "hardware_model"),
            architecture,
            _text(raw["os_product_version"], "os_product_version"),
            build,
            _uuid(raw["kernel_uuid"], "kernel_uuid"),
            _sha(raw["target_sha256"], "target_sha256"),
            _uuid(raw["target_uuid"], "target_uuid"),
            _sha(raw["control_sha256"], "control_sha256"),
            _uuid(raw["control_uuid"], "control_uuid"),
            _sha(raw["target_identity_sha256"], "target_identity_sha256"),
            _sha(raw["control_identity_sha256"], "control_identity_sha256"),
            _text(raw["input_model"], "input_model"),
            capabilities,
            raw["network_isolated"] is True,
            raw["coordinator_is_worker"] is True,
            _text(raw["accepted_at"], "accepted_at"),
            _text(raw["expires_at"], "expires_at"),
            _identifier(raw["accepted_by"], "accepted_by"),
            _sha(raw["authority_key_sha256"], "authority_key_sha256"),
            _text(raw["signature_ssh"], "signature_ssh"),
        )
        if (
            value.role != "darwin-native-observer"
            or not value.network_isolated
            or value.coordinator_is_worker
        ):
            raise ValueError("worker must be a role-separated, network-isolated Darwin observer")
        current = (now or datetime.now(UTC)).astimezone(UTC)
        accepted, expires = (
            _timestamp(value.accepted_at, "accepted_at"),
            _timestamp(value.expires_at, "expires_at"),
        )
        if accepted > current + timedelta(minutes=5) or current - accepted > _ACCEPTANCE_MAX_AGE:
            raise ValueError("worker acceptance must be no older than 7 days")
        if expires <= current or expires <= accepted:
            raise ValueError("worker acceptance is expired or inverted")
        if expires - accepted > _ACCEPTANCE_MAX_AGE:
            raise ValueError("worker acceptance window cannot exceed 7 days")
        return value

    def require_binding(self, campaign: MachOCampaign) -> None:
        if (
            self.campaign_id,
            self.coordinator,
            self.worker,
            self.hardware_model,
            self.target_sha256,
            self.target_uuid,
            self.control_sha256,
            self.control_uuid,
            self.target_identity_sha256,
            self.control_identity_sha256,
            self.input_model,
        ) != (
            campaign.campaign_id,
            campaign.coordinator,
            campaign.worker,
            campaign.hardware_model,
            campaign.target.sha256,
            campaign.target.macho_uuid,
            campaign.control.sha256,
            campaign.control.macho_uuid,
            macho_identity_commitment(campaign.target),
            macho_identity_commitment(campaign.control),
            campaign.input_model,
        ):
            raise ValueError("Darwin worker acceptance is not bound to the campaign")
        if (
            self.architecture != campaign.target.architecture
            or self.os_product_version != campaign.target.product_version
            or self.os_build != campaign.target.product_build
        ):
            raise ValueError("Darwin worker OS/build does not match the target product build")


@dataclass(frozen=True)
class ProcessAttribution:
    pid: int
    parent_pid: int
    responsible_pid: int
    launch_id: str
    executable_path: str
    executable_sha256: str
    macho_uuid: str
    cdhash: str
    evidence: EvidenceArtifact

    FIELDS = frozenset(
        {
            "pid",
            "parent_pid",
            "responsible_pid",
            "launch_id",
            "executable_path",
            "executable_sha256",
            "macho_uuid",
            "cdhash",
            "evidence",
        }
    )

    @classmethod
    def from_mapping(cls, raw: object, name: str) -> ProcessAttribution:
        if not isinstance(raw, Mapping):
            raise ValueError(f"{name} must be an object")
        _exact(raw, cls.FIELDS, name)
        integers = []
        for field in ("pid", "parent_pid", "responsible_pid"):
            value = raw[field]
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name}.{field} must be a positive integer")
            integers.append(value)
        cdhash = _text(raw["cdhash"], f"{name}.cdhash")
        if _CDHASH.fullmatch(cdhash) is None:
            raise ValueError(f"{name}.cdhash is invalid")
        return cls(
            pid=integers[0],
            parent_pid=integers[1],
            responsible_pid=integers[2],
            launch_id=_identifier(raw["launch_id"], f"{name}.launch_id"),
            executable_path=_absolute(raw["executable_path"], f"{name}.executable_path"),
            executable_sha256=_sha(raw["executable_sha256"], f"{name}.executable_sha256"),
            macho_uuid=_uuid(raw["macho_uuid"], f"{name}.macho_uuid"),
            cdhash=cdhash,
            evidence=EvidenceArtifact.from_mapping(raw["evidence"], f"{name}.evidence"),
        )


@dataclass(frozen=True)
class ReplayObservation:
    role: str
    replay_index: int
    coordinator: str
    worker: str
    campaign_sha256: str
    worker_acceptance_sha256: str
    binary_sha256: str
    binary_uuid: str
    input_sha256: str
    process: ProcessAttribution
    outcome: str
    exit_code: int | None
    termination_reason: str | None
    started_at: str
    finished_at: str
    crash_log: EvidenceArtifact | None
    sysdiagnose: EvidenceArtifact | None
    target_flag_reference: EvidenceArtifact | None
    evidence: tuple[EvidenceArtifact, ...]
    observed_by: str
    authority_key_sha256: str
    signature_ssh: str

    FIELDS = frozenset(
        {
            "role",
            "replay_index",
            "coordinator",
            "worker",
            "campaign_sha256",
            "worker_acceptance_sha256",
            "binary_sha256",
            "binary_uuid",
            "input_sha256",
            "process",
            "outcome",
            "exit_code",
            "termination_reason",
            "started_at",
            "finished_at",
            "crash_log",
            "sysdiagnose",
            "target_flag_reference",
            "evidence",
            "observed_by",
            "authority_key_sha256",
            "signature_ssh",
        }
    )

    @classmethod
    def from_mapping(cls, raw: object, role: str) -> ReplayObservation:
        if not isinstance(raw, Mapping):
            raise ValueError(f"{role} observation must be an object")
        _exact(raw, cls.FIELDS, f"{role} observation")
        if raw["role"] != role:
            raise ValueError(f"{role} observation role mismatch")
        replay = raw["replay_index"]
        if not isinstance(replay, int) or isinstance(replay, bool) or replay < 1:
            raise ValueError("replay_index must be positive")
        outcome = _text(raw["outcome"], "outcome")
        if outcome not in OUTCOMES:
            raise ValueError("unsupported Mach-O observation outcome")
        exit_code = raw["exit_code"]
        if exit_code is not None and (
            not isinstance(exit_code, int) or isinstance(exit_code, bool)
        ):
            raise ValueError("exit_code must be integer or null")
        crash_log = (
            None
            if raw["crash_log"] is None
            else EvidenceArtifact.from_mapping(raw["crash_log"], "crash_log")
        )
        sysdiagnose = (
            None
            if raw["sysdiagnose"] is None
            else EvidenceArtifact.from_mapping(raw["sysdiagnose"], "sysdiagnose")
        )
        target_flag_reference = (
            None
            if raw["target_flag_reference"] is None
            else EvidenceArtifact.from_mapping(
                raw["target_flag_reference"], "target_flag_reference"
            )
        )
        if role == "control" and target_flag_reference is not None:
            raise ValueError("control observation cannot carry Target Flag evidence")
        evidence_raw = raw["evidence"]
        if not isinstance(evidence_raw, list):
            raise ValueError("observation evidence must be an array")
        evidence = tuple(
            EvidenceArtifact.from_mapping(item, "observation evidence") for item in evidence_raw
        )
        value = cls(
            role,
            replay,
            _identifier(raw["coordinator"], "coordinator"),
            _identifier(raw["worker"], "worker"),
            _sha(raw["campaign_sha256"], "campaign_sha256"),
            _sha(raw["worker_acceptance_sha256"], "worker_acceptance_sha256"),
            _sha(raw["binary_sha256"], "binary_sha256"),
            _uuid(raw["binary_uuid"], "binary_uuid"),
            _sha(raw["input_sha256"], "input_sha256"),
            ProcessAttribution.from_mapping(raw["process"], "process"),
            outcome,
            exit_code,
            _optional_text(raw["termination_reason"], "termination_reason"),
            _text(raw["started_at"], "started_at"),
            _text(raw["finished_at"], "finished_at"),
            crash_log,
            sysdiagnose,
            target_flag_reference,
            evidence,
            _identifier(raw["observed_by"], "observed_by"),
            _sha(raw["authority_key_sha256"], "authority_key_sha256"),
            _text(raw["signature_ssh"], "signature_ssh"),
        )
        started, finished = (
            _timestamp(value.started_at, "started_at"),
            _timestamp(value.finished_at, "finished_at"),
        )
        if finished < started:
            raise ValueError("observation time window is inverted")
        if outcome == "CRASH" and (
            crash_log is None or sysdiagnose is None or not value.termination_reason
        ):
            raise ValueError("crash requires crash log, sysdiagnose, and termination reason")
        if outcome == "CRASH" and exit_code is not None:
            raise ValueError("crash replay must not be represented as a clean exit code")
        if outcome == "CLEAN" and (
            exit_code != 0 or crash_log is not None or value.termination_reason is not None
        ):
            raise ValueError("clean replay must exit zero without crash evidence")
        if outcome in {"ERROR", "TIMEOUT"}:
            if crash_log is not None:
                raise ValueError("error/timeout cannot be represented as a crash")
            if not value.termination_reason or not evidence or exit_code == 0:
                raise ValueError("error/timeout requires non-clean termination reason and evidence")
            if outcome == "TIMEOUT" and exit_code is not None:
                raise ValueError("timeout must not be represented as a process exit code")
        return value

    def require_binding(
        self, campaign: MachOCampaign, campaign_sha: str, acceptance_sha: str, input_sha: str
    ) -> None:
        binary = campaign.target if self.role == "target" else campaign.control
        if (
            self.campaign_sha256,
            self.worker_acceptance_sha256,
            self.coordinator,
            self.worker,
            self.binary_sha256,
            self.binary_uuid,
            self.input_sha256,
        ) != (
            campaign_sha,
            acceptance_sha,
            campaign.coordinator,
            campaign.worker,
            binary.sha256,
            binary.macho_uuid,
            input_sha,
        ):
            raise ValueError(f"{self.role} replay is not campaign/input bound")
        process = self.process
        if (
            process.executable_path,
            process.executable_sha256,
            process.macho_uuid,
            process.cdhash,
        ) != (
            binary.path,
            binary.sha256,
            binary.macho_uuid,
            binary.cdhash,
        ):
            raise ValueError(f"{self.role} process attribution does not identify the exact Mach-O")


@dataclass(frozen=True)
class BountyEligibility:
    status: str
    target_flag_present: bool
    public_scope_current: bool
    current_supported_build: bool
    target_only_reproduced: bool
    process_attributed: bool
    security_impact_established: bool
    originality_reviewed: bool
    private_submission_only: bool
    eligible: bool

    FIELDS = frozenset(
        {
            "status",
            "target_flag_present",
            "public_scope_current",
            "current_supported_build",
            "target_only_reproduced",
            "process_attributed",
            "security_impact_established",
            "originality_reviewed",
            "private_submission_only",
            "eligible",
        }
    )

    @classmethod
    def from_mapping(cls, raw: object) -> BountyEligibility:
        if not isinstance(raw, Mapping):
            raise ValueError("bounty eligibility must be an object")
        _exact(raw, cls.FIELDS, "bounty eligibility")
        booleans = [
            "target_flag_present",
            "public_scope_current",
            "current_supported_build",
            "target_only_reproduced",
            "process_attributed",
            "security_impact_established",
            "originality_reviewed",
            "private_submission_only",
            "eligible",
        ]
        if any(not isinstance(raw[name], bool) for name in booleans):
            raise ValueError("bounty eligibility gates must be booleans")
        status = _text(raw["status"], "bounty eligibility status")
        if status != "UNASSESSED" or raw["eligible"] is not False:
            raise ValueError(
                "execution evidence cannot claim bounty eligibility without signed adjudication"
            )
        if any(
            raw[name] is not False
            for name in (
                "current_supported_build",
                "security_impact_established",
                "originality_reviewed",
            )
        ):
            raise ValueError("unsupported bounty gates require separate signed adjudication")
        return cls(
            status=status,
            target_flag_present=bool(raw["target_flag_present"]),
            public_scope_current=bool(raw["public_scope_current"]),
            current_supported_build=bool(raw["current_supported_build"]),
            target_only_reproduced=bool(raw["target_only_reproduced"]),
            process_attributed=bool(raw["process_attributed"]),
            security_impact_established=bool(raw["security_impact_established"]),
            originality_reviewed=bool(raw["originality_reviewed"]),
            private_submission_only=bool(raw["private_submission_only"]),
            eligible=False,
        )


@dataclass(frozen=True)
class MachOCampaignReceipt:
    schema_version: str
    campaign_id: str
    campaign_sha256: str
    worker_acceptance_sha256: str
    coordinator: str
    worker: str
    hardware_model: str
    authorization_kind: str
    input: EvidenceArtifact
    started_at: str
    finished_at: str
    classification: str
    target_observation: ReplayObservation
    control_observation: ReplayObservation
    artifacts: tuple[EvidenceArtifact, ...]
    bounty_eligibility: BountyEligibility
    operational_maturity_claimed: bool
    auto_disclosure: bool

    FIELDS = frozenset(
        {
            "schema_version",
            "campaign_id",
            "campaign_sha256",
            "worker_acceptance_sha256",
            "coordinator",
            "worker",
            "hardware_model",
            "authorization_kind",
            "input",
            "started_at",
            "finished_at",
            "classification",
            "target_observation",
            "control_observation",
            "artifacts",
            "bounty_eligibility",
            "operational_maturity_claimed",
            "auto_disclosure",
        }
    )

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> MachOCampaignReceipt:
        _exact(raw, cls.FIELDS, "Mach-O campaign receipt")
        if raw["schema_version"] != RECEIPT_SCHEMA_VERSION:
            raise ValueError("unsupported Mach-O receipt schema")
        target = ReplayObservation.from_mapping(raw["target_observation"], "target")
        control = ReplayObservation.from_mapping(raw["control_observation"], "control")
        outcomes = (target.outcome, control.outcome)
        classification = {
            ("CLEAN", "CLEAN"): "CLEAN",
            ("CRASH", "CLEAN"): "TARGET_ONLY_CRASH",
            ("CLEAN", "CRASH"): "CONTROL_ONLY_CRASH",
            ("CRASH", "CRASH"): "BOTH_CRASH",
        }.get(outcomes, "TIMEOUT" if "TIMEOUT" in outcomes else "ERROR")
        if raw["classification"] != classification or classification not in CLASSIFICATIONS:
            raise ValueError("classification is not derived from target/control outcomes")
        artifacts_raw = raw["artifacts"]
        if not isinstance(artifacts_raw, list) or not artifacts_raw:
            raise ValueError("receipt artifacts must be non-empty")
        if raw["operational_maturity_claimed"] is not False or raw["auto_disclosure"] is not False:
            raise ValueError("receipt cannot claim maturity or authorize disclosure")
        eligibility = BountyEligibility.from_mapping(raw["bounty_eligibility"])
        authorization_kind = _text(raw["authorization_kind"], "authorization_kind")
        if authorization_kind not in AUTHORIZATION_KINDS:
            raise ValueError("unsupported receipt authorization kind")
        if (
            eligibility.public_scope_current
            is not (authorization_kind == "published-bounty")
            or eligibility.target_only_reproduced is not (classification == "TARGET_ONLY_CRASH")
            or eligibility.process_attributed is not True
            or eligibility.private_submission_only is not True
        ):
            raise ValueError("bounty evidence gates contradict the validated receipt")
        if eligibility.target_flag_present is not (target.target_flag_reference is not None):
            raise ValueError("Target Flag gate must match the signed target observation")
        value = cls(
            RECEIPT_SCHEMA_VERSION,
            _identifier(raw["campaign_id"], "campaign_id"),
            _sha(raw["campaign_sha256"], "campaign_sha256"),
            _sha(raw["worker_acceptance_sha256"], "worker_acceptance_sha256"),
            _identifier(raw["coordinator"], "coordinator"),
            _identifier(raw["worker"], "worker"),
            _hardware_model(raw["hardware_model"], "hardware_model"),
            authorization_kind,
            EvidenceArtifact.from_mapping(raw["input"], "input"),
            _text(raw["started_at"], "started_at"),
            _text(raw["finished_at"], "finished_at"),
            classification,
            target,
            control,
            tuple(
                EvidenceArtifact.from_mapping(item, "receipt artifact") for item in artifacts_raw
            ),
            eligibility,
            False,
            False,
        )
        if _timestamp(value.finished_at, "finished_at") < _timestamp(
            value.started_at, "started_at"
        ):
            raise ValueError("receipt time window is inverted")
        return value

    def require_binding(
        self,
        campaign: MachOCampaign,
        campaign_sha: str,
        accepted: DarwinWorkerAcceptance,
        acceptance_sha: str,
    ) -> None:
        if (
            self.campaign_id,
            self.campaign_sha256,
            self.worker_acceptance_sha256,
            self.coordinator,
            self.worker,
            self.hardware_model,
            self.authorization_kind,
        ) != (
            campaign.campaign_id,
            campaign_sha,
            acceptance_sha,
            campaign.coordinator,
            campaign.worker,
            campaign.hardware_model,
            campaign.authorization.kind,
        ):
            raise ValueError("receipt is not bound to campaign and worker")
        self.target_observation.require_binding(
            campaign, campaign_sha, acceptance_sha, self.input.sha256
        )
        self.control_observation.require_binding(
            campaign, campaign_sha, acceptance_sha, self.input.sha256
        )
        if self.target_observation.replay_index != self.control_observation.replay_index:
            raise ValueError("target/control replay indices must match")
        start, finish = (
            _timestamp(self.started_at, "started_at"),
            _timestamp(self.finished_at, "finished_at"),
        )
        accepted_at, accepted_until = (
            _timestamp(accepted.accepted_at, "accepted_at"),
            _timestamp(accepted.expires_at, "expires_at"),
        )
        authorized_at, authorized_until = (
            _timestamp(campaign.authorization.scope_checked_at, "scope_checked_at"),
            _timestamp(campaign.authorization.expires_at, "expires_at"),
        )
        if start < max(accepted_at, authorized_at) or finish > min(
            accepted_until, authorized_until
        ):
            raise ValueError("receipt execution lies outside authorization/acceptance windows")
        for observation in (self.target_observation, self.control_observation):
            if (
                _timestamp(observation.started_at, "observation started_at") < start
                or _timestamp(observation.finished_at, "observation finished_at") > finish
            ):
                raise ValueError("observation lies outside receipt window")


def _verify_artifact(root: Path, artifact: EvidenceArtifact) -> None:
    digest, size = _identity(root / artifact.path, "Mach-O evidence artifact")
    if digest != artifact.sha256 or size != artifact.size:
        raise ValueError(f"Mach-O evidence artifact differs: {artifact.path}")


def load_campaign(
    path: str | Path,
    *,
    now: datetime | None = None,
) -> tuple[MachOCampaign, str, DarwinWorkerAcceptance, str]:
    _require_fixed_ssh_keygen()
    campaign_path = Path(path)
    raw, campaign_sha = _json(campaign_path, "Mach-O campaign")
    campaign = MachOCampaign.from_mapping(raw, now)
    authorization_policy, authorization_key, authorization_fixture = _trusted_policy(
        "authorization"
    )
    acceptance_policy, acceptance_key, acceptance_fixture = _trusted_policy("acceptance")
    if authorization_key == acceptance_key:
        raise ValueError("Mach-O authorization and acceptance require separate SSH authority keys")
    if campaign.authorization.authority_key_sha256 != authorization_key:
        raise ValueError("Mach-O authorization is not bound to its SSH authority key")
    authorization_raw = raw["authorization"]
    assert isinstance(authorization_raw, Mapping)
    _verify(
        authorization_raw,
        campaign.authorization.authorized_by,
        AUTHORIZATION_SIGNATURE_NAMESPACE,
        authorization_policy,
        authorization_fixture,
        "Mach-O authorization",
    )
    _verify_artifact(campaign_path.parent, campaign.authorization.scope_evidence)
    acceptance_path = campaign_path.parent / campaign.worker_acceptance_path
    accepted_raw, acceptance_sha = _json(acceptance_path, "Darwin worker acceptance")
    if acceptance_sha != campaign.worker_acceptance_sha256:
        raise ValueError("Darwin worker acceptance SHA-256 differs")
    accepted = DarwinWorkerAcceptance.from_mapping(accepted_raw, now)
    accepted.require_binding(campaign)
    if accepted.authority_key_sha256 != acceptance_key:
        raise ValueError("Darwin worker acceptance is not bound to its SSH authority key")
    if len(
        {
            campaign.coordinator,
            campaign.worker,
            campaign.authorization.authorized_by,
            accepted.accepted_by,
        }
    ) != 4:
        raise ValueError(
            "coordinator, worker, authorization, and acceptance identities must differ"
        )
    _require_fixture_identities(
        campaign.coordinator,
        campaign.worker,
        campaign.authorization.authorized_by,
        accepted.accepted_by,
    )
    _verify(
        accepted_raw,
        accepted.accepted_by,
        ACCEPTANCE_SIGNATURE_NAMESPACE,
        acceptance_policy,
        acceptance_fixture,
        "Darwin worker acceptance",
    )
    return campaign, campaign_sha, accepted, acceptance_sha


def load_receipt(
    path: str | Path,
    campaign: MachOCampaign,
    campaign_sha: str,
    accepted: DarwinWorkerAcceptance,
    acceptance_sha: str,
) -> tuple[MachOCampaignReceipt, str]:
    _require_fixed_ssh_keygen()
    receipt_path = Path(path)
    raw, receipt_sha = _json(receipt_path, "Mach-O campaign receipt")
    receipt = MachOCampaignReceipt.from_mapping(raw)
    receipt.require_binding(campaign, campaign_sha, accepted, acceptance_sha)
    target_policy, target_key, target_fixture = _trusted_policy("target")
    control_policy, control_key, control_fixture = _trusted_policy("control")
    if target_key == control_key:
        raise ValueError("Mach-O target/control observations require separate SSH authority keys")
    identities = {
        campaign.coordinator,
        campaign.worker,
        campaign.authorization.authorized_by,
        accepted.accepted_by,
        receipt.target_observation.observed_by,
        receipt.control_observation.observed_by,
    }
    if len(identities) != 6:
        raise ValueError("all Mach-O coordinator, worker, and signer identities must differ")
    _require_fixture_identities(*identities)
    commitments = {
        campaign.authorization.authority_key_sha256,
        accepted.authority_key_sha256,
        receipt.target_observation.authority_key_sha256,
        receipt.control_observation.authority_key_sha256,
    }
    if len(commitments) != 4:
        raise ValueError("all Mach-O signing authority keys must differ")
    if receipt.target_observation.authority_key_sha256 != target_key:
        raise ValueError("target observation is not bound to its SSH authority key")
    if receipt.control_observation.authority_key_sha256 != control_key:
        raise ValueError("control observation is not bound to its SSH authority key")
    target_raw = raw["target_observation"]
    control_raw = raw["control_observation"]
    assert isinstance(target_raw, Mapping) and isinstance(control_raw, Mapping)
    _verify(
        target_raw,
        receipt.target_observation.observed_by,
        TARGET_OBSERVATION_SIGNATURE_NAMESPACE,
        target_policy,
        target_fixture,
        "Mach-O target observation",
    )
    _verify(
        control_raw,
        receipt.control_observation.observed_by,
        CONTROL_OBSERVATION_SIGNATURE_NAMESPACE,
        control_policy,
        control_fixture,
        "Mach-O control observation",
    )
    artifacts = [receipt.input, *receipt.artifacts]
    if receipt.target_observation.target_flag_reference is not None:
        artifacts.append(receipt.target_observation.target_flag_reference)
    for observation in (receipt.target_observation, receipt.control_observation):
        artifacts.extend(observation.evidence)
        artifacts.append(observation.process.evidence)
        if observation.crash_log is not None:
            artifacts.append(observation.crash_log)
        if observation.sysdiagnose is not None:
            artifacts.append(observation.sysdiagnose)
    paths = [artifact.path for artifact in artifacts]
    if len(paths) != len(set(paths)):
        raise ValueError("Mach-O receipt artifact paths must be unique")
    for artifact in artifacts:
        _verify_artifact(receipt_path.parent, artifact)
    return receipt, receipt_sha
