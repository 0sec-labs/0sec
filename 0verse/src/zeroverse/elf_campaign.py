"""Fail-closed campaign contracts for authorized Linux ELF research.

This module deliberately does not execute a target.  It validates the immutable
inputs needed before a future worker adapter may do so: current authorization,
exact target/control identities, a separately hashed worker acceptance, declared
execution/oracle modes, and hash-bound evidence receipts.
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

from .ssh_authority_commitment import ssh_authority_key_commitment
from .ssh_authorization import canonical_signed_material, verify_ssh_signature

CAMPAIGN_SCHEMA_VERSION = "0verse.elf-campaign/v1"
ACCEPTANCE_SCHEMA_VERSION = "0verse.elf-worker-acceptance/v1"
RECEIPT_SCHEMA_VERSION = "0verse.elf-campaign-receipt/v1"

AUTHORIZATION_SIGNATURE_NAMESPACE = "0verse-elf-authorization-v1"
ACCEPTANCE_SIGNATURE_NAMESPACE = "0verse-elf-worker-acceptance-v1"
TARGET_RECEIPT_SIGNATURE_NAMESPACE = "0verse-elf-target-observation-v1"
CONTROL_RECEIPT_SIGNATURE_NAMESPACE = "0verse-elf-control-observation-v1"
DEFAULT_AUTHORIZATION_ALLOWED_SIGNERS = Path("/etc/0verse/elf-authorization.allowed_signers")
DEFAULT_ACCEPTANCE_ALLOWED_SIGNERS = Path("/etc/0verse/elf-worker-acceptance.allowed_signers")
DEFAULT_TARGET_RECEIPT_ALLOWED_SIGNERS = Path("/etc/0verse/elf-target-observation.allowed_signers")
DEFAULT_CONTROL_RECEIPT_ALLOWED_SIGNERS = Path(
    "/etc/0verse/elf-control-observation.allowed_signers"
)

EXECUTION_MODES = frozenset({"native", "qemu-user"})
ORACLES = frozenset(
    {
        "asan",
        "msan",
        "ubsan",
        "native-signal",
        "differential-allocator",
        "exec-trap",
        "casr",
    }
)
AUTHORIZATION_KINDS = frozenset({"owned-lab", "published-bounty", "written-authorization"})
CLASSIFICATIONS = frozenset(
    {
        "CLEAN",
        "TARGET_ONLY_CRASH",
        "CONTROL_ONLY_CRASH",
        "BOTH_CRASH",
        "ERROR",
        "TIMEOUT",
    }
)
OBSERVATION_OUTCOMES = frozenset({"CLEAN", "CRASH", "ERROR", "TIMEOUT"})

_DIGEST = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
_RFC3339_DATE_TIME = re.compile(
    r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"[Tt](?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.[0-9]+)?(?:[Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)
_MAX_JSON_BYTES = 1024 * 1024
_AUTHORIZATION_MAX_AGE = timedelta(days=30)
_ACCEPTANCE_MAX_AGE = timedelta(days=7)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _open_regular_nofollow(path: Path, label: str) -> tuple[int, int]:
    """Open one regular inode without following it or any parent symlink."""
    absolute = path.absolute()
    parts = absolute.parts
    directory_fd = os.open(
        parts[0], os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    )
    file_fd = -1
    try:
        for component in parts[1:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(
            parts[-1],
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory_fd,
        )
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{label} must be a regular non-symlink file")
        result = file_fd
        file_fd = -1
        return result, metadata.st_size
    except OSError as exc:
        raise ValueError(f"{label} must be a regular non-symlink file") from exc
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        os.close(directory_fd)


def _read_regular_nofollow(path: Path, label: str, *, maximum: int | None = None) -> bytes:
    file_fd, size = _open_regular_nofollow(path, label)
    try:
        if maximum is not None and (size < 2 or size > maximum):
            raise ValueError(f"{label} must be a bounded JSON document")
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = os.read(file_fd, min(1024 * 1024, remaining))
            if not chunk:
                raise ValueError(f"{label} changed while it was read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(file_fd, 1):
            raise ValueError(f"{label} changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(file_fd)


def _read_json(path: Path, label: str) -> tuple[dict[str, object], str]:
    data = _read_regular_nofollow(path, label, maximum=_MAX_JSON_BYTES)
    try:
        raw = json.loads(data, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"{label} must be a JSON object")
    return raw, hashlib.sha256(data).hexdigest()


def _file_identity(path: Path) -> tuple[str, int]:
    file_fd, size = _open_regular_nofollow(path, "ELF receipt artifact")
    digest = hashlib.sha256()
    observed = 0
    try:
        while True:
            chunk = os.read(file_fd, 1024 * 1024)
            if not chunk:
                break
            observed += len(chunk)
            digest.update(chunk)
    finally:
        os.close(file_fd)
    if observed != size:
        raise ValueError("ELF receipt artifact changed while it was hashed")
    return digest.hexdigest(), observed


def _policy(path: str | Path | None, default: Path) -> tuple[Path, bool]:
    return (Path(path), False) if path is not None else (default, True)


def _verify_signed(
    raw: Mapping[str, object],
    *,
    identity: str,
    namespace: str,
    policy: Path,
    require_trusted: bool,
    label: str,
    ssh_keygen: str | Path,
) -> None:
    signature = raw.get("signature_ssh")
    if not isinstance(signature, str):
        raise ValueError(f"{label} signature_ssh must be a string")
    verify_ssh_signature(
        canonical_signed_material(raw),
        signature,
        identity=identity,
        namespace=namespace,
        allowed_signers=policy,
        label=label,
        require_trusted_policy=require_trusted,
        ssh_keygen=ssh_keygen,
    )


def _exact_fields(raw: Mapping[str, object], expected: frozenset[str], label: str) -> None:
    missing = sorted(expected - raw.keys())
    extra = sorted(raw.keys() - expected)
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing: {', '.join(missing)}")
        if extra:
            details.append(f"unexpected: {', '.join(extra)}")
        raise ValueError(f"{label} must contain the exact fields ({'; '.join(details)})")


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ValueError(f"{name} must be a non-empty string without NUL bytes")
    return value


def _digest(value: object, name: str) -> str:
    result = _text(value, name)
    if _DIGEST.fullmatch(result) is None or result == "0" * 64:
        raise ValueError(f"{name} must be a nonzero lowercase SHA-256 digest")
    return result


def _identifier(value: object, name: str) -> str:
    result = _text(value, name)
    if _IDENTIFIER.fullmatch(result) is None:
        raise ValueError(f"{name} is not a valid identifier")
    return result


def _timestamp(value: object, name: str) -> datetime:
    text = _text(value, name)
    if _RFC3339_DATE_TIME.fullmatch(text) is None:
        raise ValueError(f"{name} must be RFC3339 date-time")
    normalized = text.replace("t", "T")
    if normalized.endswith(("Z", "z")):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{name} must be RFC3339 date-time") from exc
    return parsed.astimezone(UTC)


def _string_sequence(value: object, name: str) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(f"{name} must be an array of strings")
    result = tuple(_text(item, f"{name} item") for item in value)
    if not result or len(set(result)) != len(result):
        raise ValueError(f"{name} must be a non-empty array of unique strings")
    return result


def _relative_path(value: object, name: str) -> str:
    result = _text(value, name)
    path = PurePosixPath(result)
    if (
        path.is_absolute()
        or result in {".", ".."}
        or ".." in path.parts
        or result != path.as_posix()
    ):
        raise ValueError(f"{name} must be a canonical bundle-relative path without traversal")
    return result


@dataclass(frozen=True)
class ElfArtifactIdentity:
    path: str
    sha256: str

    _FIELDS = frozenset({"path", "sha256"})

    @classmethod
    def from_mapping(cls, raw: object, name: str) -> ElfArtifactIdentity:
        if not isinstance(raw, Mapping):
            raise ValueError(f"{name} must be a JSON object")
        _exact_fields(raw, cls._FIELDS, name)
        path = _text(raw["path"], f"{name}.path")
        if not PurePosixPath(path).is_absolute():
            raise ValueError(f"{name}.path must be absolute on the worker")
        return cls(path=path, sha256=_digest(raw["sha256"], f"{name}.sha256"))


@dataclass(frozen=True)
class ElfAuthorization:
    campaign_id: str
    target_sha256: str
    control_sha256: str
    worker: str
    execution_mode: str
    oracles: tuple[str, ...]
    kind: str
    reference: str
    statement: str
    checked_at: str
    expires_at: str
    authorized_by: str
    signature_ssh: str

    _FIELDS = frozenset(
        {
            "campaign_id",
            "target_sha256",
            "control_sha256",
            "worker",
            "execution_mode",
            "oracles",
            "kind",
            "reference",
            "statement",
            "checked_at",
            "expires_at",
            "authorized_by",
            "signature_ssh",
        }
    )

    @classmethod
    def from_mapping(cls, raw: object, *, now: datetime | None = None) -> ElfAuthorization:
        if not isinstance(raw, Mapping):
            raise ValueError("authorization must be a JSON object")
        _exact_fields(raw, cls._FIELDS, "authorization")
        authorization = cls(
            campaign_id=_identifier(raw["campaign_id"], "authorization.campaign_id"),
            target_sha256=_digest(raw["target_sha256"], "authorization.target_sha256"),
            control_sha256=_digest(raw["control_sha256"], "authorization.control_sha256"),
            worker=_identifier(raw["worker"], "authorization.worker"),
            execution_mode=_text(raw["execution_mode"], "authorization.execution_mode"),
            oracles=_string_sequence(raw["oracles"], "authorization.oracles"),
            kind=_text(raw["kind"], "authorization.kind"),
            reference=_text(raw["reference"], "authorization.reference"),
            statement=_text(raw["statement"], "authorization.statement"),
            checked_at=_text(raw["checked_at"], "authorization.checked_at"),
            expires_at=_text(raw["expires_at"], "authorization.expires_at"),
            authorized_by=_identifier(raw["authorized_by"], "authorization.authorized_by"),
            signature_ssh=_text(raw["signature_ssh"], "authorization.signature_ssh"),
        )
        authorization.validate(now=now)
        return authorization

    def validate(self, *, now: datetime | None = None) -> None:
        if self.kind not in AUTHORIZATION_KINDS:
            raise ValueError(f"unsupported ELF authorization kind: {self.kind}")
        if self.kind == "published-bounty" and not self.reference.startswith("https://"):
            raise ValueError("published bounty authorization requires an https reference")
        checked = _timestamp(self.checked_at, "authorization.checked_at")
        expires = _timestamp(self.expires_at, "authorization.expires_at")
        current = (now or datetime.now(UTC)).astimezone(UTC)
        if checked > current or current - checked > _AUTHORIZATION_MAX_AGE:
            raise ValueError("ELF authorization check must be no more than 30 days old")
        if expires <= current or expires <= checked:
            raise ValueError("ELF authorization has expired or has an invalid validity window")

    def require_binding(self, campaign: ElfCampaign) -> None:
        if (
            self.campaign_id != campaign.campaign_id
            or self.target_sha256 != campaign.target.sha256
            or self.control_sha256 != campaign.control.sha256
            or self.worker != campaign.worker
            or self.execution_mode != campaign.execution_mode
            or self.oracles != campaign.oracles
        ):
            raise ValueError("ELF signed authorization is not bound to the campaign")


@dataclass(frozen=True)
class ElfCampaign:
    campaign_id: str
    target: ElfArtifactIdentity
    control: ElfArtifactIdentity
    worker: str
    worker_acceptance_path: str
    worker_acceptance_sha256: str
    execution_mode: str
    oracles: tuple[str, ...]
    authorization: ElfAuthorization
    schema_version: str = CAMPAIGN_SCHEMA_VERSION

    _FIELDS = frozenset(
        {
            "schema_version",
            "campaign_id",
            "target",
            "control",
            "worker",
            "worker_acceptance_path",
            "worker_acceptance_sha256",
            "execution_mode",
            "oracles",
            "authorization",
        }
    )

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object], *, now: datetime | None = None) -> ElfCampaign:
        _exact_fields(raw, cls._FIELDS, "ELF campaign manifest")
        campaign = cls(
            schema_version=_text(raw["schema_version"], "schema_version"),
            campaign_id=_identifier(raw["campaign_id"], "campaign_id"),
            target=ElfArtifactIdentity.from_mapping(raw["target"], "target"),
            control=ElfArtifactIdentity.from_mapping(raw["control"], "control"),
            worker=_identifier(raw["worker"], "worker"),
            worker_acceptance_path=_relative_path(
                raw["worker_acceptance_path"], "worker_acceptance_path"
            ),
            worker_acceptance_sha256=_digest(
                raw["worker_acceptance_sha256"], "worker_acceptance_sha256"
            ),
            execution_mode=_text(raw["execution_mode"], "execution_mode"),
            oracles=_string_sequence(raw["oracles"], "oracles"),
            authorization=ElfAuthorization.from_mapping(raw["authorization"], now=now),
        )
        campaign.validate(now=now)
        return campaign

    def validate(self, *, now: datetime | None = None) -> None:
        if self.schema_version != CAMPAIGN_SCHEMA_VERSION:
            raise ValueError(f"unsupported ELF campaign schema: {self.schema_version}")
        if self.execution_mode not in EXECUTION_MODES:
            raise ValueError(f"unsupported ELF execution mode: {self.execution_mode}")
        unsupported = sorted(set(self.oracles) - ORACLES)
        if unsupported:
            raise ValueError(f"unsupported ELF oracle: {', '.join(unsupported)}")
        if self.target.path == self.control.path:
            raise ValueError("ELF target and control paths must differ")
        if self.target.sha256 == self.control.sha256:
            raise ValueError("ELF target and control SHA-256 digests must differ")
        self.authorization.validate(now=now)
        self.authorization.require_binding(self)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ElfWorkerAcceptance:
    acceptance_id: str
    campaign_id: str
    worker: str
    target_sha256: str
    control_sha256: str
    execution_mode: str
    oracles: tuple[str, ...]
    accepted_at: str
    expires_at: str
    statement: str
    accepted_by: str
    signature_ssh: str
    schema_version: str = ACCEPTANCE_SCHEMA_VERSION

    _FIELDS = frozenset(
        {
            "schema_version",
            "acceptance_id",
            "campaign_id",
            "worker",
            "target_sha256",
            "control_sha256",
            "execution_mode",
            "oracles",
            "accepted_at",
            "expires_at",
            "statement",
            "accepted_by",
            "signature_ssh",
        }
    )

    @classmethod
    def from_mapping(
        cls, raw: Mapping[str, object], *, now: datetime | None = None
    ) -> ElfWorkerAcceptance:
        _exact_fields(raw, cls._FIELDS, "ELF worker acceptance")
        acceptance = cls(
            schema_version=_text(raw["schema_version"], "schema_version"),
            acceptance_id=_identifier(raw["acceptance_id"], "acceptance_id"),
            campaign_id=_identifier(raw["campaign_id"], "campaign_id"),
            worker=_identifier(raw["worker"], "worker"),
            target_sha256=_digest(raw["target_sha256"], "target_sha256"),
            control_sha256=_digest(raw["control_sha256"], "control_sha256"),
            execution_mode=_text(raw["execution_mode"], "execution_mode"),
            oracles=_string_sequence(raw["oracles"], "oracles"),
            accepted_at=_text(raw["accepted_at"], "accepted_at"),
            expires_at=_text(raw["expires_at"], "expires_at"),
            statement=_text(raw["statement"], "statement"),
            accepted_by=_identifier(raw["accepted_by"], "accepted_by"),
            signature_ssh=_text(raw["signature_ssh"], "signature_ssh"),
        )
        acceptance.validate(now=now)
        return acceptance

    def validate(self, *, now: datetime | None = None) -> None:
        if self.schema_version != ACCEPTANCE_SCHEMA_VERSION:
            raise ValueError(f"unsupported ELF worker acceptance schema: {self.schema_version}")
        if self.execution_mode not in EXECUTION_MODES:
            raise ValueError(f"unsupported ELF execution mode: {self.execution_mode}")
        unsupported = sorted(set(self.oracles) - ORACLES)
        if unsupported:
            raise ValueError(f"unsupported ELF oracle: {', '.join(unsupported)}")
        accepted = _timestamp(self.accepted_at, "accepted_at")
        expires = _timestamp(self.expires_at, "expires_at")
        current = (now or datetime.now(UTC)).astimezone(UTC)
        if accepted > current or current - accepted > _ACCEPTANCE_MAX_AGE:
            raise ValueError("ELF worker acceptance must be no more than 7 days old")
        if expires <= current or expires <= accepted:
            raise ValueError("ELF worker acceptance has expired or has an invalid window")

    def require_binding(self, campaign: ElfCampaign) -> None:
        if (
            self.campaign_id != campaign.campaign_id
            or self.worker != campaign.worker
            or self.target_sha256 != campaign.target.sha256
            or self.control_sha256 != campaign.control.sha256
            or self.execution_mode != campaign.execution_mode
            or self.oracles != campaign.oracles
        ):
            raise ValueError("ELF worker acceptance is not bound to the campaign")


@dataclass(frozen=True)
class ElfReceiptArtifact:
    path: str
    sha256: str
    size: int

    _FIELDS = frozenset({"path", "sha256", "size"})

    @classmethod
    def from_mapping(cls, raw: object) -> ElfReceiptArtifact:
        if not isinstance(raw, Mapping):
            raise ValueError("receipt artifact must be a JSON object")
        _exact_fields(raw, cls._FIELDS, "receipt artifact")
        size = raw["size"]
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ValueError("receipt artifact size must be a non-negative integer")
        return cls(
            path=_relative_path(raw["path"], "receipt artifact path"),
            sha256=_digest(raw["sha256"], "receipt artifact sha256"),
            size=size,
        )


@dataclass(frozen=True)
class ElfExecutionObservation:
    role: str
    campaign_sha256: str
    worker_acceptance_sha256: str
    binary_sha256: str
    input_sha256: str
    outcome: str
    exit_code: int | None
    signal: int | None
    started_at: str
    finished_at: str
    evidence: tuple[ElfReceiptArtifact, ...]
    observed_by: str
    signature_ssh: str

    _FIELDS = frozenset(
        {
            "role",
            "campaign_sha256",
            "worker_acceptance_sha256",
            "binary_sha256",
            "input_sha256",
            "outcome",
            "exit_code",
            "signal",
            "started_at",
            "finished_at",
            "evidence",
            "observed_by",
            "signature_ssh",
        }
    )

    @classmethod
    def from_mapping(cls, raw: object, role: str) -> ElfExecutionObservation:
        if not isinstance(raw, Mapping):
            raise ValueError(f"{role} observation must be a JSON object")
        _exact_fields(raw, cls._FIELDS, f"{role} observation")
        exit_code = raw["exit_code"]
        signal = raw["signal"]
        evidence_raw = raw["evidence"]
        if isinstance(evidence_raw, (str, bytes)) or not isinstance(evidence_raw, Sequence):
            raise ValueError(f"{role} observation evidence must be an array")
        if exit_code is not None and (
            isinstance(exit_code, bool) or not isinstance(exit_code, int)
        ):
            raise ValueError(f"{role} observation exit_code must be an integer or null")
        if signal is not None and (
            isinstance(signal, bool) or not isinstance(signal, int) or not 1 <= signal <= 255
        ):
            raise ValueError(f"{role} observation signal must be 1..255 or null")
        observation = cls(
            role=_text(raw["role"], f"{role} observation role"),
            campaign_sha256=_digest(raw["campaign_sha256"], "campaign_sha256"),
            worker_acceptance_sha256=_digest(
                raw["worker_acceptance_sha256"], "worker_acceptance_sha256"
            ),
            binary_sha256=_digest(raw["binary_sha256"], "binary_sha256"),
            input_sha256=_digest(raw["input_sha256"], "input_sha256"),
            outcome=_text(raw["outcome"], "outcome"),
            exit_code=exit_code,
            signal=signal,
            started_at=_text(raw["started_at"], "started_at"),
            finished_at=_text(raw["finished_at"], "finished_at"),
            evidence=tuple(ElfReceiptArtifact.from_mapping(item) for item in evidence_raw),
            observed_by=_identifier(raw["observed_by"], "observed_by"),
            signature_ssh=_text(raw["signature_ssh"], "signature_ssh"),
        )
        if observation.role != role or observation.outcome not in OBSERVATION_OUTCOMES:
            raise ValueError(f"{role} observation role or outcome is unsupported")
        if observation.outcome == "CRASH":
            if observation.signal is None or observation.exit_code is not None:
                raise ValueError(f"{role} crash observation requires only signal")
        elif observation.outcome == "CLEAN":
            if observation.exit_code != 0 or observation.signal is not None:
                raise ValueError(f"{role} clean observation requires exit_code 0 and no signal")
        elif observation.signal is not None:
            raise ValueError(f"{role} non-crash observation cannot carry a signal")
        evidence_paths = [artifact.path for artifact in observation.evidence]
        if len(evidence_paths) != len(set(evidence_paths)):
            raise ValueError(f"{role} observation evidence paths must be unique")
        if _timestamp(observation.finished_at, "finished_at") < _timestamp(
            observation.started_at, "started_at"
        ):
            raise ValueError(f"{role} observation finished_at precedes started_at")
        return observation

    def require_binding(
        self,
        campaign: ElfCampaign,
        campaign_sha256: str,
        acceptance_sha256: str,
        input_sha256: str,
    ) -> None:
        expected_binary = (
            campaign.target.sha256 if self.role == "target" else campaign.control.sha256
        )
        if (
            self.campaign_sha256 != campaign_sha256
            or self.worker_acceptance_sha256 != acceptance_sha256
            or self.binary_sha256 != expected_binary
            or self.input_sha256 != input_sha256
        ):
            raise ValueError(f"ELF {self.role} observation is not input/campaign bound")


def _derive_classification(target: str, control: str) -> str:
    if "TIMEOUT" in {target, control}:
        return "TIMEOUT"
    if "ERROR" in {target, control}:
        return "ERROR"
    if target == "CRASH" and control == "CLEAN":
        return "TARGET_ONLY_CRASH"
    if target == "CLEAN" and control == "CRASH":
        return "CONTROL_ONLY_CRASH"
    if target == control == "CRASH":
        return "BOTH_CRASH"
    return "CLEAN"


@dataclass(frozen=True)
class ElfCampaignReceipt:
    campaign_id: str
    campaign_sha256: str
    worker_acceptance_sha256: str
    worker: str
    target_sha256: str
    control_sha256: str
    input: ElfReceiptArtifact
    execution_mode: str
    oracles: tuple[str, ...]
    started_at: str
    finished_at: str
    classification: str
    target_observation: ElfExecutionObservation
    control_observation: ElfExecutionObservation
    artifacts: tuple[ElfReceiptArtifact, ...]
    claim_eligible: bool
    auto_disclosure: bool
    schema_version: str = RECEIPT_SCHEMA_VERSION

    _FIELDS = frozenset(
        {
            "schema_version",
            "campaign_id",
            "campaign_sha256",
            "worker_acceptance_sha256",
            "worker",
            "target_sha256",
            "control_sha256",
            "input",
            "execution_mode",
            "oracles",
            "started_at",
            "finished_at",
            "classification",
            "target_observation",
            "control_observation",
            "artifacts",
            "claim_eligible",
            "auto_disclosure",
        }
    )

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> ElfCampaignReceipt:
        _exact_fields(raw, cls._FIELDS, "ELF campaign receipt")
        artifacts_raw = raw["artifacts"]
        if isinstance(artifacts_raw, (str, bytes)) or not isinstance(artifacts_raw, Sequence):
            raise ValueError("receipt artifacts must be an array")
        artifacts = tuple(ElfReceiptArtifact.from_mapping(item) for item in artifacts_raw)
        claim_eligible = raw["claim_eligible"]
        auto_disclosure = raw["auto_disclosure"]
        for name, value in (
            ("claim_eligible", claim_eligible),
            ("auto_disclosure", auto_disclosure),
        ):
            if not isinstance(value, bool):
                raise ValueError(f"{name} must be boolean")
        assert isinstance(claim_eligible, bool)
        assert isinstance(auto_disclosure, bool)
        receipt = cls(
            schema_version=_text(raw["schema_version"], "schema_version"),
            campaign_id=_identifier(raw["campaign_id"], "campaign_id"),
            campaign_sha256=_digest(raw["campaign_sha256"], "campaign_sha256"),
            worker_acceptance_sha256=_digest(
                raw["worker_acceptance_sha256"], "worker_acceptance_sha256"
            ),
            worker=_identifier(raw["worker"], "worker"),
            target_sha256=_digest(raw["target_sha256"], "target_sha256"),
            control_sha256=_digest(raw["control_sha256"], "control_sha256"),
            input=ElfReceiptArtifact.from_mapping(raw["input"]),
            execution_mode=_text(raw["execution_mode"], "execution_mode"),
            oracles=_string_sequence(raw["oracles"], "oracles"),
            started_at=_text(raw["started_at"], "started_at"),
            finished_at=_text(raw["finished_at"], "finished_at"),
            classification=_text(raw["classification"], "classification"),
            target_observation=ElfExecutionObservation.from_mapping(
                raw["target_observation"], "target"
            ),
            control_observation=ElfExecutionObservation.from_mapping(
                raw["control_observation"], "control"
            ),
            artifacts=artifacts,
            claim_eligible=claim_eligible,
            auto_disclosure=auto_disclosure,
        )
        receipt.validate()
        return receipt

    def validate(self) -> None:
        if self.schema_version != RECEIPT_SCHEMA_VERSION:
            raise ValueError(f"unsupported ELF campaign receipt schema: {self.schema_version}")
        if self.execution_mode not in EXECUTION_MODES:
            raise ValueError(f"unsupported ELF execution mode: {self.execution_mode}")
        unsupported = sorted(set(self.oracles) - ORACLES)
        if unsupported:
            raise ValueError(f"unsupported ELF oracle: {', '.join(unsupported)}")
        if self.classification not in CLASSIFICATIONS:
            raise ValueError(f"unsupported ELF receipt classification: {self.classification}")
        derived = _derive_classification(
            self.target_observation.outcome, self.control_observation.outcome
        )
        if self.classification != derived:
            raise ValueError("ELF receipt classification is not derived from typed observations")
        started = _timestamp(self.started_at, "started_at")
        finished = _timestamp(self.finished_at, "finished_at")
        if finished < started:
            raise ValueError("ELF receipt finished_at precedes started_at")
        observation_start = min(
            _timestamp(self.target_observation.started_at, "target started_at"),
            _timestamp(self.control_observation.started_at, "control started_at"),
        )
        observation_finish = max(
            _timestamp(self.target_observation.finished_at, "target finished_at"),
            _timestamp(self.control_observation.finished_at, "control finished_at"),
        )
        if started != observation_start or finished != observation_finish:
            raise ValueError("ELF receipt window is not derived from signed observations")
        if not self.artifacts:
            raise ValueError("ELF receipt requires at least one immutable artifact")
        paths = [artifact.path for artifact in self.artifacts]
        if self.input.path in paths:
            raise ValueError("ELF input path must be distinct from evidence artifact paths")
        if len(paths) != len(set(paths)):
            raise ValueError("ELF receipt artifact paths must be unique")
        signed_artifacts = self.target_observation.evidence + self.control_observation.evidence
        if self.artifacts != signed_artifacts:
            raise ValueError("ELF receipt artifacts are not the signed observation evidence")
        if self.claim_eligible or self.auto_disclosure:
            raise ValueError(
                "ELF integrity receipts cannot claim eligibility or authorize disclosure"
            )

    def require_binding(
        self,
        campaign: ElfCampaign,
        campaign_sha256: str,
        acceptance: ElfWorkerAcceptance,
        acceptance_sha256: str,
    ) -> None:
        if (
            self.campaign_id != campaign.campaign_id
            or self.campaign_sha256 != campaign_sha256
            or self.worker_acceptance_sha256 != acceptance_sha256
            or self.worker != campaign.worker
            or self.target_sha256 != campaign.target.sha256
            or self.control_sha256 != campaign.control.sha256
            or self.execution_mode != campaign.execution_mode
            or self.oracles != campaign.oracles
        ):
            raise ValueError("ELF campaign receipt is not bound to the campaign")
        acceptance.require_binding(campaign)
        self.target_observation.require_binding(
            campaign, campaign_sha256, acceptance_sha256, self.input.sha256
        )
        self.control_observation.require_binding(
            campaign, campaign_sha256, acceptance_sha256, self.input.sha256
        )
        started = _timestamp(self.started_at, "started_at")
        finished = _timestamp(self.finished_at, "finished_at")
        if started < _timestamp(campaign.authorization.checked_at, "authorization.checked_at"):
            raise ValueError("ELF receipt predates authorization")
        if finished > _timestamp(campaign.authorization.expires_at, "authorization.expires_at"):
            raise ValueError("ELF receipt exceeds the authorization window")
        if started < _timestamp(acceptance.accepted_at, "accepted_at"):
            raise ValueError("ELF receipt predates worker acceptance")
        if finished > _timestamp(acceptance.expires_at, "expires_at"):
            raise ValueError("ELF receipt exceeds the worker acceptance window")


def load_campaign(
    path: str | Path,
    *,
    now: datetime | None = None,
    authorization_allowed_signers: str | Path | None = None,
    acceptance_allowed_signers: str | Path | None = None,
    ssh_keygen: str | Path = "ssh-keygen",
) -> tuple[ElfCampaign, str, ElfWorkerAcceptance, str]:
    """Load independently signed scope and worker-acceptance contracts."""
    manifest_path = Path(path)
    raw, campaign_sha256 = _read_json(manifest_path, "ELF campaign manifest")
    campaign = ElfCampaign.from_mapping(raw, now=now)
    authorization_policy, authorization_trusted = _policy(
        authorization_allowed_signers, DEFAULT_AUTHORIZATION_ALLOWED_SIGNERS
    )
    acceptance_policy, acceptance_trusted = _policy(
        acceptance_allowed_signers, DEFAULT_ACCEPTANCE_ALLOWED_SIGNERS
    )
    if authorization_policy.absolute() == acceptance_policy.absolute():
        raise ValueError("ELF authorization and acceptance require separate signer policies")
    if ssh_authority_key_commitment(authorization_policy) == ssh_authority_key_commitment(
        acceptance_policy
    ):
        raise ValueError("ELF authorization and acceptance require separate SSH authority keys")
    authorization_raw = raw["authorization"]
    assert isinstance(authorization_raw, Mapping)
    _verify_signed(
        authorization_raw,
        identity=campaign.authorization.authorized_by,
        namespace=AUTHORIZATION_SIGNATURE_NAMESPACE,
        policy=authorization_policy,
        require_trusted=authorization_trusted,
        label="ELF authorization",
        ssh_keygen=ssh_keygen,
    )
    acceptance_path = manifest_path.parent / campaign.worker_acceptance_path
    acceptance_raw, acceptance_sha256 = _read_json(acceptance_path, "ELF worker acceptance")
    if acceptance_sha256 != campaign.worker_acceptance_sha256:
        raise ValueError("ELF worker acceptance SHA-256 differs from the manifest")
    acceptance = ElfWorkerAcceptance.from_mapping(acceptance_raw, now=now)
    acceptance.require_binding(campaign)
    if acceptance.accepted_by == campaign.authorization.authorized_by:
        raise ValueError("ELF authorization and worker acceptance signer roles must differ")
    _verify_signed(
        acceptance_raw,
        identity=acceptance.accepted_by,
        namespace=ACCEPTANCE_SIGNATURE_NAMESPACE,
        policy=acceptance_policy,
        require_trusted=acceptance_trusted,
        label="ELF worker acceptance",
        ssh_keygen=ssh_keygen,
    )
    return campaign, campaign_sha256, acceptance, acceptance_sha256


def load_receipt(
    path: str | Path,
    campaign: ElfCampaign,
    campaign_sha256: str,
    acceptance: ElfWorkerAcceptance,
    acceptance_sha256: str,
    *,
    target_allowed_signers: str | Path | None = None,
    control_allowed_signers: str | Path | None = None,
    ssh_keygen: str | Path = "ssh-keygen",
) -> tuple[ElfCampaignReceipt, str]:
    """Validate signed typed observations plus exact input/evidence artifacts."""
    receipt_path = Path(path)
    raw, receipt_sha256 = _read_json(receipt_path, "ELF campaign receipt")
    receipt = ElfCampaignReceipt.from_mapping(raw)
    receipt.require_binding(campaign, campaign_sha256, acceptance, acceptance_sha256)
    target_policy, target_trusted = _policy(
        target_allowed_signers, DEFAULT_TARGET_RECEIPT_ALLOWED_SIGNERS
    )
    control_policy, control_trusted = _policy(
        control_allowed_signers, DEFAULT_CONTROL_RECEIPT_ALLOWED_SIGNERS
    )
    if target_policy.absolute() == control_policy.absolute():
        raise ValueError("ELF target and control observations require separate signer policies")
    if ssh_authority_key_commitment(target_policy) == ssh_authority_key_commitment(control_policy):
        raise ValueError("ELF target and control observations require separate SSH authority keys")
    if receipt.target_observation.observed_by == receipt.control_observation.observed_by:
        raise ValueError("ELF target and control observation signer roles must differ")
    for observation, observation_raw, namespace, policy, trusted in (
        (
            receipt.target_observation,
            raw["target_observation"],
            TARGET_RECEIPT_SIGNATURE_NAMESPACE,
            target_policy,
            target_trusted,
        ),
        (
            receipt.control_observation,
            raw["control_observation"],
            CONTROL_RECEIPT_SIGNATURE_NAMESPACE,
            control_policy,
            control_trusted,
        ),
    ):
        assert isinstance(observation_raw, Mapping)
        _verify_signed(
            observation_raw,
            identity=observation.observed_by,
            namespace=namespace,
            policy=policy,
            require_trusted=trusted,
            label=f"ELF {observation.role} observation",
            ssh_keygen=ssh_keygen,
        )
    for artifact in (receipt.input, *receipt.artifacts):
        artifact_path = receipt_path.parent / artifact.path
        digest, size = _file_identity(artifact_path)
        if size != artifact.size:
            raise ValueError(f"ELF receipt artifact size differs: {artifact.path}")
        if digest != artifact.sha256:
            raise ValueError(f"ELF receipt artifact SHA-256 differs: {artifact.path}")
    return receipt, receipt_sha256
