"""Authorized control-plane contracts for Windows token-transition research.

This module deliberately contains no command runner. It validates the exact
campaign, operator grant, and independent worker acceptance that a future
hash-pinned Windows-native capture helper must consume.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .ssh_authorization import canonical_signed_material, verify_ssh_signature
from .windows_app_container import valid_package_app_container_sid
from .windows_scope import WindowsScope

CAMPAIGN_SCHEMA_VERSION = "0verse.windows-token-campaign/v1"
LPAC_CAMPAIGN_SCHEMA_VERSION = "0verse.windows-token-campaign/v2"
GRANT_SCHEMA_VERSION = "0verse.windows-token-execution-grant/v1"
ACCEPTANCE_SCHEMA_VERSION = "0verse.windows-token-worker-acceptance/v2"
GRANT_SIGNATURE_NAMESPACE = "0verse-windows-token-execution-grant"
ACCEPTANCE_SIGNATURE_NAMESPACE = "0verse-windows-token-worker-acceptance"
DEFAULT_ACCEPTANCE_ALLOWED_SIGNERS = Path(
    "/etc/0verse/windows-token-acceptance.allowed_signers"
)
DEFAULT_GRANT_ALLOWED_SIGNERS = Path("/etc/0verse/windows-token-grant.allowed_signers")

_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_AUTHENTICATION_ID = re.compile(r"^[a-f0-9]{16}$")
_MACHINE_GUID = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)
_WORKER_MACHINE_ID_DOMAIN = b"0verse-windows-machine-id-v1\0"
_DENIED_WORKERS = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
    }
)
ELIGIBLE_WINDOWS_SANDBOXES = frozenset(
    {
        "edge-chromium-renderer",
        "windows-defender-msengcp",
        "winhttp-wpad-sandboxed-process",
        "utcdecoderhost-sandboxed-process",
    }
)


def derive_windows_worker_machine_id(machine_guid: str) -> str:
    """Derive the exact opaque machine identity expected by the native broker."""
    if not _MACHINE_GUID.fullmatch(machine_guid):
        raise ValueError("Windows MachineGuid must use canonical UUID text")
    canonical = machine_guid.lower().encode("ascii")
    return hashlib.sha256(_WORKER_MACHINE_ID_DOMAIN + canonical).hexdigest()


def validate_windows_witness_user_sid(value: str) -> None:
    """Require a canonical domain/local account SID, excluding built-in accounts."""
    parts = value.split("-")
    if len(parts) != 8 or parts[:3] != ["S", "1", "5"] or parts[3] != "21":
        raise ValueError("Windows witness user SID must be a canonical account SID")
    numbers = parts[4:]
    if any(
        not part.isascii()
        or not part.isdecimal()
        or (len(part) > 1 and part.startswith("0"))
        or int(part) > 2**32 - 1
        for part in numbers
    ):
        raise ValueError("Windows witness user SID must be a canonical account SID")
    if int(numbers[-1]) < 1000:
        raise ValueError("Windows witness user SID must not name a built-in account")


def _exact(raw: Mapping[str, object], expected: frozenset[str], label: str) -> None:
    missing = sorted(expected - raw.keys())
    unknown = sorted(raw.keys() - expected)
    if missing or unknown:
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if unknown:
            details.append(f"unknown {', '.join(unknown)}")
        raise ValueError(f"{label} fields invalid: {'; '.join(details)}")


def _strings(raw: Mapping[str, object], fields: frozenset[str], label: str) -> None:
    invalid = sorted(name for name in fields if not isinstance(raw[name], str))
    if invalid:
        raise ValueError(f"{label} fields must be strings: {', '.join(invalid)}")


def _bounded_text(value: str, name: str, maximum: int = 256) -> None:
    if (
        not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 0x20 for character in value)
    ):
        raise ValueError(f"{name} must be bounded, non-empty, trimmed text")


def _timestamp(value: str, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{name} must include a timezone")
    return parsed.astimezone(UTC)


def _validate_window(issued_at: str, expires_at: str, label: str) -> None:
    issued = _timestamp(issued_at, f"{label} issued_at")
    expires = _timestamp(expires_at, f"{label} expires_at")
    now = datetime.now(UTC)
    if issued > now + timedelta(minutes=5) or now - issued > timedelta(hours=24):
        raise ValueError(f"{label} issued_at is outside the 24-hour window")
    if expires <= now or expires <= issued:
        raise ValueError(f"{label} has expired or has an invalid interval")
    if expires - issued > timedelta(hours=24):
        raise ValueError(f"{label} lifetime exceeds 24 hours")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_regular_nofollow(path: Path, maximum: int = 4 * 1024 * 1024) -> bytes:
    if path.is_symlink():
        raise ValueError("Windows token control-plane files cannot be symlinks")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise ValueError("Windows token control-plane file must be bounded and regular")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("Windows token control-plane file exceeds the size limit")
        return data
    finally:
        os.close(descriptor)


def _load_object(path: str | Path) -> tuple[dict[str, object], bytes, str]:
    data = _read_regular_nofollow(Path(path))
    raw = json.loads(data, object_pairs_hook=_unique_object)
    if not isinstance(raw, dict):
        raise ValueError("Windows token control-plane file must contain a JSON object")
    return raw, data, hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class WindowsTokenCampaign:
    campaign_id: str
    worker: str
    starting_context: str
    finishing_principal: str
    target_operation_sha256: str
    control_operation_sha256: str
    trials: int
    minimum_confirmations: int
    eligible_sandbox: str = ""
    launch_app_container_executable_sha256: str = ""
    sandbox_process_executable_sha256: str = ""
    app_container_sid: str = ""
    schema_version: str = CAMPAIGN_SCHEMA_VERSION
    _source_material: bytes = field(default=b"", repr=False, compare=False)
    _source_sha256: str = field(default="", repr=False, compare=False)

    _FIELDS = frozenset(
        {
            "schema_version",
            "campaign_id",
            "worker",
            "starting_context",
            "finishing_principal",
            "target_operation_sha256",
            "control_operation_sha256",
            "trials",
            "minimum_confirmations",
        }
    )
    _LPAC_FIELDS = _FIELDS | {
        "eligible_sandbox",
        "launch_app_container_executable_sha256",
        "sandbox_process_executable_sha256",
        "app_container_sid",
    }

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> WindowsTokenCampaign:
        schema = raw.get("schema_version")
        expected = (
            cls._LPAC_FIELDS
            if schema == LPAC_CAMPAIGN_SCHEMA_VERSION
            else cls._FIELDS
        )
        _exact(raw, expected, "Windows token campaign")
        _strings(
            raw,
            expected - {"trials", "minimum_confirmations"},
            "Windows token campaign",
        )
        for name in ("trials", "minimum_confirmations"):
            if isinstance(raw[name], bool) or not isinstance(raw[name], int):
                raise ValueError(f"Windows token campaign {name} must be an integer")
        campaign = cls(**dict(raw))  # type: ignore[arg-type]
        campaign.validate()
        return campaign

    def validate(self) -> None:
        if self.schema_version not in {
            CAMPAIGN_SCHEMA_VERSION,
            LPAC_CAMPAIGN_SCHEMA_VERSION,
        }:
            raise ValueError(f"unsupported Windows token campaign schema: {self.schema_version}")
        if not _IDENTIFIER.fullmatch(self.campaign_id):
            raise ValueError("Windows token campaign_id is invalid")
        if not _HOST.fullmatch(self.worker) or self.worker.lower() in _DENIED_WORKERS:
            raise ValueError("Windows token worker is invalid or denied")
        if self.starting_context not in {"standard-user", "appcontainer", "eligible-sandbox"}:
            raise ValueError("Windows token starting_context is unsupported")
        if self.schema_version == CAMPAIGN_SCHEMA_VERSION and (
            self.starting_context == "eligible-sandbox"
            or self.eligible_sandbox
            or self.launch_app_container_executable_sha256
            or self.sandbox_process_executable_sha256
            or self.app_container_sid
        ):
            raise ValueError("eligible-sandbox campaigns require Windows token campaign v2")
        if self.schema_version == LPAC_CAMPAIGN_SCHEMA_VERSION:
            if (
                self.starting_context != "eligible-sandbox"
                or self.eligible_sandbox not in ELIGIBLE_WINDOWS_SANDBOXES
            ):
                raise ValueError(
                    "Windows token campaign v2 requires an exact eligible sandbox"
                )
            if (
                _SHA256.fullmatch(self.launch_app_container_executable_sha256) is None
                or _SHA256.fullmatch(self.sandbox_process_executable_sha256) is None
            ):
                raise ValueError(
                    "Windows token campaign v2 requires exact executable digests"
                )
            if not valid_package_app_container_sid(self.app_container_sid):
                raise ValueError(
                    "Windows token campaign v2 requires an exact package AppContainer SID"
                )
        if self.finishing_principal not in {"elevated-user", "local-system"}:
            raise ValueError("Windows token finishing_principal is unsupported")
        for name in ("target_operation_sha256", "control_operation_sha256"):
            if not _SHA256.fullmatch(getattr(self, name)):
                raise ValueError(f"Windows token campaign {name} must be a lowercase SHA-256")
        if self.target_operation_sha256 == self.control_operation_sha256:
            raise ValueError("target and control operation digests must differ")
        if not 2 <= self.trials <= 32:
            raise ValueError("Windows token trials must be between 2 and 32")
        if not 2 <= self.minimum_confirmations <= self.trials:
            raise ValueError("minimum_confirmations must be between 2 and trials")

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload.pop("_source_material")
        payload.pop("_source_sha256")
        if self.schema_version == CAMPAIGN_SCHEMA_VERSION:
            payload.pop("eligible_sandbox")
            payload.pop("launch_app_container_executable_sha256")
            payload.pop("sandbox_process_executable_sha256")
            payload.pop("app_container_sid")
        return payload

    def require_source_binding(self, source_sha256: str) -> None:
        self.validate()
        if (
            not self._source_material
            or not self._source_sha256
            or hashlib.sha256(self._source_material).hexdigest() != self._source_sha256
            or source_sha256 != self._source_sha256
        ):
            raise ValueError("Windows token campaign differs from its loaded source file")
        raw = json.loads(self._source_material, object_pairs_hook=_unique_object)
        if not isinstance(raw, dict) or self != WindowsTokenCampaign.from_mapping(raw):
            raise ValueError("Windows token campaign fields differ from loaded source")


def load_windows_token_campaign(
    path: str | Path,
) -> tuple[WindowsTokenCampaign, str]:
    raw, data, digest = _load_object(path)
    campaign = WindowsTokenCampaign.from_mapping(raw)
    return replace(
        campaign,
        _source_material=data,
        _source_sha256=digest,
    ), digest


@dataclass(frozen=True)
class WindowsTokenExecutionGrant:
    campaign_sha256: str
    scope_manifest_sha256: str
    campaign_id: str
    worker: str
    target_operation_sha256: str
    control_operation_sha256: str
    issued_at: str
    expires_at: str
    nonce: str
    authorized_by: str
    signature_ssh: str
    schema_version: str = GRANT_SCHEMA_VERSION
    _signed_material: bytes = field(default=b"", repr=False, compare=False)
    _allowed_signers: Path | None = field(default=None, repr=False, compare=False)
    _require_trusted_policy: bool = field(default=True, repr=False, compare=False)
    _authorization_verified: bool = field(default=False, repr=False, compare=False)
    _source_material: bytes = field(default=b"", repr=False, compare=False)
    _source_sha256: str = field(default="", repr=False, compare=False)

    _FIELDS = frozenset(
        {
            "schema_version",
            "campaign_sha256",
            "scope_manifest_sha256",
            "campaign_id",
            "worker",
            "target_operation_sha256",
            "control_operation_sha256",
            "issued_at",
            "expires_at",
            "nonce",
            "authorized_by",
            "signature_ssh",
        }
    )

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> WindowsTokenExecutionGrant:
        _exact(raw, cls._FIELDS, "Windows token execution grant")
        _strings(raw, cls._FIELDS, "Windows token execution grant")
        grant = cls(**dict(raw))  # type: ignore[arg-type]
        grant.validate()
        return grant

    def validate(self) -> None:
        if self.schema_version != GRANT_SCHEMA_VERSION:
            raise ValueError(f"unsupported Windows token grant schema: {self.schema_version}")
        for name in (
            "campaign_sha256",
            "scope_manifest_sha256",
            "target_operation_sha256",
            "control_operation_sha256",
        ):
            if not _SHA256.fullmatch(getattr(self, name)):
                raise ValueError(f"Windows token grant {name} must be a lowercase SHA-256")
        if self.target_operation_sha256 == self.control_operation_sha256:
            raise ValueError("Windows token grant operations must differ")
        if not _IDENTIFIER.fullmatch(self.campaign_id):
            raise ValueError("Windows token grant campaign_id is invalid")
        if not _HOST.fullmatch(self.worker) or self.worker.lower() in _DENIED_WORKERS:
            raise ValueError("Windows token grant worker is invalid or denied")
        if not _NONCE.fullmatch(self.nonce):
            raise ValueError("Windows token grant nonce is invalid")
        _bounded_text(self.authorized_by, "Windows token grant authorized_by")
        _validate_window(self.issued_at, self.expires_at, "Windows token grant")
        if not self.signature_ssh:
            raise ValueError("Windows token grant signature_ssh is required")

    def require_signed_authorization(self) -> None:
        self.validate()
        if (
            not self._authorization_verified
            or not self._signed_material
            or self._allowed_signers is None
        ):
            raise ValueError("Windows token execution requires a verified signed grant")
        raw = json.loads(self._signed_material, object_pairs_hook=_unique_object)
        if not isinstance(raw, dict):
            raise ValueError("signed Windows token grant material is malformed")
        raw["signature_ssh"] = self.signature_ssh
        if self != WindowsTokenExecutionGrant.from_mapping(raw):
            raise ValueError("live Windows token grant fields differ from signed material")
        verify_ssh_signature(
            self._signed_material,
            self.signature_ssh,
            identity=self.authorized_by,
            namespace=GRANT_SIGNATURE_NAMESPACE,
            allowed_signers=self._allowed_signers,
            label="Windows token execution grant",
            require_trusted_policy=self._require_trusted_policy,
        )

    def require_source_binding(self, source_sha256: str) -> None:
        self.require_signed_authorization()
        if (
            not self._source_material
            or not self._source_sha256
            or hashlib.sha256(self._source_material).hexdigest() != self._source_sha256
            or source_sha256 != self._source_sha256
        ):
            raise ValueError("Windows token grant SHA-256 differs from loaded source file")
        raw = json.loads(self._source_material, object_pairs_hook=_unique_object)
        if not isinstance(raw, dict) or self != WindowsTokenExecutionGrant.from_mapping(raw):
            raise ValueError("live Windows token grant differs from loaded source file")

    def require_binding(
        self,
        campaign: WindowsTokenCampaign,
        campaign_sha256: str,
        scope: WindowsScope,
        scope_sha256: str,
        grant_sha256: str,
    ) -> None:
        self.require_source_binding(grant_sha256)
        campaign.require_source_binding(campaign_sha256)
        scope.require_source_binding(scope_sha256)
        if scope.program != "windows-canary":
            raise ValueError("Windows token execution requires windows-canary scope")
        if (
            self.campaign_sha256 != campaign_sha256
            or self.scope_manifest_sha256 != scope_sha256
            or self.campaign_id != campaign.campaign_id
            or self.campaign_id != scope.campaign_id
            or self.worker != campaign.worker
            or self.worker != scope.worker
            or self.target_operation_sha256 != campaign.target_operation_sha256
            or self.control_operation_sha256 != campaign.control_operation_sha256
        ):
            raise ValueError("Windows token grant is not bound to campaign and scope")


def load_windows_token_execution_grant(
    path: str | Path,
    *,
    allowed_signers: str | Path | None = None,
    require_authorized: bool = False,
) -> tuple[WindowsTokenExecutionGrant, str]:
    raw, data, digest = _load_object(path)
    grant = WindowsTokenExecutionGrant.from_mapping(raw)
    policy = (
        Path(allowed_signers)
        if allowed_signers is not None
        else DEFAULT_GRANT_ALLOWED_SIGNERS
    )
    require_trusted = allowed_signers is None
    material = canonical_signed_material(raw)
    verify_ssh_signature(
        material,
        grant.signature_ssh,
        identity=grant.authorized_by,
        namespace=GRANT_SIGNATURE_NAMESPACE,
        allowed_signers=policy,
        label="Windows token execution grant",
        require_trusted_policy=require_trusted,
    )
    verified = replace(
        grant,
        _signed_material=material,
        _allowed_signers=policy.expanduser().resolve(),
        _require_trusted_policy=require_trusted,
        _authorization_verified=True,
        _source_material=data,
        _source_sha256=digest,
    )
    if require_authorized:
        verified.require_signed_authorization()
    return verified, digest


@dataclass(frozen=True)
class WindowsTokenWorkerAcceptance:
    campaign_sha256: str
    scope_manifest_sha256: str
    execution_grant_sha256: str
    execution_grant_nonce: str
    campaign_id: str
    worker: str
    build_lab_ex: str
    worker_machine_id: str
    runner_executable_sha256: str
    witness_user_sid: str
    witness_session_id: int
    witness_authentication_id: str
    witness_executable_sha256: str
    target_operation_sha256: str
    control_operation_sha256: str
    issued_at: str
    expires_at: str
    nonce: str
    accepted_by: str
    capture_signer: str
    signature_ssh: str
    schema_version: str = ACCEPTANCE_SCHEMA_VERSION
    _signed_material: bytes = field(default=b"", repr=False, compare=False)
    _allowed_signers: Path | None = field(default=None, repr=False, compare=False)
    _require_trusted_policy: bool = field(default=True, repr=False, compare=False)
    _authorization_verified: bool = field(default=False, repr=False, compare=False)
    _source_material: bytes = field(default=b"", repr=False, compare=False)
    _source_sha256: str = field(default="", repr=False, compare=False)

    _FIELDS = frozenset(
        {
            "schema_version",
            "campaign_sha256",
            "scope_manifest_sha256",
            "execution_grant_sha256",
            "execution_grant_nonce",
            "campaign_id",
            "worker",
            "build_lab_ex",
            "worker_machine_id",
            "runner_executable_sha256",
            "witness_user_sid",
            "witness_session_id",
            "witness_authentication_id",
            "witness_executable_sha256",
            "target_operation_sha256",
            "control_operation_sha256",
            "issued_at",
            "expires_at",
            "nonce",
            "accepted_by",
            "capture_signer",
            "signature_ssh",
        }
    )

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> WindowsTokenWorkerAcceptance:
        _exact(raw, cls._FIELDS, "Windows token worker acceptance")
        _strings(
            raw,
            cls._FIELDS - {"witness_session_id"},
            "Windows token worker acceptance",
        )
        if isinstance(raw["witness_session_id"], bool) or not isinstance(
            raw["witness_session_id"], int
        ):
            raise ValueError("Windows token acceptance witness_session_id must be an integer")
        acceptance = cls(**dict(raw))  # type: ignore[arg-type]
        acceptance.validate()
        return acceptance

    def validate(self) -> None:
        if self.schema_version != ACCEPTANCE_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported Windows token worker acceptance schema: {self.schema_version}"
            )
        for name in (
            "campaign_sha256",
            "scope_manifest_sha256",
            "execution_grant_sha256",
            "runner_executable_sha256",
            "witness_executable_sha256",
            "target_operation_sha256",
            "control_operation_sha256",
        ):
            if not _SHA256.fullmatch(getattr(self, name)):
                raise ValueError(f"Windows token acceptance {name} must be a SHA-256")
        for name in ("execution_grant_nonce", "nonce"):
            if not _NONCE.fullmatch(getattr(self, name)):
                raise ValueError(f"Windows token acceptance {name} is invalid")
        if self.nonce == self.execution_grant_nonce:
            raise ValueError("acceptance and execution grant nonces must differ")
        if not _IDENTIFIER.fullmatch(self.campaign_id):
            raise ValueError("Windows token acceptance campaign_id is invalid")
        if not _HOST.fullmatch(self.worker) or self.worker.lower() in _DENIED_WORKERS:
            raise ValueError("Windows token acceptance worker is invalid or denied")
        validate_windows_witness_user_sid(self.witness_user_sid)
        if (
            isinstance(self.witness_session_id, bool)
            or not isinstance(self.witness_session_id, int)
            or not 0 <= self.witness_session_id < 2**32
        ):
            raise ValueError("Windows token acceptance witness_session_id is invalid")
        if (
            not _AUTHENTICATION_ID.fullmatch(self.witness_authentication_id)
            or int(self.witness_authentication_id, 16) <= 0x3E7
        ):
            raise ValueError("Windows token acceptance witness_authentication_id is invalid")
        for name in (
            "build_lab_ex",
            "worker_machine_id",
            "accepted_by",
            "capture_signer",
        ):
            _bounded_text(getattr(self, name), f"Windows token acceptance {name}")
        _validate_window(self.issued_at, self.expires_at, "Windows token worker acceptance")
        if not self.signature_ssh:
            raise ValueError("Windows token worker acceptance signature_ssh is required")

    def require_signed_authorization(self) -> None:
        self.validate()
        if (
            not self._authorization_verified
            or not self._signed_material
            or self._allowed_signers is None
        ):
            raise ValueError("Windows token execution requires verified worker acceptance")
        raw = json.loads(self._signed_material, object_pairs_hook=_unique_object)
        if not isinstance(raw, dict):
            raise ValueError("signed Windows token acceptance material is malformed")
        raw["signature_ssh"] = self.signature_ssh
        if self != WindowsTokenWorkerAcceptance.from_mapping(raw):
            raise ValueError("live Windows token acceptance fields differ from signed material")
        verify_ssh_signature(
            self._signed_material,
            self.signature_ssh,
            identity=self.accepted_by,
            namespace=ACCEPTANCE_SIGNATURE_NAMESPACE,
            allowed_signers=self._allowed_signers,
            label="Windows token worker acceptance",
            require_trusted_policy=self._require_trusted_policy,
        )

    def require_source_binding(self, source_sha256: str) -> None:
        self.require_signed_authorization()
        if (
            not self._source_material
            or not self._source_sha256
            or hashlib.sha256(self._source_material).hexdigest() != self._source_sha256
            or source_sha256 != self._source_sha256
        ):
            raise ValueError("Windows token acceptance SHA-256 differs from loaded source file")
        raw = json.loads(self._source_material, object_pairs_hook=_unique_object)
        if not isinstance(raw, dict) or self != WindowsTokenWorkerAcceptance.from_mapping(raw):
            raise ValueError("live Windows token acceptance differs from loaded source file")

    def require_binding(
        self,
        campaign: WindowsTokenCampaign,
        campaign_sha256: str,
        scope: WindowsScope,
        scope_sha256: str,
        grant: WindowsTokenExecutionGrant,
        grant_sha256: str,
        acceptance_sha256: str,
    ) -> None:
        self.require_source_binding(acceptance_sha256)
        grant.require_binding(
            campaign, campaign_sha256, scope, scope_sha256, grant_sha256
        )
        if (
            self.campaign_sha256 != campaign_sha256
            or self.scope_manifest_sha256 != scope_sha256
            or self.execution_grant_sha256 != grant_sha256
            or self.execution_grant_nonce != grant.nonce
            or self.campaign_id != campaign.campaign_id
            or self.worker != campaign.worker
            or self.build_lab_ex != scope.preflight_build_lab_ex
            or self.target_operation_sha256 != campaign.target_operation_sha256
            or self.control_operation_sha256 != campaign.control_operation_sha256
        ):
            raise ValueError("Windows token worker acceptance is not authority-bound")


def load_windows_token_worker_acceptance(
    path: str | Path,
    *,
    allowed_signers: str | Path | None = None,
    require_authorized: bool = False,
) -> tuple[WindowsTokenWorkerAcceptance, str]:
    raw, data, digest = _load_object(path)
    acceptance = WindowsTokenWorkerAcceptance.from_mapping(raw)
    policy = (
        Path(allowed_signers)
        if allowed_signers is not None
        else DEFAULT_ACCEPTANCE_ALLOWED_SIGNERS
    )
    require_trusted = allowed_signers is None
    material = canonical_signed_material(raw)
    verify_ssh_signature(
        material,
        acceptance.signature_ssh,
        identity=acceptance.accepted_by,
        namespace=ACCEPTANCE_SIGNATURE_NAMESPACE,
        allowed_signers=policy,
        label="Windows token worker acceptance",
        require_trusted_policy=require_trusted,
    )
    verified = replace(
        acceptance,
        _signed_material=material,
        _allowed_signers=policy.expanduser().resolve(),
        _require_trusted_policy=require_trusted,
        _authorization_verified=True,
        _source_material=data,
        _source_sha256=digest,
    )
    if require_authorized:
        verified.require_signed_authorization()
    return verified, digest
