"""Signed per-run Windows token captures and replay protection.

The capture is raw evidence only. It contains no impact label, claim status,
payload, command line, or disclosure action. A trusted native helper must sign
one record for one grant-bound operation and process instance.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from .ssh_authorization import canonical_signed_material, verify_ssh_signature
from .windows_app_container import valid_package_app_container_sid
from .windows_scope import WindowsScope
from .windows_token_attestation import WindowsTokenSnapshot
from .windows_token_runner import (
    ELIGIBLE_WINDOWS_SANDBOXES,
    LPAC_CAMPAIGN_SCHEMA_VERSION,
    WindowsTokenCampaign,
    WindowsTokenExecutionGrant,
    WindowsTokenWorkerAcceptance,
    validate_windows_witness_user_sid,
)

SCHEMA_VERSION = "0verse.windows-token-capture/v3"
LPAC_SCHEMA_VERSION = "0verse.windows-token-capture/v4"
LPAC_PROCESS_SCHEMA_VERSION = "0verse.windows-token-capture/v5"
LPAC_LAUNCH_SCHEMA_VERSION = "0verse.windows-lpac-launch-provenance/v1"
LPAC_LAUNCH_SIGNATURE_NAMESPACE = "0verse-windows-lpac-launch-provenance"
SIGNATURE_NAMESPACE = "0verse-windows-token-capture"
DEFAULT_ALLOWED_SIGNERS = Path("/etc/0verse/windows-token-capture.allowed_signers")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_PROCESS_ID = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_AUTHENTICATION_ID = re.compile(r"^[a-f0-9]{16}$")
_DANGEROUS_PRIVILEGES = frozenset(
    {
        "SeAssignPrimaryTokenPrivilege",
        "SeBackupPrivilege",
        "SeCreateTokenPrivilege",
        "SeDebugPrivilege",
        "SeImpersonatePrivilege",
        "SeIncreaseQuotaPrivilege",
        "SeLoadDriverPrivilege",
        "SeRelabelPrivilege",
        "SeRestorePrivilege",
        "SeTakeOwnershipPrivilege",
        "SeTcbPrivilege",
    }
)


_FIELDS = frozenset(
    {
        "schema_version",
        "campaign_sha256",
        "scope_manifest_sha256",
        "execution_grant_sha256",
        "execution_grant_nonce",
        "worker_acceptance_sha256",
        "worker_acceptance_nonce",
        "campaign_id",
        "worker",
        "build_lab_ex",
        "worker_machine_id",
        "runner_executable_sha256",
        "witness_user_sid",
        "witness_session_id",
        "witness_authentication_id",
        "witness_executable_sha256",
        "operation_sha256",
        "case",
        "trial",
        "run_nonce",
        "capture_nonce",
        "process_instance_id",
        "thread_id_before",
        "thread_id_after",
        "started_at",
        "completed_at",
        "start_token",
        "finish_token",
        "signed_by",
        "signature_ssh",
    }
)
_LPAC_FIELDS = _FIELDS | {"lpac_launch"}
_STRING_FIELDS = _FIELDS - {
    "trial",
    "thread_id_before",
    "thread_id_after",
    "witness_session_id",
    "start_token",
    "finish_token",
}
_LPAC_PROCESS_FIELDS = (_FIELDS - {"thread_id_before", "thread_id_after"}) | {
    "lpac_broker_receipt_sha256",
    "lpac_launch_receipt_sha256",
}
_LPAC_PROCESS_STRING_FIELDS = _STRING_FIELDS | {
    "lpac_broker_receipt_sha256",
    "lpac_launch_receipt_sha256",
}
_LPAC_LAUNCH_FIELDS = frozenset(
    {
        "schema_version",
        "eligible_sandbox",
        "launch_app_container_executable_sha256",
        "sandbox_process_executable_sha256",
        "app_container_sid",
        "process_creation_identity_sha256",
        "launch_receipt_sha256",
        "launch_transcript_sha256",
        "lpac_flag",
        "fixed_adapter_operation_sha256",
        "campaign_sha256",
        "scope_manifest_sha256",
        "execution_grant_sha256",
        "worker_acceptance_sha256",
        "case",
        "trial",
        "run_nonce",
        "process_instance_id",
        "worker",
        "build_lab_ex",
        "signed_by",
        "signature_ssh",
    }
)

_SNAPSHOT_EXTRA_FIELDS = frozenset(
    {
        "token_source",
        "statistics_token_id_before",
        "statistics_token_id_after",
        "modified_id_before",
        "modified_id_after",
        "lpac_supported",
        "less_privileged_app_container",
        "session_id",
        "authentication_id",
    }
)
_SNAPSHOT_BASE_FIELDS = frozenset(
    {
        "token_id",
        "user_sid",
        "integrity_rid",
        "elevation_type",
        "elevated",
        "admin_group",
        "app_container",
        "restricted_sid_count",
        "enabled_privileges",
    }
)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _timestamp(value: str, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Windows token capture {name} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"Windows token capture {name} must include a timezone")
    return parsed.astimezone(UTC)


def derive_token_id(run_nonce: str, phase: str, statistics_token_id: int) -> str:
    """Derive one phase-scoped snapshot ID while retaining the raw stable LUID."""
    if phase not in {"start", "finish"}:
        raise ValueError("Windows token snapshot phase must be start or finish")
    digest = hashlib.sha256(
        b"0verse-token-snapshot-id-v1\0"
        + run_nonce.encode("ascii")
        + b"\0"
        + phase.encode("ascii")
        + b"\0"
        + statistics_token_id.to_bytes(8, "little")
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _read_regular_nofollow(path: Path, maximum: int = 1024 * 1024) -> bytes:
    if path.is_symlink():
        raise ValueError("Windows token capture cannot be a symlink")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise ValueError("Windows token capture must be a bounded regular file")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("Windows token capture exceeds the size limit")
        return data
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class ProductionWindowsTokenSnapshot:
    facts: WindowsTokenSnapshot
    token_source: str
    statistics_token_id_before: int
    statistics_token_id_after: int
    modified_id_before: int
    modified_id_after: int
    lpac_supported: bool
    less_privileged_app_container: bool
    session_id: int
    authentication_id: str
    app_container_sid: str = ""

    @classmethod
    def from_mapping(
        cls, value: object, name: str, *, require_app_container_sid: bool = False
    ) -> ProductionWindowsTokenSnapshot:
        expected = _SNAPSHOT_BASE_FIELDS | _SNAPSHOT_EXTRA_FIELDS
        if require_app_container_sid:
            expected = expected | {"app_container_sid"}
        if not isinstance(value, dict) or set(value) != expected:
            raise ValueError(f"{name} must contain the exact production token facts")
        facts = WindowsTokenSnapshot.from_mapping(
            {key: value[key] for key in _SNAPSHOT_BASE_FIELDS}, name
        )
        token_source = value["token_source"]
        if token_source not in {
            "thread",
            "process-fallback-no-thread-token",
            "process-primary",
        }:
            raise ValueError(f"{name}.token_source is invalid")
        counters: dict[str, int] = {}
        for field_name in (
            "statistics_token_id_before",
            "statistics_token_id_after",
            "modified_id_before",
            "modified_id_after",
        ):
            counter = value[field_name]
            if (
                isinstance(counter, bool)
                or not isinstance(counter, int)
                or not 0 <= counter < 2**64
            ):
                raise ValueError(f"{name}.{field_name} must be an unsigned 64-bit integer")
            counters[field_name] = counter
        if (
            counters["statistics_token_id_before"] != counters["statistics_token_id_after"]
            or counters["modified_id_before"] != counters["modified_id_after"]
        ):
            raise ValueError(f"{name} changed while token facts were captured")
        if not isinstance(value["lpac_supported"], bool) or not isinstance(
            value["less_privileged_app_container"], bool
        ):
            raise ValueError(f"{name} LPAC facts must be boolean")
        if not value["lpac_supported"]:
            raise ValueError(f"{name} must fail closed when LPAC status is unavailable")
        if require_app_container_sid and not isinstance(value["app_container_sid"], str):
            raise ValueError(f"{name}.app_container_sid must be a string")
        session_id = value["session_id"]
        authentication_id = value["authentication_id"]
        if (
            isinstance(session_id, bool)
            or not isinstance(session_id, int)
            or not 0 <= session_id < 2**32
        ):
            raise ValueError(f"{name}.session_id must be an unsigned 32-bit integer")
        if (
            not isinstance(authentication_id, str)
            or not _AUTHENTICATION_ID.fullmatch(authentication_id)
            or int(authentication_id, 16) == 0
        ):
            raise ValueError(f"{name}.authentication_id is invalid")
        return cls(
            facts=facts,
            token_source=token_source,
            statistics_token_id_before=counters["statistics_token_id_before"],
            statistics_token_id_after=counters["statistics_token_id_after"],
            modified_id_before=counters["modified_id_before"],
            modified_id_after=counters["modified_id_after"],
            lpac_supported=value["lpac_supported"],
            less_privileged_app_container=value["less_privileged_app_container"],
            session_id=session_id,
            authentication_id=authentication_id,
            app_container_sid=(
                str(value["app_container_sid"]) if require_app_container_sid else ""
            ),
        )

    def to_dict(self) -> dict[str, object]:
        result = {
            **self.facts.to_dict(),
            "token_source": self.token_source,
            "statistics_token_id_before": self.statistics_token_id_before,
            "statistics_token_id_after": self.statistics_token_id_after,
            "modified_id_before": self.modified_id_before,
            "modified_id_after": self.modified_id_after,
            "lpac_supported": self.lpac_supported,
            "less_privileged_app_container": self.less_privileged_app_container,
            "session_id": self.session_id,
            "authentication_id": self.authentication_id,
        }
        if self.app_container_sid:
            result["app_container_sid"] = self.app_container_sid
        return result

    @property
    def token_id(self) -> str:
        return self.facts.token_id

    @property
    def user_sid(self) -> str:
        return self.facts.user_sid

    @property
    def integrity_rid(self) -> int:
        return self.facts.integrity_rid

    @property
    def elevation_type(self) -> str:
        return self.facts.elevation_type

    @property
    def elevated(self) -> bool:
        return self.facts.elevated

    @property
    def admin_group(self) -> str:
        return self.facts.admin_group

    @property
    def app_container(self) -> bool:
        return self.facts.app_container

    @property
    def restricted_sid_count(self) -> int:
        return self.facts.restricted_sid_count

    @property
    def enabled_privileges(self) -> tuple[str, ...]:
        return self.facts.enabled_privileges


@dataclass(frozen=True)
class WindowsLpacLaunchProvenance:
    eligible_sandbox: str
    launch_app_container_executable_sha256: str
    sandbox_process_executable_sha256: str
    app_container_sid: str
    process_creation_identity_sha256: str
    launch_receipt_sha256: str
    launch_transcript_sha256: str
    lpac_flag: bool
    fixed_adapter_operation_sha256: str
    campaign_sha256: str
    scope_manifest_sha256: str
    execution_grant_sha256: str
    worker_acceptance_sha256: str
    case: str
    trial: int
    run_nonce: str
    process_instance_id: str
    worker: str
    build_lab_ex: str
    signed_by: str
    signature_ssh: str
    schema_version: str = LPAC_LAUNCH_SCHEMA_VERSION
    _signed_material: bytes = field(default=b"", repr=False, compare=False)
    _signature_verified: bool = field(default=False, repr=False, compare=False)

    @classmethod
    def from_mapping(cls, value: object) -> WindowsLpacLaunchProvenance:
        if not isinstance(value, dict) or set(value) != _LPAC_LAUNCH_FIELDS:
            raise ValueError("lpac_launch must contain the exact launch provenance fields")
        if not isinstance(value["lpac_flag"], bool):
            raise ValueError("lpac_launch.lpac_flag must be a boolean")
        if isinstance(value["trial"], bool) or not isinstance(value["trial"], int):
            raise ValueError("lpac_launch.trial must be an integer")
        if any(
            not isinstance(value[name], str)
            for name in _LPAC_LAUNCH_FIELDS - {"lpac_flag", "trial"}
        ):
            raise ValueError("LPAC launch provenance text fields must be strings")
        provenance = cls(**value)
        provenance.validate()
        return provenance

    def validate(self) -> None:
        if self.schema_version != LPAC_LAUNCH_SCHEMA_VERSION:
            raise ValueError("unsupported LPAC launch provenance schema")
        if self.eligible_sandbox not in ELIGIBLE_WINDOWS_SANDBOXES:
            raise ValueError("LPAC launch provenance sandbox is not officially eligible")
        for name in (
            "launch_app_container_executable_sha256",
            "sandbox_process_executable_sha256",
            "process_creation_identity_sha256",
            "launch_receipt_sha256",
            "launch_transcript_sha256",
            "fixed_adapter_operation_sha256",
            "campaign_sha256",
            "scope_manifest_sha256",
            "execution_grant_sha256",
            "worker_acceptance_sha256",
        ):
            if _SHA256.fullmatch(getattr(self, name)) is None:
                raise ValueError(f"LPAC launch provenance {name} must be a SHA-256")
        if not self.lpac_flag:
            raise ValueError("LPAC launch provenance must record the LPAC flag")
        if not valid_package_app_container_sid(self.app_container_sid):
            raise ValueError("LPAC launch provenance AppContainer SID is invalid")
        if self.case not in {"target", "control"} or not 1 <= self.trial <= 32:
            raise ValueError("LPAC launch provenance case or trial is invalid")
        if _NONCE.fullmatch(self.run_nonce) is None:
            raise ValueError("LPAC launch provenance run nonce is invalid")
        if _PROCESS_ID.fullmatch(self.process_instance_id) is None:
            raise ValueError("LPAC launch provenance process identity is invalid")
        for name in ("worker", "build_lab_ex", "signed_by"):
            value = getattr(self, name)
            if (
                not value
                or value != value.strip()
                or len(value) > 256
                or any(ord(character) < 0x20 for character in value)
            ):
                raise ValueError(f"LPAC launch provenance {name} is invalid")
        if not self.signature_ssh:
            raise ValueError("LPAC launch provenance signature is required")

    def require_signature(self) -> None:
        self.validate()
        if not self._signature_verified or not self._signed_material:
            raise ValueError("LPAC launch provenance requires a verified signature")
        raw = json.loads(self._signed_material, object_pairs_hook=_unique_object)
        if not isinstance(raw, dict):
            raise ValueError("signed LPAC launch provenance material is malformed")
        raw["signature_ssh"] = self.signature_ssh
        if self != WindowsLpacLaunchProvenance.from_mapping(raw):
            raise ValueError("LPAC launch provenance differs from signed material")

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload.pop("_signed_material")
        payload.pop("_signature_verified")
        return payload


@dataclass(frozen=True)
class WindowsTokenCapture:
    campaign_sha256: str
    scope_manifest_sha256: str
    execution_grant_sha256: str
    execution_grant_nonce: str
    worker_acceptance_sha256: str
    worker_acceptance_nonce: str
    campaign_id: str
    worker: str
    build_lab_ex: str
    worker_machine_id: str
    runner_executable_sha256: str
    witness_user_sid: str
    witness_session_id: int
    witness_authentication_id: str
    witness_executable_sha256: str
    operation_sha256: str
    case: str
    trial: int
    run_nonce: str
    capture_nonce: str
    process_instance_id: str
    thread_id_before: int
    thread_id_after: int
    started_at: str
    completed_at: str
    start_token: ProductionWindowsTokenSnapshot
    finish_token: ProductionWindowsTokenSnapshot
    signed_by: str
    signature_ssh: str
    lpac_launch: WindowsLpacLaunchProvenance | None = None
    lpac_broker_receipt_sha256: str = ""
    lpac_launch_receipt_sha256: str = ""
    schema_version: str = SCHEMA_VERSION
    _signed_material: bytes = field(default=b"", repr=False, compare=False)
    _allowed_signers: Path | None = field(default=None, repr=False, compare=False)
    _require_trusted_policy: bool = field(default=True, repr=False, compare=False)
    _signature_verified: bool = field(default=False, repr=False, compare=False)
    _source_material: bytes = field(default=b"", repr=False, compare=False)
    _source_sha256: str = field(default="", repr=False, compare=False)
    _source_name: str = field(default="", repr=False, compare=False)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> WindowsTokenCapture:
        schema = raw.get("schema_version")
        expected = (
            _LPAC_FIELDS
            if schema == LPAC_SCHEMA_VERSION
            else _LPAC_PROCESS_FIELDS
            if schema == LPAC_PROCESS_SCHEMA_VERSION
            else _FIELDS
        )
        missing = sorted(expected - raw.keys())
        unknown = sorted(raw.keys() - expected)
        if missing or unknown:
            details = []
            if missing:
                details.append(f"missing {', '.join(missing)}")
            if unknown:
                details.append(f"unknown {', '.join(unknown)}")
            raise ValueError(f"Windows token capture fields invalid: {'; '.join(details)}")
        required_string_fields = (
            _LPAC_PROCESS_STRING_FIELDS
            if schema == LPAC_PROCESS_SCHEMA_VERSION
            else _STRING_FIELDS
        )
        invalid_strings = sorted(
            name for name in required_string_fields if not isinstance(raw[name], str)
        )
        if invalid_strings:
            raise ValueError(
                "Windows token capture fields must be strings: " + ", ".join(invalid_strings)
            )
        integer_fields = {"trial", "witness_session_id"}
        if schema != LPAC_PROCESS_SCHEMA_VERSION:
            integer_fields.update({"thread_id_before", "thread_id_after"})
        for name in integer_fields:
            if isinstance(raw[name], bool) or not isinstance(raw[name], int):
                raise ValueError(f"Windows token capture {name} must be an integer")
        strings = cast(Mapping[str, str], raw)
        integers = cast(Mapping[str, int], raw)
        capture = cls(
            schema_version=strings["schema_version"],
            campaign_sha256=strings["campaign_sha256"],
            scope_manifest_sha256=strings["scope_manifest_sha256"],
            execution_grant_sha256=strings["execution_grant_sha256"],
            execution_grant_nonce=strings["execution_grant_nonce"],
            worker_acceptance_sha256=strings["worker_acceptance_sha256"],
            worker_acceptance_nonce=strings["worker_acceptance_nonce"],
            campaign_id=strings["campaign_id"],
            worker=strings["worker"],
            build_lab_ex=strings["build_lab_ex"],
            worker_machine_id=strings["worker_machine_id"],
            runner_executable_sha256=strings["runner_executable_sha256"],
            witness_user_sid=strings["witness_user_sid"],
            witness_session_id=integers["witness_session_id"],
            witness_authentication_id=strings["witness_authentication_id"],
            witness_executable_sha256=strings["witness_executable_sha256"],
            operation_sha256=strings["operation_sha256"],
            case=strings["case"],
            trial=integers["trial"],
            run_nonce=strings["run_nonce"],
            capture_nonce=strings["capture_nonce"],
            process_instance_id=strings["process_instance_id"],
            thread_id_before=(
                0 if schema == LPAC_PROCESS_SCHEMA_VERSION else integers["thread_id_before"]
            ),
            thread_id_after=(
                0 if schema == LPAC_PROCESS_SCHEMA_VERSION else integers["thread_id_after"]
            ),
            started_at=strings["started_at"],
            completed_at=strings["completed_at"],
            start_token=ProductionWindowsTokenSnapshot.from_mapping(
                raw["start_token"],
                "start_token",
                require_app_container_sid=schema
                in {LPAC_SCHEMA_VERSION, LPAC_PROCESS_SCHEMA_VERSION},
            ),
            finish_token=ProductionWindowsTokenSnapshot.from_mapping(
                raw["finish_token"],
                "finish_token",
                require_app_container_sid=schema
                in {LPAC_SCHEMA_VERSION, LPAC_PROCESS_SCHEMA_VERSION},
            ),
            signed_by=strings["signed_by"],
            signature_ssh=strings["signature_ssh"],
            lpac_launch=(
                WindowsLpacLaunchProvenance.from_mapping(raw["lpac_launch"])
                if schema == LPAC_SCHEMA_VERSION
                else None
            ),
            lpac_broker_receipt_sha256=(
                strings["lpac_broker_receipt_sha256"]
                if schema == LPAC_PROCESS_SCHEMA_VERSION
                else ""
            ),
            lpac_launch_receipt_sha256=(
                strings["lpac_launch_receipt_sha256"]
                if schema == LPAC_PROCESS_SCHEMA_VERSION
                else ""
            ),
        )
        capture.validate()
        return capture

    def validate(self) -> None:
        if self.schema_version not in {
            SCHEMA_VERSION,
            LPAC_SCHEMA_VERSION,
            LPAC_PROCESS_SCHEMA_VERSION,
        }:
            raise ValueError(f"unsupported Windows token capture schema: {self.schema_version}")
        if self.schema_version == SCHEMA_VERSION and self.lpac_launch is not None:
            raise ValueError("Windows token capture v3 cannot contain LPAC launch provenance")
        if self.schema_version != LPAC_PROCESS_SCHEMA_VERSION and self.lpac_broker_receipt_sha256:
            raise ValueError("only Windows token capture v5 can bind an LPAC broker receipt")
        if self.schema_version != LPAC_PROCESS_SCHEMA_VERSION and self.lpac_launch_receipt_sha256:
            raise ValueError("only Windows token capture v5 can bind an LPAC launch receipt")
        if self.schema_version == LPAC_PROCESS_SCHEMA_VERSION:
            if self.lpac_launch is not None:
                raise ValueError("Windows token capture v5 cannot contain v4 launch provenance")
            if _SHA256.fullmatch(self.lpac_broker_receipt_sha256) is None:
                raise ValueError("Windows token capture v5 requires an LPAC broker receipt SHA-256")
            if _SHA256.fullmatch(self.lpac_launch_receipt_sha256) is None:
                raise ValueError("Windows token capture v5 requires an LPAC launch receipt SHA-256")
        if self.schema_version == LPAC_SCHEMA_VERSION:
            if self.lpac_launch is None:
                raise ValueError("Windows token capture v4 requires LPAC launch provenance")
            self.lpac_launch.validate()
        if self.schema_version in {LPAC_SCHEMA_VERSION, LPAC_PROCESS_SCHEMA_VERSION}:
            if (
                not self.start_token.app_container
                or not self.start_token.less_privileged_app_container
                or not valid_package_app_container_sid(self.start_token.app_container_sid)
            ):
                raise ValueError("Windows LPAC token capture requires an LPAC AppContainer start")
            for name, token in (
                ("start", self.start_token),
                ("finish", self.finish_token),
            ):
                if token.app_container:
                    if not valid_package_app_container_sid(token.app_container_sid):
                        raise ValueError(
                            f"Windows LPAC token capture {name} AppContainer SID is invalid"
                        )
                elif token.app_container_sid or token.less_privileged_app_container:
                    raise ValueError(
                        f"Windows LPAC token capture {name} AppContainer facts are inconsistent"
                    )
                if token.less_privileged_app_container and not token.app_container:
                    raise ValueError(f"Windows LPAC token capture {name} LPAC fact is inconsistent")
        for name in (
            "campaign_sha256",
            "scope_manifest_sha256",
            "execution_grant_sha256",
            "worker_acceptance_sha256",
            "operation_sha256",
            "runner_executable_sha256",
            "witness_executable_sha256",
        ):
            if not _SHA256.fullmatch(getattr(self, name)):
                raise ValueError(f"Windows token capture {name} must be a SHA-256")
        nonces = (
            self.execution_grant_nonce,
            self.worker_acceptance_nonce,
            self.run_nonce,
            self.capture_nonce,
        )
        if any(_NONCE.fullmatch(value) is None for value in nonces):
            raise ValueError("Windows token capture nonce is invalid")
        if len(set(nonces)) != len(nonces):
            raise ValueError("Windows token capture nonce domains must be distinct")
        if self.case not in {"target", "control"}:
            raise ValueError("Windows token capture case must be target or control")
        if not 1 <= self.trial <= 32:
            raise ValueError("Windows token capture trial must be between 1 and 32")
        if not _PROCESS_ID.fullmatch(self.process_instance_id):
            raise ValueError("Windows token capture process_instance_id is invalid")
        validate_windows_witness_user_sid(self.witness_user_sid)
        if (
            isinstance(self.witness_session_id, bool)
            or not isinstance(self.witness_session_id, int)
            or not 0 <= self.witness_session_id < 2**32
        ):
            raise ValueError("Windows token capture witness_session_id is invalid")
        if (
            not _AUTHENTICATION_ID.fullmatch(self.witness_authentication_id)
            or int(self.witness_authentication_id, 16) <= 0x3E7
        ):
            raise ValueError("Windows token capture witness_authentication_id is invalid")
        if self.schema_version == LPAC_PROCESS_SCHEMA_VERSION:
            if self.thread_id_before != 0 or self.thread_id_after != 0:
                raise ValueError("Windows token capture v5 cannot contain thread-locus evidence")
        elif (
            not 0 < self.thread_id_before < 2**32
            or self.thread_id_before != self.thread_id_after
        ):
            raise ValueError("Windows token capture must remain on one valid OS thread")
        for name in (
            "campaign_id",
            "worker",
            "build_lab_ex",
            "worker_machine_id",
            "signed_by",
        ):
            value = getattr(self, name)
            if (
                not value
                or value != value.strip()
                or len(value) > 256
                or any(ord(character) < 0x20 for character in value)
            ):
                raise ValueError(f"Windows token capture {name} is invalid")
        if self.start_token.token_id == self.finish_token.token_id:
            raise ValueError("Windows token capture token identities must differ")
        for name, token in (("start", self.start_token), ("finish", self.finish_token)):
            if token.token_id != derive_token_id(
                self.run_nonce, name, token.statistics_token_id_before
            ):
                raise ValueError(f"Windows token capture {name} token identity is not LUID-bound")
        started = _timestamp(self.started_at, "started_at")
        completed = _timestamp(self.completed_at, "completed_at")
        now = datetime.now(UTC)
        if completed < started or completed - started > timedelta(hours=1):
            raise ValueError("Windows token capture timestamps are out of order or too long")
        if completed > now + timedelta(minutes=5) or now - completed > timedelta(hours=24):
            raise ValueError("Windows token capture is outside the 24-hour evidence window")
        if not self.signature_ssh:
            raise ValueError("Windows token capture signature_ssh is required")

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        for name in (
            "_signed_material",
            "_allowed_signers",
            "_require_trusted_policy",
            "_signature_verified",
            "_source_material",
            "_source_sha256",
            "_source_name",
        ):
            payload.pop(name)
        payload["start_token"] = self.start_token.to_dict()
        payload["finish_token"] = self.finish_token.to_dict()
        if self.schema_version == LPAC_PROCESS_SCHEMA_VERSION:
            payload.pop("thread_id_before")
            payload.pop("thread_id_after")
        if self.lpac_launch is None:
            payload.pop("lpac_launch")
        else:
            payload["lpac_launch"] = self.lpac_launch.to_dict()
        if not self.lpac_broker_receipt_sha256:
            payload.pop("lpac_broker_receipt_sha256")
        if not self.lpac_launch_receipt_sha256:
            payload.pop("lpac_launch_receipt_sha256")
        return payload

    def require_signature(self) -> None:
        self.validate()
        if (
            not self._signature_verified
            or not self._signed_material
            or self._allowed_signers is None
        ):
            raise ValueError("Windows token capture requires a verified worker signature")
        raw = json.loads(self._signed_material, object_pairs_hook=_unique_object)
        if not isinstance(raw, dict):
            raise ValueError("signed Windows token capture material is malformed")
        raw["signature_ssh"] = self.signature_ssh
        if self != WindowsTokenCapture.from_mapping(raw):
            raise ValueError("live Windows token capture differs from signed material")
        verify_ssh_signature(
            self._signed_material,
            self.signature_ssh,
            identity=self.signed_by,
            namespace=SIGNATURE_NAMESPACE,
            allowed_signers=self._allowed_signers,
            label="Windows token capture",
            require_trusted_policy=self._require_trusted_policy,
        )

    def require_source_binding(self, source_sha256: str) -> None:
        self.require_signature()
        if (
            not self._source_material
            or not self._source_sha256
            or hashlib.sha256(self._source_material).hexdigest() != self._source_sha256
            or source_sha256 != self._source_sha256
        ):
            raise ValueError("Windows token capture SHA-256 differs from loaded source file")
        raw = json.loads(self._source_material, object_pairs_hook=_unique_object)
        if not isinstance(raw, dict) or self != WindowsTokenCapture.from_mapping(raw):
            raise ValueError("live Windows token capture differs from loaded source file")

    def require_binding(
        self,
        campaign: WindowsTokenCampaign,
        campaign_sha256: str,
        scope: WindowsScope,
        scope_sha256: str,
        grant: WindowsTokenExecutionGrant,
        grant_sha256: str,
        acceptance: WindowsTokenWorkerAcceptance,
        acceptance_sha256: str,
        *,
        expected_case: str,
        expected_trial: int,
        expected_run_nonce: str,
    ) -> None:
        self.require_source_binding(self._source_sha256)
        acceptance.require_binding(
            campaign,
            campaign_sha256,
            scope,
            scope_sha256,
            grant,
            grant_sha256,
            acceptance_sha256,
        )
        expected_operation = (
            campaign.target_operation_sha256
            if expected_case == "target"
            else campaign.control_operation_sha256
        )
        if (
            expected_case not in {"target", "control"}
            or self.campaign_sha256 != campaign_sha256
            or self.scope_manifest_sha256 != scope_sha256
            or self.execution_grant_sha256 != grant_sha256
            or self.execution_grant_nonce != grant.nonce
            or self.worker_acceptance_sha256 != acceptance_sha256
            or self.worker_acceptance_nonce != acceptance.nonce
            or self.campaign_id != campaign.campaign_id
            or self.worker != campaign.worker
            or self.build_lab_ex != scope.preflight_build_lab_ex
            or self.worker_machine_id != acceptance.worker_machine_id
            or self.runner_executable_sha256 != acceptance.runner_executable_sha256
            or self.witness_user_sid != acceptance.witness_user_sid
            or self.witness_session_id != acceptance.witness_session_id
            or self.witness_authentication_id != acceptance.witness_authentication_id
            or self.witness_executable_sha256 != acceptance.witness_executable_sha256
            or self.operation_sha256 != expected_operation
            or self.case != expected_case
            or self.trial != expected_trial
            or self.run_nonce != expected_run_nonce
            or self.signed_by != acceptance.capture_signer
        ):
            raise ValueError("Windows token capture is not bound to authorized execution")
        if campaign.starting_context == "standard-user" and (
            self.start_token.user_sid != self.witness_user_sid
            or self.start_token.session_id != self.witness_session_id
            or self.start_token.authentication_id != self.witness_authentication_id
            or self.start_token.integrity_rid != 0x2000
            or self.start_token.elevation_type != "default"
            or self.start_token.elevated
            or self.start_token.admin_group != "absent"
            or self.start_token.app_container
            or self.start_token.restricted_sid_count != 0
            or self.start_token.token_source
            != "process-fallback-no-thread-token"
            or not _DANGEROUS_PRIVILEGES.isdisjoint(
                self.start_token.enabled_privileges
            )
        ):
            raise ValueError("Windows token capture start token is not the bound standard user")
        if campaign.schema_version == LPAC_CAMPAIGN_SCHEMA_VERSION:
            launch = self.lpac_launch
            if self.schema_version == LPAC_SCHEMA_VERSION and launch is not None:
                launch.require_signature()
                if (
                    launch.eligible_sandbox != campaign.eligible_sandbox
                    or launch.launch_app_container_executable_sha256
                    != campaign.launch_app_container_executable_sha256
                    or launch.sandbox_process_executable_sha256
                    != campaign.sandbox_process_executable_sha256
                    or launch.app_container_sid != campaign.app_container_sid
                    or launch.fixed_adapter_operation_sha256 != expected_operation
                    or launch.campaign_sha256 != campaign_sha256
                    or launch.scope_manifest_sha256 != scope_sha256
                    or launch.execution_grant_sha256 != grant_sha256
                    or launch.worker_acceptance_sha256 != acceptance_sha256
                    or launch.case != expected_case
                    or launch.trial != expected_trial
                    or launch.run_nonce != expected_run_nonce
                    or launch.process_instance_id != self.process_instance_id
                    or launch.worker != self.worker
                    or launch.build_lab_ex != self.build_lab_ex
                    or launch.signed_by != acceptance.capture_signer
                ):
                    raise ValueError("LPAC launch provenance is not authority/capture-bound")
            elif self.schema_version != LPAC_PROCESS_SCHEMA_VERSION:
                raise ValueError("eligible-sandbox campaign requires signed capture v4 or v5")
            start = self.start_token
            if (
                start.integrity_rid > 0x2100
                or start.elevation_type == "full"
                or start.elevated
                or start.admin_group == "enabled"
                or not start.app_container
                or not start.less_privileged_app_container
                or start.app_container_sid != campaign.app_container_sid
                or start.token_source
                != (
                    "process-primary"
                    if self.schema_version == LPAC_PROCESS_SCHEMA_VERSION
                    else "process-fallback-no-thread-token"
                )
                or not _DANGEROUS_PRIVILEGES.isdisjoint(start.enabled_privileges)
            ):
                raise ValueError("Windows token capture start token is not the bound LPAC sandbox")
            if self.schema_version == LPAC_SCHEMA_VERSION and (
                start.user_sid != self.witness_user_sid
                or start.session_id != self.witness_session_id
                or start.authentication_id != self.witness_authentication_id
            ):
                raise ValueError("Windows token capture start token is not the bound LPAC witness")
            if self.schema_version == LPAC_PROCESS_SCHEMA_VERSION and (
                self.finish_token.token_source != "process-primary"
            ):
                raise ValueError("Windows token capture v5 finish token is not process-primary")
        elif (
            self.schema_version != SCHEMA_VERSION
            or self.lpac_launch is not None
            or self.lpac_broker_receipt_sha256
            or self.lpac_launch_receipt_sha256
            or self.start_token.less_privileged_app_container
            or self.finish_token.less_privileged_app_container
        ):
            raise ValueError(
                "Windows token capture rejects LPAC: non-LPAC campaigns require capture v3"
            )
        expected_finish_session = (
            self.start_token.session_id
            if self.schema_version == LPAC_PROCESS_SCHEMA_VERSION
            else self.witness_session_id
        )
        if self.finish_token.session_id != expected_finish_session:
            raise ValueError("Windows token capture changed sessions during execution")
        started = _timestamp(self.started_at, "started_at")
        completed = _timestamp(self.completed_at, "completed_at")
        issued = max(
            _timestamp(scope.issued_at, "scope issued_at"),
            _timestamp(grant.issued_at, "grant issued_at"),
            _timestamp(acceptance.issued_at, "acceptance issued_at"),
        )
        expires = min(
            _timestamp(scope.expires_at, "scope expires_at"),
            _timestamp(grant.expires_at, "grant expires_at"),
            _timestamp(acceptance.expires_at, "acceptance expires_at"),
        )
        if started < issued or completed > expires:
            raise ValueError("Windows token capture is outside its authorization window")

    @property
    def source_sha256(self) -> str:
        if not self._source_sha256:
            raise ValueError("Windows token capture is not source-bound")
        return self._source_sha256

    @property
    def source_name(self) -> str:
        if not self._source_name:
            raise ValueError("Windows token capture is not source-bound")
        return self._source_name


def load_windows_token_capture(
    path: str | Path,
    *,
    allowed_signers: str | Path | None = None,
    require_verified: bool = False,
) -> tuple[WindowsTokenCapture, str]:
    source = Path(path)
    data = _read_regular_nofollow(source)
    raw = json.loads(data, object_pairs_hook=_unique_object)
    if not isinstance(raw, dict):
        raise ValueError("Windows token capture must contain a JSON object")
    capture = WindowsTokenCapture.from_mapping(raw)
    policy = Path(allowed_signers) if allowed_signers is not None else DEFAULT_ALLOWED_SIGNERS
    require_trusted = allowed_signers is None
    if capture.lpac_launch is not None:
        launch_raw = capture.lpac_launch.to_dict()
        launch_material = canonical_signed_material(launch_raw)
        verify_ssh_signature(
            launch_material,
            capture.lpac_launch.signature_ssh,
            identity=capture.lpac_launch.signed_by,
            namespace=LPAC_LAUNCH_SIGNATURE_NAMESPACE,
            allowed_signers=policy,
            label="Windows LPAC launch provenance",
            require_trusted_policy=require_trusted,
        )
        capture = replace(
            capture,
            lpac_launch=replace(
                capture.lpac_launch,
                _signed_material=launch_material,
                _signature_verified=True,
            ),
        )
    material = canonical_signed_material(raw)
    verify_ssh_signature(
        material,
        capture.signature_ssh,
        identity=capture.signed_by,
        namespace=SIGNATURE_NAMESPACE,
        allowed_signers=policy,
        label="Windows token capture",
        require_trusted_policy=require_trusted,
    )
    digest = hashlib.sha256(data).hexdigest()
    verified = replace(
        capture,
        _signed_material=material,
        _allowed_signers=policy.expanduser().resolve(),
        _require_trusted_policy=require_trusted,
        _signature_verified=True,
        _source_material=data,
        _source_sha256=digest,
        _source_name=source.name,
    )
    if require_verified:
        verified.require_signature()
    return verified, digest


class ExclusiveFileNonceLedger:
    """Persistent consume-once ledger for controller-side replay rejection.

    The Windows helper still needs its own ACL-protected ProgramData ledger.
    This controller ledger is a second, atomic replay boundary.
    """

    def __init__(self, root: str | Path) -> None:
        if os.name == "nt":
            raise ValueError("controller nonce ledger requires a POSIX controller")
        self.root = Path(root)
        if not self.root.exists():
            self.root.mkdir(mode=0o700, parents=False)
        if self.root.is_symlink() or not self.root.is_dir():
            raise ValueError("nonce ledger root must be a regular directory")
        if os.name != "nt" and self.root.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ValueError("nonce ledger root permissions are too broad")

    def consume(self, grant_nonce: str, run_nonce: str) -> str:
        return self.consume_batch(grant_nonce, (run_nonce,))[0]

    @contextmanager
    def _locked(self) -> Iterator[None]:
        lock_path = self.root / ".ledger.lock"
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def consume_batch(
        self,
        grant_nonce: str,
        run_nonces: tuple[str, ...],
        *,
        campaign_sha256: str | None = None,
    ) -> tuple[str, ...]:
        if (
            _NONCE.fullmatch(grant_nonce) is None
            or not run_nonces
            or len(run_nonces) != len(set(run_nonces))
            or any(
                _NONCE.fullmatch(run_nonce) is None or grant_nonce == run_nonce
                for run_nonce in run_nonces
            )
        ):
            raise ValueError("nonce ledger inputs are invalid")
        if campaign_sha256 is not None and _SHA256.fullmatch(campaign_sha256) is None:
            raise ValueError("nonce ledger campaign digest is invalid")
        from .windows_token_evidence import (
            derive_windows_token_grant_ledger_entry,
            derive_windows_token_ledger_entries,
        )

        run_identities = derive_windows_token_ledger_entries(grant_nonce, run_nonces)
        marker = (
            derive_windows_token_grant_ledger_entry(grant_nonce, campaign_sha256)
            if campaign_sha256 is not None
            else None
        )
        identities = ((marker,) if marker is not None else ()) + run_identities
        paths = tuple(self.root / f"{identity}.used" for identity in identities)
        created: list[Path] = []
        with self._locked():
            if any(path.exists() for path in paths):
                raise FileExistsError("one or more Windows token run nonces were consumed")
            try:
                for path, identity in zip(paths, identities, strict=True):
                    descriptor = os.open(
                        path,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                    )
                    try:
                        os.write(descriptor, (identity + "\n").encode("ascii"))
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    created.append(path)
                directory = os.open(self.root, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            except BaseException:
                for path in created:
                    path.unlink(missing_ok=True)
                directory = os.open(self.root, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
                raise
        return run_identities
