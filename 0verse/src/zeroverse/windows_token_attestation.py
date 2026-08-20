"""Non-claim fixture contract for future Windows token capture.

This module proves only strict parsing, canonicalization, and safe retention of
one per-run record. It deliberately has no live verifier. Production evidence
must come from the signed Windows runner tracked separately from Hyper-V.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "0verse.windows-token-capture/v1"
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_TOKEN_ID = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_SID = re.compile(r"^S-1-(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*)){1,15}$")
_PRIVILEGE = re.compile(r"^Se[A-Za-z0-9]+Privilege$")
_HARMLESS_FIXTURE_PRIVILEGES = frozenset({"SeChangeNotifyPrivilege"})


def _exact(raw: object, keys: set[str], name: str) -> dict[str, object]:
    if not isinstance(raw, dict) or set(raw) != keys:
        raise ValueError(f"{name} must contain exactly: {', '.join(sorted(keys))}")
    return raw


def _text(value: object, name: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 0x20 for character in value)
    ):
        raise ValueError(f"{name} must be bounded, non-empty, trimmed text")
    return value


def _count(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


@dataclass(frozen=True)
class WindowsTokenSnapshot:
    token_id: str
    user_sid: str
    integrity_rid: int
    elevation_type: str
    elevated: bool
    admin_group: str
    app_container: bool
    restricted_sid_count: int
    enabled_privileges: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: object, name: str) -> WindowsTokenSnapshot:
        raw = _exact(
            value,
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
            },
            name,
        )
        token_id = _text(raw["token_id"], f"{name}.token_id", 128)
        user_sid = _text(raw["user_sid"], f"{name}.user_sid", 256)
        if not _TOKEN_ID.fullmatch(token_id) or not _SID.fullmatch(user_sid):
            raise ValueError(f"{name} has an invalid token identity or SID")
        elevation_type = _text(raw["elevation_type"], f"{name}.elevation_type", 16)
        admin_group = _text(raw["admin_group"], f"{name}.admin_group", 16)
        if elevation_type not in {"default", "limited", "full"}:
            raise ValueError(f"{name}.elevation_type is invalid")
        if admin_group not in {"absent", "deny-only", "enabled"}:
            raise ValueError(f"{name}.admin_group is invalid")
        if not isinstance(raw["elevated"], bool) or not isinstance(raw["app_container"], bool):
            raise ValueError(f"{name} boolean token facts are invalid")
        privileges = raw["enabled_privileges"]
        if not isinstance(privileges, list) or len(privileges) > 128:
            raise ValueError(f"{name}.enabled_privileges must be a bounded list")
        normalized = tuple(_text(item, f"{name}.enabled_privileges", 128) for item in privileges)
        if len(set(normalized)) != len(normalized) or any(
            not _PRIVILEGE.fullmatch(item) for item in normalized
        ):
            raise ValueError(f"{name}.enabled_privileges is malformed or duplicated")
        return cls(
            token_id=token_id,
            user_sid=user_sid,
            integrity_rid=_count(raw["integrity_rid"], f"{name}.integrity_rid"),
            elevation_type=elevation_type,
            elevated=raw["elevated"],
            admin_group=admin_group,
            app_container=raw["app_container"],
            restricted_sid_count=_count(
                raw["restricted_sid_count"], f"{name}.restricted_sid_count"
            ),
            enabled_privileges=normalized,
        )

    def to_dict(self) -> dict[str, object]:
        row = asdict(self)
        row["enabled_privileges"] = list(self.enabled_privileges)
        return row


@dataclass(frozen=True)
class WindowsTokenCaptureContract:
    build_lab_ex: str
    campaign_id: str
    worker: str
    campaign_sha256: str
    scope_manifest_sha256: str
    worker_acceptance_sha256: str
    capture_nonce: str
    worker_acceptance_nonce: str
    execution_grant_nonce: str
    run_nonce: str
    case: str
    trial: int
    start_token: WindowsTokenSnapshot
    finish_token: WindowsTokenSnapshot
    claim_eligible: bool
    fixture: bool
    weaponization: bool
    auto_disclosure: bool
    schema_version: str = SCHEMA_VERSION

    @classmethod
    def from_mapping(cls, value: object) -> WindowsTokenCaptureContract:
        raw = _exact(
            value,
            {
                "schema_version",
                "build_lab_ex",
                "campaign_id",
                "worker",
                "campaign_sha256",
                "scope_manifest_sha256",
                "worker_acceptance_sha256",
                "capture_nonce",
                "worker_acceptance_nonce",
                "execution_grant_nonce",
                "run_nonce",
                "case",
                "trial",
                "start_token",
                "finish_token",
                "claim_eligible",
                "fixture",
                "weaponization",
                "auto_disclosure",
            },
            "Windows token capture contract",
        )
        if raw["schema_version"] != SCHEMA_VERSION:
            raise ValueError("unsupported Windows token capture schema")
        for name in ("claim_eligible", "fixture", "weaponization", "auto_disclosure"):
            if not isinstance(raw[name], bool):
                raise ValueError(f"{name} must be boolean")
        if raw["fixture"] is not True or raw["claim_eligible"] is not False:
            raise ValueError("only non-claim Windows token contract fixtures are accepted")
        if raw["weaponization"] is not False or raw["auto_disclosure"] is not False:
            raise ValueError("Windows token contracts forbid weaponization and auto disclosure")
        digests = {
            name: _text(raw[name], name, 64)
            for name in (
                "campaign_sha256",
                "scope_manifest_sha256",
                "worker_acceptance_sha256",
            )
        }
        if any(not _SHA256.fullmatch(value) for value in digests.values()):
            raise ValueError("Windows token contract digest is malformed")
        nonces = {
            name: _text(raw[name], name, 128)
            for name in (
                "capture_nonce",
                "worker_acceptance_nonce",
                "execution_grant_nonce",
                "run_nonce",
            )
        }
        if any(not _NONCE.fullmatch(value) for value in nonces.values()):
            raise ValueError("Windows token contract nonce is malformed")
        if len(set(nonces.values())) != len(nonces):
            raise ValueError("Windows token contract nonces must be distinct")
        case = _text(raw["case"], "case", 16)
        if case not in {"target", "control"}:
            raise ValueError("case must be target or control")
        start = WindowsTokenSnapshot.from_mapping(raw["start_token"], "start_token")
        finish = WindowsTokenSnapshot.from_mapping(raw["finish_token"], "finish_token")
        if start.token_id == finish.token_id:
            raise ValueError("token capture identities must be distinct")
        for name, token in (("start", start), ("finish", finish)):
            if (
                token.integrity_rid > 0x2100
                or token.elevated
                or token.elevation_type == "full"
                or token.admin_group == "enabled"
                or not set(token.enabled_privileges).issubset(_HARMLESS_FIXTURE_PRIVILEGES)
            ):
                raise ValueError(f"harmless fixture {name} token must remain unprivileged")
        trial = _count(raw["trial"], "trial")
        if trial < 1:
            raise ValueError("trial must be a positive integer")
        return cls(
            schema_version=SCHEMA_VERSION,
            build_lab_ex=_text(raw["build_lab_ex"], "build_lab_ex"),
            campaign_id=_text(raw["campaign_id"], "campaign_id"),
            worker=_text(raw["worker"], "worker"),
            campaign_sha256=digests["campaign_sha256"],
            scope_manifest_sha256=digests["scope_manifest_sha256"],
            worker_acceptance_sha256=digests["worker_acceptance_sha256"],
            capture_nonce=nonces["capture_nonce"],
            worker_acceptance_nonce=nonces["worker_acceptance_nonce"],
            execution_grant_nonce=nonces["execution_grant_nonce"],
            run_nonce=nonces["run_nonce"],
            case=case,
            trial=trial,
            start_token=start,
            finish_token=finish,
            claim_eligible=False,
            fixture=True,
            weaponization=False,
            auto_disclosure=False,
        )

    def to_dict(self) -> dict[str, object]:
        row = asdict(self)
        row["start_token"] = self.start_token.to_dict()
        row["finish_token"] = self.finish_token.to_dict()
        return row


@dataclass(frozen=True)
class VerifiedWindowsTokenContractFixture:
    contract: WindowsTokenCaptureContract
    canonical_bytes: bytes
    sha256: str


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_regular_nofollow(path: Path, maximum: int = 1024 * 1024) -> bytes:
    if path.is_symlink():
        raise OSError("Windows token contract symlinks are forbidden")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise ValueError("Windows token contract must be a bounded regular file")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("Windows token contract exceeds the size limit")
        return data
    finally:
        os.close(descriptor)


def load_windows_token_contract_fixture(
    path: str | Path,
) -> VerifiedWindowsTokenContractFixture:
    raw_bytes = _read_regular_nofollow(Path(path))
    raw = json.loads(raw_bytes, object_pairs_hook=_reject_duplicate_keys)
    contract = WindowsTokenCaptureContract.from_mapping(raw)
    canonical = (json.dumps(contract.to_dict(), indent=2, sort_keys=True) + "\n").encode()
    return VerifiedWindowsTokenContractFixture(
        contract=contract,
        canonical_bytes=canonical,
        sha256=hashlib.sha256(canonical).hexdigest(),
    )


def retain_windows_token_contract_fixture(
    verified: VerifiedWindowsTokenContractFixture,
    destination: str | Path,
) -> tuple[Path, str]:
    output = Path(destination)
    with output.open("xb") as stream:
        stream.write(verified.canonical_bytes)
    retained = _read_regular_nofollow(output)
    digest = hashlib.sha256(retained).hexdigest()
    if retained != verified.canonical_bytes or digest != verified.sha256:
        raise ValueError("retained Windows token contract changed while writing")
    return output, digest
