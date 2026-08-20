"""Fail-closed evidence classification for the Microsoft Windows bounty.

This module classifies retained evidence against public program requirements. It
does not decide bounty eligibility, predict an award, submit a report, or run a
proof of concept. Those decisions remain with Microsoft and a human reviewer.
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
from .windows_token_pack import WindowsTokenPackVerification

CLASSIFICATION_SCHEMA_VERSION = "0verse.windows-bounty-classification/v2"
LOCAL_EVIDENCE_SCHEMA_VERSION = "0verse.windows-local-attack-scenario-evidence/v2"
LOCAL_EVIDENCE_SIGNATURE_NAMESPACE = "0verse-windows-local-attack-scenario-evidence"
DEFAULT_LOCAL_EVIDENCE_ALLOWED_SIGNERS = Path(
    "/etc/0verse/windows-local-scenario-evidence.allowed_signers"
)

OFFICIAL_SCOPE_URL = (
    "https://www.microsoft.com/en-us/msrc/bounty-windows-insider-preview"
)
OFFICIAL_BUILD_SOURCE_URL = "https://learn.microsoft.com/en-us/windows-insider/flight-hub"
OFFICIAL_RULES_REVISION = "2026-06-03"
OFFICIAL_RULES_SOURCE_URL = OFFICIAL_SCOPE_URL

GENERAL_EOP = "GENERAL_EOP"
LOCAL_ATTACK_SCENARIO_SANDBOX_ESCAPE = "LOCAL_ATTACK_SCENARIO_SANDBOX_ESCAPE"
_CATEGORIES = frozenset({GENERAL_EOP, LOCAL_ATTACK_SCENARIO_SANDBOX_ESCAPE})
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_BUILD = re.compile(r"^(\d+\.\d+)\.[A-Za-z0-9_.-]+$")
_ELIGIBLE_SANDBOXES = frozenset(
    {
        "edge-chromium-renderer",
        "windows-defender-msengcp",
        "winhttp-wpad-sandboxed-process",
        "utcdecoderhost-sandboxed-process",
    }
)
_LOCAL_FIELDS = frozenset(
    {
        "schema_version",
        "pack_id",
        "scope_manifest_sha256",
        "build_lab_ex",
        "eligible_sandbox",
        "launch_app_container_executable_sha256",
        "launch_transcript_sha256",
        "launch_transcript_commitment_sha256",
        "reproduction_transcript_sha256",
        "lpac_flag",
        "lpac_start_token_observed",
        "debugger_required_to_trigger",
        "shipped_windows_application",
        "recorded_at",
        "signed_by",
        "signature_ssh",
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
        raise ValueError(f"{name} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{name} must include a timezone")
    return parsed.astimezone(UTC)


def _read_regular_nofollow(path: Path, maximum: int = 1024 * 1024) -> bytes:
    if path.is_symlink():
        raise ValueError("local scenario evidence cannot be a symlink")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise ValueError("local scenario evidence must be a bounded regular file")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("local scenario evidence exceeds the size limit")
        return data
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class WindowsLocalAttackScenarioEvidence:
    pack_id: str
    scope_manifest_sha256: str
    build_lab_ex: str
    eligible_sandbox: str
    launch_app_container_executable_sha256: str
    launch_transcript_sha256: str
    launch_transcript_commitment_sha256: str
    reproduction_transcript_sha256: str
    lpac_flag: bool
    lpac_start_token_observed: bool
    debugger_required_to_trigger: bool
    shipped_windows_application: bool
    recorded_at: str
    signed_by: str
    signature_ssh: str
    schema_version: str = LOCAL_EVIDENCE_SCHEMA_VERSION
    _signed_material: bytes = field(default=b"", repr=False, compare=False)
    _signed_record_sha256: str = field(default="", repr=False, compare=False)
    _signature_verified: bool = field(default=False, repr=False, compare=False)

    @classmethod
    def from_mapping(
        cls, raw: Mapping[str, object]
    ) -> WindowsLocalAttackScenarioEvidence:
        if set(raw) != _LOCAL_FIELDS:
            raise ValueError("local scenario evidence fields are invalid")
        boolean_fields = {
            "lpac_flag",
            "lpac_start_token_observed",
            "debugger_required_to_trigger",
            "shipped_windows_application",
        }
        if any(not isinstance(raw[name], bool) for name in boolean_fields):
            raise ValueError("local scenario evidence flags must be booleans")
        string_fields = _LOCAL_FIELDS - boolean_fields
        if any(not isinstance(raw[name], str) for name in string_fields):
            raise ValueError("local scenario evidence text fields must be strings")
        evidence = cls(**dict(raw))  # type: ignore[arg-type]
        evidence.validate()
        return evidence

    def validate(self) -> None:
        if self.schema_version != LOCAL_EVIDENCE_SCHEMA_VERSION:
            raise ValueError("unsupported local scenario evidence schema")
        for name in (
            "pack_id",
            "scope_manifest_sha256",
            "launch_app_container_executable_sha256",
            "launch_transcript_sha256",
            "launch_transcript_commitment_sha256",
            "reproduction_transcript_sha256",
        ):
            if _SHA256.fullmatch(getattr(self, name)) is None:
                raise ValueError(f"local scenario evidence {name} must be a SHA-256")
        if _BUILD.fullmatch(self.build_lab_ex) is None:
            raise ValueError("local scenario evidence BuildLabEx is invalid")
        if self.eligible_sandbox not in _ELIGIBLE_SANDBOXES:
            raise ValueError("local scenario evidence sandbox is not officially eligible")
        if not self.lpac_flag or not self.lpac_start_token_observed:
            raise ValueError("local scenario evidence must prove an LPAC launch")
        if self.debugger_required_to_trigger:
            raise ValueError("debugger-dependent reproduction is not attack-scenario evidence")
        if not self.shipped_windows_application:
            raise ValueError("attack-scenario evidence must exercise a shipped Windows application")
        recorded = _timestamp(self.recorded_at, "local scenario evidence recorded_at")
        now = datetime.now(UTC)
        if recorded > now + timedelta(minutes=5) or now - recorded > timedelta(hours=24):
            raise ValueError("local scenario evidence is outside the 24-hour window")
        if (
            not self.signed_by
            or self.signed_by != self.signed_by.strip()
            or len(self.signed_by) > 256
            or not self.signature_ssh
        ):
            raise ValueError("local scenario evidence signer fields are invalid")

    def require_signature(self) -> None:
        self.validate()
        if not self._signature_verified or not self._signed_material:
            raise ValueError("local scenario evidence requires a verified signature")
        raw = json.loads(self._signed_material, object_pairs_hook=_unique_object)
        if not isinstance(raw, dict):
            raise ValueError("signed local scenario evidence material is malformed")
        raw["signature_ssh"] = self.signature_ssh
        if self != WindowsLocalAttackScenarioEvidence.from_mapping(raw):
            raise ValueError("local scenario evidence fields differ from signed material")
        if hashlib.sha256(_canonical_record(raw)).hexdigest() != self._signed_record_sha256:
            raise ValueError("local scenario evidence signed-record commitment changed")

    @property
    def signed_record_sha256(self) -> str:
        self.require_signature()
        return self._signed_record_sha256


def _canonical_record(raw: Mapping[str, object]) -> bytes:
    """Canonicalize the complete record, including its verified SSH signature."""
    return json.dumps(
        raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def load_windows_local_attack_scenario_evidence(
    path: str | Path, *, allowed_signers: str | Path | None = None
) -> WindowsLocalAttackScenarioEvidence:
    data = _read_regular_nofollow(Path(path))
    raw = json.loads(data, object_pairs_hook=_unique_object)
    if not isinstance(raw, dict):
        raise ValueError("local scenario evidence must be a JSON object")
    evidence = WindowsLocalAttackScenarioEvidence.from_mapping(raw)
    material = canonical_signed_material(raw)
    policy = (
        Path(allowed_signers)
        if allowed_signers is not None
        else DEFAULT_LOCAL_EVIDENCE_ALLOWED_SIGNERS
    )
    verify_ssh_signature(
        material,
        evidence.signature_ssh,
        identity=evidence.signed_by,
        namespace=LOCAL_EVIDENCE_SIGNATURE_NAMESPACE,
        allowed_signers=policy,
        label="Windows local attack-scenario evidence",
        require_trusted_policy=allowed_signers is None,
    )
    return replace(
        evidence,
        _signed_material=material,
        _signed_record_sha256=hashlib.sha256(_canonical_record(raw)).hexdigest(),
        _signature_verified=True,
    )


@dataclass(frozen=True)
class WindowsBountyClassification:
    category: str
    evidence_gate: str
    pack_id: str
    scope_manifest_sha256: str
    build_lab_ex: str
    finishing_privilege: str
    maximum_award_tier_usd: int
    eligible_sandbox: str | None
    local_scenario_evidence_sha256: str | None
    sandbox_process_executable_sha256: str | None
    schema_version: str = CLASSIFICATION_SCHEMA_VERSION

    def to_dict(self) -> dict[str, object]:
        return {
            **asdict(self),
            "official_rules_source_url": OFFICIAL_RULES_SOURCE_URL,
            "official_rules_revision": OFFICIAL_RULES_REVISION,
            "program_eligibility": "MICROSOFT_DETERMINES",
            "award_determination": "MICROSOFT_DETERMINES",
            "award_tier_is_metadata_only": True,
            "accepted": False,
            "claim_eligible": False,
            "weaponization": False,
            "auto_disclosure": False,
            "human_report_gate": True,
        }


def classify_windows_bounty_evidence(
    verification: WindowsTokenPackVerification,
    *,
    category: str,
    local_evidence: WindowsLocalAttackScenarioEvidence | None = None,
) -> WindowsBountyClassification:
    """Classify verified evidence readiness without deciding eligibility or award."""
    if category not in _CATEGORIES:
        raise ValueError("unsupported Windows bounty classification category")
    if verification.scope_program != "windows-canary":
        raise ValueError("Windows bounty classification requires windows-canary scope")
    if verification.scope_url.rstrip("/") != OFFICIAL_SCOPE_URL:
        raise ValueError("Windows bounty scope is not bound to the official program source")
    if verification.latest_build_source_url.rstrip("/") != OFFICIAL_BUILD_SOURCE_URL:
        raise ValueError("Windows build evidence is not bound to official Flight Hub")
    match = _BUILD.fullmatch(verification.build_lab_ex)
    if match is None or match.group(1) != verification.latest_build_number:
        raise ValueError("BuildLabEx does not exactly match the officially verified build")
    verified_at = _timestamp(
        verification.latest_build_verified_at, "latest-build verification"
    )
    latest_build_age = datetime.now(UTC) - verified_at
    if latest_build_age < timedelta(0) or latest_build_age > timedelta(hours=24):
        raise ValueError("official latest-build verification is stale")
    if verification.target_confirmations < verification.minimum_confirmations:
        raise ValueError("token pack lacks the required transition confirmations")
    if verification.clean_controls != verification.trials:
        raise ValueError("token pack lacks clean controls")

    finishing_privilege = {
        "elevated-user": "HIGH_IL",
        "local-system": "SYSTEM_IL",
    }.get(verification.finishing_principal)
    if finishing_privilege is None:
        raise ValueError("finishing privilege has no Windows general-EoP tier metadata")

    if category == GENERAL_EOP:
        if local_evidence is not None:
            raise ValueError("general EoP classification does not accept local-scenario evidence")
        return WindowsBountyClassification(
            category=category,
            evidence_gate="GENERAL_EOP_EVIDENCE_READY",
            pack_id=verification.pack_id,
            scope_manifest_sha256=verification.scope_manifest_sha256,
            build_lab_ex=verification.build_lab_ex,
            finishing_privilege=finishing_privilege,
            maximum_award_tier_usd=8000,
            eligible_sandbox=None,
            local_scenario_evidence_sha256=None,
            sandbox_process_executable_sha256=None,
        )

    if verification.starting_context != "eligible-sandbox":
        raise ValueError("local Attack Scenario requires an eligible-sandbox campaign")
    if not verification.all_start_tokens_lpac:
        raise ValueError("local Attack Scenario requires LPAC in every verified start token")
    if local_evidence is None:
        raise ValueError("local Attack Scenario requires signed LPAC launch evidence")
    local_evidence.require_signature()
    if (
        local_evidence.pack_id != verification.pack_id
        or local_evidence.scope_manifest_sha256 != verification.scope_manifest_sha256
        or local_evidence.build_lab_ex != verification.build_lab_ex
    ):
        raise ValueError("local scenario evidence is not bound to the verified token pack")
    if (
        local_evidence.eligible_sandbox != verification.eligible_sandbox
        or local_evidence.launch_app_container_executable_sha256
        != verification.launch_app_container_executable_sha256
        or local_evidence.launch_transcript_commitment_sha256
        != verification.launch_transcript_commitment_sha256
        or _SHA256.fullmatch(verification.sandbox_process_executable_sha256) is None
    ):
        raise ValueError("local scenario evidence differs from pack-derived LPAC provenance")
    if local_evidence.signed_by != verification.capture_signer_identity:
        raise ValueError("local scenario evidence signer is not the authorized capture signer")
    evidence_digest = local_evidence.signed_record_sha256
    return WindowsBountyClassification(
        category=category,
        evidence_gate="LOCAL_ATTACK_SCENARIO_EVIDENCE_READY",
        pack_id=verification.pack_id,
        scope_manifest_sha256=verification.scope_manifest_sha256,
        build_lab_ex=verification.build_lab_ex,
        finishing_privilege=finishing_privilege,
        maximum_award_tier_usd=30000,
        eligible_sandbox=local_evidence.eligible_sandbox,
        local_scenario_evidence_sha256=evidence_digest,
        sandbox_process_executable_sha256=(
            verification.sandbox_process_executable_sha256
        ),
    )
