"""Local aggregation of independently signed Windows token captures.

The worker supplies raw token facts only. This controller derives transition
semantics from a complete target/control matrix and consumes every run nonce
only after all signatures, bindings, uniqueness checks, and controls pass.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from .ssh_authorization import (
    canonical_signed_material,
    sign_ssh_material,
    verify_ssh_signature,
)
from .windows_scope import WindowsScope
from .windows_token_capture import (
    ExclusiveFileNonceLedger,
    ProductionWindowsTokenSnapshot,
    WindowsTokenCapture,
)
from .windows_token_runner import (
    LPAC_CAMPAIGN_SCHEMA_VERSION,
    WindowsTokenCampaign,
    WindowsTokenExecutionGrant,
    WindowsTokenWorkerAcceptance,
    validate_windows_witness_user_sid,
)

_MAX_UNPRIVILEGED_IL = 0x2100
_HIGH_IL = 0x3000
_SYSTEM_IL = 0x4000
_SYSTEM_SID = "S-1-5-18"
EVIDENCE_SCHEMA_VERSION = "0verse.windows-token-evidence/v2"
EVIDENCE_SIGNATURE_NAMESPACE = "0verse-windows-token-evidence"
DEFAULT_EVIDENCE_ALLOWED_SIGNERS = Path(
    "/etc/0verse/windows-token-evidence.allowed_signers"
)
_EVIDENCE_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "campaign_sha256",
        "scope_manifest_sha256",
        "execution_grant_sha256",
        "worker_acceptance_sha256",
        "campaign_id",
        "worker",
        "build_lab_ex",
        "witness_user_sid",
        "witness_session_id",
        "witness_authentication_id",
        "witness_executable_sha256",
        "starting_context",
        "finishing_principal",
        "trials",
        "target_confirmations",
        "clean_controls",
        "capture_sha256",
        "ledger_entry",
        "weaponization",
        "auto_disclosure",
        "human_report_gate",
        "signed_by",
        "signature_ssh",
    }
)
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
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


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_windows_token_evidence_receipt(
    path: str | Path, *, allowed_signers: str | Path | None = None
) -> tuple[dict[str, object], str]:
    source = Path(path)
    if source.is_symlink():
        raise ValueError("Windows token evidence receipt cannot be a symlink")
    descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 4 * 1024 * 1024:
            raise ValueError("Windows token evidence receipt must be bounded and regular")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            data = stream.read(4 * 1024 * 1024 + 1)
        if len(data) > 4 * 1024 * 1024:
            raise ValueError("Windows token evidence receipt exceeds the size limit")
    finally:
        os.close(descriptor)
    raw = json.loads(data, object_pairs_hook=_unique_object)
    if not isinstance(raw, dict) or set(raw) != _EVIDENCE_FIELDS:
        raise ValueError("Windows token evidence receipt fields are invalid")
    if raw["schema_version"] != EVIDENCE_SCHEMA_VERSION or raw["status"] != "AGGREGATED":
        raise ValueError("Windows token evidence receipt schema or status is invalid")
    if (
        raw["weaponization"] is not False
        or raw["auto_disclosure"] is not False
        or raw["human_report_gate"] is not True
    ):
        raise ValueError("Windows token evidence safety gates are invalid")
    for name in (
        "campaign_sha256",
        "scope_manifest_sha256",
        "execution_grant_sha256",
        "worker_acceptance_sha256",
    ):
        if not isinstance(raw[name], str) or _SHA256.fullmatch(raw[name]) is None:
            raise ValueError(f"Windows token evidence {name} is invalid")
    for name in (
        "campaign_id",
        "worker",
        "build_lab_ex",
        "starting_context",
        "finishing_principal",
    ):
        if not isinstance(raw[name], str) or not raw[name] or len(raw[name]) > 256:
            raise ValueError(f"Windows token evidence {name} is invalid")
    for name in ("trials", "target_confirmations", "clean_controls"):
        if isinstance(raw[name], bool) or not isinstance(raw[name], int) or raw[name] < 0:
            raise ValueError(f"Windows token evidence {name} is invalid")
    session_id = raw["witness_session_id"]
    if (
        isinstance(session_id, bool)
        or not isinstance(session_id, int)
        or not 0 <= session_id < 2**32
    ):
        raise ValueError("Windows token evidence witness_session_id is invalid")
    if not isinstance(raw["witness_executable_sha256"], str) or _SHA256.fullmatch(
        raw["witness_executable_sha256"]
    ) is None:
        raise ValueError("Windows token evidence witness_executable_sha256 is invalid")
    witness_user_sid = raw["witness_user_sid"]
    witness_authentication_id = raw["witness_authentication_id"]
    if not isinstance(witness_user_sid, str):
        raise ValueError("Windows token evidence witness_user_sid is invalid")
    validate_windows_witness_user_sid(witness_user_sid)
    if (
        not isinstance(witness_authentication_id, str)
        or _AUTHENTICATION_ID.fullmatch(witness_authentication_id) is None
        or int(witness_authentication_id, 16) <= 0x3E7
    ):
        raise ValueError("Windows token evidence witness_authentication_id is invalid")
    trials = raw["trials"]
    if raw["clean_controls"] != trials or raw["target_confirmations"] > trials:
        raise ValueError("Windows token evidence derived counts are inconsistent")
    for name in ("capture_sha256", "ledger_entry"):
        values = raw[name]
        if (
            not isinstance(values, list)
            or len(values) != trials * 2
            or len(values) != len(set(values))
            or any(
                not isinstance(value, str) or _SHA256.fullmatch(value) is None
                for value in values
            )
        ):
            raise ValueError(f"Windows token evidence {name} is invalid")
    signed_by = raw["signed_by"]
    signature = raw["signature_ssh"]
    if not isinstance(signed_by, str) or not isinstance(signature, str):
        raise ValueError("Windows token evidence signature fields are invalid")
    policy = (
        Path(allowed_signers)
        if allowed_signers is not None
        else DEFAULT_EVIDENCE_ALLOWED_SIGNERS
    )
    verify_ssh_signature(
        canonical_signed_material(raw),
        signature,
        identity=signed_by,
        namespace=EVIDENCE_SIGNATURE_NAMESPACE,
        allowed_signers=policy,
        label="Windows token evidence receipt",
        require_trusted_policy=allowed_signers is None,
    )
    return raw, hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class WindowsTokenEvidence:
    campaign_sha256: str
    scope_manifest_sha256: str
    execution_grant_sha256: str
    worker_acceptance_sha256: str
    campaign_id: str
    worker: str
    build_lab_ex: str
    witness_user_sid: str
    witness_session_id: int
    witness_authentication_id: str
    witness_executable_sha256: str
    starting_context: str
    finishing_principal: str
    trials: int
    target_confirmations: int
    clean_controls: int
    capture_sha256: tuple[str, ...]
    ledger_entry: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "campaign_sha256": self.campaign_sha256,
            "scope_manifest_sha256": self.scope_manifest_sha256,
            "execution_grant_sha256": self.execution_grant_sha256,
            "worker_acceptance_sha256": self.worker_acceptance_sha256,
            "campaign_id": self.campaign_id,
            "worker": self.worker,
            "build_lab_ex": self.build_lab_ex,
            "witness_user_sid": self.witness_user_sid,
            "witness_session_id": self.witness_session_id,
            "witness_authentication_id": self.witness_authentication_id,
            "witness_executable_sha256": self.witness_executable_sha256,
            "starting_context": self.starting_context,
            "finishing_principal": self.finishing_principal,
            "trials": self.trials,
            "target_confirmations": self.target_confirmations,
            "clean_controls": self.clean_controls,
            "capture_sha256": list(self.capture_sha256),
            "ledger_entry": list(self.ledger_entry),
            "weaponization": False,
            "auto_disclosure": False,
            "human_report_gate": True,
        }

    def signed_receipt(
        self, *, signed_by: str, signing_key: str | Path
    ) -> dict[str, object]:
        if (
            not signed_by
            or signed_by != signed_by.strip()
            or len(signed_by) > 256
            or any(ord(character) < 0x20 for character in signed_by)
        ):
            raise ValueError("Windows token evidence signer is invalid")
        receipt: dict[str, object] = {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "status": "AGGREGATED",
            **self.to_dict(),
            "signed_by": signed_by,
            "signature_ssh": "",
        }
        receipt["signature_ssh"] = sign_ssh_material(
            canonical_signed_material(receipt),
            signing_key=signing_key,
            namespace=EVIDENCE_SIGNATURE_NAMESPACE,
            label="Windows token evidence receipt",
        )
        return receipt


@dataclass(frozen=True)
class WindowsTokenObservation:
    """Neutral derivation of one complete target/control token matrix."""

    evidence: WindowsTokenEvidence
    clean_target_no_transitions: int
    ambiguous_targets: int

    @property
    def target_confirmations(self) -> int:
        return self.evidence.target_confirmations

    @property
    def clean_controls(self) -> int:
        return self.evidence.clean_controls


def _unprivileged(token: ProductionWindowsTokenSnapshot) -> bool:
    return (
        token.integrity_rid <= _MAX_UNPRIVILEGED_IL
        and not token.elevated
        and token.elevation_type != "full"
        and token.admin_group != "enabled"
        and not (_DANGEROUS_PRIVILEGES & set(token.enabled_privileges))
    )


def _valid_context(token: ProductionWindowsTokenSnapshot, context: str) -> bool:
    if not _unprivileged(token):
        return False
    if context == "standard-user":
        return not token.app_container and token.restricted_sid_count == 0
    if context == "appcontainer":
        return token.app_container
    return (
        token.app_container
        and token.less_privileged_app_container
        and bool(token.app_container_sid)
    )


def _clean_control(capture: WindowsTokenCapture, context: str) -> bool:
    basic = (
        _valid_context(capture.start_token, context)
        and _valid_context(capture.finish_token, context)
        and capture.finish_token.user_sid == capture.start_token.user_sid
        and capture.finish_token.app_container == capture.start_token.app_container
        and capture.finish_token.restricted_sid_count
        == capture.start_token.restricted_sid_count
        and capture.finish_token.less_privileged_app_container
        == capture.start_token.less_privileged_app_container
    )
    if not basic or context != "eligible-sandbox":
        return basic
    start = capture.start_token
    finish = capture.finish_token
    return (
        finish.integrity_rid == start.integrity_rid
        and finish.elevation_type == start.elevation_type
        and finish.elevated == start.elevated
        and finish.admin_group == start.admin_group
        and finish.enabled_privileges == start.enabled_privileges
        and finish.token_source == start.token_source
        and finish.session_id == start.session_id
        and finish.authentication_id == start.authentication_id
        and finish.app_container_sid == start.app_container_sid
        and finish.statistics_token_id_before == start.statistics_token_id_before
        and finish.statistics_token_id_after == start.statistics_token_id_after
        and finish.modified_id_before == start.modified_id_before
        and finish.modified_id_after == start.modified_id_after
    )


def _target_transition(capture: WindowsTokenCapture, principal: str) -> bool:
    start = capture.start_token
    finish = capture.finish_token
    if principal == "elevated-user":
        return (
            finish.user_sid == start.user_sid
            and finish.integrity_rid >= _HIGH_IL
            and finish.elevated
            and finish.elevation_type == "full"
            and finish.admin_group == "enabled"
            and not finish.app_container
            and finish.restricted_sid_count == 0
        )
    return (
        finish.user_sid == _SYSTEM_SID
        and finish.integrity_rid >= _SYSTEM_IL
        and finish.elevated
        and finish.elevation_type == "default"
        and not finish.app_container
        and finish.restricted_sid_count == 0
    )


def derive_windows_token_ledger_entries(
    grant_nonce: str, run_nonces: tuple[str, ...]
) -> tuple[str, ...]:
    """Derive the stable per-run ledger identities without consuming state."""
    nonce = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
    if (
        nonce.fullmatch(grant_nonce) is None
        or not run_nonces
        or len(run_nonces) != len(set(run_nonces))
        or any(nonce.fullmatch(value) is None or value == grant_nonce for value in run_nonces)
    ):
        raise ValueError("Windows token ledger inputs are invalid")
    return tuple(
        hashlib.sha256(
            b"0verse-windows-token-ledger-v1\0"
            + grant_nonce.encode("ascii")
            + b"\0"
            + run_nonce.encode("ascii")
        ).hexdigest()
        for run_nonce in run_nonces
    )


def derive_windows_token_grant_ledger_entry(
    grant_nonce: str, campaign_sha256: str
) -> str:
    """Derive the stable single-use grant identity without consuming state."""
    nonce = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
    sha256 = re.compile(r"^[0-9a-f]{64}$")
    if nonce.fullmatch(grant_nonce) is None or sha256.fullmatch(campaign_sha256) is None:
        raise ValueError("Windows token grant ledger inputs are invalid")
    return hashlib.sha256(
        b"0verse-windows-token-grant-once-v1\0"
        + grant_nonce.encode("ascii")
        + b"\0"
        + campaign_sha256.encode("ascii")
    ).hexdigest()


def observe_windows_token_evidence(
    captures: list[WindowsTokenCapture],
    campaign: WindowsTokenCampaign,
    campaign_sha256: str,
    scope: WindowsScope,
    scope_sha256: str,
    grant: WindowsTokenExecutionGrant,
    grant_sha256: str,
    acceptance: WindowsTokenWorkerAcceptance,
    acceptance_sha256: str,
) -> WindowsTokenObservation:
    """Validate and neutrally classify a matrix without applying a claim threshold."""

    campaign.require_source_binding(campaign_sha256)
    grant.require_binding(campaign, campaign_sha256, scope, scope_sha256, grant_sha256)
    acceptance.require_binding(
        campaign,
        campaign_sha256,
        scope,
        scope_sha256,
        grant,
        grant_sha256,
        acceptance_sha256,
    )
    expected = {
        (case, trial)
        for case in ("target", "control")
        for trial in range(1, campaign.trials + 1)
    }
    indexed = {(capture.case, capture.trial): capture for capture in captures}
    if len(indexed) != len(captures) or set(indexed) != expected:
        raise ValueError("Windows token evidence must contain one complete target/control matrix")

    uniqueness = (
        [capture.run_nonce for capture in captures],
        [capture.capture_nonce for capture in captures],
        [capture.process_instance_id for capture in captures],
        [capture.source_sha256 for capture in captures],
        [capture.start_token.token_id for capture in captures],
        [capture.finish_token.token_id for capture in captures],
    )
    if any(len(values) != len(set(values)) for values in uniqueness):
        raise ValueError("Windows token evidence contains reused per-run identities")

    target_confirmations = 0
    clean_target_no_transitions = 0
    ambiguous_targets = 0
    clean_controls = 0
    ordered: list[WindowsTokenCapture] = []
    for trial in range(1, campaign.trials + 1):
        for case in ("target", "control"):
            capture = indexed[(case, trial)]
            capture.require_binding(
                campaign,
                campaign_sha256,
                scope,
                scope_sha256,
                grant,
                grant_sha256,
                acceptance,
                acceptance_sha256,
                expected_case=case,
                expected_trial=trial,
                expected_run_nonce=capture.run_nonce,
            )
            if not _valid_context(capture.start_token, campaign.starting_context):
                raise ValueError("Windows token evidence start context is not eligible")
            if case == "control":
                if not _clean_control(capture, campaign.starting_context):
                    raise ValueError("Windows token evidence control is not clean")
                clean_controls += 1
            elif _target_transition(capture, campaign.finishing_principal):
                target_confirmations += 1
            elif _clean_control(capture, campaign.starting_context):
                clean_target_no_transitions += 1
            else:
                ambiguous_targets += 1
            ordered.append(capture)

    if clean_controls != campaign.trials:
        raise ValueError("Windows token evidence lacks clean controls")

    ledger_entries = derive_windows_token_ledger_entries(
        grant.nonce, tuple(capture.run_nonce for capture in ordered)
    )
    evidence = WindowsTokenEvidence(
        campaign_sha256=campaign_sha256,
        scope_manifest_sha256=scope_sha256,
        execution_grant_sha256=grant_sha256,
        worker_acceptance_sha256=acceptance_sha256,
        campaign_id=campaign.campaign_id,
        worker=campaign.worker,
        build_lab_ex=scope.preflight_build_lab_ex,
        witness_user_sid=acceptance.witness_user_sid,
        witness_session_id=acceptance.witness_session_id,
        witness_authentication_id=acceptance.witness_authentication_id,
        witness_executable_sha256=acceptance.witness_executable_sha256,
        starting_context=campaign.starting_context,
        finishing_principal=campaign.finishing_principal,
        trials=campaign.trials,
        target_confirmations=target_confirmations,
        clean_controls=clean_controls,
        capture_sha256=tuple(capture.source_sha256 for capture in ordered),
        ledger_entry=ledger_entries,
    )
    if campaign.schema_version == LPAC_CAMPAIGN_SCHEMA_VERSION:
        raise ValueError(
            "eligible-sandbox aggregation is disabled until the native authenticated "
            "external LPAC witness capability is implemented"
        )
    return WindowsTokenObservation(
        evidence=evidence,
        clean_target_no_transitions=clean_target_no_transitions,
        ambiguous_targets=ambiguous_targets,
    )


def derive_windows_token_evidence(
    captures: list[WindowsTokenCapture],
    campaign: WindowsTokenCampaign,
    campaign_sha256: str,
    scope: WindowsScope,
    scope_sha256: str,
    grant: WindowsTokenExecutionGrant,
    grant_sha256: str,
    acceptance: WindowsTokenWorkerAcceptance,
    acceptance_sha256: str,
) -> WindowsTokenEvidence:
    """Preserve the strict candidate-evidence threshold used by existing callers."""
    observation = observe_windows_token_evidence(
        captures,
        campaign,
        campaign_sha256,
        scope,
        scope_sha256,
        grant,
        grant_sha256,
        acceptance,
        acceptance_sha256,
    )
    if observation.target_confirmations < campaign.minimum_confirmations:
        raise ValueError("Windows token evidence lacks the required target confirmations")
    return observation.evidence


def aggregate_windows_token_evidence(
    captures: list[WindowsTokenCapture],
    campaign: WindowsTokenCampaign,
    campaign_sha256: str,
    scope: WindowsScope,
    scope_sha256: str,
    grant: WindowsTokenExecutionGrant,
    grant_sha256: str,
    acceptance: WindowsTokenWorkerAcceptance,
    acceptance_sha256: str,
    ledger: ExclusiveFileNonceLedger,
) -> WindowsTokenEvidence:
    """Derive evidence, then atomically consume the grant and every run nonce."""
    evidence = derive_windows_token_evidence(
        captures,
        campaign,
        campaign_sha256,
        scope,
        scope_sha256,
        grant,
        grant_sha256,
        acceptance,
        acceptance_sha256,
    )
    consumed = ledger.consume_batch(
        grant.nonce,
        tuple(capture.run_nonce for capture in captures),
        campaign_sha256=campaign_sha256,
    )
    if set(consumed) != set(evidence.ledger_entry):
        raise AssertionError("nonce ledger identities differ from derived evidence")
    return evidence


def aggregate_windows_token_observation(
    captures: list[WindowsTokenCapture],
    campaign: WindowsTokenCampaign,
    campaign_sha256: str,
    scope: WindowsScope,
    scope_sha256: str,
    grant: WindowsTokenExecutionGrant,
    grant_sha256: str,
    acceptance: WindowsTokenWorkerAcceptance,
    acceptance_sha256: str,
    ledger: ExclusiveFileNonceLedger,
) -> WindowsTokenObservation:
    """Neutrally derive a complete matrix, then consume its replay identities.

    Unlike :func:`aggregate_windows_token_evidence`, this path deliberately
    does not apply the candidate-side minimum-confirmation threshold.  It is
    therefore suitable for both a candidate matrix and the required clean
    fixed-build matrix.  Signature, authority, control, uniqueness, and
    consume-once checks remain identical.
    """
    observation = observe_windows_token_evidence(
        captures,
        campaign,
        campaign_sha256,
        scope,
        scope_sha256,
        grant,
        grant_sha256,
        acceptance,
        acceptance_sha256,
    )
    consumed = ledger.consume_batch(
        grant.nonce,
        tuple(capture.run_nonce for capture in captures),
        campaign_sha256=campaign_sha256,
    )
    if set(consumed) != set(observation.evidence.ledger_entry):
        raise AssertionError("nonce ledger identities differ from derived evidence")
    return observation
