from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

import zeroverse.macho_campaign as macho_campaign
from zeroverse.macho_campaign import (
    ACCEPTANCE_SCHEMA_VERSION,
    CAMPAIGN_SCHEMA_VERSION,
    RECEIPT_SCHEMA_VERSION,
    DarwinWorkerAcceptance,
    MachOCampaign,
    MachOCampaignReceipt,
    MachOIdentity,
    load_campaign,
    load_receipt,
    macho_identity_commitment,
)

NOW = datetime(2026, 7, 15, 12, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[1]
TARGET_SHA = hashlib.sha256(b"target-macho").hexdigest()
CONTROL_SHA = hashlib.sha256(b"control-macho").hexdigest()
INPUT_SHA = hashlib.sha256(b"input").hexdigest()
TARGET_UUID = "11111111-2222-3333-4444-555555555555"
CONTROL_UUID = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
KERNEL_UUID = "12345678-ABCD-EF01-2345-6789ABCDEF01"
AUTH_KEY = hashlib.sha256(b"/etc/0verse/macho-authorization.allowed_signers").hexdigest()
ACCEPT_KEY = hashlib.sha256(b"/etc/0verse/macho-worker-acceptance.allowed_signers").hexdigest()
TARGET_KEY = hashlib.sha256(b"/etc/0verse/macho-target-observation.allowed_signers").hexdigest()
CONTROL_KEY = hashlib.sha256(b"/etc/0verse/macho-control-observation.allowed_signers").hexdigest()


@pytest.fixture(autouse=True)
def trusted_test_signatures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("zeroverse.macho_campaign.verify_ssh_signature", lambda *a, **k: None)
    monkeypatch.setattr(
        "zeroverse.macho_campaign._FIXTURE_TRUST",
        {
            "authorization": (Path("/fixture/authorization"), "1" * 64, AUTH_KEY),
            "acceptance": (Path("/fixture/acceptance"), "2" * 64, ACCEPT_KEY),
            "target": (Path("/fixture/target"), "3" * 64, TARGET_KEY),
            "control": (Path("/fixture/control"), "4" * 64, CONTROL_KEY),
        },
    )


def iso(delta: timedelta) -> str:
    return (NOW + delta).isoformat()


def artifact(path: str, data: bytes) -> dict[str, object]:
    return {"path": path, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def macho(role: str) -> dict[str, object]:
    target = role == "target"
    return {
        "path": f"/System/Library/Extensions/Test.kext/Contents/MacOS/Test-{role}",
        "sha256": TARGET_SHA if target else CONTROL_SHA,
        "macho_uuid": TARGET_UUID if target else CONTROL_UUID,
        "code_signature_sha256": ("3" if target else "4") * 64,
        "cdhash": ("5" if target else "6") * 40,
        "signing_identifier": "com.apple.driver.Test",
        "team_identifier": "APPLECOMPUTER",
        "architecture": "arm64e",
        "product_name": "macOS",
        "product_version": "26.0" if target else "15.6",
        "product_build": "25A123" if target else "24G90",
    }


def identity_commitment(role: str) -> str:
    return macho_identity_commitment(MachOIdentity.from_mapping(macho(role), role))


def acceptance(**updates: object) -> dict[str, object]:
    raw: dict[str, object] = {
        "schema_version": ACCEPTANCE_SCHEMA_VERSION,
        "acceptance_id": "macho-worker-acceptance-001",
        "campaign_id": "macho-contract-test-001",
        "coordinator": "fixture-macho-coordinator-01",
        "worker": "fixture-darwin-worker-01",
        "role": "darwin-native-observer",
        "hardware_model": "Mac14,12",
        "architecture": "arm64e",
        "os_product_version": "26.0",
        "os_build": "25A123",
        "kernel_uuid": KERNEL_UUID,
        "target_sha256": TARGET_SHA,
        "target_uuid": TARGET_UUID,
        "control_sha256": CONTROL_SHA,
        "control_uuid": CONTROL_UUID,
        "target_identity_sha256": identity_commitment("target"),
        "control_identity_sha256": identity_commitment("control"),
        "input_model": "bounded IOKit external-method selector and structure",
        "capabilities": [
            "native-macho",
            "crash-log-capture",
            "sysdiagnose-capture",
            "process-attribution",
        ],
        "network_isolated": True,
        "coordinator_is_worker": False,
        "accepted_at": iso(timedelta(hours=-2)),
        "expires_at": iso(timedelta(days=1)),
        "accepted_by": "fixture-darwin-worker-authority",
        "authority_key_sha256": ACCEPT_KEY,
        "signature_ssh": "test-signature",
    }
    raw.update(updates)
    return raw


def manifest(acceptance_sha: str, scope: dict[str, object], **updates: object) -> dict[str, object]:
    raw: dict[str, object] = {
        "schema_version": CAMPAIGN_SCHEMA_VERSION,
        "campaign_id": "macho-contract-test-001",
        "target": macho("target"),
        "control": macho("control"),
        "coordinator": "fixture-macho-coordinator-01",
        "worker": "fixture-darwin-worker-01",
        "hardware_model": "Mac14,12",
        "worker_acceptance_path": "worker-acceptance.json",
        "worker_acceptance_sha256": acceptance_sha,
        "input_model": "bounded IOKit external-method selector and structure",
        "authorization": {
            "campaign_id": "macho-contract-test-001",
            "target_sha256": TARGET_SHA,
            "target_uuid": TARGET_UUID,
            "control_sha256": CONTROL_SHA,
            "control_uuid": CONTROL_UUID,
            "target_identity_sha256": identity_commitment("target"),
            "control_identity_sha256": identity_commitment("control"),
            "coordinator": "fixture-macho-coordinator-01",
            "worker": "fixture-darwin-worker-01",
            "hardware_model": "Mac14,12",
            "input_model": "bounded IOKit external-method selector and structure",
            "kind": "published-bounty",
            "scope_url": "https://security.apple.com/bounty/categories/",
            "scope_evidence": scope,
            "scope_checked_at": iso(timedelta(hours=-1)),
            "expires_at": iso(timedelta(hours=12)),
            "statement": "bounded private research under current public scope only",
            "authorized_by": "fixture-macho-scope-authority",
            "authority_key_sha256": AUTH_KEY,
            "signature_ssh": "test-signature",
        },
    }
    raw.update(updates)
    return raw


def write_campaign(tmp_path: Path, **updates: object) -> Path:
    scope_bytes = b"retained Apple bounty scope snapshot"
    (tmp_path / "scope.html").write_bytes(scope_bytes)
    acceptance_path = tmp_path / "worker-acceptance.json"
    acceptance_path.write_text(json.dumps(acceptance(), sort_keys=True), encoding="utf-8")
    acceptance_sha = hashlib.sha256(acceptance_path.read_bytes()).hexdigest()
    path = tmp_path / "campaign.json"
    path.write_text(
        json.dumps(
            manifest(acceptance_sha, artifact("scope.html", scope_bytes), **updates), sort_keys=True
        ),
        encoding="utf-8",
    )
    return path


def process(role: str) -> dict[str, object]:
    target = role == "target"
    evidence = f"{role} process attribution".encode()
    return {
        "pid": 101 if target else 102,
        "parent_pid": 10,
        "responsible_pid": 10,
        "launch_id": f"{role}-launch-001",
        "executable_path": macho(role)["path"],
        "executable_sha256": TARGET_SHA if target else CONTROL_SHA,
        "macho_uuid": TARGET_UUID if target else CONTROL_UUID,
        "cdhash": ("5" if target else "6") * 40,
        "evidence": artifact(f"{role}-process.json", evidence),
    }


def observation(
    role: str, campaign_sha: str, acceptance_sha: str, outcome: str
) -> dict[str, object]:
    target = role == "target"
    return {
        "role": role,
        "replay_index": 1,
        "coordinator": "fixture-macho-coordinator-01",
        "worker": "fixture-darwin-worker-01",
        "campaign_sha256": campaign_sha,
        "worker_acceptance_sha256": acceptance_sha,
        "binary_sha256": TARGET_SHA if target else CONTROL_SHA,
        "binary_uuid": TARGET_UUID if target else CONTROL_UUID,
        "input_sha256": INPUT_SHA,
        "process": process(role),
        "outcome": outcome,
        "exit_code": None if outcome == "CRASH" else 0,
        "termination_reason": "EXC_BAD_ACCESS/KERN_INVALID_ADDRESS" if outcome == "CRASH" else None,
        "started_at": iso(timedelta(minutes=-30)),
        "finished_at": iso(timedelta(minutes=-29)),
        "crash_log": artifact("target.crash", b"target crash log") if outcome == "CRASH" else None,
        "sysdiagnose": artifact("target.sysdiagnose.tar", b"target sysdiagnose")
        if outcome == "CRASH"
        else None,
        "target_flag_reference": None,
        "evidence": [],
        "observed_by": f"fixture-{role}-observation-authority",
        "authority_key_sha256": TARGET_KEY if target else CONTROL_KEY,
        "signature_ssh": "test-signature",
    }


def receipt(campaign_sha: str, acceptance_sha: str, **updates: object) -> dict[str, object]:
    raw: dict[str, object] = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "campaign_id": "macho-contract-test-001",
        "campaign_sha256": campaign_sha,
        "worker_acceptance_sha256": acceptance_sha,
        "coordinator": "fixture-macho-coordinator-01",
        "worker": "fixture-darwin-worker-01",
        "hardware_model": "Mac14,12",
        "authorization_kind": "published-bounty",
        "input": artifact("input.bin", b"input"),
        "started_at": iso(timedelta(minutes=-31)),
        "finished_at": iso(timedelta(minutes=-28)),
        "classification": "TARGET_ONLY_CRASH",
        "target_observation": observation("target", campaign_sha, acceptance_sha, "CRASH"),
        "control_observation": observation("control", campaign_sha, acceptance_sha, "CLEAN"),
        "artifacts": [artifact("run-metadata.json", b"run metadata")],
        "bounty_eligibility": {
            "status": "UNASSESSED",
            "target_flag_present": False,
            "public_scope_current": True,
            "current_supported_build": False,
            "target_only_reproduced": True,
            "process_attributed": True,
            "security_impact_established": False,
            "originality_reviewed": False,
            "private_submission_only": True,
            "eligible": False,
        },
        "operational_maturity_claimed": False,
        "auto_disclosure": False,
    }
    raw.update(updates)
    return raw


def write_receipt(tmp_path: Path, campaign_sha: str, acceptance_sha: str) -> Path:
    files = {
        "input.bin": b"input",
        "run-metadata.json": b"run metadata",
        "target-process.json": b"target process attribution",
        "control-process.json": b"control process attribution",
        "target.crash": b"target crash log",
        "target.sysdiagnose.tar": b"target sysdiagnose",
    }
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
    path = tmp_path / "receipt.json"
    path.write_text(
        json.dumps(receipt(campaign_sha, acceptance_sha), sort_keys=True), encoding="utf-8"
    )
    return path


def test_loads_fresh_scope_and_role_separated_worker(tmp_path: Path) -> None:
    path = write_campaign(tmp_path)
    campaign, campaign_sha, accepted, acceptance_sha = load_campaign(path, now=NOW)
    assert campaign.target.product_build == accepted.os_build == "25A123"
    assert campaign.target.macho_uuid == TARGET_UUID
    assert campaign.target.code_signature_sha256 == "3" * 64
    assert campaign.target.cdhash == "5" * 40
    assert accepted.hardware_model == "Mac14,12"
    assert campaign_sha == hashlib.sha256(path.read_bytes()).hexdigest()
    assert acceptance_sha == campaign.worker_acceptance_sha256


def test_scope_snapshot_freshness_and_bytes_are_enforced(tmp_path: Path) -> None:
    path = write_campaign(tmp_path)
    raw = json.loads(path.read_text())
    raw["authorization"]["scope_checked_at"] = iso(timedelta(hours=-25))
    path.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="24 hours"):
        load_campaign(path, now=NOW)

    path = write_campaign(tmp_path)
    (tmp_path / "scope.html").write_bytes(b"drift")
    with pytest.raises(ValueError, match="artifact differs"):
        load_campaign(path, now=NOW)


def test_published_scope_must_be_official_apple_https() -> None:
    raw = manifest("a" * 64, artifact("scope.html", b"scope"))
    raw["authorization"]["scope_url"] = "https://security.apple.com.evil.invalid/bounty"
    schema = json.loads((ROOT / "schemas" / "macho-campaign-v1.schema.json").read_text())
    with pytest.raises(ValidationError):
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(raw)
    with pytest.raises(ValueError, match="https"):
        MachOCampaign.from_mapping(raw, NOW)


def test_worker_must_be_separate_darwin_role_and_exact_build() -> None:
    with pytest.raises(ValueError, match="role-separated"):
        DarwinWorkerAcceptance.from_mapping(acceptance(coordinator_is_worker=True), NOW)
    value = acceptance(os_build="25A124")
    accepted = DarwinWorkerAcceptance.from_mapping(value, NOW)
    campaign = MachOCampaign.from_mapping(manifest("a" * 64, artifact("scope.html", b"scope")), NOW)
    with pytest.raises(ValueError, match="OS/build"):
        accepted.require_binding(campaign)

    value = acceptance(os_product_version="26.1")
    accepted = DarwinWorkerAcceptance.from_mapping(value, NOW)
    with pytest.raises(ValueError, match="OS/build"):
        accepted.require_binding(campaign)


def test_target_control_require_exact_uuid_signature_and_pairing() -> None:
    raw = manifest("a" * 64, artifact("scope.html", b"scope"))
    raw["control"] = dict(raw["target"])
    raw["control"]["path"] = "/different/path"
    with pytest.raises(ValueError, match="hashes and Mach-O UUIDs"):
        MachOCampaign.from_mapping(raw, NOW)

    raw = manifest("a" * 64, artifact("scope.html", b"scope"))
    raw["control"]["signing_identifier"] = "com.apple.other"
    with pytest.raises(ValueError, match="signing identifiers"):
        MachOCampaign.from_mapping(raw, NOW)

    raw = manifest("a" * 64, artifact("scope.html", b"scope"))
    raw["target"]["product_build"] = "25A124"
    with pytest.raises(ValueError, match="authorization is not bound"):
        MachOCampaign.from_mapping(raw, NOW)


def test_scope_and_worker_windows_are_bounded() -> None:
    raw = manifest("a" * 64, artifact("scope.html", b"scope"))
    raw["authorization"]["expires_at"] = iso(timedelta(days=2))
    with pytest.raises(ValueError, match="cannot exceed 24 hours"):
        MachOCampaign.from_mapping(raw, NOW)

    with pytest.raises(ValueError, match="cannot exceed 7 days"):
        DarwinWorkerAcceptance.from_mapping(acceptance(expires_at=iso(timedelta(days=8))), NOW)


def test_receipt_binds_process_crash_log_sysdiagnose_and_replay(tmp_path: Path) -> None:
    campaign_path = write_campaign(tmp_path)
    campaign, campaign_sha, accepted, acceptance_sha = load_campaign(campaign_path, now=NOW)
    receipt_path = write_receipt(tmp_path, campaign_sha, acceptance_sha)
    loaded, digest = load_receipt(receipt_path, campaign, campaign_sha, accepted, acceptance_sha)
    assert loaded.classification == "TARGET_ONLY_CRASH"
    assert loaded.target_observation.process.macho_uuid == TARGET_UUID
    assert loaded.target_observation.crash_log is not None
    assert loaded.target_observation.sysdiagnose is not None
    assert loaded.bounty_eligibility.status == "UNASSESSED"
    assert not loaded.bounty_eligibility.eligible
    assert digest == hashlib.sha256(receipt_path.read_bytes()).hexdigest()


@pytest.mark.parametrize("field", ["crash_log", "sysdiagnose"])
def test_crash_cannot_omit_platform_evidence(field: str) -> None:
    raw = observation("target", "a" * 64, "b" * 64, "CRASH")
    raw[field] = None
    with pytest.raises(ValueError, match="crash requires"):
        MachOCampaignReceipt.from_mapping(receipt("a" * 64, "b" * 64, target_observation=raw))


def test_process_attribution_must_match_exact_role_binary() -> None:
    raw = receipt("a" * 64, "b" * 64)
    raw["target_observation"]["process"]["macho_uuid"] = CONTROL_UUID
    parsed = MachOCampaignReceipt.from_mapping(raw)
    campaign = MachOCampaign.from_mapping(manifest("b" * 64, artifact("scope.html", b"scope")), NOW)
    accepted = DarwinWorkerAcceptance.from_mapping(acceptance(), NOW)
    with pytest.raises(ValueError, match="process attribution"):
        parsed.require_binding(campaign, "a" * 64, accepted, "b" * 64)

    raw = receipt("a" * 64, "b" * 64)
    raw["target_observation"]["process"]["executable_path"] = "/different/target"
    parsed = MachOCampaignReceipt.from_mapping(raw)
    with pytest.raises(ValueError, match="process attribution"):
        parsed.require_binding(campaign, "a" * 64, accepted, "b" * 64)


def test_replay_input_and_index_must_match() -> None:
    raw = receipt("a" * 64, "b" * 64)
    raw["control_observation"]["replay_index"] = 2
    parsed = MachOCampaignReceipt.from_mapping(raw)
    campaign = MachOCampaign.from_mapping(manifest("b" * 64, artifact("scope.html", b"scope")), NOW)
    accepted = DarwinWorkerAcceptance.from_mapping(acceptance(), NOW)
    with pytest.raises(ValueError, match="indices"):
        parsed.require_binding(campaign, "a" * 64, accepted, "b" * 64)


def test_execution_receipt_cannot_claim_bounty_or_maturity() -> None:
    raw = receipt("a" * 64, "b" * 64)
    raw["bounty_eligibility"]["eligible"] = True
    with pytest.raises(ValueError, match="cannot claim bounty"):
        MachOCampaignReceipt.from_mapping(raw)
    raw = receipt("a" * 64, "b" * 64, operational_maturity_claimed=True)
    with pytest.raises(ValueError, match="maturity"):
        MachOCampaignReceipt.from_mapping(raw)


def test_target_flag_presence_requires_reference() -> None:
    raw = receipt("a" * 64, "b" * 64)
    raw["bounty_eligibility"]["target_flag_present"] = True
    with pytest.raises(ValueError, match="Target Flag"):
        MachOCampaignReceipt.from_mapping(raw)


def test_target_flag_evidence_is_retained_and_hash_bound(tmp_path: Path) -> None:
    campaign_path = write_campaign(tmp_path)
    campaign, campaign_sha, accepted, acceptance_sha = load_campaign(campaign_path, now=NOW)
    receipt_path = write_receipt(tmp_path, campaign_sha, acceptance_sha)
    flag = b"Apple Target Flag observation"
    (tmp_path / "target-flag.txt").write_bytes(flag)
    raw = json.loads(receipt_path.read_text())
    raw["bounty_eligibility"]["target_flag_present"] = True
    raw["target_observation"]["target_flag_reference"] = artifact("target-flag.txt", flag)
    receipt_path.write_text(json.dumps(raw))
    load_receipt(receipt_path, campaign, campaign_sha, accepted, acceptance_sha)
    (tmp_path / "target-flag.txt").write_bytes(b"tampered")
    with pytest.raises(ValueError, match="artifact differs"):
        load_receipt(receipt_path, campaign, campaign_sha, accepted, acceptance_sha)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("current_supported_build", True),
        ("security_impact_established", True),
        ("originality_reviewed", True),
        ("status", "BLOCKED"),
    ],
)
def test_unsigned_adjudication_gates_fail_schema_and_runtime(field: str, value: object) -> None:
    raw = receipt("a" * 64, "b" * 64)
    raw["bounty_eligibility"][field] = value
    schema = json.loads((ROOT / "schemas" / "macho-campaign-receipt-v1.schema.json").read_text())
    with pytest.raises(ValidationError):
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(raw)
    with pytest.raises(ValueError, match="adjudication"):
        MachOCampaignReceipt.from_mapping(raw)


@pytest.mark.parametrize(
    ("kind", "public_scope_current"),
    [
        ("published-bounty", True),
        ("written-authorization", False),
        ("owned-lab", False),
    ],
)
def test_public_scope_gate_is_derived_from_authorization_kind(
    kind: str, public_scope_current: bool
) -> None:
    schema = json.loads((ROOT / "schemas" / "macho-campaign-receipt-v1.schema.json").read_text())
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    raw = receipt("a" * 64, "b" * 64)
    raw["authorization_kind"] = kind
    raw["bounty_eligibility"]["public_scope_current"] = public_scope_current
    validator.validate(raw)
    assert (
        MachOCampaignReceipt.from_mapping(raw).bounty_eligibility.public_scope_current
        is public_scope_current
    )

    raw["bounty_eligibility"]["public_scope_current"] = not public_scope_current
    with pytest.raises(ValidationError):
        validator.validate(raw)
    with pytest.raises(ValueError, match="gates contradict"):
        MachOCampaignReceipt.from_mapping(raw)


def test_receipt_authorization_kind_is_cross_document_bound() -> None:
    raw = receipt("a" * 64, "b" * 64)
    parsed = MachOCampaignReceipt.from_mapping(raw)
    campaign_raw = manifest("b" * 64, artifact("scope.html", b"scope"))
    campaign_raw["authorization"]["kind"] = "written-authorization"
    campaign = MachOCampaign.from_mapping(campaign_raw, NOW)
    accepted = DarwinWorkerAcceptance.from_mapping(acceptance(), NOW)
    with pytest.raises(ValueError, match="bound to campaign"):
        parsed.require_binding(campaign, "a" * 64, accepted, "b" * 64)


def test_target_flag_must_be_inside_signed_target_observation() -> None:
    raw = receipt("a" * 64, "b" * 64)
    raw["bounty_eligibility"]["target_flag_present"] = True
    raw["control_observation"]["target_flag_reference"] = artifact("flag.txt", b"flag")
    schema = json.loads((ROOT / "schemas" / "macho-campaign-receipt-v1.schema.json").read_text())
    with pytest.raises(ValidationError):
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(raw)
    with pytest.raises(ValueError, match="control observation"):
        MachOCampaignReceipt.from_mapping(raw)


@pytest.mark.parametrize("outcome", ["ERROR", "TIMEOUT"])
def test_nonclean_outcomes_require_reason_and_signed_evidence(outcome: str) -> None:
    raw = receipt("a" * 64, "b" * 64)
    observation_raw = observation("target", "a" * 64, "b" * 64, outcome)
    raw["target_observation"] = observation_raw
    raw["classification"] = outcome
    raw["bounty_eligibility"]["target_only_reproduced"] = False
    schema = json.loads((ROOT / "schemas" / "macho-campaign-receipt-v1.schema.json").read_text())
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    with pytest.raises(ValidationError):
        validator.validate(raw)
    with pytest.raises(ValueError, match="non-clean"):
        MachOCampaignReceipt.from_mapping(raw)

    observation_raw["exit_code"] = None if outcome == "TIMEOUT" else 70
    observation_raw["termination_reason"] = "worker watchdog expired"
    observation_raw["evidence"] = [artifact("watchdog.json", b"watchdog")]
    validator.validate(raw)
    assert MachOCampaignReceipt.from_mapping(raw).classification == outcome


def test_error_classification_requires_an_error_outcome_in_schema_and_runtime() -> None:
    raw = receipt("a" * 64, "b" * 64)
    raw["target_observation"] = observation("target", "a" * 64, "b" * 64, "CLEAN")
    raw["classification"] = "ERROR"
    raw["bounty_eligibility"]["target_only_reproduced"] = False
    schema = json.loads((ROOT / "schemas" / "macho-campaign-receipt-v1.schema.json").read_text())
    with pytest.raises(ValidationError):
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(raw)
    with pytest.raises(ValueError, match="classification"):
        MachOCampaignReceipt.from_mapping(raw)


def test_production_loaders_reject_caller_policy_and_ssh_keygen_overrides(
    tmp_path: Path,
) -> None:
    campaign_path = write_campaign(tmp_path)
    with pytest.raises(TypeError, match="authorization_allowed_signers"):
        load_campaign(
            campaign_path,
            now=NOW,
            authorization_allowed_signers="same-policy",
        )
    with pytest.raises(TypeError, match="ssh_keygen"):
        load_campaign(campaign_path, now=NOW, ssh_keygen="/usr/bin/true")
    campaign, campaign_sha, accepted, acceptance_sha = load_campaign(campaign_path, now=NOW)
    receipt_path = write_receipt(tmp_path, campaign_sha, acceptance_sha)
    with pytest.raises(TypeError, match="target_allowed_signers"):
        load_receipt(
            receipt_path,
            campaign,
            campaign_sha,
            accepted,
            acceptance_sha,
            target_allowed_signers="same-policy",
        )
    with pytest.raises(TypeError, match="ssh_keygen"):
        load_receipt(
            receipt_path,
            campaign,
            campaign_sha,
            accepted,
            acceptance_sha,
            ssh_keygen="/usr/bin/true",
        )


def test_fixed_policy_requires_exact_owner_mode_raw_and_key_commitments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = tmp_path / "authorization.allowed_signers"
    policy.write_text("fixture-authority ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA==\n")
    policy.chmod(0o644)
    original = policy.read_bytes()
    raw_sha256 = hashlib.sha256(original).hexdigest()
    key_commitment = "9" * 64
    monkeypatch.setattr(macho_campaign, "_FIXTURE_TRUST", None)
    monkeypatch.setattr(macho_campaign, "TRUSTED_POLICY_UID", policy.stat().st_uid)
    monkeypatch.setattr(macho_campaign, "TRUSTED_POLICY_GID", policy.stat().st_gid)
    monkeypatch.setattr(
        macho_campaign,
        "TRUSTED_POLICIES",
        {**macho_campaign.TRUSTED_POLICIES, "authorization": (policy, raw_sha256, key_commitment)},
    )
    monkeypatch.setattr(
        macho_campaign, "ssh_authority_key_commitment", lambda path: key_commitment
    )
    assert macho_campaign._trusted_policy("authorization") == (
        policy,
        key_commitment,
        False,
    )

    policy.chmod(0o600)
    with pytest.raises(ValueError, match="ownership or mode"):
        macho_campaign._trusted_policy("authorization")
    policy.chmod(0o644)
    policy.write_text(policy.read_text() + "# drift\n")
    with pytest.raises(ValueError, match="raw commitment"):
        macho_campaign._trusted_policy("authorization")
    policy.write_bytes(original)
    monkeypatch.setattr(
        macho_campaign, "ssh_authority_key_commitment", lambda path: "8" * 64
    )
    with pytest.raises(ValueError, match="key commitment"):
        macho_campaign._trusted_policy("authorization")


def test_fixture_trust_cannot_validate_production_looking_identities(tmp_path: Path) -> None:
    campaign_path = write_campaign(tmp_path)
    raw = json.loads(campaign_path.read_text())
    raw["authorization"]["authorized_by"] = "production-scope-authority"
    campaign_path.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="fixture-prefixed"):
        load_campaign(campaign_path, now=NOW)


def test_all_principal_identities_and_key_commitments_are_globally_distinct(
    tmp_path: Path,
) -> None:
    campaign_path = write_campaign(tmp_path)
    campaign, campaign_sha, accepted, acceptance_sha = load_campaign(campaign_path, now=NOW)
    receipt_path = write_receipt(tmp_path, campaign_sha, acceptance_sha)
    raw = json.loads(receipt_path.read_text())
    raw["target_observation"]["observed_by"] = accepted.accepted_by
    receipt_path.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="identities must differ"):
        load_receipt(receipt_path, campaign, campaign_sha, accepted, acceptance_sha)

    receipt_path = write_receipt(tmp_path, campaign_sha, acceptance_sha)
    raw = json.loads(receipt_path.read_text())
    raw["target_observation"]["authority_key_sha256"] = CONTROL_KEY
    receipt_path.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="authority keys must differ"):
        load_receipt(receipt_path, campaign, campaign_sha, accepted, acceptance_sha)

    receipt_path = write_receipt(tmp_path, campaign_sha, acceptance_sha)
    raw = json.loads(receipt_path.read_text())
    raw["target_observation"]["observed_by"] = campaign.coordinator
    receipt_path.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="identities must differ"):
        load_receipt(receipt_path, campaign, campaign_sha, accepted, acceptance_sha)


def test_worker_cannot_accept_itself(tmp_path: Path) -> None:
    campaign_path = write_campaign(tmp_path)
    acceptance_path = tmp_path / "worker-acceptance.json"
    accepted_raw = json.loads(acceptance_path.read_text())
    accepted_raw["accepted_by"] = accepted_raw["worker"]
    acceptance_path.write_text(json.dumps(accepted_raw, sort_keys=True))
    campaign_raw = json.loads(campaign_path.read_text())
    campaign_raw["worker_acceptance_sha256"] = hashlib.sha256(
        acceptance_path.read_bytes()
    ).hexdigest()
    campaign_path.write_text(json.dumps(campaign_raw, sort_keys=True))
    with pytest.raises(ValueError, match="identities must differ"):
        load_campaign(campaign_path, now=NOW)


def test_signed_observation_binds_coordinator_and_worker() -> None:
    raw = receipt("a" * 64, "b" * 64)
    raw["target_observation"]["coordinator"] = "fixture-different-coordinator"
    parsed = MachOCampaignReceipt.from_mapping(raw)
    campaign = MachOCampaign.from_mapping(manifest("b" * 64, artifact("scope.html", b"scope")), NOW)
    accepted = DarwinWorkerAcceptance.from_mapping(acceptance(), NOW)
    with pytest.raises(ValueError, match="campaign/input bound"):
        parsed.require_binding(campaign, "a" * 64, accepted, "b" * 64)


def test_embedded_authority_key_commitments_match_trusted_policies(tmp_path: Path) -> None:
    campaign_path = write_campaign(tmp_path)
    raw = json.loads(campaign_path.read_text())
    raw["authorization"]["authority_key_sha256"] = "f" * 64
    campaign_path.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="authorization is not bound"):
        load_campaign(campaign_path, now=NOW)


def test_signatures_use_four_separate_roles_and_namespaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: list[dict[str, object]] = []
    monkeypatch.setattr(
        "zeroverse.macho_campaign.verify_ssh_signature",
        lambda *a, **k: observed.append(k),
    )
    campaign_path = write_campaign(tmp_path)
    campaign, campaign_sha, accepted, acceptance_sha = load_campaign(campaign_path, now=NOW)
    receipt_path = write_receipt(tmp_path, campaign_sha, acceptance_sha)
    load_receipt(receipt_path, campaign, campaign_sha, accepted, acceptance_sha)
    assert [(item["identity"], item["namespace"]) for item in observed] == [
        ("fixture-macho-scope-authority", "0verse-macho-authorization-v1"),
        ("fixture-darwin-worker-authority", "0verse-macho-worker-acceptance-v1"),
        ("fixture-target-observation-authority", "0verse-macho-target-observation-v1"),
        ("fixture-control-observation-authority", "0verse-macho-control-observation-v1"),
    ]
    assert all(item["ssh_keygen"] == Path("/usr/bin/ssh-keygen") for item in observed)
    assert all(item["inherit_environment"] is False for item in observed)


def test_duplicate_keys_symlinks_and_artifact_tampering_fail_closed(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"schema_version":"a","schema_version":"b"}')
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_campaign(bad, now=NOW)

    campaign_path = write_campaign(tmp_path)
    campaign, campaign_sha, accepted, acceptance_sha = load_campaign(campaign_path, now=NOW)
    receipt_path = write_receipt(tmp_path, campaign_sha, acceptance_sha)
    (tmp_path / "target.crash").write_bytes(b"tampered")
    with pytest.raises(ValueError, match="artifact differs"):
        load_receipt(receipt_path, campaign, campaign_sha, accepted, acceptance_sha)


def test_published_schemas_match_runtime_examples() -> None:
    scope = artifact("scope.html", b"scope")
    instances = {
        "macho-campaign-v1.schema.json": manifest("a" * 64, scope),
        "macho-worker-acceptance-v1.schema.json": acceptance(),
        "macho-campaign-receipt-v1.schema.json": receipt("a" * 64, "b" * 64),
    }
    versions = {
        "macho-campaign-v1.schema.json": CAMPAIGN_SCHEMA_VERSION,
        "macho-worker-acceptance-v1.schema.json": ACCEPTANCE_SCHEMA_VERSION,
        "macho-campaign-receipt-v1.schema.json": RECEIPT_SCHEMA_VERSION,
    }
    for name, instance in instances.items():
        schema = json.loads((ROOT / "schemas" / name).read_text())
        Draft202012Validator.check_schema(schema)
        assert schema["additionalProperties"] is False
        assert schema["properties"]["schema_version"]["const"] == versions[name]
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(instance)


def test_documentation_template_is_intentionally_not_authorized() -> None:
    raw = json.loads((ROOT / "examples" / "macho_campaign.template.json").read_text())
    with pytest.raises(ValueError, match="SHA-256"):
        MachOCampaign.from_mapping(raw, NOW)


def test_schema_and_runtime_reject_noncanonical_uuid() -> None:
    raw = manifest("a" * 64, artifact("scope.html", b"scope"))
    raw["target"]["macho_uuid"] = "abcdefab-cdef-abcd-efab-cdefabcdefab"
    schema = json.loads((ROOT / "schemas" / "macho-campaign-v1.schema.json").read_text())
    with pytest.raises(ValidationError):
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(raw)
    with pytest.raises(ValueError, match="canonical"):
        MachOCampaign.from_mapping(raw, NOW)
