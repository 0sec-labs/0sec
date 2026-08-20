from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from authorization_helpers import authorization_key, authorization_policy, sign_document
from test_windows_token_pack import _closure, _verify

from zeroverse.cli import main
from zeroverse.ssh_authorization import canonical_signed_material, sign_ssh_material
from zeroverse.windows_bounty_eligibility import (
    GENERAL_EOP,
    LOCAL_ATTACK_SCENARIO_SANDBOX_ESCAPE,
    LOCAL_EVIDENCE_SIGNATURE_NAMESPACE,
    classify_windows_bounty_evidence,
    load_windows_local_attack_scenario_evidence,
)


def test_general_eop_uses_finishing_privilege_tier_as_metadata_only(
    tmp_path: Path,
) -> None:
    verification = _verify(_closure(tmp_path))
    result = classify_windows_bounty_evidence(verification, category=GENERAL_EOP).to_dict()

    assert result["evidence_gate"] == "GENERAL_EOP_EVIDENCE_READY"
    assert result["finishing_privilege"] == "SYSTEM_IL"
    assert result["maximum_award_tier_usd"] == 8000
    assert result["award_tier_is_metadata_only"] is True
    assert result["program_eligibility"] == "MICROSOFT_DETERMINES"
    assert result["award_determination"] == "MICROSOFT_DETERMINES"
    assert result["claim_eligible"] is False
    assert result["auto_disclosure"] is False
    assert result["human_report_gate"] is True


def test_cli_reverifies_pack_before_general_eop_classification(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle = _closure(tmp_path)
    assert (
        main(
            [
                "windows-token-bounty-classify",
                str(bundle["envelope"]),
                "--blob-dir",
                str(bundle["blobs"]),
                "--acceptance-policy",
                str(bundle["policy"]),
                "--expected-context",
                str(bundle["expected"]),
                "--pack-signer-policy",
                str(bundle["pack_policy"]),
                "--category",
                GENERAL_EOP,
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["evidence_gate"] == "GENERAL_EOP_EVIDENCE_READY"
    assert result["claim_eligible"] is False


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"scope_url": "https://example.test/bounty"}, "official program source"),
        ({"latest_build_source_url": "https://example.test/build"}, "Flight Hub"),
        ({"latest_build_number": "99999.1"}, "exactly match"),
        ({"scope_program": "hyperv-insider"}, "windows-canary"),
    ],
)
def test_classification_rejects_unofficial_or_inexact_scope_evidence(
    tmp_path: Path, changes: dict[str, object], message: str
) -> None:
    verification = replace(_verify(_closure(tmp_path)), **changes)
    with pytest.raises(ValueError, match=message):
        classify_windows_bounty_evidence(verification, category=GENERAL_EOP)


def _local_evidence_payload(verification, **changes: object) -> dict[str, object]:
    raw: dict[str, object] = {
        "schema_version": "0verse.windows-local-attack-scenario-evidence/v2",
        "pack_id": verification.pack_id,
        "scope_manifest_sha256": verification.scope_manifest_sha256,
        "build_lab_ex": verification.build_lab_ex,
        "eligible_sandbox": "windows-defender-msengcp",
        "launch_app_container_executable_sha256": "1" * 64,
        "launch_transcript_sha256": "2" * 64,
        "launch_transcript_commitment_sha256": "2" * 64,
        "reproduction_transcript_sha256": "3" * 64,
        "lpac_flag": True,
        "lpac_start_token_observed": True,
        "debugger_required_to_trigger": False,
        "shipped_windows_application": True,
        "recorded_at": datetime.now(UTC).isoformat(),
        "signed_by": verification.capture_signer_identity,
        "signature_ssh": "",
    }
    raw.update(changes)
    return raw


def _local_evidence(tmp_path: Path, verification, **changes: object):
    raw = _local_evidence_payload(verification, **changes)
    path = tmp_path / "local-scenario.json"
    path.write_text(
        json.dumps(sign_document(raw, LOCAL_EVIDENCE_SIGNATURE_NAMESPACE)),
        encoding="utf-8",
    )
    return load_windows_local_attack_scenario_evidence(
        path, allowed_signers=authorization_policy()
    )


def _sign_local_evidence(raw: dict[str, object], signing_key: Path) -> dict[str, object]:
    signed = json.loads(json.dumps(raw))
    assert isinstance(signed, dict)
    signed["signature_ssh"] = sign_ssh_material(
        canonical_signed_material(signed),
        signing_key=signing_key,
        namespace=LOCAL_EVIDENCE_SIGNATURE_NAMESPACE,
        label="test local scenario evidence",
    )
    return signed


def test_local_attack_scenario_requires_signed_lpac_non_debugger_evidence(
    tmp_path: Path,
) -> None:
    verification = replace(
        _verify(_closure(tmp_path)),
        starting_context="eligible-sandbox",
        all_start_tokens_lpac=True,
        eligible_sandbox="windows-defender-msengcp",
        launch_app_container_executable_sha256="1" * 64,
        sandbox_process_executable_sha256="4" * 64,
        launch_transcript_commitment_sha256="2" * 64,
    )
    evidence = _local_evidence(tmp_path, verification)
    result = classify_windows_bounty_evidence(
        verification,
        category=LOCAL_ATTACK_SCENARIO_SANDBOX_ESCAPE,
        local_evidence=evidence,
    ).to_dict()

    assert result["evidence_gate"] == "LOCAL_ATTACK_SCENARIO_EVIDENCE_READY"
    assert result["eligible_sandbox"] == "windows-defender-msengcp"
    assert result["maximum_award_tier_usd"] == 30000
    assert result["claim_eligible"] is False
    assert result["local_scenario_evidence_sha256"] == evidence.signed_record_sha256


def test_signed_record_digest_distinguishes_valid_signatures_over_same_material(
    tmp_path: Path,
) -> None:
    verification = replace(
        _verify(_closure(tmp_path)),
        starting_context="eligible-sandbox",
        all_start_tokens_lpac=True,
        eligible_sandbox="windows-defender-msengcp",
        launch_app_container_executable_sha256="1" * 64,
        sandbox_process_executable_sha256="4" * 64,
        launch_transcript_commitment_sha256="2" * 64,
    )
    second_key = tmp_path / "second-local-evidence-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(second_key)],
        check=True,
    )
    identity = verification.capture_signer_identity
    second_public = second_key.with_suffix(".pub").read_text(encoding="utf-8").strip()
    policy = tmp_path / "local-evidence.allowed-signers"
    policy.write_text(
        authorization_policy().read_text(encoding="utf-8")
        + f"{identity} {second_public}\n",
        encoding="utf-8",
    )
    raw = _local_evidence_payload(verification)
    signed_records = (
        _sign_local_evidence(raw, authorization_key()),
        _sign_local_evidence(raw, second_key),
    )
    assert signed_records[0]["signature_ssh"] != signed_records[1]["signature_ssh"]

    loaded = []
    for index, signed in enumerate(signed_records):
        path = tmp_path / f"local-scenario-{index}.json"
        path.write_text(json.dumps(signed), encoding="utf-8")
        loaded.append(
            load_windows_local_attack_scenario_evidence(path, allowed_signers=policy)
        )

    assert loaded[0]._signed_material == loaded[1]._signed_material
    assert hashlib.sha256(loaded[0]._signed_material).hexdigest() == hashlib.sha256(
        loaded[1]._signed_material
    ).hexdigest()
    assert loaded[0].signed_record_sha256 != loaded[1].signed_record_sha256
    classifications = [
        classify_windows_bounty_evidence(
            verification,
            category=LOCAL_ATTACK_SCENARIO_SANDBOX_ESCAPE,
            local_evidence=evidence,
        )
        for evidence in loaded
    ]
    assert (
        classifications[0].local_scenario_evidence_sha256
        != classifications[1].local_scenario_evidence_sha256
    )


def test_local_attack_scenario_cannot_upgrade_a_non_lpac_pack(tmp_path: Path) -> None:
    verification = replace(
        _verify(_closure(tmp_path)), starting_context="eligible-sandbox"
    )
    evidence = _local_evidence(tmp_path, verification)
    with pytest.raises(ValueError, match="every verified start token"):
        classify_windows_bounty_evidence(
            verification,
            category=LOCAL_ATTACK_SCENARIO_SANDBOX_ESCAPE,
            local_evidence=evidence,
        )


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"eligible_sandbox": "generic-appcontainer"}, "officially eligible"),
        ({"lpac_flag": False}, "LPAC launch"),
        ({"lpac_start_token_observed": False}, "LPAC launch"),
        ({"debugger_required_to_trigger": True}, "debugger-dependent"),
        ({"shipped_windows_application": False}, "shipped Windows application"),
    ],
)
def test_local_attack_scenario_evidence_fails_closed(
    tmp_path: Path, changes: dict[str, object], message: str
) -> None:
    verification = replace(
        _verify(_closure(tmp_path)),
        starting_context="eligible-sandbox",
        all_start_tokens_lpac=True,
    )
    with pytest.raises(ValueError, match=message):
        _local_evidence(tmp_path, verification, **changes)


def test_local_attack_scenario_rejects_missing_or_cross_pack_evidence(
    tmp_path: Path,
) -> None:
    verification = replace(
        _verify(_closure(tmp_path)),
        starting_context="eligible-sandbox",
        all_start_tokens_lpac=True,
    )
    with pytest.raises(ValueError, match="signed LPAC"):
        classify_windows_bounty_evidence(
            verification, category=LOCAL_ATTACK_SCENARIO_SANDBOX_ESCAPE
        )

    evidence = _local_evidence(tmp_path, verification, pack_id="f" * 64)
    with pytest.raises(ValueError, match="not bound"):
        classify_windows_bounty_evidence(
            verification,
            category=LOCAL_ATTACK_SCENARIO_SANDBOX_ESCAPE,
            local_evidence=evidence,
        )


def test_local_attack_scenario_rejects_post_verification_mutation(tmp_path: Path) -> None:
    verification = replace(
        _verify(_closure(tmp_path)),
        starting_context="eligible-sandbox",
        all_start_tokens_lpac=True,
    )
    evidence = replace(
        _local_evidence(tmp_path, verification), eligible_sandbox="edge-chromium-renderer"
    )
    with pytest.raises(ValueError, match="differ from signed material"):
        classify_windows_bounty_evidence(
            verification,
            category=LOCAL_ATTACK_SCENARIO_SANDBOX_ESCAPE,
            local_evidence=evidence,
        )
