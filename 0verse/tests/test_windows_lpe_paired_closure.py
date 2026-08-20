from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_windows_servicing import _fixture as servicing_fixture
from test_windows_servicing import _verify as verify_servicing
from test_windows_token_pack import _closure as token_closure
from test_windows_token_pack import _verify as verify_token_pack

from zeroverse.cli import main
from zeroverse.ssh_authority_commitment import ssh_authority_key_commitment
from zeroverse.ssh_authorization import canonical_signed_material, sign_ssh_material
from zeroverse.windows_lpe_paired_closure import (
    EXPERIMENT_SIGNATURE_NAMESPACE,
    VerifiedWindowsLpeExperiment,
    WindowsServicingInputs,
    WindowsTokenPackInputs,
    derive_windows_lpe_paired_closure,
    verify_windows_lpe_paired_closure,
    verify_windows_lpe_paired_closure_cas,
)
from zeroverse.windows_pair_plan import verify_windows_pair_plan


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _matrix(prefix: str, count: int) -> tuple[str, ...]:
    return tuple(_digest(f"{prefix}-{index}") for index in range(count))


def _authority(tmp_path: Path, identity: str) -> tuple[Path, Path]:
    key = tmp_path / f"{identity.replace('@', '-')}.key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
        capture_output=True,
    )
    policy = tmp_path / f"{identity.replace('@', '-')}.allowed-signers"
    public = key.with_suffix(".key.pub").read_text(encoding="utf-8").strip()
    policy.write_text(f"{identity} {public}\n", encoding="utf-8")
    return key, policy


def _sign_with_key(
    raw: dict[str, object], namespace: str, signing_key: Path
) -> dict[str, object]:
    signed = json.loads(json.dumps(raw))
    signed["signature_ssh"] = ""
    signed["signature_ssh"] = sign_ssh_material(
        canonical_signed_material(signed),
        signing_key=signing_key,
        namespace=namespace,
        label="test LPE authority",
    )
    return signed


def _rewrite_servicing(path: Path, raw: dict[str, object], signing_key: Path) -> None:
    path.write_text(json.dumps(raw, sort_keys=True), encoding="utf-8")
    Path(f"{path}.sig").write_text(
        sign_ssh_material(
            path.read_bytes(),
            signing_key=signing_key,
            namespace="0verse-windows-servicing-receipt-v1",
            label="test servicing receipt",
        ),
        encoding="utf-8",
    )


def _pack_inputs(bundle: dict[str, Path | dict[str, object]]) -> WindowsTokenPackInputs:
    return WindowsTokenPackInputs(
        envelope_path=bundle["envelope"],  # type: ignore[arg-type]
        blob_dir=bundle["blobs"],  # type: ignore[arg-type]
        acceptance_policy_path=bundle["policy"],  # type: ignore[arg-type]
        expected_context_path=bundle["expected"],  # type: ignore[arg-type]
        pack_signer_policy_path=bundle["pack_policy"],  # type: ignore[arg-type]
    )


def _paired_fixture(tmp_path: Path):
    servicing_paths = servicing_fixture(tmp_path / "servicing", role="candidate")
    plan = verify_windows_pair_plan(servicing_paths[0])
    candidate_receipt = replace(
        verify_servicing(servicing_paths),
        receipt_signer_identity="candidate-servicing@example.test",
        receipt_signer_authority_commitment_sha256=_digest("candidate-servicing-key"),
    )
    candidate_pack = replace(
        verify_token_pack(token_closure(tmp_path / "candidate-pack")),
        build_lab_ex=plan.candidate_build_lab_ex,
        worker_machine_id=candidate_receipt.worker_machine_id,
        grant_authorized_by="candidate-grant@example.test",
        acceptance_accepted_by="candidate-acceptance@example.test",
        capture_signer_identity="candidate-capture@example.test",
        pack_signer_identity="candidate-pack@example.test",
        scope_authorized_by="candidate-scope@example.test",
        aggregate_signed_by="candidate-aggregate@example.test",
        scope_authority_key_commitment_sha256=_digest("candidate-scope-key"),
        grant_authority_key_commitment_sha256=_digest("candidate-grant-key"),
        acceptance_authority_key_commitment_sha256=_digest("candidate-acceptance-key"),
        capture_authority_key_commitment_sha256=_digest("candidate-capture-key"),
        aggregate_authority_key_commitment_sha256=_digest("candidate-aggregate-key"),
        pack_authority_key_commitment_sha256=_digest("candidate-pack-key"),
    )
    fixed_machine = "worker-02"
    fixed_receipt = replace(
        candidate_receipt,
        receipt_sha256=_digest("fixed-servicing-receipt"),
        receipt_signature_sha256=_digest("fixed-servicing-signature"),
        role="control",
        artifact_path=servicing_paths[0].parent / "control" / plan.component,
        artifact_sha256=plan.control_sha256,
        build_lab_ex=plan.control_build_lab_ex,
        servicing_package_sha256s=(plan.control_acquisition_artifact_sha256s[1],),
        acquisition_receipt_sha256s=plan.control_acquisition_receipt_sha256s,
        worker_machine_id=fixed_machine,
        receipt_signer_identity="fixed-servicing@example.test",
        receipt_signer_authority_commitment_sha256=_digest("fixed-servicing-key"),
    )
    run_count = candidate_pack.trials * 2
    fixed_pack = replace(
        candidate_pack,
        pack_id=_digest("fixed-pack"),
        run_id="fixed-run",
        job_nonce="fixed_job_nonce_000000000000000001",
        campaign_sha256=_digest("fixed-campaign"),
        scope_manifest_sha256=_digest("fixed-scope"),
        execution_grant_sha256=_digest("fixed-grant"),
        worker_acceptance_sha256=_digest("fixed-acceptance"),
        aggregate_receipt_sha256=_digest("fixed-aggregate"),
        campaign_id="fixed-campaign",
        worker="fixed-worker",
        build_lab_ex=plan.control_build_lab_ex,
        worker_machine_id=fixed_machine,
        witness_user_sid="S-1-5-21-4-5-6-1002",
        witness_session_id=2,
        witness_authentication_id="0000000000001002",
        target_confirmations=0,
        clean_target_no_transitions=candidate_pack.trials,
        ambiguous_targets=0,
        grant_authorized_by="fixed-grant@example.test",
        acceptance_accepted_by="fixed-acceptance@example.test",
        capture_signer_identity="fixed-capture@example.test",
        pack_signer_identity="fixed-pack@example.test",
        scope_authorized_by="fixed-scope@example.test",
        aggregate_signed_by="fixed-aggregate@example.test",
        scope_authority_key_commitment_sha256=_digest("fixed-scope-key"),
        grant_authority_key_commitment_sha256=_digest("fixed-grant-key"),
        acceptance_authority_key_commitment_sha256=_digest("fixed-acceptance-key"),
        capture_authority_key_commitment_sha256=_digest("fixed-capture-key"),
        aggregate_authority_key_commitment_sha256=_digest("fixed-aggregate-key"),
        pack_authority_key_commitment_sha256=_digest("fixed-pack-key"),
        run_id_commitment_sha256=_digest("fixed-run-id"),
        job_nonce_commitment_sha256=_digest("fixed-job-nonce"),
        execution_grant_nonce_commitment_sha256=_digest("fixed-grant-nonce"),
        worker_acceptance_nonce_commitment_sha256=_digest("fixed-acceptance-nonce"),
        ordered_capture_nonce_commitment_sha256=_matrix(
            "fixed-capture-nonce", run_count
        ),
        grant_replay_identity_sha256=_digest("fixed-grant-replay"),
        worker_acceptance_replay_identity_sha256=_digest("fixed-acceptance-replay"),
        ordered_run_replay_identity_sha256=_matrix("fixed-run-replay", run_count),
        ordered_capture_sha256=_matrix("fixed-capture", run_count),
        ordered_process_identity_sha256=_matrix("fixed-process", run_count),
    )
    experiment = VerifiedWindowsLpeExperiment(
        source_sha256=_digest("experiment"),
        pair_plan_sha256=plan.plan_sha256,
        component=plan.component,
        candidate_artifact_sha256=plan.candidate_sha256,
        control_artifact_sha256=plan.control_sha256,
        target_operation_sha256=candidate_pack.target_operation_sha256,
        control_operation_sha256=candidate_pack.control_operation_sha256,
        runner_executable_sha256=candidate_pack.runner_executable_sha256,
        authorized_by="experiment@example.test",
        authority_key_commitment_sha256=_digest("experiment-key"),
    )
    return plan, experiment, candidate_receipt, candidate_pack, fixed_receipt, fixed_pack


def test_derives_nonclaim_paired_closure_and_service_replay_verdict(tmp_path: Path) -> None:
    closure = derive_windows_lpe_paired_closure(*_paired_fixture(tmp_path))
    raw = closure.to_dict()
    assert raw["schema_version"] == "0verse.windows-lpe-paired-closure/v2"
    assert raw["status"] == "PAIRED_DIFFERENTIAL_OBSERVED"
    assert raw["candidate"]["target_confirmations"] == 2
    assert raw["fixed"]["target_confirmations"] == 0
    assert raw["fixed"]["clean_target_no_transitions"] == 2
    assert raw["candidate"]["witness"] == {
        "user_sid": "S-1-5-21-1-2-3-1001",
        "session_id": 1,
        "authentication_id": "0000000000001001",
        "executable_sha256": "d" * 64,
    }
    assert raw["fixed"]["witness"] == {
        "user_sid": "S-1-5-21-4-5-6-1002",
        "session_id": 2,
        "authentication_id": "0000000000001002",
        "executable_sha256": "d" * 64,
    }
    assert raw["claim_eligible"] is False
    assert raw["bounty_eligible"] is False
    assert raw["accepted"] is False
    assert raw["replay_state_consumed"] is False
    assert raw["human_report_gate"] is True
    assert len(raw["candidate"]["identity_commitments"]["ordered_capture_nonce_sha256"]) == 4
    assert len(raw["ordered_replay_identity_sha256"]) == 29
    assert len(set(raw["ordered_replay_identity_sha256"])) == 29


@pytest.mark.parametrize(
    ("side", "changes", "message"),
    [
        ("candidate", {"target_confirmations": 1}, "lacks required"),
        ("candidate", {"ambiguous_targets": 1}, "ambiguous"),
        ("fixed", {"target_confirmations": 1}, "contains a target transition"),
        ("fixed", {"clean_target_no_transitions": 1}, "not all clean"),
        ("fixed", {"clean_controls": 1}, "controls are not all clean"),
        ("fixed", {"target_operation_sha256": "f" * 64}, "operation identities differ"),
        ("fixed", {"runner_executable_sha256": "f" * 64}, "runner, witness, or operation"),
        ("fixed", {"witness_executable_sha256": "f" * 64}, "runner, witness, or operation"),
    ],
)
def test_rejects_ineligible_or_noncomparable_observations(
    tmp_path: Path, side: str, changes: dict[str, object], message: str
) -> None:
    plan, experiment, candidate_receipt, candidate_pack, fixed_receipt, fixed_pack = (
        _paired_fixture(tmp_path)
    )
    if side == "candidate":
        candidate_pack = replace(candidate_pack, **changes)
    else:
        fixed_pack = replace(fixed_pack, **changes)
    with pytest.raises(ValueError, match=message):
        derive_windows_lpe_paired_closure(
            plan, experiment, candidate_receipt, candidate_pack, fixed_receipt, fixed_pack
        )


@pytest.mark.parametrize(
    ("field", "message"),
    [
        ("execution_grant_sha256", "authority identity"),
        ("ordered_run_replay_identity_sha256", "per-run identity"),
        ("ordered_capture_sha256", "per-run identity"),
        ("ordered_process_identity_sha256", "per-run identity"),
    ],
)
def test_rejects_cross_build_authority_capture_process_and_replay_reuse(
    tmp_path: Path, field: str, message: str
) -> None:
    plan, experiment, candidate_receipt, candidate_pack, fixed_receipt, fixed_pack = (
        _paired_fixture(tmp_path)
    )
    fixed_pack = replace(fixed_pack, **{field: getattr(candidate_pack, field)})
    with pytest.raises(ValueError, match=message):
        derive_windows_lpe_paired_closure(
            plan, experiment, candidate_receipt, candidate_pack, fixed_receipt, fixed_pack
        )


def test_rejects_same_machine_for_both_builds(tmp_path: Path) -> None:
    plan, experiment, candidate_receipt, candidate_pack, fixed_receipt, fixed_pack = (
        _paired_fixture(tmp_path)
    )
    fixed_receipt = replace(
        fixed_receipt, worker_machine_id=candidate_pack.worker_machine_id
    )
    fixed_pack = replace(fixed_pack, worker_machine_id=candidate_pack.worker_machine_id)
    with pytest.raises(ValueError, match=r"distinct.*machines"):
        derive_windows_lpe_paired_closure(
            plan, experiment, candidate_receipt, candidate_pack, fixed_receipt, fixed_pack
        )


def test_rejects_broker_pack_until_identity_separation_schema_exists(tmp_path: Path) -> None:
    plan, experiment, candidate_receipt, candidate_pack, fixed_receipt, fixed_pack = (
        _paired_fixture(tmp_path)
    )
    candidate_pack = replace(
        candidate_pack,
        ordered_broker_receipt_replay_identity_sha256=("a" * 64,),
        ordered_broker_process_replay_identity_sha256=("b" * 64,),
        ordered_broker_transcript_replay_identity_sha256=("c" * 64,),
        broker_receipt_authority_key_commitment_sha256="d" * 64,
        broker_receipt_signer_identity="broker@example.test",
    )
    with pytest.raises(ValueError, match="acceptance-witness/measured-process"):
        derive_windows_lpe_paired_closure(
            plan, experiment, candidate_receipt, candidate_pack, fixed_receipt, fixed_pack
        )


def test_cross_machine_witness_identity_is_side_specific_and_committed(
    tmp_path: Path,
) -> None:
    args = _paired_fixture(tmp_path)
    baseline = derive_windows_lpe_paired_closure(*args)
    fixed_pack = replace(args[5], witness_session_id=3)
    changed = derive_windows_lpe_paired_closure(*args[:5], fixed_pack)
    assert baseline.candidate_witness_user_sid != baseline.fixed_witness_user_sid
    assert baseline.candidate_witness_session_id != baseline.fixed_witness_session_id
    assert baseline.candidate_witness_authentication_id != (
        baseline.fixed_witness_authentication_id
    )
    assert baseline.closure_commitment_sha256 != changed.closure_commitment_sha256


@pytest.mark.parametrize(
    "field",
    [
        "run_id_commitment_sha256",
        "job_nonce_commitment_sha256",
        "execution_grant_nonce_commitment_sha256",
        "worker_acceptance_nonce_commitment_sha256",
        "ordered_capture_nonce_commitment_sha256",
    ],
)
def test_rejects_same_kind_cross_build_nonce_reuse(tmp_path: Path, field: str) -> None:
    plan, experiment, candidate_receipt, candidate_pack, fixed_receipt, fixed_pack = (
        _paired_fixture(tmp_path)
    )
    fixed_pack = replace(fixed_pack, **{field: getattr(candidate_pack, field)})
    with pytest.raises(ValueError, match=r"nonce|per-run identity"):
        derive_windows_lpe_paired_closure(
            plan, experiment, candidate_receipt, candidate_pack, fixed_receipt, fixed_pack
        )


def test_rejects_signer_role_reuse_within_and_across_builds(tmp_path: Path) -> None:
    plan, experiment, candidate_receipt, candidate_pack, fixed_receipt, fixed_pack = (
        _paired_fixture(tmp_path)
    )
    mutations = (
        replace(
            candidate_pack,
            acceptance_accepted_by=candidate_pack.grant_authorized_by,
        ),
        candidate_pack,
    )
    fixed_mutations = (
        fixed_pack,
        replace(
            fixed_pack,
            grant_authorized_by=candidate_pack.grant_authorized_by,
        ),
    )
    for changed_candidate, changed_fixed in zip(mutations, fixed_mutations, strict=True):
        with pytest.raises(ValueError, match="signer roles"):
            derive_windows_lpe_paired_closure(
                plan,
                experiment,
                candidate_receipt,
                changed_candidate,
                fixed_receipt,
                changed_fixed,
            )

    reused_servicing = replace(
        fixed_receipt,
        receipt_signer_identity=candidate_pack.pack_signer_identity,
    )
    with pytest.raises(ValueError, match="signer roles"):
        derive_windows_lpe_paired_closure(
            plan,
            experiment,
            candidate_receipt,
            candidate_pack,
            reused_servicing,
            fixed_pack,
        )


def test_authority_commitment_allows_principal_aliases_but_rejects_multiple_keys(
    tmp_path: Path,
) -> None:
    _, first_policy = _authority(tmp_path, "first@example.test")
    first_line = first_policy.read_text(encoding="utf-8").strip()
    alias_policy = tmp_path / "aliases.allowed-signers"
    alias_policy.write_text(
        "# same key may authorize multiple principals\n"
        + first_line
        + "\n"
        + first_line.replace("first@", "alias@", 1)
        + "\n",
        encoding="utf-8",
    )
    assert ssh_authority_key_commitment(alias_policy) == ssh_authority_key_commitment(
        first_policy
    )

    _, second_policy = _authority(tmp_path, "second@example.test")
    alias_policy.write_text(
        first_line + "\n" + second_policy.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="exactly one unique SSH public key"):
        ssh_authority_key_commitment(alias_policy)


@pytest.mark.parametrize(
    ("field", "source_field"),
    [
        ("grant_authority_key_commitment_sha256", "grant_authority_key_commitment_sha256"),
        ("scope_authority_key_commitment_sha256", "aggregate_authority_key_commitment_sha256"),
        (
            "aggregate_authority_key_commitment_sha256",
            "scope_authority_key_commitment_sha256",
        ),
    ],
)
def test_rejects_distinct_principals_backed_by_same_or_colliding_role_keys(
    tmp_path: Path, field: str, source_field: str
) -> None:
    plan, experiment, candidate_receipt, candidate_pack, fixed_receipt, fixed_pack = (
        _paired_fixture(tmp_path)
    )
    fixed_pack = replace(
        fixed_pack,
        **{field: getattr(candidate_pack, source_field)},
    )
    with pytest.raises(ValueError, match="independent SSH keys"):
        derive_windows_lpe_paired_closure(
            plan, experiment, candidate_receipt, candidate_pack, fixed_receipt, fixed_pack
        )


def test_rejects_servicing_artifact_build_role_and_machine_drift(tmp_path: Path) -> None:
    plan, experiment, candidate_receipt, candidate_pack, fixed_receipt, fixed_pack = (
        _paired_fixture(tmp_path)
    )
    for receipt in (
        replace(fixed_receipt, role="candidate"),
        replace(fixed_receipt, artifact_sha256="f" * 64),
        replace(fixed_receipt, build_lab_ex=plan.candidate_build_lab_ex),
        replace(fixed_receipt, worker_machine_id="other-machine"),
    ):
        with pytest.raises(ValueError, match="servicing/build/machine binding mismatch"):
            derive_windows_lpe_paired_closure(
                plan, experiment, candidate_receipt, candidate_pack, receipt, fixed_pack
            )


def test_top_level_reverifies_real_signed_nested_files_and_rejects_mutation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    servicing_paths = servicing_fixture(tmp_path / "servicing", role="candidate")
    plan_path, candidate_artifact, candidate_receipt_path, candidate_raw = servicing_paths
    plan_raw = json.loads(plan_path.read_text(encoding="utf-8"))
    plan_raw["candidate"]["build_lab_ex"] = "29000.1.amd64fre.rs_prerelease"
    plan_raw["control"]["build_lab_ex"] = "29000.2.amd64fre.rs_prerelease"
    plan_path.write_text(json.dumps(plan_raw, sort_keys=True), encoding="utf-8")
    plan = verify_windows_pair_plan(plan_path)

    candidate_machine = "candidate-machine-001"
    fixed_machine = "fixed-machine-002"
    candidate_servicing_identity = "candidate-servicing@example.test"
    fixed_servicing_identity = "fixed-servicing@example.test"
    candidate_servicing_key, candidate_servicing_policy = _authority(
        tmp_path, candidate_servicing_identity
    )
    fixed_servicing_key, fixed_servicing_policy = _authority(
        tmp_path, fixed_servicing_identity
    )
    candidate_raw["receipt_signer_identity"] = candidate_servicing_identity
    candidate_raw["pair_plan"] = {"sha256": plan.plan_sha256}
    candidate_raw["observation"]["build_lab_ex"] = plan.candidate_build_lab_ex
    candidate_raw["execution"]["pre_machine_id"] = candidate_machine
    candidate_raw["execution"]["post_machine_id"] = candidate_machine
    _rewrite_servicing(candidate_receipt_path, candidate_raw, candidate_servicing_key)

    fixed_raw = json.loads(json.dumps(candidate_raw))
    fixed_raw["receipt_signer_identity"] = fixed_servicing_identity
    fixed_raw["role"] = "control"
    fixed_raw["inputs"] = {
        "acquisition_artifact_sha256s": list(
            plan.control_acquisition_artifact_sha256s
        ),
        "acquisition_receipt_sha256s": list(plan.control_acquisition_receipt_sha256s),
    }
    fixed_raw["execution"]["pre_machine_id"] = fixed_machine
    fixed_raw["execution"]["post_machine_id"] = fixed_machine
    fixed_raw["execution"]["steps"][0]["package_sha256"] = (
        plan.control_acquisition_artifact_sha256s[1]
    )
    fixed_artifact = plan_path.parent / "control" / plan.component
    fixed_raw["observation"] = {
        "build_lab_ex": plan.control_build_lab_ex,
        "retained_output": {
            "basename": plan.component,
            "sha256": plan.control_sha256,
            "size_bytes": fixed_artifact.stat().st_size,
        },
    }
    fixed_receipt_path = plan_path.parent / "control.servicing.json"
    _rewrite_servicing(fixed_receipt_path, fixed_raw, fixed_servicing_key)

    def make_pack(
        side: str, build: str, machine: str, *, target_transition: bool
    ) -> dict[str, Path | dict[str, object]]:
        identities = {
            role: f"{side}-{role}@example.test"
            for role in ("scope", "grant", "acceptance", "capture", "aggregateReceipt")
        }
        authorities = {
            role: _authority(tmp_path, identity) for role, identity in identities.items()
        }
        signing_keys = {role: authority[0] for role, authority in authorities.items()}
        policies = {role: authority[1] for role, authority in authorities.items()}
        worker = f"{side}-worker"
        campaign_id = f"{side}-campaign"
        preflight = {
            "ok": True,
            "program": "windows-canary",
            "checked_at": datetime.now(UTC).isoformat(),
            "build_lab_ex": build,
            "product_name": "Windows 11 Pro",
            "hyperv_available": False,
            "insider": {
                "ring": "Experimental Future Platforms",
                "content_type": "Mainline",
                "branch_name": "rs_prerelease",
                "channel_family": "experimental-future-platforms",
            },
        }
        authority_kwargs: dict[str, object] = {
            "campaign_overrides": {"campaign_id": campaign_id, "worker": worker},
            "scope_overrides": {
                "campaign_id": campaign_id,
                "worker": worker,
                "latest_build_number": build.split(".amd64fre", 1)[0],
                "preflight": preflight,
                "authorized_by": identities["scope"],
                "nonce": f"{side}_scope_authorization_nonce_00001",
            },
            "grant_overrides": {
                "campaign_id": campaign_id,
                "worker": worker,
                "nonce": f"{side}_execution_grant_nonce_000001",
                "authorized_by": identities["grant"],
            },
            "acceptance_overrides": {
                "campaign_id": campaign_id,
                "worker": worker,
                "build_lab_ex": build,
                "worker_machine_id": machine,
                "execution_grant_nonce": f"{side}_execution_grant_nonce_000001",
                "nonce": f"{side}_worker_acceptance_nonce_0001",
                "accepted_by": identities["acceptance"],
                "capture_signer": identities["capture"],
            },
            "role_policies": {
                "scope": policies["scope"],
                "grant": policies["grant"],
                "acceptance": policies["acceptance"],
            },
            "role_signing_keys": {
                "scope": signing_keys["scope"],
                "grant": signing_keys["grant"],
                "acceptance": signing_keys["acceptance"],
            },
        }
        pack_identity = f"{side}-pack@example.test"
        pack_key, pack_policy = _authority(tmp_path, pack_identity)
        return token_closure(
            tmp_path / f"{side}-pack",
            target_transition=target_transition,
            authority_kwargs=authority_kwargs,
            role_policies=policies,
            role_identities=identities,
            role_signing_keys=signing_keys,
            pack_policy=pack_policy,
            pack_signing_key=pack_key,
            pack_signer_identity=pack_identity,
            run_id=f"{side}-run",
            job_nonce=f"{side}_job_nonce_000000000000000000001",
            nonce_tag=side,
        )

    candidate_bundle = make_pack(
        "candidate", plan.candidate_build_lab_ex, candidate_machine, target_transition=True
    )
    fixed_bundle = make_pack(
        "fixed", plan.control_build_lab_ex, fixed_machine, target_transition=False
    )
    experiment_identity = "experiment-authority@example.test"
    experiment_key, experiment_policy = _authority(tmp_path, experiment_identity)
    experiment_path = tmp_path / "experiment.json"
    experiment = {
        "schema_version": "0verse.windows-lpe-experiment/v1",
        "pair_plan_sha256": plan.plan_sha256,
        "component": plan.component,
        "candidate": {"role": "candidate", "artifact_sha256": plan.candidate_sha256},
        "control": {"role": "control", "artifact_sha256": plan.control_sha256},
        "target_operation_sha256": "a" * 64,
        "control_operation_sha256": "b" * 64,
        "runner_executable_sha256": "c" * 64,
        "authorized_by": experiment_identity,
        "signature_ssh": "",
    }
    experiment_path.write_text(
        json.dumps(
            _sign_with_key(
                experiment, EXPERIMENT_SIGNATURE_NAMESPACE, experiment_key
            )
        ),
        encoding="utf-8",
    )
    kwargs = {
        "experiment_path": experiment_path,
        "experiment_allowed_signers_path": experiment_policy,
        "candidate_servicing": WindowsServicingInputs(
            candidate_artifact, candidate_receipt_path, candidate_servicing_policy
        ),
        "candidate_token_pack": _pack_inputs(candidate_bundle),
        "fixed_servicing": WindowsServicingInputs(
            fixed_artifact, fixed_receipt_path, fixed_servicing_policy
        ),
        "fixed_token_pack": _pack_inputs(fixed_bundle),
    }
    closure = verify_windows_lpe_paired_closure(plan_path, **kwargs)
    assert closure.candidate_target_confirmations == 2
    assert closure.fixed_clean_target_no_transitions == 2

    cli_args = [
        "windows-lpe-paired-closure-verify",
        str(plan_path),
        "--experiment",
        str(experiment_path),
        "--experiment-allowed-signers",
        str(experiment_policy),
    ]
    for side, artifact, receipt, servicing_policy, bundle in (
        (
            "candidate",
            candidate_artifact,
            candidate_receipt_path,
            candidate_servicing_policy,
            candidate_bundle,
        ),
        (
            "fixed",
            fixed_artifact,
            fixed_receipt_path,
            fixed_servicing_policy,
            fixed_bundle,
        ),
    ):
        cli_args.extend(
            [
                f"--{side}-artifact",
                str(artifact),
                f"--{side}-servicing-receipt",
                str(receipt),
                f"--{side}-servicing-allowed-signers",
                str(servicing_policy),
                f"--{side}-envelope",
                str(bundle["envelope"]),
                f"--{side}-blob-dir",
                str(bundle["blobs"]),
                f"--{side}-acceptance-policy",
                str(bundle["policy"]),
                f"--{side}-expected-context",
                str(bundle["expected"]),
                f"--{side}-pack-signer-policy",
                str(bundle["pack_policy"]),
            ]
        )
    assert main(cli_args) == 0
    cli_closure = json.loads(capsys.readouterr().out)
    assert cli_closure == closure.to_dict()
    assert cli_closure["accepted"] is False
    assert cli_closure["replay_state_consumed"] is False
    assert cli_closure["human_report_gate"] is True

    opaque_paths: set[Path] = set()
    for side in ("candidate", "control"):
        side_raw = plan_raw[side]
        assert isinstance(side_raw, dict)
        acquisitions = side_raw["acquisition_receipts"]
        assert isinstance(acquisitions, list)
        for acquisition in acquisitions:
            assert isinstance(acquisition, dict)
            opaque_paths.add(
                plan_path.parent / str(acquisition["bundle_path"]) / "artifact"
            )
    reproduction = plan_raw["reproduction"]
    assert isinstance(reproduction, dict)
    recipe_ref = reproduction["recipe"]
    assert isinstance(recipe_ref, dict)
    opaque_paths.add(plan_path.parent / str(recipe_ref["path"]))
    tools = reproduction["tools"]
    assert isinstance(tools, list)
    for tool in tools:
        assert isinstance(tool, dict)
        opaque_paths.add(plan_path.parent / str(tool["path"]))
    for receipt_path, receipt_raw in (
        (candidate_receipt_path, candidate_raw),
        (fixed_receipt_path, fixed_raw),
    ):
        execution = receipt_raw["execution"]
        assert isinstance(execution, dict)
        steps = execution["steps"]
        assert isinstance(steps, list)
        for step in steps:
            assert isinstance(step, dict)
            for stream in ("stdout", "stderr"):
                reference = step[stream]
                assert isinstance(reference, dict)
                opaque_paths.add(receipt_path.parent / str(reference["path"]))
    retained = {path: path.read_bytes() for path in opaque_paths}
    opaque_manifest = {
        "schema_version": "0verse.windows-lpe-opaque-content/v1",
        "files": [
            {
                "path": path.relative_to(plan_path.parent).as_posix(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data),
            }
            for path, data in sorted(
                retained.items(), key=lambda item: item[0].relative_to(plan_path.parent).as_posix()
            )
        ],
    }
    opaque_path = plan_path.parent / "opaque-content.json"
    opaque_path.write_text(
        json.dumps(opaque_manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    for path in opaque_paths:
        path.unlink()
    cas_closure = verify_windows_lpe_paired_closure_cas(
        plan_path, opaque_content_path=opaque_path, **kwargs
    )
    assert cas_closure == closure
    cas_cli_args = [
        "windows-lpe-paired-closure-verify-cas",
        *cli_args[1:],
        "--opaque-content",
        str(opaque_path),
    ]
    assert main(cas_cli_args) == 0
    cas_stdout = capsys.readouterr().out
    assert cas_stdout == json.dumps(
        closure.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ) + "\n"

    opaque_tampered = json.loads(opaque_path.read_text(encoding="utf-8"))
    opaque_tampered["files"][0]["sha256"] = "0" * 64
    opaque_path.write_text(
        json.dumps(opaque_tampered, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="opaque content reference mismatch"):
        verify_windows_lpe_paired_closure_cas(
            plan_path, opaque_content_path=opaque_path, **kwargs
        )
    assert main(cas_cli_args) == 2
    assert capsys.readouterr().out == ""
    opaque_path.write_text(
        json.dumps(opaque_manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    candidate_signature = Path(f"{candidate_receipt_path}.sig")
    candidate_signature_bytes = candidate_signature.read_bytes()
    candidate_signature.unlink()
    with pytest.raises(ValueError, match="receipt signature"):
        verify_windows_lpe_paired_closure_cas(
            plan_path, opaque_content_path=opaque_path, **kwargs
        )
    candidate_signature.write_bytes(candidate_signature_bytes)
    for path, data in retained.items():
        path.write_bytes(data)

    experiment_raw = json.loads(experiment_path.read_text(encoding="utf-8"))
    experiment_raw["runner_executable_sha256"] = "d" * 64
    experiment_path.write_text(json.dumps(experiment_raw), encoding="utf-8")
    with pytest.raises(ValueError, match="signature is invalid"):
        verify_windows_lpe_paired_closure(plan_path, **kwargs)
    assert main(cli_args) == 2
    assert capsys.readouterr().out == ""
