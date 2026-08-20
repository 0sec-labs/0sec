from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from authorization_helpers import authorization_policy, sign_document
from test_windows_byo_corpus import _fixture as _byo_fixture
from test_windows_ioctl_real_rank import _fixture, _replace, _rewrite_export, _v2_export

from zeroverse.ssh_authorization import canonical_signed_material, sign_ssh_material
from zeroverse.windows_byo_corpus import verify_windows_byo_corpus_manifest
from zeroverse.windows_ioctl_real_eval import (
    LABEL_PROOF_LIMIT,
    LABEL_PROOF_LIMIT_V2,
    LABEL_VERSION,
    LABEL_VERSION_V2,
    RANK_RECEIPT_NAMESPACE,
    RANK_RECEIPT_NAMESPACE_V2,
    RANK_RECEIPT_PROOF_LIMIT,
    RANK_RECEIPT_PROOF_LIMIT_V2,
    RANK_RECEIPT_VERSION,
    RANK_RECEIPT_VERSION_V2,
    SIGNATURE_NAMESPACE,
    _candidate_site,
    _site_id,
    evaluate_windows_ioctl_real_static,
)
from zeroverse.windows_ioctl_real_eval import (
    SIGNATURE_NAMESPACE_V2 as LABEL_SIGNATURE_NAMESPACE_V2,
)
from zeroverse.windows_ioctl_real_rank import (
    ADMISSION_VERSION_V2,
    ADMISSION_VERSION_V3,
    BYO_ADMISSION_PROOF_LIMIT,
    CAMPAIGN_VERSION_V2,
    RESULT_VERSION_V2,
    RESULT_VERSION_V3,
    SIGNATURE_NAMESPACE_V2,
    SIGNATURE_NAMESPACE_V3,
    rank_windows_ioctl_real_static,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _authority(root: Path, name: str, identity: str) -> tuple[Path, Path, str]:
    key = root / f"{name}-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    public = key.with_suffix(".pub").read_text(encoding="utf-8").strip()
    policy = root / f"{name}.allowed_signers"
    policy.write_text(f"{identity} {public}\n", encoding="utf-8")
    return key, policy, identity


def _sign(raw: dict[str, object], key: Path, identity: str, namespace: str) -> dict[str, object]:
    payload = dict(raw)
    identity_field = "labeled_by" if "label_set_id" in payload else "receipt_signer_identity"
    payload[identity_field] = identity
    payload["signature_ssh"] = ""
    payload["signature_ssh"] = sign_ssh_material(
        canonical_signed_material(payload),
        signing_key=key,
        namespace=namespace,
        label="test authority",
    )
    return payload


def _closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    label_mutator: Any | None = None,
    receipt_mutator: Any | None = None,
    byo: bool = False,
    byo_campaign_mutator: Any | None = None,
    byo_admission_mutator: Any | None = None,
    admission_before_inventory: bool = False,
) -> tuple[Path, Path, Path, Path, Path]:
    inventory_path: Path | None = None
    inventory: Any | None = None
    if byo:
        inventory_path, curator_policy, _ = _byo_fixture(tmp_path / "byo")
        monkeypatch.setattr("zeroverse.windows_byo_corpus.DEFAULT_ALLOWED_SIGNERS", curator_policy)
        monkeypatch.setattr(
            "zeroverse.windows_byo_corpus._require_production_policy_permissions",
            lambda _path: None,
        )
        inventory = verify_windows_byo_corpus_manifest(inventory_path)
    issued_override = None
    if admission_before_inventory:
        assert inventory is not None
        issued_override = datetime.fromisoformat(inventory.declared_frozen_at) - timedelta(
            seconds=1
        )
    campaign, artifact = _fixture(tmp_path, monkeypatch, issued_at=issued_override)

    _rewrite_export(
        campaign,
        artifact,
        monkeypatch,
        lambda raw: _replace(
            raw, _v2_export(artifact, include_guarded_control=True)
        ),
    )
    byo_bindings: dict[str, object] = {}
    if byo:
        assert inventory is not None and inventory_path is not None
        item = inventory.item_commitment_sha256s[0]
        bundle = inventory.private_bundle_commitment_sha256s[0]
        byo_bindings = {
            "byo_inventory_sha256": inventory.inventory_sha256,
            "byo_inventory_signature_sha256": inventory.signature_sha256,
            "byo_inventory_id": inventory.inventory_id,
            "byo_inventory_nonce": inventory.inventory_nonce,
            "byo_curator_principal": inventory.manifest_signer_identity,
            "byo_curator_authority_key_commitment": (inventory.authority_key_commitment_sha256),
            "byo_blinding_key_commitment_sha256": (inventory.blinding_key_commitment_sha256),
            "byo_source_index_commitment_sha256": (
                inventory.declared_source_index_commitment_sha256
            ),
            "byo_item_commitment_sha256": item,
            "byo_private_bundle_commitment_sha256": bundle,
            "byo_declared_frozen_at": inventory.declared_frozen_at,
        }
    admission_path = tmp_path / "analysis-admission-nonce-000000000001.json"
    admission = json.loads(admission_path.read_text(encoding="utf-8"))

    v1 = rank_windows_ioctl_real_static(campaign, allowed_signers=authorization_policy())
    if byo:
        assert inventory is not None and inventory_path is not None
        campaign_raw = json.loads(campaign.read_text(encoding="utf-8"))
        campaign_raw.update(
            {
                "schema_version": CAMPAIGN_VERSION_V2,
                "byo_inventory_path": str(inventory_path.relative_to(tmp_path)),
                "byo_inventory_sha256": inventory.inventory_sha256,
                "byo_inventory_signature_sha256": inventory.signature_sha256,
                "byo_item_commitment_sha256": byo_bindings["byo_item_commitment_sha256"],
                "byo_private_bundle_commitment_sha256": byo_bindings[
                    "byo_private_bundle_commitment_sha256"
                ],
            }
        )
        if byo_campaign_mutator is not None:
            byo_campaign_mutator(campaign_raw)
        campaign.write_text(json.dumps(campaign_raw, sort_keys=True), encoding="utf-8")
    candidate = cast(list[dict[str, Any]], v1["candidates"])[0]
    expected_site = _candidate_site(v1, candidate)
    export = json.loads(artifact.export_path.read_text(encoding="utf-8"))
    dispatch = export["dispatches"][0]
    control = dispatch["fields"][1]
    control_site = {
        "ioctl_code": f"0x{dispatch['ioctl_code']:08x}",
        "registration_rva": dispatch["registration_rva"],
        "handler_name": dispatch["handler_name"],
        "handler_rva": dispatch["handler_rva"],
        "source": control["source"],
        "source_inst_id": control["source_inst_id"],
        "field_offset": control["offset"],
        "field_width": control["width"],
        "field_kind": control["kind"],
        "sink_kind": control["sink_kind"],
        "sink_function": control["sink_function"],
        "sink_address": control["sink_address"],
        "sink_inst_id": control["sink_inst_id"],
    }
    control_site["site_id"] = _site_id(
        str(v1["driver_sha256"]),
        str(v1["analysis_sha256"]),
        {key: value for key, value in control_site.items() if key != "site_id"},
    )
    admission_issued = datetime.fromisoformat(admission["issued_at"])
    label_key, label_policy, label_identity = _authority(tmp_path, "labels", "labeler@example.test")
    labels: dict[str, object] = {
        "schema_version": LABEL_VERSION,
        "purpose": "blinded-static-corpus-labels-only",
        "label_set_id": "blind-label-set-01",
        "family_id": "fixture-ioctl-family",
        "blind_salt": "a1" * 32,
        "split": "holdout",
        "campaign_id": v1["campaign_id"],
        "driver_sha256": v1["driver_sha256"],
        "pdb_sha256": v1["pdb_sha256"],
        "pdb_codeview_identity": v1["pdb_codeview_identity"],
        "analysis_sha256": v1["analysis_sha256"],
        "analysis_receipt_sha256": v1["analysis_receipt_sha256"],
        "rank_contract": RESULT_VERSION_V2,
        "score_version": v1["score_version"],
        "rank_cutoff": 1,
        "minimum_recall_at_cutoff": 1.0,
        "minimum_control_suppression": 1.0,
        "maximum_emitted_abstention_rate": 0.0,
        "provenance_source_sha256s": ["7" * 64],
        "frozen_at": (admission_issued - timedelta(minutes=2)).isoformat(),
        "issued_at": (admission_issued - timedelta(minutes=1)).isoformat(),
        "expires_at": (admission_issued + timedelta(hours=1)).isoformat(),
        "nonce": "blinded-label-manifest-nonce-000000001",
        "expected_sites": [expected_site],
        "control_sites": [control_site],
        "abstention_sites": [],
        "proof_limit": LABEL_PROOF_LIMIT,
    }
    if byo:
        labels.update(byo_bindings)
        labels["private_bundle_verified"] = False
        labels["schema_version"] = LABEL_VERSION_V2
        labels["rank_contract"] = RESULT_VERSION_V3
        labels["proof_limit"] = LABEL_PROOF_LIMIT_V2
    if label_mutator is not None:
        label_mutator(labels, admission_issued)
    labels = _sign(
        labels,
        label_key,
        label_identity,
        LABEL_SIGNATURE_NAMESPACE_V2 if byo else SIGNATURE_NAMESPACE,
    )
    labels_path = tmp_path / "labels.json"
    labels_path.write_text(json.dumps(labels, sort_keys=True), encoding="utf-8")

    admission["schema_version"] = ADMISSION_VERSION_V3 if byo else ADMISSION_VERSION_V2
    admission["rank_contract"] = RESULT_VERSION_V3 if byo else RESULT_VERSION_V2
    admission["label_manifest_commitment_sha256"] = _sha(labels_path)
    if byo:
        admission.update(byo_bindings)
        admission["private_bundle_verified"] = False
        admission["proof_limit"] = BYO_ADMISSION_PROOF_LIMIT
        if byo_admission_mutator is not None:
            byo_admission_mutator(admission)
    admission.pop("signature_ssh")
    admission = sign_document(admission, SIGNATURE_NAMESPACE_V3 if byo else SIGNATURE_NAMESPACE_V2)
    admission_path.write_text(json.dumps(admission, sort_keys=True), encoding="utf-8")
    campaign_raw = json.loads(campaign.read_text(encoding="utf-8"))
    campaign_raw["admission_sha256"] = _sha(admission_path)
    campaign.write_text(json.dumps(campaign_raw, sort_keys=True), encoding="utf-8")

    result = rank_windows_ioctl_real_static(campaign, allowed_signers=authorization_policy())
    result_path = tmp_path / "rank-result.json"
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    content_ids = [
        row["candidate_content_id"] for row in cast(list[dict[str, Any]], result["candidates"])
    ]
    ordered_digest = hashlib.sha256(
        b"0verse-windows-ioctl-ordered-candidate-content-ids-v1\0"
        + json.dumps(content_ids, separators=(",", ":")).encode()
    ).hexdigest()
    receipt_key, receipt_policy, receipt_identity = _authority(
        tmp_path, "rank-receipt", "rank-receipt@example.test"
    )
    completed_at = datetime.now(UTC)
    rank_started_at = max(
        datetime.fromisoformat(str(result["admission_issued_at"])),
        completed_at - timedelta(seconds=1),
    )
    receipt_raw: dict[str, object] = {
        "schema_version": RANK_RECEIPT_VERSION_V2 if byo else RANK_RECEIPT_VERSION,
        "producer": "zeroverse.windows-ioctl-real-rank-worker/v1",
        "purpose": "static-rank-result-observation-only",
        "rank_contract": RESULT_VERSION_V3 if byo else RESULT_VERSION_V2,
        "result_schema_version": RESULT_VERSION_V3 if byo else RESULT_VERSION_V2,
        "rank_result_sha256": _sha(result_path),
        "rank_result_size_bytes": result_path.stat().st_size,
        "campaign_id": result["campaign_id"],
        "campaign_sha256": result["campaign_sha256"],
        "admission_sha256": result["admission_sha256"],
        "label_manifest_commitment_sha256": result["label_manifest_commitment_sha256"],
        "driver_sha256": result["driver_sha256"],
        "pdb_sha256": result["pdb_sha256"],
        "pdb_codeview_identity": result["pdb_codeview_identity"],
        "analysis_sha256": result["analysis_sha256"],
        "analysis_receipt_sha256": result["analysis_receipt_sha256"],
        "score_version": result["score_version"],
        "candidate_count": result["candidate_count"],
        "ordered_candidate_content_ids_sha256": ordered_digest,
        "site_count": result["site_count"],
        "site_universe_sha256": result["site_universe_sha256"],
        "analysis_run_id": result["analysis_run_id"],
        "static_only": True,
        "runtime_consumable": False,
        "execution_authorized": False,
        "device_ioctl_attempts": 0,
        "ranker_executable_sha256": "8" * 64,
        "ranker_configuration_sha256": "9" * 64,
        "worker_machine_id": "fixture-static-rank-worker-01",
        "started_at": rank_started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "issued_at": completed_at.isoformat(),
        "run_nonce": "rank-result-receipt-nonce-0000000001",
        "proof_limit": (RANK_RECEIPT_PROOF_LIMIT_V2 if byo else RANK_RECEIPT_PROOF_LIMIT),
    }
    if byo:
        receipt_raw.update(
            {
                **byo_bindings,
                "admission_expires_at": result["admission_expires_at"],
                "private_bundle_verified": False,
            }
        )
    if receipt_mutator is not None:
        receipt_mutator(receipt_raw, result)
    receipt = _sign(
        receipt_raw,
        receipt_key,
        receipt_identity,
        RANK_RECEIPT_NAMESPACE_V2 if byo else RANK_RECEIPT_NAMESPACE,
    )
    receipt_path = tmp_path / "rank-receipt.json"
    receipt_path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
    return result_path, receipt_path, labels_path, receipt_policy, label_policy


def test_blinded_eval_opens_precommitted_labels_and_reports_metrics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, receipt, labels, receipt_policy, label_policy = _closure(tmp_path, monkeypatch)
    evaluated = evaluate_windows_ioctl_real_static(
        result,
        receipt,
        labels,
        rank_receipt_allowed_signers=receipt_policy,
        label_allowed_signers=label_policy,
    )
    assert evaluated["recall_at_cutoff"] == 1.0
    assert evaluated["control_suppression"] == 1.0
    assert evaluated["passed"] is True
    assert evaluated["capability_measure"] is False
    assert evaluated["execution_authorized"] is False


def test_byo_v3_bindings_flow_from_verified_inventory_through_v2_evaluation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, receipt, labels, receipt_policy, label_policy = _closure(
        tmp_path, monkeypatch, byo=True
    )
    ranked = json.loads(result.read_text(encoding="utf-8"))
    evaluated = evaluate_windows_ioctl_real_static(
        result,
        receipt,
        labels,
        rank_receipt_allowed_signers=receipt_policy,
        label_allowed_signers=label_policy,
    )
    assert ranked["schema_version"] == RESULT_VERSION_V3
    assert evaluated["schema_version"] == "0verse.windows-ioctl-real-evaluation/v2"
    assert evaluated["byo_inventory_sha256"] == ranked["byo_inventory_sha256"]
    assert evaluated["byo_item_commitment_sha256"] == ranked["byo_item_commitment_sha256"]
    assert evaluated["private_bundle_verified"] is False
    assert evaluated["redistribution"] is False


def test_byo_campaign_rejects_unlisted_item_bundle_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ValueError, match="selected item/bundle"):
        _closure(
            tmp_path,
            monkeypatch,
            byo=True,
            receipt_mutator=None,
            byo_campaign_mutator=lambda campaign: campaign.__setitem__(
                "byo_private_bundle_commitment_sha256", "e" * 64
            ),
        )


def test_byo_campaign_rejects_inventory_signature_substitution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ValueError, match="bytes/signature binding mismatch"):
        _closure(
            tmp_path,
            monkeypatch,
            byo=True,
            byo_campaign_mutator=lambda campaign: campaign.__setitem__(
                "byo_inventory_signature_sha256", "e" * 64
            ),
        )


def test_byo_admission_cannot_invent_verified_inventory_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ValueError, match="admission BYO inventory binding mismatch"):
        _closure(
            tmp_path,
            monkeypatch,
            byo=True,
            byo_admission_mutator=lambda admission: admission.__setitem__(
                "byo_item_commitment_sha256", "e" * 64
            ),
        )


@pytest.mark.parametrize("mutation", ["true", "missing"])
def test_byo_admission_must_sign_unresolved_private_bundle_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    def mutate(admission: dict[str, object]) -> None:
        if mutation == "true":
            admission["private_bundle_verified"] = True
        else:
            admission.pop("private_bundle_verified")

    with pytest.raises(ValueError, match=r"private bundle unresolved|fields mismatch"):
        _closure(
            tmp_path,
            monkeypatch,
            byo=True,
            byo_admission_mutator=mutate,
        )


def test_byo_inventory_must_freeze_before_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ValueError, match="freeze must not postdate"):
        _closure(tmp_path, monkeypatch, byo=True, admission_before_inventory=True)


def test_byo_labels_must_freeze_before_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def mutate(labels: dict[str, object], issued: datetime) -> None:
        labels["frozen_at"] = issued.isoformat()
        labels["issued_at"] = issued.isoformat()

    paths = _closure(tmp_path, monkeypatch, byo=True, label_mutator=mutate)
    with pytest.raises(ValueError, match="no later than the BYO inventory"):
        evaluate_windows_ioctl_real_static(
            paths[0],
            paths[1],
            paths[2],
            rank_receipt_allowed_signers=paths[3],
            label_allowed_signers=paths[4],
        )


def test_byo_rank_run_must_complete_inside_admission_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def mutate(receipt: dict[str, object], result: dict[str, object]) -> None:
        expires = datetime.fromisoformat(str(result["admission_expires_at"]))
        receipt["started_at"] = (expires - timedelta(seconds=1)).isoformat()
        receipt["completed_at"] = (expires + timedelta(seconds=1)).isoformat()
        receipt["issued_at"] = (expires + timedelta(seconds=1)).isoformat()

    paths = _closure(tmp_path, monkeypatch, byo=True, receipt_mutator=mutate)
    with pytest.raises(ValueError, match="timing/commitment order"):
        evaluate_windows_ioctl_real_static(
            paths[0],
            paths[1],
            paths[2],
            rank_receipt_allowed_signers=paths[3],
            label_allowed_signers=paths[4],
            now=datetime.now(UTC) + timedelta(hours=2),
        )


def test_byo_receipt_v1_downgrade_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def mutate(receipt: dict[str, object], _result: dict[str, object]) -> None:
        receipt["schema_version"] = RANK_RECEIPT_VERSION

    paths = _closure(tmp_path, monkeypatch, byo=True, receipt_mutator=mutate)
    with pytest.raises(ValueError, match="unsupported real rank result receipt contract"):
        evaluate_windows_ioctl_real_static(
            paths[0],
            paths[1],
            paths[2],
            rank_receipt_allowed_signers=paths[3],
            label_allowed_signers=paths[4],
        )


def test_byo_receipt_binding_is_rejected_before_label_bytes_are_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def mutate(receipt: dict[str, object], _result: dict[str, object]) -> None:
        receipt["byo_item_commitment_sha256"] = "e" * 64

    paths = _closure(tmp_path, monkeypatch, byo=True, receipt_mutator=mutate)
    paths[2].unlink()
    with pytest.raises(ValueError, match="receipt is not bound to the exact result"):
        evaluate_windows_ioctl_real_static(
            paths[0],
            paths[1],
            paths[2],
            rank_receipt_allowed_signers=paths[3],
            label_allowed_signers=paths[4],
        )


def test_byo_label_cannot_substitute_inventory_item(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def mutate(labels: dict[str, object], _issued: datetime) -> None:
        labels["byo_item_commitment_sha256"] = "e" * 64

    paths = _closure(tmp_path, monkeypatch, byo=True, label_mutator=mutate)
    with pytest.raises(ValueError, match="labels are not bound"):
        evaluate_windows_ioctl_real_static(
            paths[0],
            paths[1],
            paths[2],
            rank_receipt_allowed_signers=paths[3],
            label_allowed_signers=paths[4],
        )


def test_post_admission_frozen_labels_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def mutate(labels: dict[str, object], issued: datetime) -> None:
        labels["frozen_at"] = (issued + timedelta(seconds=1)).isoformat()
        labels["issued_at"] = (issued + timedelta(seconds=1)).isoformat()

    paths = _closure(tmp_path, monkeypatch, label_mutator=mutate)
    with pytest.raises(ValueError, match="frozen after admission"):
        evaluate_windows_ioctl_real_static(
            paths[0],
            paths[1],
            paths[2],
            rank_receipt_allowed_signers=paths[3],
            label_allowed_signers=paths[4],
        )


def test_overlapping_labels_are_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def mutate(labels: dict[str, object], _issued: datetime) -> None:
        labels["control_sites"] = list(cast(list[object], labels["expected_sites"]))

    paths = _closure(tmp_path, monkeypatch, label_mutator=mutate)
    with pytest.raises(ValueError, match="must be disjoint"):
        evaluate_windows_ioctl_real_static(
            paths[0],
            paths[1],
            paths[2],
            rank_receipt_allowed_signers=paths[3],
            label_allowed_signers=paths[4],
        )


def test_rank_result_mutation_breaks_receipt_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _closure(tmp_path, monkeypatch)
    result = json.loads(paths[0].read_text(encoding="utf-8"))
    result["candidates"] = []
    result["candidate_count"] = 0
    paths[0].write_text(json.dumps(result), encoding="utf-8")
    with pytest.raises(ValueError, match="not bound to the exact result"):
        evaluate_windows_ioctl_real_static(
            paths[0],
            paths[1],
            paths[2],
            rank_receipt_allowed_signers=paths[3],
            label_allowed_signers=paths[4],
        )


def test_rank_result_safety_flag_tampering_is_rejected_before_labels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _closure(tmp_path, monkeypatch)
    result = json.loads(paths[0].read_text(encoding="utf-8"))
    result["runtime_consumable"] = True
    paths[0].write_text(json.dumps(result), encoding="utf-8")
    with pytest.raises(ValueError, match="safety flags"):
        evaluate_windows_ioctl_real_static(
            paths[0],
            paths[1],
            paths[2],
            rank_receipt_allowed_signers=paths[3],
            label_allowed_signers=paths[4],
        )


def test_label_bytes_must_open_preanalysis_commitment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _closure(tmp_path, monkeypatch)
    paths[2].write_text(paths[2].read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="do not open"):
        evaluate_windows_ioctl_real_static(
            paths[0],
            paths[1],
            paths[2],
            rank_receipt_allowed_signers=paths[3],
            label_allowed_signers=paths[4],
        )


def test_duplicate_label_sites_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def mutate(labels: dict[str, object], _issued: datetime) -> None:
        expected = cast(list[dict[str, object]], labels["expected_sites"])
        expected.append(dict(expected[0]))

    paths = _closure(tmp_path, monkeypatch, label_mutator=mutate)
    with pytest.raises(ValueError, match="duplicate sites"):
        evaluate_windows_ioctl_real_static(
            paths[0],
            paths[1],
            paths[2],
            rank_receipt_allowed_signers=paths[3],
            label_allowed_signers=paths[4],
        )


def test_invented_control_cannot_expand_site_universe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def mutate(labels: dict[str, object], _issued: datetime) -> None:
        control = cast(list[dict[str, object]], labels["control_sites"])[0]
        control["sink_inst_id"] = cast(int, control["sink_inst_id"]) + 10
        record = {key: value for key, value in control.items() if key != "site_id"}
        control["site_id"] = _site_id(
            str(labels["driver_sha256"]), str(labels["analysis_sha256"]), record
        )

    paths = _closure(tmp_path, monkeypatch, label_mutator=mutate)
    with pytest.raises(ValueError, match="site universe"):
        evaluate_windows_ioctl_real_static(
            paths[0],
            paths[1],
            paths[2],
            rank_receipt_allowed_signers=paths[3],
            label_allowed_signers=paths[4],
        )


def test_rank_run_cannot_predate_label_committing_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def mutate(receipt: dict[str, object], result: dict[str, object]) -> None:
        admission_issued = datetime.fromisoformat(str(result["admission_issued_at"]))
        receipt["started_at"] = (admission_issued - timedelta(seconds=2)).isoformat()
        receipt["completed_at"] = (admission_issued - timedelta(seconds=1)).isoformat()

    paths = _closure(tmp_path, monkeypatch, receipt_mutator=mutate)
    with pytest.raises(ValueError, match="commitment order"):
        evaluate_windows_ioctl_real_static(
            paths[0],
            paths[1],
            paths[2],
            rank_receipt_allowed_signers=paths[3],
            label_allowed_signers=paths[4],
        )
