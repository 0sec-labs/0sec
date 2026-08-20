from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from authorization_helpers import authorization_policy, sign_document

from zeroverse.cli import main
from zeroverse.windows_ioctl_ghidra_export import (
    EXTRACTOR_CONFIG_SHA256,
    EXTRACTOR_PROFILE,
    RAW_FACT_VERSION,
    compile_windows_ioctl_high_pcode_facts,
)
from zeroverse.windows_ioctl_rank import _preflight_artifact_files
from zeroverse.windows_ioctl_real_rank import (
    ADMISSION_VERSION,
    CAMPAIGN_VERSION,
    EXPORT_VERSION,
    EXPORT_VERSION_V3,
    RESULT_VERSION,
    SIGNATURE_NAMESPACE,
    rank_windows_ioctl_real_static,
)
from zeroverse.windows_token_runner import load_windows_token_execution_grant
from zeroverse.windows_variant import Artifact, _load_artifact


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    nonce: str = "analysis-admission-nonce-000000000001",
    issued_at: datetime | None = None,
) -> tuple[Path, Artifact]:
    export = tmp_path / "real-ssa.json"
    driver_sha = "1" * 64
    pdb_sha = "2" * 64
    receipt_sha = "3" * 64
    export.write_text(
        json.dumps(
            {
                "schema_version": EXPORT_VERSION,
                "producer": "ghidra-high-pcode",
                "driver_sha256": driver_sha,
                "pdb_sha256": pdb_sha,
                "pdb_codeview_identity": "00112233445566778899AABBCCDDEEFF:1:driver.pdb",
                "dispatches": [
                    {
                        "ioctl_code": 0x222004,
                        "device_type": 0x22,
                        "function": 0x801,
                        "method": 0,
                        "access": 0,
                        "handler_name": "DispatchDeviceControl",
                        "handler_rva": "0x1200",
                        "registration_rva": "0x1100",
                        "dispatch_resolved": True,
                        "unresolved_edges": [],
                        "fields": [
                            {
                                "offset": 8,
                                "width": 4,
                                "kind": "length",
                                "source": "SystemBuffer",
                                "source_inst_id": 41,
                                "sink_kind": "copy",
                                "sink_function": "memcpy",
                                "sink_address": "0x1280",
                                "sink_inst_id": 55,
                                "guards": ["input-buffer-length"],
                            }
                        ],
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    artifact = Artifact(
        binary_path=tmp_path / "driver.sys",
        export_path=export,
        binary_sha256=driver_sha,
        export_sha256=_sha(export),
        pdb_identity="00112233445566778899AABBCCDDEEFF:1:driver.pdb",
        pdb_sha256=pdb_sha,
        analysis_receipt_sha256=receipt_sha,
        ghidra_version="11.4.2",
        cache_key=driver_sha[:16],
        synthetic_fixture=False,
        export={},
    )
    export.write_text(json.dumps(_v2_export(artifact), sort_keys=True), encoding="utf-8")
    artifact = replace(artifact, export_sha256=_sha(export))
    monkeypatch.setattr(
        "zeroverse.windows_ioctl_real_rank._preflight_artifact_files",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        "zeroverse.windows_ioctl_real_rank._load_artifact",
        lambda *_args: artifact,
    )
    issued = issued_at or datetime.now(UTC)
    admission = sign_document(
        {
            "schema_version": ADMISSION_VERSION,
            "purpose": "static-candidate-ranking-only",
            "campaign_id": "real-campaign-01",
            "driver_sha256": artifact.binary_sha256,
            "pdb_sha256": artifact.pdb_sha256,
            "pdb_codeview_identity": artifact.pdb_identity,
            "ghidra_export_sha256": artifact.export_sha256,
            "analysis_receipt_sha256": artifact.analysis_receipt_sha256,
            "rank_contract": RESULT_VERSION,
            "score_version": "0verse.windows-ioctl-static-score/v1",
            "max_dispatches": 4,
            "max_fields_per_dispatch": 8,
            "max_candidates": 16,
            "issued_at": issued.isoformat(),
            "expires_at": (issued + timedelta(hours=1)).isoformat(),
            "nonce": nonce,
            "admitted_by": "operator@example.test",
        },
        SIGNATURE_NAMESPACE,
    )
    admission_path = tmp_path / f"{nonce}.json"
    admission_path.write_text(json.dumps(admission, sort_keys=True), encoding="utf-8")
    artifact_record = {
        "binary_path": "driver.sys",
        "ghidra_export_path": export.name,
        "binary_sha256": artifact.binary_sha256,
        "ghidra_export_sha256": artifact.export_sha256,
        "analysis_receipt_path": "analysis-receipt.json",
        "analysis_receipt_sha256": artifact.analysis_receipt_sha256,
    }
    campaign = tmp_path / f"campaign-{nonce}.json"
    campaign.write_text(
        json.dumps(
            {
                "schema_version": CAMPAIGN_VERSION,
                "campaign_id": "real-campaign-01",
                "artifact": artifact_record,
                "admission_path": admission_path.name,
                "admission_sha256": _sha(admission_path),
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return campaign, artifact


def _rewrite_export(
    campaign: Path,
    artifact: Artifact,
    monkeypatch: pytest.MonkeyPatch,
    mutate: Any,
) -> Artifact:
    raw = json.loads(artifact.export_path.read_text(encoding="utf-8"))
    mutate(raw)
    artifact.export_path.write_text(json.dumps(raw, sort_keys=True), encoding="utf-8")
    changed = replace(artifact, export_sha256=_sha(artifact.export_path))
    monkeypatch.setattr(
        "zeroverse.windows_ioctl_real_rank._load_artifact",
        lambda *_args: changed,
    )
    campaign_raw = json.loads(campaign.read_text(encoding="utf-8"))
    admission_path = campaign.parent / campaign_raw["admission_path"]
    admission = json.loads(admission_path.read_text(encoding="utf-8"))
    admission["ghidra_export_sha256"] = changed.export_sha256
    admission.pop("signature_ssh")
    admission = sign_document(admission, SIGNATURE_NAMESPACE)
    admission_path.write_text(json.dumps(admission, sort_keys=True), encoding="utf-8")
    campaign_raw["artifact"]["ghidra_export_sha256"] = changed.export_sha256
    campaign_raw["admission_sha256"] = _sha(admission_path)
    campaign.write_text(json.dumps(campaign_raw, sort_keys=True), encoding="utf-8")
    return changed


def _v2_export(artifact: Artifact, *, include_guarded_control: bool = False) -> dict[str, Any]:
    def ref(instruction: str, opcode: str) -> dict[str, object]:
        return {
            "function_rva": "0x1200",
            "instruction_rva": instruction,
            "pcode_order": 0,
            "opcode": opcode,
        }

    store = ref("0x1210", "STORE")
    registration_address = ref("0x1208", "PTRADD")
    registration_target = ref("0x120c", "COPY")
    comparison = ref("0x1220", "INT_EQUAL")
    branch = ref("0x1228", "CBRANCH")
    source = ref("0x1240", "LOAD")
    input_length = ref("0x1248", "LOAD")
    guard_comparison = ref("0x1250", "INT_LESS")
    guard_branch = ref("0x1258", "CBRANCH")
    remaining = ref("0x1260", "INT_SUB")
    source_comparison = ref("0x1268", "INT_LESS")
    source_branch = ref("0x1270", "CBRANCH")
    destination_comparison = ref("0x1274", "INT_LESS")
    destination_branch = ref("0x1278", "CBRANCH")
    sink = ref("0x1280", "CALL")
    control_sink = ref("0x1288", "CALL")
    reject_return = ref("0x1290", "RETURN")
    header_proof = {
        "proof_kind": "input-field-readable",
        "comparison_ref": guard_comparison,
        "branch_ref": guard_branch,
        "sink_successor_ref": sink,
        "reject_return_ref": reject_return,
        "sink_comparison_result": False,
        "dominates_sink": True,
        "entry_reachable": True,
        "unique_sink_successor": True,
        "reject_successor_reaches_sink": False,
        "input_buffer_length_ref": input_length,
        "field_end": 12,
    }
    return compile_windows_ioctl_high_pcode_facts(
        {
            "schema_version": RAW_FACT_VERSION,
            "driver_sha256": artifact.binary_sha256,
            "pdb_sha256": artifact.pdb_sha256,
            "pdb_codeview_identity": artifact.pdb_identity,
            "architecture": "x86_64",
            "pointer_size": 8,
            "image_base": "0x140000000",
            "coverage": {
                "framework": "wdm",
                "truncated": False,
                "dynamic_dispatch": False,
                "unresolved_edges": [],
            },
            "dispatches": [
                {
                    "ioctl_code": 0x222004,
                    "device_type": 0x22,
                    "function": 0x801,
                    "method": 0,
                    "access": 0,
                    "handler_name": "DispatchDeviceControl",
                    "handler_rva": "0x1200",
                    "registration_rva": "0x1100",
                    "dispatch_resolved": True,
                    "unresolved_edges": [],
                        "registration_evidence": {
                            "major_function_index": 14,
                            "target_rva": "0x1200",
                            "store_ref": store,
                            "address_dependency_refs": [registration_address],
                            "target_dependency_refs": [registration_target],
                    },
                    "ioctl_match_evidence": {
                        "ioctl_code": 0x222004,
                        "comparison_ref": comparison,
                        "branch_ref": branch,
                        "dominates_handler": True,
                        "match_successor_ref": sink,
                        "reject_return_ref": reject_return,
                        "match_comparison_result": True,
                        "entry_reachable": True,
                        "unique_match_successor": True,
                        "reject_successor_reaches_sink": False,
                    },
                    "ops": [
                        {"ref": registration_address, "input_refs": []},
                        {"ref": registration_target, "input_refs": []},
                        {
                            "ref": store,
                            "input_refs": [registration_address, registration_target],
                        },
                        {"ref": comparison, "input_refs": [source]},
                        {"ref": branch, "input_refs": [comparison]},
                        {"ref": source, "input_refs": []},
                        {"ref": input_length, "input_refs": []},
                        {"ref": guard_comparison, "input_refs": [input_length]},
                        {"ref": guard_branch, "input_refs": [guard_comparison]},
                        {"ref": remaining, "input_refs": [input_length]},
                        {"ref": source_comparison, "input_refs": [source, remaining]},
                        {"ref": source_branch, "input_refs": [source_comparison]},
                        {"ref": destination_comparison, "input_refs": [source]},
                        {"ref": destination_branch, "input_refs": [destination_comparison]},
                        {"ref": sink, "input_refs": [source]},
                        {"ref": control_sink, "input_refs": [source]},
                        {"ref": reject_return, "input_refs": []},
                    ],
                    "fields": [
                        {
                            "offset": 8,
                            "width": 4,
                            "kind": "length",
                            "source": "SystemBuffer",
                            "source_root": "irp.system_buffer",
                            "source_ref": source,
                            "sink_kind": "copy",
                            "sink_function": "memcpy",
                            "sink_address": "0x1280",
                            "sink_ref": sink,
                            "sink_argument_index": 2,
                            "taint_path": [source, sink],
                            "safety_proofs": [
                                {
                                    **header_proof,
                                }
                            ],
                        }
                    ]
                    + (
                        [
                            {
                                "offset": 8,
                                "width": 4,
                                "kind": "length",
                                "source": "SystemBuffer",
                                "source_root": "irp.system_buffer",
                                "source_ref": source,
                                "sink_kind": "copy",
                                "sink_function": "memcpy",
                                "sink_address": "0x1288",
                                "sink_ref": control_sink,
                                "sink_argument_index": 2,
                                "taint_path": [source, control_sink],
                                "safety_proofs": [
                                    {**header_proof, "sink_successor_ref": control_sink},
                                    {
                                        "proof_kind": "source-copy-span",
                                        "comparison_ref": source_comparison,
                                        "branch_ref": source_branch,
                                        "sink_successor_ref": control_sink,
                                        "reject_return_ref": reject_return,
                                        "sink_comparison_result": False,
                                        "dominates_sink": True,
                                        "entry_reachable": True,
                                        "unique_sink_successor": True,
                                        "reject_successor_reaches_sink": False,
                                        "attacker_length_path": [source],
                                        "input_buffer_length_ref": input_length,
                                        "remaining_length_ref": remaining,
                                        "field_end": 12,
                                    },
                                    {
                                        "proof_kind": "destination-copy-span",
                                        "comparison_ref": destination_comparison,
                                        "branch_ref": destination_branch,
                                        "sink_successor_ref": control_sink,
                                        "reject_return_ref": reject_return,
                                        "sink_comparison_result": False,
                                        "dominates_sink": True,
                                        "entry_reachable": True,
                                        "unique_sink_successor": True,
                                        "reject_successor_reaches_sink": False,
                                        "attacker_length_path": [source],
                                        "destination_base_rva": "0x2000",
                                        "destination_capacity": 64,
                                        "destination_extent_source": "pdb-static-array",
                                        "sink_destination_argument_index": 0,
                                    },
                                ],
                            }
                        ]
                        if include_guarded_control
                        else []
                    ),
                }
            ],
        }
    )


def _replace(raw: dict[str, Any], replacement: dict[str, Any]) -> None:
    raw.clear()
    raw.update(replacement)


def test_real_ranker_is_static_candidate_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, _ = _fixture(tmp_path, monkeypatch)
    result = rank_windows_ioctl_real_static(
        campaign, allowed_signers=authorization_policy()
    )

    assert result["candidate_count"] == 1
    assert result["static_only"] is True
    assert result["runtime_consumable"] is False
    assert result["execution_authorized"] is False
    assert result["device_ioctl_attempts"] == 0
    assert result["vulnerability_established"] is False
    assert result["bounty_eligible"] is False
    assert result["human_promotion_gate"] is True
    assert result["human_report_gate"] is True
    assert result["redistribution"] is False
    assert "device_path" not in json.dumps(result)
    candidate = cast(list[dict[str, Any]], result["candidates"])[0]
    assert candidate["score"] == 75
    assert candidate["ssa_evidence"]["missing_guards"] == ["checked-arithmetic"]


def test_real_ranker_accepts_canonical_v2_export_through_legacy_score_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, artifact = _fixture(tmp_path, monkeypatch)
    export_v2 = _v2_export(artifact)
    _rewrite_export(
        campaign,
        artifact,
        monkeypatch,
        lambda raw: _replace(raw, export_v2),
    )

    result = rank_windows_ioctl_real_static(
        campaign, allowed_signers=authorization_policy()
    )

    assert result["candidate_count"] == 1
    candidate = cast(list[dict[str, Any]], result["candidates"])[0]
    assert candidate["score"] == 75
    assert candidate["ssa_evidence"]["ioctl_code"] == "0x00222004"
    assert candidate["ssa_evidence"]["missing_guards"] == ["checked-arithmetic"]
    assert result["static_only"] is True
    assert result["device_ioctl_attempts"] == 0
    assert result["execution_authorized"] is False


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("extractor_profile", "wrong-profile", "extractor contract"),
        ("extractor_config_sha256", "0" * 64, "extractor contract"),
        ("schema_version", "unknown/export-v9", "unsupported"),
    ],
)
def test_real_ranker_rejects_v2_export_contract_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    replacement: str,
    message: str,
) -> None:
    campaign, artifact = _fixture(tmp_path, monkeypatch)
    export_v2 = _v2_export(artifact)
    export_v2[field] = replacement
    _rewrite_export(
        campaign,
        artifact,
        monkeypatch,
        lambda raw: _replace(raw, export_v2),
    )
    with pytest.raises(ValueError, match=message):
        rank_windows_ioctl_real_static(campaign, allowed_signers=authorization_policy())


@pytest.mark.parametrize("mutation", ["extra", "missing", "derived-summary"])
def test_real_ranker_rejects_noncanonical_v2_export_or_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    campaign, artifact = _fixture(tmp_path, monkeypatch)
    export_v2 = _v2_export(artifact)
    if mutation == "extra":
        export_v2["unexpected"] = False
    elif mutation == "missing":
        export_v2.pop("facts")
    else:
        field = cast(list[dict[str, Any]], export_v2["dispatches"])[0]["fields"][0]
        field["source_inst_id"] = cast(int, field["source_inst_id"]) + 1
    _rewrite_export(
        campaign,
        artifact,
        monkeypatch,
        lambda raw: _replace(raw, export_v2),
    )
    with pytest.raises(ValueError, match=r"fields mismatch|not canonical"):
        rank_windows_ioctl_real_static(campaign, allowed_signers=authorization_policy())


def test_v2_bridge_requires_exporter_profile_and_config_constants(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, artifact = _fixture(tmp_path, monkeypatch)
    export_v2 = _v2_export(artifact)
    assert export_v2["schema_version"] == EXPORT_VERSION_V3
    assert export_v2["extractor_profile"] == EXTRACTOR_PROFILE
    assert export_v2["extractor_config_sha256"] == EXTRACTOR_CONFIG_SHA256
    _rewrite_export(
        campaign,
        artifact,
        monkeypatch,
        lambda raw: _replace(raw, export_v2),
    )
    result = rank_windows_ioctl_real_static(
        campaign, allowed_signers=authorization_policy()
    )
    assert result["runtime_consumable"] is False


def test_content_identity_is_stable_but_admission_identity_rotates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first, _ = _fixture(tmp_path, monkeypatch, nonce="analysis-admission-nonce-000000000001")
    second, _ = _fixture(tmp_path, monkeypatch, nonce="analysis-admission-nonce-000000000002")
    one = rank_windows_ioctl_real_static(first, allowed_signers=authorization_policy())
    two = rank_windows_ioctl_real_static(second, allowed_signers=authorization_policy())
    one_candidates = cast(list[dict[str, Any]], one["candidates"])
    two_candidates = cast(list[dict[str, Any]], two["candidates"])
    assert one_candidates[0]["candidate_content_id"] == two_candidates[0][
        "candidate_content_id"
    ]
    assert one_candidates[0]["candidate_id"] != two_candidates[0]["candidate_id"]


def test_real_ranker_rejects_stale_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, _ = _fixture(
        tmp_path,
        monkeypatch,
        issued_at=datetime.now(UTC) - timedelta(days=2),
    )
    with pytest.raises(ValueError, match="not currently fresh"):
        rank_windows_ioctl_real_static(campaign, allowed_signers=authorization_policy())


def test_real_ranker_rejects_ctl_code_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, artifact = _fixture(tmp_path, monkeypatch)
    _rewrite_export(
        campaign,
        artifact,
        monkeypatch,
        lambda raw: raw["dispatches"][0].__setitem__("ioctl_code", 0x222008),
    )
    with pytest.raises(ValueError, match=r"CTL_CODE decomposition mismatch|not canonical"):
        rank_windows_ioctl_real_static(campaign, allowed_signers=authorization_policy())


def test_v3_ranker_rejects_tampered_derived_source_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, artifact = _fixture(tmp_path, monkeypatch)
    _rewrite_export(
        campaign,
        artifact,
        monkeypatch,
        lambda raw: raw["dispatches"][0]["fields"][0].__setitem__(
            "source", "OutputBufferLength"
        ),
    )
    with pytest.raises(ValueError, match="not canonical"):
        rank_windows_ioctl_real_static(campaign, allowed_signers=authorization_policy())


def test_fully_guarded_duplicate_evidence_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, artifact = _fixture(tmp_path, monkeypatch)

    def duplicate(raw: dict[str, Any]) -> None:
        field = raw["dispatches"][0]["fields"][0]
        field["guards"] = [
            "checked-arithmetic",
            "field-within-input",
            "input-buffer-length",
        ]
        raw["dispatches"][0]["fields"].append(dict(field))

    _rewrite_export(campaign, artifact, monkeypatch, duplicate)
    with pytest.raises(ValueError, match="not canonical"):
        rank_windows_ioctl_real_static(campaign, allowed_signers=authorization_policy())


def test_zero_rva_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, artifact = _fixture(tmp_path, monkeypatch)
    _rewrite_export(
        campaign,
        artifact,
        monkeypatch,
        lambda raw: raw["dispatches"][0].__setitem__("handler_rva", "0x0"),
    )
    with pytest.raises(ValueError, match=r"nonzero 64-bit RVA|not canonical"):
        rank_windows_ioctl_real_static(campaign, allowed_signers=authorization_policy())


def test_real_ranker_rejects_synthetic_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, artifact = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "zeroverse.windows_ioctl_real_rank._load_artifact",
        lambda *_args: replace(artifact, synthetic_fixture=True),
    )
    with pytest.raises(ValueError, match="rejects synthetic"):
        rank_windows_ioctl_real_static(campaign, allowed_signers=authorization_policy())


def test_admission_signature_is_namespace_separated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, _ = _fixture(tmp_path, monkeypatch)
    campaign_raw = json.loads(campaign.read_text(encoding="utf-8"))
    admission_path = tmp_path / campaign_raw["admission_path"]
    admission = json.loads(admission_path.read_text(encoding="utf-8"))
    admission.pop("signature_ssh")
    admission = sign_document(admission, "0verse-windows-scope-authorization")
    admission_path.write_text(json.dumps(admission, sort_keys=True), encoding="utf-8")
    campaign_raw["admission_sha256"] = _sha(admission_path)
    campaign.write_text(json.dumps(campaign_raw, sort_keys=True), encoding="utf-8")
    with pytest.raises(ValueError, match="signature is invalid"):
        rank_windows_ioctl_real_static(campaign, allowed_signers=authorization_policy())


def test_rank_output_cannot_be_consumed_as_execution_grant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, _ = _fixture(tmp_path, monkeypatch)
    result = rank_windows_ioctl_real_static(
        campaign, allowed_signers=authorization_policy()
    )
    output = tmp_path / "rank-output.json"
    output.write_text(json.dumps(result), encoding="utf-8")
    with pytest.raises(ValueError):
        load_windows_token_execution_grant(
            output,
            allowed_signers=authorization_policy(),
            require_authorized=True,
        )


def test_real_ranker_traverses_pe_pdb_and_receipt_loader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, artifact = _fixture(tmp_path, monkeypatch)
    binary = tmp_path / "driver.sys"
    pdb = tmp_path / "driver.pdb"
    receipt = tmp_path / "analysis-receipt.json"
    binary.write_bytes(b"MZ-real-driver-contract")
    pdb.write_bytes(b"real-pdb-contract")
    binary_sha = _sha(binary)
    pdb_sha = _sha(pdb)
    codeview = "00112233445566778899AABBCCDDEEFF:1:driver.pdb"
    export_raw = json.loads(artifact.export_path.read_text(encoding="utf-8"))
    export_raw["driver_sha256"] = binary_sha
    export_raw["pdb_sha256"] = pdb_sha
    artifact.export_path.write_text(json.dumps(export_raw, sort_keys=True), encoding="utf-8")
    export_sha = _sha(artifact.export_path)
    receipt.write_text(
        json.dumps(
            {
                "schema_version": "0verse.ghidra-analysis-receipt/v1",
                "producer": "zeroverse.windows-analysis/v1",
                "binary_path": binary.name,
                "binary_sha256": binary_sha,
                "ghidra_export_path": artifact.export_path.name,
                "ghidra_export_sha256": export_sha,
                "tool": "ghidra",
                "tool_version": "11.4.2",
                "cache_key": binary_sha[:16],
                "synthetic_fixture": False,
                "pdb": {
                    "path": pdb.name,
                    "sha256": pdb_sha,
                    "codeview_identity": codeview,
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    receipt_sha = _sha(receipt)
    campaign_raw = json.loads(campaign.read_text(encoding="utf-8"))
    campaign_raw["artifact"].update(
        {
            "binary_sha256": binary_sha,
            "ghidra_export_sha256": export_sha,
            "analysis_receipt_sha256": receipt_sha,
        }
    )
    admission_path = tmp_path / campaign_raw["admission_path"]
    admission = json.loads(admission_path.read_text(encoding="utf-8"))
    admission.update(
        {
            "driver_sha256": binary_sha,
            "pdb_sha256": pdb_sha,
            "pdb_codeview_identity": codeview,
            "ghidra_export_sha256": export_sha,
            "analysis_receipt_sha256": receipt_sha,
        }
    )
    admission.pop("signature_ssh")
    admission = sign_document(admission, SIGNATURE_NAMESPACE)
    admission_path.write_text(json.dumps(admission, sort_keys=True), encoding="utf-8")
    campaign_raw["admission_sha256"] = _sha(admission_path)
    campaign.write_text(json.dumps(campaign_raw, sort_keys=True), encoding="utf-8")

    monkeypatch.setattr(
        "zeroverse.windows_variant.pe_codeview_identity",
        lambda _path: ("00112233445566778899AABBCCDDEEFF", 1, "driver.pdb"),
    )
    monkeypatch.setattr(
        "zeroverse.windows_variant.pdb_codeview_identity",
        lambda _path: ("00112233445566778899AABBCCDDEEFF", 1, "driver.pdb"),
    )
    monkeypatch.setattr("zeroverse.windows_ioctl_real_rank._load_artifact", _load_artifact)
    monkeypatch.setattr(
        "zeroverse.windows_ioctl_real_rank._preflight_artifact_files",
        _preflight_artifact_files,
    )
    result = rank_windows_ioctl_real_static(
        campaign, allowed_signers=authorization_policy()
    )
    assert result["driver_sha256"] == binary_sha
    assert result["pdb_sha256"] == pdb_sha
    assert result["analysis_receipt_sha256"] == receipt_sha


def test_cli_uses_fixed_policy_without_policy_argument(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, _ = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "zeroverse.windows_ioctl_real_rank.DEFAULT_ALLOWED_SIGNERS",
        authorization_policy(),
    )
    monkeypatch.setattr(
        "zeroverse.windows_ioctl_real_rank.verify_ssh_signature",
        lambda *_args, **_kwargs: None,
    )
    output = tmp_path / "result.json"
    assert main(["windows-ioctl-real-rank", str(campaign), "--output", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["runtime_consumable"] is False
