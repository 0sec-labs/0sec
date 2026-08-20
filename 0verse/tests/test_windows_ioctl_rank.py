from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from zeroverse.cli import main
from zeroverse.windows_ioctl_rank import rank_windows_ioctl_static


def _ctl_code(device: int, function: int) -> int:
    return (device << 16) | (function << 2)


def _plan() -> dict[str, object]:
    code = _ctl_code(0x8337, 0x801)
    return {
        "schema_version": "0verse.windows-ioctl-boundary/v1",
        "campaign_id": "ssa-fixture",
        "synthetic_fixture": True,
        "scope_manifest_sha256": "3" * 64,
        "worker": {
            "fqdn": "fixture-worker.local",
            "machine_id": "2" * 64,
            "build_lab_ex": "synthetic.26100.amd64fre.fixture",
            "architecture": "amd64",
            "collector_sha256": "4" * 64,
        },
        "target": {
            "driver_sha256": "1" * 64,
            "pdb_sha256": "5" * 64,
            "analysis_receipt_sha256": "6" * 64,
            "service_name": "Fixture",
            "device_type": 0x8337,
        },
        "boundary": {
            "schema_version": "0verse.windows-boundary-observation/fixture-v1",
            "receipt_sha256": "7" * 64,
            "worker_machine_id": "2" * 64,
            "build_lab_ex": "synthetic.26100.amd64fre.fixture",
            "driver_sha256": "1" * 64,
            "interface_class_guid": "{12345678-1234-1234-1234-1234567890ab}",
            "instance_id": "ROOT\\FIXTURE\\0000",
            "starting_context_assertion": "synthetic-standard-user",
            "open_result_assertion": "synthetic-allowed",
        },
        "budgets": {
            "max_ioctls": 2,
            "max_seeds": 2,
            "max_fields_per_seed": 2,
            "max_candidates": 32,
            "max_input_bytes": 4096,
            "max_output_bytes": 4096,
            "timeout_ms": 1000,
        },
        "ioctls": [
            {
                "code": code,
                "device_type": 0x8337,
                "function": 0x801,
                "method": "buffered",
                "access": "any",
                "handler_name": "FixtureDispatch",
                "handler_rva": 0x1200,
                "max_output_bytes": 256,
            }
        ],
        "seeds": [
            {
                "sha256": "8" * 64,
                "size": 16,
                "fields": [
                    {
                        "name": "length",
                        "offset": 4,
                        "width": 4,
                        "byte_order": "little",
                        "kind": "length",
                    }
                ],
            }
        ],
        "policy": {
            "owned_isolated_lab": True,
            "snapshot_reset_required": True,
            "network_allowed": False,
            "concurrency": 1,
            "attempts_per_candidate": 1,
            "runtime_enabled": False,
            "automatic_disclosure": False,
            "human_report_gate": True,
        },
    }


def _analysis(
    driver_digest: str,
    *,
    guards: list[str] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": "0verse.windows-ioctl-ssa-export/v1",
        "producer": "ghidra-high-pcode",
        "driver_sha256": driver_digest,
        "dispatches": [
            {
                "ioctl_code": _ctl_code(0x8337, 0x801),
                "handler_name": "FixtureDispatch",
                "handler_rva": 0x1200,
                "registration_rva": 0x1000,
                "dispatch_resolved": True,
                "unresolved_edges": [],
                "fields": [
                    {
                        "name": "length",
                        "offset": 4,
                        "width": 4,
                        "kind": "length",
                        "source": "SystemBuffer",
                        "source_inst_id": 10,
                        "sink_kind": "copy",
                        "sink_function": "RtlCopyMemory",
                        "sink_address": "0x1300",
                        "sink_inst_id": 20,
                        "guards": guards or [],
                    }
                ],
            }
        ],
    }


def _fixture(tmp_path: Path, *, guards: list[str] | None = None) -> tuple[Path, Path, Path]:
    binary_path = tmp_path / "fixture.sys"
    binary_path.write_bytes(b"synthetic-driver-not-a-pe")
    binary_digest = hashlib.sha256(binary_path.read_bytes()).hexdigest()
    ghidra_path = tmp_path / "ghidra.json"
    ghidra_path.write_text(
        json.dumps(_analysis(binary_digest, guards=guards), sort_keys=True),
        encoding="utf-8",
    )
    ghidra_digest = hashlib.sha256(ghidra_path.read_bytes()).hexdigest()
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(
        json.dumps(
            {
                "schema_version": "0verse.ghidra-analysis-receipt/v1",
                "producer": "zeroverse.windows-analysis/fixture-v1",
                "binary_path": "fixture.sys",
                "binary_sha256": binary_digest,
                "ghidra_export_path": "ghidra.json",
                "ghidra_export_sha256": ghidra_digest,
                "tool": "ghidra",
                "tool_version": "fixture-1",
                "cache_key": binary_digest[:16],
                "synthetic_fixture": True,
                "pdb": {"path": "", "sha256": "", "codeview_identity": ""},
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    receipt_digest = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    plan_path = tmp_path / "plan.json"
    plan = _plan()
    plan["target"]["driver_sha256"] = binary_digest  # type: ignore[index]
    plan["target"]["analysis_receipt_sha256"] = receipt_digest  # type: ignore[index]
    plan["boundary"]["driver_sha256"] = binary_digest  # type: ignore[index]
    plan_path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")
    # The planner commits to the exact raw manifest bytes.
    plan_manifest_digest = hashlib.sha256(plan_path.read_bytes()).hexdigest()
    analysis_path = ghidra_path
    campaign = {
        "schema_version": "0verse.windows-ioctl-static-campaign/v1",
        "plan_path": "plan.json",
        "plan_sha256": plan_manifest_digest,
        "analysis_path": "ghidra.json",
        "analysis_sha256": hashlib.sha256(analysis_path.read_bytes()).hexdigest(),
        "artifact": {
            "binary_path": "fixture.sys",
            "binary_sha256": binary_digest,
            "ghidra_export_path": "ghidra.json",
            "ghidra_export_sha256": ghidra_digest,
            "analysis_receipt_path": "receipt.json",
            "analysis_receipt_sha256": receipt_digest,
        },
    }
    campaign_path = tmp_path / "campaign.json"
    campaign_path.write_text(json.dumps(campaign, sort_keys=True), encoding="utf-8")
    return campaign_path, plan_path, analysis_path


def _rebind(campaign: Path, plan: Path, analysis: Path) -> None:
    root = campaign.parent
    analysis_digest = hashlib.sha256(analysis.read_bytes()).hexdigest()
    receipt_path = root / "receipt.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["ghidra_export_sha256"] = analysis_digest
    receipt_path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
    receipt_digest = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    plan_raw = json.loads(plan.read_text())
    plan_raw["target"]["analysis_receipt_sha256"] = receipt_digest
    plan.write_text(json.dumps(plan_raw, sort_keys=True), encoding="utf-8")
    campaign_raw = json.loads(campaign.read_text())
    campaign_raw["plan_sha256"] = hashlib.sha256(plan.read_bytes()).hexdigest()
    campaign_raw["analysis_sha256"] = analysis_digest
    campaign_raw["artifact"]["ghidra_export_sha256"] = analysis_digest
    campaign_raw["artifact"]["analysis_receipt_sha256"] = receipt_digest
    campaign.write_text(json.dumps(campaign_raw, sort_keys=True), encoding="utf-8")


def test_ranks_exact_unguarded_ssa_evidence_deterministically(tmp_path: Path) -> None:
    campaign, _, _ = _fixture(tmp_path)
    first = rank_windows_ioctl_static(campaign)
    assert first == rank_windows_ioctl_static(campaign)
    assert first["candidate_count"] == 1
    assert first["device_ioctl_attempts"] == 0
    assert first["synthetic_fixture"] is True
    assert first["contract_only"] is True
    assert first["human_report_gate"] is True
    assert first["claim_eligible"] is False
    row = first["candidates"][0]
    assert row["status"] == "candidate"
    assert row["rank"] == 1
    assert row["ssa_evidence"]["missing_guards"] == [
        "checked-arithmetic",
        "field-within-input",
        "input-buffer-length",
    ]


def test_fully_guarded_control_is_suppressed(tmp_path: Path) -> None:
    campaign, _, _ = _fixture(
        tmp_path,
        guards=["checked-arithmetic", "field-within-input", "input-buffer-length"],
    )
    assert rank_windows_ioctl_static(campaign)["candidate_count"] == 0


@pytest.mark.parametrize("mutation", ["handler", "field", "driver", "unresolved"])
def test_rejects_unbound_or_unresolved_evidence(tmp_path: Path, mutation: str) -> None:
    campaign, plan_path, analysis_path = _fixture(tmp_path)
    analysis = json.loads(analysis_path.read_text())
    if mutation == "handler":
        analysis["dispatches"][0]["handler_rva"] = 0x1201
    elif mutation == "field":
        analysis["dispatches"][0]["fields"][0]["offset"] = 5
    elif mutation == "driver":
        analysis["driver_sha256"] = "9" * 64
    else:
        analysis["dispatches"][0]["dispatch_resolved"] = False
        analysis["dispatches"][0]["unresolved_edges"] = ["CALLIND@0x1010"]
    analysis_path.write_text(json.dumps(analysis, sort_keys=True), encoding="utf-8")
    _rebind(campaign, plan_path, analysis_path)
    with pytest.raises(ValueError):
        rank_windows_ioctl_static(campaign)


def test_duplicate_ssa_evidence_fails_closed(tmp_path: Path) -> None:
    campaign, plan, analysis_path = _fixture(tmp_path)
    analysis = json.loads(analysis_path.read_text())
    analysis["dispatches"][0]["fields"].append(
        copy.deepcopy(analysis["dispatches"][0]["fields"][0])
    )
    analysis_path.write_text(json.dumps(analysis, sort_keys=True), encoding="utf-8")
    _rebind(campaign, plan, analysis_path)
    with pytest.raises(ValueError, match="duplicate SSA field evidence"):
        rank_windows_ioctl_static(campaign)


def test_candidate_identity_binds_analysis_receipt(tmp_path: Path) -> None:
    campaign, plan, analysis = _fixture(tmp_path)
    first = rank_windows_ioctl_static(campaign)["candidates"][0]["candidate_id"]
    receipt_path = tmp_path / "receipt.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["tool_version"] = "fixture-2"
    receipt_path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
    # Rebind the unchanged export through the changed receipt and plan.
    _rebind(campaign, plan, analysis)
    second = rank_windows_ioctl_static(campaign)["candidates"][0]["candidate_id"]
    assert first != second


def test_hash_tamper_and_unknown_fields_fail_closed(tmp_path: Path) -> None:
    campaign, _, _ = _fixture(tmp_path)
    raw = json.loads(campaign.read_text())
    raw["analysis_sha256"] = "9" * 64
    campaign.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        rank_windows_ioctl_static(campaign)
    raw = copy.deepcopy(raw)
    raw["payload"] = "forbidden"
    campaign.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="fields mismatch"):
        rank_windows_ioctl_static(campaign)


def test_cli_writes_exclusively(tmp_path: Path) -> None:
    campaign, _, _ = _fixture(tmp_path)
    output = tmp_path / "ranked.json"
    assert main(["windows-ioctl-rank", str(campaign), "--output", str(output)]) == 0
    assert json.loads(output.read_text())["device_ioctl_attempts"] == 0
    assert main(["windows-ioctl-rank", str(campaign), "--output", str(output)]) == 2
