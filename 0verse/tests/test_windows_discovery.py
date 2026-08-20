from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from zeroverse.cli import main
from zeroverse.windows_discovery import _write_private_json, discover_windows_candidates
from zeroverse.windows_ioctl_ghidra_export import (
    RAW_FACT_VERSION,
    compile_windows_ioctl_high_pcode_facts,
    validate_windows_ioctl_high_pcode_export,
)
from zeroverse.windows_variant import Artifact


def _ref(base: int, order: int, opcode: str) -> dict[str, object]:
    return {
        "function_rva": f"0x{base:x}",
        "instruction_rva": f"0x{base + order:x}",
        "pcode_order": order,
        "opcode": opcode,
    }


def _export(
    driver_sha256: str,
    pdb_sha256: str,
    *,
    ioctl_code: int = 0x222004,
    guarded: bool,
    source_kind: str = "SystemBuffer",
    base_delta: int = 0,
    handler_name: str = "DispatchDeviceControl",
) -> dict[str, Any]:
    base = 0x1200 + ((ioctl_code & 0xFFF) << 4) + base_delta
    registration_address = _ref(base, 1, "PTRADD")
    registration_target = _ref(base, 2, "COPY")
    store = _ref(base, 3, "STORE")
    ioctl_load = _ref(base, 4, "LOAD")
    ioctl_compare = _ref(base, 5, "INT_EQUAL")
    ioctl_branch = _ref(base, 6, "CBRANCH")
    source = _ref(base, 7, "LOAD")
    input_length = _ref(base, 8, "LOAD")
    guard_compare = _ref(base, 9, "INT_LESS")
    guard_branch = _ref(base, 10, "CBRANCH")
    sink = _ref(base, 11, "CALL")
    reject_return = _ref(base, 12, "RETURN")
    ops = [
        {"ref": registration_address, "input_refs": []},
        {"ref": registration_target, "input_refs": []},
        {"ref": store, "input_refs": [registration_address, registration_target]},
        {"ref": ioctl_load, "input_refs": []},
        {"ref": ioctl_compare, "input_refs": [ioctl_load]},
        {"ref": ioctl_branch, "input_refs": [ioctl_compare]},
        {"ref": source, "input_refs": []},
        {"ref": input_length, "input_refs": []},
        {"ref": guard_compare, "input_refs": [input_length]},
        {"ref": guard_branch, "input_refs": [guard_compare]},
        {"ref": sink, "input_refs": [source]},
        {"ref": reject_return, "input_refs": []},
    ]
    proofs: list[dict[str, object]] = []
    if guarded:
        proofs.append(
            {
                "proof_kind": "input-field-readable",
                "comparison_ref": guard_compare,
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
        )
    raw = {
        "schema_version": RAW_FACT_VERSION,
        "driver_sha256": driver_sha256,
        "pdb_sha256": pdb_sha256,
        "pdb_codeview_identity": "00112233445566778899AABBCCDDEEFF:1:driver.pdb",
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
                "ioctl_code": ioctl_code,
                "device_type": ioctl_code >> 16,
                "function": (ioctl_code >> 2) & 0xFFF,
                "method": ioctl_code & 3,
                "access": (ioctl_code >> 14) & 3,
                "handler_name": handler_name,
                "handler_rva": f"0x{base:x}",
                "registration_rva": f"0x{base - 0x100:x}",
                "dispatch_resolved": True,
                "unresolved_edges": [],
                "registration_evidence": {
                    "major_function_index": 14,
                    "target_rva": f"0x{base:x}",
                    "store_ref": store,
                    "address_dependency_refs": [registration_address],
                    "target_dependency_refs": [registration_target],
                },
                "ioctl_match_evidence": {
                    "ioctl_code": ioctl_code,
                    "comparison_ref": ioctl_compare,
                    "branch_ref": ioctl_branch,
                    "dominates_handler": True,
                    "match_successor_ref": sink,
                    "reject_return_ref": reject_return,
                    "match_comparison_result": True,
                    "entry_reachable": True,
                    "unique_match_successor": True,
                    "reject_successor_reaches_sink": False,
                },
                "ops": ops,
                "fields": [
                    {
                        "offset": 8,
                        "width": 4,
                        "kind": "length",
                        "source": source_kind,
                        "source_root": {
                            "SystemBuffer": "irp.system_buffer",
                            "InputBufferLength": "stack.input_buffer_length",
                            "OutputBufferLength": "stack.output_buffer_length",
                        }[source_kind],
                        "source_ref": source,
                        "sink_kind": "copy",
                        "sink_function": "memcpy",
                        "sink_address": f"0x{base + 11:x}",
                        "sink_ref": sink,
                        "sink_argument_index": 2,
                        "taint_path": [source, sink],
                        "safety_proofs": proofs,
                    }
                ],
            }
        ],
    }
    result = compile_windows_ioctl_high_pcode_facts(raw)
    validate_windows_ioctl_high_pcode_export(result)
    return result


def _artifact(tmp_path: Path, side: str, export: dict[str, Any]) -> Artifact:
    export_sha256 = hashlib.sha256(
        json.dumps(export, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return Artifact(
        tmp_path / side / "driver.sys",
        tmp_path / side / "driver.json",
        str(export["driver_sha256"]),
        export_sha256,
        str(export["pdb_codeview_identity"]),
        str(export["pdb_sha256"]),
        hashlib.sha256(f"{side}-receipt".encode()).hexdigest(),
        "11.4.2",
        hashlib.sha256(f"{side}-cache".encode()).hexdigest(),
        False,
        export,
    )


def _campaign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    previous: Artifact,
    current: Artifact,
) -> Path:
    campaign = tmp_path / "campaign.json"
    campaign.write_text(
        json.dumps(
            {
                "schema_version": "0verse.windows-discovery-campaign/v1",
                "source_declaration": {
                    "kind": "owned-fixture",
                    "description": "validated semantic v3 unit fixture",
                },
                "previous": {},
                "current": {},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "zeroverse.windows_discovery._load_artifact",
        lambda _raw, _base, label: previous if label == "previous" else current,
    )
    return campaign


def _pair_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    previous: Artifact,
    current: Artifact,
) -> Path:
    def descriptor(artifact: Artifact, side: str) -> dict[str, str]:
        return {
            "binary_path": f"{side}/driver.sys",
            "binary_sha256": artifact.binary_sha256,
            "ghidra_export_path": f"{side}/driver.json",
            "ghidra_export_sha256": artifact.export_sha256,
            "analysis_receipt_path": f"{side}/receipt.json",
            "analysis_receipt_sha256": artifact.analysis_receipt_sha256,
        }

    intake_sha256 = "a" * 64
    manifest_sha256s = ["b" * 64, "c" * 64]
    descriptors = [descriptor(previous, "previous"), descriptor(current, "current")]
    pair_material = {
        "intake_sha256": intake_sha256,
        "snapshot_manifest_sha256s": manifest_sha256s,
        "binary_sha256s": [previous.binary_sha256, current.binary_sha256],
    }
    pair_id = hashlib.sha256(
        b"0verse-windows-driver-discovery-pair-v1\0"
        + json.dumps(pair_material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    snapshots = []
    for index, (artifact, descriptor_value) in enumerate(
        zip((previous, current), descriptors, strict=True)
    ):
        snapshots.append(
            {
                "slot": f"snapshot-{index}",
                "snapshot_id": f"snapshot-{index}",
                "source_kind": "owned-fixture",
                "producer_series_ordinal": index,
                "build_lab_ex": f"26100.{1000 + index}.amd64fre.ge_release.260701-1200",
                "manifest_path": f"snapshot-{index}.json",
                "manifest_sha256": manifest_sha256s[index],
                "binary_sha256": artifact.binary_sha256,
                "pdb_sha256": artifact.pdb_sha256,
                "pdb_codeview_identity": artifact.pdb_identity,
                "ghidra_export_sha256": artifact.export_sha256,
                "analysis_receipt_sha256": artifact.analysis_receipt_sha256,
                "ghidra_version": artifact.ghidra_version,
                "extractor_profile": str(artifact.export["extractor_profile"]),
                "extractor_config_sha256": str(artifact.export["extractor_config_sha256"]),
                "discovery_artifact": descriptor_value,
            }
        )
    pair = tmp_path / "pair-input.json"
    pair.write_text(
        json.dumps(
            {
                "schema_version": "0verse.windows-driver-local-pair-input/v1",
                "producer": "zeroverse.windows-driver-pair-intake/v1",
                "campaign_id": "local-pair-1",
                "intake_manifest_sha256": intake_sha256,
                "pair_id": pair_id,
                "declared_local_series": {
                    "producer_series_ordinals_consecutive": True,
                    "servicing_lineage_verified": False,
                    "servicing_adjacency_verified": False,
                },
                "snapshots": snapshots,
                "role_neutral": True,
                "labels_consumed": False,
                "network_performed": False,
                "execution_performed": False,
                "device_ioctl_attempts": 0,
                "all_outputs_are_discovery_inputs": True,
                "capability_measure": False,
                "reachability_established": False,
                "vulnerability_established": False,
                "novelty_established": False,
                "claim_eligible": False,
                "bounty_eligible": False,
                "weaponization": False,
                "automatic_disclosure": False,
                "human_promotion_gate": True,
                "windows_discovery_campaign": {
                    "schema_version": "0verse.windows-discovery-campaign/v1",
                    "source_declaration": {
                        "kind": "owned-fixture",
                        "description": "verified ordered local semantic-v3 snapshot pair",
                    },
                    "previous": descriptors[0],
                    "current": descriptors[1],
                },
                "proof_limit": "producer-declared local ordering only",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "zeroverse.windows_discovery._load_artifact",
        lambda _raw, _base, label: previous if label == "previous" else current,
    )
    return pair


def test_v3_semantic_guard_regression_is_candidate_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    previous = _artifact(tmp_path, "previous", _export("1" * 64, "2" * 64, guarded=True))
    current = _artifact(tmp_path, "current", _export("3" * 64, "4" * 64, guarded=False))
    result = discover_windows_candidates(_campaign(tmp_path, monkeypatch, previous, current))

    assert result["candidate_count"] == 1
    candidate = result["candidates"][0]
    assert candidate["evidence"]["change"] == "semantic-proof-removal"
    assert candidate["evidence"]["request_source"] == "SystemBuffer"
    assert "attacker_parameter" not in candidate["evidence"]
    assert candidate["status"] == "candidate"
    assert result["execution_authority_established"] is False
    assert result["servicing_adjacency_established"] is False


def test_unchanged_unguarded_site_is_not_called_a_regression(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    previous = _artifact(tmp_path, "previous", _export("1" * 64, "2" * 64, guarded=False))
    current = _artifact(tmp_path, "current", _export("3" * 64, "4" * 64, guarded=False))
    result = discover_windows_candidates(_campaign(tmp_path, monkeypatch, previous, current))
    assert result["candidates"][0]["evidence"]["change"] == "persistent-proof-gap"


def test_different_ioctl_site_is_current_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    previous = _artifact(
        tmp_path, "previous", _export("1" * 64, "2" * 64, ioctl_code=0x222004, guarded=False)
    )
    current = _artifact(
        tmp_path, "current", _export("3" * 64, "4" * 64, ioctl_code=0x222008, guarded=False)
    )
    result = discover_windows_candidates(_campaign(tmp_path, monkeypatch, previous, current))
    assert result["candidates"][0]["evidence"]["change"] == "current-only-surface"


def test_candidate_id_is_bound_to_campaign_and_current_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    previous = _artifact(tmp_path, "previous", _export("1" * 64, "2" * 64, guarded=True))
    first = _artifact(tmp_path, "current", _export("3" * 64, "4" * 64, guarded=False))
    campaign = _campaign(tmp_path, monkeypatch, previous, first)
    first_id = discover_windows_candidates(campaign)["candidates"][0]["candidate_id"]
    second = _artifact(tmp_path, "current", _export("5" * 64, "6" * 64, guarded=False))
    _campaign(tmp_path, monkeypatch, previous, second)
    second_id = discover_windows_candidates(campaign)["candidates"][0]["candidate_id"]
    assert first_id != second_id


def test_rejects_self_asserted_authorization_field(tmp_path: Path) -> None:
    campaign = tmp_path / "campaign.json"
    campaign.write_text(
        json.dumps(
            {
                "schema_version": "0verse.windows-discovery-campaign/v1",
                "authorization": {"basis": "owned-lab", "source": "claim"},
                "previous": {},
                "current": {},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unexpected or missing fields"):
        discover_windows_candidates(campaign)


def test_rejects_legacy_decompiler_export(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    previous = _artifact(tmp_path, "previous", _export("1" * 64, "2" * 64, guarded=True))
    current = _artifact(tmp_path, "current", _export("3" * 64, "4" * 64, guarded=False))
    current = replace(current, export={"meta": {"decompiled_c": {}}})
    campaign = _campaign(tmp_path, monkeypatch, previous, current)
    with pytest.raises(ValueError, match="incompatible architecture"):
        discover_windows_candidates(campaign)


def test_rejects_different_component_basenames(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    previous = _artifact(tmp_path, "previous", _export("1" * 64, "2" * 64, guarded=True))
    current = _artifact(tmp_path, "current", _export("3" * 64, "4" * 64, guarded=False))
    current = replace(current, binary_path=current.binary_path.with_name("other.sys"))
    campaign = _campaign(tmp_path, monkeypatch, previous, current)
    with pytest.raises(ValueError, match="same component basename"):
        discover_windows_candidates(campaign)


def test_cli_writes_private_v3_candidate_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    previous = _artifact(tmp_path, "previous", _export("1" * 64, "2" * 64, guarded=True))
    current = _artifact(tmp_path, "current", _export("3" * 64, "4" * 64, guarded=False))
    campaign = _campaign(tmp_path, monkeypatch, previous, current)
    output = tmp_path / "result.json"
    assert main(["windows-discover", str(campaign), "--output", str(output)]) == 0
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["candidate_count"] == 1
    assert result["safety"]["device_ioctl_attempts"] == 0
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert not (tmp_path / ".zeroverse-windows-discovery.tmp").exists()
    assert not list(tmp_path.glob(".result.json.*.tmp"))
    with pytest.raises(ValueError, match="already exists"):
        main(["windows-discover", str(campaign), "--output", str(output)])
    victim = tmp_path / "victim.json"
    victim.write_text("unchanged", encoding="utf-8")
    linked_output = tmp_path / "linked-result.json"
    linked_output.symlink_to(victim)
    with pytest.raises(ValueError, match="already exists"):
        main(["windows-discover", str(campaign), "--output", str(linked_output)])
    assert victim.read_text(encoding="utf-8") == "unchanged"


def test_private_output_preserves_preexisting_stage(tmp_path: Path) -> None:
    stage = tmp_path / ".zeroverse-windows-discovery.tmp"
    stage.write_text("foreign-stage", encoding="utf-8")

    with pytest.raises(ValueError, match="already exists"):
        _write_private_json(tmp_path / "result.json", {"candidate_count": 0})

    assert stage.read_text(encoding="utf-8") == "foreign-stage"
    assert not (tmp_path / "result.json").exists()


def test_concurrent_private_output_does_not_delete_owned_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first_write_started = threading.Event()
    release_first_write = threading.Event()
    original_write = os.write
    errors: list[BaseException] = []

    def blocking_write(descriptor: int, payload: bytes) -> int:
        if not first_write_started.is_set():
            first_write_started.set()
            if not release_first_write.wait(timeout=5):
                raise TimeoutError("concurrent output test did not release first writer")
        return original_write(descriptor, payload)

    monkeypatch.setattr("zeroverse.windows_discovery.os.write", blocking_write)

    def first_writer() -> None:
        try:
            _write_private_json(tmp_path / "first.json", {"writer": "first"})
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    thread = threading.Thread(target=first_writer)
    thread.start()
    assert first_write_started.wait(timeout=5)
    try:
        with pytest.raises(ValueError, match="already exists"):
            _write_private_json(tmp_path / "second.json", {"writer": "second"})
        assert (tmp_path / ".zeroverse-windows-discovery.tmp").exists()
    finally:
        release_first_write.set()
        thread.join(timeout=5)

    assert not thread.is_alive()
    assert errors == []
    assert json.loads((tmp_path / "first.json").read_text(encoding="utf-8")) == {"writer": "first"}
    assert not (tmp_path / "second.json").exists()
    assert not (tmp_path / ".zeroverse-windows-discovery.tmp").exists()


def test_output_buffer_length_does_not_invent_legacy_guard_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    previous = _artifact(
        tmp_path,
        "previous",
        _export("1" * 64, "2" * 64, guarded=False, source_kind="OutputBufferLength"),
    )
    current = _artifact(
        tmp_path,
        "current",
        _export("3" * 64, "4" * 64, guarded=False, source_kind="OutputBufferLength"),
    )
    result = discover_windows_candidates(_campaign(tmp_path, monkeypatch, previous, current))
    assert result["candidate_count"] == 0


def test_semantic_site_id_survives_address_and_symbol_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    previous = _artifact(
        tmp_path,
        "previous",
        _export(
            "1" * 64,
            "2" * 64,
            guarded=False,
            base_delta=0,
            handler_name="OldDispatchName",
        ),
    )
    current = _artifact(
        tmp_path,
        "current",
        _export(
            "3" * 64,
            "4" * 64,
            guarded=False,
            base_delta=0x4000,
            handler_name="NewDispatchName",
        ),
    )
    result = discover_windows_candidates(_campaign(tmp_path, monkeypatch, previous, current))
    candidate = result["candidates"][0]
    assert candidate["evidence"]["change"] == "persistent-proof-gap"
    assert len(candidate["evidence"]["semantic_site_id"]) == 64


def test_manifest_reader_rejects_duplicate_keys_and_oversize(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema_version":"0verse.windows-discovery-campaign/v1",'
        '"schema_version":"0verse.windows-discovery-campaign/v1"}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate JSON field"):
        discover_windows_candidates(duplicate)
    oversized = tmp_path / "oversized.json"
    descriptor = os.open(oversized, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, b" " * (2 * 1024 * 1024 + 1))
    finally:
        os.close(descriptor)
    with pytest.raises(ValueError, match="bounded nonempty regular file"):
        discover_windows_candidates(oversized)


def test_pair_intake_output_is_recomputed_and_bound_to_loaded_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    previous = _artifact(tmp_path, "previous", _export("1" * 64, "2" * 64, guarded=True))
    current = _artifact(tmp_path, "current", _export("3" * 64, "4" * 64, guarded=False))
    pair = _pair_input(tmp_path, monkeypatch, previous, current)
    result = discover_windows_candidates(pair)
    assert result["pair_intake_binding"]["pair_intake_consumed"] is True
    assert result["pair_intake_binding"]["pair_id"]
    assert result["servicing_lineage_established"] is False
    assert result["servicing_adjacency_established"] is False

    tampered = json.loads(pair.read_text(encoding="utf-8"))
    tampered["snapshots"][1]["binary_sha256"] = "9" * 64
    pair.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ValueError, match="descriptor hash mismatch"):
        discover_windows_candidates(pair)


def test_direct_pair_input_cannot_bypass_public_artifact_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    previous = _artifact(tmp_path, "previous", _export("1" * 64, "2" * 64, guarded=True))
    current = _artifact(tmp_path, "current", _export("3" * 64, "4" * 64, guarded=False))
    pair = _pair_input(tmp_path, monkeypatch, previous, current)
    raw = json.loads(pair.read_text(encoding="utf-8"))
    for snapshot in raw["snapshots"]:
        snapshot["source_kind"] = "public-artifact"
    raw["windows_discovery_campaign"]["source_declaration"]["kind"] = "public-artifact"
    pair.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="public-artifact local-pair discovery is unsupported"):
        discover_windows_candidates(pair)


@pytest.mark.parametrize(
    ("declaration", "public_sides", "message"),
    [
        ("owned-fixture", (True, True), "does not match loaded artifact provenance"),
        ("public-artifact", (False, False), "does not match loaded artifact provenance"),
        ("public-artifact", (True, False), "mix public and legacy"),
    ],
)
def test_direct_campaign_binds_declared_kind_to_artifact_receipts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    declaration: str,
    public_sides: tuple[bool, bool],
    message: str,
) -> None:
    previous = _artifact(tmp_path, "previous", _export("1" * 64, "2" * 64, guarded=True))
    current = _artifact(tmp_path, "current", _export("3" * 64, "4" * 64, guarded=False))

    def public(artifact: Artifact, enabled: bool) -> Artifact:
        if not enabled:
            return artifact
        return replace(
            artifact,
            public_pdb_receipt_sha256="a" * 64,
            public_pdb_requested_url=(
                "https://msdl.microsoft.com/download/symbols/driver.pdb/key/driver.pdb"
            ),
            public_pdb_exact_age_match=False,
            pe_codeview_identity=artifact.pdb_identity,
        )

    campaign = _campaign(
        tmp_path,
        monkeypatch,
        public(previous, public_sides[0]),
        public(current, public_sides[1]),
    )
    raw = json.loads(campaign.read_text(encoding="utf-8"))
    raw["source_declaration"]["kind"] = declaration
    campaign.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        discover_windows_candidates(campaign)
