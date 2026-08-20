from __future__ import annotations

import json
from pathlib import Path

import pytest

from zeroverse.cli import main
from zeroverse.windows_ioctl_boundary import plan_windows_ioctl_boundary


def _ctl_code(device_type: int, function: int, method: int = 0, access: int = 0) -> int:
    return (device_type << 16) | (access << 14) | (function << 2) | method


def _manifest() -> dict[str, object]:
    driver = "1" * 64
    machine = "2" * 64
    build = "synthetic.26100.amd64fre.fixture"
    return {
        "schema_version": "0verse.windows-ioctl-boundary/v1",
        "campaign_id": "fixture-driver-buffer-geometry",
        "synthetic_fixture": True,
        "scope_manifest_sha256": "3" * 64,
        "worker": {
            "fqdn": "fixture-worker.local",
            "machine_id": machine,
            "build_lab_ex": build,
            "architecture": "amd64",
            "collector_sha256": "4" * 64,
        },
        "target": {
            "driver_sha256": driver,
            "pdb_sha256": "5" * 64,
            "analysis_receipt_sha256": "6" * 64,
            "service_name": "ZeroverseFixture",
            "device_type": 0x8337,
        },
        "boundary": {
            "schema_version": "0verse.windows-boundary-observation/fixture-v1",
            "receipt_sha256": "7" * 64,
            "worker_machine_id": machine,
            "build_lab_ex": build,
            "driver_sha256": driver,
            "interface_class_guid": "{12345678-1234-1234-1234-1234567890ab}",
            "instance_id": "ROOT\\ZEROVERSEFIXTURE\\0000",
            "starting_context_assertion": "synthetic-standard-user",
            "open_result_assertion": "synthetic-allowed",
        },
        "budgets": {
            "max_ioctls": 4,
            "max_seeds": 4,
            "max_fields_per_seed": 4,
            "max_candidates": 64,
            "max_input_bytes": 4096,
            "max_output_bytes": 4096,
            "timeout_ms": 5000,
        },
        "ioctls": [
            {
                "code": _ctl_code(0x8337, 0x801),
                "device_type": 0x8337,
                "function": 0x801,
                "method": "buffered",
                "access": "any",
                "handler_name": "FixtureDeviceControl",
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


def _write(tmp_path: Path, manifest: dict[str, object]) -> Path:
    path = tmp_path / "campaign.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return path


def test_plans_deterministic_bounded_candidate_descriptors(tmp_path: Path) -> None:
    path = _write(tmp_path, _manifest())
    first = plan_windows_ioctl_boundary(path)
    second = plan_windows_ioctl_boundary(path)

    assert first == second
    assert first["candidate_count"] == 6
    assert first["device_ioctl_attempts"] == 0
    assert first["capability_measure"] is False
    assert first["claim_eligible"] is False
    assert first["bounty_eligible"] is False
    assert first["weaponization"] is False
    assert first["automatic_disclosure"] is False
    assert first["human_report_gate"] is True
    assert first["budgets"] == _manifest()["budgets"]
    assert first["boundary"]["receipt_verified"] is False
    assert "verified" not in first["boundary"]["starting_context_assertion"]
    assert first["boundary"]["open_result_assertion"] == "synthetic-allowed"
    candidates = first["candidates"]
    assert isinstance(candidates, list)
    assert {row["status"] for row in candidates} == {"candidate"}
    assert [row["mutation"]["value"] for row in candidates] == [0, 1, 15, 16, 17, 4096]
    assert len({row["candidate_id"] for row in candidates}) == len(candidates)


def test_access_any_is_preserved_but_not_treated_as_reachability_proof(tmp_path: Path) -> None:
    result = plan_windows_ioctl_boundary(_write(tmp_path, _manifest()))
    candidate = result["candidates"][0]  # type: ignore[index]
    assert candidate["access"] == "any"
    assert (
        "signed natural-standard-user boundary observation" in candidate["required_next_validator"]
    )
    assert "does not prove device reachability" in result["proof_limit"]


@pytest.mark.parametrize("method,number", [("in-direct", 1), ("out-direct", 2), ("neither", 3)])
def test_rejects_non_buffered_methods(tmp_path: Path, method: str, number: int) -> None:
    manifest = _manifest()
    ioctl = manifest["ioctls"][0]  # type: ignore[index]
    ioctl["method"] = method
    ioctl["code"] = _ctl_code(0x8337, 0x801, number)
    with pytest.raises(ValueError, match="METHOD_BUFFERED"):
        plan_windows_ioctl_boundary(_write(tmp_path, manifest))


def test_rejects_ctl_code_decomposition_mismatch(tmp_path: Path) -> None:
    manifest = _manifest()
    manifest["ioctls"][0]["function"] = 0x802  # type: ignore[index]
    with pytest.raises(ValueError, match="CTL_CODE decomposition"):
        plan_windows_ioctl_boundary(_write(tmp_path, manifest))


def test_rejects_unbound_boundary_observation(tmp_path: Path) -> None:
    manifest = _manifest()
    manifest["boundary"]["driver_sha256"] = "9" * 64  # type: ignore[index]
    with pytest.raises(ValueError, match="not bound"):
        plan_windows_ioctl_boundary(_write(tmp_path, manifest))


def test_rejects_unsigned_verified_reachability_semantics(tmp_path: Path) -> None:
    manifest = _manifest()
    manifest["boundary"]["starting_context_assertion"] = "standard-user-verified"  # type: ignore[index]
    with pytest.raises(ValueError, match="synthetic assertions"):
        plan_windows_ioctl_boundary(_write(tmp_path, manifest))


def test_rejects_non_synthetic_campaign_until_signed_runtime_exists(tmp_path: Path) -> None:
    manifest = _manifest()
    manifest["synthetic_fixture"] = False
    with pytest.raises(ValueError, match="synthetic-fixture"):
        plan_windows_ioctl_boundary(_write(tmp_path, manifest))


def test_rejects_runtime_or_network_policy(tmp_path: Path) -> None:
    manifest = _manifest()
    manifest["policy"]["runtime_enabled"] = True  # type: ignore[index]
    with pytest.raises(ValueError, match="inert v1 safety policy"):
        plan_windows_ioctl_boundary(_write(tmp_path, manifest))


def test_rejects_candidate_budget_overflow(tmp_path: Path) -> None:
    manifest = _manifest()
    manifest["budgets"]["max_candidates"] = 5  # type: ignore[index]
    with pytest.raises(ValueError, match="exceed max_candidates"):
        plan_windows_ioctl_boundary(_write(tmp_path, manifest))


def test_rejects_field_outside_seed(tmp_path: Path) -> None:
    manifest = _manifest()
    manifest["seeds"][0]["fields"][0]["offset"] = 14  # type: ignore[index]
    with pytest.raises(ValueError, match="extends beyond seed"):
        plan_windows_ioctl_boundary(_write(tmp_path, manifest))


def test_rejects_unknown_fields_and_duplicate_json_keys(tmp_path: Path) -> None:
    manifest = _manifest()
    manifest["payload"] = "not accepted"
    with pytest.raises(ValueError, match="fields mismatch"):
        plan_windows_ioctl_boundary(_write(tmp_path, manifest))

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":"x","schema_version":"y"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON key"):
        plan_windows_ioctl_boundary(duplicate)


def test_cli_writes_exclusively_and_does_not_overwrite(tmp_path: Path) -> None:
    manifest = _write(tmp_path, _manifest())
    output = tmp_path / "plan.json"
    assert main(["windows-ioctl-plan", str(manifest), "--output", str(output)]) == 0
    assert json.loads(output.read_text())["device_ioctl_attempts"] == 0
    assert main(["windows-ioctl-plan", str(manifest), "--output", str(output)]) == 2
