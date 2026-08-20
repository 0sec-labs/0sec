from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[1]
BASELINE_PATH = ROOT / "docs" / "baselines" / "r0-2026-07-17.json"
BENCHMARK_PATH = ROOT / "benchmarks" / "groundtruth" / "results.json"


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_r0_baseline_is_bound_to_audited_evidence() -> None:
    baseline = _load(BASELINE_PATH)
    assert baseline["schema_version"] == "0verse.r0-baseline/v1"
    assert re.fullmatch(r"[0-9a-f]{40}", baseline["audited_revision"])

    core = baseline["supported_profiles"]["core_linux"]
    assert core["pytest"]["status"] == "passed"
    assert core["pytest"]["passed"] > 0
    assert core["pytest"]["failed"] == 0
    assert core["evidence_url"].startswith("https://github.com/0sec-labs/0verse/actions/")

    external = baseline["external_profiles"]
    assert external["windows_contract"]["status"] == "unavailable"
    assert external["windows_contract"]["reason"]
    assert external["windows_contract"]["last_known_green"]["passed"] > 0
    assert external["windows_ioctl_ghidra_e2e"]["status"] == "passed"


def test_r0_benchmark_metrics_match_the_hashed_artifact() -> None:
    baseline = _load(BASELINE_PATH)
    result = _load(BENCHMARK_PATH)
    recorded = baseline["benchmark"]
    metrics = result["metrics"]

    digest = hashlib.sha256(BENCHMARK_PATH.read_bytes()).hexdigest()
    assert recorded["artifact"] == str(BENCHMARK_PATH.relative_to(ROOT))
    assert recorded["sha256"] == digest
    assert recorded["lane"] == result["lane"]
    assert recorded["capability_measure"] is False
    assert result["capability_measure"] is False
    assert recorded["runtime_s"] == result["wall_s"]
    assert recorded["items"] == result["n_items"]

    current_gate = recorded["current_pov_gate"]
    assert current_gate["audited_revision"] == baseline["audited_revision"]
    assert current_gate["status"] == "passed"
    assert current_gate["passed"] == current_gate["items"] > 0
    assert current_gate["evidence_url"].startswith(
        "https://github.com/0sec-labs/0verse/actions/"
    )

    detection = recorded["detection"]
    assert detection == {
        "vulnerable_items": metrics["n_vulnerable"],
        "located_items": metrics["located_finds"],
        "confirmed_items": metrics["confirmed_finds"],
        "located_recall": metrics["recall_located"],
        "confirmed_recall": metrics["recall_confirmed"],
        "confirmed_pov_rate": metrics["confirmed_pov_rate"],
    }
    false_positives = recorded["false_positives"]
    assert false_positives == {
        "clean_items": metrics["n_clean"],
        "confirmed_fp_items": metrics["confirmed_fps_items"],
        "hypothesis_fp_items": metrics["hypothesis_fps"],
        "confirmed_fp_rate": metrics["fp_rate_confirmed"],
        "hypothesis_fp_rate": metrics["fp_rate_hypothesis"],
        "confirmed_precision": metrics["precision_confirmed"],
    }


def test_toolchain_inventory_has_paths_and_explicit_skip_reasons() -> None:
    baseline = _load(BASELINE_PATH)
    gates = baseline["toolchain_gates"]
    ids = {gate["id"] for gate in gates}
    assert len(ids) == len(gates)
    assert {
        "openssh-signing",
        "native-c-compiler",
        "linux-elf-execution",
        "angr",
        "afl-plus-plus",
        "qiling",
        "binwalk",
        "rizin-r2ghidra",
        "native-fastpath",
        "windows-native-contracts",
        "linux-procfs",
        "gcc-gdb-container",
        "private-vid-ghidra-pair",
    } <= ids

    for gate in gates:
        assert gate["core_status"]
        assert gate["test_paths"]
        assert gate["skip_reasons"]
        assert all(reason.strip() for reason in gate["skip_reasons"])
        for relative_path in gate["test_paths"]:
            assert (ROOT / relative_path).is_file(), relative_path

    unavailable = baseline["unavailable_capabilities"]
    assert all(item["id"] and item["reason"] for item in unavailable)
    assert {
        "firmware-acquisition-contract",
        "socketcan-capture",
        "isotp-uds-discovery",
        "ecu-firmware-read",
    } <= {item["id"] for item in unavailable}
