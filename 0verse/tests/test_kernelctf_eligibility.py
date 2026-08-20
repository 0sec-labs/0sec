from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).parents[1] / "scripts/kernelctf/eligibility.py"
SPEC = importlib.util.spec_from_file_location("kernelctf_eligibility", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def valid() -> tuple[dict[str, Any], dict[str, Any], dict[str, bool]]:
    candidate = {
        "requires_unprivileged_userns": False,
        "requires_io_uring": False,
        "requires_nftables": False,
        "required_config": ["CONFIG_KEYS"],
        "reliability_percent": 90,
        "runtime_seconds": 20,
        "stole_flag": True,
        "kernelxdk_ready": True,
    }
    target = {
        "release": "lts-6.12.94",
        "commit_hash": "0b8f247169e4",
        "slot_status": "free",
        "runtime_policy": {
            "unprivileged_userns": False,
            "io_uring": False,
            "nftables": False,
        },
    }
    return candidate, target, {"CONFIG_KEYS": True}


def test_valid_candidate_passes() -> None:
    assert MODULE.evaluate(*valid()) == []


def test_taken_slot_and_runtime_dependency_fail() -> None:
    candidate, target, config = valid()
    target["slot_status"] = "taken"
    candidate["requires_io_uring"] = True
    failures = MODULE.evaluate(candidate, target, config)
    assert "target slot is taken" in failures
    assert "candidate does not confirm requires_io_uring=false" in failures


def test_missing_config_and_measurements_fail_closed() -> None:
    candidate, target, config = valid()
    candidate["required_config"] = ["CONFIG_MISSING"]
    del candidate["reliability_percent"]
    del candidate["runtime_seconds"]
    failures = MODULE.evaluate(candidate, target, config)
    assert "required target config is disabled or absent: CONFIG_MISSING" in failures
    assert "measured reliability is below 10% or missing" in failures
    assert "measured runtime exceeds 300 seconds or is missing" in failures
