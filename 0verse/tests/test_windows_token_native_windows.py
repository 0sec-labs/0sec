from __future__ import annotations

import json
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from zeroverse.windows_token_attestation import WindowsTokenSnapshot
from zeroverse.windows_token_capture import ProductionWindowsTokenSnapshot, derive_token_id

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="requires Windows")

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "native" / "windows-token-capture" / "Cargo.toml"
OPERATION = "fixture.control.noop"
BASE_TOKEN_FIELDS = {
    "token_id",
    "user_sid",
    "integrity_rid",
    "elevation_type",
    "elevated",
    "admin_group",
    "app_container",
    "restricted_sid_count",
    "enabled_privileges",
}


def _run_fixture(run_nonce: str, operation: str = OPERATION) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "--manifest-path",
            str(MANIFEST),
            "--",
            "--run-nonce",
            run_nonce,
            "--operation",
            operation,
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_native_noop_fixture_matches_python_contract_and_rejects_replay() -> None:
    run_nonce = uuid.uuid4().hex
    completed = _run_fixture(run_nonce)
    assert completed.returncode == 0, completed.stderr

    raw = json.loads(completed.stdout)
    assert raw["schema_version"] == "0verse.windows-token-snapshot-pair-fixture/v1"
    assert raw["operation_id"] == OPERATION
    assert raw["run_nonce"] == run_nonce
    assert raw["thread_id_before"] == raw["thread_id_after"]
    assert raw["recorded_at_unix_ms"] > 0
    assert raw["claim_eligible"] is False
    assert raw["fixture"] is True
    assert raw["replay_protection"] == "user-scoped-best-effort"
    assert raw["weaponization"] is False
    assert raw["auto_disclosure"] is False

    snapshots: dict[str, dict[str, object]] = {
        "start": raw["start_token"],
        "finish": raw["finish_token"],
    }
    for phase, snapshot in snapshots.items():
        facts = WindowsTokenSnapshot.from_mapping(
            {key: snapshot[key] for key in BASE_TOKEN_FIELDS}, f"{phase}_token"
        )
        assert snapshot["statistics_token_id_before"] == snapshot["statistics_token_id_after"]
        assert snapshot["modified_id_before"] == snapshot["modified_id_after"]
        assert facts.token_id == derive_token_id(
            run_nonce, phase, snapshot["statistics_token_id_before"]
        )
        if snapshot["lpac_supported"]:
            ProductionWindowsTokenSnapshot.from_mapping(snapshot, f"{phase}_token")
        else:
            assert snapshot["less_privileged_app_container"] is False
            with pytest.raises(ValueError, match="LPAC status is unavailable"):
                ProductionWindowsTokenSnapshot.from_mapping(snapshot, f"{phase}_token")

    assert (
        snapshots["start"]["statistics_token_id_before"]
        == snapshots["finish"]["statistics_token_id_before"]
    )
    assert snapshots["start"]["token_id"] != snapshots["finish"]["token_id"]

    replay = _run_fixture(run_nonce)
    assert replay.returncode != 0
    assert "already been consumed" in replay.stderr


def test_native_fixture_rejects_unregistered_operation_without_consuming_nonce() -> None:
    run_nonce = uuid.uuid4().hex
    rejected = _run_fixture(run_nonce, "candidate.supplied.operation")
    assert rejected.returncode != 0
    assert "fixed harmless operation" in rejected.stderr

    accepted = _run_fixture(run_nonce)
    assert accepted.returncode == 0, accepted.stderr
