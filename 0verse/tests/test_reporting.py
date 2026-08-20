from __future__ import annotations

import json
from pathlib import Path

import pytest

from zeroverse.reporting import load_ndjson, windows_report


def _row(build: str = "26100.1.amd64fre.ge_release") -> dict[str, object]:
    return {
        "classification": "TARGET_ONLY_CRASH",
        "sha256": "a" * 64,
        "size": 5,
        "target": {
            "status": "CRASH",
            "sha256": "a" * 64,
            "binary_name": "target.exe",
            "binary_sha256": "c" * 64,
            "build_lab_ex": build,
            "crash_function": "parse_chunk",
            "crash_cwe": "CWE-787",
            "crash_kind": "heap-buffer-overflow",
            "scope_mode": "UNSPECIFIED",
            "scope_program": "",
            "scope_manifest_sha256": "",
        },
        "control": {
            "status": "CLEAN",
            "sha256": "a" * 64,
            "binary_name": "control.exe",
            "binary_sha256": "d" * 64,
            "build_lab_ex": build,
            "scope_mode": "UNSPECIFIED",
            "scope_program": "",
            "scope_manifest_sha256": "",
        },
    }


def test_windows_report_is_fail_closed() -> None:
    report = windows_report([_row()], title="Candidate")
    assert "Submission ready: NO" in report
    assert "[x] Differential reproduction" in report
    assert "[ ] Canary channel identity" in report
    assert "[ ] Bounty scope provenance" in report
    assert "[ ] Submission approval" in report
    assert "parse_chunk" in report and "CWE-787" in report


def test_canary_identity_passes_but_manual_gates_remain() -> None:
    report = windows_report([_row("28020.1.amd64fre.canary")], title="Candidate")
    assert "[x] Canary channel identity" in report
    assert "Submission ready: NO" in report


def test_scope_provenance_requires_bounty_mode_and_digest() -> None:
    row = _row("28020.1.amd64fre.canary")
    assert isinstance(row["target"], dict)
    row["target"].update(
        scope_mode="BOUNTY_SCOPE",
        scope_program="windows-canary",
        scope_manifest_sha256="a" * 64,
    )
    assert isinstance(row["control"], dict)
    row["control"].update(
        scope_mode="BOUNTY_SCOPE",
        scope_program="windows-canary",
        scope_manifest_sha256="a" * 64,
    )
    report = windows_report([row], title="Candidate")
    assert "[x] Bounty scope provenance" in report
    row["target"]["scope_mode"] = "LAB_ONLY"
    report = windows_report([row], title="Candidate")
    assert "[ ] Bounty scope provenance" in report


def test_report_rejects_forged_top_level_classification() -> None:
    row = _row()
    assert isinstance(row["target"], dict)
    row["target"]["status"] = "CLEAN"
    report = windows_report([row], title="Candidate")
    assert "[ ] Differential reproduction" in report
    assert "[ ] Evidence row consistency" in report


def test_report_rejects_mixed_build_or_scope_evidence() -> None:
    first = _row("28020.1.amd64fre.canary")
    second = _row("28021.1.amd64fre.canary")
    second["sha256"] = "b" * 64
    assert isinstance(second["target"], dict)
    assert isinstance(second["control"], dict)
    second["target"]["sha256"] = "b" * 64
    second["control"]["sha256"] = "b" * 64
    report = windows_report([first, second], title="Candidate")
    assert "[ ] Evidence row consistency" in report
    assert "[ ] Exact build captured" in report


def test_report_rejects_same_binary_as_target_and_control() -> None:
    row = _row("28020.1.amd64fre.canary")
    assert isinstance(row["target"], dict)
    assert isinstance(row["control"], dict)
    row["control"]["binary_sha256"] = row["target"]["binary_sha256"]
    report = windows_report([row], title="Candidate")
    assert "[ ] Differential reproduction" in report
    assert "[ ] Evidence row consistency" in report


def test_load_ndjson(tmp_path: Path) -> None:
    path = tmp_path / "evidence.ndjson"
    path.write_text(json.dumps(_row()) + "\n", encoding="utf-8")
    assert len(load_ndjson(path)) == 1
    path.write_text("[]\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_ndjson(path)


@pytest.mark.parametrize("field", ["target", "control"])
def test_report_fails_closed_on_non_object_nested_evidence(field: str) -> None:
    row = _row("28020.1.amd64fre.canary")
    row[field] = ["not", "an", "object"]

    report = windows_report([row], title="Candidate")

    assert "Submission ready: NO" in report
    assert "[ ] Differential reproduction" in report
    assert "[ ] Evidence row consistency" in report
