from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from zeroverse import windows_oracle
from zeroverse.cli import main
from zeroverse.oracle import RunResult
from zeroverse.windows_scope import WindowsScope, load_scope, verify_evidence_builds


def scope(**updates: object) -> dict[str, object]:
    now = datetime.now(UTC).isoformat()
    raw: dict[str, object] = {
        "schema_version": "0verse.windows-scope/v1",
        "campaign_id": "wic-parser-001",
        "program": "windows-canary",
        "scope_url": "https://www.microsoft.com/en-us/msrc/bounty-windows-insider-preview",
        "target_feature": "Windows Imaging Component",
        "reachability": "attacker-supplied image opened through serviced Explorer preview",
        "authorization": "published MSRC bounty scope; 0sec-owned VM",
        "worker": "worker-01.example.test",
        "latest_build_verified_at": now,
        "latest_build_number": "29617.1000",
        "latest_build_source_url": "https://learn.microsoft.com/en-us/windows-insider/flight-hub/",
        "preflight": {
            "ok": True,
            "program": "windows-canary",
            "checked_at": now,
            "build_lab_ex": "29617.1000.amd64fre.rs_prerelease",
            "product_name": "Windows 11 Pro",
            "hyperv_available": False,
            "insider": {
                "ring": "CanaryChannel",
                "content_type": "Mainline",
                "branch_name": "CanaryChannel",
                "channel_family": "experimental-future-platforms",
            },
        },
    }
    raw.update(updates)
    return raw


def test_load_scope_and_hash(tmp_path: Path) -> None:
    path = tmp_path / "scope.json"
    path.write_text(json.dumps(scope()), encoding="utf-8")
    loaded, digest = load_scope(path)
    assert loaded.program == "windows-canary"
    assert len(digest) == 64


def test_preflight_must_pass_and_match() -> None:
    bad = scope()
    assert isinstance(bad["preflight"], dict)
    bad["preflight"]["ok"] = False
    with pytest.raises(ValueError, match="did not pass"):
        WindowsScope.from_mapping(bad)
    mismatch = scope()
    assert isinstance(mismatch["preflight"], dict)
    mismatch["preflight"]["program"] = "hyperv-server"
    with pytest.raises(ValueError, match="program mismatch"):
        WindowsScope.from_mapping(mismatch)


def test_loader_rechecks_channel_identity_instead_of_trusting_ok() -> None:
    ga = scope()
    assert isinstance(ga["preflight"], dict)
    ga["preflight"]["build_lab_ex"] = "26100.1.amd64fre.ge_release"
    ga["preflight"]["insider"] = {"ring": "", "content_type": "", "branch_name": ""}
    with pytest.raises(ValueError, match="Canary-successor"):
        WindowsScope.from_mapping(ga)


def test_current_canary_successors_are_accepted_but_generic_experimental_is_not() -> None:
    for family, build in (
        ("experimental-26h1", "28120.2387"),
        ("experimental-future-platforms", "29617.1000"),
    ):
        raw = scope(latest_build_number=build)
        assert isinstance(raw["preflight"], dict)
        raw["preflight"]["build_lab_ex"] = f"{build}.amd64fre.rs_prerelease"
        assert isinstance(raw["preflight"]["insider"], dict)
        raw["preflight"]["insider"]["channel_family"] = family
        WindowsScope.from_mapping(raw)

    dev = scope(latest_build_number="26300.8772")
    assert isinstance(dev["preflight"], dict)
    dev["preflight"]["build_lab_ex"] = "26300.8772.amd64fre.rs_prerelease"
    assert isinstance(dev["preflight"]["insider"], dict)
    dev["preflight"]["insider"].update(
        {"ring": "External", "branch_name": "rs_prerelease", "channel_family": "experimental"}
    )
    with pytest.raises(ValueError, match="Canary-successor"):
        WindowsScope.from_mapping(dev)


def test_latest_build_must_match_official_flight_hub_record() -> None:
    stale = scope(latest_build_number="29613.1000")
    with pytest.raises(ValueError, match="officially verified latest build"):
        WindowsScope.from_mapping(stale)

    untrusted = scope(latest_build_source_url="https://example.test/flight-hub")
    with pytest.raises(ValueError, match="official English Flight Hub"):
        WindowsScope.from_mapping(untrusted)


def test_channel_family_is_rederived_from_captured_facts() -> None:
    forged = scope()
    assert isinstance(forged["preflight"], dict)
    forged["preflight"]["build_lab_ex"] = "26300.8772.amd64fre.rs_prerelease"
    assert isinstance(forged["preflight"]["insider"], dict)
    forged["preflight"]["insider"].update(
        {"ring": "External", "branch_name": "rs_prerelease", "channel_family": "canary-legacy"}
    )
    with pytest.raises(ValueError, match="Canary-successor"):
        WindowsScope.from_mapping(forged)

    mismatch = scope()
    assert isinstance(mismatch["preflight"], dict)
    assert isinstance(mismatch["preflight"]["insider"], dict)
    mismatch["preflight"]["insider"]["channel_family"] = "experimental-26h1"
    with pytest.raises(ValueError, match="classification mismatch"):
        WindowsScope.from_mapping(mismatch)


@pytest.mark.parametrize(
    ("program", "preflight", "error"),
    [
        (
            "hyperv-insider",
            {
                "build_lab_ex": "28020.1.amd64fre.rs_prerelease",
                "product_name": "Windows 11 Pro",
                "hyperv_available": False,
                "insider": {
                    "ring": "External",
                    "content_type": "Mainline",
                    "branch_name": "rs_prerelease",
                },
            },
            "Hyper-V",
        ),
        (
            "hyperv-server",
            {
                "build_lab_ex": "26100.1.amd64fre.ge_release",
                "product_name": "Windows 11 Pro",
                "hyperv_available": True,
                "insider": {"ring": "", "content_type": "", "branch_name": ""},
            },
            "Windows Server",
        ),
    ],
)
def test_loader_rechecks_hyperv_program_facts(
    program: str, preflight: dict[str, object], error: str
) -> None:
    raw = scope(program=program)
    assert isinstance(raw["preflight"], dict)
    raw["preflight"].update(preflight)
    raw["preflight"]["program"] = program
    with pytest.raises(ValueError, match=error):
        WindowsScope.from_mapping(raw)


def test_freshness_is_24_hours() -> None:
    old = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    with pytest.raises(ValueError, match="24 hours"):
        WindowsScope.from_mapping(scope(latest_build_verified_at=old))


def test_evidence_build_must_match_preflight() -> None:
    loaded = WindowsScope.from_mapping(scope())
    verify_evidence_builds(loaded, [loaded.preflight_build_lab_ex] * 2)
    with pytest.raises(ValueError, match="build changed"):
        verify_evidence_builds(loaded, ["different-build"])
    with pytest.raises(ValueError, match="no BuildLabEx"):
        verify_evidence_builds(loaded, [""])


def test_windows_replay_requires_explicit_evidence_mode(tmp_path: Path) -> None:
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    poc = tmp_path / "poc"
    poc.write_bytes(b"input")
    with pytest.raises(SystemExit) as exc:
        main(["windows-replay", str(binary), str(poc)])
    assert exc.value.code == 2


def test_cli_lab_only_marks_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    poc = tmp_path / "poc"
    poc.write_bytes(b"input")
    output = tmp_path / "evidence.json"

    class Worker:
        def __init__(self, host: str, **kwargs: object) -> None:
            assert host == "fixture-worker"
            assert kwargs == {"lab_only": True}

        def run_drmemory(self, binary: Path, data: bytes, *, timeout: float) -> RunResult:
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            input_digest = hashlib.sha256(data).hexdigest()
            return RunResult(
                False,
                stderr=(
                    "0VERSE-BUILDLABEX:lab-build\n"
                    f"0VERSE-BINARY-SHA256:{digest}\n"
                    f"0VERSE-INPUT-SHA256:{input_digest}\n"
                    "0VERSE-EXIT:0"
                ),
            )

    monkeypatch.setattr(windows_oracle, "WindowsWorker", Worker)
    assert (
        main(
            [
                "windows-replay",
                str(binary),
                str(poc),
                "--host",
                "fixture-worker",
                "--lab-only",
                "--format",
                "json",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    rows = json.loads(output.read_text(encoding="utf-8"))
    assert rows[0]["scope_mode"] == "LAB_ONLY"
    assert rows[0]["scope_manifest_sha256"] == ""
