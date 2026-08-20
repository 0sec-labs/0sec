from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time
from functools import cache
from pathlib import Path
from typing import cast

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="requires Windows handles")


def _producer() -> Path:
    return (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "windows"
        / "write-retained-driver-servicing-evidence.ps1"
    )


def _command(driver: Path, output: Path) -> list[str]:
    return [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(_producer()),
        "-DriverPath",
        str(driver),
        "-OutputPath",
        str(output),
    ]


def _run(
    driver: Path, output: Path, *, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # foxguard: ignore[py/no-command-injection]
        _command(driver, output),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
    )


def _start(
    driver: Path,
    output: Path,
    *,
    pause_before_publish_ms: int | None = None,
    pause_after_rename_ms: int | None = None,
    fail_after_rename: bool = False,
) -> subprocess.Popen[str]:
    env = os.environ.copy()
    if pause_before_publish_ms is not None:
        env["ZEROVERSE_SERVICING_TEST_PAUSE_BEFORE_PUBLISH_MS"] = str(
            pause_before_publish_ms
        )
    if pause_after_rename_ms is not None:
        env["ZEROVERSE_SERVICING_TEST_PAUSE_AFTER_RENAME_MS"] = str(pause_after_rename_ms)
    if fail_after_rename:
        env["ZEROVERSE_SERVICING_TEST_FAIL_AFTER_RENAME"] = "1"
    return subprocess.Popen(  # foxguard: ignore[py/no-command-injection]
        _command(driver, output),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )


def _fixed_version(path: Path) -> tuple[int, int, int, int]:
    env = os.environ.copy()
    env["ZEROVERSE_TEST_FIXED_VERSION_PATH"] = str(path)
    script = (
        "$path=$env:ZEROVERSE_TEST_FIXED_VERSION_PATH;"
        "if ([string]::IsNullOrWhiteSpace($path)) { throw 'missing test path' };"
        "$v=[System.Diagnostics.FileVersionInfo]::GetVersionInfo($path);"
        "Write-Output \"$($v.FileMajorPart).$($v.FileMinorPart)."
        "$($v.FileBuildPart).$($v.FilePrivatePart)\""
    )
    process = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=env,
    )
    assert process.returncode == 0, process.stdout + process.stderr
    fields = tuple(int(field) for field in process.stdout.strip().split("."))
    assert len(fields) == 4
    return cast(tuple[int, int, int, int], fields)


def _current_build() -> int:
    import winreg

    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
    ) as key:
        value, _kind = winreg.QueryValueEx(key, "CurrentBuild")
    return int(value)


def _machine(path: Path) -> int:
    with path.open("rb") as stream:
        assert stream.read(2) == b"MZ"
        stream.seek(0x3C)
        pe_offset = struct.unpack("<I", stream.read(4))[0]
        stream.seek(pe_offset)
        assert stream.read(4) == b"PE\0\0"
        return struct.unpack("<H", stream.read(2))[0]


@cache
def _authentic_driver() -> Path:
    system32 = Path(os.environ["SYSTEMROOT"]) / "System32"
    drivers = system32 / "drivers"
    preferred = tuple(
        drivers / candidate_name
        for candidate_name in ("null.sys", "disk.sys", "ndis.sys", "acpi.sys")
    )
    discovered = sorted(
        (*drivers.rglob("*.sys"), *system32.glob("*.sys")),
        key=lambda candidate: str(candidate).casefold(),
    )
    seen: set[Path] = set()
    current_build = _current_build()
    rejected: list[str] = []
    for candidate in (*preferred, *discovered):
        normalized = Path(os.path.normcase(candidate.resolve(strict=False)))
        if normalized in seen:
            continue
        seen.add(normalized)
        try:
            if (
                candidate.is_file()
                and _machine(candidate) == 0x8664
                and _fixed_version(candidate)[2] == current_build
            ):
                return candidate
        except (AssertionError, OSError, ValueError) as exc:
            rejected.append(f"{candidate.name}: {exc}")
    details = "; ".join(rejected[:5]) or "no readable candidates"
    pytest.fail(
        "required native servicing tests could not find a readable amd64 system "
        f"driver with fixed-version build {current_build} under {drivers} or "
        f"{system32}: {details}"
    )


def _retained_driver(tmp_path: Path, name: str = "vmswitch.sys") -> Path:
    candidate = _authentic_driver()
    try:
        retained = tmp_path / name
        shutil.copyfile(candidate, retained)
        return retained
    except OSError as exc:
        pytest.fail(f"required native servicing driver copy failed for {candidate}: {exc}")


def _wait_for_temporary_output(parent: Path, process: subprocess.Popen[str]) -> Path:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        matches = list(parent.glob(".servicing-evidence-*.tmp"))
        if matches:
            try:
                if matches[0].stat().st_size > 0:
                    return matches[0]
            except FileNotFoundError:
                pass
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(f"producer exited before publication pause: {stdout}{stderr}")
        time.sleep(0.02)
    process.kill()
    stdout, stderr = process.communicate()
    pytest.fail(f"producer did not reach publication pause: {stdout}{stderr}")


def _wait_for_final_output(output: Path, process: subprocess.Popen[str]) -> None:
    # Publication becomes visible before the producer releases its DELETE-capable
    # custody handle. Observe directory-entry existence here; read only after exit.
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if output.is_file():
            return
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(f"producer exited before post-rename pause: {stdout}{stderr}")
        time.sleep(0.02)
    process.kill()
    stdout, stderr = process.communicate()
    pytest.fail(f"producer did not reach post-rename pause: {stdout}{stderr}")


def test_required_normalizes_actual_fixed_version_from_custodied_snapshot(
    tmp_path: Path,
) -> None:
    driver = _retained_driver(tmp_path)
    output = tmp_path / "servicing-evidence.json"
    expected_version = _fixed_version(driver)

    process = _run(driver, output)

    assert process.returncode == 0, process.stdout + process.stderr
    evidence = json.loads(output.read_bytes())
    assert evidence["component"] == driver.name
    assert evidence["file_version"] == ".".join(str(field) for field in expected_version)
    assert evidence["binary_sha256"] == hashlib.sha256(driver.read_bytes()).hexdigest()
    assert not list(tmp_path.glob(".servicing-evidence-*.tmp"))
    assert not list(tmp_path.glob(".zeroverse-servicing-*"))


def test_rejects_final_driver_symlink_without_output(tmp_path: Path) -> None:
    target = _retained_driver(tmp_path, "target.sys")
    link = tmp_path / "linked.sys"
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"file symlink creation is unavailable: {exc}")
    output = tmp_path / "servicing-evidence.json"

    process = _run(link, output)

    assert process.returncode != 0
    assert "non-reparse" in process.stderr or "different final path" in process.stderr
    assert not output.exists()


def test_rejects_output_ancestor_junction(tmp_path: Path) -> None:
    driver = _retained_driver(tmp_path)
    actual = tmp_path / "actual-output"
    actual.mkdir()
    junction = tmp_path / "junction-output"
    linked = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(actual)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if linked.returncode != 0:
        pytest.skip(f"junction creation is unavailable: {linked.stdout}{linked.stderr}")

    output = junction / "servicing-evidence.json"
    process = _run(driver, output)

    assert process.returncode != 0
    assert "ancestry must not contain a reparse point" in process.stderr
    assert not output.exists()
    assert not (actual / output.name).exists()


def test_required_held_identities_block_source_and_output_ancestor_retarget(
    tmp_path: Path,
) -> None:
    source_parent = tmp_path / "source"
    source_parent.mkdir()
    output_ancestor = tmp_path / "output-ancestor"
    parent = output_ancestor / "custodied-output"
    parent.mkdir(parents=True)
    driver = _retained_driver(source_parent)
    replacement = _retained_driver(tmp_path, "replacement.sys")
    original_sha256 = hashlib.sha256(driver.read_bytes()).hexdigest()
    output = parent / "servicing-evidence.json"
    process = _start(driver, output, pause_before_publish_ms=5000)
    _wait_for_temporary_output(parent, process)

    with pytest.raises(OSError):
        replacement.replace(driver)
    with pytest.raises(OSError):
        parent.rename(tmp_path / "retargeted-output")
    with pytest.raises(OSError):
        output_ancestor.rename(tmp_path / "retargeted-ancestor")

    stdout, stderr = process.communicate(timeout=30)
    assert process.returncode == 0, stdout + stderr
    evidence = json.loads(output.read_bytes())
    assert evidence["binary_sha256"] == original_sha256
    assert parent.is_dir()
    assert not (tmp_path / "retargeted-output").exists()
    assert not (tmp_path / "retargeted-ancestor").exists()


def test_required_interruption_never_publishes_partial_final_output(
    tmp_path: Path,
) -> None:
    driver = _retained_driver(tmp_path)
    output = tmp_path / "servicing-evidence.json"
    process = _start(driver, output, pause_before_publish_ms=30000)
    _wait_for_temporary_output(tmp_path, process)

    process.terminate()
    process.communicate(timeout=30)

    assert process.returncode != 0
    assert not output.exists()


def test_required_post_rename_interruption_leaves_only_complete_final_output(
    tmp_path: Path,
) -> None:
    driver = _retained_driver(tmp_path)
    output = tmp_path / "servicing-evidence.json"
    process = _start(driver, output, pause_after_rename_ms=30000)
    _wait_for_final_output(output, process)

    process.terminate()
    process.communicate(timeout=30)

    assert process.returncode != 0
    published = output.read_bytes()
    evidence = json.loads(published)
    assert evidence["binary_sha256"] == hashlib.sha256(driver.read_bytes()).hexdigest()


def test_required_post_rename_failure_cleans_only_held_output_handle(
    tmp_path: Path,
) -> None:
    driver = _retained_driver(tmp_path)
    output = tmp_path / "servicing-evidence.json"
    operator_file = tmp_path / "operator-owned.json"
    operator_file.write_bytes(b"operator-owned\n")
    process = _start(
        driver,
        output,
        pause_after_rename_ms=5000,
        fail_after_rename=True,
    )
    _wait_for_final_output(output, process)

    with pytest.raises(OSError):
        operator_file.replace(output)

    stdout, stderr = process.communicate(timeout=30)
    assert process.returncode != 0, stdout + stderr
    assert not output.exists()
    assert operator_file.read_bytes() == b"operator-owned\n"


def test_required_raced_final_name_is_never_replaced(tmp_path: Path) -> None:
    driver = _retained_driver(tmp_path)
    output = tmp_path / "servicing-evidence.json"
    raced = b"raced-operator-output\n"
    process = _start(driver, output, pause_before_publish_ms=5000)
    _wait_for_temporary_output(tmp_path, process)
    output.write_bytes(raced)

    process.communicate(timeout=30)

    assert process.returncode != 0
    assert output.read_bytes() == raced


def test_required_rejects_ntfs_alternate_data_stream_output(tmp_path: Path) -> None:
    driver = _retained_driver(tmp_path)
    output = tmp_path / "servicing-evidence.json:stream"

    process = _run(driver, output)

    assert process.returncode != 0
    assert "safe final basename" in process.stderr
    assert not (tmp_path / "servicing-evidence.json").exists()


def test_required_no_replace_publication_preserves_existing_output(tmp_path: Path) -> None:
    driver = _retained_driver(tmp_path)
    output = tmp_path / "servicing-evidence.json"
    original = b"operator-owned\n"
    output.write_bytes(original)

    process = _run(driver, output)

    assert process.returncode != 0
    assert output.read_bytes() == original


@pytest.mark.parametrize("name", ["receipt.json:stream", "NUL.json", "receipt."])
def test_required_rejects_unsafe_output_basename_without_side_effects(
    tmp_path: Path, name: str
) -> None:
    driver = _retained_driver(tmp_path)
    output = tmp_path / name

    process = _run(driver, output)

    assert process.returncode != 0
    assert "safe final basename" in process.stderr
    assert not output.exists()
    assert not list(tmp_path.glob(".servicing-evidence-*.tmp"))
    assert not list(tmp_path.glob(".zeroverse-servicing-*"))
