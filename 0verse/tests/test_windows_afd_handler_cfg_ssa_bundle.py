from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import zeroverse.windows_afd_handler_cfg_ssa_bundle as bundle
import zeroverse.windows_afd_handler_cfg_ssa_side_replay as side_replay
from zeroverse import cli


def _write_at(directory_fd: int, name: str, raw: bytes) -> None:
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory_fd)
    try:
        os.write(descriptor, raw)
    finally:
        os.close(descriptor)


def _fake_native_snapshot(_source_fd: int, destination_fd: int) -> None:
    _write_at(destination_fd, "semantics.json", b"{}\n")
    _write_at(destination_fd, "receipt.json", b"{}\n")


def _fake_native() -> dict[str, object]:
    return {"sides": {"side_a": {"side": "side_a"}, "side_b": {"side": "side_b"}}}


def test_config_binds_dynamic_core_and_side_schemas() -> None:
    assert bundle._CONFIG["cfg_ssa_schema"] == bundle.core.EXPORT_VERSION
    assert bundle._CONFIG["side_schema"] == bundle.core.ACQUISITION_VERSION
    assert bundle._CONFIG["functions_per_side"] == 33
    assert bundle._CONFIG["isolated_replay_timeout_seconds"] == 1800
    assert bundle._CONFIG["static_only"] is True


def test_receipt_rejects_runtime_attempts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(bundle, "_toolchain_fingerprint", lambda _home: {"pinned": True})
    monkeypatch.setattr(bundle, "_extractor_script_sha256", lambda: "4" * 64)
    receipt = bundle._receipt("1" * 64, "2" * 64, "3" * 64, "4" * 64, {"pinned": True})
    bundle._validate_receipt(receipt, tmp_path)
    receipt["runtime_attempts"] = 1
    with pytest.raises(ValueError, match="receipt contract mismatch"):
        bundle._validate_receipt(receipt, tmp_path)
    receipt["runtime_attempts"] = 0
    receipt["isolated_replay_timeout_seconds"] = True
    with pytest.raises(ValueError, match="receipt contract mismatch"):
        bundle._validate_receipt(receipt, tmp_path)


def test_producer_builds_privately_and_publishes_no_replace(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "native-source"
    source.mkdir()
    output = tmp_path / "published"
    artifact_bytes = b"{}\n"
    artifact_sha = hashlib.sha256(artifact_bytes).hexdigest()
    monkeypatch.setattr(bundle, "_snapshot_semantics_bundle", _fake_native_snapshot)
    monkeypatch.setattr(bundle, "_verify_snapshotted_semantics_bundle", lambda *_: _fake_native())
    monkeypatch.setattr(bundle, "_toolchain_fingerprint", lambda _home: {"pinned": True})
    monkeypatch.setattr(bundle, "_extractor_script_sha256", lambda: "4" * 64)
    monkeypatch.setattr(bundle, "_require_pins", lambda *_: None)
    monkeypatch.setattr(
        bundle, "_retained_side_inputs", lambda *_: (tmp_path / "driver", tmp_path / "pdb")
    )
    monkeypatch.setattr(
        bundle, "_acquire_side_isolated", lambda *_args, side, **_kwargs: {"side": side}
    )
    monkeypatch.setattr(bundle, "compile_windows_afd_handler_cfg_ssa", lambda *_: {})
    monkeypatch.setattr(bundle, "canonical_handler_cfg_ssa_bytes", lambda _raw: artifact_bytes)
    monkeypatch.setattr(bundle, "_verify_bundle_isolated", lambda *_: artifact_sha)

    result = bundle.produce_windows_afd_handler_cfg_ssa(source, output, ghidra_home=tmp_path)

    assert result["cfg_ssa_sha256"] == artifact_sha
    assert (output / "cfg-ssa.json").read_bytes() == artifact_bytes
    receipt = json.loads((output / "receipt.json").read_bytes())
    assert receipt["native_bundle"] == "native"
    assert receipt["side_hard_process_timeout_seconds"] == 300
    assert receipt["static_only"] is True
    assert receipt["execution_authorized"] is False
    assert (output / "native" / "semantics.json").is_file()

    with pytest.raises(FileExistsError, match="output already exists"):
        bundle.produce_windows_afd_handler_cfg_ssa(source, output, ghidra_home=tmp_path)


def test_snapshot_rejects_symlinked_artifact(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    (source / "receipt.json").write_bytes(b"{}\n")
    target = source / "outside.json"
    target.write_bytes(b"{}\n")
    (source / "cfg-ssa.json").symlink_to(target)
    (source / "native").mkdir()
    source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    destination_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(ValueError, match="regular non-symlink"):
            bundle._snapshot_cfg_ssa_bundle(source_fd, destination_fd)
    finally:
        os.close(destination_fd)
        os.close(source_fd)


def test_capture_process_kills_and_reaps_eof_live_child() -> None:
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import os,time;os.close(1);os.close(2);time.sleep(60)",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    with pytest.raises(ValueError, match="exceeded its timeout"):
        bundle._capture_process(process, timeout_seconds=1, label="test child")
    assert process.returncode is not None


def test_capture_process_read_exception_kills_and_reaps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import os,time;os.write(1,b'x');time.sleep(60)",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )

    def fail_read(_descriptor: int, _size: int) -> bytes:
        raise OSError("synthetic read failure")

    monkeypatch.setattr(bundle.os, "read", fail_read)
    with pytest.raises(OSError, match="synthetic read failure"):
        bundle._capture_process(process, timeout_seconds=1, label="test child")
    assert process.returncode is not None


def _spawn_leader_with_detached_io_descendant(pid_path: Path) -> subprocess.Popen[bytes]:
    script = (
        "import pathlib,subprocess,sys;"
        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],"
        "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
        f"pathlib.Path({str(pid_path)!r}).write_text(str(child.pid));"
        "print('invalid-marker',flush=True);"
        "raise SystemExit(7)"
    )
    return subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )


def _assert_process_terminated(pid: int) -> None:
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        try:
            stat_suffix = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1]
        except (IndexError, OSError):
            pass
        else:
            if stat_suffix.split()[0] == "Z":
                return
        time.sleep(0.02)
    pytest.fail(f"process {pid} remained executable after dedicated process-group cleanup")


def test_cleanup_kills_descendant_after_leader_already_exited(tmp_path: Path) -> None:
    pid_path = tmp_path / "descendant.pid"
    process = _spawn_leader_with_detached_io_descendant(pid_path)
    assert process.wait(timeout=5) == 7
    descendant = int(pid_path.read_text())
    os.kill(descendant, 0)
    bundle._kill_process_group(process)
    _assert_process_terminated(descendant)


def test_normal_capture_sweeps_nonzero_invalid_marker_descendant(tmp_path: Path) -> None:
    pid_path = tmp_path / "descendant.pid"
    process = _spawn_leader_with_detached_io_descendant(pid_path)
    stdout, _stderr = bundle._capture_process(
        process, timeout_seconds=5, label="invalid marker child"
    )
    assert process.returncode == 7
    assert stdout == b"invalid-marker\n"
    _assert_process_terminated(int(pid_path.read_text()))


def test_side_isolation_uses_private_canonical_file_and_hard_deadline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    observed: dict[str, object] = {}

    def fake_popen(command: list[str], **kwargs: object) -> SimpleNamespace:
        observed["command"] = command
        observed["popen"] = kwargs
        return SimpleNamespace(returncode=0)

    def fake_capture(_process: object, *, timeout_seconds: int, label: str) -> tuple[bytes, bytes]:
        observed["timeout"] = timeout_seconds
        observed["label"] = label
        output = Path(cast(list[str], observed["command"])[-1])
        raw = b'{"side":"side_a"}\n'
        output.write_bytes(raw)
        marker = {
            "schema_version": "0verse.windows-afd-cfg-ssa-side-isolated-result/v1",
            "side": "side_a",
            "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        }
        return (
            (
                "0VERSE_AFD_CFG_SSA_SIDE_RESULT=" + json.dumps(marker, sort_keys=True) + "\n"
            ).encode(),
            b"",
        )

    monkeypatch.setattr(bundle.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(bundle, "_capture_process", fake_capture)
    facts = bundle._acquire_side_isolated(
        tmp_path / "driver",
        tmp_path / "pdb",
        tmp_path / "ghidra",
        tmp_path / "semantics.json",
        side="side_a",
    )
    assert facts == {"side": "side_a"}
    assert observed["timeout"] == 300
    assert cast(dict[str, object], observed["popen"])["start_new_session"] is True
    assert cast(list[str], observed["command"])[0:3] == [sys.executable, "-I", "-c"]


def test_side_isolation_rejects_output_hash_tamper(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    command_holder: list[str] = []

    def fake_popen(command: list[str], **_kwargs: object) -> SimpleNamespace:
        command_holder[:] = command
        return SimpleNamespace(returncode=0)

    def fake_capture(_process: object, *, timeout_seconds: int, label: str) -> tuple[bytes, bytes]:
        del timeout_seconds, label
        Path(command_holder[-1]).write_bytes(b'{"side":"side_a"}\n')
        marker = {
            "schema_version": "0verse.windows-afd-cfg-ssa-side-isolated-result/v1",
            "side": "side_a",
            "artifact_sha256": "0" * 64,
        }
        return (
            (
                "0VERSE_AFD_CFG_SSA_SIDE_RESULT=" + json.dumps(marker, sort_keys=True) + "\n"
            ).encode(),
            b"",
        )

    monkeypatch.setattr(bundle.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(bundle, "_capture_process", fake_capture)
    with pytest.raises(ValueError, match="artifact SHA-256 mismatch"):
        bundle._acquire_side_isolated(
            tmp_path / "driver",
            tmp_path / "pdb",
            tmp_path / "ghidra",
            tmp_path / "semantics.json",
            side="side_a",
        )


def test_side_helper_writes_exclusive_canonical_private_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    native = tmp_path / "native.json"
    native.write_bytes(b"{}")
    output = tmp_path / "side.json"
    monkeypatch.setattr(
        side_replay,
        "_validate_native",
        lambda _raw: {"sides": {"side_a": {"side": "side_a"}}},
    )
    monkeypatch.setattr(
        side_replay,
        "acquire_afd_handler_cfg_ssa_side",
        lambda *_args, **_kwargs: {"z": 1, "a": 2},
    )
    argv = ["driver", "pdb", "ghidra", str(native), "side_a", str(output)]
    assert side_replay.main(argv) == 0
    assert output.read_bytes() == b'{"a":2,"z":1}\n'
    assert output.stat().st_mode & 0o777 == 0o600
    marker = capsys.readouterr().out
    assert marker.startswith("0VERSE_AFD_CFG_SSA_SIDE_RESULT=")
    with pytest.raises(FileExistsError):
        side_replay.main(argv)


def test_cli_requires_toolchain_for_cfg_ssa_commands(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["windows-afd-handler-cfg-ssa", "native", "output"]) == 2
    assert "--ghidra-home" in capsys.readouterr().err
    assert cli.main(["windows-afd-handler-cfg-ssa-verify", "bundle"]) == 2
    assert "--ghidra-home" in capsys.readouterr().err


def test_cli_dispatches_cfg_ssa_producer(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    observed: dict[str, Any] = {}

    def fake_produce(native: str, output: str, *, ghidra_home: str) -> dict[str, str]:
        observed.update(native=native, output=output, ghidra_home=ghidra_home)
        return {"cfg_ssa_sha256": "a" * 64}

    monkeypatch.setattr(bundle, "produce_windows_afd_handler_cfg_ssa", fake_produce)
    assert (
        cli.main(
            [
                "windows-afd-handler-cfg-ssa",
                "native",
                "output",
                "--ghidra-home",
                "/ghidra",
            ]
        )
        == 0
    )
    assert observed == {"native": "native", "output": "output", "ghidra_home": "/ghidra"}
    assert json.loads(capsys.readouterr().out)["cfg_ssa_sha256"] == "a" * 64


def test_cli_dispatches_cfg_ssa_verifier(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    observed: dict[str, str] = {}

    def fake_verify(bundle_path: str, *, ghidra_home: str) -> dict[str, str]:
        observed.update(bundle=bundle_path, ghidra_home=ghidra_home)
        return {"schema_version": "verified"}

    monkeypatch.setattr(bundle, "verify_windows_afd_handler_cfg_ssa_bundle", fake_verify)
    assert (
        cli.main(
            [
                "windows-afd-handler-cfg-ssa-verify",
                "bundle",
                "--ghidra-home",
                "/ghidra",
            ]
        )
        == 0
    )
    assert observed == {"bundle": "bundle", "ghidra_home": "/ghidra"}
    assert json.loads(capsys.readouterr().out) == {"schema_version": "verified"}
