from __future__ import annotations

import base64
import grp
import hashlib
import importlib.util
import json
import os
import pwd
import socket
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType

import pytest

SUPERVISOR = Path(__file__).parents[1] / "scripts/browser/run-campaign.py"
PROTOCOL = "0verse.browser-campaign-supervisor/v1"
RECORD_PREFIX = "0VERSE-BROWSER-CAMPAIGN:"
MAX_OUTPUT_BYTES = 1024 * 1024


def _supervisor_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("browser_campaign_supervisor_test", SUPERVISOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fixture(
    tmp_path: Path, harness_source: str, *, timeout: float = 10
) -> tuple[dict[str, object], Path]:
    source = tmp_path / "src"
    harness = source / "out" / "asan" / "fixture_fuzzer"
    corpus = tmp_path / "corpus"
    artifact_root = tmp_path / "artifacts"
    artifact_dir = artifact_root / "fixture"
    marker = tmp_path / ".browser-worker"
    harness.parent.mkdir(parents=True)
    corpus.mkdir()
    artifact_dir.mkdir(parents=True)
    marker.write_text("schema=1\nhostname=browser\n", encoding="utf-8")
    marker.chmod(0o640)
    harness.write_text(harness_source, encoding="utf-8")
    harness.chmod(0o750)
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(source),
            "-c",
            "user.name=0verse test",
            "-c",
            "user.email=test@0verse.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    revision = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    marker_stat = marker.stat()
    artifact_prefix = f"-artifact_prefix={artifact_dir}/"
    header: dict[str, object] = {
        "protocol": PROTOCOL,
        "marker": "a" * 32,
        "helper_sha256": hashlib.sha256(SUPERVISOR.read_bytes()).hexdigest(),
        "worker_hostname": socket.gethostname().split(".", 1)[0].lower(),
        "worker_user": pwd.getpwuid(os.geteuid()).pw_name,
        "worker_group": grp.getgrgid(os.getegid()).gr_name,
        "bootstrap_marker": str(marker),
        "bootstrap_marker_owner": pwd.getpwuid(marker_stat.st_uid).pw_name,
        "bootstrap_marker_group": grp.getgrgid(marker_stat.st_gid).gr_name,
        "revision": revision,
        "harness": str(harness),
        "harness_sha256": hashlib.sha256(harness.read_bytes()).hexdigest(),
        "source_root": str(source),
        "corpus": str(corpus),
        "artifact_root": str(artifact_root),
        "artifact_dir": str(artifact_dir),
        "argv": [str(harness), artifact_prefix, str(corpus)],
        "timeout_seconds": timeout,
    }
    return header, artifact_dir


def _run(header: dict[str, object]) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
    token = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
    ).decode().rstrip("=")
    result = subprocess.run(
        [sys.executable, str(SUPERVISOR), token],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    if result.returncode != 0:
        return result, {}
    prefix = f"{RECORD_PREFIX}{header['marker']}:"
    assert result.stdout.startswith(prefix)
    record = json.loads(base64.b64decode(result.stdout[len(prefix) :]))
    return result, record


def test_supervisor_bounds_streams_and_retrieves_hashed_artifacts(tmp_path: Path) -> None:
    output_bytes = MAX_OUTPUT_BYTES + 113
    harness = f"""#!/usr/bin/env python3
import pathlib
import sys

prefix = next(value.split("=", 1)[1] for value in sys.argv if value.startswith("-artifact_prefix="))
pathlib.Path(prefix, "crash-fixture").write_bytes(b"reproducer")
sys.stdout.buffer.write(b"x" * {output_bytes})
sys.stderr.buffer.write(b"ERROR: AddressSanitizer")
raise SystemExit(1)
"""
    header, _ = _fixture(tmp_path, harness)

    result, record = _run(header)

    assert result.returncode == 0, result.stderr
    assert record["target_returncode"] == 1
    stdout = record["stdout"]
    assert isinstance(stdout, dict)
    assert stdout["bytes"] == output_bytes
    assert stdout["truncated"] is True
    assert len(base64.b64decode(stdout["tail_base64"])) == MAX_OUTPUT_BYTES
    assert stdout["sha256"] == hashlib.sha256(b"x" * output_bytes).hexdigest()
    artifacts = record["artifacts"]
    assert isinstance(artifacts, list) and len(artifacts) == 1
    artifact = artifacts[0]
    assert artifact["name"] == "crash-fixture"
    assert artifact["sha256"] == hashlib.sha256(b"reproducer").hexdigest()
    assert base64.b64decode(artifact["content_base64"]) == b"reproducer"


def test_supervisor_timeout_kills_the_entire_process_group(tmp_path: Path) -> None:
    child_marker = tmp_path / "escaped-child"
    child_code = (
        "import pathlib,time;time.sleep(1);"
        f"pathlib.Path({str(child_marker)!r}).write_text('escaped')"
    )
    harness = f"""#!/usr/bin/env python3
import subprocess
import sys
import time

subprocess.Popen([sys.executable, "-c", {child_code!r}])
time.sleep(10)
"""
    header, _ = _fixture(tmp_path, harness, timeout=0.1)

    result, record = _run(header)

    assert result.returncode == 0, result.stderr
    assert record["timed_out"] is True
    assert record["target_returncode"] != 0
    time.sleep(1.2)
    assert not child_marker.exists()


def test_supervisor_rejects_tampered_helper_attestation(tmp_path: Path) -> None:
    header, _ = _fixture(tmp_path, "#!/bin/sh\nexit 0\n")
    header["helper_sha256"] = "0" * 64

    result, record = _run(header)

    assert record == {}
    assert result.returncode == 125
    assert "supervisor SHA-256 mismatch" in result.stderr


def test_supervisor_requires_an_empty_per_run_artifact_directory(tmp_path: Path) -> None:
    header, artifact_dir = _fixture(tmp_path, "#!/bin/sh\nexit 0\n")
    (artifact_dir / "stale-crash").write_bytes(b"old")

    result, record = _run(header)

    assert record == {}
    assert result.returncode == 125
    assert "empty and unique to this run" in result.stderr


def test_supervisor_rejects_symlinked_harness_and_artifact_directory(tmp_path: Path) -> None:
    header, artifact_dir = _fixture(tmp_path, "#!/bin/sh\nexit 0\n")
    harness = Path(str(header["harness"]))
    real_harness = harness.with_name("real-harness")
    harness.rename(real_harness)
    harness.symlink_to(real_harness)

    result, record = _run(header)
    assert record == {}
    assert result.returncode == 125
    assert "symlinked campaign harness" in result.stderr

    harness.unlink()
    real_harness.rename(harness)
    real_artifacts = artifact_dir.with_name("real-artifacts")
    artifact_dir.rename(real_artifacts)
    artifact_dir.symlink_to(real_artifacts, target_is_directory=True)

    result, record = _run(header)
    assert record == {}
    assert result.returncode == 125
    assert "symlinked campaign artifact directory" in result.stderr


def test_cleanup_permission_error_never_counts_as_group_exit(
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    module = _supervisor_module()

    def denied(_pgid: int, _signal: int) -> None:
        raise PermissionError

    monkeypatch.setattr(module.os, "killpg", denied)
    assert module._group_exists(1234) is True

    class Process:
        pid = 1234

    with pytest.raises(RuntimeError, match="could not receive SIGTERM"):
        module._terminate_group(Process())


@pytest.mark.skipif(not Path("/proc/self/fd").is_dir(), reason="Linux procfs contract")
def test_supervisor_executes_open_harness_and_artifact_descriptors_after_path_swap(
    tmp_path: Path,
) -> None:
    harness_source = """#!/usr/bin/env python3
import pathlib
import sys
prefix = next(value.split("=", 1)[1] for value in sys.argv if value.startswith("-artifact_prefix="))
pathlib.Path(prefix, "crash-held").write_bytes(b"held artifact")
sys.stdout.write(sys.argv[0])
"""
    header, artifact_dir = _fixture(tmp_path, harness_source)
    module = _supervisor_module()
    validated = module._validate(header, SUPERVISOR.resolve())
    source_root = validated[2]
    descriptors = tuple(validated[3:7])
    command = validated[7]
    harness_path = Path(str(header["harness"]))
    held_harness = harness_path.with_name("held-original")
    held_artifacts = artifact_dir.with_name("held-artifacts")
    try:
        harness_path.rename(held_harness)
        harness_path.write_text("#!/bin/sh\necho REPLACED\n", encoding="utf-8")
        harness_path.chmod(0o750)
        artifact_dir.rename(held_artifacts)
        artifact_dir.mkdir()

        returncode, timed_out, stdout, _ = module._run(
            command,
            module._fd_path(descriptors[1]),
            source_root,
            descriptors[0],
            descriptors,
            5,
        )
        artifacts = module._artifacts(descriptors[3])

        assert returncode == 0 and timed_out is False
        # The security property: the held-open inode executed even after the
        # path was swapped. A script harness cannot observe the spoofed
        # argv[0] — the kernel hands the interpreter the exec'd path, so on
        # Linux sys.argv[0] is the descriptor path. What must never appear is
        # the swapped-in replacement's output.
        observed = base64.b64decode(stdout["tail_base64"])
        assert observed != b"REPLACED\n"
        assert observed in (
            str(harness_path).encode(),
            module._fd_path(descriptors[1]).encode(),
        )
        assert artifacts[0]["name"] == "crash-held"
        assert not any(artifact_dir.iterdir())
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
