from __future__ import annotations

import base64
import grp
import hashlib
import json
import os
import pwd
import re
import socket
import subprocess
import sys
from pathlib import Path

import pytest

HELPER = Path(__file__).parents[1] / "scripts" / "browser" / "replay-candidate.py"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _source_and_harness(tmp_path: Path, body: str) -> tuple[Path, Path, str]:
    source = tmp_path / "src"
    source.mkdir()
    harness = source / "component_fuzzer"
    harness.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    harness.chmod(0o755)
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "add", "component_fuzzer"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(source),
            "-c",
            "user.name=0verse Test",
            "-c",
            "user.email=test@invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    revision = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    return source, harness, revision


def _run_helper(
    source: Path,
    harness: Path,
    revision: str,
    payload: bytes,
    *,
    timeout: float = 2.0,
) -> subprocess.CompletedProcess[bytes]:
    marker = "2" * 32
    worker_user = pwd.getpwuid(os.geteuid()).pw_name
    worker_group = grp.getgrgid(os.getegid()).gr_name
    bootstrap_marker = source.parent / ".browser-worker"
    bootstrap_marker.write_text(
        "schema=1\n"
        f"hostname={socket.gethostname().split('.', 1)[0].lower()}\n"
        "bootstrapped_at_utc=2026-07-13T00:00:00Z\n"
        f"bootstrap_sha256={'b' * 64}\n",
        encoding="utf-8",
    )
    bootstrap_marker.chmod(0o640)
    header = {
        "protocol": "0verse.browser-replay/v1",
        "marker": marker,
        "target_sha256": _sha256(harness),
        "input_sha256": hashlib.sha256(payload).hexdigest(),
        "helper_sha256": _sha256(HELPER),
        "worker_hostname": socket.gethostname().split(".", 1)[0].lower(),
        "worker_user": worker_user,
        "worker_group": worker_group,
        "bootstrap_marker": str(bootstrap_marker),
        "bootstrap_marker_owner": worker_user,
        "bootstrap_marker_group": worker_group,
        "oracle": "asan",
        "revision": revision,
        "timeout_seconds": timeout,
        "source_root": str(source),
        "harness": str(harness),
        "argv": [str(harness), "{input}"],
    }
    framed = json.dumps(header, separators=(",", ":")).encode() + b"\n" + payload
    return subprocess.run(
        [sys.executable, str(HELPER)],
        input=framed,
        capture_output=True,
        timeout=5,
        check=False,
    )


def _record(output: bytes, name: str) -> str:
    match = re.search(
        rb"^0VERSE-BROWSER-2{32}-" + name.encode() + rb":(.*)$",
        output,
        re.MULTILINE,
    )
    assert match is not None
    return match.group(1).decode()


@pytest.mark.skipif(os.name == "nt", reason="remote helper is Linux/POSIX only")
def test_replay_helper_binds_target_input_revision_and_exit(tmp_path: Path) -> None:
    source, harness, revision = _source_and_harness(
        tmp_path, "echo 'ERROR: AddressSanitizer: fixture' >&2; exit 1"
    )
    payload = b"structured browser input"
    result = _run_helper(source, harness, revision, payload)
    assert result.returncode == 0
    assert _record(result.stdout, "WORKER-USER") == pwd.getpwuid(os.geteuid()).pw_name
    assert _record(result.stdout, "BOOTSTRAP-SHA256") == "b" * 64
    assert _record(result.stdout, "ORACLE") == "asan"
    assert _record(result.stdout, "TARGET-SHA256-BEFORE") == _sha256(harness)
    assert _record(result.stdout, "TARGET-SHA256-AFTER") == _sha256(harness)
    assert _record(result.stdout, "INPUT-SHA256") == hashlib.sha256(payload).hexdigest()
    assert _record(result.stdout, "REVISION-BEFORE") == revision
    assert _record(result.stdout, "REVISION-AFTER") == revision
    assert _record(result.stdout, "TARGET-EXIT") == "1"
    assert _record(result.stdout, "TIMED-OUT") == "0"


@pytest.mark.skipif(os.name == "nt", reason="remote helper is Linux/POSIX only")
def test_replay_helper_kills_timed_out_process_group(tmp_path: Path) -> None:
    source, harness, revision = _source_and_harness(tmp_path, "sleep 2; exit 0")
    result = _run_helper(source, harness, revision, b"x", timeout=0.05)
    assert result.returncode == 0
    assert _record(result.stdout, "TARGET-EXIT") == "124"
    assert _record(result.stdout, "TIMED-OUT") == "1"


@pytest.mark.skipif(os.name == "nt", reason="remote helper is Linux/POSIX only")
def test_replay_helper_retains_only_bounded_output_tail(tmp_path: Path) -> None:
    source, harness, revision = _source_and_harness(
        tmp_path, "head -c 1100000 /dev/zero; exit 0"
    )
    result = _run_helper(source, harness, revision, b"x")
    assert result.returncode == 0
    assert _record(result.stdout, "STDOUT-TRUNCATED") == "1"
    retained = base64.b64decode(_record(result.stdout, "STDOUT-B64"), validate=True)
    assert len(retained) == 1024 * 1024
    assert hashlib.sha256(retained).hexdigest() == _record(
        result.stdout, "STDOUT-TAIL-SHA256"
    )
