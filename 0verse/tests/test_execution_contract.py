from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from zeroverse.execution import (
    EXECUTION_CONTRACT_VERSION,
    ExecutionCapabilities,
    ExecutionEvidence,
    ExecutionRequest,
    LocalProcessBackend,
)
from zeroverse.execution.windows import WindowsExecutionBackend
from zeroverse.oracle import RunResult


def _markers(binary: Path, payload: bytes) -> str:
    return (
        "0VERSE-BUILDLABEX:test-build\n"
        f"0VERSE-BINARY-SHA256:{hashlib.sha256(binary.read_bytes()).hexdigest()}\n"
        f"0VERSE-INPUT-SHA256:{hashlib.sha256(payload).hexdigest()}\n"
        "0VERSE-EXIT:-1\n"
    )


def test_contract_rejects_unknown_vectors_and_unbound_crashes(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"binary")
    with pytest.raises(ValueError, match="input vector"):
        ExecutionCapabilities(
            formats=frozenset({"ELF"}),
            vectors=frozenset({"socket"}),
            oracles=frozenset({"native-crash"}),
        )
    with pytest.raises(ValueError, match="signal or oracle signature"):
        ExecutionEvidence(
            backend="fake",
            status="CRASH",
            oracle="native-crash",
            target_sha256=hashlib.sha256(b"binary").hexdigest(),
            input_sha256=hashlib.sha256(b"input").hexdigest(),
            environment={"host": "lab"},
        )


def test_evidence_matches_exact_request_hashes(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"binary")
    request = ExecutionRequest(
        target=str(target),
        target_format="ELF",
        payload=b"input",
        vector="stdin",
        oracle="native-crash",
    )
    evidence = ExecutionEvidence(
        backend="fake",
        status="CLEAN",
        oracle="native-crash",
        target_sha256=request.target_sha256,
        input_sha256=request.input_sha256,
        environment={"host": "lab"},
    )
    assert request.contract_version == EXECUTION_CONTRACT_VERSION
    assert evidence.matches(request)


def test_local_process_adapter_preserves_hashes_and_output() -> None:
    backend = LocalProcessBackend()
    request = ExecutionRequest(
        target=sys.executable,
        target_format=next(iter(backend.capabilities.formats)),
        payload=b"hello",
        vector="stdin",
        oracle="native-crash",
        argv=("-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"),
    )
    evidence = backend.run(request)
    assert evidence.status == "CLEAN"
    assert evidence.stdout == "hello"
    assert evidence.matches(request)
    assert evidence.environment["mode"] == "local-process"


def test_local_adapter_rejects_target_changed_after_request(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"before")
    backend = LocalProcessBackend()
    request = ExecutionRequest(
        target=str(target),
        target_format=next(iter(backend.capabilities.formats)),
        payload=b"input",
        vector="stdin",
        oracle="native-crash",
    )
    target.write_bytes(b"changed")
    evidence = backend.run(request)
    assert evidence.status == "ERROR"
    assert "changed after" in evidence.error


def test_windows_adapter_requires_scope_and_authorization() -> None:
    worker = SimpleNamespace(host="worker-01.example.test")
    with pytest.raises(ValueError, match="scope"):
        WindowsExecutionBackend(worker, scope_mode="", authorization="owned")
    with pytest.raises(ValueError, match="authorization"):
        WindowsExecutionBackend(worker, scope_mode="LAB_ONLY", authorization="")


def test_windows_adapter_normalizes_hash_bound_crash(tmp_path: Path) -> None:
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZtarget")
    payload = b"crash"
    report = _markers(binary, payload) + "VERIFIER STOP\n"
    worker = SimpleNamespace(
        host="worker-01.example.test",
        run_drmemory=lambda *args, **kwargs: RunResult(
            True, sanitizer="drmemory", stderr=report
        ),
        run_pageheap=lambda *args, **kwargs: RunResult(
            True, sanitizer="pageheap-cdb", stderr=report
        ),
    )
    request = ExecutionRequest(
        target=str(binary),
        target_format="PE",
        payload=payload,
        vector="file",
        oracle="drmemory",
    )
    evidence = WindowsExecutionBackend(
        worker,
        oracle="drmemory",
        scope_mode="LAB_ONLY",
        authorization="operator-owned disposable VM",
    ).run(request)
    assert evidence.status == "CRASH"
    assert evidence.crash_signature == "drmemory"
    assert evidence.environment == {
        "host": "worker-01.example.test",
        "mode": "windows-worker",
        "scope_mode": "LAB_ONLY",
        "authorization": "operator-owned disposable VM",
        "build_lab_ex": "test-build",
    }
    assert evidence.matches(request)


def test_windows_adapter_rejects_marker_with_mismatched_hash(tmp_path: Path) -> None:
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZtarget")
    payload = b"crash"
    report = (
        "0VERSE-BUILDLABEX:test-build\n"
        f"0VERSE-BINARY-SHA256:{'f' * 64}\n"
        f"0VERSE-INPUT-SHA256:{hashlib.sha256(payload).hexdigest()}\n"
        "0VERSE-EXIT:-1\nVERIFIER STOP\n"
    )
    worker = SimpleNamespace(
        host="worker-01.example.test",
        run_drmemory=lambda *args, **kwargs: RunResult(
            True, sanitizer="drmemory", stderr=report
        ),
    )
    request = ExecutionRequest(
        target=str(binary),
        target_format="PE",
        payload=payload,
        vector="file",
        oracle="drmemory",
    )
    evidence = WindowsExecutionBackend(
        worker,
        oracle="drmemory",
        scope_mode="LAB_ONLY",
        authorization="operator-owned disposable VM",
    ).run(request)
    assert evidence.status == "ERROR"
    assert not evidence.confirmed_crash
    assert "mismatched" in evidence.error
