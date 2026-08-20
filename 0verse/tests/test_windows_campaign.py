from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

import pytest

from zeroverse.oracle import RunResult
from zeroverse.windows_campaign import (
    corpus_inputs,
    replay_corpus,
    replay_differential,
    write_evidence,
)


def _worker_markers(binary: Path, data: bytes, exit_code: int = 0) -> str:
    binary_digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    input_digest = hashlib.sha256(data).hexdigest()
    return (
        "0VERSE-BUILDLABEX:test-build\n"
        f"0VERSE-BINARY-SHA256:{binary_digest}\n"
        f"0VERSE-INPUT-SHA256:{input_digest}\n"
        f"0VERSE-EXIT:{exit_code}"
    )


class FakeWorker:
    def run_drmemory(self, binary: Path, data: bytes, *, timeout: float) -> RunResult:
        if data == b"crash":
            return RunResult(False, stderr=_worker_markers(binary, data, -1))
        return RunResult(False, stderr=_worker_markers(binary, data))

    def run_pageheap(self, binary: Path, data: bytes, *, timeout: float) -> RunResult:
        report = f"""{_worker_markers(binary, data)}
EXCEPTION_CODE: (NTSTATUS) 0xc0000005
Attempt to write to address 00000000
STACK_TEXT:
00000000 00000000 target!parse_chunk+0x10
"""
        return RunResult(True, sanitizer="pageheap-cdb", stderr=report)


class DifferentialWorker(FakeWorker):
    def run_drmemory(self, binary: Path, data: bytes, *, timeout: float) -> RunResult:
        if "vuln" in binary.name and data == b"crash":
            return RunResult(False, stderr=_worker_markers(binary, data, -1))
        return RunResult(False, stderr=_worker_markers(binary, data))


class MissingBuildWorker(FakeWorker):
    def run_drmemory(self, binary: Path, data: bytes, *, timeout: float) -> RunResult:
        return RunResult(True, sanitizer="drmemory", stderr="UNADDRESSABLE ACCESS")


class MismatchedBinaryWorker(FakeWorker):
    def run_drmemory(self, binary: Path, data: bytes, *, timeout: float) -> RunResult:
        return RunResult(
            False,
            stderr=(
                "0VERSE-BUILDLABEX:test-build\n"
                f"0VERSE-BINARY-SHA256:{'f' * 64}\n"
                f"0VERSE-INPUT-SHA256:{hashlib.sha256(data).hexdigest()}\n"
                "0VERSE-EXIT:0"
            ),
        )


class MismatchedInputWorker(FakeWorker):
    def run_drmemory(self, binary: Path, data: bytes, *, timeout: float) -> RunResult:
        binary_digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        return RunResult(
            False,
            stderr=(
                "0VERSE-BUILDLABEX:test-build\n"
                f"0VERSE-BINARY-SHA256:{binary_digest}\n"
                f"0VERSE-INPUT-SHA256:{'e' * 64}\n"
                "0VERSE-EXIT:0"
            ),
        )


class TransportFailureWorker(FakeWorker):
    pageheap_called = False

    def run_drmemory(self, binary: Path, data: bytes, *, timeout: float) -> RunResult:
        return RunResult(
            False,
            stderr=(
                "Windows worker error: SSH/PowerShell exited 255: "
                f"{_worker_markers(binary, data, -1)}"
            ),
        )

    def run_pageheap(self, binary: Path, data: bytes, *, timeout: float) -> RunResult:
        self.pageheap_called = True
        return super().run_pageheap(binary, data, timeout=timeout)


def test_corpus_inputs_are_deterministic_and_flat(tmp_path: Path) -> None:
    (tmp_path / "b").write_bytes(b"b")
    (tmp_path / "a").write_bytes(b"a")
    (tmp_path / "nested").mkdir()
    assert [item.name for item in corpus_inputs(tmp_path)] == ["a", "b"]


def test_replay_records_clean_and_fallback_crash(tmp_path: Path) -> None:
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "01-clean").write_bytes(b"clean")
    (corpus / "02-crash").write_bytes(b"crash")
    rows = replay_corpus(binary, corpus, worker=FakeWorker())  # type: ignore[arg-type]
    assert [row.status for row in rows] == ["CLEAN", "CRASH"]
    assert rows[1].oracle == "pageheap-cdb"
    assert rows[1].build_lab_ex == "test-build"
    assert rows[1].crash_function == "parse_chunk"
    assert rows[1].crash_cwe == "CWE-787"
    assert len(rows[1].sha256) == 64


def test_write_evidence_ndjson() -> None:
    out = io.StringIO()
    write_evidence([], out)
    assert out.getvalue() == ""
    with pytest.raises(ValueError):
        write_evidence([], out, "csv")


def test_missing_worker_build_identity_is_error_even_with_crash_marker(tmp_path: Path) -> None:
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    poc = tmp_path / "poc"
    poc.write_bytes(b"input")
    rows = replay_corpus(
        binary,
        poc,
        worker=MissingBuildWorker(),  # type: ignore[arg-type]
        oracle="drmemory",
    )
    assert rows[0].status == "ERROR"
    assert "no unambiguous BuildLabEx" in rows[0].error


def test_transport_error_does_not_trigger_pageheap_fallback(tmp_path: Path) -> None:
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    poc = tmp_path / "poc"
    poc.write_bytes(b"input")
    worker = TransportFailureWorker()
    rows = replay_corpus(binary, poc, worker=worker)  # type: ignore[arg-type]
    assert not worker.pageheap_called
    assert rows[0].status == "ERROR"


def test_remote_binary_hash_must_match_local_snapshot(tmp_path: Path) -> None:
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    poc = tmp_path / "poc"
    poc.write_bytes(b"input")
    rows = replay_corpus(
        binary,
        poc,
        worker=MismatchedBinaryWorker(),  # type: ignore[arg-type]
        oracle="drmemory",
    )
    assert rows[0].status == "ERROR"
    assert "remote=" in rows[0].error and "mismatched" in rows[0].error


def test_remote_input_hash_must_match_local_pov(tmp_path: Path) -> None:
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    poc = tmp_path / "poc"
    poc.write_bytes(b"input")
    rows = replay_corpus(
        binary,
        poc,
        worker=MismatchedInputWorker(),  # type: ignore[arg-type]
        oracle="drmemory",
    )
    assert rows[0].status == "ERROR"
    assert "input SHA-256" in rows[0].error


def test_write_evidence_json(tmp_path: Path) -> None:
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    poc = tmp_path / "poc"
    poc.write_bytes(b"clean")
    rows = replay_corpus(binary, poc, worker=FakeWorker())  # type: ignore[arg-type]
    out = io.StringIO()
    write_evidence(rows, out, "json")
    assert json.loads(out.getvalue())[0]["status"] == "CLEAN"


def test_replay_records_scope_provenance(tmp_path: Path) -> None:
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    poc = tmp_path / "poc"
    poc.write_bytes(b"clean")
    rows = replay_corpus(
        binary,
        poc,
        worker=FakeWorker(),  # type: ignore[arg-type]
        scope_mode="BOUNTY_SCOPE",
        scope_program="windows-canary",
        scope_manifest_sha256="a" * 64,
    )
    assert rows[0].scope_mode == "BOUNTY_SCOPE"
    assert rows[0].scope_program == "windows-canary"
    assert rows[0].scope_manifest_sha256 == "a" * 64


def test_differential_target_only_crash(tmp_path: Path) -> None:
    vulnerable = tmp_path / "vuln.exe"
    fixed = tmp_path / "fixed.exe"
    vulnerable.write_bytes(b"MZvulnerable")
    fixed.write_bytes(b"MZfixed")
    poc = tmp_path / "poc"
    poc.write_bytes(b"crash")
    rows = replay_differential(
        vulnerable,
        fixed,
        poc,
        worker=DifferentialWorker(),  # type: ignore[arg-type]
    )
    assert rows[0].classification == "TARGET_ONLY_CRASH"
    assert rows[0].target.status == "CRASH"
    assert rows[0].control.status == "CLEAN"
    assert rows[0].target.binary_name == "vuln.exe"
    assert rows[0].control.binary_name == "fixed.exe"
    assert len(rows[0].target.binary_sha256) == 64
    assert rows[0].target.binary_sha256 != rows[0].control.binary_sha256


def test_differential_rejects_identical_target_and_control_binaries(tmp_path: Path) -> None:
    target = tmp_path / "vuln.exe"
    control = tmp_path / "fixed.exe"
    target.write_bytes(b"MZsame")
    control.write_bytes(b"MZsame")
    poc = tmp_path / "poc"
    poc.write_bytes(b"crash")
    rows = replay_differential(
        target,
        control,
        poc,
        worker=DifferentialWorker(),  # type: ignore[arg-type]
    )
    assert rows[0].classification == "ERROR"
