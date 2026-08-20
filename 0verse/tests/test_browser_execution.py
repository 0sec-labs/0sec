from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from zeroverse.execution import ExecutionRequest
from zeroverse.execution.browser import (
    BrowserExecutionBackend,
    BrowserTransportResult,
    SshBrowserCandidateTransport,
)


def _manifest(binary: Path, **updates: object) -> dict[str, object]:
    raw: dict[str, object] = {
        "schema_version": "0verse.browser-campaign/v2",
        "campaign_id": "v8-json-replay",
        "component": "v8",
        "revision": "0123456789abcdef0123456789abcdef01234567",
        "build_flags": ["is_asan=true", "dcheck_always_on=true"],
        "corpus": "/srv/corpus/json",
        "harness": binary.name,
        "harness_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "oracle": "asan",
        "process": "js-engine",
        "target_os": "linux",
        "bounty_program": "Chrome Vulnerability Reward Program",
        "bounty_scope_url": "https://example.test/scope",
        "scope_checked_at": datetime.now(UTC).isoformat(),
        "authorization": "published scope; owned dedicated worker",
        "worker": "browser-worker",
        "source_root": "/srv/chromium/src",
        "command": [f"/srv/chromium/src/out/asan/{binary.name}", "/srv/corpus/json"],
        "replay_command": [
            f"/srv/chromium/src/out/asan/{binary.name}",
            "-runs=1",
            "{input}",
        ],
        "timeout_seconds": 60,
    }
    raw.update(updates)
    return raw


def _write_manifest(tmp_path: Path, binary: Path, **updates: object) -> Path:
    path = tmp_path / "campaign.json"
    path.write_text(json.dumps(_manifest(binary, **updates)), encoding="utf-8")
    return path


class FakeTransport:
    helper_sha256 = "a" * 64

    def __init__(
        self,
        *,
        target_exit: int = 1,
        target_stderr: bytes = (
            b"==123==ERROR: AddressSanitizer: heap-buffer-overflow\n"
            b"SUMMARY: AddressSanitizer: heap-buffer-overflow fixture.cc:1"
        ),
        transport_exit: int = 0,
        mismatch: str = "",
        duplicate: str = "",
        timed_out: bool = False,
    ) -> None:
        self.target_exit = target_exit
        self.target_stderr = target_stderr
        self.transport_exit = transport_exit
        self.mismatch = mismatch
        self.duplicate = duplicate
        self.timed_out = timed_out

    def run(self, campaign, request):  # type: ignore[no-untyped-def]
        marker = "1" * 32
        stdout = b""
        stderr = self.target_stderr
        values = {
            "WORKER-HOSTNAME": "browser",
            "WORKER-USER": "browser",
            "WORKER-GROUP": "browser",
            "BOOTSTRAP-MARKER-OWNER": "root",
            "BOOTSTRAP-MARKER-GROUP": "browser",
            "BOOTSTRAP-MARKER-SHA256": "b" * 64,
            "BOOTSTRAP-SHA256": "c" * 64,
            "ORACLE": campaign.oracle,
            "HELPER-SHA256": self.helper_sha256,
            "TARGET-SHA256-BEFORE": request.target_sha256,
            "TARGET-SHA256-AFTER": request.target_sha256,
            "INPUT-SHA256": request.input_sha256,
            "REVISION-BEFORE": campaign.revision,
            "REVISION-AFTER": campaign.revision,
            "TARGET-EXIT": str(self.target_exit),
            "TIMED-OUT": "1" if self.timed_out else "0",
            "STDOUT-SHA256": hashlib.sha256(stdout).hexdigest(),
            "STDERR-SHA256": hashlib.sha256(stderr).hexdigest(),
            "STDOUT-TAIL-SHA256": hashlib.sha256(stdout).hexdigest(),
            "STDERR-TAIL-SHA256": hashlib.sha256(stderr).hexdigest(),
            "STDOUT-TRUNCATED": "0",
            "STDERR-TRUNCATED": "0",
            "STDOUT-B64": base64.b64encode(stdout).decode(),
            "STDERR-B64": base64.b64encode(stderr).decode(),
        }
        if self.mismatch:
            values[self.mismatch] = "f" * 64
        lines = [f"0VERSE-BROWSER-{marker}-{name}:{value}" for name, value in values.items()]
        if self.duplicate:
            lines.append(
                f"0VERSE-BROWSER-{marker}-{self.duplicate}:{values[self.duplicate]}"
            )
        return BrowserTransportResult(
            marker=marker,
            returncode=self.transport_exit,
            stdout=("\n".join(lines) + "\n").encode(),
            stderr=b"transport failed" if self.transport_exit else b"",
        )


def _request(binary: Path, payload: bytes = b"candidate") -> ExecutionRequest:
    return ExecutionRequest(
        target=str(binary),
        target_format="ELF",
        payload=payload,
        vector="file",
        oracle="asan",
    )


def test_browser_adapter_confirms_hash_bound_component_crash(tmp_path: Path) -> None:
    binary = tmp_path / "json_parser_fuzzer"
    binary.write_bytes(b"exact local harness snapshot")
    backend = BrowserExecutionBackend(
        _write_manifest(tmp_path, binary), transport=FakeTransport()
    )
    evidence = backend.run(_request(binary))
    assert evidence.status == "CRASH"
    assert evidence.crash_signature == "ERROR: AddressSanitizer"
    assert evidence.matches(_request(binary))
    assert evidence.environment["component"] == "v8"
    assert len(evidence.environment["manifest_sha256"]) == 64
    assert evidence.environment["worker_user"] == "browser"
    assert evidence.environment["helper_sha256"] == FakeTransport.helper_sha256
    assert evidence.environment["target_sha256_before"] == _request(binary).target_sha256
    assert evidence.environment["revision_after"] == _manifest(binary)["revision"]


@pytest.mark.parametrize(
    "transport",
    [
        FakeTransport(mismatch="TARGET-SHA256-BEFORE"),
        FakeTransport(duplicate="INPUT-SHA256"),
        FakeTransport(target_exit=0),
        FakeTransport(target_exit=2, target_stderr=b"ordinary failure"),
        FakeTransport(target_exit=2, target_stderr=b"ERROR: AddressSanitizer: reflected"),
        FakeTransport(transport_exit=255),
    ],
)
def test_browser_adapter_fails_closed_on_ambiguous_evidence(
    tmp_path: Path, transport: FakeTransport
) -> None:
    binary = tmp_path / "json_parser_fuzzer"
    binary.write_bytes(b"harness")
    backend = BrowserExecutionBackend(
        _write_manifest(tmp_path, binary), transport=transport
    )
    evidence = backend.run(_request(binary))
    assert evidence.status == "ERROR"
    assert not evidence.confirmed_crash


def test_browser_adapter_reports_target_timeout(tmp_path: Path) -> None:
    binary = tmp_path / "json_parser_fuzzer"
    binary.write_bytes(b"harness")
    backend = BrowserExecutionBackend(
        _write_manifest(tmp_path, binary), transport=FakeTransport(timed_out=True)
    )
    evidence = backend.run(_request(binary))
    assert evidence.status == "TIMEOUT"


def test_browser_adapter_reloads_and_rejects_manifest_drift(tmp_path: Path) -> None:
    binary = tmp_path / "json_parser_fuzzer"
    binary.write_bytes(b"harness")
    manifest = _write_manifest(tmp_path, binary)
    backend = BrowserExecutionBackend(manifest, transport=FakeTransport())
    raw = json.loads(manifest.read_text())
    raw["authorization"] = "changed after adapter construction"
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    evidence = backend.run(_request(binary))
    assert evidence.status == "ERROR"
    assert "manifest changed" in evidence.error


def test_browser_adapter_rejects_wrong_oracle_or_implicit_argv(tmp_path: Path) -> None:
    binary = tmp_path / "json_parser_fuzzer"
    binary.write_bytes(b"harness")
    backend = BrowserExecutionBackend(
        _write_manifest(tmp_path, binary), transport=FakeTransport()
    )
    wrong_oracle = ExecutionRequest(
        target=str(binary),
        target_format="ELF",
        payload=b"x",
        vector="file",
        oracle="msan",
    )
    assert backend.run(wrong_oracle).status == "UNSUPPORTED"
    with_argv = ExecutionRequest(
        target=str(binary),
        target_format="ELF",
        payload=b"x",
        vector="file",
        oracle="asan",
        argv=("--extra",),
    )
    assert backend.run(with_argv).status == "UNSUPPORTED"
    expanded_timeout = ExecutionRequest(
        target=str(binary),
        target_format="ELF",
        payload=b"x",
        vector="file",
        oracle="asan",
        timeout=61,
    )
    assert backend.run(expanded_timeout).status == "ERROR"


def test_ssh_transport_keeps_payload_out_of_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "json_parser_fuzzer"
    binary.write_bytes(b"harness")
    manifest = _write_manifest(tmp_path, binary)
    from zeroverse.browser_campaign import load_manifest

    campaign, _ = load_manifest(manifest)
    request = _request(binary, b"payload with spaces; $(not-a-shell)")
    seen: dict[str, object] = {}

    def fake_run(argv, **kwargs):  # type: ignore[no-untyped-def]
        seen["argv"] = argv
        seen["input"] = kwargs["input"]
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr("zeroverse.execution.browser.subprocess.run", fake_run)
    transport = SshBrowserCandidateTransport()
    transport.run(campaign, request)
    argv = seen["argv"]
    assert isinstance(argv, list)
    assert request.payload not in b" ".join(item.encode() for item in argv)
    framed = seen["input"]
    assert isinstance(framed, bytes)
    header, payload = framed.split(b"\n", 1)
    decoded = json.loads(header)
    assert decoded["input_sha256"] == request.input_sha256
    assert decoded["worker_hostname"] == "browser"
    assert decoded["worker_user"] == "browser"
    assert decoded["worker_group"] == "browser"
    assert decoded["bootstrap_marker_owner"] == "root"
    assert decoded["bootstrap_marker_group"] == "browser"
    assert decoded["bootstrap_marker"] == "/srv/0verse/.browser-worker"
    assert decoded["oracle"] == "asan"
    assert payload == request.payload
