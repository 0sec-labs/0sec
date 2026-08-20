import subprocess
from types import SimpleNamespace

import pytest

import zeroverse.adjudicate as adj
from zeroverse.adjudicate import (
    CONFIRMED,
    UNRUNNABLE,
    adjudicate_finding,
    parse_cdb_crash,
    parse_drmemory_crash,
)
from zeroverse.agentic import AgentVerdict
from zeroverse.oracle import RunResult
from zeroverse.windows_oracle import (
    WindowsWorker,
    _encoded_powershell,
    _ps_quote,
    extract_binary_sha256,
    extract_buildlabex,
    extract_input_sha256,
)


def test_parse_drmemory_oob_write_skips_interceptor():
    report = """Error #1: UNADDRESSABLE ACCESS: writing 4 byte(s)
# 0 target.exe!memcpy [crt.c:10]
# 1 target.exe!parse_chunk+0x2a [parse.c:88]
# 2 target.exe!main+0x19 [main.c:12]
"""
    crash = parse_drmemory_crash(report)
    assert crash.kind == "heap-buffer-overflow"
    assert crash.access == "WRITE" and crash.size == 4
    assert crash.crash_function == "parse_chunk"
    assert crash.cwe == "CWE-787" and crash.family == "oob"


def test_parse_drmemory_uaf_read():
    report = """Error #2: USE AFTER FREE: reading 8 byte(s)
# 0 parser.dll!decode_record+0x10
# 1 harness.exe!main+0x20
"""
    crash = parse_drmemory_crash(report)
    assert crash.kind == "use-after-free"
    assert crash.crash_function == "decode_record"
    assert crash.cwe == "CWE-416"


def test_parse_cdb_pageheap_access_violation():
    report = """EXCEPTION_CODE: (NTSTATUS) 0xc0000005
Attempt to write to address 0000012345679000
STACK_TEXT:
000000aa`0012f000 00007ff6`12341000 00000000`00000000 target!memcpy+0x12
000000aa`0012f040 00007ff6`12342000 00000000`00000000 target!parse_chunk+0x2a
"""
    crash = parse_cdb_crash(report)
    assert crash.kind == "heap-buffer-overflow"
    assert crash.access == "WRITE"
    assert crash.crash_function == "parse_chunk"
    assert crash.cwe == "CWE-787"


def test_parse_cdb_verifier_stop_with_real_stack_shape():
    report = """VERIFIER STOP 000000000000000F: corrupted suffix pattern
STACK_TEXT:
0000005c`eb9fe850 00007fff`5d4d5d57 : 000001df`1592bff0 : verifier!VerifierStopMessage+0x2f2
0000005c`eb9fed70 00007ff6`28e914db : 00007ff6`28e97040 : ucrtbase!free_base+0x1b
0000005c`eb9feda0 00007ff6`28e9159d : 0000005c`eb9fee10 : tier1_vuln!parse_chunk+0x8b
"""
    crash = parse_cdb_crash(report)
    assert crash.kind == "heap-buffer-overflow"
    assert crash.access == "WRITE"
    assert crash.crash_function == "parse_chunk"
    assert crash.cwe == "CWE-787"


def test_parse_cdb_keeps_unsymbolized_image_rva():
    report = """VERIFIER STOP 000000000000000F: corrupted suffix pattern
STACK_TEXT:
000000ea`ac1fe3e0 00007fff`71b15d57 : verifier!VerifierStopMessage+0x2f2
000000ea`ac1fe930 00007ff6`ff64159d : image00007ff6_ff640000+0x14db
"""
    crash = parse_cdb_crash(report)
    assert "image00007ff6_ff640000+0x14db" in crash.frames


def test_non_crash_windows_output_is_empty():
    assert not parse_drmemory_crash("NO ERRORS FOUND").crashed
    assert not parse_cdb_crash("quit: clean exit").crashed


def test_powershell_transport_encoding_and_quote():
    assert _encoded_powershell("Write-Output 'ok'").startswith(
        "powershell.exe -NoProfile -NonInteractive -EncodedCommand "
    )
    assert _ps_quote("a'b") == "'a''b'"
    assert extract_buildlabex("0VERSE-BUILDLABEX:99999.1.amd64fre.canary.260711-1000\n") == (
        "99999.1.amd64fre.canary.260711-1000"
    )
    conflicting = (
        "0VERSE-BUILDLABEX:99999.1.amd64fre.canary\n"
        "0VERSE-BUILDLABEX:26100.1.amd64fre.ge_release\n"
    )
    assert extract_buildlabex(conflicting) == ""
    digest = "a" * 64
    assert extract_binary_sha256(f"0VERSE-BINARY-SHA256:{digest}\n") == digest
    assert extract_binary_sha256(f"0VERSE-BINARY-SHA256:{digest}\r\n") == digest
    assert extract_binary_sha256(
        f"0VERSE-BINARY-SHA256:{digest}\n0VERSE-BINARY-SHA256:{'b' * 64}\n"
    ) == ""
    assert extract_input_sha256(f"0VERSE-INPUT-SHA256:{digest}\n") == digest
    assert extract_input_sha256(f"0VERSE-INPUT-SHA256:{digest}\r\n") == digest


def test_windows_worker_requires_configuration(tmp_path, monkeypatch):
    pe = tmp_path / "target.exe"
    pe.write_bytes(b"MZfixture")
    monkeypatch.delenv("ZEROVERSE_WINDOWS_HOST", raising=False)
    verdict = AgentVerdict(True, "CWE-787", "parse_chunk", "", "")
    result = adjudicate_finding(verdict, pe, b"A")
    assert result.status == UNRUNNABLE
    assert "ZEROVERSE_WINDOWS_HOST" in result.reason


def test_pe_dispatches_to_windows_worker(tmp_path, monkeypatch):
    pe = tmp_path / "target.exe"
    pe.write_bytes(b"MZfixture")
    report = """Error #1: UNADDRESSABLE ACCESS: writing 4 byte(s)
# 0 target.exe!parse_chunk+0x2a [parse.c:88]
"""
    worker = SimpleNamespace(
        host="lab",
        available=lambda: (True, "drmemory.exe"),
        run_drmemory=lambda *args, **kwargs: RunResult(
            True, sanitizer="drmemory", stderr=report
        ),
    )
    monkeypatch.setattr(adj.WindowsWorker, "from_env", lambda: worker)
    verdict = AgentVerdict(True, "CWE-787", "parse_chunk", "", "")
    assert adjudicate_finding(verdict, pe, b"A").status == CONFIRMED


def test_worker_availability_fails_closed(monkeypatch):
    worker = WindowsWorker("lab", lab_only=True)
    monkeypatch.setattr(
        WindowsWorker,
        "_ssh",
        lambda self, *args, **kwargs: SimpleNamespace(
            returncode=2, stdout=b"", stderr=b"drmemory.exe not found"
        ),
    )
    available, detail = worker.available()
    assert not available and "not found" in detail


@pytest.mark.parametrize(
    "host",
    ["-oProxyCommand=touch /tmp/owned", "host name", "host\n-oProxyCommand=bad", ""],
)
def test_windows_worker_rejects_ssh_option_or_invalid_host_tokens(host):
    with pytest.raises(ValueError, match="plain SSH host"):
        WindowsWorker(host, lab_only=True)


@pytest.mark.parametrize(
    "host",
    ["worker-02.example.test", "administrator@worker-02.example.test", "192.0.2.11"],
)
def test_windows_worker_accepts_plain_ssh_destinations(host):
    assert WindowsWorker(host, lab_only=True).host == host


def test_signed_worker_rechecks_authorization_immediately_before_scp(monkeypatch):
    class Authorization:
        worker = "worker-02.example.test"
        expired = False

        def require_signed_authorization(self) -> None:
            if self.expired:
                raise ValueError("scope authorization has expired")

    authorization = Authorization()
    worker = WindowsWorker("worker-02.example.test", authorization=authorization)  # type: ignore[arg-type]
    authorization.expired = True
    monkeypatch.setattr(
        "zeroverse.windows_oracle.subprocess.run",
        lambda *args, **kwargs: pytest.fail("expired authorization reached subprocess"),
    )
    with pytest.raises(ValueError, match="expired"):
        worker._scp(["target.exe"], "0verse-" + "a" * 32)


def test_signed_worker_retains_cleanup_only_path_after_expiry(monkeypatch):
    class Authorization:
        worker = "worker-02.example.test"
        checks = 0

        def require_signed_authorization(self) -> None:
            self.checks += 1

    authorization = Authorization()
    worker = WindowsWorker("worker-02.example.test", authorization=authorization)  # type: ignore[arg-type]
    monkeypatch.setattr(
        "zeroverse.windows_oracle.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
    )
    capability = worker._issue_cleanup_capability(
        "0verse-" + "a" * 32, ttl_seconds=60
    )
    cleaned = worker._ssh_cleanup(timeout=5, capability=capability)
    assert cleaned.returncode == 0
    assert authorization.checks == 2
    with pytest.raises(ValueError, match="already consumed"):
        worker._ssh_cleanup(timeout=5, capability=capability)


def test_cleanup_capability_accepts_only_a_validated_run_context(monkeypatch):
    worker = WindowsWorker("worker-02.example.test", lab_only=True)
    monkeypatch.setattr(
        WindowsWorker,
        "_ssh",
        lambda self, *args, **kwargs: pytest.fail("invalid cleanup reached SSH"),
    )
    with pytest.raises(ValueError, match="run identifier"):
        worker._issue_cleanup_capability("Remove-Item run-a", ttl_seconds=60)


def test_scp_destination_is_derived_from_authorized_host(monkeypatch):
    seen: list[list[str]] = []

    def fake_run(argv, **kwargs):
        seen.append(argv)
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr("zeroverse.windows_oracle.subprocess.run", fake_run)
    WindowsWorker("worker-02.example.test", lab_only=True)._scp(
        ["target.exe"], "0verse-" + "a" * 32
    )
    assert seen[0][-1] == "worker-02.example.test:C:/Windows/Temp/0verse-" + "a" * 32 + "/"
    with pytest.raises(ValueError, match="run identifier"):
        WindowsWorker("worker-02.example.test", lab_only=True)._scp(
            ["target.exe"], "attacker:/redirect"
        )


def test_pageheap_lock_contention_fails_without_releasing_another_run(tmp_path, monkeypatch):
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    calls = []

    def fake_ssh(self, script, *, timeout):
        calls.append(script)
        if len(calls) == 2:
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"already exists")
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(WindowsWorker, "_ssh", fake_ssh)
    result = WindowsWorker("worker-02.example.test", lab_only=True).run_pageheap(binary, b"poc")
    assert not result.crashed
    assert "another replay owns the lock" in result.stderr
    assert "0verse-pageheap.lock" not in calls[-1]
    assert "/disable" not in calls[-1]


def test_pageheap_timeout_runs_out_of_band_disable_and_unlock(tmp_path, monkeypatch):
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    calls = []

    def fake_ssh(self, script, *, timeout):
        calls.append(script)
        if "0VERSE-BUILDLABEX" in script:
            raise subprocess.TimeoutExpired("ssh", timeout)
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(WindowsWorker, "_ssh", fake_ssh)
    monkeypatch.setattr(
        "zeroverse.windows_oracle.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
    )
    result = WindowsWorker("worker-02.example.test", lab_only=True).run_pageheap(binary, b"poc")
    assert not result.crashed
    assert "timeout" in result.stderr.lower()
    assert "target.exe" in calls[1]
    assert "0verse-pageheap.lock" in calls[-1]
    assert "/disable" in calls[-1]
    assert calls[-1].index("/disable") < calls[-1].index("Remove-Item")
    assert "gflags PageHeap disable failed" in calls[-1]


def test_pageheap_cleanup_failure_invalidates_crash_result(tmp_path, monkeypatch):
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    calls = []

    def fake_ssh(self, script, *, timeout):
        calls.append(script)
        if "0VERSE-BUILDLABEX" in script:
            return SimpleNamespace(
                returncode=0,
                stdout=b"0VERSE-BUILDLABEX:test.canary\nVERIFIER STOP\n",
                stderr=b"",
            )
        if "/disable" in script:
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"gflags failed")
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(WindowsWorker, "_ssh", fake_ssh)
    monkeypatch.setattr(
        "zeroverse.windows_oracle.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
    )
    result = WindowsWorker("worker-02.example.test", lab_only=True).run_pageheap(binary, b"poc")
    assert not result.crashed
    assert result.sanitizer == ""
    assert "cleanup failed; lock retained" in result.stderr


def test_drmemory_transport_failure_cannot_confirm_crash(tmp_path, monkeypatch):
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    calls = []

    def fake_ssh(self, script, *, timeout):
        calls.append(script)
        if "0VERSE-BUILDLABEX" in script:
            return SimpleNamespace(
                returncode=255,
                stdout=b"0VERSE-BUILDLABEX:test.canary\nUNADDRESSABLE ACCESS\n",
                stderr=b"connection lost",
            )
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(WindowsWorker, "_ssh", fake_ssh)
    monkeypatch.setattr(
        "zeroverse.windows_oracle.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
    )
    result = WindowsWorker("worker-02.example.test", lab_only=True).run_drmemory(binary, b"poc")
    assert not result.crashed
    assert "exited 255" in result.stderr
