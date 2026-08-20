"""Sandboxed-execution seam — hermetic checks on the pure pieces (rc/sentinel
classification, run-script assembly, staging rules, local-executor semantics,
honest unavailability). No ssh, no msb: the live microsandbox run is exercised
against the fleet (ZEROVERSE_EXECUTOR=msb), not in unit tests."""

from __future__ import annotations

import base64
import json
import re
import subprocess
from pathlib import Path

import pytest

from zeroverse import oracle
from zeroverse import sandbox_exec as sx
from zeroverse.sandbox_exec import (
    DEFAULT_MSB_IMAGE,
    DEFAULT_MSB_SHA256,
    DisabledExecutor,
    ExecResult,
    LocalExecutor,
    MsbSshExecutor,
)

# --- rc / sentinel classification --------------------------------------------


def test_parse_exec_output_extracts_and_strips_sentinels() -> None:
    text = "some target output\n0VERSE-STATUS-abc123:S:11\n0VERSE-MSBEXEC-abc123:0\n"
    rc, timed_out, cleaned, error = sx.parse_exec_output(text, "abc123")
    assert (rc, timed_out, error) == (-11, False, "")
    assert "0VERSE-STATUS" not in cleaned and "0VERSE-MSBEXEC" not in cleaned
    assert "some target output" in cleaned


def test_parse_exec_output_absent_sentinel_is_honest() -> None:
    rc, _, cleaned, error = sx.parse_exec_output("garbage, no sentinel\n", "abc123")
    assert rc is None
    assert "garbage" in cleaned and "host completion" in error
    # msb-exec's own failure is surfaced for diagnosis
    rc2, _, _, error2 = sx.parse_exec_output(
        "boom\n0VERSE-MSBEXEC-abc123:1\n", "abc123"
    )
    assert rc2 is None
    assert error2 == "msb exec exited 1"


def test_parse_exec_output_uses_final_root_status_and_distinguishes_exit() -> None:
    text = (
        "0VERSE-STATUS-abc123:S:11\n"
        "0VERSE-STATUS-abc123:E:139\n"
        "0VERSE-MSBEXEC-abc123:0\n"
    )
    assert sx.parse_exec_output(text, "abc123")[:2] == (139, False)
    timeout = "0VERSE-STATUS-abc123:T\n0VERSE-MSBEXEC-abc123:0\n"
    assert sx.parse_exec_output(timeout, "abc123")[:2] == (0, True)
    exec_error = "0VERSE-STATUS-abc123:X:2\n0VERSE-MSBEXEC-abc123:0\n"
    parsed = sx.parse_exec_output(exec_error, "abc123")
    assert parsed[0] is None and parsed[3] == "guest exec failed with errno 2"


def test_exec_command_carries_env_timeout_redirect_and_sentinel() -> None:
    cmd = sx.build_exec_command(
        ["/work/bin/deadbeef", "/work/in/c1-a1-poc.bin"],
        env={"ASAN_OPTIONS": "abort_on_error=1"}, timeout=7.9, canary="c1",
        stdin_guest_path="/work/in/c1-stdin.bin",
    )
    assert "4153414e5f4f5054494f4e53" in cmd  # ASAN_OPTIONS, hex-encoded as data
    assert "abort_on_error" not in cmd
    assert "perl -e " in cmd and "setuid(65534)" in cmd
    assert "syscall(116,0,0)" in cmd and "syscall(157,38,1,0,0,0)" in cmd
    assert "$fail->(9004)" in cmd and "$fail->(9007)" in cmd
    assert "pkill" in cmd
    assert "< /work/in/c1-stdin.bin" in cmd
    assert "0VERSE-STATUS-c1" in cmd
    # no stdin -> no redirect
    cmd2 = sx.build_exec_command(
        ["/bin/true"], env=None, timeout=10, canary="c2", stdin_guest_path=None,
    )
    assert " < " not in cmd2 and "env " not in cmd2


def _heredoc_payloads(script: str) -> list[bytes]:
    return [
        base64.b64decode(m.group(1))
        for m in re.finditer(r"<<'0VERSE-B64'\n([A-Za-z0-9+/=\n]+)\n0VERSE-B64", script)
    ]


def test_run_script_assembles_staging_exec_and_cleanup() -> None:
    script = sx.build_run_script(
        sandbox="sb1", image=DEFAULT_MSB_IMAGE,
        guest_argv=["/work/bin/deadbeef", "/work/in/c1-a1-poc.bin"],
        staged_files={"/work/in/c1-a1-poc.bin": b"POCDATA"},
        env=None, timeout=10, canary="c1", stdin_guest_path=None,
        expected_msb_sha256=DEFAULT_MSB_SHA256,
    )
    assert f'run -d {DEFAULT_MSB_IMAGE} --name "$SB"' in script
    assert "set -euo pipefail" in script
    assert 'remove -f -q "$SB"' in script
    assert "EXPECTED_MSB_SHA256=" in script
    assert _heredoc_payloads(script) == [b"POCDATA"]
    assert '"$MSB" cp "$D/f0" "$SB:/work/in/c1-a1-poc.bin"' in script
    assert "GUEST_SHA=" in script
    assert "0VERSE-MSBEXEC-c1:$MRC" in script
    assert 'test -x /usr/bin/pkill' in script


def test_run_script_rejects_shell_metacharacters_in_guest_path() -> None:
    with pytest.raises(ValueError, match="unsafe guest staging path"):
        sx.build_run_script(
            sandbox="sb1", image=DEFAULT_MSB_IMAGE,
            guest_argv=["/work/bin/deadbeef"],
            staged_files={"/work/in/$(touch-pwned)": b"x"}, env=None,
            timeout=1, canary="c1", stdin_guest_path=None,
            expected_msb_sha256=DEFAULT_MSB_SHA256,
        )


# --- LocalExecutor (native, the default) --------------------------------------


def test_local_executor_exit_codes_and_signal() -> None:
    ex = LocalExecutor()
    assert ex.run(["/bin/sh", "-c", "exit 0"]).returncode == 0
    assert ex.run(["/bin/sh", "-c", "exit 1"]).returncode == 1
    segv = ex.run(["/bin/sh", "-c", "kill -SEGV $$"])
    assert segv.returncode == -11
    assert not segv.timed_out and not segv.error


def test_local_executor_stdin_env_and_timeout() -> None:
    ex = LocalExecutor()
    r = ex.run(["/bin/cat"], stdin=b"hello-stdin")
    assert r.stdout == "hello-stdin"
    r2 = ex.run(["/bin/sh", "-c", "printf %s \"$OV_TEST_VAR\""],
                env={"OV_TEST_VAR": "marked"})
    assert r2.stdout == "marked"
    t = ex.run(["/bin/sh", "-c", "sleep 5"], timeout=0.3)
    assert t.timed_out


def test_local_executor_oserror_is_honest_error() -> None:
    r = LocalExecutor().run(["/nonexistent/definitely-not-here"])
    assert r.error and not r.timed_out


def test_local_executor_invalid_request_is_honest_error() -> None:
    bad_env = LocalExecutor().run(["/bin/true"], env={"BAD\x00KEY": "value"})
    assert bad_env.error
    bad_timeout = LocalExecutor().run(["/bin/true"], timeout=float("nan"))
    assert bad_timeout.error


# --- MsbSshExecutor (no infra — scripted fake ssh) ----------------------------


def _x86_64_elf() -> bytes:
    header = bytearray(120)
    header[:6] = b"\x7fELF\x02\x01"
    header[18:20] = (62).to_bytes(2, "little")
    header[32:40] = (64).to_bytes(8, "little")
    header[54:56] = (56).to_bytes(2, "little")
    header[56:58] = (1).to_bytes(2, "little")
    header[64:68] = (3).to_bytes(4, "little")  # PT_INTERP
    return bytes(header) + b"target"


class _FakeSsh:
    """Captures scripts and answers with synthetic sentinels; stands in for the
    ssh subprocess so the executor's staging/parsing flow is testable hermetically."""

    def __init__(self) -> None:
        self.scripts: list[str] = []

    def __call__(self, script: str, timeout: float) -> subprocess.CompletedProcess[bytes]:
        self.scripts.append(script)
        m = re.search(r"0VERSE-STATUS-([0-9a-f]+):", script)
        canary = m.group(1) if m else "unknown"
        out = (
            f"target said hi\n0VERSE-STATUS-{canary}:E:0\n"
            f"0VERSE-MSBEXEC-{canary}:0\n"
        )
        return subprocess.CompletedProcess([], 0, out.encode(), b"")


def test_msb_executor_stages_and_rewrites(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binary = tmp_path / "target.bin"
    binary.write_bytes(_x86_64_elf())
    poc = tmp_path / "poc.bin"
    poc.write_bytes(b"POC")
    preload = tmp_path / "guard.so"
    preload.write_bytes(b"ELF-PRELOAD")
    ex = MsbSshExecutor(host="fakehost")
    fake = _FakeSsh()
    monkeypatch.setattr(ex, "_ssh", fake)

    r = ex.run(
        [str(binary), str(poc)],
        stdin=b"STDIN",
        env={"LD_PRELOAD": str(preload)},
        timeout=10,
    )

    assert r.returncode == 0 and "target said hi" in r.stderr
    run_script = fake.scripts[0]
    payloads = _heredoc_payloads(run_script)
    assert {_x86_64_elf(), b"POC", b"STDIN", b"ELF-PRELOAD"} <= set(payloads)
    assert "/work/bin/" in run_script and "poc.bin" not in run_script
    assert str(preload) not in run_script and "-env-" in run_script
    assert "LOAD_OUT=" in run_script and 'test -z "$LOAD_OUT"' in run_script
    assert r.provenance["target_sha256"]
    first_sandbox = r.provenance["sandbox"]
    second = ex.run(
        [str(binary), str(poc)],
        stdin=b"STDIN",
        env={"LD_PRELOAD": str(preload)},
        timeout=10,
    )
    assert len(fake.scripts) == 2
    assert first_sandbox not in fake.scripts[1]
    assert second.provenance["input_sha256"] == r.provenance["input_sha256"]
    assert second.provenance["invocation_sha256"] == r.provenance["invocation_sha256"]


def test_msb_executor_rejects_unstaged_preload(tmp_path: Path) -> None:
    binary = tmp_path / "target"
    binary.write_bytes(_x86_64_elf())
    result = MsbSshExecutor().run(
        [str(binary)], env={"LD_PRELOAD": str(tmp_path / "missing.so")}
    )
    assert result.error.startswith("remote LD_PRELOAD component is not a local file")


def test_msb_executor_rejects_wrong_arch_before_guest_exec(tmp_path: Path) -> None:
    binary = tmp_path / "mips-target"
    header = bytearray(_x86_64_elf())
    header[18:20] = (8).to_bytes(2, "little")
    binary.write_bytes(header)
    result = MsbSshExecutor().run([str(binary)])
    assert result.error == "remote ELF target architecture is unsupported (e_machine=8)"


def test_msb_executor_returns_structured_error_for_invalid_request(tmp_path: Path) -> None:
    binary = tmp_path / "target"
    binary.write_bytes(_x86_64_elf())
    bad_env = MsbSshExecutor().run([str(binary)], env={"BAD\x00KEY": "value"})
    assert bad_env.error.startswith("invalid remote execution request")
    bad_timeout = MsbSshExecutor().run([str(binary)], timeout=float("nan"))
    assert bad_timeout.error.startswith("invalid remote execution request")


def test_remote_shared_object_build_receipt(monkeypatch: pytest.MonkeyPatch) -> None:
    artifact = _x86_64_elf()
    compiler_sha = "a" * 64
    output = f"0VERSE-COMPILER-SHA:{compiler_sha}\n".encode()
    output += base64.b64encode(artifact) + b"\n"
    ex = MsbSshExecutor()
    monkeypatch.setattr(
        ex,
        "_ssh",
        lambda script, timeout: subprocess.CompletedProcess([], 0, output, b""),
    )
    built, compiler = ex.build_shared_object(b"int x;", link_dl=True)
    assert built == artifact and compiler == compiler_sha


def test_msb_executor_records_preload_build_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "target"
    binary.write_bytes(_x86_64_elf())
    preload = tmp_path / "guard.so"
    preload.write_bytes(_x86_64_elf())
    preload.with_suffix(".build.json").write_text(
        json.dumps({"compiler_sha256": "b" * 64, "source_sha256": "c" * 64})
    )
    ex = MsbSshExecutor(host="fakehost")
    monkeypatch.setattr(ex, "_ssh", _FakeSsh())
    result = ex.run([str(binary)], env={"LD_PRELOAD": str(preload)})
    assert result.error == ""
    assert result.provenance["preload_sha256"]
    assert result.provenance["preload_build_sha256"] != (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_msb_executor_rejects_malformed_preload_receipt(tmp_path: Path) -> None:
    binary = tmp_path / "target"
    binary.write_bytes(_x86_64_elf())
    preload = tmp_path / "guard.so"
    preload.write_bytes(_x86_64_elf())
    preload.with_suffix(".build.json").write_text("{bad json")
    result = MsbSshExecutor().run([str(binary)], env={"LD_PRELOAD": str(preload)})
    assert result.error
    preload.with_suffix(".build.json").write_text("[]")
    result = MsbSshExecutor().run([str(binary)], env={"LD_PRELOAD": str(preload)})
    assert result.error


def test_msb_executor_rejects_preload_for_static_target(tmp_path: Path) -> None:
    binary = tmp_path / "static-target"
    static = bytearray(_x86_64_elf())
    static[56:58] = (0).to_bytes(2, "little")
    binary.write_bytes(static)
    preload = tmp_path / "guard.so"
    preload.write_bytes(_x86_64_elf())
    result = MsbSshExecutor().run([str(binary)], env={"LD_PRELOAD": str(preload)})
    assert result.error == "remote LD_PRELOAD proof requires an interpreter-backed target"


def test_msb_executor_honest_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    ex = MsbSshExecutor(host="unavailable")
    monkeypatch.setattr(
        ex,
        "_ssh",
        lambda script, timeout: subprocess.CompletedProcess([], 255, b"", b"down"),
    )
    ok, why = ex.available()
    assert not ok and why


def test_msb_transport_timeout_is_infrastructure_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "target"
    binary.write_bytes(_x86_64_elf())
    ex = MsbSshExecutor()

    def timeout(script: str, timeout: float):
        raise subprocess.TimeoutExpired("ssh", timeout)

    monkeypatch.setattr(ex, "_ssh", timeout)
    result = ex.run([str(binary)])
    assert result.error.startswith("infrastructure timeout")
    assert not result.timed_out


def test_msb_rejects_mutable_image_reference(tmp_path: Path) -> None:
    binary = tmp_path / "target"
    binary.write_bytes(_x86_64_elf())
    result = MsbSshExecutor(image="ubuntu:24.04").run([str(binary)])
    assert result.error == "microsandbox image must be pinned by OCI digest"


def test_msb_nonzero_ssh_invalidates_forged_valid_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "target"
    binary.write_bytes(_x86_64_elf())
    ex = MsbSshExecutor()

    def failed(script: str, timeout: float):
        canary = re.search(r"0VERSE-STATUS-([0-9a-f]+):", script).group(1)
        output = (
            f"0VERSE-STATUS-{canary}:E:0\n0VERSE-MSBEXEC-{canary}:0\n"
        ).encode()
        return subprocess.CompletedProcess([], 255, output, b"connection lost")

    monkeypatch.setattr(ex, "_ssh", failed)
    result = ex.run([str(binary)])
    assert result.error == "ssh transport exited 255: connection lost"


# --- oracle wiring -------------------------------------------------------------


class _Recorder:
    def __init__(self, result: ExecResult) -> None:
        self.result = result
        self.calls: list[dict] = []

    def run(self, argv, *, stdin=b"", env=None, timeout=10.0):
        self.calls.append({"argv": argv, "stdin": stdin, "env": env, "timeout": timeout})
        return self.result


@pytest.fixture
def _restore_executor():
    yield
    sx.reset_executor()


def test_oracle_exec_routes_through_executor(_restore_executor) -> None:
    rec = _Recorder(ExecResult(returncode=-11, stderr="segv here"))
    sx.set_executor(rec)
    res = oracle._exec("/bin/whatever", argv=["-x"], stdin=b"i", timeout=3)
    assert res.crashed and res.signal == "SIGSEGV" and res.stderr == "segv here"
    assert rec.calls[0]["argv"] == ["/bin/whatever", "-x"]
    assert rec.calls[0]["stdin"] == b"i" and rec.calls[0]["timeout"] == 3


def test_oracle_exec_executor_error_is_not_a_crash(_restore_executor) -> None:
    sx.set_executor(_Recorder(ExecResult(error="ssh down")))
    res = oracle._exec("/bin/whatever")
    assert not res.crashed and not res.valid and res.infrastructure_error == "ssh down"
    sx.set_executor(_Recorder(ExecResult(timed_out=True, stderr="timeout")))
    timeout = oracle._exec("/bin/whatever")
    assert not timeout.crashed and not timeout.valid and timeout.timed_out


def test_differential_never_confirms_invalid_control() -> None:
    crash = oracle.RunResult(crashed=True)
    invalid_clean = oracle.RunResult(crashed=False, valid=False)
    assert not oracle.differential_confirmed(crash, invalid_clean)


def test_run_sanitizer_routes_and_classifies(_restore_executor, tmp_path: Path) -> None:
    asan = (
        "=================================================================\n"
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502\n"
        "READ of size 1 at 0x502 thread T0\n"
    )
    rec = _Recorder(ExecResult(returncode=1, stderr=asan))
    sx.set_executor(rec)
    res = oracle.run_sanitizer("/bin/target", b"A" * 16, vector="file")
    assert res.crashed and res.sanitizer == "heap-buffer-overflow"
    # the file vector materialized a temp poc whose path rode in argv after the target
    assert rec.calls[0]["argv"][0] == "/bin/target"
    assert len(rec.calls[0]["argv"]) == 2


def test_executor_selection_is_explicit(_restore_executor, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ZEROVERSE_EXECUTOR", raising=False)
    assert isinstance(sx.executor_from_env(), DisabledExecutor)
    monkeypatch.setenv("ZEROVERSE_EXECUTOR", "local")
    assert isinstance(sx.executor_from_env(), LocalExecutor)
    monkeypatch.setenv("ZEROVERSE_EXECUTOR", "msb")
    monkeypatch.setenv("ZEROVERSE_MSB_HOST", "somehost")
    ex = sx.executor_from_env()
    assert isinstance(ex, MsbSshExecutor) and ex.host == "somehost"


def test_oracle_propagates_executor_provenance(_restore_executor) -> None:
    sx.set_executor(
        _Recorder(ExecResult(returncode=0, provenance={"target_sha256": "a" * 64}))
    )
    assert oracle._exec("/bin/whatever").provenance["target_sha256"] == "a" * 64
