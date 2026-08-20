"""#15 AFL++ driver — seed/dict strategy, crash collection, fake + real guards."""

from __future__ import annotations

from pathlib import Path

import pytest

from zeroverse.fuzz import aflpp
from zeroverse.fuzz.aflpp import (
    AflConfig,
    FakeAfl,
    SubprocessAfl,
    seeds_from_tokens,
    tokens_from_context,
    write_dict_file,
)
from zeroverse.sandbox_exec import DisabledExecutor, reset_executor, set_executor


@pytest.fixture(autouse=True)
def _unpiped_core_pattern(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the host's core handler to "not piped" for the whole module.

    `SubprocessAfl.fuzz` refuses the instrumented lane on a host whose
    `kernel.core_pattern` is a userspace pipe (#312), and a stock Ubuntu CI
    runner has exactly that (apport). Without this, every non-QEMU test here
    would pass or fail depending on the box it ran on. The refusal itself is
    covered explicitly below."""
    monkeypatch.setattr(aflpp, "_piped_core_pattern", lambda: "")


def test_build_fuzz_binaries_propagates_runtime_link_libraries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands: list[tuple[str, list[str]]] = []
    monkeypatch.setattr(aflpp, "afl_cc", lambda: "afl-clang-fast")

    def compile_stub(cc: str, args: list[str], **_kwargs: object) -> tuple[bool, str]:
        commands.append((cc, args))
        return True, ""

    monkeypatch.setattr(aflpp, "_compile", compile_stub)
    compiled = aflpp.build_fuzz_binaries(
        "int main(void) { return 0; }",
        [],
        tmp_path,
        config=AflConfig(cmplog=True),
        link_libs=("-ldl",),
        compiler_path="/planned/afl-clang-fast",
        native_compiler_path="/planned/native-cc",
        compiler_resolved=True,
    )
    assert compiled is not None
    assert [compiler for compiler, _ in commands] == [
        "/planned/afl-clang-fast",
        "/planned/afl-clang-fast",
        "/planned/native-cc",
    ]
    assert all("-ldl" in command for _, command in commands)


    c = 'if (memcmp(data, "REC0", 4) != 0) return -1;  char *s = "ab";'
    toks = tokens_from_context(c)
    assert "REC0" in toks
    assert "ab" in toks


def test_seeds_from_tokens_prefix_magic() -> None:
    seeds = seeds_from_tokens(["REC0"])
    assert seeds and seeds[0].startswith(b"REC0")


def test_write_dict_file_escapes_nonprintable(tmp_path: Path) -> None:
    p = write_dict_file(["RE\x01C"], tmp_path / "d.dict")
    assert p is not None
    body = p.read_text()
    assert 'tok_0="RE\\x01C"' in body


def test_write_dict_file_none_for_empty(tmp_path: Path) -> None:
    assert write_dict_file([], tmp_path / "d.dict") is None


def test_fake_afl_reports_constructed_crashes(tmp_path: Path) -> None:
    backend = FakeAfl(crashes=[b"REC0\xffAAAA"])
    res = backend.fuzz(
        Path("/bin/true"), in_dir=tmp_path / "in", out_dir=tmp_path / "out",
        config=AflConfig(),
    )
    assert res.found_crash
    assert res.crashes == [b"REC0\xffAAAA"]
    # the crash was actually written to the AFL-style crash dir
    assert (tmp_path / "out" / "default" / "crashes").is_dir()


def test_collect_crashes_reads_id_files(tmp_path: Path) -> None:
    cdir = tmp_path / "default" / "crashes"
    cdir.mkdir(parents=True)
    (cdir / "id:000000,sig:11").write_bytes(b"boom")
    (cdir / "README.txt").write_text("ignore me")
    crashes, files = aflpp._collect_crashes(tmp_path)
    assert crashes == [b"boom"]
    assert len(files) == 1


def test_subprocess_afl_consumes_resolved_path_without_reprobe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        aflpp,
        "afl_fuzz_path",
        lambda: (_ for _ in ()).throw(AssertionError("AFL path was re-probed")),
    )
    monkeypatch.setattr(
        aflpp.subprocess,
        "run",
        lambda cmd, **kwargs: commands.append(cmd),
    )

    SubprocessAfl(afl_path="/planned/afl-fuzz", resolved=True).fuzz(
        Path("/bin/true"),
        in_dir=tmp_path / "in",
        out_dir=tmp_path / "out",
        config=AflConfig(qemu_mode=False, duration_s=1),
    )

    assert commands[0][0] == "/planned/afl-fuzz"


def test_subprocess_afl_consumes_planned_host_qemu_helper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    traces: list[str | None] = []
    environments: list[dict[str, str]] = []
    monkeypatch.setattr(
        aflpp,
        "_prepare_cross_afl_path",
        lambda cpu, near, trace=None: traces.append(trace) or "/planned/afl-path",
    )
    monkeypatch.setattr(
        aflpp.subprocess,
        "run",
        lambda cmd, **kwargs: environments.append(kwargs["env"]),
    )

    SubprocessAfl(
        afl_path="/planned/afl-fuzz",
        qemu_path="/planned/afl-qemu-trace",
        resolved=True,
        execution_authorized=True,
    ).fuzz(
        Path("/bin/true"),
        in_dir=tmp_path / "in",
        out_dir=tmp_path / "out",
        config=AflConfig(qemu_mode=True, duration_s=1),
    )

    assert traces == ["/planned/afl-qemu-trace"]
    assert environments[0]["AFL_PATH"] == "/planned/afl-path"


def test_subprocess_afl_cannot_bypass_disabled_executor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        aflpp.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("raw AFL subprocess bypassed DisabledExecutor")
        ),
    )
    set_executor(DisabledExecutor("disabled for test"))
    try:
        result = SubprocessAfl(
            afl_path="/planned/afl-fuzz",
            resolved=True,
        ).fuzz(
            Path("/bin/true"),
            in_dir=tmp_path / "in",
            out_dir=tmp_path / "out",
            config=AflConfig(duration_s=1),
        )
    finally:
        reset_executor()

    assert "disabled" in result.note.lower()


def test_subprocess_afl_cannot_use_remote_executor_as_local_authorization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class RemoteExecutor:
        def run(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            raise AssertionError("remote executor was invoked by raw AFL")

    monkeypatch.setattr(
        aflpp.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("local AFL launched under remote placement")
        ),
    )
    set_executor(RemoteExecutor())
    try:
        result = SubprocessAfl(
            afl_path="/planned/afl-fuzz",
            resolved=True,
        ).fuzz(
            Path("/bin/true"),
            in_dir=tmp_path / "in",
            out_dir=tmp_path / "out",
            config=AflConfig(duration_s=1),
        )
    finally:
        reset_executor()

    assert "disabled" in result.note.lower()


def test_subprocess_afl_qemu_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(aflpp, "afl_fuzz_path", lambda: "/fake/afl-fuzz")
    monkeypatch.setattr(aflpp, "afl_qemu_available", lambda *_a: False)
    res = SubprocessAfl().fuzz(
        Path("/bin/true"), in_dir=tmp_path / "in", out_dir=tmp_path / "out",
        config=AflConfig(qemu_mode=True),
    )
    assert not res.found_crash
    assert "afl-qemu-trace" in res.note


def test_subprocess_afl_missing_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(aflpp, "afl_available", lambda: False)
    res = SubprocessAfl().fuzz(
        Path("/bin/true"), in_dir=tmp_path / "in", out_dir=tmp_path / "out",
        config=AflConfig(),
    )
    assert "afl-fuzz" in res.note


# --- #315: the three-way routing predicate ----------------------------------

_INSTRUMENTED = b"\x7fELF" + b"\x00" * 32 + b"__AFL_SHM_ID\x00__afl_area_ptr\x00"


def test_instrumented_driverless_binary_is_not_a_file_input_driver(
    tmp_path: Path
) -> None:
    """magma ``lua``'s shape: AFL instrumentation, no libFuzzer/AFL driver entry.

    ``is_instrumented_fuzz_target`` also selects the ``@@`` file-arg input form,
    so it must stay False here — ``lua`` reads STDIN. ``has_afl_instrumentation``
    is the weaker predicate that only keeps it out of ``-Q``."""
    b = tmp_path / "lua"
    b.write_bytes(_INSTRUMENTED + b"__sanitizer_cov_trace_pc\x00")

    assert aflpp.is_instrumented_fuzz_target(b) is False
    assert aflpp.has_afl_instrumentation(b) is True


def test_instrumented_driver_binary_satisfies_both_predicates(tmp_path: Path) -> None:
    b = tmp_path / "libpng_read_fuzzer"
    b.write_bytes(
        _INSTRUMENTED + b"__sanitizer_cov_trace_pc\x00LLVMFuzzerTestOneInput\x00")

    assert aflpp.is_instrumented_fuzz_target(b) is True
    assert aflpp.has_afl_instrumentation(b) is True


def test_asan_without_afl_coverage_stays_in_qemu_mode(tmp_path: Path) -> None:
    """A plain ASan build carries no AFL forkserver, so afl-fuzz would abort the
    OTHER way ("No instrumentation detected") if we pulled it out of ``-Q``."""
    b = tmp_path / "plain_asan"
    b.write_bytes(b"\x7fELF" + b"\x00" * 32 + b"__asan_init\x00")

    assert aflpp.is_instrumented_fuzz_target(b) is False
    assert aflpp.has_afl_instrumentation(b) is False


def test_unreadable_path_is_not_instrumented(tmp_path: Path) -> None:
    assert aflpp.has_afl_instrumentation(tmp_path / "nope") is False

# --- #312: a piped core handler is a REFUSAL, not a slow discovery ----------

def test_instrumented_lane_refuses_a_piped_core_pattern(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A userspace crash reporter swallows the crashes afl-fuzz has to observe.
    Combined with `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES` (which we must set for
    shared hosts) AFL's own hard abort becomes a silent stall that reports as a
    clean zero. Refuse up front and name the host fix."""
    monkeypatch.setattr(
        aflpp, "_piped_core_pattern", lambda: "|/usr/share/apport/apport %p %s"
    )
    monkeypatch.setattr(
        aflpp.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("afl-fuzz was launched against a piped core handler")
        ),
    )

    res = SubprocessAfl(
        afl_path="/planned/afl-fuzz", resolved=True, execution_authorized=True
    ).fuzz(
        Path("/bin/true"),
        in_dir=tmp_path / "in",
        out_dir=tmp_path / "out",
        config=AflConfig(qemu_mode=False, duration_s=1),
    )

    assert res.note.startswith("REFUSED:")
    assert "core_pattern" in res.note
    assert "apport" in res.note
    assert "sysctl" in res.note
    assert not res.found_crash
    assert not res.timed_out


def test_piped_core_pattern_refusal_does_not_touch_the_qemu_lane(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The refusal is scoped to the lane it was measured on. QEMU-mode keeps the
    existing behaviour: run, and name the piped handler in the timeout note."""
    launched: list[list[str]] = []
    monkeypatch.setattr(
        aflpp, "_piped_core_pattern", lambda: "|/usr/share/apport/apport %p %s"
    )
    monkeypatch.setattr(
        aflpp.subprocess, "run", lambda cmd, **kwargs: launched.append(cmd)
    )

    SubprocessAfl(
        afl_path="/planned/afl-fuzz",
        qemu_path="/planned/afl-qemu-trace",
        resolved=True,
        execution_authorized=True,
    ).fuzz(
        Path("/bin/true"),
        in_dir=tmp_path / "in",
        out_dir=tmp_path / "out",
        config=AflConfig(qemu_mode=True, duration_s=1),
    )

    assert launched, "QEMU-mode was refused by the instrumented-lane guard"


# --- #313: the fork server must be killable ---------------------------------

def test_fork_server_is_killed_with_sigkill_not_sigterm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AFL++ >= 4.09 defaults to SIGTERM for the fork server. A prebuilt
    OSS-Fuzz/magma driver carries an older afl-compiler-rt whose SIGTERM handler
    kills the child and RETURNS, so the fork server survives, goes back to
    blocking on the control pipe, and afl-fuzz deadlocks in waitpid — the run is
    over after its first crash (#313)."""
    environments: list[dict[str, str]] = []
    monkeypatch.setattr(
        aflpp.subprocess, "run", lambda cmd, **kwargs: environments.append(kwargs["env"])
    )

    SubprocessAfl(
        afl_path="/planned/afl-fuzz", resolved=True, execution_authorized=True
    ).fuzz(
        Path("/bin/true"),
        in_dir=tmp_path / "in",
        out_dir=tmp_path / "out",
        config=AflConfig(qemu_mode=False, duration_s=1),
    )

    assert environments[0]["AFL_FORK_SERVER_KILL_SIGNAL"] == "9"


def test_operator_can_override_the_fork_server_kill_signal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    environments: list[dict[str, str]] = []
    monkeypatch.setattr(
        aflpp.subprocess, "run", lambda cmd, **kwargs: environments.append(kwargs["env"])
    )

    SubprocessAfl(
        afl_path="/planned/afl-fuzz", resolved=True, execution_authorized=True
    ).fuzz(
        Path("/bin/true"),
        in_dir=tmp_path / "in",
        out_dir=tmp_path / "out",
        config=AflConfig(
            qemu_mode=False,
            duration_s=1,
            extra_env={"AFL_FORK_SERVER_KILL_SIGNAL": "15"},
        ),
    )

    assert environments[0]["AFL_FORK_SERVER_KILL_SIGNAL"] == "15"


# --- #320: the dry-run timeout ceiling and skipped-seed accounting -----------

class _FakeProc:
    def __init__(self, stdout: bytes = b"", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = b""
        self.returncode = returncode


def _run_capturing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    config: AflConfig,
    stdout: bytes = b"",
    returncode: int = 0,
) -> tuple[list[str], aflpp.FuzzResult]:
    seen: list[list[str]] = []

    def fake_run(cmd: list[str], **_kwargs: object) -> _FakeProc:
        seen.append(cmd)
        return _FakeProc(stdout, returncode)

    monkeypatch.setattr(aflpp.subprocess, "run", fake_run)
    monkeypatch.setattr(aflpp, "_prepare_cross_afl_path", lambda *_a, **_k: "/afl-path")
    res = SubprocessAfl(
        afl_path="/planned/afl-fuzz",
        qemu_path="/planned/afl-qemu-trace",
        resolved=True,
        execution_authorized=True,
    ).fuzz(
        Path("/bin/true"),
        in_dir=tmp_path / "in",
        out_dir=tmp_path / "out",
        config=config,
    )
    return seen[0], res


def test_argv_always_carries_an_explicit_exec_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#320 — omitting ``-t`` does NOT select afl's default ceiling, it selects
    the dry run that FATALs on the first slow seed (afl-fuzz-init.c:975), killing
    the campaign before a single mutation. The flag must always be present."""
    cmd, _ = _run_capturing(monkeypatch, tmp_path, AflConfig(duration_s=1))

    assert "-t" in cmd
    assert cmd[cmd.index("-t") + 1] == str(aflpp.EXEC_TIMEOUT_MS)


def test_exec_timeout_is_the_plain_form_not_the_auto_calculating_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """NOT ``-t N+``. In 4.09c any ``-t`` already skips a slow seed instead of
    aborting; ``+`` additionally overwrites the ceiling after the dry run with
    the slowest seed's ``exec_us`` — microseconds into a millisecond field
    (afl-fuzz.c:2448). Measured on bench: ``-t 1000+`` yielded exec_timeout
    350573 ms and 1.33 execs/s where plain ``-t 1000`` yielded 35.13 execs/s."""
    for config in (AflConfig(duration_s=1), AflConfig(qemu_mode=True, duration_s=1)):
        cmd, _ = _run_capturing(monkeypatch, tmp_path, config)
        assert not cmd[cmd.index("-t") + 1].endswith("+")


def test_qemu_lane_gets_a_larger_ceiling_than_the_native_lane(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``-t`` is the dry-run admission bar as well as the per-exec kill, and
    afl-fuzz does not scale it for ``-Q``. A native-tuned ceiling under QEMU
    would reject seeds that are fine natively (measured 1.5-3.1x per-exec cost
    on bench), i.e. it would silently shrink the corpus for the binary-only
    lane only."""
    native, _ = _run_capturing(monkeypatch, tmp_path, AflConfig(duration_s=1))
    qemu, _ = _run_capturing(
        monkeypatch, tmp_path, AflConfig(qemu_mode=True, duration_s=1)
    )

    n = int(native[native.index("-t") + 1])
    q = int(qemu[qemu.index("-t") + 1])
    assert q > n
    assert aflpp.exec_timeout_ms(AflConfig(qemu_mode=True)) == q


def test_skipped_seeds_are_counted_and_surfaced_in_the_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``-t`` trades a loud FATAL for a SILENT skip. A run that lost half its
    corpus must not read like one that kept it (#296/#297/#304), so afl-fuzz's
    own dry-run tally is parsed and reported."""
    afl_output = (
        b"[*] Attempting dry run with 'id:000003,orig:slow'...\n"
        b"[!] WARNING: Test case results in a timeout (skipping)\n"
        b"[!] WARNING: Skipped 2 test cases (50.00%) due to timeouts or crashes.\n"
        b"[+] All test cases processed.\n"
    )
    _, res = _run_capturing(
        monkeypatch,
        tmp_path,
        AflConfig(duration_s=1, seeds=[b"a", b"b", b"c", b"d"]),
        stdout=afl_output,
    )

    assert res.seeds_skipped == 2
    assert res.seeds_total == 4
    assert res.corpus_lost
    assert "DROPPED 2/4" in res.note


def test_skipped_seed_tally_is_read_from_a_run_that_hit_the_hard_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The dry-run tally is printed at startup, so a campaign that later wedged
    into the hard timeout still reported what it dropped. Discarding the
    exception's captured output would throw that away."""

    def fake_run(cmd: list[str], **_kwargs: object) -> _FakeProc:
        raise aflpp.subprocess.TimeoutExpired(
            cmd,
            1.0,
            output=b"[!] WARNING: Skipped 1 test cases (50.00%) due to timeouts.\n",
            stderr=b"",
        )

    monkeypatch.setattr(aflpp.subprocess, "run", fake_run)
    res = SubprocessAfl(
        afl_path="/planned/afl-fuzz", resolved=True, execution_authorized=True
    ).fuzz(
        Path("/bin/true"),
        in_dir=tmp_path / "in",
        out_dir=tmp_path / "out",
        config=AflConfig(duration_s=1, seeds=[b"a", b"b"]),
    )

    assert res.timed_out
    assert res.seeds_skipped == 1
    assert "DROPPED 1/2" in res.note


def test_a_run_whose_whole_corpus_was_rejected_is_a_failure_not_a_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """afl-fuzz FATALs when every seed times out or crashes in the dry run
    (afl-fuzz-init.c:1256). That campaign fuzzed nothing — reporting it as a
    clean zero is the exact failure family this repo keeps hitting."""
    _, res = _run_capturing(
        monkeypatch,
        tmp_path,
        AflConfig(duration_s=1, seeds=[b"a", b"b", b"c"]),
        stdout=b"[-] PROGRAM ABORT : All test cases time out or crash, giving up!\n",
        returncode=1,
    )

    assert res.note.startswith("FAILED:")
    assert res.seeds_skipped == 3
    assert res.seeds_total == 3
    assert res.corpus_lost
    assert res.execs == 0


def test_a_clean_run_reports_no_lost_corpus(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, res = _run_capturing(
        monkeypatch,
        tmp_path,
        AflConfig(duration_s=1, seeds=[b"a", b"b"]),
        stdout=b"[+] All test cases processed.\n",
    )

    assert res.seeds_skipped == 0
    assert res.seeds_total == 2
    assert not res.corpus_lost
    assert "DROPPED" not in res.note


def test_skipped_seed_parser_accepts_afls_real_coloured_output() -> None:
    """Parsed from afl's real output rather than guessed. Verified on bench that
    this line goes to STDOUT, and that AFL_NO_UI still wraps it in colour."""
    coloured = (
        b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mSkipped 1 test cases (25.00%) "
        b"due to timeouts or crashes.\x1b[0m\n"
    )
    assert aflpp._parse_skipped_seeds(coloured) == 1
    assert aflpp._parse_skipped_seeds(None, b"Skipped 17 test case (3.00%)") == 17
    assert aflpp._parse_skipped_seeds(b"nothing to see") == 0
