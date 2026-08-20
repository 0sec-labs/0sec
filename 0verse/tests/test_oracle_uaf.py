"""M4 #24 — the quarantine guard allocator (poison-on-free + mprotect quarantine)
and the ``uaf_differential`` oracle. Logic-level checks are hermetic; the real
catch-a-UAF / catch-a-double-free checks compile a tiny binary, gated on cc."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from zeroverse import oracle

_HAS_CC = shutil.which("cc") or shutil.which("gcc")
requires_cc = pytest.mark.skipif(not _HAS_CC, reason="no C compiler")
requires_linux_elf = pytest.mark.skipif(
    sys.platform != "linux", reason="UAF quarantine proof builds and runs ELF"
)


def test_format_string_probe_shape() -> None:
    probe = oracle.format_string_probe(4)
    assert probe == b"%s%s%s%s%n"
    assert probe.endswith(b"%n")  # a controlled-write conversion caps the read spray


def test_quarantine_env_fallback_without_cc(monkeypatch: pytest.MonkeyPatch) -> None:
    # when the guard .so cannot be built, fall back to the glibc guard env, which
    # still aborts on double-free (honest degrade, never a silent pass).
    monkeypatch.setattr(oracle, "build_quarantine_guard", lambda: None)
    env = oracle.quarantine_env()
    assert env["MALLOC_CHECK_"] == "3"


def test_uaf_verdict_requires_trigger_crash_and_clean_control() -> None:
    confirmed = oracle.UafVerdict(
        trigger=oracle.RunResult(crashed=True, signal="SIGSEGV"),
        control=oracle.RunResult(crashed=False),
        confirmed=True, kind="use-after-free",
    )
    assert confirmed.confirmed and confirmed.kind == "use-after-free"


@requires_cc
def test_build_quarantine_guard_is_cached() -> None:
    so = oracle.build_quarantine_guard()
    assert so is not None and Path(so).is_file()
    assert oracle.build_quarantine_guard() == so  # idempotent / cached
    assert oracle.quarantine_available()


def _cc(src: str, out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    binp = out / "t"
    (out / "t.c").write_text(src)
    subprocess.run(["cc", "-O0", "-no-pie", str(out / "t.c"), "-o", str(binp)],
                   check=True, capture_output=True)
    return binp


@requires_cc
@requires_linux_elf
def test_uaf_differential_catches_real_use_after_free(tmp_path: Path) -> None:
    src = ('#include <stdlib.h>\n#include <unistd.h>\n'
           'int main(void){char*p=malloc(64);free(p);char in[4]={0};'
           'int n=read(0,in,3);if(n<0)n=0;in[n]=0;'
           'if(in[0]==\'X\'){p[0]=1;return p[1];}return 0;}\n')
    binp = _cc(src, tmp_path)
    v = oracle.uaf_differential(str(binp), b"X", b"n")
    assert v.confirmed and v.kind == "use-after-free"
    assert v.trigger.crashed and not v.control.crashed


@requires_cc
@requires_linux_elf
def test_uaf_differential_catches_double_free(tmp_path: Path) -> None:
    src = ('#include <stdlib.h>\n#include <unistd.h>\n'
           'int main(void){char*p=malloc(32);free(p);char in[4]={0};'
           'int n=read(0,in,3);if(n<0)n=0;in[n]=0;if(in[0]==\'X\')free(p);return 0;}\n')
    binp = _cc(src, tmp_path)
    v = oracle.uaf_differential(str(binp), b"X", b"n")
    assert v.confirmed and v.kind == "double-free"


@requires_cc
def test_uaf_differential_rejects_clean_program(tmp_path: Path) -> None:
    # no UAF: both trigger and control run clean -> not confirmed.
    src = ('#include <stdlib.h>\n#include <unistd.h>\n'
           'int main(void){char*p=malloc(32);char in[4]={0};read(0,in,3);'
           'free(p);return 0;}\n')
    binp = _cc(src, tmp_path)
    v = oracle.uaf_differential(str(binp), b"X", b"n")
    assert not v.confirmed
