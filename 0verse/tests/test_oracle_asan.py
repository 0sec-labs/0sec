"""ASan + file-input confirmation path (feat/asan-file-oracle).

The hermetic tests exercise the sanitizer-report parser with no binary; the
end-to-end tests compile a tiny ``-fsanitize=address`` libFuzzer-style target
(input as a FILE in argv[1], crash via an ASan report at a non-zero exit) and are
skip-guarded when no clang is available.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from zeroverse import oracle
from zeroverse.agent import Verdict
from zeroverse.analyze import Finding
from zeroverse.dynamic import confirm_asan_file

# A libFuzzer-shaped target: reads argv[1] as a file, overflows an 8-byte heap
# buffer only when the input is large (>100B), so a 64B benign control stays
# clean while the 4096-byte probe trips ASan. The LLVMFuzzerTestOneInput symbol
# makes ``is_asan_file_target`` recognize it.
_ASAN_SRC = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const unsigned char *data, long size) {
    char *buf = (char *)malloc(8);
    if (size > 100) {
        memcpy(buf, data, size);   /* heap-buffer-overflow */
    }
    free(buf);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 0;
    static unsigned char buf[1 << 16];
    long n = (long)fread(buf, 1, sizeof buf, f);
    fclose(f);
    return LLVMFuzzerTestOneInput(buf, n);
}
"""


def _build_asan(tmp_path) -> str:  # type: ignore[no-untyped-def]
    clang = shutil.which("clang")
    if clang is None:
        pytest.skip("clang not available")
    src = tmp_path / "asan_target.c"
    src.write_text(_ASAN_SRC)
    out = tmp_path / "asan_target"
    r = subprocess.run(
        [clang, "-fsanitize=address", "-O0", "-g", "-o", str(out), str(src)],
        capture_output=True,
    )
    if r.returncode != 0 or not out.exists():
        pytest.skip(f"asan build unavailable: {r.stderr.decode('utf-8', 'replace')[:200]}")
    return str(out)


# --- hermetic: the sanitizer-report parser ---------------------------------

def test_sanitizer_report_detects_asan_kind() -> None:
    err = (
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdead\n"
        "SUMMARY: AddressSanitizer: heap-buffer-overflow foo.c:1 in bar\n"
    )
    assert oracle.sanitizer_report(err) == "heap-buffer-overflow"


def test_sanitizer_report_detects_ubsan() -> None:
    # UBSan now names the SPECIFIC undefined behavior (hyphenated) so it can map to a
    # CWE — signed integer overflow -> a token crash_to_cwe reads as CWE-190.
    assert (
        oracle.sanitizer_report(
            "foo.c:3:5: runtime error: signed integer overflow: 2 * 2147483647 "
            "cannot be represented in type 'int'"
        )
        == "signed-integer-overflow"
    )
    # An unfamiliar/wordless UB phrase still degrades to the class-less label.
    assert oracle.sanitizer_report("x.c:1:1: runtime error:") == "undefined-behavior"


def test_sanitizer_report_detects_msan_uninit() -> None:
    # MSan uninitialized-value reports (no ``ERROR:`` banner) were previously MISSED
    # entirely (read as NO_CRASH). Now classified so crash_to_cwe -> CWE-457.
    err = (
        "==1==WARNING: MemorySanitizer: use-of-uninitialized-value\n"
        "    #0 0x deadbeef in LLVMFuzzerTestOneInput foo.c:10:6\n"
        "SUMMARY: MemorySanitizer: use-of-uninitialized-value foo.c:10:6\n"
    )
    assert oracle.sanitizer_report(err) == "use-of-uninitialized-value"


def test_sanitizer_report_msan_does_not_swallow_via_leak_guard() -> None:
    # The leak guard must not fire before an MSan hard error is classified.
    err = (
        "==1==WARNING: MemorySanitizer: use-of-uninitialized-value\n"
        "SUMMARY: MemorySanitizer: use-of-uninitialized-value x.c:1\n"
    )
    assert oracle.sanitizer_report(err) != ""


def test_sanitizer_report_ignores_leak() -> None:
    # A LeakSanitizer-only report is not the OOB/UAF crash we hunt.
    err = (
        "==1==ERROR: LeakSanitizer: detected memory leaks\n"
        "SUMMARY: AddressSanitizer: 40 byte(s) leaked in 1 allocation(s).\n"
    )
    assert oracle.sanitizer_report(err) == ""


def test_sanitizer_report_detects_ubsan_deadly_signal() -> None:
    # UBSan intercepting a fatal signal (-fsanitize=undefined traps a SEGV and
    # reports it WITHOUT any ``runtime error:`` line) previously fell through
    # every detector — a UBSan-caught null-deref fuzz crash on an isan target
    # read as NO_CRASH and was silently dropped (#224, magma libpng driver).
    err = (
        "Monitor not running. Canaries will be disabled.\n"
        "UndefinedBehaviorSanitizer:DEADLYSIGNAL\n"
        "==10==ERROR: UndefinedBehaviorSanitizer: SEGV on unknown address "
        "0x000000000000 (pc 0x7ffffee3353b bp 0x7ffffffc5460 sp 0x7ffffffc5428 T10)\n"
        "==10==The signal is caused by a READ memory access.\n"
        "==10==Hint: address points to the zero page.\n"
        "    #0 0x7ffffee3353a  (/lib/x86_64-linux-gnu/libc.so.6+0x4553a)\n"
        "    #1 0x46f152  (/bins/libpng/libpng_read_fuzzer+0x46f152)\n"
    )
    assert oracle.sanitizer_report(err) == "segv"
    # a BUS intercept classifies likewise
    assert oracle.sanitizer_report(
        "==3==ERROR: UndefinedBehaviorSanitizer: BUS on unknown address 0x0\n"
    ) == "bus"


def test_sanitizer_report_clean() -> None:
    assert oracle.sanitizer_report("all good, executed 1 input\n") == ""


# --- end-to-end: real ASan target, file-input vector -----------------------

def test_run_sanitizer_file_vector_crash_and_clean(tmp_path) -> None:  # type: ignore[no-untyped-def]
    binary = _build_asan(tmp_path)
    crash = oracle.run_sanitizer(binary, b"A" * 4096, vector="file")
    assert crash.crashed and crash.sanitizer == "heap-buffer-overflow"
    clean = oracle.run_sanitizer(binary, b"A" * 64, vector="file")
    assert not clean.crashed and clean.sanitizer == ""


def test_is_asan_file_target_and_launch(tmp_path) -> None:  # type: ignore[no-untyped-def]
    binary = _build_asan(tmp_path)
    assert oracle.is_asan_file_target(binary)
    assert oracle.host_can_launch(binary)


def test_confirm_asan_file_confirms(tmp_path) -> None:  # type: ignore[no-untyped-def]
    binary = _build_asan(tmp_path)
    finding = Finding("read", "LLVMFuzzerTestOneInput", "main", 0x1000, 0x1010, 6)
    verdict = Verdict(
        is_real=True, bug_class="memory-safety", severity="high",
        explanation="", input_example="",
    )
    pov = confirm_asan_file(finding, verdict, binary)
    assert pov is not None and pov.reproduced
    assert pov.file_input is True
    assert pov.crash_class == "heap-buffer-overflow"
    assert pov.input_bytes  # a concrete crashing file body


def test_confirm_asan_file_clean_target_returns_none(tmp_path) -> None:  # type: ignore[no-untyped-def]
    clang = shutil.which("clang")
    if clang is None:
        pytest.skip("clang not available")
    src = tmp_path / "clean.c"
    src.write_text(
        "int LLVMFuzzerTestOneInput(const unsigned char*d,long n){(void)d;(void)n;return 0;}\n"
        "#include <stdio.h>\nint main(int c,char**v){(void)c;(void)v;return 0;}\n"
    )
    out = tmp_path / "clean"
    r = subprocess.run(
        [clang, "-fsanitize=address", "-O0", "-o", str(out), str(src)],
        capture_output=True,
    )
    if r.returncode != 0:
        pytest.skip("asan build unavailable")
    finding = Finding("read", "LLVMFuzzerTestOneInput", "main", 0, 0, 0)
    verdict = Verdict(is_real=True, bug_class="x", severity="low",
                      explanation="", input_example="")
    # No input trips the sanitizer -> no fabricated PoV.
    assert confirm_asan_file(finding, verdict, str(out)) is None


def test_file_input_minimization_is_bounded_and_preserves_predicate() -> None:
    # The generic reducer knows nothing about a target: its predicate represents
    # the already-selected file-input crash oracle.
    seen: list[bytes] = []

    def confirms(data: bytes) -> bool:
        seen.append(data)
        return b"!" in data

    result = oracle.minimize_file_input(b"abc!def", confirms, max_runs=3)
    assert b"!" in result.candidate
    assert result.oracle_runs == len(seen) <= 3
    assert result.max_runs == 3


def test_crash_feedback_receipt_contains_only_input_commitments() -> None:
    raw = b"secret crash payload\x00\xff"
    receipt = oracle.crash_feedback_receipt(
        target="/targets/parser", original_input=raw, minimized_input=b"\xff",
        oracle="sanitizer-report", crash_class="heap-buffer-overflow",
        sanitizer="heap-buffer-overflow", dedup_bucket="bucket", oracle_runs=4,
        max_runs=24,
    ).to_dict()
    encoded = str(receipt)
    assert raw.decode("latin-1") not in encoded
    assert "input_bytes" not in encoded
    assert receipt["input"]["originalBytes"] == len(raw)
    assert receipt["input"]["minimizedBytes"] == 1
    assert receipt["receiptDigest"].startswith("sha256:")
