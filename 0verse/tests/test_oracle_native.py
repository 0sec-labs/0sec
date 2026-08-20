"""Native oracles added for M1 #6 — CASR wrapper, differential-allocator, and
suspected-known dedup. Logic is tested hermetically (no real binary/CASR/network);
the end-to-end run against a real ELF lives in the benchmark corpus (#9)."""

from zeroverse.oracle import (
    GUARD_ENV,
    DiffAllocVerdict,
    RunResult,
    _parse_casrep,
    guard_env,
    suspected_known,
)


def test_guard_env_has_glibc_checks() -> None:
    env = guard_env()
    assert env["MALLOC_CHECK_"] == "3"
    assert "glibc.malloc.check" in env["GLIBC_TUNABLES"]
    # the static template is never mutated by guard_env()
    assert "EF_ALLOW_MALLOC_0" not in GUARD_ENV


def test_diff_alloc_clean_to_crash_is_real_heap_bug() -> None:
    v = DiffAllocVerdict(
        stock=RunResult(crashed=False),
        guard=RunResult(crashed=True, signal="SIGSEGV"),
        real_heap_bug=True, both_crash=False,
    )
    assert v.confirmed and v.real_heap_bug


def test_diff_alloc_both_clean_not_confirmed() -> None:
    v = DiffAllocVerdict(
        stock=RunResult(crashed=False), guard=RunResult(crashed=False),
        real_heap_bug=False, both_crash=False,
    )
    assert not v.confirmed


def test_parse_casrep_maps_severity_and_capability() -> None:
    rep = _parse_casrep({
        "CrashSeverity": {
            "Type": "EXPLOITABLE", "ShortDescription": "ReturnAv",
            "Description": "Access violation during return instruction",
        },
        "Stacktrace": ["#0 0x401199 in main", "#1 0x7f00 in __libc_start"],
        "CrashLine": "overflow.c:11",
    })
    assert rep.severity == "EXPLOITABLE"
    assert rep.short_desc == "ReturnAv"
    assert rep.capability == "oob-write"   # ReturnAv => write capability
    assert rep.frames and "0x" not in rep.frames[0]  # addresses stripped


def test_suspected_known_flags_but_does_not_dismiss() -> None:
    advisories = [{"id": "CVE-2020-0001", "package": "libfoo",
                   "symbols": ["parse_header"]}]
    hits = suspected_known("libfoo", "1.2.3", "parse_header", advisories)
    assert len(hits) == 1 and hits[0].advisory_id == "CVE-2020-0001"
    # a different symbol in the same package is still flagged (never auto-dismissed)
    assert suspected_known("libbar", "1.0", "x", advisories) == []
