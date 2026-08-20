"""Open verification oracles — deterministic, no LLM, no network."""

import pytest

from zeroverse.oracle import (
    LADDER,
    CrashSet,
    RunResult,
    adjudicate_capability,
    classify_crash,
    crash_state,
    differential_confirmed,
    marker_line,
    new_canary,
)

# --- canary-marker capability oracle ---------------------------------------

def test_canary_unique_and_hex() -> None:
    a, b = new_canary(), new_canary()
    assert a != b
    assert all(c in "0123456789abcdef" for c in a)


def test_marker_line_format_and_validation() -> None:
    assert marker_line("deadbeef", "oob-write") == "0VERSE-CANARY:deadbeef:oob-write"
    with pytest.raises(ValueError):
        marker_line("deadbeef", "not-a-rung")


def test_adjudicate_highest_rung() -> None:
    canary = "abc123"
    out = (
        b"boot\n"
        + marker_line(canary, "reached-sink").encode()
        + b"\n"
        + marker_line(canary, "oob-write").encode()
        + b"\ndone\n"
    )
    v = adjudicate_capability(out, canary)
    assert v.proven
    assert v.highest_rung == "oob-write"
    assert v.rungs_seen == ["reached-sink", "oob-write"]


def test_adjudicate_rejects_wrong_canary() -> None:
    # A marker bound to a DIFFERENT canary must not count (replay/stale guard).
    out = marker_line("OTHER", "controlled-pc").encode()
    v = adjudicate_capability(out, "thisrun")
    assert not v.proven and v.highest_rung is None


def test_ladder_is_ordered() -> None:
    assert LADDER.index("attempted") < LADDER.index("crash") < LADDER.index("controlled-pc")


# --- differential crash oracle ---------------------------------------------

def test_differential_confirmed() -> None:
    crashed = RunResult(crashed=True, signal="SIGSEGV")
    clean = RunResult(crashed=False)
    assert differential_confirmed(crashed, clean) is True
    assert differential_confirmed(crashed, crashed) is False   # crashes control too
    assert differential_confirmed(clean, clean) is False


@pytest.mark.parametrize(
    "stderr,expected",
    [
        ("AddressSanitizer: heap-buffer-overflow WRITE of size 8", "oob-write"),
        ("AddressSanitizer: heap-buffer-overflow READ of size 4", "oob-read"),
        ("AddressSanitizer: stack-buffer-overflow", "oob-write"),
        ("AddressSanitizer: use-after-free", "uaf"),
        ("Segmentation fault (SIGSEGV)", "crash"),
        ("nothing interesting", "unknown"),
    ],
)
def test_classify_crash(stderr: str, expected: str) -> None:
    assert classify_crash(stderr) == expected


# --- crash dedup -----------------------------------------------------------

def test_crash_state_normalizes_noise() -> None:
    a = crash_state(["main at file.c:42", "do_thing+0x10 0xdeadbeef"])
    b = crash_state(["main at file.c:99", "do_thing+0x20 0xfeedface"])
    assert a == b   # addresses/offsets/line numbers stripped -> same bucket


def test_crashset_dedups() -> None:
    cs = CrashSet()
    frames = ["main at x.c:1", "sink+0x4"]
    assert cs.add("asan", frames) is True     # first time -> new
    assert cs.add("asan", frames) is False    # duplicate -> dropped
    assert cs.add("asan", ["other"]) is True   # different bucket -> new
