"""Oracle PoV-adjudication tests — mock the ASan run, assert the honest verdict."""

import zeroverse.adjudicate as adj
from zeroverse.adjudicate import (
    CONFIRMED,
    DIVERGENT,
    NO_CRASH,
    UNRUNNABLE,
    adjudicate_finding,
)
from zeroverse.agentic import AgentVerdict
from zeroverse.oracle import RunResult

_ASAN_READ = (
    "==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xf2f00c40 at pc 0x8\n"
    "READ of size 4 at 0xf2f00c40 thread T0\n"
    "    #0 0x822fe88 in parseAdobeRAFMakernote /src/fuji.cpp:229:33\n"
    "    #1 0x822d340 in LibRaw::parse_makernote /src/x.cpp:100\n"
)


def _fake_run(crashed=True, stderr=_ASAN_READ, sanitizer="AddressSanitizer"):
    return RunResult(crashed=crashed, stderr=stderr, sanitizer=sanitizer)


def _patch(mp, *, launch=True, run=None):
    mp.setattr(adj, "host_can_launch", lambda *a, **k: launch)
    if run is not None:
        mp.setattr(adj, "run_sanitizer", lambda *a, **k: run)


def test_confirmed_when_function_and_cwe_match(monkeypatch):
    _patch(monkeypatch, run=_fake_run())
    v = AgentVerdict(
        is_bug=True,
        cwe="CWE-125",
        sink="parseAdobeRAFMakernote reads offset via sget4",
        source="",
        explanation="",
    )
    r = adjudicate_finding(v, "/x/vuln", b"poc")
    assert r.status == CONFIRMED and r.confirmed
    assert "parseAdobeRAFMakernote" in r.crash_function


def test_divergent_when_crash_is_a_different_function(monkeypatch):
    _patch(monkeypatch, run=_fake_run())
    v = AgentVerdict(
        is_bug=True,
        cwe="CWE-125",
        sink="processCanonCameraInfo indexes tag",
        source="",
        explanation="",
    )
    r = adjudicate_finding(v, "/x/vuln", b"poc")
    assert r.status == DIVERGENT and not r.confirmed


def test_oob_read_write_confusion_still_confirms_same_family(monkeypatch):
    # The LLM often can't tell READ from WRITE on decompiled pseudo-C; a WRITE(787)
    # claim on a READ(125) crash at the SAME function is the same OOB bug -> CONFIRMED.
    _patch(monkeypatch, run=_fake_run())
    v = AgentVerdict(
        is_bug=True, cwe="CWE-787", sink="parseAdobeRAFMakernote", source="", explanation=""
    )
    assert adjudicate_finding(v, "/x/vuln", b"poc").status == CONFIRMED


def test_divergent_when_cwe_class_mismatches(monkeypatch):
    # A UAF(416) claim on an OOB-READ(125) crash is a genuine CROSS-FAMILY mismatch.
    _patch(monkeypatch, run=_fake_run())
    v = AgentVerdict(
        is_bug=True, cwe="CWE-416", sink="parseAdobeRAFMakernote", source="", explanation=""
    )
    r = adjudicate_finding(v, "/x/vuln", b"poc")
    assert r.status == DIVERGENT


def test_no_crash_when_poc_does_not_trigger(monkeypatch):
    _patch(monkeypatch, run=_fake_run(crashed=False, stderr="exit 0", sanitizer=""))
    v = AgentVerdict(
        is_bug=True, cwe="CWE-125", sink="parseAdobeRAFMakernote", source="", explanation=""
    )
    r = adjudicate_finding(v, "/x/vuln", b"poc")
    assert r.status == NO_CRASH


def test_unrunnable_when_host_cannot_launch(monkeypatch):
    _patch(monkeypatch, launch=False)
    v = AgentVerdict(is_bug=True, cwe="CWE-125", sink="x", source="", explanation="")
    r = adjudicate_finding(v, "/x/vuln", b"poc")
    assert r.status == UNRUNNABLE


# --- crash_to_cwe: the new MSan/UBSan sanitizer kinds map to the right family -----
# These are the tokens oracle.sanitizer_report now emits (see test_oracle_asan). They
# must land in the uninit / intoverflow families so a CWE-457 / CWE-190 hypothesis can
# CONFIRM instead of staying class-less and forever DIVERGENT.

def test_crash_to_cwe_msan_uninitialized_value():
    assert adj.crash_to_cwe("use-of-uninitialized-value", "") == ("CWE-457", "uninit")


def test_crash_to_cwe_ubsan_signed_integer_overflow():
    assert adj.crash_to_cwe("signed-integer-overflow", "") == ("CWE-190", "intoverflow")
    assert adj.crash_to_cwe("unsigned-integer-overflow", "") == ("CWE-190", "intoverflow")


def test_uninit_hypothesis_confirms_on_msan_report(monkeypatch):
    msan = (
        "==7==WARNING: MemorySanitizer: use-of-uninitialized-value\n"
        "    #0 0x0 in decode_frame src/dec.c:88:6\n"
        "SUMMARY: MemorySanitizer: use-of-uninitialized-value src/dec.c:88:6\n"
    )
    _patch(monkeypatch, run=_fake_run(stderr=msan, sanitizer="use-of-uninitialized-value"))
    v = AgentVerdict(is_bug=True, cwe="CWE-457", sink="decode_frame", source="",
                     explanation="")
    r = adjudicate_finding(v, "/x/vuln", b"poc")
    assert r.status == CONFIRMED and r.crash_cwe == "CWE-457"
