"""M7 #48 — tiered crash dedup wired into the dataset emitter and fleet sweeps:
same-bug-different-input collapses to one emitted record/variant, distinct bugs
survive (the boundary), and a confirmed-unique bug is never dropped.
"""

from __future__ import annotations

from zeroverse import dataset, fleet
from zeroverse.agent import Verdict
from zeroverse.analyze import Finding
from zeroverse.fleet import ConfirmedVariant, VariantCandidate
from zeroverse.ingest import Triage
from zeroverse.pipeline import RunResult, TriagedFinding
from zeroverse.report import PoV

_SAME_BUG_FRAMES = ["process_record at p.c:1", "copy at p.c:2", "memcpy at p.c:3"]
_OTHER_FRAMES = ["json_parse at j.c:1", "tokenize at j.c:2", "next_char at j.c:3"]


def _confirmed_tf(function: str, sink_addr: int, frames: list[str], inp: bytes) -> TriagedFinding:
    f = Finding("read", "memcpy", function, 0x1000, sink_addr, 4)
    v = Verdict(True, "CWE-787", "high", "oob", "AAAA")
    pov = PoV(input_bytes=inp, crash_class="SIGSEGV-write", capability="oob-write",
              frames=frames, reproduced=True, crash_trace="overflow")
    return TriagedFinding(finding=f, verdict=v, pov=pov)


def _run(findings: list[TriagedFinding]) -> RunResult:
    t = Triage(path="/bin/vuln", fmt="ELF", arch="x86-64", bits=64,
               endian="little", kind="EXEC")
    return RunResult(triage=t, stages_run=["ingest", "analyze", "dynamic", "poc"],
                     findings=findings)


# --- dataset emitter dedup --------------------------------------------------

def test_dataset_collapses_same_bug_different_input() -> None:
    rr = _run([
        _confirmed_tf("process_record", 0x401000, _SAME_BUG_FRAMES, b"input-A"),
        _confirmed_tf("process_record", 0x401000, _SAME_BUG_FRAMES, b"input-B"),  # dup
        _confirmed_tf("json_parse", 0x402000, _OTHER_FRAMES, b"json-crash"),       # distinct
    ])
    recs = dataset.records_from_run(rr, binary="/bin/vuln", backend="test")
    # the two same-bug PoVs collapse; the distinct bug survives -> 2 records.
    assert len(recs) == 2
    functions = {r.function for r in recs}
    assert functions == {"process_record", "json_parse"}


def test_dataset_keeps_distinct_bugs_control() -> None:
    rr = _run([
        _confirmed_tf("process_record", 0x401000, _SAME_BUG_FRAMES, b"a"),
        _confirmed_tf("json_parse", 0x402000, _OTHER_FRAMES, b"b"),
    ])
    recs = dataset.records_from_run(rr, binary="/bin/vuln", backend="test")
    assert len(recs) == 2   # never drops a distinct confirmed bug


def test_dataset_dedup_off_keeps_duplicates() -> None:
    rr = _run([
        _confirmed_tf("process_record", 0x401000, _SAME_BUG_FRAMES, b"a"),
        _confirmed_tf("process_record", 0x401000, _SAME_BUG_FRAMES, b"b"),
    ])
    recs = dataset.records_from_run(rr, binary="/bin/vuln", backend="test", dedup=False)
    assert len(recs) == 2   # opt-out preserves the raw per-finding rows


# --- fleet sweep dedup ------------------------------------------------------

def _cv(function: str, frames: list[str]) -> ConfirmedVariant:
    cand = VariantCandidate(member="m", function=function, sink="memcpy",
                            source="read", similarity=1.0, route="userland",
                            detector="symbol-pass")
    pov = PoV(crash_class="SIGSEGV-write", frames=frames, reproduced=True)
    return ConfirmedVariant(candidate=cand, status="confirmed", pov=pov, oracle="diff-alloc")


def test_fleet_dedup_collapses_same_crash_distinct_sinks() -> None:
    confs = [
        _cv("handler_a", _SAME_BUG_FRAMES),
        _cv("handler_b", _SAME_BUG_FRAMES),   # same crash, different sink coord
        _cv("json_parse", _OTHER_FRAMES),     # genuinely distinct
    ]
    out = fleet._dedup_confirmations(confs)
    assert len(out) == 2   # the same-crash pair fuzzy-merges; the distinct stays


def test_fleet_dedup_keeps_distinct_control() -> None:
    confs = [_cv("a", _SAME_BUG_FRAMES), _cv("b", _OTHER_FRAMES)]
    assert len(fleet._dedup_confirmations(confs)) == 2
