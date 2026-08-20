"""M6 #34 — negative-results emitter: classification of why a run confirmed
nothing, and the rule that positive (PoV-confirmed) runs are NOT logged here."""

from __future__ import annotations

from pathlib import Path

from zeroverse import negative
from zeroverse.agent import Verdict
from zeroverse.analyze import Finding
from zeroverse.concolic import AngrVerdict
from zeroverse.ingest import Triage
from zeroverse.negative import NEGATIVE_LOG_VERSION
from zeroverse.pipeline import RunResult, TriagedFinding
from zeroverse.report import PoV

_FROZEN = lambda: "2026-01-01T00:00:00+00:00"  # noqa: E731


def _elf(path: str = "/bin/x") -> Triage:
    return Triage(path=path, fmt="ELF", arch="x86-64", bits=64, endian="little", kind="EXEC")


def _hyp_finding() -> TriagedFinding:
    f = Finding("recv", "memcpy", "h", 0x2000, 0x2100, 3)
    return TriagedFinding(finding=f, verdict=Verdict(True, "CWE-120", "medium", "maybe", ""))


def test_confirmed_run_is_not_negative() -> None:
    f = Finding("getenv", "system", "main", 0x1000, 0x1100, 4)
    pov = PoV(crash_class="command-injection", capability="command-exec",
              pov_script="/out/pov.py", reproduced=True)
    rr = RunResult(triage=_elf(), stages_run=["ingest", "decompile", "analyze", "dynamic"],
                   findings=[TriagedFinding(finding=f, verdict=Verdict(True, "CWE-78", "high",
                                                                       "ci", ""), pov=pov)])
    assert negative.classify(rr) is None
    assert negative.record_from_run(rr, binary="/bin/x", backend="ghidra") is None


def test_no_candidates() -> None:
    rr = RunResult(triage=_elf(), stages_run=["ingest", "decompile", "analyze"], findings=[])
    reason, _ = negative.classify(rr)  # type: ignore[misc]
    assert reason == "no-candidates"


def test_all_pruned() -> None:
    tf = _hyp_finding()
    tf.angr = AngrVerdict(outcome="unsat")
    rr = RunResult(triage=_elf(), stages_run=["ingest", "decompile", "analyze", "concolic"],
                   findings=[tf])
    reason, _ = negative.classify(rr)  # type: ignore[misc]
    assert reason == "all-pruned"


def test_static_only_degrade_from_note() -> None:
    rr = RunResult(triage=_elf(), stages_run=["ingest", "decompile", "analyze"],
                   findings=[_hyp_finding()],
                   note="Mach-O/arm64: static-only on this host — remain hypotheses")
    reason, _ = negative.classify(rr)  # type: ignore[misc]
    assert reason == "static-only-degrade"


def test_unsupported_format() -> None:
    t = Triage(path="/x.txt", fmt="unknown", arch="unknown")
    rr = RunResult(triage=t, stages_run=["ingest"], findings=[])
    reason, _ = negative.classify(rr)  # type: ignore[misc]
    assert reason == "unsupported-format"


def test_emit_writes_only_negative_runs(tmp_path: Path) -> None:
    log = tmp_path / "neg.ndjson"
    rr = RunResult(triage=_elf(), stages_run=["ingest", "decompile", "analyze"], findings=[])
    wrote = negative.emit_run(rr, log, binary="/bin/x", backend="ghidra", now=_FROZEN)
    assert wrote is True
    rec = negative.record_from_run(rr, binary="/bin/x", backend="ghidra", now=_FROZEN)
    assert rec is not None
    d = rec.to_dict()
    assert d["log_version"] == NEGATIVE_LOG_VERSION
    assert d["reason"] == "no-candidates"
    assert d["created_at"] == "2026-01-01T00:00:00+00:00"
    assert log.read_text().count("\n") == 1
