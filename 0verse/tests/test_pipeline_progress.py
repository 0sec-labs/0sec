"""#224 sub-gap (c): the pipeline's incremental stage-progress mirror — a
timeout-killed scan must leave WHERE it stood, not an empty log."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from zeroverse.ingest import Triage
from zeroverse.pipeline import RunResult, TriagedFinding, _ProgressStages


def _result() -> RunResult:
    t = Triage(path="/bin/x", fmt="ELF", arch="x86-64", bits=64,
               endian="little", kind="EXEC")
    return RunResult(triage=t)


def _wrap(rr: RunResult) -> _ProgressStages:
    stages = _ProgressStages(rr)
    rr.stages_run = stages
    return stages


def test_progress_mirror_writes_one_record_per_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prog = tmp_path / "prog.ndjson"
    monkeypatch.setenv("ZEROVERSE_PROGRESS_PATH", str(prog))
    rr = _result()
    stages = _wrap(rr)
    stages.append("ingest")
    stages.extend(["decompile", "lift", "analyze"])
    lines = prog.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 4
    recs = [json.loads(line) for line in lines]
    assert [r["stage"] for r in recs] == ["ingest", "decompile", "lift", "analyze"]
    # the last record carries the full stage list + running counts
    assert recs[-1]["stages_run"] == ["ingest", "decompile", "lift", "analyze"]
    assert recs[-1]["findings"] == 0 and recs[-1]["confirmed"] == 0


def test_progress_mirror_counts_confirmed_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zeroverse.agent import Verdict
    from zeroverse.analyze import Finding
    from zeroverse.report import PoV

    prog = tmp_path / "prog.ndjson"
    monkeypatch.setenv("ZEROVERSE_PROGRESS_PATH", str(prog))
    rr = _result()
    stages = _wrap(rr)
    f = Finding(source="fuzz:stdin", sink="parse", function="parse",
                source_addr=0, sink_addr=0, path_len=0, origin="fuzz")
    v = Verdict(is_real=True, bug_class="oob", severity="high",
                explanation="", input_example="")
    rr.findings.append(TriagedFinding(finding=f, verdict=v, pov=PoV(reproduced=True)))
    rr.findings.append(TriagedFinding(finding=f, verdict=v, pov=None))
    stages.append("poc")
    rec = json.loads(prog.read_text(encoding="utf-8").strip())
    assert rec["findings"] == 2
    assert rec["confirmed"] == 1  # only the reproduced PoV counts


def test_progress_mirror_off_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ZEROVERSE_PROGRESS_PATH", raising=False)
    rr = _result()
    stages = _wrap(rr)
    stages.append("ingest")  # no file, no error
    assert list(stages) == ["ingest"]
