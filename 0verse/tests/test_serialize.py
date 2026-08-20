"""Report serialization — JSON / SARIF / NDJSON / markdown for a RunResult."""

import json

from zeroverse import serialize
from zeroverse.agent import Verdict
from zeroverse.analyze import Finding
from zeroverse.ingest import Triage
from zeroverse.pipeline import RunResult, TriagedFinding
from zeroverse.report import PoV


def _result() -> RunResult:
    t = Triage(path="/bin/vuln", fmt="ELF", arch="x86-64", bits=64, endian="little", kind="EXEC")
    f = Finding("getenv", "system", "main", 0x1000, 0x40117C, 4)
    v = Verdict(True, "CWE-78", "high", "cmd injection", 'CMD="; id"')
    pov = PoV(env={"CMD": "echo MARK"}, crash_class="command-injection",
              crash_trace="MARK", reproduced=True)
    return RunResult(
        triage=t,
        stages_run=["ingest", "decompile", "lift", "analyze", "reason", "dynamic", "poc"],
        findings=[TriagedFinding(finding=f, verdict=v, pov=pov)],
    )


def test_json() -> None:
    d = json.loads(serialize.to_json(_result()))
    assert d["binary"] == "/bin/vuln"
    fd = d["findings"][0]
    assert fd["confirmed"] is True and fd["sink"] == "system"
    assert fd["pov"]["crash_class"] == "command-injection"


def test_sarif_valid_shape() -> None:
    s = json.loads(serialize.to_sarif(_result()))
    assert s["version"] == "2.1.0"
    res = s["runs"][0]["results"][0]
    assert res["ruleId"] == "CWE-78"
    assert res["level"] == "error"          # confirmed -> error
    assert res["locations"][0]["logicalLocations"][0]["name"] == "main"


def test_ndjson_one_per_line() -> None:
    lines = serialize.to_ndjson(_result()).splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["confirmed"] is True


def test_markdown() -> None:
    md = serialize.to_markdown(_result())
    assert "CONFIRMED" in md and "getenv → system" in md and "command-injection" in md


def test_unconfirmed_is_warning() -> None:
    r = _result()
    r.findings[0].pov = None
    res = json.loads(serialize.to_sarif(r))["runs"][0]["results"][0]
    assert res["level"] == "warning"
