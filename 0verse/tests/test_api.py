"""M5 #28 — the embeddable scan() API + the versioned machine result contract.

Engine-free: builds a synthetic ``RunResult`` and checks the contract projection,
the version stamp, schema stability (the fixed field set), the NDJSON ``_meta``
header, SARIF level mapping, and PoV-is-truth (confirmed only with a reproducing
PoV). A small end-to-end ``scan()`` on an unsupported file exercises the wrapper.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from zeroverse import api
from zeroverse.agent import Verdict
from zeroverse.analyze import Finding
from zeroverse.api import CONTRACT_VERSION, ScanOptions
from zeroverse.ingest import Triage
from zeroverse.pipeline import RunResult, TriagedFinding
from zeroverse.report import PoV

_FINDING_FIELDS = {
    "id", "bug_class", "severity", "file", "function", "offset", "source", "sink",
    "confirmed", "hypothesis", "pruned", "capability", "pov_path", "repro_cmd",
    "dedup_bucket", "explanation",
    # v1.1 additive optional fields
    "crash_output", "confidence",
    # v1.2 additive optional patch fields (M7 #45/#46)
    "patch_available", "patch_verified", "patch_mode", "patch_path",
    "patch_recommendation", "patch_regression",
}


def _confirmed_result() -> RunResult:
    t = Triage(path="/bin/vuln", fmt="ELF", arch="x86-64", bits=64, endian="little", kind="EXEC")
    f = Finding("getenv", "system", "main", 0x1000, 0x40117C, 4)
    v = Verdict(True, "CWE-78", "high", "cmd injection", 'CMD="; id"')
    pov = PoV(env={"CMD": "echo MARK"}, crash_class="command-injection",
              capability="command-exec", dedup_bucket="b1",
              pov_script="/out/pov.py", crash_trace="MARK", reproduced=True)
    return RunResult(triage=t, stages_run=["ingest", "analyze", "dynamic", "poc"],
                     findings=[TriagedFinding(finding=f, verdict=v, pov=pov)])


def _hypothesis_result() -> RunResult:
    t = Triage(path="/bin/maybe", fmt="ELF", arch="x86-64", bits=64, endian="little", kind="EXEC")
    f = Finding("recv", "memcpy", "handler", 0x2000, 0x2100, 3)
    v = Verdict(True, "CWE-120", "medium", "possible overflow", "")
    return RunResult(triage=t, stages_run=["ingest", "analyze"],
                     findings=[TriagedFinding(finding=f, verdict=v, pov=None)])


def test_contract_version_is_v1_5() -> None:
    # v1.5 is an additive MINOR bump (terminal and stage outcomes). MAJOR stays 1
    # so a consumer pinned to MAJOR 1 keeps working.
    assert CONTRACT_VERSION == "1.5"
    assert CONTRACT_VERSION.split(".")[0] == "1"


def test_contract_version_and_tool() -> None:
    r = api._result_from_run("/bin/vuln", _confirmed_result())
    assert r.contract_version == CONTRACT_VERSION
    assert r.tool["name"] == "0verse"
    assert r.format == "ELF" and r.arch == "x86-64"


def test_finding_schema_is_stable() -> None:
    r = api._result_from_run("/bin/vuln", _confirmed_result())
    d = r.findings[0].to_dict()
    assert set(d.keys()) == _FINDING_FIELDS  # locked field set — guards the contract
    assert d["confirmed"] is True
    assert d["repro_cmd"] == "python3 /out/pov.py"
    assert d["offset"] == "0x40117c"
    # ids are stable + deterministic.
    again = api._result_from_run("/bin/vuln", _confirmed_result())
    assert again.findings[0].id == r.findings[0].id


def test_v1_1_fields_present_and_optional() -> None:
    # The two v1.1 fields are surfaced and OPTIONAL: a confirmed PoV with a captured
    # crash_trace carries it as crash_output; a hypothesis (no PoV) leaves both None.
    confirmed = api._result_from_run("/bin/vuln", _confirmed_result()).findings[0].to_dict()
    assert "crash_output" in confirmed and "confidence" in confirmed
    assert confirmed["crash_output"] == "MARK"   # the oracle's real captured blob
    assert confirmed["confidence"] is None       # no CASR signal in this fixture
    hyp = api._result_from_run("/bin/maybe", _hypothesis_result()).findings[0].to_dict()
    assert hyp["crash_output"] is None and hyp["confidence"] is None


def test_confidence_from_casr_signal() -> None:
    # When the oracle attached a CASR exploitability verdict, confidence is derived
    # from it (real signal, never fabricated); absent CASR it stays None.
    rr = _confirmed_result()
    rr.findings[0].pov.casr_severity = "EXPLOITABLE"  # type: ignore[union-attr]
    d = api._result_from_run("/bin/vuln", rr).findings[0].to_dict()
    assert d["confidence"] == 0.95


def test_pov_is_truth() -> None:
    r = api._result_from_run("/bin/maybe", _hypothesis_result())
    d = r.findings[0].to_dict()
    assert d["confirmed"] is False        # no PoV -> never confirmed
    assert d["hypothesis"] is True
    assert d["repro_cmd"] == ""


def test_ndjson_has_meta_header_then_findings() -> None:
    r = api._result_from_run("/bin/vuln", _confirmed_result())
    lines = api.result_to_ndjson(r).splitlines()
    head = json.loads(lines[0])
    assert head["_meta"]["contract_version"] == CONTRACT_VERSION
    assert head["_meta"]["confirmed_count"] == 1
    body = json.loads(lines[1])
    assert body["sink"] == "system" and body["confirmed"] is True


def test_sarif_level_mapping() -> None:
    confirmed = json.loads(api.result_to_sarif(api._result_from_run("/x", _confirmed_result())))
    hyp = json.loads(api.result_to_sarif(api._result_from_run("/x", _hypothesis_result())))
    assert confirmed["runs"][0]["results"][0]["level"] == "error"
    assert hyp["runs"][0]["results"][0]["level"] == "warning"
    driver = confirmed["runs"][0]["tool"]["driver"]
    assert driver["properties"]["contract_version"] == CONTRACT_VERSION


def test_json_roundtrips() -> None:
    r = api._result_from_run("/bin/vuln", _confirmed_result())
    d = json.loads(api.result_to_json(r))
    assert d["contract_version"] == CONTRACT_VERSION
    assert d["confirmed_count"] == 1
    assert d["findings"][0]["sink"] == "system"


def test_execution_metadata_is_additive() -> None:
    rr = _confirmed_result()
    rr.execution = {
        "contract_version": "1.0",
        "backend": "windows-worker",
        "capabilities": {"formats": ["PE"], "vectors": ["file"]},
    }
    result = api._result_from_run("/bin/vuln", rr)
    assert result.execution is not None
    assert result.execution["backend"] == "windows-worker"
    header = json.loads(api.result_to_ndjson(result).splitlines()[0])
    assert header["_meta"]["execution"]["contract_version"] == "1.0"


def test_scan_forwards_only_explicit_execution_backend(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    backend = SimpleNamespace(name="fake")
    captured: dict[str, object] = {}

    def fake_run(path, **kwargs):  # type: ignore[no-untyped-def]
        captured.update(kwargs)
        return _confirmed_result()

    monkeypatch.setattr(api, "run", fake_run)
    api.scan("/bin/vuln", ScanOptions(execution_backend=backend))  # type: ignore[arg-type]
    assert captured["execution_backend"] is backend


def test_scan_completion_routes_evidence_to_flywheel_learning(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from zeroverse import flywheel

    captured: dict[str, object] = {}

    def remember(rr, *, binary, backend):  # type: ignore[no-untyped-def]
        captured.update(rr=rr, binary=binary, backend=backend)
        return 1

    monkeypatch.setattr(flywheel, "remember_completed_run", remember)
    monkeypatch.delenv("ZEROVERSE_DATASET_PATH", raising=False)
    monkeypatch.delenv("ZEROVERSE_NEGATIVE_LOG", raising=False)
    rr = _confirmed_result()
    api._maybe_capture(rr, "/bin/vuln", "ghidra")
    assert captured == {"rr": rr, "binary": "/bin/vuln", "backend": "ghidra"}


def test_evaluation_reads_frozen_dataset_without_appending(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from zeroverse import dataset

    def fail_emit(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("evaluation leaked")

    monkeypatch.setenv("ZEROVERSE_DATASET_PATH", "/private/frozen-eval.ndjson")
    monkeypatch.setenv("ZEROVERSE_EVALUATION", "1")
    monkeypatch.setattr(dataset, "emit_run", fail_emit)
    api._maybe_capture(_confirmed_result(), "/bin/vuln", "ghidra")


def test_scan_wrapper_on_unsupported_file(tmp_path) -> None:  # type: ignore[no-untyped-def]
    p = tmp_path / "junk.bin"
    p.write_bytes(b"not a binary at all")
    result = api.scan(p, ScanOptions(backend="auto"))
    assert result.contract_version == CONTRACT_VERSION
    assert result.findings == []
    assert "supports" in result.note
